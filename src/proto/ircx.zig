// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX base protocol model.
//!
//! This module is intentionally transport-free. Parsers return views into
//! caller-owned command lines, while stores own only the bytes they must retain
//! after validation.
const std = @import("std");
const cloak_match = @import("cloak_match.zig");
const irc_line = @import("irc_line.zig");

pub const MAX_PROP_NAME: usize = 64;
pub const MAX_PROP_VALUE: usize = 512;
pub const MAX_ENTITY_ID: usize = 128;
pub const MAX_ACCESS_MASK: usize = 128;
pub const MAX_PROPERTY_KEY: usize = 8 + 1 + MAX_ENTITY_ID + 1 + MAX_PROP_NAME;

pub const IrcxError = error{
    UnknownIrcxCommand,
    InvalidEntity,
    InvalidPropertyName,
    InvalidPropertyValue,
    InvalidAccessMask,
    InvalidAccessLevel,
    OutputTooSmall,
};

pub const ParseIrcxError = irc_line.ParseError || error{
    UnknownIrcxCommand,
};

/// IRCX commands handled by the base opt-in layer.
pub const IrcxCommand = enum {
    ircx,
    isircx,

    pub fn parse(command: []const u8) ?IrcxCommand {
        if (std.ascii.eqlIgnoreCase(command, "IRCX")) return .ircx;
        if (std.ascii.eqlIgnoreCase(command, "ISIRCX")) return .isircx;
        return null;
    }
};

/// Per-client IRCX state. Socket/session code owns one of these per client.
pub const ClientIrcxState = struct {
    enabled: bool = false,
    namesx: bool = false,
    capability_mask: u64 = 0,

    pub fn applyCommand(self: *ClientIrcxState, command: IrcxCommand, auto_caps: u64) void {
        switch (command) {
            .ircx, .isircx => {
                self.enabled = true;
                self.namesx = true;
                self.capability_mask |= auto_caps;
            },
        }
    }
};

/// ISUPPORT/advertisement limits for the base IRCX surface.
pub const AdvertiseLimits = struct {
    max_codepage: usize = 0,
    max_language: usize = 0,
    max_prop: usize = 0,
    max_access: usize = 0,
};

/// Render space-separated IRCX advertisement tokens into caller storage.
pub fn writeAdvertiseTokens(out: []u8, limits: AdvertiseLimits) IrcxError![]const u8 {
    return std.fmt.bufPrint(
        out,
        "IRCX MAXCODEPAGE={} MAXLANGUAGE={} MAXPROP={} MAXACCESS={}",
        .{ limits.max_codepage, limits.max_language, limits.max_prop, limits.max_access },
    ) catch error.OutputTooSmall;
}

/// Parse a raw IRC line and return the IRCX command it carries.
pub fn parseIrcxCommand(line: []const u8) ParseIrcxError!IrcxCommand {
    const parsed = try irc_line.parseLine(line);
    return IrcxCommand.parse(parsed.command) orelse error.UnknownIrcxCommand;
}

/// Parse and apply an IRCX/ISIRCX line to per-client state.
pub fn applyIrcxLine(state: *ClientIrcxState, line: []const u8, auto_caps: u64) ParseIrcxError!IrcxCommand {
    const command = try parseIrcxCommand(line);
    state.applyCommand(command, auto_caps);
    return command;
}

/// IRCX property entity scopes.
pub const EntityScope = enum {
    channel,
    user,
    account,
    member,
    onjoin,
    onpart,
    ownerkey,
    opkey,

    pub fn token(self: EntityScope) []const u8 {
        return switch (self) {
            .channel => "channel",
            .user => "user",
            .account => "account",
            .member => "member",
            .onjoin => "onjoin",
            .onpart => "onpart",
            .ownerkey => "ownerkey",
            .opkey => "opkey",
        };
    }

    pub fn parse(raw: []const u8) ?EntityScope {
        inline for (@typeInfo(EntityScope).@"enum".field_names) |field_name| {
            if (std.ascii.eqlIgnoreCase(raw, field_name)) {
                return @field(EntityScope, field_name);
            }
        }
        return null;
    }

    pub fn isSecret(self: EntityScope) bool {
        return self == .ownerkey or self == .opkey;
    }
};

/// Property entity key. `id` is a caller-owned view.
pub const Entity = struct {
    scope: EntityScope,
    id: []const u8,

    pub fn init(scope: EntityScope, id: []const u8) IrcxError!Entity {
        try validateEntityId(scope, id);
        return .{ .scope = scope, .id = id };
    }
};

/// Property view returned from stores. Slices are owned by the store.
pub const PropertyView = struct {
    entity: Entity,
    name: []const u8,
    value: []const u8,
};

const Property = struct {
    entity_id: []u8,
    name: []u8,
    value: []u8,
    scope: EntityScope,

    fn view(self: *const Property) PropertyView {
        return .{
            .entity = .{ .scope = self.scope, .id = self.entity_id },
            .name = self.name,
            .value = self.value,
        };
    }
};

/// Owning property store keyed by `(entity scope, entity id, property name)`.
pub const PropertyStore = struct {
    allocator: std.mem.Allocator,
    props: std.StringHashMap(Property),

    pub fn init(allocator: std.mem.Allocator) PropertyStore {
        return .{
            .allocator = allocator,
            .props = std.StringHashMap(Property).init(allocator),
        };
    }

    pub fn deinit(self: *PropertyStore) void {
        var it = self.props.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeProperty(self.allocator, entry.value_ptr.*);
        }
        self.props.deinit();
        self.* = undefined;
    }

    pub fn set(self: *PropertyStore, entity: Entity, name: []const u8, value: []const u8) !void {
        try validatePropertyName(name);
        try validatePropertyValue(value);

        const key = try makePropertyKey(self.allocator, entity, name);
        errdefer self.allocator.free(key);

        const entity_copy = try self.allocator.dupe(u8, entity.id);
        errdefer self.allocator.free(entity_copy);
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        const gop = try self.props.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(key);
            self.allocator.free(entity_copy);
            self.allocator.free(name_copy);
            self.allocator.free(gop.value_ptr.value);
            gop.value_ptr.value = value_copy;
            return;
        }

        gop.key_ptr.* = key;
        gop.value_ptr.* = .{
            .entity_id = entity_copy,
            .name = name_copy,
            .value = value_copy,
            .scope = entity.scope,
        };
    }

    pub fn get(self: *const PropertyStore, entity: Entity, name: []const u8) IrcxError!?PropertyView {
        try validatePropertyName(name);
        var key_buf: [MAX_PROPERTY_KEY]u8 = undefined;
        const key = try writePropertyKey(&key_buf, entity, name);

        if (self.props.getPtr(key)) |prop| return prop.view();
        return null;
    }

    pub fn remove(self: *PropertyStore, entity: Entity, name: []const u8) IrcxError!bool {
        try validatePropertyName(name);
        var key_buf: [MAX_PROPERTY_KEY]u8 = undefined;
        const key = try writePropertyKey(&key_buf, entity, name);

        if (self.props.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            freeProperty(self.allocator, kv.value);
            return true;
        }
        return false;
    }

    /// List matching properties into caller storage. `pattern` accepts `*` and
    /// `?`; null lists all properties on the entity.
    pub fn list(
        self: *const PropertyStore,
        entity: Entity,
        pattern: ?[]const u8,
        out: []PropertyView,
    ) IrcxError![]const PropertyView {
        if (pattern) |raw| try validatePropertyPattern(raw);

        var count: usize = 0;
        var it = self.props.iterator();
        while (it.next()) |entry| {
            const prop = entry.value_ptr;
            if (prop.scope != entity.scope) continue;
            if (!std.ascii.eqlIgnoreCase(prop.entity_id, entity.id)) continue;
            if (pattern) |raw| {
                if (!globMatch(raw, prop.name)) continue;
            }

            if (count >= out.len) return error.OutputTooSmall;
            out[count] = prop.view();
            count += 1;
        }

        return out[0..count];
    }
};

/// IRCX channel access levels.
pub const AccessLevel = enum(u8) {
    voice = 1,
    host = 2,
    owner = 4,
    deny = 10,
    grant = 11,
    quiet = 12,

    pub fn token(self: AccessLevel) []const u8 {
        return switch (self) {
            .voice => "VOICE",
            .host => "HOST",
            .owner => "OWNER",
            .deny => "DENY",
            .grant => "GRANT",
            .quiet => "QUIET",
        };
    }

    pub fn parse(raw: []const u8) ?AccessLevel {
        if (std.ascii.eqlIgnoreCase(raw, "VOICE")) return .voice;
        if (std.ascii.eqlIgnoreCase(raw, "HOST") or std.ascii.eqlIgnoreCase(raw, "OP")) return .host;
        if (std.ascii.eqlIgnoreCase(raw, "OWNER") or std.ascii.eqlIgnoreCase(raw, "ADMIN")) return .owner;
        if (std.ascii.eqlIgnoreCase(raw, "DENY")) return .deny;
        if (std.ascii.eqlIgnoreCase(raw, "GRANT")) return .grant;
        if (std.ascii.eqlIgnoreCase(raw, "QUIET")) return .quiet;
        return null;
    }

    pub fn rank(self: AccessLevel) u8 {
        return switch (self) {
            .voice => 1,
            .host => 2,
            .owner => 4,
            .deny, .grant, .quiet => 0,
        };
    }
};

/// Access entry view. Slices are owned by the store.
pub const AccessEntryView = struct {
    channel: []const u8,
    mask: []const u8,
    level: AccessLevel,
};

const AccessEntry = struct {
    channel: []u8,
    mask: []u8,
    level: AccessLevel,

    fn view(self: *const AccessEntry) AccessEntryView {
        return .{ .channel = self.channel, .mask = self.mask, .level = self.level };
    }
};

/// Owning per-channel IRCX ACCESS store.
pub const AccessStore = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(AccessEntry) = .empty,

    pub fn init(allocator: std.mem.Allocator) AccessStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *AccessStore) void {
        for (self.entries.items) |entry| freeAccessEntry(self.allocator, entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add or update one channel access entry.
    pub fn add(self: *AccessStore, channel: []const u8, mask: []const u8, level: AccessLevel) !void {
        try validateChannelName(channel);
        try validateAccessMask(mask);

        if (self.findIndex(channel, mask)) |idx| {
            self.entries.items[idx].level = level;
            return;
        }

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const mask_copy = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(mask_copy);

        try self.entries.append(self.allocator, .{
            .channel = channel_copy,
            .mask = mask_copy,
            .level = level,
        });
    }

    pub fn remove(self: *AccessStore, channel: []const u8, mask: []const u8) IrcxError!bool {
        try validateChannelName(channel);
        try validateAccessMask(mask);

        const idx = self.findIndex(channel, mask) orelse return false;
        const removed = self.entries.swapRemove(idx);
        freeAccessEntry(self.allocator, removed);
        return true;
    }

    /// Return the highest ranked matching membership entry for a hostmask.
    /// DENY/GRANT/QUIET are returned on direct match but do not outrank
    /// OWNER/HOST/VOICE because they are mode-list levels in IRCX.
    pub fn matchHostmask(self: *const AccessStore, channel: []const u8, hostmask: []const u8) IrcxError!?AccessEntryView {
        return self.matchHostmaskWithCloak(channel, hostmask, null);
    }

    pub fn matchHostmaskWithCloak(self: *const AccessStore, channel: []const u8, hostmask: []const u8, ctx: ?cloak_match.Context) IrcxError!?AccessEntryView {
        try validateChannelName(channel);
        try validateAccessMask(hostmask);

        var best: ?*const AccessEntry = null;
        for (self.entries.items) |*entry| {
            if (!std.ascii.eqlIgnoreCase(entry.channel, channel)) continue;
            if (!cloak_match.match(entry.mask, hostmask, ctx)) continue;

            if (best == null or entry.level.rank() > best.?.level.rank()) {
                best = entry;
            }
        }

        if (best) |entry| return entry.view();
        return null;
    }

    pub fn list(self: *const AccessStore, channel: []const u8, out: []AccessEntryView) IrcxError![]const AccessEntryView {
        try validateChannelName(channel);
        var count: usize = 0;
        for (self.entries.items) |*entry| {
            if (!std.ascii.eqlIgnoreCase(entry.channel, channel)) continue;
            if (count >= out.len) return error.OutputTooSmall;
            out[count] = entry.view();
            count += 1;
        }
        return out[0..count];
    }

    fn findIndex(self: *const AccessStore, channel: []const u8, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (std.ascii.eqlIgnoreCase(entry.channel, channel) and
                std.ascii.eqlIgnoreCase(entry.mask, mask))
            {
                return idx;
            }
        }
        return null;
    }
};

/// Selected IRCX numerics used by the base/PROP/ACCESS layer.
pub const NumericReply = struct {
    code: u16,
    name: []const u8,
    text: []const u8,
};

pub const numeric_replies = [_]NumericReply{
    .{ .code = 800, .name = "RPL_IRCX", .text = "IRCX enabled; SASL mechanisms follow" },
    .{ .code = 801, .name = "RPL_ACCESSADD", .text = "ACCESS entry added" },
    .{ .code = 802, .name = "RPL_ACCESSDELETE", .text = "ACCESS entry deleted" },
    .{ .code = 803, .name = "RPL_ACCESSSTART", .text = "ACCESS list begins" },
    .{ .code = 804, .name = "RPL_ACCESSENTRY", .text = "ACCESS list entry" },
    .{ .code = 805, .name = "RPL_ACCESSEND", .text = "ACCESS list ends" },
    .{ .code = 808, .name = "RPL_EVENTADD", .text = "Event added" },
    .{ .code = 809, .name = "RPL_EVENTLIST", .text = "Event subscription" },
    .{ .code = 810, .name = "RPL_EVENTEND", .text = "Event list ends" },
    .{ .code = 818, .name = "RPL_PROPLIST", .text = "PROP list entry" },
    .{ .code = 819, .name = "RPL_PROPEND", .text = "PROP list ends" },
    .{ .code = 821, .name = "ERR_EVENTDUP", .text = "Event already subscribed" },
    .{ .code = 822, .name = "ERR_EVENTMIS", .text = "Not subscribed to event" },
    .{ .code = 823, .name = "ERR_NOSUCHEVENT", .text = "No such event" },
    .{ .code = 824, .name = "RPL_EVENTDELETE", .text = "Event removed" },
    .{ .code = 825, .name = "RPL_EVENTCHANGE", .text = "Event updated" },
    .{ .code = 915, .name = "ERR_ACCESS_MISSING", .text = "ACCESS entry missing" },
    .{ .code = 916, .name = "ERR_ACCESS_TOOMANY", .text = "Too many ACCESS entries" },
    .{ .code = 917, .name = "ERR_PROP_TOOMANY", .text = "Too many properties" },
    .{ .code = 918, .name = "ERR_PROPDENIED", .text = "Property denied" },
    .{ .code = 919, .name = "ERR_PROP_MISSING", .text = "Property missing" },
};

pub fn numericByCode(code: u16) ?NumericReply {
    for (numeric_replies) |reply| {
        if (reply.code == code) return reply;
    }
    return null;
}

/// Case-insensitive IRC-style glob. Supports `*` and `?`.
pub fn globMatch(pattern: []const u8, value: []const u8) bool {
    if (pattern.len == 0) return value.len == 0;

    var p: usize = 0;
    var v: usize = 0;
    var star: ?usize = null;
    var retry_v: usize = 0;

    while (v < value.len) {
        if (p < pattern.len and (pattern[p] == '?' or asciiLower(pattern[p]) == asciiLower(value[v]))) {
            p += 1;
            v += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            retry_v = v;
        } else if (star) |star_pos| {
            p = star_pos + 1;
            retry_v += 1;
            v = retry_v;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// Constant-time equality helper for ownerkey/opkey property values.
pub fn secretValueEquals(a: []const u8, b: []const u8) bool {
    const max_len = @max(a.len, b.len);
    var diff: usize = a.len ^ b.len;
    var idx: usize = 0;
    while (idx < max_len) : (idx += 1) {
        const ac: u8 = if (idx < a.len) a[idx] else 0;
        const bc: u8 = if (idx < b.len) b[idx] else 0;
        diff |= @as(usize, ac ^ bc);
    }
    return diff == 0;
}

/// Write the canonical property key for `(entity, name)` into caller storage.
pub fn writePropertyKey(out: []u8, entity: Entity, name: []const u8) IrcxError![]const u8 {
    try validateEntityId(entity.scope, entity.id);
    try validatePropertyName(name);

    const len = propertyKeyLen(entity, name);
    if (out.len < len) return error.OutputTooSmall;
    fillPropertyKey(out[0..len], entity, name);
    return out[0..len];
}

fn validateEntityId(scope: EntityScope, id: []const u8) IrcxError!void {
    if (id.len == 0 or id.len > MAX_ENTITY_ID) return error.InvalidEntity;
    try validateSafeText(id, error.InvalidEntity);

    switch (scope) {
        .channel, .onjoin, .onpart, .ownerkey, .opkey => try validateChannelName(id),
        .user, .account => {},
        .member => {
            if (std.mem.indexOfScalar(u8, id, ':') == null) return error.InvalidEntity;
        },
    }
}

fn validateChannelName(channel: []const u8) IrcxError!void {
    if (channel.len == 0 or channel.len > MAX_ENTITY_ID) return error.InvalidEntity;
    try validateSafeText(channel, error.InvalidEntity);
    switch (channel[0]) {
        '#', '&', '%', '+' => {},
        else => return error.InvalidEntity,
    }
    for (channel) |ch| {
        if (ch == ' ' or ch == ',' or ch == 7) return error.InvalidEntity;
    }
}

fn validatePropertyName(name: []const u8) IrcxError!void {
    if (name.len == 0 or name.len > MAX_PROP_NAME) return error.InvalidPropertyName;
    for (name) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidPropertyName,
        }
    }
}

fn validatePropertyPattern(pattern: []const u8) IrcxError!void {
    if (pattern.len == 0 or pattern.len > MAX_PROP_NAME) return error.InvalidPropertyName;
    for (pattern) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.', '*', '?' => {},
            else => return error.InvalidPropertyName,
        }
    }
}

fn validatePropertyValue(value: []const u8) IrcxError!void {
    if (value.len > MAX_PROP_VALUE) return error.InvalidPropertyValue;
    try validateSafeText(value, error.InvalidPropertyValue);
}

fn validateAccessMask(mask: []const u8) IrcxError!void {
    if (mask.len == 0 or mask.len > MAX_ACCESS_MASK) return error.InvalidAccessMask;
    try validateSafeText(mask, error.InvalidAccessMask);
    for (mask) |ch| {
        if (ch == ' ' or ch == ',') return error.InvalidAccessMask;
    }
}

fn validateSafeText(bytes: []const u8, comptime err: IrcxError) IrcxError!void {
    for (bytes) |ch| {
        switch (ch) {
            0, '\r', '\n' => return err,
            1...8, 11, 12, 14...31, 127 => return err,
            else => {},
        }
    }
}

fn makePropertyKey(allocator: std.mem.Allocator, entity: Entity, name: []const u8) ![]u8 {
    try validateEntityId(entity.scope, entity.id);
    try validatePropertyName(name);

    const len = propertyKeyLen(entity, name);
    const key = try allocator.alloc(u8, len);
    errdefer allocator.free(key);
    fillPropertyKey(key, entity, name);
    return key;
}

fn propertyKeyLen(entity: Entity, name: []const u8) usize {
    return entity.scope.token().len + 1 + entity.id.len + 1 + name.len;
}

fn fillPropertyKey(key: []u8, entity: Entity, name: []const u8) void {
    const scope = entity.scope.token();
    var pos: usize = 0;
    copyLower(key[pos .. pos + scope.len], scope);
    pos += scope.len;
    key[pos] = 0x1f;
    pos += 1;
    copyLower(key[pos .. pos + entity.id.len], entity.id);
    pos += entity.id.len;
    key[pos] = 0x1f;
    pos += 1;
    copyLower(key[pos .. pos + name.len], name);
}

fn copyLower(dst: []u8, src: []const u8) void {
    for (src, 0..) |ch, idx| dst[idx] = asciiLower(ch);
}

fn asciiLower(ch: u8) u8 {
    return std.ascii.toLower(ch);
}

fn freeProperty(allocator: std.mem.Allocator, prop: Property) void {
    allocator.free(prop.entity_id);
    allocator.free(prop.name);
    allocator.free(prop.value);
}

fn freeAccessEntry(allocator: std.mem.Allocator, entry: AccessEntry) void {
    allocator.free(entry.channel);
    allocator.free(entry.mask);
}

test "PROP set/get/list round-trip and validation rejects bad names" {
    var store = PropertyStore.init(std.testing.allocator);
    defer store.deinit();

    const channel = try Entity.init(.channel, "#onyx");
    try store.set(channel, "Topic", "Zig IRCX");

    const got = (try store.get(channel, "topic")).?;
    try std.testing.expectEqualStrings("#onyx", got.entity.id);
    try std.testing.expectEqual(EntityScope.channel, got.entity.scope);
    try std.testing.expectEqualStrings("Topic", got.name);
    try std.testing.expectEqualStrings("Zig IRCX", got.value);

    var out: [4]PropertyView = undefined;
    const listed = try store.list(channel, "To*", &out);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("Topic", listed[0].name);

    try std.testing.expectError(error.InvalidPropertyName, store.set(channel, "bad name", "value"));
    try std.testing.expectError(error.InvalidPropertyName, store.set(channel, "", "value"));
    try std.testing.expectError(error.InvalidPropertyValue, store.set(channel, "bad", "line\nbreak"));
}

test "ACCESS add/remove and hostmask match positive and negative" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    try store.add("#onyx", "*!user@*.example.net", .host);
    try store.add("#onyx", "friend!*@host.example.net", .voice);

    const hit = (try store.matchHostmask("#onyx", "nick!user@shell.example.net")).?;
    try std.testing.expectEqual(AccessLevel.host, hit.level);
    try std.testing.expectEqualStrings("*!user@*.example.net", hit.mask);

    try std.testing.expectEqual(@as(?AccessEntryView, null), try store.matchHostmask("#onyx", "nick!user@else.invalid"));

    try std.testing.expect(try store.remove("#onyx", "*!user@*.example.net"));
    try std.testing.expect(!try store.remove("#onyx", "*!user@*.example.net"));
    try std.testing.expectEqual(@as(?AccessEntryView, null), try store.matchHostmask("#onyx", "nick!user@shell.example.net"));
}

test "IRCX enable parse" {
    var state = ClientIrcxState{};
    const command = try applyIrcxLine(&state, "IRCX", 0x20);
    try std.testing.expectEqual(IrcxCommand.ircx, command);
    try std.testing.expect(state.enabled);
    try std.testing.expect(state.namesx);
    try std.testing.expectEqual(@as(u64, 0x20), state.capability_mask);

    try std.testing.expectEqual(IrcxCommand.isircx, try parseIrcxCommand("ISIRCX"));
    try std.testing.expectError(error.UnknownIrcxCommand, parseIrcxCommand("PING token"));
}

test "IRCX numeric metadata includes EVENT numerics" {
    try std.testing.expectEqualStrings("RPL_EVENTADD", numericByCode(808).?.name);
    try std.testing.expectEqualStrings("RPL_EVENTLIST", numericByCode(809).?.name);
    try std.testing.expectEqualStrings("RPL_EVENTEND", numericByCode(810).?.name);
    try std.testing.expectEqualStrings("ERR_EVENTDUP", numericByCode(821).?.name);
    try std.testing.expectEqualStrings("ERR_EVENTMIS", numericByCode(822).?.name);
    try std.testing.expectEqualStrings("ERR_NOSUCHEVENT", numericByCode(823).?.name);
    try std.testing.expectEqualStrings("RPL_EVENTDELETE", numericByCode(824).?.name);
    try std.testing.expectEqualStrings("RPL_EVENTCHANGE", numericByCode(825).?.name);
}
