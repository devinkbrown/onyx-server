// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified IRCv3 metadata and IRCX PROP property store.
//! Metadata and IRCX properties are one key/value system here: IRCv3 exposes
//! lower-case metadata keys, while IRCX PROP names are canonicalized onto those
//! same keys. The store owns retained bytes; lookup, visibility checks, and
//! notification fan-out use caller storage and do not allocate.
const std = @import("std");

pub const default_max_entity_bytes: usize = 128;
pub const default_max_key_bytes: usize = 64;
pub const default_max_value_bytes: usize = 512;
pub const default_max_keys_per_entity: usize = 64;
pub const default_max_subscriptions: usize = 64;

pub const default_restricted_keys = [_][]const u8{
    "ownerkey",
    "hostkey",
    "memberkey",
    "opkey",
    "aidekey",
    "voicekey",
};

pub const MetadataError = error{
    InvalidEntity,
    InvalidKey,
    InvalidValue,
    InvalidVisibility,
    KeyRestricted,
    KeyNotSet,
    LimitReached,
    TooManySubscriptions,
    NoPermission,
    OutputTooSmall,
};

/// Tunable store limits. Values are comptime so hot validation is branch-simple.
pub const Options = struct {
    max_entity_bytes: usize = default_max_entity_bytes,
    max_key_bytes: usize = default_max_key_bytes,
    max_value_bytes: usize = default_max_value_bytes,
    max_keys_per_entity: usize = default_max_keys_per_entity,
    max_subscriptions: usize = default_max_subscriptions,
    restricted_keys: []const []const u8 = &default_restricted_keys,
};

/// IRC metadata targets supported by the unified store.
pub const EntityKind = enum {
    user,
    channel,

    fn prefix(self: EntityKind) u8 {
        return switch (self) {
            .user => 'u',
            .channel => 'c',
        };
    }
};

/// Borrowed entity identifier. Names remain caller-owned.
pub const Entity = struct {
    kind: EntityKind,
    name: []const u8,
};

/// Visibility token emitted in IRCv3 METADATA/RPL_KEYVALUE replies.
pub const Visibility = enum {
    public,
    members,
    admins,
    server,
    secret,

    pub fn token(self: Visibility) []const u8 {
        return switch (self) {
            .public => "*",
            .members => "members",
            .admins => "admins",
            .server => "server",
            .secret => "secret",
        };
    }

    pub fn fromToken(raw: []const u8) ?Visibility {
        if (std.mem.eql(u8, raw, "*")) return .public;
        if (std.mem.eql(u8, raw, "members")) return .members;
        if (std.mem.eql(u8, raw, "admins")) return .admins;
        if (std.mem.eql(u8, raw, "server")) return .server;
        if (std.mem.eql(u8, raw, "secret")) return .secret;
        return null;
    }

    pub fn canRead(self: Visibility, access: Access) bool {
        return switch (self) {
            .public => true,
            .members => access.atLeast(.member),
            .admins => access.atLeast(.admin),
            .server => access.atLeast(.server),
            .secret => false,
        };
    }
};

/// Requester's relationship to a target for visibility filtering.
pub const Access = enum(u8) {
    public = 0,
    member = 1,
    admin = 2,
    server = 3,

    pub fn atLeast(self: Access, needed: Access) bool {
        return @backingInt(self) >= @backingInt(needed);
    }
};

/// Authority used for writes. Restricted keys require server authority.
pub const WriteAccess = enum(u8) {
    self = 0,
    channel_admin = 1,
    server = 2,

    fn canWriteRestricted(self: WriteAccess) bool {
        return self == .server;
    }
};

/// Stable view of a stored key. Slices are owned by the store.
pub const EntryView = struct {
    entity: Entity,
    key: []const u8,
    value: []const u8,
    visibility: Visibility,

    pub fn ircv3VisibilityToken(self: EntryView) []const u8 {
        return self.visibility.token();
    }
};

/// Change event used by dispatch code to produce IRCv3 METADATA notifications.
pub const Change = struct {
    entity: Entity,
    key: []const u8,
    value: ?[]const u8,
    visibility: Visibility,
};

/// Result of notification fan-out. `subscriber` is store-owned.
pub const Notification = struct {
    subscriber: []const u8,
    change: Change,
};

pub const PropView = struct {
    entity: Entity,
    prop: []const u8,
    entry: EntryView,
};

const IrcxProp = struct {
    prop: []const u8,
    key: []const u8,
    visibility: Visibility,
};

const ircx_props = [_]IrcxProp{
    .{ .prop = "OID", .key = "oid", .visibility = .server },
    .{ .prop = "Name", .key = "name", .visibility = .public },
    .{ .prop = "Creation", .key = "creation", .visibility = .public },
    .{ .prop = "Language", .key = "language", .visibility = .public },
    .{ .prop = "OwnerKey", .key = "ownerkey", .visibility = .secret },
    .{ .prop = "HostKey", .key = "hostkey", .visibility = .secret },
    .{ .prop = "MemberKey", .key = "memberkey", .visibility = .secret },
    .{ .prop = "OpKey", .key = "opkey", .visibility = .secret },
    .{ .prop = "AideKey", .key = "aidekey", .visibility = .secret },
    .{ .prop = "VoiceKey", .key = "voicekey", .visibility = .secret },
    .{ .prop = "PICS", .key = "pics", .visibility = .public },
    .{ .prop = "Topic", .key = "topic", .visibility = .public },
    .{ .prop = "Subject", .key = "subject", .visibility = .public },
    .{ .prop = "Client", .key = "client", .visibility = .public },
    .{ .prop = "OnJoin", .key = "onjoin", .visibility = .members },
    .{ .prop = "OnPart", .key = "onpart", .visibility = .members },
    .{ .prop = "Lag", .key = "lag", .visibility = .admins },
    .{ .prop = "Account", .key = "account", .visibility = .public },
    .{ .prop = "ClientGuid", .key = "clientguid", .visibility = .public },
    .{ .prop = "ServicePath", .key = "servicepath", .visibility = .server },
};

/// Owning metadata store. Instantiate as `MetadataStore(.{})`.
pub fn MetadataStore(comptime options: Options) type {
    if (options.max_entity_bytes == 0 or options.max_key_bytes == 0) {
        @compileError("metadata entity/key limits must be non-zero");
    }

    return struct {
        const Self = @This();
        const max_entity_map_key = options.max_entity_bytes + 2;

        allocator: std.mem.Allocator,
        entities: std.StringHashMap(EntityState),
        subscribers: std.StringHashMap(Subscriber),

        const EntityState = struct {
            kind: EntityKind,
            name: []u8,
            entries: std.StringHashMap(Entry),
            count: usize = 0,

            fn init(allocator: std.mem.Allocator, kind: EntityKind, name: []u8) EntityState {
                return .{
                    .kind = kind,
                    .name = name,
                    .entries = std.StringHashMap(Entry).init(allocator),
                };
            }

            fn deinit(self: *EntityState, allocator: std.mem.Allocator) void {
                var it = self.entries.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.deinit(allocator);
                }
                self.entries.deinit();
                allocator.free(self.name);
            }
        };

        const Entry = struct {
            value: []u8,
            visibility: Visibility,

            fn deinit(self: Entry, allocator: std.mem.Allocator) void {
                allocator.free(self.value);
            }
        };

        const Subscriber = struct {
            id: []u8,
            keys: std.StringHashMap(void),
            count: usize = 0,

            fn init(allocator: std.mem.Allocator, id: []u8) Subscriber {
                return .{
                    .id = id,
                    .keys = std.StringHashMap(void).init(allocator),
                };
            }

            fn deinit(self: *Subscriber, allocator: std.mem.Allocator) void {
                var it = self.keys.iterator();
                while (it.next()) |entry| allocator.free(entry.key_ptr.*);
                self.keys.deinit();
                allocator.free(self.id);
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .entities = std.StringHashMap(EntityState).init(allocator),
                .subscribers = std.StringHashMap(Subscriber).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var entity_it = self.entities.iterator();
            while (entity_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.entities.deinit();

            var sub_it = self.subscribers.iterator();
            while (sub_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.subscribers.deinit();
            self.* = undefined;
        }

        pub fn set(
            self: *Self,
            entity: Entity,
            key: []const u8,
            value: []const u8,
            visibility: Visibility,
            writer: WriteAccess,
        ) MetadataError!Change {
            try validateEntity(entity, options.max_entity_bytes);
            try validateKeyWithLimit(key, options.max_key_bytes);
            try validateValue(value, options.max_value_bytes);
            if (visibility == .secret and !writer.canWriteRestricted()) return error.KeyRestricted;

            const restricted = isRestrictedKey(key);
            if (restricted and !writer.canWriteRestricted()) return error.KeyRestricted;

            var state = try self.getOrCreateEntity(entity);
            const existing = state.entries.getEntry(key);
            if (existing == null and state.count >= options.max_keys_per_entity) return error.LimitReached;

            const stored_visibility: Visibility = if (restricted) .secret else visibility;
            const value_copy = self.allocator.dupe(u8, value) catch return error.LimitReached;
            errdefer self.allocator.free(value_copy);

            if (existing) |entry| {
                self.allocator.free(entry.value_ptr.value);
                entry.value_ptr.* = .{ .value = value_copy, .visibility = stored_visibility };
                return .{
                    .entity = .{ .kind = state.kind, .name = state.name },
                    .key = entry.key_ptr.*,
                    .value = entry.value_ptr.value,
                    .visibility = stored_visibility,
                };
            }

            const key_copy = self.allocator.dupe(u8, key) catch return error.LimitReached;
            errdefer self.allocator.free(key_copy);

            const gop = state.entries.getOrPut(key) catch return error.LimitReached;
            if (gop.found_existing) {
                self.allocator.free(gop.value_ptr.value);
                gop.value_ptr.* = .{ .value = value_copy, .visibility = stored_visibility };
                return .{
                    .entity = .{ .kind = state.kind, .name = state.name },
                    .key = gop.key_ptr.*,
                    .value = gop.value_ptr.value,
                    .visibility = stored_visibility,
                };
            }

            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .{ .value = value_copy, .visibility = stored_visibility };
            state.count += 1;
            return .{
                .entity = .{ .kind = state.kind, .name = state.name },
                .key = gop.key_ptr.*,
                .value = gop.value_ptr.value,
                .visibility = stored_visibility,
            };
        }

        /// Return a visible metadata key. Hidden existing keys fail with permission.
        pub fn get(self: *const Self, entity: Entity, key: []const u8, access: Access) MetadataError!?EntryView {
            try validateEntity(entity, options.max_entity_bytes);
            try validateKeyWithLimit(key, options.max_key_bytes);

            const state = self.getEntity(entity) orelse return null;
            const entry = state.entries.getEntry(key) orelse return null;
            if (!entry.value_ptr.visibility.canRead(access)) return error.NoPermission;

            return view(state, entry);
        }

        /// List visible metadata entries into caller-owned output.
        pub fn list(
            self: *const Self,
            entity: Entity,
            access: Access,
            out: []EntryView,
        ) MetadataError![]EntryView {
            try validateEntity(entity, options.max_entity_bytes);
            const state = self.getEntity(entity) orelse return out[0..0];

            var count: usize = 0;
            var it = state.entries.iterator();
            while (it.next()) |entry| {
                if (!entry.value_ptr.visibility.canRead(access)) continue;
                if (count >= out.len) return error.OutputTooSmall;
                out[count] = view(state, entry);
                count += 1;
            }
            return out[0..count];
        }

        /// Clear one metadata key. `false` means it was already absent.
        pub fn clearKey(self: *Self, entity: Entity, key: []const u8, writer: WriteAccess) MetadataError!bool {
            try validateEntity(entity, options.max_entity_bytes);
            try validateKeyWithLimit(key, options.max_key_bytes);
            if (isRestrictedKey(key) and !writer.canWriteRestricted()) return error.KeyRestricted;

            const state = self.getEntityMut(entity) orelse return false;
            if (state.entries.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                removed.value.deinit(self.allocator);
                state.count -= 1;
                return true;
            }
            return false;
        }

        /// Clear all keys on a target.
        pub fn clear(self: *Self, entity: Entity, writer: WriteAccess) MetadataError!usize {
            try validateEntity(entity, options.max_entity_bytes);
            const state = self.getEntityMut(entity) orelse return 0;

            var cleared: usize = 0;
            var it = state.entries.iterator();
            while (it.next()) |entry| {
                if (isRestrictedKey(entry.key_ptr.*) and !writer.canWriteRestricted()) return error.KeyRestricted;
            }

            var drain = state.entries.iterator();
            while (drain.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
                cleared += 1;
            }
            state.entries.clearRetainingCapacity();
            state.count = 0;
            return cleared;
        }

        /// Subscribe a client to metadata keys, processing keys in order.
        pub fn subscribe(self: *Self, subscriber_id: []const u8, keys: []const []const u8) MetadataError!usize {
            try validateSubscriberId(subscriber_id);
            var sub = try self.getOrCreateSubscriber(subscriber_id);

            var accepted: usize = 0;
            for (keys) |key| {
                try validateKeyWithLimit(key, options.max_key_bytes);
                if (sub.keys.contains(key)) {
                    accepted += 1;
                    continue;
                }
                if (sub.count >= options.max_subscriptions) return error.TooManySubscriptions;

                const key_copy = self.allocator.dupe(u8, key) catch return error.LimitReached;
                errdefer self.allocator.free(key_copy);
                const gop = sub.keys.getOrPut(key) catch return error.LimitReached;
                if (gop.found_existing) {
                    self.allocator.free(key_copy);
                } else {
                    gop.key_ptr.* = key_copy;
                    gop.value_ptr.* = {};
                    sub.count += 1;
                }
                accepted += 1;
            }
            return accepted;
        }

        /// Unsubscribe a client from metadata keys. Missing keys are successful.
        pub fn unsubscribe(self: *Self, subscriber_id: []const u8, keys: []const []const u8) MetadataError!usize {
            try validateSubscriberId(subscriber_id);
            var sub = self.subscribers.getPtr(subscriber_id) orelse return keys.len;

            for (keys) |key| {
                try validateKeyWithLimit(key, options.max_key_bytes);
                if (sub.keys.fetchRemove(key)) |removed| {
                    self.allocator.free(removed.key);
                    sub.count -= 1;
                }
            }
            return keys.len;
        }

        /// List a subscriber's keys into caller-owned output.
        pub fn subscriptions(
            self: *const Self,
            subscriber_id: []const u8,
            out: [][]const u8,
        ) MetadataError![][]const u8 {
            try validateSubscriberId(subscriber_id);
            const sub = self.subscribers.getPtr(subscriber_id) orelse return out[0..0];

            var count: usize = 0;
            var it = sub.keys.iterator();
            while (it.next()) |entry| {
                if (count >= out.len) return error.OutputTooSmall;
                out[count] = entry.key_ptr.*;
                count += 1;
            }
            return out[0..count];
        }

        /// Build notification recipients for a change. Reachability filtering
        /// (same-channel, monitor, self) belongs to the daemon; this enforces
        /// subscription and visibility only.
        pub fn notify(
            self: *const Self,
            change: Change,
            access: Access,
            out: []Notification,
        ) MetadataError![]Notification {
            try validateEntity(change.entity, options.max_entity_bytes);
            try validateKeyWithLimit(change.key, options.max_key_bytes);
            if (!change.visibility.canRead(access)) return out[0..0];

            var count: usize = 0;
            var it = self.subscribers.iterator();
            while (it.next()) |entry| {
                if (!entry.value_ptr.keys.contains(change.key)) continue;
                if (count >= out.len) return error.OutputTooSmall;
                out[count] = .{ .subscriber = entry.value_ptr.id, .change = change };
                count += 1;
            }
            return out[0..count];
        }

        /// IRCX PROP read over the unified metadata keys.
        pub fn propGet(self: *const Self, entity: Entity, prop_name: []const u8, access: Access) MetadataError!?PropView {
            const prop = try propSpec(prop_name);
            const entry = (try self.get(entity, prop.key, access)) orelse return null;
            return .{ .entity = entry.entity, .prop = prop.prop, .entry = entry };
        }

        /// IRCX PROP write over the unified metadata keys.
        pub fn propSet(
            self: *Self,
            entity: Entity,
            prop_name: []const u8,
            value: []const u8,
            writer: WriteAccess,
        ) MetadataError!Change {
            const prop = try propSpec(prop_name);
            return self.set(entity, prop.key, value, prop.visibility, writer);
        }

        /// IRCX PROP clear over the unified metadata keys.
        pub fn propClear(self: *Self, entity: Entity, prop_name: []const u8, writer: WriteAccess) MetadataError!bool {
            const prop = try propSpec(prop_name);
            return self.clearKey(entity, prop.key, writer);
        }

        /// IRCX PROP `*` listing over visible metadata entries.
        pub fn propList(self: *const Self, entity: Entity, access: Access, out: []PropView) MetadataError![]PropView {
            try validateEntity(entity, options.max_entity_bytes);
            const state = self.getEntity(entity) orelse return out[0..0];

            var count: usize = 0;
            for (ircx_props) |prop| {
                const entry = state.entries.getEntry(prop.key) orelse continue;
                if (!entry.value_ptr.visibility.canRead(access)) continue;
                if (count >= out.len) return error.OutputTooSmall;
                out[count] = .{ .entity = .{ .kind = state.kind, .name = state.name }, .prop = prop.prop, .entry = view(state, entry) };
                count += 1;
            }
            return out[0..count];
        }

        pub fn isRestricted(self: *const Self, key: []const u8) MetadataError!bool {
            _ = self;
            try validateKeyWithLimit(key, options.max_key_bytes);
            return isRestrictedKey(key);
        }

        fn getEntity(self: *const Self, entity: Entity) ?*const EntityState {
            var key_buf: [max_entity_map_key]u8 = undefined;
            const entity_key = writeEntityKey(&key_buf, entity) catch return null;
            return self.entities.getPtr(entity_key);
        }

        fn getEntityMut(self: *Self, entity: Entity) ?*EntityState {
            var key_buf: [max_entity_map_key]u8 = undefined;
            const entity_key = writeEntityKey(&key_buf, entity) catch return null;
            return self.entities.getPtr(entity_key);
        }

        fn getOrCreateEntity(self: *Self, entity: Entity) MetadataError!*EntityState {
            var key_buf: [max_entity_map_key]u8 = undefined;
            const entity_key = try writeEntityKey(&key_buf, entity);
            if (self.entities.getPtr(entity_key)) |state| return state;

            const map_key = self.allocator.dupe(u8, entity_key) catch return error.LimitReached;
            errdefer self.allocator.free(map_key);
            const name_copy = self.allocator.dupe(u8, entity.name) catch return error.LimitReached;
            errdefer self.allocator.free(name_copy);

            const gop = self.entities.getOrPut(entity_key) catch return error.LimitReached;
            if (gop.found_existing) {
                self.allocator.free(map_key);
                self.allocator.free(name_copy);
                return gop.value_ptr;
            }
            gop.key_ptr.* = map_key;
            gop.value_ptr.* = EntityState.init(self.allocator, entity.kind, name_copy);
            return gop.value_ptr;
        }

        fn getOrCreateSubscriber(self: *Self, subscriber_id: []const u8) MetadataError!*Subscriber {
            if (self.subscribers.getPtr(subscriber_id)) |sub| return sub;

            const map_key = self.allocator.dupe(u8, subscriber_id) catch return error.LimitReached;
            errdefer self.allocator.free(map_key);
            const id_copy = self.allocator.dupe(u8, subscriber_id) catch return error.LimitReached;
            errdefer self.allocator.free(id_copy);

            const gop = self.subscribers.getOrPut(subscriber_id) catch return error.LimitReached;
            if (gop.found_existing) {
                self.allocator.free(map_key);
                self.allocator.free(id_copy);
                return gop.value_ptr;
            }
            gop.key_ptr.* = map_key;
            gop.value_ptr.* = Subscriber.init(self.allocator, id_copy);
            return gop.value_ptr;
        }

        fn isRestrictedKey(key: []const u8) bool {
            var matched: u8 = 0;
            inline for (options.restricted_keys) |restricted| {
                matched |= ctEqlAscii(key, restricted);
            }
            return matched != 0;
        }

        fn writeEntityKey(out: []u8, entity: Entity) MetadataError![]const u8 {
            if (out.len < entity.name.len + 2) return error.InvalidEntity;
            out[0] = entity.kind.prefix();
            out[1] = ':';
            @memcpy(out[2..][0..entity.name.len], entity.name);
            return out[0 .. entity.name.len + 2];
        }

        fn view(state: *const EntityState, entry: std.StringHashMap(Entry).Entry) EntryView {
            return .{
                .entity = .{ .kind = state.kind, .name = state.name },
                .key = entry.key_ptr.*,
                .value = entry.value_ptr.value,
                .visibility = entry.value_ptr.visibility,
            };
        }
    };
}

pub const DefaultStore = MetadataStore(.{});

pub fn validateKey(key: []const u8) MetadataError!void {
    try validateKeyWithLimit(key, default_max_key_bytes);
}

pub fn validateEntity(entity: Entity, max_entity_bytes: usize) MetadataError!void {
    if (entity.name.len == 0 or entity.name.len > max_entity_bytes) return error.InvalidEntity;
    for (entity.name) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ',' or byte == ':') return error.InvalidEntity;
    }
    switch (entity.kind) {
        .channel => {
            if (entity.name[0] != '#' and entity.name[0] != '&') return error.InvalidEntity;
        },
        .user => {
            if (entity.name[0] == '#' or entity.name[0] == '&') return error.InvalidEntity;
        },
    }
}

fn validateSubscriberId(id: []const u8) MetadataError!void {
    if (id.len == 0 or id.len > default_max_entity_bytes) return error.InvalidEntity;
    for (id) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidEntity;
    }
}

fn validateKeyWithLimit(key: []const u8, max_key_bytes: usize) MetadataError!void {
    if (key.len == 0 or key.len > max_key_bytes) return error.InvalidKey;
    for (key) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '.' or byte == '/' or byte == '-';
        if (!ok) return error.InvalidKey;
    }
}

fn validateValue(value: []const u8, max_value_bytes: usize) MetadataError!void {
    if (value.len > max_value_bytes) return error.InvalidValue;
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidValue;
}

fn propSpec(prop_name: []const u8) MetadataError!IrcxProp {
    if (prop_name.len == 0) return error.InvalidKey;
    for (ircx_props) |prop| {
        if (std.ascii.eqlIgnoreCase(prop.prop, prop_name) or std.ascii.eqlIgnoreCase(prop.key, prop_name)) return prop;
    }
    try validateKeyWithLimit(prop_name, default_max_key_bytes);
    return .{ .prop = prop_name, .key = prop_name, .visibility = .public };
}

fn ctEqlAscii(a: []const u8, b: []const u8) u8 {
    var diff: usize = a.len ^ b.len;
    const max = @max(a.len, b.len);
    var i: usize = 0;
    while (i < max) : (i += 1) {
        const ca = if (i < a.len) std.ascii.toLower(a[i]) else 0;
        const cb = if (i < b.len) std.ascii.toLower(b[i]) else 0;
        diff |= @as(usize, ca ^ cb);
    }
    return @intFromBool(diff == 0);
}

test "set get and clear metadata" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const alice = Entity{ .kind = .user, .name = "alice" };
    const change = try store.set(alice, "display-name", "Alice A.", .public, .self);
    try std.testing.expectEqualStrings("display-name", change.key);
    try std.testing.expectEqualStrings("Alice A.", change.value.?);
    try std.testing.expectEqualStrings("*", change.visibility.token());

    const got = (try store.get(alice, "display-name", .public)).?;
    try std.testing.expectEqualStrings("Alice A.", got.value);

    try std.testing.expect(try store.clearKey(alice, "display-name", .self));
    try std.testing.expectEqual(@as(?EntryView, null), try store.get(alice, "display-name", .public));
}

test "subscriptions feed notification list" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const keys = [_][]const u8{ "topic", "url" };
    try std.testing.expectEqual(@as(usize, 2), try store.subscribe("client-a", &keys));
    try std.testing.expectEqual(@as(usize, 1), try store.subscribe("client-b", &[_][]const u8{"url"}));

    const room = Entity{ .kind = .channel, .name = "#zig" };
    const change = try store.set(room, "topic", "Zig 0.16", .public, .channel_admin);

    var out: [4]Notification = undefined;
    const notifications = try store.notify(change, .public, &out);
    try std.testing.expectEqual(@as(usize, 1), notifications.len);
    try std.testing.expectEqualStrings("client-a", notifications[0].subscriber);
    try std.testing.expectEqualStrings("topic", notifications[0].change.key);

    _ = try store.unsubscribe("client-a", &[_][]const u8{"topic"});
    try std.testing.expectEqual(@as(usize, 0), (try store.notify(change, .public, &out)).len);
}

test "key validation and restricted keys" {
    try validateKey("im.xmpp");
    try validateKey("client/status-v1");
    try std.testing.expectError(error.InvalidKey, validateKey(""));
    try std.testing.expectError(error.InvalidKey, validateKey("BadKey"));
    try std.testing.expectError(error.InvalidKey, validateKey("bad key"));
    try std.testing.expectError(error.InvalidKey, validateKey("bad$key"));

    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const room = Entity{ .kind = .channel, .name = "#ops" };
    try std.testing.expect(try store.isRestricted("ownerkey"));
    try std.testing.expectError(error.KeyRestricted, store.set(room, "ownerkey", "secret", .secret, .channel_admin));

    const change = try store.set(room, "ownerkey", "secret", .secret, .server);
    try std.testing.expectEqual(.secret, change.visibility);
    try std.testing.expectError(error.NoPermission, store.get(room, "ownerkey", .server));
}

test "IRCX PROP access shares the metadata store" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const room = Entity{ .kind = .channel, .name = "#chat" };
    _ = try store.propSet(room, "Topic", "same bytes", .channel_admin);

    const via_metadata = (try store.get(room, "topic", .public)).?;
    try std.testing.expectEqualStrings("same bytes", via_metadata.value);

    const via_prop = (try store.propGet(room, "topic", .public)).?;
    try std.testing.expectEqualStrings("Topic", via_prop.prop);
    try std.testing.expectEqualStrings(via_metadata.value, via_prop.entry.value);

    var props: [8]PropView = undefined;
    const listed = try store.propList(room, .public, &props);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("Topic", listed[0].prop);
}

test "limits are enforced" {
    const TinyStore = MetadataStore(.{
        .max_entity_bytes = 16,
        .max_key_bytes = 8,
        .max_value_bytes = 4,
        .max_keys_per_entity = 2,
        .max_subscriptions = 1,
    });
    var store = TinyStore.init(std.testing.allocator);
    defer store.deinit();

    const bob = Entity{ .kind = .user, .name = "bob" };
    try std.testing.expectError(error.InvalidValue, store.set(bob, "a", "12345", .public, .self));
    _ = try store.set(bob, "a", "1", .public, .self);
    _ = try store.set(bob, "b", "2", .public, .self);
    try std.testing.expectError(error.LimitReached, store.set(bob, "c", "3", .public, .self));
    try std.testing.expectError(error.InvalidKey, store.set(bob, "toolongkey", "3", .public, .self));

    try std.testing.expectEqual(@as(usize, 1), try store.subscribe("client", &[_][]const u8{"a"}));
    try std.testing.expectError(error.TooManySubscriptions, store.subscribe("client", &[_][]const u8{"b"}));
}

test "clear all and deinit release allocator-owned bytes" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const room = Entity{ .kind = .channel, .name = "#leaks" };
    _ = try store.set(room, "topic", "one", .public, .channel_admin);
    _ = try store.set(room, "url", "https://example.invalid", .public, .channel_admin);
    try std.testing.expectEqual(@as(usize, 2), try store.clear(room, .channel_admin));
    var entries: [2]EntryView = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try store.list(room, .public, &entries)).len);
}
