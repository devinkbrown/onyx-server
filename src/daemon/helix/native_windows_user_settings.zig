// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Windows Helix custody for RAM-only account and operator settings.
//! Capture runs under the server's accepted-event cut. A successor validates
//! and stages every replacement before COMMIT, then swaps them without alloc.

const std = @import("std");
const autojoin = @import("../autojoin.zig");
const memo_group = @import("../memo_group.zig");
const welcome_pack = @import("../welcome_pack.zig");
const host_request = @import("../host_request.zig");
const slash_cmd = @import("../slash_cmd.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'U', 'S' };
const domain = "onyx-native-windows-user-settings-v1";
const header_len: usize = 88;
pub const max_checkpoint_bytes: usize = wire.max_checkpoint_bytes;
pub const Error = wire.Error || error{ConfigMismatch};

comptime {
    assertFieldNames(autojoin.Params, &.{ "max_accounts", "max_account_bytes", "max_channel_bytes", "max_channels_per_account" });
    assertFieldNames(welcome_pack.Params, &.{ "max_lines", "max_line_bytes", "max_accounts", "max_account_bytes" });
    assertFieldNames(host_request.Params, &.{ "max_requests", "max_account_bytes", "min_vhost_bytes", "max_vhost_bytes", "max_reason_bytes" });
}

fn assertFieldNames(comptime T: type, comptime expected: []const []const u8) void {
    const actual = @typeInfo(T).@"struct".field_names;
    if (actual.len != expected.len) @compileError("HXUS policy layout changed; bump checkpoint version and header");
    inline for (expected, 0..) |name, index| {
        if (!std.mem.eql(u8, actual[index], name)) @compileError("HXUS policy layout changed; bump checkpoint version and header");
    }
}

const Header = struct {
    auto_count: usize,
    group_count: usize,
    line_count: usize,
    delivered_count: usize,
    host_count: usize,
    slash_count: usize,
    auto_params: autojoin.Params,
    welcome_params: welcome_pack.Params,
    host_params: host_request.Params,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

/// Allocation-free semantic validation, including canonical account order,
/// duplicate detection, policy bounds, slash holes, and request phases.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const h = try readHeader(bytes);
    var reader = wire.Reader{ .bytes = body };
    var previous: ?[]const u8 = null;
    for (0..h.auto_count) |_| {
        const account_len = try reader.readU16();
        const channel_count = try reader.readU16();
        const account = try reader.take(account_len);
        try checkAutoAccount(account, channel_count, h.auto_params);
        try advanceFolded(&previous, account);
        // Configured limits may exceed a fixed stack bound. Compare directly
        // with the already parsed prefix instead of storing a second copy.
        const channels_start = reader.pos;
        for (0..channel_count) |index| {
            const len = try reader.readU16();
            const channel = try reader.take(len);
            try checkAutoChannel(channel, h.auto_params);
            var scan = wire.Reader{ .bytes = body[channels_start..reader.pos] };
            for (0..index) |_| {
                const old_len = try scan.readU16();
                const old = try scan.take(old_len);
                if (std.ascii.eqlIgnoreCase(old, channel)) return error.DuplicateEntry;
            }
        }
    }
    previous = null;
    for (0..h.group_count) |_| {
        const account_len = try reader.readU16();
        const nick_count = try reader.readU16();
        const primary = try reader.readU16();
        const account = try reader.take(account_len);
        try checkGroupAccount(account, nick_count, primary);
        try advanceExact(&previous, account);
        const nicks_start = reader.pos;
        for (0..nick_count) |index| {
            const len = try reader.readU16();
            const nick = try reader.take(len);
            if (nick.len == 0 or nick.len > group_params.max_nick_bytes) return error.InvalidField;
            var scan = wire.Reader{ .bytes = body[nicks_start..reader.pos] };
            for (0..index) |_| {
                const old_len = try scan.readU16();
                const old = try scan.take(old_len);
                if (std.mem.eql(u8, old, nick)) return error.DuplicateEntry;
            }
        }
    }
    for (0..h.line_count) |_| {
        const len = try reader.readU16();
        const line = try reader.take(len);
        if (line.len == 0 or line.len > h.welcome_params.max_line_bytes) return error.InvalidField;
    }
    previous = null;
    for (0..h.delivered_count) |_| {
        const len = try reader.readU16();
        const account = try reader.take(len);
        if (account.len == 0 or account.len > h.welcome_params.max_account_bytes) return error.InvalidField;
        try advanceExact(&previous, account);
    }
    previous = null;
    for (0..h.host_count) |_| {
        const record = try readHost(&reader);
        try checkHost(record, h.host_params);
        try advanceFolded(&previous, record.account);
    }
    var previous_slot: ?usize = null;
    var seen: [slash_cmd.max_cmds]SlashRecord = undefined;
    var seen_count: usize = 0;
    for (0..h.slash_count) |_| {
        const record = try readSlash(&reader);
        try checkSlash(record);
        if (previous_slot) |slot| if (record.slot <= slot) return error.NonCanonicalOrder;
        previous_slot = record.slot;
        for (seen[0..seen_count]) |old| {
            if (std.ascii.eqlIgnoreCase(old.account, record.account) and
                std.ascii.eqlIgnoreCase(old.name, record.name)) return error.DuplicateEntry;
        }
        seen[seen_count] = record;
        seen_count += 1;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

const group_params: memo_group.Params = .{};

/// Build one deterministic, self-checking checkpoint from the frozen source.
pub fn encode(
    allocator: std.mem.Allocator,
    auto: *const autojoin.AutoJoin,
    groups: *const memo_group.NickGroup,
    welcome: *const welcome_pack.WelcomePack,
    hosts: *const host_request.Queue,
    slash: *const slash_cmd.Table,
) Error![]u8 {
    const h = try sourceHeader(auto, groups, welcome, hosts, slash);
    const auto_keys = try sortedKeys(allocator, &auto.accounts, true);
    defer allocator.free(auto_keys);
    const group_keys = try sortedKeys(allocator, &groups.accounts, false);
    defer allocator.free(group_keys);
    const delivered_keys = try sortedKeys(allocator, &welcome.delivered, false);
    defer allocator.free(delivered_keys);
    const host_keys = try sortedKeys(allocator, &hosts.requests, false);
    defer allocator.free(host_keys);

    var size: usize = header_len + wire.checksum_len;
    for (auto_keys) |account| {
        const channels = auto.accounts.get(account).?.channels.items;
        try checkAutoAccount(account, channels.len, h.auto_params);
        try boundedU16(account.len);
        try boundedU16(channels.len);
        try wire.addLen(&size, 4 + account.len);
        for (channels) |channel| {
            try checkAutoChannel(channel, h.auto_params);
            try boundedU16(channel.len);
            try wire.addLen(&size, 2 + channel.len);
        }
    }
    for (group_keys) |account| {
        const state = groups.accounts.get(account).?;
        try checkGroupAccount(account, state.nicks.items.len, state.primary_index);
        try boundedU16(account.len);
        try wire.addLen(&size, 6 + account.len);
        for (state.nicks.items) |nick| {
            if (nick.len == 0 or nick.len > group_params.max_nick_bytes) return error.InvalidField;
            try boundedU16(nick.len);
            try wire.addLen(&size, 2 + nick.len);
        }
    }
    for (welcome.pack_lines.items) |line| {
        if (line.len == 0 or line.len > h.welcome_params.max_line_bytes) return error.InvalidField;
        try boundedU16(line.len);
        try wire.addLen(&size, 2 + line.len);
    }
    for (delivered_keys) |account| {
        if (account.len == 0 or account.len > h.welcome_params.max_account_bytes) return error.InvalidField;
        try boundedU16(account.len);
        try wire.addLen(&size, 2 + account.len);
    }
    for (host_keys) |key| {
        const request = hosts.requests.get(key).?;
        const record = HostRecord.fromRequest(request);
        try checkHost(record, h.host_params);
        try boundedU16(record.account.len);
        try boundedU16(record.vhost.len);
        try boundedU16(record.reason.len);
        try wire.addLen(&size, 23 + record.account.len + record.vhost.len + record.reason.len);
    }
    for (slash.slots) |*slot| {
        if (!slot.used) continue;
        const record = SlashRecord.fromSlot(slot);
        try checkSlash(record);
        try wire.addLen(&size, 5 + record.account.len + record.name.len + record.help.len);
    }
    if (size > max_checkpoint_bytes) return error.CheckpointTooLarge;

    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writeHeader(&writer, h, size - header_len - wire.checksum_len);
    for (auto_keys) |account| {
        const channels = auto.accounts.get(account).?.channels.items;
        writer.writeU16(@intCast(account.len));
        writer.writeU16(@intCast(channels.len));
        writer.writeBytes(account);
        for (channels) |channel| {
            writer.writeU16(@intCast(channel.len));
            writer.writeBytes(channel);
        }
    }
    for (group_keys) |account| {
        const state = groups.accounts.get(account).?;
        writer.writeU16(@intCast(account.len));
        writer.writeU16(@intCast(state.nicks.items.len));
        writer.writeU16(@intCast(state.primary_index));
        writer.writeBytes(account);
        for (state.nicks.items) |nick| {
            writer.writeU16(@intCast(nick.len));
            writer.writeBytes(nick);
        }
    }
    for (welcome.pack_lines.items) |line| {
        writer.writeU16(@intCast(line.len));
        writer.writeBytes(line);
    }
    for (delivered_keys) |account| {
        writer.writeU16(@intCast(account.len));
        writer.writeBytes(account);
    }
    for (host_keys) |key| {
        const r = hosts.requests.get(key).?;
        writer.writeU16(@intCast(r.account.len));
        writer.writeU16(@intCast(r.vhost.len));
        writer.writeU16(@intCast(r.reason.len));
        writer.writeByte(@intFromEnum(r.status));
        writer.writeI64(r.requested_ms);
        writer.writeI64(r.decided_ms);
        writer.writeBytes(r.account);
        writer.writeBytes(r.vhost);
        writer.writeBytes(r.reason);
    }
    for (slash.slots, 0..) |*slot, index| {
        if (!slot.used) continue;
        const r = SlashRecord.fromSlot(slot);
        writer.writeByte(@intCast(index));
        writer.writeByte(@intCast(r.account.len));
        writer.writeByte(@intCast(r.name.len));
        writer.writeByte(@intCast(r.help.len));
        writer.writeByte(r.argc);
        writer.writeBytes(r.account);
        writer.writeBytes(r.name);
        writer.writeBytes(r.help);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub const Staged = struct {
    target_auto: *autojoin.AutoJoin,
    target_groups: *memo_group.NickGroup,
    target_welcome: *welcome_pack.WelcomePack,
    target_hosts: *host_request.Queue,
    target_slash: *slash_cmd.Table,
    auto: autojoin.AutoJoin,
    groups: memo_group.NickGroup,
    welcome: welcome_pack.WelcomePack,
    hosts: host_request.Queue,
    slash: slash_cmd.Table,
    committed: bool = false,

    pub fn commit(self: *Staged) void {
        std.debug.assert(!self.committed);
        std.mem.swap(autojoin.AutoJoin, &self.auto, self.target_auto);
        std.mem.swap(memo_group.NickGroup, &self.groups, self.target_groups);
        std.mem.swap(welcome_pack.WelcomePack, &self.welcome, self.target_welcome);
        std.mem.swap(host_request.Queue, &self.hosts, self.target_hosts);
        std.mem.swap(slash_cmd.Table, &self.slash, self.target_slash);
        self.committed = true;
    }

    pub fn deinit(self: *Staged) void {
        self.auto.deinit();
        self.groups.deinit();
        self.welcome.deinit();
        self.hosts.deinit();
        self.slash.deinit();
        self.* = undefined;
    }
};

/// A malformed or policy-mismatched checkpoint returns before allocating.
/// Each candidate is fully owned until the no-fail commit swaps all five.
pub fn stageFor(
    bytes: []const u8,
    auto: *autojoin.AutoJoin,
    groups: *memo_group.NickGroup,
    welcome: *welcome_pack.WelcomePack,
    hosts: *host_request.Queue,
    slash: *slash_cmd.Table,
) Error!Staged {
    try validateCheckpoint(bytes);
    const h = try readHeader(bytes);
    if (!std.meta.eql(h.auto_params, auto.params) or
        !std.meta.eql(h.welcome_params, welcome.params) or
        !std.meta.eql(h.host_params, hosts.params) or slash.slots.len != slash_cmd.max_cmds)
        return error.ConfigMismatch;
    var result: Staged = .{
        .target_auto = auto,
        .target_groups = groups,
        .target_welcome = welcome,
        .target_hosts = hosts,
        .target_slash = slash,
        .auto = autojoin.AutoJoin.initWithParams(auto.allocator, auto.params),
        .groups = memo_group.NickGroup.init(groups.allocator),
        .welcome = welcome_pack.WelcomePack.initParams(welcome.allocator, welcome.params),
        .hosts = host_request.Queue.init(hosts.allocator, hosts.params),
        .slash = try slash_cmd.Table.init(slash.allocator),
    };
    errdefer result.deinit();

    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..h.auto_count) |_| {
        const account_len = try reader.readU16();
        const channel_count = try reader.readU16();
        const account = try reader.take(account_len);
        for (0..channel_count) |_| {
            const len = try reader.readU16();
            result.auto.add(account, try reader.take(len)) catch |err| return mapStoreError(err);
        }
    }
    for (0..h.group_count) |_| {
        const account_len = try reader.readU16();
        const nick_count = try reader.readU16();
        const primary = try reader.readU16();
        const account = try reader.take(account_len);
        var primary_nick: []const u8 = undefined;
        for (0..nick_count) |index| {
            const len = try reader.readU16();
            const nick = try reader.take(len);
            const added = result.groups.add(account, nick) catch |err| return mapStoreError(err);
            if (!added) return error.DuplicateEntry;
            if (index == primary) primary_nick = nick;
        }
        result.groups.setPrimary(account, primary_nick) catch |err| return mapStoreError(err);
    }
    for (0..h.line_count) |_| {
        const len = try reader.readU16();
        const line = try reader.take(len);
        const owned = try result.welcome.allocator.dupe(u8, line);
        result.welcome.pack_lines.append(result.welcome.allocator, owned) catch |err| {
            result.welcome.allocator.free(owned);
            return err;
        };
    }
    for (0..h.delivered_count) |_| {
        const len = try reader.readU16();
        result.welcome.markDelivered(try reader.take(len)) catch |err| return mapStoreError(err);
    }
    for (0..h.host_count) |_| {
        const r = try readHost(&reader);
        result.hosts.submit(r.account, r.vhost, r.requested_ms) catch |err| return mapStoreError(err);
        switch (r.status) {
            .pending => {},
            .approved => result.hosts.approve(r.account, r.decided_ms) catch |err| return mapStoreError(err),
            .denied => result.hosts.deny(r.account, r.reason, r.decided_ms) catch |err| return mapStoreError(err),
        }
    }
    for (0..h.slash_count) |_| {
        const r = try readSlash(&reader);
        result.slash.restoreAt(r.slot, r.account, r.name, r.help, r.argc) catch |err| return mapStoreError(err);
    }
    std.debug.assert(reader.remaining() == 0);
    return result;
}

fn mapStoreError(err: anyerror) Error {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidField;
}

fn boundedU16(len: usize) Error!void {
    if (len > std.math.maxInt(u16)) return error.CheckpointTooLarge;
}

fn asU32(value: usize) Error!u32 {
    if (value > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    return @intCast(value);
}

fn sourceHeader(auto: *const autojoin.AutoJoin, groups: *const memo_group.NickGroup, welcome: *const welcome_pack.WelcomePack, hosts: *const host_request.Queue, slash: *const slash_cmd.Table) Error!Header {
    if (slash.slots.len != slash_cmd.max_cmds or hosts.count != hosts.requests.count()) return error.InvalidField;
    var slash_count: usize = 0;
    for (slash.slots) |slot| if (slot.used) {
        slash_count += 1;
    };
    const h: Header = .{
        .auto_count = auto.accounts.count(),
        .group_count = groups.accounts.count(),
        .line_count = welcome.pack_lines.items.len,
        .delivered_count = welcome.delivered.count(),
        .host_count = hosts.count,
        .slash_count = slash_count,
        .auto_params = auto.params,
        .welcome_params = welcome.params,
        .host_params = hosts.params,
    };
    try checkHeader(h);
    return h;
}

fn checkHeader(h: Header) Error!void {
    if (h.auto_count > h.auto_params.max_accounts or h.group_count > group_params.max_accounts or
        h.line_count > h.welcome_params.max_lines or h.delivered_count > h.welcome_params.max_accounts or
        h.host_count > h.host_params.max_requests or h.slash_count > slash_cmd.max_cmds or
        h.host_params.min_vhost_bytes > h.host_params.max_vhost_bytes) return error.InvalidField;
    _ = try asU32(h.auto_count);
    _ = try asU32(h.group_count);
    _ = try asU32(h.line_count);
    _ = try asU32(h.delivered_count);
    _ = try asU32(h.host_count);
    _ = try asU32(h.slash_count);
    inline for (@typeInfo(autojoin.Params).@"struct".field_names) |name| _ = try asU32(@field(h.auto_params, name));
    inline for (@typeInfo(welcome_pack.Params).@"struct".field_names) |name| _ = try asU32(@field(h.welcome_params, name));
    inline for (@typeInfo(host_request.Params).@"struct".field_names) |name| _ = try asU32(@field(h.host_params, name));
}

fn writeHeader(writer: *wire.Writer, h: Header, body_len: usize) void {
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(body_len));
    writer.writeU32(@intCast(h.auto_count));
    writer.writeU32(@intCast(h.group_count));
    writer.writeU32(@intCast(h.line_count));
    writer.writeU32(@intCast(h.delivered_count));
    writer.writeU32(@intCast(h.host_count));
    writer.writeU32(@intCast(h.slash_count));
    inline for (@typeInfo(autojoin.Params).@"struct".field_names) |name| writer.writeU32(@intCast(@field(h.auto_params, name)));
    inline for (@typeInfo(welcome_pack.Params).@"struct".field_names) |name| writer.writeU32(@intCast(@field(h.welcome_params, name)));
    inline for (@typeInfo(host_request.Params).@"struct".field_names) |name| writer.writeU32(@intCast(@field(h.host_params, name)));
    std.debug.assert(writer.pos == header_len);
}

fn readHeader(bytes: []const u8) Error!Header {
    var h: Header = .{
        .auto_count = std.mem.readInt(u32, bytes[12..16], .little),
        .group_count = std.mem.readInt(u32, bytes[16..20], .little),
        .line_count = std.mem.readInt(u32, bytes[20..24], .little),
        .delivered_count = std.mem.readInt(u32, bytes[24..28], .little),
        .host_count = std.mem.readInt(u32, bytes[28..32], .little),
        .slash_count = std.mem.readInt(u32, bytes[32..36], .little),
        .auto_params = .{},
        .welcome_params = .{},
        .host_params = .{},
    };
    var pos: usize = 36;
    inline for (@typeInfo(autojoin.Params).@"struct".field_names) |name| {
        @field(h.auto_params, name) = std.mem.readInt(u32, bytes[pos..][0..4], .little);
        pos += 4;
    }
    inline for (@typeInfo(welcome_pack.Params).@"struct".field_names) |name| {
        @field(h.welcome_params, name) = std.mem.readInt(u32, bytes[pos..][0..4], .little);
        pos += 4;
    }
    inline for (@typeInfo(host_request.Params).@"struct".field_names) |name| {
        @field(h.host_params, name) = std.mem.readInt(u32, bytes[pos..][0..4], .little);
        pos += 4;
    }
    std.debug.assert(pos == header_len);
    try checkHeader(h);
    return h;
}

fn sortedKeys(allocator: std.mem.Allocator, map: anytype, comptime folded: bool) Error![][]const u8 {
    const keys = try allocator.alloc([]const u8, map.count());
    var it = map.keyIterator();
    for (keys) |*key| key.* = it.next().?.*;
    if (folded) {
        std.mem.sort([]const u8, keys, {}, lessFolded);
    } else {
        std.mem.sort([]const u8, keys, {}, lessExact);
    }
    return keys;
}

fn lessExact(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn lessFolded(_: void, left: []const u8, right: []const u8) bool {
    return foldedOrder(left, right) == .lt;
}

fn foldedOrder(left: []const u8, right: []const u8) std.math.Order {
    for (left[0..@min(left.len, right.len)], right[0..@min(left.len, right.len)]) |a, b| {
        const x = std.ascii.toLower(a);
        const y = std.ascii.toLower(b);
        if (x < y) return .lt;
        if (x > y) return .gt;
    }
    return std.math.order(left.len, right.len);
}

fn advanceFolded(previous: *?[]const u8, current: []const u8) Error!void {
    if (previous.*) |old| {
        switch (foldedOrder(old, current)) {
            .lt => {},
            .eq => return error.DuplicateEntry,
            .gt => return error.NonCanonicalOrder,
        }
    }
    previous.* = current;
}

fn advanceExact(previous: *?[]const u8, current: []const u8) Error!void {
    if (previous.*) |old| {
        switch (std.mem.order(u8, old, current)) {
            .lt => {},
            .eq => return error.DuplicateEntry,
            .gt => return error.NonCanonicalOrder,
        }
    }
    previous.* = current;
}

fn checkAutoAccount(account: []const u8, channels: usize, params: autojoin.Params) Error!void {
    if (account.len == 0 or account.len > params.max_account_bytes or
        channels == 0 or channels > params.max_channels_per_account or channels > std.math.maxInt(u16))
        return error.InvalidField;
}

fn checkAutoChannel(channel: []const u8, params: autojoin.Params) Error!void {
    if (channel.len == 0 or channel.len > params.max_channel_bytes) return error.InvalidField;
}

fn checkGroupAccount(account: []const u8, nicks: usize, primary: usize) Error!void {
    if (account.len == 0 or account.len > group_params.max_account_bytes or
        nicks == 0 or nicks > group_params.max_nicks_per_group or primary >= nicks) return error.InvalidField;
    for (account) |b| if (b != std.ascii.toLower(b)) return error.InvalidField;
}

const HostRecord = struct {
    account: []const u8,
    vhost: []const u8,
    reason: []const u8,
    status: host_request.Status,
    requested_ms: i64,
    decided_ms: i64,

    fn fromRequest(r: host_request.Request) HostRecord {
        return .{ .account = r.account, .vhost = r.vhost, .reason = r.reason, .status = r.status, .requested_ms = r.requested_ms, .decided_ms = r.decided_ms };
    }
};

fn readHost(reader: *wire.Reader) Error!HostRecord {
    const account_len = try reader.readU16();
    const vhost_len = try reader.readU16();
    const reason_len = try reader.readU16();
    const status = std.enums.fromInt(host_request.Status, try reader.readByte()) orelse return error.InvalidField;
    const requested_ms = try reader.readI64();
    const decided_ms = try reader.readI64();
    return .{ .account = try reader.take(account_len), .vhost = try reader.take(vhost_len), .reason = try reader.take(reason_len), .status = status, .requested_ms = requested_ms, .decided_ms = decided_ms };
}

fn checkHost(r: HostRecord, params: host_request.Params) Error!void {
    if (r.account.len == 0 or r.account.len > params.max_account_bytes or
        r.vhost.len < params.min_vhost_bytes or r.vhost.len > params.max_vhost_bytes or
        r.reason.len > params.max_reason_bytes) return error.InvalidField;
    for (r.account) |b| if (b == 0 or b <= 0x20 or b == 0x7f) return error.InvalidField;
    for (r.vhost) |b| switch (b) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-' => {},
        else => return error.InvalidField,
    };
    switch (r.status) {
        .pending => if (r.reason.len != 0 or r.decided_ms != 0) return error.InvalidField,
        .approved => if (r.reason.len != 0) return error.InvalidField,
        .denied => if (r.reason.len == 0) return error.InvalidField,
    }
}

const SlashRecord = struct {
    slot: usize,
    account: []const u8,
    name: []const u8,
    help: []const u8,
    argc: u8,

    fn fromSlot(slot: *const slash_cmd.Slot) SlashRecord {
        return .{ .slot = 0, .account = slot.account[0..slot.account_len], .name = slot.name[0..slot.name_len], .help = slot.help[0..slot.help_len], .argc = slot.argc };
    }
};

fn readSlash(reader: *wire.Reader) Error!SlashRecord {
    const slot = try reader.readByte();
    const account_len = try reader.readByte();
    const name_len = try reader.readByte();
    const help_len = try reader.readByte();
    const argc = try reader.readByte();
    return .{ .slot = slot, .account = try reader.take(account_len), .name = try reader.take(name_len), .help = try reader.take(help_len), .argc = argc };
}

fn checkSlash(r: SlashRecord) Error!void {
    if (r.slot >= slash_cmd.max_cmds or r.account.len == 0 or r.account.len > slash_cmd.max_account or
        r.name.len == 0 or r.name.len > slash_cmd.max_name or r.help.len == 0 or
        r.help.len > slash_cmd.max_help or r.argc > slash_cmd.max_args) return error.InvalidField;
    for (r.name) |b| if (!std.ascii.isAlphanumeric(b) and b != '_') return error.InvalidField;
}

test "HXUS preserves account settings, request phases, delivery ledger, and slash holes" {
    const allocator = std.testing.allocator;
    var auto = autojoin.AutoJoin.init(allocator);
    defer auto.deinit();
    var groups = memo_group.NickGroup.init(allocator);
    defer groups.deinit();
    var welcome = welcome_pack.WelcomePack.init(allocator);
    defer welcome.deinit();
    var hosts = host_request.Queue.init(allocator, .{});
    defer hosts.deinit();
    var slash = try slash_cmd.Table.init(allocator);
    defer slash.deinit();
    try auto.add("Alice", "#Main");
    try auto.add("alice", "#Second");
    try auto.add("bob", "#quiet");
    _ = try groups.add("ALICE", "FirstNick");
    _ = try groups.add("alice", "SecondNick");
    try groups.setPrimary("alice", "SecondNick");
    try welcome.setLines(&.{ "Welcome to Onyx", "Read the rules" });
    try welcome.markDelivered("Alice");
    try welcome.markDelivered("alice");
    try welcome.markDelivered("bob");
    try hosts.submit("Alice", "host.example", 100);
    try hosts.deny("alice", "not allowed", 200);
    try hosts.submit("BOB", "staff.example", 101);
    try hosts.approve("bob", 201);
    try hosts.submit("Carol", "pending.example", 102);
    try slash.restoreAt(5, "Helper", "ping", "say hello", 2);
    try slash.restoreAt(9, "Helper", "rules", "show rules", 0);

    const bytes = try encode(allocator, &auto, &groups, &welcome, &hosts, &slash);
    defer allocator.free(bytes);
    try validateCheckpoint(bytes);

    var next_auto = autojoin.AutoJoin.init(allocator);
    defer next_auto.deinit();
    var next_groups = memo_group.NickGroup.init(allocator);
    defer next_groups.deinit();
    var next_welcome = welcome_pack.WelcomePack.init(allocator);
    defer next_welcome.deinit();
    var next_hosts = host_request.Queue.init(allocator, .{});
    defer next_hosts.deinit();
    var next_slash = try slash_cmd.Table.init(allocator);
    defer next_slash.deinit();
    try next_auto.add("old", "#old");
    _ = try next_groups.add("old", "OldNick");
    try next_welcome.setLines(&.{"old"});
    try next_welcome.markDelivered("old");
    try next_hosts.submit("old", "old.example", 1);
    try next_slash.add("old", "old", "old help", 0);

    var staged = try stageFor(bytes, &next_auto, &next_groups, &next_welcome, &next_hosts, &next_slash);
    defer staged.deinit();
    try std.testing.expect(try next_auto.contains("old", "#old"));
    const staged_bytes = try encode(allocator, &staged.auto, &staged.groups, &staged.welcome, &staged.hosts, &staged.slash);
    defer allocator.free(staged_bytes);
    try std.testing.expectEqualSlices(u8, bytes, staged_bytes);
    staged.commit();
    try std.testing.expect(!(try next_auto.contains("old", "#old")));
    const channels = try next_auto.list("ALICE");
    try std.testing.expectEqual(@as(usize, 2), channels.len);
    try std.testing.expectEqualStrings("#Main", channels[0]);
    try std.testing.expectEqualStrings("#Second", channels[1]);
    try std.testing.expectEqualStrings("SecondNick", (try next_groups.primary("alice")).?);
    try std.testing.expectEqualStrings("Welcome to Onyx", next_welcome.lines()[0]);
    try std.testing.expect(next_welcome.wasDelivered("Alice"));
    try std.testing.expect(next_welcome.wasDelivered("alice"));
    try std.testing.expect((try next_welcome.deliverOnce("Alice")) == null);
    try std.testing.expectEqual(host_request.Status.denied, next_hosts.get("alice").?.status);
    try std.testing.expectEqualStrings("Alice", next_hosts.get("alice").?.account);
    try std.testing.expectEqualStrings("not allowed", next_hosts.get("alice").?.reason);
    try std.testing.expectEqual(@as(i64, 200), next_hosts.get("alice").?.decided_ms);
    try std.testing.expectEqual(host_request.Status.approved, next_hosts.get("bob").?.status);
    try std.testing.expectEqual(host_request.Status.pending, next_hosts.get("carol").?.status);
    try std.testing.expect(next_slash.slots[5].used);
    try std.testing.expect(next_slash.slots[9].used);
    try std.testing.expect(!next_slash.slots[0].used);
    try next_slash.add("Helper", "next", "next command", 0);
    try std.testing.expect(next_slash.slots[0].used);
}

fn rechecksum(bytes: []u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}

test "HXUS rejects corruption, recomputed semantic tamper, and policy mismatch" {
    const allocator = std.testing.allocator;
    var auto = autojoin.AutoJoin.init(allocator);
    defer auto.deinit();
    var groups = memo_group.NickGroup.init(allocator);
    defer groups.deinit();
    var welcome = welcome_pack.WelcomePack.init(allocator);
    defer welcome.deinit();
    var hosts = host_request.Queue.init(allocator, .{});
    defer hosts.deinit();
    var slash = try slash_cmd.Table.init(allocator);
    defer slash.deinit();
    try slash.restoreAt(5, "helper", "ping", "help", 0);
    const bytes = try encode(allocator, &auto, &groups, &welcome, &hosts, &slash);
    defer allocator.free(bytes);
    try std.testing.expectError(error.Truncated, validateCheckpoint(bytes[0 .. bytes.len - 1]));
    const bad = try allocator.dupe(u8, bytes);
    defer allocator.free(bad);
    bad[header_len] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));
    bad[header_len] = slash_cmd.max_cmds;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    std.mem.writeInt(u32, bad[52..56], 1, .little); // max welcome lines
    rechecksum(bad);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    welcome.allocator = failing.allocator();
    defer welcome.allocator = allocator;
    try std.testing.expectError(error.ConfigMismatch, stageFor(bad, &auto, &groups, &welcome, &hosts, &slash));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}

fn allocationRollback(allocator: std.mem.Allocator, bytes: []const u8) !void {
    const stable = std.testing.allocator;
    var auto = autojoin.AutoJoin.init(stable);
    defer auto.deinit();
    var groups = memo_group.NickGroup.init(stable);
    defer groups.deinit();
    var welcome = welcome_pack.WelcomePack.init(stable);
    defer welcome.deinit();
    var hosts = host_request.Queue.init(stable, .{});
    defer hosts.deinit();
    var slash = try slash_cmd.Table.init(stable);
    defer slash.deinit();
    try auto.add("old", "#old");
    _ = try groups.add("old", "OldNick");
    try welcome.setLines(&.{"old"});
    try welcome.markDelivered("old");
    try hosts.submit("old", "old.example", 1);
    try slash.add("old", "old", "old help", 0);
    const before = try encode(stable, &auto, &groups, &welcome, &hosts, &slash);
    defer stable.free(before);
    auto.allocator = allocator;
    groups.allocator = allocator;
    welcome.allocator = allocator;
    hosts.allocator = allocator;
    slash.allocator = allocator;
    defer {
        auto.allocator = stable;
        groups.allocator = stable;
        welcome.allocator = stable;
        hosts.allocator = stable;
        slash.allocator = stable;
    }
    var staged = stageFor(bytes, &auto, &groups, &welcome, &hosts, &slash) catch |err| {
        const after = try encode(stable, &auto, &groups, &welcome, &hosts, &slash);
        defer stable.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        return err;
    };
    staged.deinit();
    const after = try encode(stable, &auto, &groups, &welcome, &hosts, &slash);
    defer stable.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "HXUS stage sweeps allocations with byte-exact rollback" {
    const allocator = std.testing.allocator;
    var auto = autojoin.AutoJoin.init(allocator);
    defer auto.deinit();
    var groups = memo_group.NickGroup.init(allocator);
    defer groups.deinit();
    var welcome = welcome_pack.WelcomePack.init(allocator);
    defer welcome.deinit();
    var hosts = host_request.Queue.init(allocator, .{});
    defer hosts.deinit();
    var slash = try slash_cmd.Table.init(allocator);
    defer slash.deinit();
    try auto.add("alice", "#one");
    try auto.add("alice", "#two");
    _ = try groups.add("alice", "NickOne");
    _ = try groups.add("alice", "NickTwo");
    try groups.setPrimary("alice", "NickTwo");
    try welcome.setLines(&.{ "first", "second" });
    try welcome.markDelivered("alice");
    try hosts.submit("Alice", "example.net", 11);
    try hosts.deny("alice", "reason", 12);
    try slash.restoreAt(3, "alice", "cmd", "help", 1);
    const bytes = try encode(allocator, &auto, &groups, &welcome, &hosts, &slash);
    defer allocator.free(bytes);
    try std.testing.checkAllAllocationFailures(allocator, allocationRollback, .{bytes});
}
