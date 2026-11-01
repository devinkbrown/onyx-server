// SPDX-License-Identifier: AGPL-3.0-or-later
//! Helix presentation data only; no guest/session authority or FD mapping.
//! Core must validate frontier IDs against the independently adopted relation.
const std = @import("std");

pub const PublicIdentity = struct { username: []const u8, host: []const u8 };
pub const Frontier = struct { old_client: u64, identity: PublicIdentity };
pub const Pending = struct { channel: []const u8, identity: PublicIdentity, hlc: u64 };
pub const Projection = struct {
    node: u64,
    nick: []const u8,
    visible: PublicIdentity,
    watermark: u64,
    transition_stamp: u64,
    last_roster_seen_ms: i64,
    roster_absent_since_ms: ?i64,
    pending: ?Pending,
    frontiers: []const Frontier,
};
/// String and frontier limits are cumulative across the complete snapshot;
/// max_wire_bytes bounds the complete encoded image.
pub const Limits = struct { max_projections: usize, max_frontiers: usize, max_string_bytes: usize, max_wire_bytes: usize };
pub const Error = std.mem.Allocator.Error || error{ Invalid, Truncated, TrailingBytes, BadVersion, LimitExceeded, NonCanonical, Duplicate };
pub const OwnedSnapshot = struct {
    arena: std.heap.ArenaAllocator,
    projections: []const Projection,
    pub fn deinit(self: *OwnedSnapshot) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const magic = "RPS1";
fn cmpNick(a: []const u8, b: []const u8) std.math.Order {
    const n = @min(a.len, b.len);
    for (0..n) |i| {
        const x = std.ascii.toLower(a[i]);
        const y = std.ascii.toLower(b[i]);
        if (x < y) return .lt;
        if (x > y) return .gt;
    }
    return std.math.order(a.len, b.len);
}
fn projectionLess(_: void, a: Projection, b: Projection) bool {
    if (a.node != b.node) return a.node < b.node;
    return cmpNick(a.nick, b.nick) == .lt;
}
fn frontierLess(_: void, a: Frontier, b: Frontier) bool {
    return a.old_client < b.old_client;
}
fn addCount(total: *usize, value: usize, limit: usize) Error!void {
    total.* = std.math.add(usize, total.*, value) catch return error.LimitExceeded;
    if (total.* > limit) return error.LimitExceeded;
}
const Writer = struct {
    a: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    limits: Limits,
    strings: usize = 0,
    fn bytes(self: *Writer, data: []const u8) Error!void {
        if (data.len > self.limits.max_wire_bytes or self.out.items.len > self.limits.max_wire_bytes - data.len) return error.LimitExceeded;
        try self.out.appendSlice(self.a, data);
    }
    fn int(self: *Writer, comptime T: type, value: T) Error!void {
        var buf: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buf, value, .big);
        try self.bytes(&buf);
    }
    fn string(self: *Writer, value: []const u8) Error!void {
        try addCount(&self.strings, value.len, self.limits.max_string_bytes);
        const size = std.math.cast(u32, value.len) orelse return error.LimitExceeded;
        try self.int(u32, size);
        try self.bytes(value);
    }
    fn identity(self: *Writer, value: PublicIdentity) Error!void {
        try self.string(value.username);
        try self.string(value.host);
    }
};

pub fn encode(a: std.mem.Allocator, projections: []const Projection, limits: Limits) Error![]u8 {
    if (projections.len > limits.max_projections) return error.LimitExceeded;
    const sorted = try a.dupe(Projection, projections);
    defer a.free(sorted);
    std.mem.sort(Projection, sorted, {}, projectionLess);
    var writer = Writer{ .a = a, .limits = limits };
    errdefer writer.out.deinit(a);
    try writer.bytes(magic);
    try writer.int(u8, 1);
    try writer.bytes(&.{ 0, 0, 0 });
    try writer.int(u64, @intCast(sorted.len));
    var total_frontiers: usize = 0;
    for (sorted, 0..) |p, i| {
        if (p.nick.len == 0) return error.Invalid;
        if (i > 0 and p.node == sorted[i - 1].node and cmpNick(p.nick, sorted[i - 1].nick) == .eq) return error.Duplicate;
        try addCount(&total_frontiers, p.frontiers.len, limits.max_frontiers);
        try writer.int(u64, p.node);
        try writer.string(p.nick);
        try writer.identity(p.visible);
        try writer.int(u64, p.watermark);
        try writer.int(u64, p.transition_stamp);
        try writer.int(i64, p.last_roster_seen_ms);
        try writer.int(u8, if (p.roster_absent_since_ms != null) 1 else 0);
        if (p.roster_absent_since_ms) |v| try writer.int(i64, v);
        try writer.int(u8, if (p.pending != null) 1 else 0);
        if (p.pending) |pending| {
            if (pending.channel.len == 0) return error.Invalid;
            try writer.string(pending.channel);
            try writer.identity(pending.identity);
            try writer.int(u64, pending.hlc);
        }
        const frontiers = try a.dupe(Frontier, p.frontiers);
        defer a.free(frontiers);
        std.mem.sort(Frontier, frontiers, {}, frontierLess);
        try writer.int(u64, @intCast(frontiers.len));
        for (frontiers, 0..) |f, j| {
            if (f.old_client == std.math.maxInt(u64)) return error.Invalid;
            if (j != 0 and f.old_client == frontiers[j - 1].old_client) return error.Duplicate;
            try writer.int(u64, f.old_client);
            try writer.identity(f.identity);
        }
    }
    return writer.out.toOwnedSlice(a);
}
const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    limits: Limits,
    strings: usize = 0,
    frontiers: usize = 0,
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.bytes.len - self.pos) return error.Truncated;
        const result = self.bytes[self.pos..][0..n];
        self.pos += n;
        return result;
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn string(self: *Reader) Error![]const u8 {
        const n: usize = try self.int(u32);
        try addCount(&self.strings, n, self.limits.max_string_bytes);
        return self.take(n);
    }
    fn identity(self: *Reader) Error!PublicIdentity {
        return .{ .username = try self.string(), .host = try self.string() };
    }
    fn flag(self: *Reader) Error!bool {
        return switch (try self.int(u8)) {
            0 => false,
            1 => true,
            else => error.Invalid,
        };
    }
    fn header(self: *Reader) Error!usize {
        if (self.bytes.len > self.limits.max_wire_bytes) return error.LimitExceeded;
        if (!std.mem.eql(u8, try self.take(4), magic)) return error.Invalid;
        if (try self.int(u8) != 1) return error.BadVersion;
        if (!std.mem.allEqual(u8, try self.take(3), 0)) return error.Invalid;
        const count = std.math.cast(usize, try self.int(u64)) orelse return error.LimitExceeded;
        if (count > self.limits.max_projections) return error.LimitExceeded;
        return count;
    }
};

fn readProjection(reader: *Reader, allocator: ?std.mem.Allocator) Error!Projection {
    const node = try reader.int(u64);
    const nick = try reader.string();
    if (nick.len == 0) return error.Invalid;
    const visible = try reader.identity();
    const watermark = try reader.int(u64);
    const transition_stamp = try reader.int(u64);
    const last_roster_seen_ms = try reader.int(i64);
    const absent: ?i64 = if (try reader.flag()) try reader.int(i64) else null;
    const pending: ?Pending = if (try reader.flag()) blk: {
        const channel = try reader.string();
        if (channel.len == 0) return error.Invalid;
        break :blk .{ .channel = channel, .identity = try reader.identity(), .hlc = try reader.int(u64) };
    } else null;
    const count = std.math.cast(usize, try reader.int(u64)) orelse return error.LimitExceeded;
    try addCount(&reader.frontiers, count, reader.limits.max_frontiers);
    if (count > (reader.bytes.len - reader.pos) / 16) return error.Truncated;
    const frontiers: []Frontier = if (allocator) |a| try a.alloc(Frontier, count) else @constCast(&.{});
    var previous: ?u64 = null;
    for (0..count) |i| {
        const id = try reader.int(u64);
        if (id == std.math.maxInt(u64)) return error.Invalid;
        if (previous) |last| if (id <= last) return error.NonCanonical;
        previous = id;
        const ident = try reader.identity();
        if (allocator != null) frontiers[i] = .{ .old_client = id, .identity = ident };
    }
    return .{ .node = node, .nick = nick, .visible = visible, .watermark = watermark, .transition_stamp = transition_stamp, .last_roster_seen_ms = last_roster_seen_ms, .roster_absent_since_ms = absent, .pending = pending, .frontiers = frontiers };
}
fn scan(bytes: []const u8, limits: Limits, allocator: ?std.mem.Allocator) Error![]Projection {
    var reader = Reader{ .bytes = bytes, .limits = limits };
    const count = try reader.header();
    // Each projection contains at least 54 bytes, excluding string payloads.
    if (count > (bytes.len - reader.pos) / 54) return error.Truncated;
    const projections: []Projection = if (allocator) |a| try a.alloc(Projection, count) else @constCast(&.{});
    var previous: ?Projection = null;
    for (0..count) |i| {
        const item = try readProjection(&reader, allocator);
        if (previous) |prior| {
            if (item.node < prior.node or (item.node == prior.node and cmpNick(item.nick, prior.nick) != .gt)) return error.NonCanonical;
        }
        previous = item;
        if (allocator != null) projections[i] = item;
    }
    if (reader.pos != bytes.len) return error.TrailingBytes;
    return projections;
}
/// Identifies the wire family only; callers must separately validate it.
pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

/// Strict structural validation without allocation or publication.
pub fn validateWire(bytes: []const u8, limits: Limits) Error!void {
    _ = try scan(bytes, limits, null);
}

/// Validate the entire borrowed wire before allocating; then copy wire and
/// construct owned arrays in an arena. OOM never publishes a partial snapshot.
pub fn decodeOwned(a: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!OwnedSnapshot {
    _ = try scan(bytes, limits, null);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const owned_bytes = try arena.allocator().dupe(u8, bytes);
    const projections = try scan(owned_bytes, limits, arena.allocator());
    return .{ .arena = arena, .projections = projections };
}

const test_limits = Limits{ .max_projections = 8, .max_frontiers = 16, .max_string_bytes = 1024, .max_wire_bytes = 4096 };
fn testProjection(nick: []const u8, frontiers: []const Frontier) Projection {
    return .{ .node = 7, .nick = nick, .visible = .{ .username = "", .host = "cloak" }, .watermark = 21, .transition_stamp = 19, .last_roster_seen_ms = -5, .roster_absent_since_ms = 0, .pending = .{ .channel = "#room", .identity = .{ .username = "user", .host = "pending" }, .hlc = 0 }, .frontiers = frontiers };
}
test "remote presentation snapshot roundtrip preserves pending times and physical zero" {
    const a = std.testing.allocator;
    const frontiers = [_]Frontier{ .{ .old_client = 9, .identity = .{ .username = "b", .host = "h2" } }, .{ .old_client = 0, .identity = .{ .username = "a", .host = "h1" } } };
    const rows = [_]Projection{testProjection("Alice", &frontiers)};
    const bytes = try encode(a, &rows, test_limits);
    defer a.free(bytes);
    var owned = try decodeOwned(a, bytes, test_limits);
    defer owned.deinit();
    @memset(bytes, 0);
    const p = owned.projections[0];
    try std.testing.expectEqualStrings("Alice", p.nick);
    try std.testing.expectEqualStrings("", p.visible.username);
    try std.testing.expectEqual(@as(i64, -5), p.last_roster_seen_ms);
    try std.testing.expectEqual(@as(?i64, 0), p.roster_absent_since_ms);
    try std.testing.expectEqual(@as(u64, 0), p.pending.?.hlc);
    try std.testing.expectEqualStrings("#room", p.pending.?.channel);
    try std.testing.expectEqual(@as(u64, 0), p.frontiers[0].old_client);
    try std.testing.expectEqual(@as(u64, 9), p.frontiers[1].old_client);
}
test "remote presentation snapshot empty image and corrupt framing fail closed" {
    const a = std.testing.allocator;
    const empty = try encode(a, &.{}, test_limits);
    defer a.free(empty);
    var decoded = try decodeOwned(a, empty, test_limits);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 0), decoded.projections.len);
    for (0..empty.len) |n| try std.testing.expectError(error.Truncated, decodeOwned(a, empty[0..n], test_limits));
    var padded: [17]u8 = undefined;
    @memcpy(padded[0..16], empty);
    padded[16] = 0;
    try std.testing.expectError(error.TrailingBytes, decodeOwned(a, &padded, test_limits));
    var malformed: [16]u8 = undefined;
    @memcpy(&malformed, empty);
    malformed[5] = 1;
    try std.testing.expectError(error.Invalid, decodeOwned(a, &malformed, test_limits));
    @memcpy(&malformed, empty);
    malformed[4] = 2;
    try std.testing.expectError(error.BadVersion, decodeOwned(a, &malformed, test_limits));
    @memcpy(&malformed, empty);
    std.mem.writeInt(u64, malformed[8..16], std.math.maxInt(u64), .big);
    try std.testing.expectError(error.LimitExceeded, decodeOwned(a, &malformed, test_limits));
}
test "remote presentation snapshot aliases duplicate frontiers and limits rejected" {
    const a = std.testing.allocator;
    const rows = [_]Projection{ testProjection("ALICE", &.{}), testProjection("alice", &.{}) };
    try std.testing.expectError(error.Duplicate, encode(a, &rows, test_limits));
    const duplicate = [_]Frontier{ .{ .old_client = 0, .identity = .{ .username = "a", .host = "b" } }, .{ .old_client = 0, .identity = .{ .username = "x", .host = "y" } } };
    try std.testing.expectError(error.Duplicate, encode(a, &.{testProjection("n", &duplicate)}, test_limits));
    const invalid = [_]Frontier{.{ .old_client = std.math.maxInt(u64), .identity = .{ .username = "", .host = "" } }};
    try std.testing.expectError(error.Invalid, encode(a, &.{testProjection("n", &invalid)}, test_limits));
    try std.testing.expectError(error.Invalid, encode(a, &.{testProjection("", &.{})}, test_limits));
    var p = testProjection("n", &.{});
    p.pending.?.channel = "";
    try std.testing.expectError(error.Invalid, encode(a, &.{p}, test_limits));
    var small = test_limits;
    small.max_string_bytes = 2;
    try std.testing.expectError(error.LimitExceeded, encode(a, &.{testProjection("n", &.{})}, small));
    small = test_limits;
    small.max_wire_bytes = 15;
    try std.testing.expectError(error.LimitExceeded, encode(a, &.{}, small));
}
fn snapshotFailureExercise(a: std.mem.Allocator) !void {
    const f = [_]Frontier{.{ .old_client = 0, .identity = .{ .username = "u", .host = "h" } }};
    const wire = try encode(a, &.{testProjection("Nick", &f)}, test_limits);
    defer a.free(wire);
    var decoded = try decodeOwned(a, wire, test_limits);
    defer decoded.deinit();
    try std.testing.expectEqualStrings("Nick", decoded.projections[0].nick);
}
test "remote presentation snapshot allocation failures unwind encode and decode" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, snapshotFailureExercise, .{});
}

test "remote presentation snapshot rejects incoming case aliases and every truncation" {
    const a = std.testing.allocator;
    const rows = [_]Projection{ testProjection("Alice", &.{}), testProjection("bravo", &.{}) };
    const bytes = try encode(a, &rows, test_limits);
    defer a.free(bytes);
    for (0..bytes.len) |n| try std.testing.expectError(error.Truncated, decodeOwned(a, bytes[0..n], test_limits));
    const second = std.mem.indexOf(u8, bytes, "bravo") orelse return error.TestUnexpectedResult;
    @memcpy(bytes[second..][0..5], "aLiCe");
    try std.testing.expectError(error.NonCanonical, decodeOwned(a, bytes, test_limits));
}

test "remote presentation snapshot decoder rejects malformed flags and frontier IDs" {
    const a = std.testing.allocator;
    const fronts = [_]Frontier{
        .{ .old_client = 0, .identity = .{ .username = "u", .host = "a" } },
        .{ .old_client = 2, .identity = .{ .username = "v", .host = "b" } },
    };
    const wire = try encode(a, &.{testProjection("Nick", &fronts)}, test_limits);
    defer a.free(wire);
    // Locate fields by walking the original well-formed image; mutate only the
    // target byte(s), keeping all surrounding fields and counts intact.
    var r = Reader{ .bytes = wire, .limits = test_limits };
    try std.testing.expectEqual(@as(usize, 1), try r.header());
    _ = try r.int(u64);
    _ = try r.string();
    _ = try r.identity();
    _ = try r.int(u64);
    _ = try r.int(u64);
    _ = try r.int(i64);
    const absent_flag = r.pos;
    try std.testing.expect(try r.flag());
    _ = try r.int(i64);
    const pending_flag = r.pos;
    try std.testing.expect(try r.flag());
    _ = try r.string();
    _ = try r.identity();
    _ = try r.int(u64);
    try std.testing.expectEqual(@as(u64, 2), try r.int(u64));
    const first_id = r.pos;
    _ = try r.int(u64);
    _ = try r.identity();
    const second_id = r.pos;
    wire[absent_flag] = 2;
    try std.testing.expectError(error.Invalid, decodeOwned(a, wire, test_limits));
    wire[absent_flag] = 1;
    wire[pending_flag] = 3;
    try std.testing.expectError(error.Invalid, decodeOwned(a, wire, test_limits));
    wire[pending_flag] = 1;
    std.mem.writeInt(u64, wire[second_id..][0..8], 0, .big);
    try std.testing.expectError(error.NonCanonical, decodeOwned(a, wire, test_limits));
    std.mem.writeInt(u64, wire[second_id..][0..8], 2, .big);
    std.mem.writeInt(u64, wire[first_id..][0..8], std.math.maxInt(u64), .big);
    try std.testing.expectError(error.Invalid, decodeOwned(a, wire, test_limits));
}

test "remote presentation snapshot decoder enforces cumulative limits across rows" {
    const a = std.testing.allocator;
    const frontier = [_]Frontier{.{ .old_client = 0, .identity = .{ .username = "", .host = "" } }};
    const one = testProjection("one", &frontier);
    const two = testProjection("two", &frontier);
    const single_wire = try encode(a, &.{one}, test_limits);
    defer a.free(single_wire);
    const double_wire = try encode(a, &.{ one, two }, test_limits);
    defer a.free(double_wire);
    var limited = test_limits;
    limited.max_frontiers = 1;
    var single = try decodeOwned(a, single_wire, limited);
    single.deinit();
    try std.testing.expectError(error.LimitExceeded, decodeOwned(a, double_wire, limited));
    limited = test_limits;
    // Each projection contains 24 bytes of string payload; together they have 48.
    limited.max_string_bytes = 30;
    single = try decodeOwned(a, single_wire, limited);
    single.deinit();
    try std.testing.expectError(error.LimitExceeded, decodeOwned(a, double_wire, limited));
}
