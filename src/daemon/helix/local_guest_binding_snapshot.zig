// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded unpublished binding data, not issuer authority or physical mapping.
//! Core validates custody and remaps every old physical identity before adoption.
const std = @import("std");

pub const Facts = struct { nick: []const u8, username: []const u8, host: []const u8, realname: []const u8, server: []const u8, description: []const u8 };
pub const Row = struct { physical: u64, origin: [32]u8, guest: [16]u8, facts: Facts };
pub const Ticket = struct { generation: u64, physical: ?u64 = null, facts: ?Facts = null, reserved: ?[16]u8 = null, issuer_incarnation: u64 = 0 };
pub const Image = struct { incarnation: u64, issuer_incarnation: u64, rows: []const Row, tickets: []const Ticket };
pub const Limits = struct { rows: usize, tickets: usize, wire_bytes: usize };
pub const Error = std.mem.Allocator.Error || error{ Invalid, Limit, Truncated, Trailing, NonCanonical };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    image: Image,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const max_lengths = [_]usize{ 64, 32, 255, 256, 255, 256 };
const Writer = struct {
    allocator: std.mem.Allocator,
    limit: usize,
    bytes: std.ArrayList(u8) = .empty,
    fn append(self: *Writer, data: []const u8) Error!void {
        if (data.len > self.limit or self.bytes.items.len > self.limit - data.len) return error.Limit;
        try self.bytes.appendSlice(self.allocator, data);
    }
    fn number(self: *Writer, comptime T: type, n: T) Error!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, n, .big);
        try self.append(&b);
    }
    fn facts(self: *Writer, f: Facts) Error!void {
        const values = [_][]const u8{ f.nick, f.username, f.host, f.realname, f.server, f.description };
        for (values, max_lengths) |value, max| {
            if (value.len > max) return error.Limit;
            try self.number(u16, @intCast(value.len));
            try self.append(value);
        }
    }
};
pub fn encode(a: std.mem.Allocator, image: Image, limits: Limits) Error![]u8 {
    if (image.incarnation == 0 or image.issuer_incarnation == 0 or image.rows.len > limits.rows or image.tickets.len > limits.tickets) return error.Limit;
    var w = Writer{ .allocator = a, .limit = limits.wire_bytes };
    errdefer w.bytes.deinit(a);
    try w.append("LGB1");
    try w.number(u64, image.incarnation);
    try w.number(u64, image.issuer_incarnation);
    try w.number(u64, @intCast(image.rows.len));
    try w.number(u64, @intCast(image.tickets.len));
    var previous: ?u64 = null;
    for (image.rows) |r| {
        if (r.physical == std.math.maxInt(u64)) return error.Invalid;
        if (previous) |v| if (r.physical <= v) return error.NonCanonical;
        previous = r.physical;
        try w.number(u64, r.physical);
        try w.append(&r.origin);
        try w.append(&r.guest);
        try w.facts(r.facts);
    }
    for (image.tickets) |t| {
        if (t.physical == null and (t.facts != null or t.reserved != null or t.issuer_incarnation != 0)) return error.Invalid;
        if (t.physical != null and (t.physical.? == std.math.maxInt(u64) or t.generation == 0 or t.issuer_incarnation != image.issuer_incarnation or (t.reserved != null and t.facts == null))) return error.Invalid;
        try w.number(u64, t.generation);
        const flags: u8 = @intFromBool(t.physical != null) | (@as(u8, @intFromBool(t.facts != null)) << 1) | (@as(u8, @intFromBool(t.reserved != null)) << 2);
        try w.number(u8, flags);
        if (t.physical) |id| {
            try w.number(u64, id);
            try w.number(u64, t.issuer_incarnation);
        }
        if (t.facts) |f| try w.facts(f);
        if (t.reserved) |id| try w.append(&id);
    }
    return w.bytes.toOwnedSlice(a);
}
const Reader = struct {
    data: []const u8,
    pos: usize = 0,
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.data.len - self.pos) return error.Truncated;
        const r = self.data[self.pos..][0..n];
        self.pos += n;
        return r;
    }
    fn number(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn facts(self: *Reader) Error!Facts {
        var values: [6][]const u8 = undefined;
        for (&values, max_lengths) |*v, max| {
            const n = try self.number(u16);
            if (n > max) return error.Limit;
            v.* = try self.take(n);
        }
        return .{ .nick = values[0], .username = values[1], .host = values[2], .realname = values[3], .server = values[4], .description = values[5] };
    }
};
pub fn decodeOwned(a: std.mem.Allocator, data: []const u8, limits: Limits) Error!Owned {
    if (data.len > limits.wire_bytes) return error.Limit;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const aa = arena.allocator();
    const copy = try aa.dupe(u8, data);
    var r = Reader{ .data = copy };
    if (!std.mem.eql(u8, try r.take(4), "LGB1")) return error.Invalid;
    const incarnation = try r.number(u64);
    const issuer_incarnation = try r.number(u64);
    const row_count = std.math.cast(usize, try r.number(u64)) orelse return error.Limit;
    const ticket_count = std.math.cast(usize, try r.number(u64)) orelse return error.Limit;
    if (incarnation == 0 or issuer_incarnation == 0 or row_count > limits.rows or ticket_count > limits.tickets or row_count > (copy.len - r.pos) / 68 or ticket_count > (copy.len - r.pos) / 9) return error.Limit;
    const rows = try aa.alloc(Row, row_count);
    const tickets = try aa.alloc(Ticket, ticket_count);
    var previous: ?u64 = null;
    for (rows) |*row| {
        const id = try r.number(u64);
        if (id == std.math.maxInt(u64)) return error.Invalid;
        if (previous) |v| if (id <= v) return error.NonCanonical;
        previous = id;
        row.* = .{ .physical = id, .origin = (try r.take(32))[0..32].*, .guest = (try r.take(16))[0..16].*, .facts = try r.facts() };
    }
    for (tickets) |*ticket| {
        const generation = try r.number(u64);
        const flags = try r.number(u8);
        if (flags & 0xf8 != 0 or (flags & 1 == 0 and flags != 0) or (flags & 4 != 0 and flags & 2 == 0)) return error.Invalid;
        var t: Ticket = .{ .generation = generation };
        if (flags & 1 != 0) {
            t.physical = try r.number(u64);
            t.issuer_incarnation = try r.number(u64);
            if (t.physical.? == std.math.maxInt(u64) or generation == 0 or t.issuer_incarnation != issuer_incarnation) return error.Invalid;
        }
        if (flags & 2 != 0) t.facts = try r.facts();
        if (flags & 4 != 0) t.reserved = (try r.take(16))[0..16].*;
        ticket.* = t;
    }
    if (r.pos != copy.len) return error.Trailing;
    return .{ .arena = arena, .image = .{ .incarnation = incarnation, .issuer_incarnation = issuer_incarnation, .rows = rows, .tickets = tickets } };
}

test "local guest binding snapshot preserves slot generations and bytes" {
    const a = std.testing.allocator;
    const facts: Facts = .{ .nick = "nick", .username = "user", .host = "host", .realname = "real", .server = "s", .description = "d" };
    const rows = [_]Row{.{ .physical = 0, .origin = @splat(7), .guest = @splat(8), .facts = facts }};
    const tickets = [_]Ticket{ .{ .generation = std.math.maxInt(u64) }, .{ .generation = 4, .physical = 9, .facts = facts, .reserved = @splat(3), .issuer_incarnation = 2 } };
    const limits: Limits = .{ .rows = 3, .tickets = 3, .wire_bytes = 4096 };
    const bytes = try encode(a, .{ .incarnation = 1, .issuer_incarnation = 2, .rows = &rows, .tickets = &tickets }, limits);
    defer a.free(bytes);
    var result = try decodeOwned(a, bytes, limits);
    defer result.deinit();
    try std.testing.expectEqual(@as(u64, 0), result.image.rows[0].physical);
    try std.testing.expectEqualStrings("host", result.image.rows[0].facts.host);
    try std.testing.expectEqual(std.math.maxInt(u64), result.image.tickets[0].generation);
    try std.testing.expectEqual(@as(?u64, 9), result.image.tickets[1].physical);
    try std.testing.expectEqualSlices(u8, &tickets[1].reserved.?, &result.image.tickets[1].reserved.?);
    for (0..bytes.len) |n| {
        if (decodeOwned(a, bytes[0..n], limits)) |owned| {
            var unexpected = owned;
            unexpected.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    const trailing = try a.alloc(u8, bytes.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try std.testing.expectError(error.Trailing, decodeOwned(a, trailing, limits));
}
