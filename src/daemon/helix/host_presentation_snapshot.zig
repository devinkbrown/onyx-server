// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded host presentation claims, not authority. Core binds every row to the
//! authenticated physical owner and exact host before adopting any intent.
const std = @import("std");

pub const Source = enum(u8) {
    unknown = 0,
    generated_address = 1,
    generated_account = 2,
    operator = 3,
    persona_granted = 4,
    persona_claimed = 5,
    persona_verified = 6,
    persona_auto = 7,
};
pub const Row = struct { physical: u64, host: []const u8, source: Source, owner_account: []const u8 = "", whois_revision: u64 = 0 };
pub const Image = struct { account_cloak: bool, rows: []const Row };
pub const Limits = struct { rows: usize, wire_bytes: usize };
pub const Error = std.mem.Allocator.Error || error{ Invalid, Limit, Truncated, Trailing, NonCanonical };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    image: Image,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const header_len = 10;

fn validOwner(owner: []const u8) bool {
    if (owner.len > 32) return false;
    for (owner) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_' or c == '.' or c == '-')) return false;
    }
    return true;
}
fn validHost(host: []const u8) bool {
    if (host.len > 255) return false;
    // Preserve the existing host byte contract, including non-UTF-8 high bytes.
    for (host) |byte| if (byte <= 0x20 or byte == 0x7f) return false;
    return true;
}
fn validateRow(row: Row) Error!void {
    if (row.physical == std.math.maxInt(u64) or !validHost(row.host) or !validOwner(row.owner_account)) return error.Invalid;
    if (row.host.len == 0 and row.source != .unknown) return error.Invalid;
    switch (row.source) {
        .unknown, .generated_address => if (row.owner_account.len != 0) return error.Invalid,
        .generated_account, .persona_granted, .persona_claimed, .persona_verified, .persona_auto => if (row.owner_account.len == 0) return error.Invalid,
        .operator => {},
    }
}
const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.bytes.len - self.pos) return error.Truncated;
        const result = self.bytes[self.pos..][0..n];
        self.pos += n;
        return result;
    }
    fn number(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn row(self: *Reader) Error!Row {
        const physical = try self.number(u64);
        const whois_revision = try self.number(u64);
        const tag = try self.number(u8);
        if (tag > 7) return error.Invalid;
        const host_len = try self.number(u16);
        if (host_len > 255) return error.Limit;
        const host = try self.take(host_len);
        const owner_len = try self.number(u8);
        if (owner_len > 32) return error.Limit;
        return .{ .physical = physical, .whois_revision = whois_revision, .source = @fromBackingInt(tag), .host = host, .owner_account = try self.take(owner_len) };
    }
};
/// Iterator borrows the unchanged bytes validated by validateWire.
pub const Iterator = struct {
    reader: Reader,
    remaining: usize,
    pub fn next(self: *Iterator) ?Row {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        return self.reader.row() catch unreachable;
    }
};
pub const View = struct {
    bytes: []const u8,
    account_cloak: bool,
    count: usize,
    pub fn iterator(self: View) Iterator {
        return .{ .reader = .{ .bytes = self.bytes, .pos = header_len }, .remaining = self.count };
    }
};
/// No allocation and no authority proof. Caller must keep bytes unchanged and
/// separately bind every row to the authenticated physical owner and host.
pub fn validateWire(bytes: []const u8, limits: Limits) Error!View {
    if (bytes.len > limits.wire_bytes) return error.Limit;
    var r = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try r.take(4), "HPR1")) return error.Invalid;
    if (try r.number(u8) != 1) return error.Invalid;
    const flags = try r.number(u8);
    if (flags > 1) return error.Invalid;
    const count = try r.number(u32);
    if (count > limits.rows) return error.Limit;
    // Each row has at least 20 bytes. This also bounds iteration before parsing.
    if (count > (bytes.len - r.pos) / 20) return error.Truncated;
    var previous: ?u64 = null;
    for (0..count) |_| {
        const row = try r.row();
        try validateRow(row);
        if (previous) |id| if (row.physical <= id) return error.NonCanonical;
        previous = row.physical;
    }
    if (r.pos != bytes.len) return error.Trailing;
    return .{ .bytes = bytes, .account_cloak = flags == 1, .count = count };
}
const Writer = struct {
    allocator: std.mem.Allocator,
    limit: usize,
    bytes: std.ArrayList(u8) = .empty,
    fn append(self: *Writer, data: []const u8) Error!void {
        if (data.len > self.limit or self.bytes.items.len > self.limit - data.len) return error.Limit;
        try self.bytes.appendSlice(self.allocator, data);
    }
    fn number(self: *Writer, comptime T: type, n: T) Error!void {
        var raw: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &raw, n, .big);
        try self.append(&raw);
    }
};
/// Input rows must already be in strictly increasing physical-ID order.
pub fn encode(a: std.mem.Allocator, image: Image, limits: Limits) Error![]u8 {
    if (image.rows.len > limits.rows) return error.Limit;
    const count = std.math.cast(u32, image.rows.len) orelse return error.Limit;
    var w = Writer{ .allocator = a, .limit = limits.wire_bytes };
    errdefer w.bytes.deinit(a);
    try w.append("HPR1");
    try w.number(u8, 1);
    try w.number(u8, @intFromBool(image.account_cloak));
    try w.number(u32, count);
    var previous: ?u64 = null;
    for (image.rows) |row| {
        try validateRow(row);
        if (previous) |id| if (row.physical <= id) return error.NonCanonical;
        previous = row.physical;
        try w.number(u64, row.physical);
        try w.number(u64, row.whois_revision);
        try w.number(u8, @backingInt(row.source));
        try w.number(u16, @intCast(row.host.len));
        try w.append(row.host);
        try w.number(u8, @intCast(row.owner_account.len));
        try w.append(row.owner_account);
    }
    return w.bytes.toOwnedSlice(a);
}
pub fn decodeOwned(a: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Owned {
    // Reject malformed input before allocation. Decode again from owned bytes so
    // all strings survive caller buffer release; errdefer makes OOM atomic.
    const view = try validateWire(bytes, limits);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const aa = arena.allocator();
    const copy = try aa.dupe(u8, bytes);
    const rows = try aa.alloc(Row, view.count);
    var it = (try validateWire(copy, limits)).iterator();
    for (rows) |*row| row.* = it.next().?;
    return .{ .arena = arena, .image = .{ .account_cloak = view.account_cloak, .rows = rows } };
}

test "host presentation round trip and explicit empty state" {
    const a = std.testing.allocator;
    const limits: Limits = .{ .rows = 8, .wire_bytes = 4096 };
    const rows = [_]Row{
        .{ .physical = 0, .host = "", .source = .unknown },
        .{ .physical = 4, .host = "a.example", .source = .generated_address, .whois_revision = 123456789 },
        .{ .physical = 9, .host = "alice.users.onyx", .source = .generated_account, .owner_account = "alice" },
        .{ .physical = 12, .host = "staff.example", .source = .operator },
        .{ .physical = 15, .host = "persona.\xffexample", .source = .persona_claimed, .owner_account = "alice_1", .whois_revision = std.math.maxInt(u64) },
    };
    const bytes = try encode(a, .{ .account_cloak = true, .rows = &rows }, limits);
    defer a.free(bytes);
    const view = try validateWire(bytes, limits);
    try std.testing.expect(view.account_cloak);
    try std.testing.expectEqual(rows.len, view.count);
    var iter = view.iterator();
    for (rows) |row| try std.testing.expectEqualDeep(row, iter.next().?);
    try std.testing.expect(iter.next() == null);
    var owned = try decodeOwned(a, bytes, limits);
    defer owned.deinit();
    try std.testing.expectEqualDeep(@as([]const Row, &rows), owned.image.rows);
    for ([_]bool{ false, true }) |flag| {
        const empty = try encode(a, .{ .account_cloak = flag, .rows = &.{} }, limits);
        defer a.free(empty);
        try std.testing.expectEqual(@as(usize, header_len), empty.len);
        const empty_view = try validateWire(empty, limits);
        try std.testing.expectEqual(flag, empty_view.account_cloak);
        try std.testing.expectEqual(@as(usize, 0), empty_view.count);
    }
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, wire: []const u8, bounds: Limits) !void {
            var result = try decodeOwned(allocator, wire, bounds);
            defer result.deinit();
            try std.testing.expectEqual(@as(usize, 5), result.image.rows.len);
            try std.testing.expectEqual(@as(u64, 123456789), result.image.rows[1].whois_revision);
            try std.testing.expectEqual(std.math.maxInt(u64), result.image.rows[4].whois_revision);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Sweep.run, .{ bytes, limits });
}

test "host presentation rejects malformed framing and unsafe claims" {
    const a = std.testing.allocator;
    const limits: Limits = .{ .rows = 2, .wire_bytes = 4096 };
    const rows = [_]Row{ .{ .physical = 1, .host = "first", .source = .generated_address }, .{ .physical = 3, .host = "second", .source = .generated_account, .owner_account = "alice" } };
    const bytes = try encode(a, .{ .account_cloak = true, .rows = &rows }, limits);
    defer a.free(bytes);
    for (0..bytes.len) |n| {
        if (validateWire(bytes[0..n], limits)) |_| return error.TestUnexpectedResult else |_| {}
    }
    const corrupt = try a.alloc(u8, bytes.len + 1);
    defer a.free(corrupt);
    @memcpy(corrupt[0..bytes.len], bytes);
    corrupt[bytes.len] = 0;
    try std.testing.expectError(error.Trailing, validateWire(corrupt, limits));
    corrupt[5] = 2;
    try std.testing.expectError(error.Invalid, validateWire(corrupt[0..bytes.len], limits));
    corrupt[5] = 1;
    corrupt[header_len + 16] = 8;
    try std.testing.expectError(error.Invalid, validateWire(corrupt[0..bytes.len], limits));
    corrupt[header_len + 16] = 1;
    const second_row = header_len + 20 + rows[0].host.len;
    std.mem.writeInt(u64, corrupt[second_row..][0..8], 1, .big);
    try std.testing.expectError(error.NonCanonical, validateWire(corrupt[0..bytes.len], limits));
    try std.testing.expectError(error.Limit, validateWire(bytes, .{ .rows = 1, .wire_bytes = 4096 }));
    try std.testing.expectError(error.Limit, validateWire(bytes, .{ .rows = 2, .wire_bytes = bytes.len - 1 }));
    const oversized_host: [256]u8 = @splat('a');
    const bad_rows = [_]Row{
        .{ .physical = std.math.maxInt(u64), .host = "x", .source = .operator },
        .{ .physical = 1, .host = "", .source = .operator },
        .{ .physical = 1, .host = "x\n", .source = .operator },
        .{ .physical = 1, .host = "x y", .source = .operator },
        .{ .physical = 1, .host = "x", .source = .unknown, .owner_account = "alice" },
        .{ .physical = 1, .host = "x", .source = .generated_address, .owner_account = "alice" },
        .{ .physical = 1, .host = "x", .source = .generated_account },
        .{ .physical = 1, .host = "x", .source = .persona_auto },
        .{ .physical = 1, .host = "x", .source = .persona_claimed, .owner_account = "Alice" },
        .{ .physical = 1, .host = &oversized_host, .source = .operator },
        .{ .physical = 1, .host = "x", .source = .operator, .owner_account = "_________________________________" },
    };
    for (bad_rows) |row| try std.testing.expectError(error.Invalid, encode(a, .{ .account_cloak = true, .rows = &.{row} }, limits));
    const duplicate = [_]Row{ rows[0], rows[0] };
    try std.testing.expectError(error.NonCanonical, encode(a, .{ .account_cloak = true, .rows = &duplicate }, limits));
    const unsorted = [_]Row{ rows[1], rows[0] };
    try std.testing.expectError(error.NonCanonical, encode(a, .{ .account_cloak = true, .rows = &unsorted }, limits));
}

test "host presentation preserves the full 255-byte host boundary" {
    const a = std.testing.allocator;
    const limits: Limits = .{ .rows = 1, .wire_bytes = 1024 };
    const host: [256]u8 = @splat('h');
    for ([_]usize{ 253, 254, 255 }) |len| {
        const row: Row = .{ .physical = 1, .host = host[0..len], .source = .operator };
        const bytes = try encode(a, .{ .account_cloak = true, .rows = &.{row} }, limits);
        defer a.free(bytes);
        const view = try validateWire(bytes, limits);
        var it = view.iterator();
        try std.testing.expectEqualStrings(row.host, it.next().?.host);
        try std.testing.expect(it.next() == null);
        var owned = try decodeOwned(a, bytes, limits);
        defer owned.deinit();
        try std.testing.expectEqualStrings(row.host, owned.image.rows[0].host);
    }
    const too_long: Row = .{ .physical = 1, .host = &host, .source = .operator };
    try std.testing.expectError(error.Invalid, encode(a, .{ .account_cloak = true, .rows = &.{too_long} }, limits));
    const max_row: Row = .{ .physical = 1, .host = host[0..255], .source = .operator };
    const max_wire = try encode(a, .{ .account_cloak = true, .rows = &.{max_row} }, limits);
    defer a.free(max_wire);
    const oversized_wire = try a.alloc(u8, max_wire.len + 1);
    defer a.free(oversized_wire);
    @memcpy(oversized_wire[0 .. max_wire.len - 1], max_wire[0 .. max_wire.len - 1]);
    oversized_wire[max_wire.len - 1] = 'h';
    oversized_wire[max_wire.len] = 0; // Empty owner follows the 256-byte host.
    std.mem.writeInt(u16, oversized_wire[header_len + 17 ..][0..2], 256, .big);
    try std.testing.expectError(error.Limit, validateWire(oversized_wire, limits));
    try std.testing.expectError(error.Limit, decodeOwned(a, oversized_wire, limits));
}
