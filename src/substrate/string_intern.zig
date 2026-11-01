// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const Symbol = enum(u32) {
    _,

    pub fn index(self: Symbol) u32 {
        return @backingInt(self);
    }
};

pub const StringIntern = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    by_string: std.StringHashMap(Symbol),
    by_symbol: std.ArrayList([]const u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) StringIntern {
        return .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .by_string = std.StringHashMap(Symbol).init(allocator),
        };
    }

    pub fn deinit(self: *StringIntern) void {
        self.by_symbol.deinit(self.allocator);
        self.by_string.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn intern(self: *StringIntern, bytes: []const u8) !Symbol {
        if (self.by_string.get(bytes)) |existing| return existing;

        const next_id = self.by_symbol.items.len;
        if (next_id > std.math.maxInt(u32)) return error.TooManySymbols;

        const owned = try self.arena.allocator().dupe(u8, bytes);
        const symbol: Symbol = @fromBackingInt(@intCast(@as(u32, @intCast(next_id))));

        try self.by_string.put(owned, symbol);
        errdefer _ = self.by_string.remove(owned);
        try self.by_symbol.append(self.allocator, owned);

        return symbol;
    }

    pub fn resolve(self: *const StringIntern, symbol: Symbol) []const u8 {
        const id: usize = @intCast(symbol.index());
        std.debug.assert(id < self.by_symbol.items.len);
        return self.by_symbol.items[id];
    }

    pub fn count(self: *const StringIntern) usize {
        return self.by_symbol.items.len;
    }
};

test "identical strings get the same symbol" {
    var table = StringIntern.init(std.testing.allocator);
    defer table.deinit();

    const first = try table.intern("alpha");
    const second = try table.intern("alpha");

    try std.testing.expectEqual(first, second);
    try std.testing.expectEqual(@as(usize, 1), table.count());
}

test "distinct strings get distinct symbols" {
    var table = StringIntern.init(std.testing.allocator);
    defer table.deinit();

    const alpha = try table.intern("alpha");
    const beta = try table.intern("beta");
    const gamma = try table.intern("gamma");

    try std.testing.expect(alpha != beta);
    try std.testing.expect(beta != gamma);
    try std.testing.expect(alpha != gamma);
    try std.testing.expectEqual(@as(usize, 3), table.count());
}

test "resolve round trips interned bytes" {
    var table = StringIntern.init(std.testing.allocator);
    defer table.deinit();

    const samples = [_][]const u8{
        "onyx",
        "substrate",
        "string-intern",
        "with spaces",
        "with\x00nul",
    };

    for (samples) |sample| {
        const symbol = try table.intern(sample);
        try std.testing.expectEqualStrings(sample, table.resolve(symbol));
    }
}

test "large number of interns" {
    var table = StringIntern.init(std.testing.allocator);
    defer table.deinit();

    const total = 4096;
    var expected: [total]Symbol = undefined;

    for (&expected, 0..) |*slot, i| {
        var buf: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "name-{d}", .{i});
        slot.* = try table.intern(text);
        try std.testing.expectEqual(@as(u32, @intCast(i)), slot.index());
    }

    try std.testing.expectEqual(@as(usize, total), table.count());

    for (expected, 0..) |symbol, i| {
        var buf: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "name-{d}", .{i});
        try std.testing.expectEqual(symbol, try table.intern(text));
        try std.testing.expectEqualStrings(text, table.resolve(symbol));
    }

    try std.testing.expectEqual(@as(usize, total), table.count());
}

test "empty string interns and resolves" {
    var table = StringIntern.init(std.testing.allocator);
    defer table.deinit();

    const empty_a = try table.intern("");
    const empty_b = try table.intern("");
    const non_empty = try table.intern("not empty");

    try std.testing.expectEqual(empty_a, empty_b);
    try std.testing.expect(empty_a != non_empty);
    try std.testing.expectEqualStrings("", table.resolve(empty_a));
    try std.testing.expectEqual(@as(usize, 2), table.count());
}

test "bytes remain valid after more interns" {
    var table = StringIntern.init(std.testing.allocator);
    defer table.deinit();

    const root = try table.intern("root");
    const resolved_before = table.resolve(root);
    const ptr_before = resolved_before.ptr;

    for (0..2048) |i| {
        var buf: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "later-value-{d}", .{i});
        _ = try table.intern(text);
    }

    const resolved_after = table.resolve(root);
    try std.testing.expectEqual(ptr_before, resolved_after.ptr);
    try std.testing.expectEqualStrings("root", resolved_before);
    try std.testing.expectEqualStrings("root", resolved_after);
}

test "interning is deterministic" {
    var first = StringIntern.init(std.testing.allocator);
    defer first.deinit();
    var second = StringIntern.init(std.testing.allocator);
    defer second.deinit();

    const sequence = [_][]const u8{
        "alpha",
        "beta",
        "alpha",
        "gamma",
        "",
        "beta",
        "delta",
        "",
    };

    for (sequence) |text| {
        const a = try first.intern(text);
        const b = try second.intern(text);
        try std.testing.expectEqual(a, b);
        try std.testing.expectEqualStrings(first.resolve(a), second.resolve(b));
    }

    try std.testing.expectEqual(first.count(), second.count());
    for (0..first.count()) |i| {
        const symbol: Symbol = @fromBackingInt(@intCast(@as(u32, @intCast(i))));
        try std.testing.expectEqualStrings(first.resolve(symbol), second.resolve(symbol));
    }
}
