// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Zeroizing secret wrappers for byte material that should not leak through logs.
//!
//! `Secret(N)` keeps fixed-size sensitive bytes behind an explicit `expose`
//! method, compares them without data-dependent early exits, and always formats
//! as redacted text. `SecretSlice` provides the same discipline for
//! allocator-owned runtime-length bytes and wipes its allocation on `deinit`.

const std = @import("std");

const redacted = "[redacted]";

pub fn Secret(comptime spec: anytype) type {
    const Value = secretValueType(spec);

    return struct {
        const Self = @This();

        value: Value,

        pub fn init(value: Value) Self {
            return .{ .value = value };
        }

        pub fn constantTimeEql(self: *const Self, other: *const Self) bool {
            return constantTimeBytesEql(self.expose(), other.expose());
        }

        pub fn wipe(self: *Self) void {
            switch (@typeInfo(Value)) {
                .array => std.crypto.secureZero(u8, self.value[0..]),
                .pointer => |ptr| {
                    if (ptr.size != .slice or ptr.is_const) {
                        @compileError("Secret(" ++ @typeName(Value) ++ ").wipe requires mutable byte storage");
                    }
                    std.crypto.secureZero(u8, self.value);
                },
                else => @compileError("Secret(" ++ @typeName(Value) ++ ") must wrap bytes"),
            }
        }

        pub fn expose(self: *const Self) []const u8 {
            // Slice self.value IN PLACE — never via a by-value helper, which would
            // return a slice into a temporary copy (dangling after return).
            return switch (@typeInfo(Value)) {
                .array => self.value[0..],
                .pointer => |ptr| if (ptr.size == .slice and ptr.child == u8)
                    self.value
                else
                    @compileError("Secret pointer type must be a u8 slice"),
                else => @compileError("Secret value must be a byte array or byte slice"),
            };
        }

        pub fn declassify(self: *const Self) Value {
            return self.value;
        }

        pub fn format(_: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeAll(redacted);
        }
    };
}

pub const SecretSlice = struct {
    const Self = @This();

    bytes: []u8,

    pub fn init(allocator: std.mem.Allocator, bytes: []const u8) !Self {
        const owned = try allocator.dupe(u8, bytes);
        return .{ .bytes = owned };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.wipe();
        allocator.free(self.bytes);
        self.bytes = &.{};
    }

    pub fn constantTimeEql(self: *const Self, other: *const Self) bool {
        return constantTimeBytesEql(self.bytes, other.bytes);
    }

    pub fn wipe(self: *Self) void {
        std.crypto.secureZero(u8, self.bytes);
    }

    pub fn expose(self: *const Self) []const u8 {
        return self.bytes;
    }

    pub fn format(_: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(redacted);
    }
};

fn secretValueType(comptime spec: anytype) type {
    return switch (@TypeOf(spec)) {
        comptime_int => [spec]u8,
        type => spec,
        else => @compileError("Secret expects a byte count or byte container type"),
    };
}

fn bytesView(comptime T: type, value: T) []const u8 {
    return switch (@typeInfo(T)) {
        .array => |array| blk: {
            if (array.child != u8) @compileError("Secret array child type must be u8");
            break :blk value[0..];
        },
        .pointer => |ptr| blk: {
            if (ptr.size != .slice or ptr.child != u8) {
                @compileError("Secret pointer type must be a u8 slice");
            }
            break :blk value;
        },
        else => @compileError("Secret value must be a byte array or byte slice"),
    };
}

fn constantTimeBytesEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= (x ^ y);
    return diff == 0;
}

test "Secret constantTimeEql reports true and false" {
    const Key = Secret(4);
    const a = Key.init(.{ 1, 2, 3, 4 });
    const b = Key.init(.{ 1, 2, 3, 4 });
    const c = Key.init(.{ 1, 2, 3, 5 });

    try std.testing.expect(a.constantTimeEql(&b));
    try std.testing.expect(!a.constantTimeEql(&c));
}

test "Secret format redacts bytes" {
    const key = Secret(4).init(.{ 9, 8, 7, 6 });
    var buf: [32]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "{f}", .{key});

    try std.testing.expectEqualStrings(redacted, out);
}

test "Secret wipe zeroes bytes" {
    var key = Secret(4).init(.{ 1, 2, 3, 4 });

    key.wipe();

    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, key.expose());
}

test "Secret expose returns bytes" {
    const key = Secret(4).init(.{ 4, 3, 2, 1 });

    try std.testing.expectEqualSlices(u8, &.{ 4, 3, 2, 1 }, key.expose());
}

test "SecretSlice owns compares exposes and wipes" {
    const allocator = std.testing.allocator;
    var a = try SecretSlice.init(allocator, &.{ 1, 2, 3 });
    defer a.deinit(allocator);
    var b = try SecretSlice.init(allocator, &.{ 1, 2, 3 });
    defer b.deinit(allocator);
    var c = try SecretSlice.init(allocator, &.{ 1, 2, 4 });
    defer c.deinit(allocator);

    try std.testing.expect(a.constantTimeEql(&b));
    try std.testing.expect(!a.constantTimeEql(&c));
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, a.expose());

    a.wipe();
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, a.expose());
}

test "SecretSlice format redacts bytes" {
    const allocator = std.testing.allocator;
    var secret = try SecretSlice.init(allocator, &.{ 8, 6, 7, 5, 3, 0, 9 });
    defer secret.deinit(allocator);

    var buf: [32]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "{f}", .{secret});

    try std.testing.expectEqualStrings(redacted, out);
}
