// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CoilPack structured-value layer: a canonical, signature-stable document model.
//!
//! This is the higher layer above the atom primitives in `coilpack.zig`
//! (Cbs/Cbb varints + length-prefixed bytes). Where `coilpack.zig` answers "how
//! do I write a varint / length-prefixed field," this module answers "how do I
//! canonically serialize an arbitrary structured object so its signature is
//! stable regardless of map insertion order" — a CBOR/msgpack-style canonical
//! format for signing config / metadata / capability objects.
//!
//! The encoder always emits the same byte sequence for the same logical value:
//! map entries are sorted by raw key bytes, and the decoder rejects non-canonical
//! input (overlong varints, unsorted/duplicate map keys, invalid UTF-8,
//! truncation, trailing bytes).

const std = @import("std");

const Tag = enum(u8) {
    nil = 0x00,
    false = 0x01,
    true = 0x02,
    u64 = 0x03,
    i64 = 0x04,
    bytes = 0x05,
    string = 0x06,
    array = 0x07,
    map = 0x08,
};

/// A decoded or encodable CoilPack value.
///
/// Values returned by `Decoder.decode` own all nested buffers and must be
/// released with `deinit`. Values constructed from borrowed/static memory may
/// be encoded directly but should not be deinitialized.
pub const Value = union(enum) {
    nil,
    boolean: bool,
    unsigned: u64,
    signed: i64,
    bytes: []const u8,
    string: []const u8,
    array: []Value,
    map: []MapEntry,

    /// Releases an owned value tree, including nested arrays, maps, keys, and
    /// byte/string buffers allocated by the decoder or test helpers.
    pub fn deinit(self: *Value, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .nil, .boolean, .unsigned, .signed => {},
            .bytes => |bytes| allocator.free(bytes),
            .string => |string| allocator.free(string),
            .array => |items| {
                for (items) |*item| item.deinit(allocator);
                allocator.free(items);
            },
            .map => |entries| {
                for (entries) |*entry| {
                    allocator.free(entry.key);
                    entry.value.deinit(allocator);
                }
                allocator.free(entries);
            },
        }
        self.* = .nil;
    }
};

/// A map entry. Keys are raw byte strings, compared bytewise for canonical
/// ordering. Duplicate keys are invalid.
pub const MapEntry = struct {
    key: []const u8,
    value: Value,
};

/// CoilPack decoding and encoding failures that are not allocator failures.
pub const FormatError = error{
    Truncated,
    TrailingBytes,
    UnknownTag,
    NonCanonicalVarint,
    VarintOverflow,
    InvalidUtf8,
    MapKeysOutOfOrder,
    DuplicateMapKey,
    NestingTooDeep,
    TooManyValues,
};

pub const max_decode_depth = 128;
pub const max_decode_values = 1_000_000;

/// Canonical CoilPack encoder.
pub const Encoder = struct {
    /// Serializes `value` into a newly allocated canonical byte slice.
    pub fn encode(allocator: std.mem.Allocator, value: Value) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        try appendValue(allocator, &out, value);
        return try out.toOwnedSlice(allocator);
    }

    /// Appends the canonical encoding of `value` to an existing unmanaged list.
    pub fn appendValue(
        allocator: std.mem.Allocator,
        out: *std.ArrayList(u8),
        value: Value,
    ) anyerror!void {
        switch (value) {
            .nil => try out.append(allocator, @backingInt(Tag.nil)),
            .boolean => |b| try out.append(
                allocator,
                if (b) @backingInt(Tag.true) else @backingInt(Tag.false),
            ),
            .unsigned => |n| {
                try out.append(allocator, @backingInt(Tag.u64));
                try appendVarint(allocator, out, n);
            },
            .signed => |n| {
                try out.append(allocator, @backingInt(Tag.i64));
                try appendVarint(allocator, out, zigZagEncode(n));
            },
            .bytes => |bytes| {
                try out.append(allocator, @backingInt(Tag.bytes));
                try appendLenAndBytes(allocator, out, bytes);
            },
            .string => |string| {
                if (!isValidUtf8(string)) return FormatError.InvalidUtf8;
                try out.append(allocator, @backingInt(Tag.string));
                try appendLenAndBytes(allocator, out, string);
            },
            .array => |items| {
                try out.append(allocator, @backingInt(Tag.array));
                try appendVarint(allocator, out, items.len);
                for (items) |item| try appendValue(allocator, out, item);
            },
            .map => |entries| {
                try out.append(allocator, @backingInt(Tag.map));
                try appendVarint(allocator, out, entries.len);
                try appendSortedMap(allocator, out, entries);
            },
        }
    }
};

/// Canonical CoilPack decoder.
pub const Decoder = struct {
    input: []const u8,
    pos: usize = 0,
    values_seen: usize = 0,

    /// Parses one complete CoilPack value from `input` into an owned value tree.
    pub fn decode(allocator: std.mem.Allocator, input: []const u8) !Value {
        var decoder = Decoder{ .input = input };
        var value = try decoder.readValue(allocator, 0);
        errdefer value.deinit(allocator);

        if (decoder.pos != input.len) return FormatError.TrailingBytes;
        return value;
    }

    fn readValue(self: *Decoder, allocator: std.mem.Allocator, depth: usize) anyerror!Value {
        if (depth > max_decode_depth) return FormatError.NestingTooDeep;
        if (self.values_seen == max_decode_values) return FormatError.TooManyValues;
        self.values_seen += 1;

        const tag_byte = try self.readByte();
        const tag: Tag = switch (tag_byte) {
            @backingInt(Tag.nil) => .nil,
            @backingInt(Tag.false) => .false,
            @backingInt(Tag.true) => .true,
            @backingInt(Tag.u64) => .u64,
            @backingInt(Tag.i64) => .i64,
            @backingInt(Tag.bytes) => .bytes,
            @backingInt(Tag.string) => .string,
            @backingInt(Tag.array) => .array,
            @backingInt(Tag.map) => .map,
            else => return FormatError.UnknownTag,
        };

        return switch (tag) {
            .nil => .nil,
            .false => .{ .boolean = false },
            .true => .{ .boolean = true },
            .u64 => .{ .unsigned = try self.readVarint() },
            .i64 => .{ .signed = zigZagDecode(try self.readVarint()) },
            .bytes => .{ .bytes = try self.readOwnedBytes(allocator) },
            .string => blk: {
                const string = try self.readOwnedBytes(allocator);
                errdefer allocator.free(string);
                if (!isValidUtf8(string)) return FormatError.InvalidUtf8;
                break :blk .{ .string = string };
            },
            .array => try self.readArray(allocator, depth + 1),
            .map => try self.readMap(allocator, depth + 1),
        };
    }

    fn readArray(self: *Decoder, allocator: std.mem.Allocator, depth: usize) anyerror!Value {
        const count = try self.readVarintAsUsize();
        var items: std.ArrayList(Value) = .empty;
        errdefer {
            for (items.items) |*item| item.deinit(allocator);
            items.deinit(allocator);
        }

        var i: usize = 0;
        while (i < count) : (i += 1) {
            var item = try self.readValue(allocator, depth);
            errdefer item.deinit(allocator);
            try items.append(allocator, item);
        }

        return .{ .array = try items.toOwnedSlice(allocator) };
    }

    fn readMap(self: *Decoder, allocator: std.mem.Allocator, depth: usize) anyerror!Value {
        const count = try self.readVarintAsUsize();
        var entries: std.ArrayList(MapEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| {
                allocator.free(entry.key);
                entry.value.deinit(allocator);
            }
            entries.deinit(allocator);
        }

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const key_view = try self.readBytesView();
            if (entries.items.len != 0) {
                const prev = entries.items[entries.items.len - 1].key;
                if (!std.mem.lessThan(u8, prev, key_view)) {
                    if (std.mem.eql(u8, prev, key_view)) {
                        return FormatError.DuplicateMapKey;
                    }
                    return FormatError.MapKeysOutOfOrder;
                }
            }

            const key = try allocator.dupe(u8, key_view);
            errdefer allocator.free(key);
            var value = try self.readValue(allocator, depth);
            errdefer value.deinit(allocator);

            try entries.append(allocator, .{
                .key = key,
                .value = value,
            });
        }

        return .{ .map = try entries.toOwnedSlice(allocator) };
    }

    fn readOwnedBytes(self: *Decoder, allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, try self.readBytesView());
    }

    fn readBytesView(self: *Decoder) ![]const u8 {
        const len = try self.readVarintAsUsize();
        if (len > self.input.len - self.pos) return FormatError.Truncated;
        const start = self.pos;
        self.pos += len;
        return self.input[start..self.pos];
    }

    fn readByte(self: *Decoder) !u8 {
        if (self.pos >= self.input.len) return FormatError.Truncated;
        const byte = self.input[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readVarintAsUsize(self: *Decoder) !usize {
        const value = try self.readVarint();
        if (value > std.math.maxInt(usize)) return FormatError.VarintOverflow;
        return @intCast(value);
    }

    fn readVarint(self: *Decoder) !u64 {
        const start = self.pos;
        var result: u64 = 0;

        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const byte = try self.readByte();
            const payload: u64 = byte & 0x7f;
            if (i == 9 and payload > 1) return FormatError.VarintOverflow;

            result |= payload << @intCast(i * 7);
            if ((byte & 0x80) == 0) {
                const used = self.pos - start;
                if (varintLen(result) != used) {
                    return FormatError.NonCanonicalVarint;
                }
                return result;
            }
        }

        return FormatError.VarintOverflow;
    }
};

/// Returns true when two logical CoilPack values are deeply equal.
///
/// Map comparison is order-insensitive, matching the canonical map semantics.
pub fn eql(a: Value, b: Value) bool {
    return switch (a) {
        .nil => b == .nil,
        .boolean => |x| b == .boolean and b.boolean == x,
        .unsigned => |x| b == .unsigned and b.unsigned == x,
        .signed => |x| b == .signed and b.signed == x,
        .bytes => |x| b == .bytes and std.mem.eql(u8, x, b.bytes),
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .array => |xs| blk: {
            if (b != .array or xs.len != b.array.len) break :blk false;
            for (xs, b.array) |x, y| {
                if (!eql(x, y)) break :blk false;
            }
            break :blk true;
        },
        .map => |xs| blk: {
            if (b != .map or xs.len != b.map.len) break :blk false;
            break :blk eqlLargeMaps(xs, b.map);
        },
    };
}

fn eqlLargeMaps(a: []MapEntry, b: []MapEntry) bool {
    for (a) |x| {
        var matches: usize = 0;
        for (b) |y| {
            if (std.mem.eql(u8, x.key, y.key) and eql(x.value, y.value)) {
                matches += 1;
            }
        }
        if (matches != 1) return false;
    }
    return true;
}

fn appendSortedMap(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    entries: []MapEntry,
) anyerror!void {
    var order: std.ArrayList(usize) = .empty;
    defer order.deinit(allocator);

    for (entries, 0..) |_, index| try order.append(allocator, index);
    std.mem.sort(usize, order.items, entries, mapIndexLessThan);

    var prev: ?[]const u8 = null;
    for (order.items) |index| {
        const entry = entries[index];
        if (prev) |prev_key| {
            if (std.mem.eql(u8, prev_key, entry.key)) {
                return FormatError.DuplicateMapKey;
            }
        }
        prev = entry.key;

        try appendLenAndBytes(allocator, out, entry.key);
        try Encoder.appendValue(allocator, out, entry.value);
    }
}

fn mapIndexLessThan(entries: []MapEntry, a: usize, b: usize) bool {
    return std.mem.lessThan(u8, entries[a].key, entries[b].key);
}

fn appendLenAndBytes(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    bytes: []const u8,
) !void {
    try appendVarint(allocator, out, bytes.len);
    try out.appendSlice(allocator, bytes);
}

fn appendVarint(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: u64) !void {
    var remaining = value;
    while (remaining >= 0x80) {
        try out.append(allocator, @as(u8, @intCast(remaining & 0x7f)) | 0x80);
        remaining >>= 7;
    }
    try out.append(allocator, @intCast(remaining));
}

fn varintLen(value: u64) usize {
    var remaining = value;
    var len: usize = 1;
    while (remaining >= 0x80) {
        remaining >>= 7;
        len += 1;
    }
    return len;
}

fn zigZagEncode(value: i64) u64 {
    return (@as(u64, @bitCast(value)) << 1) ^ @as(u64, @bitCast(value >> 63));
}

fn zigZagDecode(value: u64) i64 {
    return @bitCast((value >> 1) ^ (0 -% (value & 1)));
}

fn isValidUtf8(bytes: []const u8) bool {
    var i: usize = 0;
    while (i < bytes.len) {
        const first = bytes[i];
        if (first <= 0x7f) {
            i += 1;
        } else if (first >= 0xc2 and first <= 0xdf) {
            if (i + 1 >= bytes.len or !isCont(bytes[i + 1])) return false;
            i += 2;
        } else if (first == 0xe0) {
            if (i + 2 >= bytes.len) return false;
            if (!(bytes[i + 1] >= 0xa0 and bytes[i + 1] <= 0xbf) or !isCont(bytes[i + 2])) {
                return false;
            }
            i += 3;
        } else if (first >= 0xe1 and first <= 0xec) {
            if (i + 2 >= bytes.len or !isCont(bytes[i + 1]) or !isCont(bytes[i + 2])) {
                return false;
            }
            i += 3;
        } else if (first == 0xed) {
            if (i + 2 >= bytes.len) return false;
            if (!(bytes[i + 1] >= 0x80 and bytes[i + 1] <= 0x9f) or !isCont(bytes[i + 2])) {
                return false;
            }
            i += 3;
        } else if (first >= 0xee and first <= 0xef) {
            if (i + 2 >= bytes.len or !isCont(bytes[i + 1]) or !isCont(bytes[i + 2])) {
                return false;
            }
            i += 3;
        } else if (first == 0xf0) {
            if (i + 3 >= bytes.len) return false;
            if (!(bytes[i + 1] >= 0x90 and bytes[i + 1] <= 0xbf) or
                !isCont(bytes[i + 2]) or
                !isCont(bytes[i + 3]))
            {
                return false;
            }
            i += 4;
        } else if (first >= 0xf1 and first <= 0xf3) {
            if (i + 3 >= bytes.len or
                !isCont(bytes[i + 1]) or
                !isCont(bytes[i + 2]) or
                !isCont(bytes[i + 3]))
            {
                return false;
            }
            i += 4;
        } else if (first == 0xf4) {
            if (i + 3 >= bytes.len) return false;
            if (!(bytes[i + 1] >= 0x80 and bytes[i + 1] <= 0x8f) or
                !isCont(bytes[i + 2]) or
                !isCont(bytes[i + 3]))
            {
                return false;
            }
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

fn isCont(byte: u8) bool {
    return byte >= 0x80 and byte <= 0xbf;
}

fn roundTrip(value: Value) !void {
    const allocator = std.testing.allocator;
    const encoded = try Encoder.encode(allocator, value);
    defer allocator.free(encoded);

    var decoded = try Decoder.decode(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expect(eql(value, decoded));
}

test "round-trip nil and bool" {
    try roundTrip(.nil);
    try roundTrip(.{ .boolean = false });
    try roundTrip(.{ .boolean = true });
}

test "round-trip u64 values" {
    try roundTrip(.{ .unsigned = 0 });
    try roundTrip(.{ .unsigned = 127 });
    try roundTrip(.{ .unsigned = 128 });
    try roundTrip(.{ .unsigned = std.math.maxInt(u64) });
}

test "round-trip i64 values and zigzag polarity" {
    try roundTrip(.{ .signed = 0 });
    try roundTrip(.{ .signed = -1 });
    try roundTrip(.{ .signed = 1 });
    try roundTrip(.{ .signed = std.math.minInt(i64) });
    try roundTrip(.{ .signed = std.math.maxInt(i64) });

    const neg_one = try Encoder.encode(std.testing.allocator, .{ .signed = -1 });
    defer std.testing.allocator.free(neg_one);
    try std.testing.expectEqualSlices(u8, &.{ @backingInt(Tag.i64), 0x01 }, neg_one);

    const pos_one = try Encoder.encode(std.testing.allocator, .{ .signed = 1 });
    defer std.testing.allocator.free(pos_one);
    try std.testing.expectEqualSlices(u8, &.{ @backingInt(Tag.i64), 0x02 }, pos_one);
}

test "round-trip bytes and string" {
    try roundTrip(.{ .bytes = "\x00\x01raw\xff" });
    try roundTrip(.{ .string = "onyx coilpack \xc3\xb8" });
}

test "round-trip array" {
    var items = [_]Value{
        .nil,
        .{ .boolean = true },
        .{ .unsigned = 42 },
        .{ .string = "ok" },
    };
    try roundTrip(.{ .array = items[0..] });
}

test "round-trip map" {
    var entries = [_]MapEntry{
        .{ .key = "alpha", .value = .{ .unsigned = 1 } },
        .{ .key = "beta", .value = .{ .string = "two" } },
    };
    try roundTrip(.{ .map = entries[0..] });
}

test "canonical integer minimal-length enforced" {
    try std.testing.expectError(
        FormatError.NonCanonicalVarint,
        Decoder.decode(std.testing.allocator, &.{ @backingInt(Tag.u64), 0x80, 0x00 }),
    );
    try std.testing.expectError(
        FormatError.NonCanonicalVarint,
        Decoder.decode(std.testing.allocator, &.{ @backingInt(Tag.u64), 0x81, 0x00 }),
    );
    try std.testing.expectError(
        FormatError.NonCanonicalVarint,
        Decoder.decode(std.testing.allocator, &.{ @backingInt(Tag.i64), 0x80, 0x00 }),
    );
}

test "map key ordering enforced and duplicate rejection" {
    try std.testing.expectError(
        FormatError.MapKeysOutOfOrder,
        Decoder.decode(
            std.testing.allocator,
            &.{
                @backingInt(Tag.map), 0x02,
                0x01,                 'b',
                @backingInt(Tag.nil), 0x01,
                'a',                  @backingInt(Tag.nil),
            },
        ),
    );

    try std.testing.expectError(
        FormatError.DuplicateMapKey,
        Decoder.decode(
            std.testing.allocator,
            &.{
                @backingInt(Tag.map), 0x02,
                0x01,                 'a',
                @backingInt(Tag.nil), 0x01,
                'a',                  @backingInt(Tag.nil),
            },
        ),
    );
}

test "signature-stability for unordered map input" {
    var first_entries = [_]MapEntry{
        .{ .key = "zeta", .value = .{ .unsigned = 6 } },
        .{ .key = "alpha", .value = .{ .string = "one" } },
        .{ .key = "mid", .value = .{ .boolean = true } },
    };
    var second_entries = [_]MapEntry{
        .{ .key = "mid", .value = .{ .boolean = true } },
        .{ .key = "zeta", .value = .{ .unsigned = 6 } },
        .{ .key = "alpha", .value = .{ .string = "one" } },
    };

    const first = try Encoder.encode(std.testing.allocator, .{ .map = first_entries[0..] });
    defer std.testing.allocator.free(first);
    const second = try Encoder.encode(std.testing.allocator, .{ .map = second_entries[0..] });
    defer std.testing.allocator.free(second);

    try std.testing.expectEqualSlices(u8, first, second);
}

test "nested array and map" {
    var inner_array = [_]Value{
        .{ .signed = -5 },
        .{ .bytes = "payload" },
    };
    var inner_map_entries = [_]MapEntry{
        .{ .key = "list", .value = .{ .array = inner_array[0..] } },
        .{ .key = "name", .value = .{ .string = "coilpack" } },
    };
    var outer_array = [_]Value{
        .{ .map = inner_map_entries[0..] },
        .{ .boolean = false },
    };

    try roundTrip(.{ .array = outer_array[0..] });
}

test "invalid utf8 is rejected" {
    try std.testing.expectError(
        FormatError.InvalidUtf8,
        Encoder.encode(std.testing.allocator, .{ .string = "\xc0\x80" }),
    );

    try std.testing.expectError(
        FormatError.InvalidUtf8,
        Decoder.decode(std.testing.allocator, &.{ @backingInt(Tag.string), 0x02, 0xc0, 0x80 }),
    );
}

test "truncation and trailing bytes are rejected" {
    try std.testing.expectError(
        FormatError.Truncated,
        Decoder.decode(std.testing.allocator, &.{ @backingInt(Tag.bytes), 0x04, 'a', 'b' }),
    );
    try std.testing.expectError(
        FormatError.Truncated,
        Decoder.decode(std.testing.allocator, &.{ @backingInt(Tag.array), 0x01 }),
    );
    try std.testing.expectError(
        FormatError.TrailingBytes,
        Decoder.decode(std.testing.allocator, &.{ @backingInt(Tag.nil), @backingInt(Tag.nil) }),
    );
}

test "decoder rejects unknown tag and overflowing varint" {
    try std.testing.expectError(
        FormatError.UnknownTag,
        Decoder.decode(std.testing.allocator, &.{0xff}),
    );
    try std.testing.expectError(
        FormatError.VarintOverflow,
        Decoder.decode(
            std.testing.allocator,
            &.{
                @backingInt(Tag.u64),
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
                0x02,
            },
        ),
    );
}

test "encoder rejects duplicate map keys" {
    var entries = [_]MapEntry{
        .{ .key = "same", .value = .nil },
        .{ .key = "same", .value = .{ .unsigned = 1 } },
    };
    try std.testing.expectError(
        FormatError.DuplicateMapKey,
        Encoder.encode(std.testing.allocator, .{ .map = entries[0..] }),
    );
}
