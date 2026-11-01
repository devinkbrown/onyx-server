// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal RFC 8949 CBOR subset codec.
//!
//! This module implements definite-length unsigned integers, negative
//! integers, byte strings, text strings, arrays, maps, booleans, and null.
//! Decode borrows directly from the caller-owned input slice and encode writes
//! into a caller-provided output buffer.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("CBOR codec requires a 64-bit target");
}

/// Maximum number of bytes needed for any CBOR major-type header in this subset.
pub const max_header_len = 9;

/// CBOR major-type field from the high three bits of the first byte.
pub const MajorType = enum(u3) {
    unsigned = 0,
    negative = 1,
    bytes = 2,
    text = 3,
    array = 4,
    map = 5,
    tag = 6,
    simple = 7,
};

/// Resource and validation limits for complete-value validation.
pub const Params = struct {
    /// Maximum nested array/map depth accepted by `validate` and `Reader.skipValue`.
    max_depth: usize = 32,
};

/// Failures returned while decoding borrowed CBOR input.
pub const DecodeError = error{
    Truncated,
    InvalidAdditionalInfo,
    IndefiniteLength,
    LengthTooLarge,
    UnsupportedTag,
    UnsupportedSimple,
    InvalidUtf8,
    TrailingBytes,
    NestingTooDeep,
};

/// Failures returned while encoding into a caller-provided output buffer.
pub const EncodeError = error{
    BufferTooSmall,
    InvalidUtf8,
    LengthTooLarge,
};

/// One decoded CBOR item.
///
/// Arrays and maps carry only their element or pair counts; callers then read
/// each child from the same `Reader`, preserving allocation-free decode.
pub const Value = union(enum) {
    unsigned: u64,
    negative: u64,
    bytes: []const u8,
    text: []const u8,
    array: usize,
    map: usize,
    boolean: bool,
    null,
};

/// Streaming borrowed reader over a caller-owned CBOR byte slice.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    /// Initializes a reader over `buf`.
    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    /// Releases reader state. The reader owns no memory.
    pub fn deinit(self: *Reader) void {
        self.* = undefined;
    }

    /// Returns the number of unread bytes.
    pub fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    /// Returns true when the cursor is exactly at the end of input.
    pub fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }

    /// Requires that no unread input remains.
    pub fn expectDone(self: *const Reader) DecodeError!void {
        if (!self.done()) return error.TrailingBytes;
    }

    /// Reads one CBOR item header and any immediate borrowed payload.
    pub fn readValue(self: *Reader) DecodeError!Value {
        const first = try self.readByte();
        const major: MajorType = @fromBackingInt(@intCast(@as(u3, @intCast(first >> 5))));
        const addl: u5 = @intCast(first & 0x1f);

        return switch (major) {
            .unsigned => .{ .unsigned = try self.readArgument(addl) },
            .negative => .{ .negative = try self.readArgument(addl) },
            .bytes => .{ .bytes = try self.readBytesLike(addl) },
            .text => blk: {
                const text = try self.readBytesLike(addl);
                if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
                break :blk .{ .text = text };
            },
            .array => .{ .array = try self.readCount(addl) },
            .map => .{ .map = try self.readCount(addl) },
            .tag => error.UnsupportedTag,
            .simple => try self.readSimple(addl),
        };
    }

    /// Skips one complete value, including nested array/map contents.
    pub fn skipValue(self: *Reader, params: Params) DecodeError!void {
        try self.skipValueAt(params, 0);
    }

    fn skipValueAt(self: *Reader, params: Params, depth: usize) DecodeError!void {
        if (depth > params.max_depth) return error.NestingTooDeep;

        const value = try self.readValue();
        switch (value) {
            .array => |count| {
                var i: usize = 0;
                while (i < count) : (i += 1) {
                    try self.skipValueAt(params, depth + 1);
                }
            },
            .map => |count| {
                var i: usize = 0;
                while (i < count) : (i += 1) {
                    try self.skipValueAt(params, depth + 1);
                    try self.skipValueAt(params, depth + 1);
                }
            },
            .unsigned, .negative, .bytes, .text, .boolean, .null => {},
        }
    }

    fn readByte(self: *Reader) DecodeError!u8 {
        if (self.remaining() == 0) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readArgument(self: *Reader, addl: u5) DecodeError!u64 {
        return switch (addl) {
            0...23 => addl,
            24 => try self.readU8(),
            25 => try self.readU16Be(),
            26 => try self.readU32Be(),
            27 => try self.readU64Be(),
            28...30 => error.InvalidAdditionalInfo,
            31 => error.IndefiniteLength,
        };
    }

    fn readCount(self: *Reader, addl: u5) DecodeError!usize {
        const value = try self.readArgument(addl);
        if (value > @as(u64, std.math.maxInt(usize))) return error.LengthTooLarge;
        return @intCast(value);
    }

    fn readBytesLike(self: *Reader, addl: u5) DecodeError![]const u8 {
        const len = try self.readCount(addl);
        if (self.remaining() < len) return error.Truncated;

        const start = self.pos;
        self.pos += len;
        return self.buf[start..self.pos];
    }

    fn readSimple(self: *Reader, addl: u5) DecodeError!Value {
        return switch (addl) {
            20 => .{ .boolean = false },
            21 => .{ .boolean = true },
            22 => .null,
            23 => error.UnsupportedSimple,
            24 => {
                _ = try self.readU8();
                return error.UnsupportedSimple;
            },
            25...27 => error.UnsupportedSimple,
            28...30 => error.InvalidAdditionalInfo,
            31 => error.IndefiniteLength,
            0...19 => error.UnsupportedSimple,
        };
    }

    fn readU8(self: *Reader) DecodeError!u8 {
        return self.readByte();
    }

    fn readU16Be(self: *Reader) DecodeError!u16 {
        if (self.remaining() < 2) return error.Truncated;
        const p = self.pos;
        self.pos += 2;
        return (@as(u16, self.buf[p]) << 8) |
            @as(u16, self.buf[p + 1]);
    }

    fn readU32Be(self: *Reader) DecodeError!u32 {
        if (self.remaining() < 4) return error.Truncated;
        const p = self.pos;
        self.pos += 4;
        return (@as(u32, self.buf[p]) << 24) |
            (@as(u32, self.buf[p + 1]) << 16) |
            (@as(u32, self.buf[p + 2]) << 8) |
            @as(u32, self.buf[p + 3]);
    }

    fn readU64Be(self: *Reader) DecodeError!u64 {
        if (self.remaining() < 8) return error.Truncated;
        const p = self.pos;
        self.pos += 8;
        return (@as(u64, self.buf[p]) << 56) |
            (@as(u64, self.buf[p + 1]) << 48) |
            (@as(u64, self.buf[p + 2]) << 40) |
            (@as(u64, self.buf[p + 3]) << 32) |
            (@as(u64, self.buf[p + 4]) << 24) |
            (@as(u64, self.buf[p + 5]) << 16) |
            (@as(u64, self.buf[p + 6]) << 8) |
            @as(u64, self.buf[p + 7]);
    }
};

/// Bounded writer into a caller-owned output buffer.
pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    /// Initializes a writer over `buf`.
    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    /// Releases writer state. The writer owns no memory.
    pub fn deinit(self: *Writer) void {
        self.* = undefined;
    }

    /// Returns the number of bytes written so far.
    pub fn bytesWritten(self: *const Writer) usize {
        return self.pos;
    }

    /// Returns the written prefix of the output buffer.
    pub fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }

    /// Returns the number of bytes still available for writing.
    pub fn remaining(self: *const Writer) usize {
        return self.buf.len - self.pos;
    }

    /// Writes an unsigned integer.
    pub fn writeUint(self: *Writer, value: u64) EncodeError!usize {
        return self.writeMajorArg(.unsigned, value);
    }

    /// Writes a negative integer encoded as -1 minus `encoded`.
    pub fn writeNegInt(self: *Writer, encoded: u64) EncodeError!usize {
        return self.writeMajorArg(.negative, encoded);
    }

    /// Writes a signed integer using major type 0 or 1.
    pub fn writeSigned(self: *Writer, value: i64) EncodeError!usize {
        if (value >= 0) return self.writeUint(@intCast(value));
        return self.writeNegInt(@intCast(-1 - value));
    }

    /// Writes a byte string.
    pub fn writeBytes(self: *Writer, bytes: []const u8) EncodeError!usize {
        const start = self.pos;
        try self.ensureMajorArgAndPayload(bytes.len, bytes.len);
        _ = try self.writeTypeAndLen(.bytes, bytes.len);
        try self.writeRaw(bytes);
        return self.pos - start;
    }

    /// Writes a UTF-8 text string.
    pub fn writeText(self: *Writer, text: []const u8) EncodeError!usize {
        if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;

        const start = self.pos;
        try self.ensureMajorArgAndPayload(text.len, text.len);
        _ = try self.writeTypeAndLen(.text, text.len);
        try self.writeRaw(text);
        return self.pos - start;
    }

    /// Writes an array header for `count` child values.
    pub fn writeArray(self: *Writer, count: usize) EncodeError!usize {
        return self.writeTypeAndLen(.array, count);
    }

    /// Writes a map header for `count` key/value pairs.
    pub fn writeMap(self: *Writer, count: usize) EncodeError!usize {
        return self.writeTypeAndLen(.map, count);
    }

    /// Writes a boolean value.
    pub fn writeBool(self: *Writer, value: bool) EncodeError!usize {
        return self.writeByte(if (value) 0xf5 else 0xf4);
    }

    /// Writes null.
    pub fn writeNull(self: *Writer) EncodeError!usize {
        return self.writeByte(0xf6);
    }

    fn writeTypeAndLen(self: *Writer, major: MajorType, len: usize) EncodeError!usize {
        if (len > @as(usize, std.math.maxInt(u64))) return error.LengthTooLarge;
        return self.writeMajorArg(major, @intCast(len));
    }

    fn writeMajorArg(self: *Writer, major: MajorType, value: u64) EncodeError!usize {
        const start = self.pos;
        try self.ensure(majorArgLen(value));
        if (value <= 23) {
            _ = try self.writeByte(majorByte(major, @intCast(value)));
        } else if (value <= std.math.maxInt(u8)) {
            _ = try self.writeByte(majorByte(major, 24));
            _ = try self.writeByte(@intCast(value));
        } else if (value <= std.math.maxInt(u16)) {
            _ = try self.writeByte(majorByte(major, 25));
            try self.writeU16Be(@intCast(value));
        } else if (value <= std.math.maxInt(u32)) {
            _ = try self.writeByte(majorByte(major, 26));
            try self.writeU32Be(@intCast(value));
        } else {
            _ = try self.writeByte(majorByte(major, 27));
            try self.writeU64Be(value);
        }
        return self.pos - start;
    }

    fn writeRaw(self: *Writer, bytes: []const u8) EncodeError!void {
        try self.ensure(bytes.len);
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn writeByte(self: *Writer, value: u8) EncodeError!usize {
        try self.ensure(1);
        self.buf[self.pos] = value;
        self.pos += 1;
        return 1;
    }

    fn writeU16Be(self: *Writer, value: u16) EncodeError!void {
        try self.ensure(2);
        const p = self.pos;
        self.buf[p] = @intCast(value >> 8);
        self.buf[p + 1] = @intCast(value & 0xff);
        self.pos += 2;
    }

    fn writeU32Be(self: *Writer, value: u32) EncodeError!void {
        try self.ensure(4);
        const p = self.pos;
        self.buf[p] = @intCast(value >> 24);
        self.buf[p + 1] = @intCast((value >> 16) & 0xff);
        self.buf[p + 2] = @intCast((value >> 8) & 0xff);
        self.buf[p + 3] = @intCast(value & 0xff);
        self.pos += 4;
    }

    fn writeU64Be(self: *Writer, value: u64) EncodeError!void {
        try self.ensure(8);
        const p = self.pos;
        self.buf[p] = @intCast(value >> 56);
        self.buf[p + 1] = @intCast((value >> 48) & 0xff);
        self.buf[p + 2] = @intCast((value >> 40) & 0xff);
        self.buf[p + 3] = @intCast((value >> 32) & 0xff);
        self.buf[p + 4] = @intCast((value >> 24) & 0xff);
        self.buf[p + 5] = @intCast((value >> 16) & 0xff);
        self.buf[p + 6] = @intCast((value >> 8) & 0xff);
        self.buf[p + 7] = @intCast(value & 0xff);
        self.pos += 8;
    }

    fn ensure(self: *const Writer, needed: usize) EncodeError!void {
        if (self.remaining() < needed) return error.BufferTooSmall;
    }

    fn ensureMajorArgAndPayload(self: *const Writer, arg: usize, payload_len: usize) EncodeError!void {
        const header_len = majorArgLen(@intCast(arg));
        const remaining_bytes = self.remaining();
        if (remaining_bytes < payload_len) return error.BufferTooSmall;
        if (remaining_bytes - payload_len < header_len) return error.BufferTooSmall;
    }
};

/// Validates that `input` contains exactly one complete supported CBOR value.
pub fn validate(input: []const u8, params: Params) DecodeError!void {
    var reader = Reader.init(input);
    defer reader.deinit();

    try reader.skipValue(params);
    try reader.expectDone();
}

fn majorByte(major: MajorType, addl: u5) u8 {
    return (@as(u8, @backingInt(major)) << 5) | @as(u8, addl);
}

fn majorArgLen(value: u64) usize {
    if (value <= 23) return 1;
    if (value <= std.math.maxInt(u8)) return 2;
    if (value <= std.math.maxInt(u16)) return 3;
    if (value <= std.math.maxInt(u32)) return 5;
    return 9;
}

test "round trip unsigned integers across header widths" {
    // Arrange.
    const allocator = std.testing.allocator;
    const values = [_]u64{
        0,
        1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        std.math.maxInt(u32) + 1,
        std.math.maxInt(u64),
    };
    const out = try allocator.alloc(u8, values.len * max_header_len);
    defer allocator.free(out);

    // Act.
    var writer = Writer.init(out);
    defer writer.deinit();
    for (values) |value| _ = try writer.writeUint(value);

    // Assert.
    var reader = Reader.init(writer.written());
    defer reader.deinit();
    for (values) |expected| {
        const actual = try reader.readValue();
        try std.testing.expectEqual(Value{ .unsigned = expected }, actual);
    }
    try reader.expectDone();
}

test "round trip negative integers as encoded CBOR magnitude" {
    // Arrange.
    const allocator = std.testing.allocator;
    const values = [_]u64{ 0, 1, 10, 23, 24, 1000, std.math.maxInt(u32) + 7 };
    const out = try allocator.alloc(u8, values.len * max_header_len);
    defer allocator.free(out);

    // Act.
    var writer = Writer.init(out);
    defer writer.deinit();
    for (values) |value| _ = try writer.writeNegInt(value);

    // Assert.
    var reader = Reader.init(writer.written());
    defer reader.deinit();
    for (values) |expected| {
        const actual = try reader.readValue();
        try std.testing.expectEqual(Value{ .negative = expected }, actual);
    }
    try reader.expectDone();
}

test "round trip byte and text strings borrow input" {
    // Arrange.
    const allocator = std.testing.allocator;
    const bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const text = "onyx cbor \xf0\x9f\x8c\x8a";
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    // Act.
    var writer = Writer.init(out);
    defer writer.deinit();
    _ = try writer.writeBytes(&bytes);
    _ = try writer.writeText(text);

    // Assert.
    const encoded = writer.written();
    var reader = Reader.init(encoded);
    defer reader.deinit();

    const got_bytes = try reader.readValue();
    const got_text = try reader.readValue();
    try std.testing.expectEqual(Value{ .bytes = encoded[1..5] }, got_bytes);
    try std.testing.expectEqual(Value{ .text = encoded[6 .. 6 + text.len] }, got_text);
    try std.testing.expectEqual(@intFromPtr(encoded.ptr) + 1, @intFromPtr(got_bytes.bytes.ptr));
    try std.testing.expectEqual(@intFromPtr(encoded.ptr) + 6, @intFromPtr(got_text.text.ptr));
    try reader.expectDone();
}

test "round trip arrays through streaming child reads" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 32);
    defer allocator.free(out);

    // Act.
    var writer = Writer.init(out);
    defer writer.deinit();
    _ = try writer.writeArray(3);
    _ = try writer.writeUint(7);
    _ = try writer.writeBool(true);
    _ = try writer.writeNull();

    // Assert.
    var reader = Reader.init(writer.written());
    defer reader.deinit();
    try std.testing.expectEqual(Value{ .array = 3 }, try reader.readValue());
    try std.testing.expectEqual(Value{ .unsigned = 7 }, try reader.readValue());
    try std.testing.expectEqual(Value{ .boolean = true }, try reader.readValue());
    try std.testing.expectEqual(Value.null, try reader.readValue());
    try reader.expectDone();
    try validate(writer.written(), .{});
}

test "round trip maps through streaming key value reads" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    // Act.
    var writer = Writer.init(out);
    defer writer.deinit();
    _ = try writer.writeMap(2);
    _ = try writer.writeText("n");
    _ = try writer.writeUint(9);
    _ = try writer.writeText("ok");
    _ = try writer.writeBool(false);

    // Assert.
    var reader = Reader.init(writer.written());
    defer reader.deinit();
    try std.testing.expectEqual(Value{ .map = 2 }, try reader.readValue());
    const first_key = try reader.readValue();
    switch (first_key) {
        .text => |actual| try std.testing.expectEqualStrings("n", actual),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(Value{ .unsigned = 9 }, try reader.readValue());
    const second_key = try reader.readValue();
    switch (second_key) {
        .text => |actual| try std.testing.expectEqualStrings("ok", actual),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(Value{ .boolean = false }, try reader.readValue());
    try reader.expectDone();
    try validate(writer.written(), .{});
}

test "round trip booleans and null" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 8);
    defer allocator.free(out);

    // Act.
    var writer = Writer.init(out);
    defer writer.deinit();
    _ = try writer.writeBool(false);
    _ = try writer.writeBool(true);
    _ = try writer.writeNull();

    // Assert.
    var reader = Reader.init(writer.written());
    defer reader.deinit();
    try std.testing.expectEqual(Value{ .boolean = false }, try reader.readValue());
    try std.testing.expectEqual(Value{ .boolean = true }, try reader.readValue());
    try std.testing.expectEqual(Value.null, try reader.readValue());
    try reader.expectDone();
}

test "truncation is rejected for scalar payloads and complete containers" {
    // Arrange.
    const cases = [_][]const u8{
        &[_]u8{0x18},
        &[_]u8{ 0x19, 0x01 },
        &[_]u8{ 0x1a, 0x01, 0x02, 0x03 },
        &[_]u8{ 0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
        &[_]u8{ 0x43, 0x01, 0x02 },
        &[_]u8{ 0x62, 'h' },
        &[_]u8{0x81},
        &[_]u8{ 0xa1, 0x61, 'k' },
    };

    // Act and assert.
    for (cases) |case| {
        try std.testing.expectError(error.Truncated, validate(case, .{}));
    }
}

test "unsupported and malformed encodings are rejected" {
    // Arrange.
    const trailing = [_]u8{ 0x00, 0x00 };
    const indefinite_bytes = [_]u8{0x5f};
    const tag = [_]u8{ 0xc0, 0x00 };
    const float16 = [_]u8{ 0xf9, 0x00, 0x00 };
    const bad_utf8 = [_]u8{ 0x61, 0xff };

    // Act and assert.
    try std.testing.expectError(error.TrailingBytes, validate(&trailing, .{}));
    try std.testing.expectError(error.IndefiniteLength, validate(&indefinite_bytes, .{}));
    try std.testing.expectError(error.UnsupportedTag, validate(&tag, .{}));
    try std.testing.expectError(error.UnsupportedSimple, validate(&float16, .{}));
    try std.testing.expectError(error.InvalidUtf8, validate(&bad_utf8, .{}));
}

test "encode rejects short buffers and invalid text" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 2);
    defer allocator.free(out);
    const bad_text = [_]u8{ 0xff, 0xff };

    // Act.
    var writer = Writer.init(out);
    defer writer.deinit();

    // Assert.
    try std.testing.expectError(error.BufferTooSmall, writer.writeBytes("abc"));
    try std.testing.expectEqual(@as(usize, 0), writer.bytesWritten());
    try std.testing.expectError(error.InvalidUtf8, writer.writeText(&bad_text));
    try std.testing.expectEqual(@as(usize, 0), writer.bytesWritten());
}

test "validation enforces maximum nested depth" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 16);
    defer allocator.free(out);
    var writer = Writer.init(out);
    defer writer.deinit();
    _ = try writer.writeArray(1);
    _ = try writer.writeArray(1);
    _ = try writer.writeNull();

    // Act and assert.
    try std.testing.expectError(error.NestingTooDeep, validate(writer.written(), .{ .max_depth = 1 }));
    try validate(writer.written(), .{ .max_depth = 2 });
}
