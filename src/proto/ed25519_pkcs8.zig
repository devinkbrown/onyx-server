// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) {
        @compileError("ed25519_pkcs8 requires a 64-bit target");
    }
}

pub const seed_len = 32;
pub const der_len = 48;

const Tag = enum(u8) {
    integer = 0x02,
    oid = 0x06,
    octet_string = 0x04,
    sequence = 0x30,
};

const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

pub const ParseError = error{
    Truncated,
    Oversize,
    InvalidDer,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    InvalidKeyLength,
};

pub const EncodeError = error{
    NoSpaceLeft,
};

pub fn parse(der: []const u8) ParseError![seed_len]u8 {
    var top_reader = Reader.init(der);
    const top = try top_reader.expect(.sequence);
    if (!top_reader.done()) return error.InvalidDer;

    var body = Reader.init(top.value);

    const version = try body.expect(.integer);
    if (!std.mem.eql(u8, version.value, &[_]u8{0x00})) {
        return error.UnsupportedVersion;
    }

    const algorithm = try body.expect(.sequence);
    try parseAlgorithm(algorithm.value);

    const private_key = try body.expect(.octet_string);
    if (!body.done()) return error.InvalidDer;

    var private_reader = Reader.init(private_key.value);
    const inner = try private_reader.expect(.octet_string);
    if (!private_reader.done()) return error.InvalidDer;
    if (inner.value.len != seed_len) return error.InvalidKeyLength;

    var seed: [seed_len]u8 = undefined;
    @memcpy(&seed, inner.value[0..seed_len]);
    return seed;
}

pub fn encode(out: []u8, seed: [seed_len]u8) EncodeError![]u8 {
    var writer = Writer.init(out);
    try writer.tlv(.sequence, der_len - 2);
    try writer.value(&[_]u8{ 0x02, 0x01, 0x00 });
    try writer.value(&[_]u8{ 0x30, 0x05, 0x06, 0x03 });
    try writer.value(&oid_ed25519);
    try writer.tlv(.octet_string, seed_len + 2);
    try writer.tlv(.octet_string, seed_len);
    try writer.value(&seed);
    return writer.written();
}

fn parseAlgorithm(der: []const u8) ParseError!void {
    var reader = Reader.init(der);
    const oid = try reader.expect(.oid);
    if (!std.mem.eql(u8, oid.value, &oid_ed25519)) {
        return error.UnsupportedAlgorithm;
    }
    if (!reader.done()) return error.InvalidDer;
}

const Tlv = struct {
    tag: Tag,
    value: []const u8,
};

const Reader = struct {
    der: []const u8,
    pos: usize,

    fn init(der: []const u8) Reader {
        return .{ .der = der, .pos = 0 };
    }

    fn done(self: Reader) bool {
        return self.pos == self.der.len;
    }

    fn expect(self: *Reader, tag: Tag) ParseError!Tlv {
        const tlv = try self.read();
        if (tlv.tag != tag) return error.InvalidDer;
        return tlv;
    }

    fn read(self: *Reader) ParseError!Tlv {
        const tag_octet = try self.takeByte();
        const tag: Tag = switch (tag_octet) {
            @backingInt(Tag.integer) => .integer,
            @backingInt(Tag.oid) => .oid,
            @backingInt(Tag.octet_string) => .octet_string,
            @backingInt(Tag.sequence) => .sequence,
            else => return error.InvalidDer,
        };

        const len = try self.readLength();
        if (self.der.len - self.pos < len) return error.Truncated;

        const start = self.pos;
        self.pos += len;
        return .{ .tag = tag, .value = self.der[start..self.pos] };
    }

    fn takeByte(self: *Reader) ParseError!u8 {
        if (self.pos >= self.der.len) return error.Truncated;
        const byte = self.der[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readLength(self: *Reader) ParseError!usize {
        const first = try self.takeByte();
        if ((first & 0x80) == 0) return first;

        const count = first & 0x7f;
        if (count == 0) return error.InvalidDer;
        if (count > @sizeOf(usize)) return error.Oversize;
        if (self.der.len - self.pos < count) return error.Truncated;
        if (self.der[self.pos] == 0) return error.InvalidDer;

        var len: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            len = (len << 8) | self.der[self.pos + i];
        }
        self.pos += count;

        if (len < 128) return error.InvalidDer;
        return len;
    }
};

const Writer = struct {
    out: []u8,
    pos: usize,

    fn init(out: []u8) Writer {
        return .{ .out = out, .pos = 0 };
    }

    fn written(self: Writer) []u8 {
        return self.out[0..self.pos];
    }

    fn tlv(self: *Writer, tag: Tag, len: usize) EncodeError!void {
        try self.byte(@backingInt(tag));
        try self.length(len);
    }

    fn value(self: *Writer, bytes: []const u8) EncodeError!void {
        if (self.out.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.out[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn byte(self: *Writer, value_byte: u8) EncodeError!void {
        if (self.pos >= self.out.len) return error.NoSpaceLeft;
        self.out[self.pos] = value_byte;
        self.pos += 1;
    }

    fn length(self: *Writer, len: usize) EncodeError!void {
        if (len < 128) {
            try self.byte(@intCast(len));
            return;
        }

        var tmp: [@sizeOf(usize)]u8 = undefined;
        var n = len;
        var count: usize = 0;
        while (n != 0) : (n >>= 8) {
            tmp[tmp.len - 1 - count] = @intCast(n & 0xff);
            count += 1;
        }

        try self.byte(0x80 | @as(u8, @intCast(count)));
        try self.value(tmp[tmp.len - count ..]);
    }
};

fn testSeed() [seed_len]u8 {
    var seed: [seed_len]u8 = undefined;
    for (&seed, 0..) |*byte, i| {
        byte.* = @intCast(i);
    }
    return seed;
}

fn expectedDerForTestSeed() [der_len]u8 {
    return .{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
}

test "encode emits known DER for a fixed Ed25519 seed" {
    // Arrange
    const seed = testSeed();
    const expected = expectedDerForTestSeed();
    var out: [der_len]u8 = undefined;

    // Act
    const actual = try encode(&out, seed);

    // Assert
    try std.testing.expectEqualSlices(u8, &expected, actual);
}

test "parse returns the seed from known DER" {
    // Arrange
    const expected = testSeed();
    const der = expectedDerForTestSeed();

    // Act
    const actual = try parse(&der);

    // Assert
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "parse and encode round-trip all byte values used by a seed prefix" {
    // Arrange
    var seed: [seed_len]u8 = undefined;
    for (&seed, 0..) |*byte, i| {
        byte.* = @intCast(0xff - i);
    }
    var out: [der_len]u8 = undefined;

    // Act
    const der = try encode(&out, seed);
    const actual = try parse(der);

    // Assert
    try std.testing.expectEqualSlices(u8, &seed, &actual);
}

test "parse rejects every truncated prefix of a valid key" {
    // Arrange
    const der = expectedDerForTestSeed();

    // Act, Assert
    for (0..der.len) |end| {
        try std.testing.expectError(error.Truncated, parse(der[0..end]));
    }
}

test "encode reports NoSpaceLeft for caller buffers that are too small" {
    // Arrange
    const seed = testSeed();
    var out: [der_len - 1]u8 = undefined;

    // Act, Assert
    try std.testing.expectError(error.NoSpaceLeft, encode(&out, seed));
}

test "parse rejects an oversized inner private key" {
    // Arrange
    var der = [_]u8{
        0x30, 0x2f, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x23, 0x04, 0x21,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa,
    };

    // Act, Assert
    try std.testing.expectError(error.InvalidKeyLength, parse(&der));
}

test "parse rejects a DER length field wider than usize" {
    // Arrange
    const der = [_]u8{
        0x30,
        0x89,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    // Act, Assert
    try std.testing.expectError(error.Oversize, parse(&der));
}

test "parse rejects unsupported version and algorithm parameters" {
    // Arrange
    var bad_version = expectedDerForTestSeed();
    bad_version[4] = 0x01;

    var bad_algorithm = expectedDerForTestSeed();
    bad_algorithm[5] = 0x07;
    bad_algorithm[12] = 0x04;
    bad_algorithm[13] = 0x20;

    // Act, Assert
    try std.testing.expectError(error.UnsupportedVersion, parse(&bad_version));
    try std.testing.expectError(error.InvalidDer, parse(&bad_algorithm));
}

test "parse rejects trailing bytes after the top-level sequence" {
    // Arrange
    var der: [der_len + 1]u8 = undefined;
    const valid = expectedDerForTestSeed();
    @memcpy(der[0..der_len], &valid);
    der[der_len] = 0x00;

    // Act, Assert
    try std.testing.expectError(error.InvalidDer, parse(&der));
}
