// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! QUIC v1 packet header coding and header-protection masking model.
//!
//! This module handles only RFC 9000 packet header structure. It deliberately
//! does not derive header-protection masks or manage crypto keys; callers pass
//! the already-derived five-byte mask used to protect or unprotect a header.

const std = @import("std");

pub const max_connection_id_len: usize = 20;
pub const max_packet_number_len: usize = 4;

pub const QuicPacketError = error{
    BufferTooSmall,
    InvalidConnectionIdLength,
    InvalidFixedBit,
    InvalidHeaderForm,
    InvalidPacketNumberLength,
    InvalidLongPacketType,
    PacketNumberTooLarge,
    Truncated,
};

pub const LongPacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

pub const PacketNumberLength = enum(u2) {
    one = 0,
    two = 1,
    three = 2,
    four = 3,

    pub fn byteLen(self: PacketNumberLength) usize {
        return @as(usize, @backingInt(self)) + 1;
    }

    pub fn fromByteLen(len: usize) QuicPacketError!PacketNumberLength {
        return switch (len) {
            1 => .one,
            2 => .two,
            3 => .three,
            4 => .four,
            else => error.InvalidPacketNumberLength,
        };
    }
};

pub const ConnectionId = struct {
    len: u8 = 0,
    bytes: [max_connection_id_len]u8 = @splat(0),

    pub fn init(bytes: []const u8) QuicPacketError!ConnectionId {
        if (bytes.len > max_connection_id_len) return error.InvalidConnectionIdLength;

        var id = ConnectionId{ .len = @intCast(bytes.len) };
        @memcpy(id.bytes[0..bytes.len], bytes);
        return id;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..@as(usize, self.len)];
    }
};

pub const LongHeader = struct {
    packet_type: LongPacketType,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    packet_number_len: PacketNumberLength = .one,
};

pub const DecodedLongHeader = struct {
    header: LongHeader,
    consumed: usize,
};

pub const ShortHeader = struct {
    spin: bool = false,
    key_phase: bool = false,
    dcid: ConnectionId,
    packet_number: u32,
    packet_number_len: PacketNumberLength,
};

pub const DecodedShortHeader = struct {
    header: ShortHeader,
    consumed: usize,
};

pub fn encodeLongHeader(out: []u8, header: LongHeader) QuicPacketError!usize {
    const dcid = header.dcid.slice();
    const scid = header.scid.slice();
    if (dcid.len > max_connection_id_len or scid.len > max_connection_id_len) {
        return error.InvalidConnectionIdLength;
    }

    const needed = 1 + 4 + 1 + dcid.len + 1 + scid.len;
    if (out.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    out[pos] = 0x80 | 0x40 |
        (@as(u8, @backingInt(header.packet_type)) << 4) |
        @as(u8, @backingInt(header.packet_number_len));
    pos += 1;

    std.mem.writeInt(u32, out[pos..][0..4], header.version, .big);
    pos += 4;

    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos .. pos + dcid.len], dcid);
    pos += dcid.len;

    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos .. pos + scid.len], scid);
    pos += scid.len;

    return pos;
}

pub fn decodeLongHeader(input: []const u8) QuicPacketError!DecodedLongHeader {
    if (input.len < 6) return error.Truncated;
    const first = input[0];
    if ((first & 0x80) == 0) return error.InvalidHeaderForm;
    if ((first & 0x40) == 0) return error.InvalidFixedBit;

    const packet_type = longPacketTypeFromBits((first >> 4) & 0x03);
    const packet_number_len = packetNumberLengthFromBits(first & 0x03);
    const version = std.mem.readInt(u32, input[1..5], .big);

    var pos: usize = 5;
    const dcid_len = input[pos];
    pos += 1;
    if (dcid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (input.len < pos + dcid_len + 1) return error.Truncated;
    const dcid = try ConnectionId.init(input[pos .. pos + dcid_len]);
    pos += dcid_len;

    const scid_len = input[pos];
    pos += 1;
    if (scid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (input.len < pos + scid_len) return error.Truncated;
    const scid = try ConnectionId.init(input[pos .. pos + scid_len]);
    pos += scid_len;

    return .{
        .header = .{
            .packet_type = packet_type,
            .version = version,
            .dcid = dcid,
            .scid = scid,
            .packet_number_len = packet_number_len,
        },
        .consumed = pos,
    };
}

pub fn encodeShortHeader(out: []u8, header: ShortHeader) QuicPacketError!usize {
    const dcid = header.dcid.slice();
    if (dcid.len > max_connection_id_len) return error.InvalidConnectionIdLength;

    const pn_len = header.packet_number_len.byteLen();
    const needed = 1 + dcid.len + pn_len;
    if (out.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    out[pos] = 0x40 |
        (if (header.spin) @as(u8, 0x20) else 0) |
        (if (header.key_phase) @as(u8, 0x04) else 0) |
        @as(u8, @backingInt(header.packet_number_len));
    pos += 1;

    @memcpy(out[pos .. pos + dcid.len], dcid);
    pos += dcid.len;
    pos += try encodePacketNumber(out[pos..], header.packet_number, header.packet_number_len);

    return pos;
}

pub fn decodeShortHeader(input: []const u8, dcid_len: usize) QuicPacketError!DecodedShortHeader {
    if (input.len < 1) return error.Truncated;
    if (dcid_len > max_connection_id_len) return error.InvalidConnectionIdLength;

    const first = input[0];
    if ((first & 0x80) != 0) return error.InvalidHeaderForm;
    if ((first & 0x40) == 0) return error.InvalidFixedBit;

    const packet_number_len = packetNumberLengthFromBits(first & 0x03);
    const pn_len = packet_number_len.byteLen();
    const needed = 1 + dcid_len + pn_len;
    if (input.len < needed) return error.Truncated;

    const dcid = try ConnectionId.init(input[1 .. 1 + dcid_len]);
    const pn_offset = 1 + dcid_len;
    const packet_number = try decodePacketNumber(input[pn_offset .. pn_offset + pn_len], packet_number_len);

    return .{
        .header = .{
            .spin = (first & 0x20) != 0,
            .key_phase = (first & 0x04) != 0,
            .dcid = dcid,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
        },
        .consumed = needed,
    };
}

pub fn encodePacketNumber(
    out: []u8,
    packet_number: u32,
    packet_number_len: PacketNumberLength,
) QuicPacketError!usize {
    const len = packet_number_len.byteLen();
    if (out.len < len) return error.BufferTooSmall;
    if (!packetNumberFits(packet_number, len)) return error.PacketNumberTooLarge;

    var i: usize = 0;
    while (i < len) : (i += 1) {
        const shift: u5 = @intCast((len - 1 - i) * 8);
        out[i] = @intCast((packet_number >> shift) & 0xff);
    }
    return len;
}

pub fn decodePacketNumber(
    input: []const u8,
    packet_number_len: PacketNumberLength,
) QuicPacketError!u32 {
    const len = packet_number_len.byteLen();
    if (input.len < len) return error.Truncated;

    var value: u32 = 0;
    for (input[0..len]) |byte| {
        value = (value << 8) | byte;
    }
    return value;
}

pub fn applyHeaderProtection(packet: []u8, packet_number_offset: usize, mask: [5]u8) QuicPacketError!void {
    try maskHeader(packet, packet_number_offset, mask, .apply);
}

pub fn removeHeaderProtection(packet: []u8, packet_number_offset: usize, mask: [5]u8) QuicPacketError!void {
    try maskHeader(packet, packet_number_offset, mask, .remove);
}

const ProtectionMode = enum {
    apply,
    remove,
};

fn maskHeader(packet: []u8, packet_number_offset: usize, mask: [5]u8, mode: ProtectionMode) QuicPacketError!void {
    if (packet.len == 0 or packet_number_offset == 0) return error.Truncated;
    if (packet_number_offset >= packet.len) return error.Truncated;

    const first_mask = headerProtectionFirstByteMask(packet[0]);
    const pn_len = switch (mode) {
        .apply => packetNumberLengthFromBits(packet[0] & 0x03).byteLen(),
        .remove => blk: {
            packet[0] ^= first_mask & mask[0];
            break :blk packetNumberLengthFromBits(packet[0] & 0x03).byteLen();
        },
    };

    if (packet.len < packet_number_offset + pn_len) return error.Truncated;

    if (mode == .apply) packet[0] ^= first_mask & mask[0];
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        packet[packet_number_offset + i] ^= mask[i + 1];
    }
}

fn headerProtectionFirstByteMask(first: u8) u8 {
    return if ((first & 0x80) != 0) 0x0f else 0x1f;
}

fn packetNumberFits(packet_number: u32, len: usize) bool {
    return switch (len) {
        1 => packet_number <= 0xff,
        2 => packet_number <= 0xffff,
        3 => packet_number <= 0xff_ffff,
        4 => true,
        else => false,
    };
}

fn longPacketTypeFromBits(bits: u8) LongPacketType {
    return switch (bits & 0x03) {
        0 => .initial,
        1 => .zero_rtt,
        2 => .handshake,
        3 => .retry,
        else => unreachable,
    };
}

fn packetNumberLengthFromBits(bits: u8) PacketNumberLength {
    return switch (bits & 0x03) {
        0 => .one,
        1 => .two,
        2 => .three,
        3 => .four,
        else => unreachable,
    };
}

fn expectConnectionId(expected: []const u8, actual: ConnectionId) !void {
    try std.testing.expectEqualSlices(u8, expected, actual.slice());
}

test "long header round-trip is deterministic" {
    const dcid_bytes = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid_bytes = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    const header = LongHeader{
        .packet_type = .initial,
        .version = 1,
        .dcid = try ConnectionId.init(&dcid_bytes),
        .scid = try ConnectionId.init(&scid_bytes),
        .packet_number_len = .four,
    };

    var encoded: [64]u8 = undefined;
    const len = try encodeLongHeader(&encoded, header);

    const expected = [_]u8{
        0xc3,
        0x00,
        0x00,
        0x00,
        0x01,
        0x08,
        0x83,
        0x94,
        0xc8,
        0xf0,
        0x3e,
        0x51,
        0x57,
        0x08,
        0x04,
        0x00,
        0x01,
        0x02,
        0x03,
    };
    try std.testing.expectEqualSlices(u8, &expected, encoded[0..len]);

    const decoded = try decodeLongHeader(encoded[0..len]);
    try std.testing.expectEqual(len, decoded.consumed);
    try std.testing.expectEqual(LongPacketType.initial, decoded.header.packet_type);
    try std.testing.expectEqual(@as(u32, 1), decoded.header.version);
    try std.testing.expectEqual(PacketNumberLength.four, decoded.header.packet_number_len);
    try expectConnectionId(&dcid_bytes, decoded.header.dcid);
    try expectConnectionId(&scid_bytes, decoded.header.scid);

    var encoded_again: [64]u8 = undefined;
    const len_again = try encodeLongHeader(&encoded_again, decoded.header);
    try std.testing.expectEqualSlices(u8, encoded[0..len], encoded_again[0..len_again]);
}

test "short header round-trip carries spin key phase dcid and packet number" {
    const dcid_bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x42 };
    const header = ShortHeader{
        .spin = true,
        .key_phase = true,
        .dcid = try ConnectionId.init(&dcid_bytes),
        .packet_number = 0xface,
        .packet_number_len = .two,
    };

    var encoded: [32]u8 = undefined;
    const len = try encodeShortHeader(&encoded, header);
    const expected = [_]u8{ 0x65, 0xde, 0xad, 0xbe, 0xef, 0x42, 0xfa, 0xce };
    try std.testing.expectEqualSlices(u8, &expected, encoded[0..len]);

    const decoded = try decodeShortHeader(encoded[0..len], dcid_bytes.len);
    try std.testing.expectEqual(len, decoded.consumed);
    try std.testing.expect(decoded.header.spin);
    try std.testing.expect(decoded.header.key_phase);
    try expectConnectionId(&dcid_bytes, decoded.header.dcid);
    try std.testing.expectEqual(@as(u32, 0xface), decoded.header.packet_number);
    try std.testing.expectEqual(PacketNumberLength.two, decoded.header.packet_number_len);
}

test "packet-number length encoding supports one through four bytes" {
    const cases = [_]struct {
        len: PacketNumberLength,
        value: u32,
        bytes: []const u8,
    }{
        .{ .len = .one, .value = 0xab, .bytes = &.{0xab} },
        .{ .len = .two, .value = 0xabcd, .bytes = &.{ 0xab, 0xcd } },
        .{ .len = .three, .value = 0xab_cdef, .bytes = &.{ 0xab, 0xcd, 0xef } },
        .{ .len = .four, .value = 0xabcd_ef01, .bytes = &.{ 0xab, 0xcd, 0xef, 0x01 } },
    };

    for (cases) |case| {
        var out: [4]u8 = undefined;
        const encoded_len = try encodePacketNumber(&out, case.value, case.len);
        try std.testing.expectEqual(case.len.byteLen(), encoded_len);
        try std.testing.expectEqualSlices(u8, case.bytes, out[0..encoded_len]);
        try std.testing.expectEqual(case.value, try decodePacketNumber(out[0..encoded_len], case.len));
    }

    var too_small: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodePacketNumber(too_small[0..0], 1, .one));
    try std.testing.expectError(error.PacketNumberTooLarge, encodePacketNumber(&too_small, 0x100, .one));
    try std.testing.expectError(error.InvalidPacketNumberLength, PacketNumberLength.fromByteLen(0));
    try std.testing.expectEqual(PacketNumberLength.four, try PacketNumberLength.fromByteLen(4));
}

test "header protection is reversible for long and short headers" {
    const mask = [_]u8{ 0x44, 0x9d, 0x31, 0x22, 0xa7 };

    const long_header = LongHeader{
        .packet_type = .handshake,
        .version = 1,
        .dcid = try ConnectionId.init(&.{ 0xaa, 0xbb, 0xcc }),
        .scid = try ConnectionId.init(&.{ 0x01, 0x02 }),
        .packet_number_len = .three,
    };
    var long_packet: [64]u8 = @splat(0);
    var long_len = try encodeLongHeader(&long_packet, long_header);
    const long_pn_offset = long_len;
    long_len += try encodePacketNumber(long_packet[long_len..], 0x10203, .three);
    long_packet[long_len] = 0x40;
    long_len += 1;
    const long_original = long_packet;

    try applyHeaderProtection(long_packet[0..long_len], long_pn_offset, mask);
    try std.testing.expect(!std.mem.eql(u8, long_original[0..long_len], long_packet[0..long_len]));
    try std.testing.expectEqual(@as(u8, long_original[0] ^ (0x0f & mask[0])), long_packet[0]);
    try std.testing.expectEqual(@as(u8, 0x01 ^ mask[1]), long_packet[long_pn_offset]);
    try removeHeaderProtection(long_packet[0..long_len], long_pn_offset, mask);
    try std.testing.expectEqualSlices(u8, long_original[0..long_len], long_packet[0..long_len]);

    const short_header = ShortHeader{
        .spin = true,
        .key_phase = false,
        .dcid = try ConnectionId.init(&.{ 0x10, 0x11, 0x12, 0x13 }),
        .packet_number = 0x7f,
        .packet_number_len = .one,
    };
    var short_packet: [32]u8 = @splat(0);
    var short_len = try encodeShortHeader(&short_packet, short_header);
    const short_pn_offset = short_len - short_header.packet_number_len.byteLen();
    short_packet[short_len] = 0x99;
    short_len += 1;
    const short_original = short_packet;

    try applyHeaderProtection(short_packet[0..short_len], short_pn_offset, mask);
    try std.testing.expect(!std.mem.eql(u8, short_original[0..short_len], short_packet[0..short_len]));
    try std.testing.expectEqual(@as(u8, short_original[0] ^ (0x1f & mask[0])), short_packet[0]);
    try removeHeaderProtection(short_packet[0..short_len], short_pn_offset, mask);
    try std.testing.expectEqualSlices(u8, short_original[0..short_len], short_packet[0..short_len]);
}

test "truncation and invalid header errors are explicit" {
    try std.testing.expectError(error.Truncated, decodeLongHeader(&.{ 0xc0, 0, 0, 0, 1 }));
    try std.testing.expectError(error.InvalidHeaderForm, decodeLongHeader(&.{ 0x40, 0, 0, 0, 1, 0 }));
    try std.testing.expectError(error.InvalidFixedBit, decodeLongHeader(&.{ 0x80, 0, 0, 0, 1, 0 }));
    try std.testing.expectError(
        error.Truncated,
        decodeLongHeader(&.{ 0xc0, 0, 0, 0, 1, 3, 0xaa, 0xbb }),
    );
    try std.testing.expectError(
        error.InvalidConnectionIdLength,
        decodeLongHeader(&.{ 0xc0, 0, 0, 0, 1, 21 }),
    );

    try std.testing.expectError(error.Truncated, decodeShortHeader(&.{}, 0));
    try std.testing.expectError(error.InvalidHeaderForm, decodeShortHeader(&.{ 0xc0, 0 }, 0));
    try std.testing.expectError(error.InvalidFixedBit, decodeShortHeader(&.{ 0x00, 0 }, 0));
    try std.testing.expectError(error.Truncated, decodeShortHeader(&.{ 0x43, 0xde, 0xad }, 1));
    try std.testing.expectError(error.Truncated, decodePacketNumber(&.{0xaa}, .two));

    var packet = [_]u8{ 0x43, 0x01, 0x02 };
    try std.testing.expectError(error.Truncated, applyHeaderProtection(&packet, 3, .{ 1, 2, 3, 4, 5 }));
    try std.testing.expectError(error.Truncated, removeHeaderProtection(&packet, 3, .{ 1, 2, 3, 4, 5 }));
}
