// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TURN (RFC 5766) message framing and parsing — no sockets, no heap.
//!
//! Covers: STUN header (20-byte, magic cookie 0x2112A442, 96-bit txn id),
//! TLV attribute codec (4-byte padded), TURN methods and attributes
//! (REQUESTED-TRANSPORT, LIFETIME, XOR-RELAYED/PEER-ADDRESS, DATA,
//! CHANNEL-NUMBER), XOR-address transform for IPv4 and IPv6, and compact
//! ChannelData framing.  All operations work on caller-provided slices.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// ── constants ────────────────────────────────────────────────────────────────

pub const magic_cookie: u32 = 0x2112_A442;
pub const stun_header_len: usize = 20;
pub const channel_data_header_len: usize = 4;

// ── STUN message types ───────────────────────────────────────────────────────

/// Message class encoded in the two reserved bits of the type field.
pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success_response = 0b10,
    error_response = 0b11,
};

/// TURN / STUN method values (12-bit).
pub const Method = enum(u12) {
    binding = 0x001,
    allocate = 0x003,
    refresh = 0x004,
    send = 0x006,
    data = 0x007,
    create_permission = 0x008,
    channel_bind = 0x009,
};

/// Encode a (method, class) pair into the 16-bit STUN message-type word.
/// The class bits are spread across positions 4-5 and 8 of the type field
/// per RFC 5389 §6.
pub fn encodeMessageType(method: Method, class: Class) u16 {
    const m: u16 = @backingInt(method);
    const c: u16 = @backingInt(class);
    // method bits: M11..M6 in bits 13..8, M5..M4 in bits 6..5, M3..M0 in 3..0
    // class bits:  C1 in bit 7, C0 in bit 4
    const m_lo: u16 = m & 0x00F; // M3..M0  (RFC 5389 §6: M3..M0 → bits 3-0)
    const m_high: u16 = (m >> 6) & 0x03F; // M11..M6 → bits 13..8
    const m_mid2: u16 = (m >> 4) & 0x003; // M5..M4
    const c1: u16 = (c >> 1) & 0x1;
    const c0: u16 = c & 0x1;
    return (m_high << 8) | (c1 << 7) | (m_mid2 << 5) | (c0 << 4) | m_lo;
}

/// Decode the 16-bit type word back into (Method, Class).
pub const DecodedType = struct { method: Method, class: Class };
pub fn decodeMessageType(word: u16) error{UnknownMethod}!DecodedType {
    const m_high: u16 = (word >> 8) & 0x03F; // bits 13..8
    const m_mid2: u16 = (word >> 5) & 0x003; // bits 6..5
    const m_lo: u16 = word & 0x00F; // bits 3..0
    const m: u16 = (m_high << 6) | (m_mid2 << 4) | m_lo;
    const c1: u16 = (word >> 7) & 0x1;
    const c0: u16 = (word >> 4) & 0x1;
    const c: u2 = @truncate((c1 << 1) | c0);
    const method = std.enums.fromInt(Method, @as(u12, @truncate(m))) orelse return error.UnknownMethod;
    const class: Class = @fromBackingInt(@intCast(c));
    return .{ .method = method, .class = class };
}

pub const TxnId = [12]u8;

pub const StunHeader = struct {
    msg_type: u16, // encoded (method + class)
    length: u16, // byte length of attributes following header
    txn_id: TxnId,
};

/// Write a 20-byte STUN header into `buf[0..20]`.
pub fn encodeStunHeader(buf: []u8, hdr: StunHeader) void {
    std.debug.assert(buf.len >= stun_header_len);
    mem.writeInt(u16, buf[0..2], hdr.msg_type, .big);
    mem.writeInt(u16, buf[2..4], hdr.length, .big);
    mem.writeInt(u32, buf[4..8], magic_cookie, .big);
    @memcpy(buf[8..20], &hdr.txn_id);
}

pub const DecodeError = error{
    BufferTooShort,
    BadMagicCookie,
    TruncatedAttributes,
};

/// Parsed STUN header plus a validated slice of the attribute bytes that follow.
pub const ParsedStun = struct {
    header: StunHeader,
    attrs: []const u8,
};

pub fn decodeStunHeader(buf: []const u8) DecodeError!ParsedStun {
    if (buf.len < stun_header_len) return error.BufferTooShort;
    const msg_type = mem.readInt(u16, buf[0..2], .big);
    const length = mem.readInt(u16, buf[2..4], .big);
    const cookie = mem.readInt(u32, buf[4..8], .big);
    if (cookie != magic_cookie) return error.BadMagicCookie;
    var txn_id: TxnId = undefined;
    @memcpy(&txn_id, buf[8..20]);
    const attrs_end: usize = stun_header_len + length;
    if (buf.len < attrs_end) return error.TruncatedAttributes;
    return .{
        .header = .{ .msg_type = msg_type, .length = length, .txn_id = txn_id },
        .attrs = buf[stun_header_len..attrs_end],
    };
}

pub const AttrType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    channel_number = 0x000C,
    lifetime = 0x000D,
    xor_peer_address = 0x0012,
    data = 0x0013,
    realm = 0x0014,
    nonce = 0x0015,
    xor_relayed_address = 0x0016,
    requested_transport = 0x0019,
    xor_mapped_address = 0x0020,
    software = 0x8022,
    fingerprint = 0x8028,
    _,
};

pub const RawAttr = struct {
    attr_type: u16,
    value: []const u8, // original (unpadded) value bytes
};

/// Value length rounded up to a multiple of 4 (excludes the 4-byte TLV header).
pub fn attrPaddedLen(value_len: usize) usize {
    return (value_len + 3) & ~@as(usize, 3);
}

/// Total on-wire size: 4-byte TLV header + padded value.
pub fn attrWireLen(value_len: usize) usize {
    return 4 + attrPaddedLen(value_len);
}

/// Encode a single attribute into `buf`.  Returns the number of bytes written.
pub fn encodeAttr(buf: []u8, attr_type: u16, value: []const u8) usize {
    const padded = attrPaddedLen(value.len);
    const total = 4 + padded;
    std.debug.assert(buf.len >= total);
    mem.writeInt(u16, buf[0..2], attr_type, .big);
    mem.writeInt(u16, buf[2..4], @intCast(value.len), .big);
    @memcpy(buf[4..][0..value.len], value);
    for (buf[4 + value.len ..][0 .. padded - value.len]) |*b| b.* = 0; // zero-pad
    return total;
}

/// Iterator over TLV attributes in a flat byte slice.
pub const AttrIter = struct {
    buf: []const u8,
    pos: usize,

    pub fn init(buf: []const u8) AttrIter {
        return .{ .buf = buf, .pos = 0 };
    }

    pub const AttrIterError = error{MalformedAttribute};

    pub fn next(self: *AttrIter) AttrIterError!?RawAttr {
        if (self.pos >= self.buf.len) return null;
        if (self.buf.len - self.pos < 4) return error.MalformedAttribute;
        const attr_type = mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        const value_len = mem.readInt(u16, self.buf[self.pos + 2 ..][0..2], .big);
        const padded = attrPaddedLen(value_len);
        if (self.buf.len - self.pos - 4 < padded) return error.MalformedAttribute;
        const value = self.buf[self.pos + 4 ..][0..value_len];
        self.pos += 4 + padded;
        return .{ .attr_type = attr_type, .value = value };
    }
};

// ── XOR-address transform ─────────────────────────────────────────────────────

pub const AddrFamily = enum(u8) { v4 = 0x01, v6 = 0x02 };

pub const XorAddr = union(AddrFamily) {
    v4: [4]u8,
    v6: [16]u8,
};

/// Value length of an XOR-ADDRESS attribute (8 for v4, 20 for v6).
pub fn xorAddrValueLen(family: AddrFamily) usize {
    return switch (family) {
        .v4 => 8,
        .v6 => 20,
    };
}

/// Encode an XOR-address value.  Port is host byte order; txn_id needed for IPv6.
pub fn encodeXorAddr(buf: []u8, addr: XorAddr, port: u16, txn_id: *const TxnId) void {
    switch (addr) {
        .v4 => |raw| {
            std.debug.assert(buf.len >= 8);
            buf[0] = 0x00; // reserved
            buf[1] = @backingInt(AddrFamily.v4);
            const xport: u16 = port ^ @as(u16, @truncate(magic_cookie >> 16));
            mem.writeInt(u16, buf[2..4], xport, .big);
            const mc_bytes: [4]u8 = @bitCast(std.mem.nativeToBig(u32, magic_cookie));
            for (0..4) |i| buf[4 + i] = raw[i] ^ mc_bytes[i];
        },
        .v6 => |raw| {
            std.debug.assert(buf.len >= 20);
            buf[0] = 0x00;
            buf[1] = @backingInt(AddrFamily.v6);
            const xport: u16 = port ^ @as(u16, @truncate(magic_cookie >> 16));
            mem.writeInt(u16, buf[2..4], xport, .big);
            const mc_bytes: [4]u8 = @bitCast(std.mem.nativeToBig(u32, magic_cookie));
            for (0..4) |i| buf[4 + i] = raw[i] ^ mc_bytes[i];
            for (0..12) |i| buf[8 + i] = raw[4 + i] ^ txn_id[i];
        },
    }
}

pub const XorAddrDecodeError = error{ BufferTooShort, UnknownFamily };

pub const DecodedXorAddr = struct {
    addr: XorAddr,
    port: u16,
};

/// Decode an XOR-address attribute value, reversing the XOR transform.
pub fn decodeXorAddr(buf: []const u8, txn_id: *const TxnId) XorAddrDecodeError!DecodedXorAddr {
    if (buf.len < 4) return error.BufferTooShort;
    const family: u8 = buf[1];
    const xport = mem.readInt(u16, buf[2..4], .big);
    const port: u16 = xport ^ @as(u16, @truncate(magic_cookie >> 16));
    switch (family) {
        0x01 => {
            if (buf.len < 8) return error.BufferTooShort;
            const mc_bytes: [4]u8 = @bitCast(std.mem.nativeToBig(u32, magic_cookie));
            var raw: [4]u8 = undefined;
            for (0..4) |i| raw[i] = buf[4 + i] ^ mc_bytes[i];
            return .{ .addr = .{ .v4 = raw }, .port = port };
        },
        0x02 => {
            if (buf.len < 20) return error.BufferTooShort;
            const mc_bytes: [4]u8 = @bitCast(std.mem.nativeToBig(u32, magic_cookie));
            var raw: [16]u8 = undefined;
            for (0..4) |i| raw[i] = buf[4 + i] ^ mc_bytes[i];
            for (0..12) |i| raw[4 + i] = buf[8 + i] ^ txn_id[i];
            return .{ .addr = .{ .v6 = raw }, .port = port };
        },
        else => return error.UnknownFamily,
    }
}

// ── Typed attribute helpers ───────────────────────────────────────────────────

/// REQUESTED-TRANSPORT attribute: 1-byte protocol (0x11 = UDP) + 3 RFFU bytes.
pub const TransportProto = enum(u8) { udp = 0x11 };

pub fn encodeRequestedTransport(buf: []u8, proto: TransportProto) usize {
    var value: [4]u8 = .{ @backingInt(proto), 0, 0, 0 };
    return encodeAttr(buf, @backingInt(AttrType.requested_transport), &value);
}

pub fn decodeRequestedTransport(value: []const u8) error{MalformedAttribute}!TransportProto {
    if (value.len < 1) return error.MalformedAttribute;
    return switch (value[0]) {
        0x11 => .udp,
        else => error.MalformedAttribute,
    };
}

/// LIFETIME attribute: 4-byte unsigned integer (seconds).
pub fn encodeLifetime(buf: []u8, seconds: u32) usize {
    var value: [4]u8 = undefined;
    mem.writeInt(u32, &value, seconds, .big);
    return encodeAttr(buf, @backingInt(AttrType.lifetime), &value);
}

pub fn decodeLifetime(value: []const u8) error{MalformedAttribute}!u32 {
    if (value.len < 4) return error.MalformedAttribute;
    return mem.readInt(u32, value[0..4], .big);
}

/// CHANNEL-NUMBER attribute: 2-byte channel number + 2 RFFU bytes.
/// Valid channel numbers are in [0x4000, 0x7FFF].
pub const ChannelNumber = u16;
pub const channel_number_min: u16 = 0x4000;
pub const channel_number_max: u16 = 0x7FFF;

pub fn encodeChannelNumber(buf: []u8, channel: ChannelNumber) usize {
    var value: [4]u8 = undefined;
    mem.writeInt(u16, value[0..2], channel, .big);
    mem.writeInt(u16, value[2..4], 0, .big);
    return encodeAttr(buf, @backingInt(AttrType.channel_number), &value);
}

pub fn decodeChannelNumber(value: []const u8) error{MalformedAttribute}!ChannelNumber {
    if (value.len < 2) return error.MalformedAttribute;
    return mem.readInt(u16, value[0..2], .big);
}

// ── Full STUN/TURN message builder ────────────────────────────────────────────

/// Builds a TURN message into a caller-supplied buffer: init → append → finish.
pub const MessageBuilder = struct {
    buf: []u8,
    pos: usize, // current write position (starts at stun_header_len)
    msg_type: u16,
    txn_id: TxnId,

    pub fn init(buf: []u8, method: Method, class: Class, txn_id: TxnId) MessageBuilder {
        std.debug.assert(buf.len >= stun_header_len);
        return .{
            .buf = buf,
            .pos = stun_header_len,
            .msg_type = encodeMessageType(method, class),
            .txn_id = txn_id,
        };
    }

    pub fn appendRaw(self: *MessageBuilder, attr_type: u16, value: []const u8) void {
        self.pos += encodeAttr(self.buf[self.pos..], attr_type, value);
    }
    pub fn appendLifetime(self: *MessageBuilder, seconds: u32) void {
        self.pos += encodeLifetime(self.buf[self.pos..], seconds);
    }
    pub fn appendRequestedTransport(self: *MessageBuilder, proto: TransportProto) void {
        self.pos += encodeRequestedTransport(self.buf[self.pos..], proto);
    }
    pub fn appendChannelNumber(self: *MessageBuilder, channel: ChannelNumber) void {
        self.pos += encodeChannelNumber(self.buf[self.pos..], channel);
    }
    pub fn appendXorPeerAddress(self: *MessageBuilder, addr: XorAddr, port: u16) void {
        var vbuf: [20]u8 = undefined;
        const vlen = xorAddrValueLen(switch (addr) {
            .v4 => .v4,
            .v6 => .v6,
        });
        encodeXorAddr(vbuf[0..vlen], addr, port, &self.txn_id);
        self.pos += encodeAttr(self.buf[self.pos..], @backingInt(AttrType.xor_peer_address), vbuf[0..vlen]);
    }
    pub fn appendXorRelayedAddress(self: *MessageBuilder, addr: XorAddr, port: u16) void {
        var vbuf: [20]u8 = undefined;
        const vlen = xorAddrValueLen(switch (addr) {
            .v4 => .v4,
            .v6 => .v6,
        });
        encodeXorAddr(vbuf[0..vlen], addr, port, &self.txn_id);
        self.pos += encodeAttr(self.buf[self.pos..], @backingInt(AttrType.xor_relayed_address), vbuf[0..vlen]);
    }
    pub fn appendData(self: *MessageBuilder, data: []const u8) void {
        self.pos += encodeAttr(self.buf[self.pos..], @backingInt(AttrType.data), data);
    }
    /// Finalise: write the STUN header and return the complete message slice.
    pub fn finish(self: *MessageBuilder) []const u8 {
        const attrs_len: u16 = @intCast(self.pos - stun_header_len);
        encodeStunHeader(self.buf[0..stun_header_len], .{
            .msg_type = self.msg_type,
            .length = attrs_len,
            .txn_id = self.txn_id,
        });
        return self.buf[0..self.pos];
    }
};

// ── ChannelData framing ───────────────────────────────────────────────────────

/// Encode a ChannelData frame: 2-byte channel, 2-byte length, then data.
/// No transport-level padding is added (caller's responsibility for TCP).
pub fn encodeChannelData(buf: []u8, channel: ChannelNumber, data: []const u8) usize {
    std.debug.assert(buf.len >= channel_data_header_len + data.len);
    mem.writeInt(u16, buf[0..2], channel, .big);
    mem.writeInt(u16, buf[2..4], @intCast(data.len), .big);
    @memcpy(buf[4..][0..data.len], data);
    return channel_data_header_len + data.len;
}

pub const ChannelDataDecodeError = error{
    BufferTooShort,
    TruncatedPayload,
    InvalidChannel,
};

pub const ChannelDataFrame = struct {
    channel: ChannelNumber,
    data: []const u8,
};

/// Decode a ChannelData frame; the returned `data` slice aliases `buf`.
pub fn decodeChannelData(buf: []const u8) ChannelDataDecodeError!ChannelDataFrame {
    if (buf.len < channel_data_header_len) return error.BufferTooShort;
    const channel = mem.readInt(u16, buf[0..2], .big);
    if (channel < channel_number_min or channel > channel_number_max)
        return error.InvalidChannel;
    const data_len = mem.readInt(u16, buf[2..4], .big);
    if (buf.len < channel_data_header_len + data_len) return error.TruncatedPayload;
    return .{ .channel = channel, .data = buf[4..][0..data_len] };
}

/// Returns true if `buf` starts with a ChannelData frame (channel in [0x4000,0x7FFF]).
pub fn isChannelData(buf: []const u8) bool {
    if (buf.len < 1) return false;
    return buf[0] >= 0x40 and buf[0] <= 0x7F;
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "encodeMessageType / decodeMessageType round-trip" {
    const cases = .{
        .{ Method.allocate, Class.request },
        .{ Method.allocate, Class.success_response },
        .{ Method.allocate, Class.error_response },
        .{ Method.refresh, Class.request },
        .{ Method.send, Class.indication },
        .{ Method.data, Class.indication },
        .{ Method.create_permission, Class.request },
        .{ Method.channel_bind, Class.request },
        .{ Method.binding, Class.request },
    };
    inline for (cases) |c| {
        const word = encodeMessageType(c[0], c[1]);
        const decoded = try decodeMessageType(word);
        try testing.expectEqual(c[0], decoded.method);
        try testing.expectEqual(c[1], decoded.class);
    }
}

test "STUN header encode/decode round-trip" {
    const txn: TxnId = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    const msg_type = encodeMessageType(.allocate, .request);
    var buf: [20]u8 = undefined;
    encodeStunHeader(&buf, .{ .msg_type = msg_type, .length = 0, .txn_id = txn });
    const parsed = try decodeStunHeader(&buf);
    try testing.expectEqual(msg_type, parsed.header.msg_type);
    try testing.expectEqual(@as(u16, 0), parsed.header.length);
    try testing.expectEqualSlices(u8, &txn, &parsed.header.txn_id);
    try testing.expectEqual(@as(usize, 0), parsed.attrs.len);
}

test "STUN header decode: bad magic cookie" {
    var buf: [20]u8 = @splat(0);
    mem.writeInt(u32, buf[4..8], 0xDEAD_BEEF, .big); // wrong cookie
    const result = decodeStunHeader(&buf);
    try testing.expectError(error.BadMagicCookie, result);
}

test "STUN header decode: buffer too short" {
    const buf: [10]u8 = @splat(0);
    try testing.expectError(error.BufferTooShort, decodeStunHeader(&buf));
}

test "STUN header decode: truncated attributes" {
    var buf: [24]u8 = @splat(0);
    const msg_type = encodeMessageType(.allocate, .request);
    mem.writeInt(u16, buf[0..2], msg_type, .big);
    mem.writeInt(u16, buf[2..4], 100, .big); // claims 100 bytes of attrs
    mem.writeInt(u32, buf[4..8], magic_cookie, .big);
    const result = decodeStunHeader(&buf);
    try testing.expectError(error.TruncatedAttributes, result);
}

test "attribute TLV encode/decode round-trip" {
    var buf: [64]u8 = undefined;
    const written = encodeAttr(&buf, 0x0001, "hello"); // padded 5→8, total 12
    try testing.expectEqual(@as(usize, 12), written);
    var iter = AttrIter.init(buf[0..written]);
    const attr = (try iter.next()).?;
    try testing.expectEqual(@as(u16, 0x0001), attr.attr_type);
    try testing.expectEqualSlices(u8, "hello", attr.value);
    try testing.expectEqual(@as(?RawAttr, null), try iter.next());
}

test "attribute TLV: multiple attrs iteration" {
    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    pos += encodeAttr(buf[pos..], 0x0001, "abc");
    pos += encodeAttr(buf[pos..], 0x0002, "defgh");
    pos += encodeAttr(buf[pos..], 0x0003, "");
    var iter = AttrIter.init(buf[0..pos]);
    const a1 = (try iter.next()).?;
    try testing.expectEqual(@as(u16, 0x0001), a1.attr_type);
    try testing.expectEqualSlices(u8, "abc", a1.value);
    const a2 = (try iter.next()).?;
    try testing.expectEqual(@as(u16, 0x0002), a2.attr_type);
    try testing.expectEqualSlices(u8, "defgh", a2.value);
    const a3 = (try iter.next()).?;
    try testing.expectEqual(@as(u16, 0x0003), a3.attr_type);
    try testing.expectEqual(@as(usize, 0), a3.value.len);
    try testing.expectEqual(@as(?RawAttr, null), try iter.next());
}

test "XOR-address IPv4 encode/decode round-trip" {
    const txn: TxnId = @splat(0);
    const ip4: [4]u8 = .{ 192, 168, 1, 10 };
    var vbuf: [8]u8 = undefined;
    encodeXorAddr(&vbuf, .{ .v4 = ip4 }, 3478, &txn);
    const decoded = try decodeXorAddr(&vbuf, &txn);
    try testing.expectEqual(@as(u16, 3478), decoded.port);
    try testing.expectEqualSlices(u8, &ip4, &decoded.addr.v4);
}

test "XOR-address IPv6 encode/decode round-trip" {
    const txn: TxnId = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC };
    const ip6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    var vbuf: [20]u8 = undefined;
    encodeXorAddr(&vbuf, .{ .v6 = ip6 }, 49152, &txn);
    const decoded = try decodeXorAddr(&vbuf, &txn);
    try testing.expectEqual(@as(u16, 49152), decoded.port);
    try testing.expectEqualSlices(u8, &ip6, &decoded.addr.v6);
}

test "XOR-address decode: buffer too short" {
    const txn: TxnId = @splat(0);
    const short: [3]u8 = .{ 0, 1, 0 };
    try testing.expectError(error.BufferTooShort, decodeXorAddr(&short, &txn));
}

test "XOR-address decode: unknown family" {
    const txn: TxnId = @splat(0);
    var buf: [8]u8 = @splat(0);
    buf[1] = 0x03; // invalid family
    try testing.expectError(error.UnknownFamily, decodeXorAddr(&buf, &txn));
}

test "LIFETIME attribute encode/decode" {
    var buf: [8]u8 = undefined;
    const written = encodeLifetime(&buf, 600);
    try testing.expectEqual(@as(usize, 8), written);
    var iter = AttrIter.init(buf[0..written]);
    const attr = (try iter.next()).?;
    try testing.expectEqual(@backingInt(AttrType.lifetime), attr.attr_type);
    try testing.expectEqual(@as(u32, 600), try decodeLifetime(attr.value));
}

test "REQUESTED-TRANSPORT attribute encode/decode" {
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 8), encodeRequestedTransport(&buf, .udp));
    var iter = AttrIter.init(&buf);
    const attr = (try iter.next()).?;
    try testing.expectEqual(@backingInt(AttrType.requested_transport), attr.attr_type);
    try testing.expectEqual(TransportProto.udp, try decodeRequestedTransport(attr.value));
}

test "CHANNEL-NUMBER attribute encode/decode" {
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 8), encodeChannelNumber(&buf, 0x4001));
    var iter = AttrIter.init(&buf);
    const attr = (try iter.next()).?;
    try testing.expectEqual(@backingInt(AttrType.channel_number), attr.attr_type);
    try testing.expectEqual(@as(ChannelNumber, 0x4001), try decodeChannelNumber(attr.value));
}

test "ChannelData encode/decode round-trip" {
    const payload = "relay me";
    var buf: [64]u8 = undefined;
    const written = encodeChannelData(&buf, 0x4000, payload);
    try testing.expectEqual(@as(usize, channel_data_header_len + payload.len), written);

    const frame = try decodeChannelData(buf[0..written]);
    try testing.expectEqual(@as(ChannelNumber, 0x4000), frame.channel);
    try testing.expectEqualSlices(u8, payload, frame.data);
}

test "ChannelData decode: buffer too short" {
    const buf: [3]u8 = .{ 0x40, 0x00, 0x00 };
    try testing.expectError(error.BufferTooShort, decodeChannelData(&buf));
}

test "ChannelData decode: truncated payload" {
    var buf: [6]u8 = undefined;
    mem.writeInt(u16, buf[0..2], 0x4000, .big);
    mem.writeInt(u16, buf[2..4], 100, .big); // claims 100 bytes
    buf[4] = 0;
    buf[5] = 0;
    try testing.expectError(error.TruncatedPayload, decodeChannelData(&buf));
}

test "ChannelData decode: invalid channel number (below range)" {
    var buf: [8]u8 = @splat(0);
    mem.writeInt(u16, buf[0..2], 0x3FFF, .big); // one below valid range
    try testing.expectError(error.InvalidChannel, decodeChannelData(&buf));
}

test "ChannelData decode: invalid channel number (above range)" {
    var buf: [8]u8 = @splat(0);
    mem.writeInt(u16, buf[0..2], 0x8000, .big); // one above valid range
    try testing.expectError(error.InvalidChannel, decodeChannelData(&buf));
}

test "isChannelData discriminator" {
    try testing.expect(!isChannelData(&.{ 0x00, 0x03, 0x00, 0x00 })); // STUN: bits 15-14 == 0
    try testing.expect(isChannelData(&.{ 0x40, 0x00, 0x00, 0x00 })); // channel 0x4000
    try testing.expect(isChannelData(&.{ 0x7F, 0xFF, 0x00, 0x00 })); // channel 0x7FFF
}

test "Allocate request round-trip" {
    const txn: TxnId = .{ 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0 };
    var buf: [256]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .allocate, .request, txn);
    builder.appendRequestedTransport(.udp);
    builder.appendLifetime(3600);
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    const dt = try decodeMessageType(parsed.header.msg_type);
    try testing.expectEqual(Method.allocate, dt.method);
    try testing.expectEqual(Class.request, dt.class);
    try testing.expectEqualSlices(u8, &txn, &parsed.header.txn_id);
    var found_transport: bool = false;
    var found_lifetime: bool = false;
    var iter = AttrIter.init(parsed.attrs);
    while (try iter.next()) |attr| {
        if (attr.attr_type == @backingInt(AttrType.requested_transport)) {
            try testing.expectEqual(TransportProto.udp, try decodeRequestedTransport(attr.value));
            found_transport = true;
        } else if (attr.attr_type == @backingInt(AttrType.lifetime)) {
            try testing.expectEqual(@as(u32, 3600), try decodeLifetime(attr.value));
            found_lifetime = true;
        }
    }
    try testing.expect(found_transport);
    try testing.expect(found_lifetime);
}

test "Allocate success response with XOR-RELAYED-ADDRESS (IPv4)" {
    const txn: TxnId = .{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0 };
    const relay_ip4: [4]u8 = .{ 203, 0, 113, 42 };
    var buf: [256]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .allocate, .success_response, txn);
    builder.appendXorRelayedAddress(.{ .v4 = relay_ip4 }, 49152);
    builder.appendLifetime(600);
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    var iter = AttrIter.init(parsed.attrs);
    var found: bool = false;
    while (try iter.next()) |attr| {
        if (attr.attr_type == @backingInt(AttrType.xor_relayed_address)) {
            const dec = try decodeXorAddr(attr.value, &txn);
            try testing.expectEqual(@as(u16, 49152), dec.port);
            try testing.expectEqualSlices(u8, &relay_ip4, &dec.addr.v4);
            found = true;
        }
    }
    try testing.expect(found);
}

test "Allocate success response with XOR-RELAYED-ADDRESS (IPv6)" {
    const txn: TxnId = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const relay_ip6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 };
    var buf: [256]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .allocate, .success_response, txn);
    builder.appendXorRelayedAddress(.{ .v6 = relay_ip6 }, 1234);
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    var iter = AttrIter.init(parsed.attrs);
    var found: bool = false;
    while (try iter.next()) |attr| {
        if (attr.attr_type == @backingInt(AttrType.xor_relayed_address)) {
            const dec = try decodeXorAddr(attr.value, &txn);
            try testing.expectEqual(@as(u16, 1234), dec.port);
            try testing.expectEqualSlices(u8, &relay_ip6, &dec.addr.v6);
            found = true;
        }
    }
    try testing.expect(found);
}

test "ChannelBind request round-trip" {
    const txn: TxnId = @splat(0x99);
    const peer_ip4: [4]u8 = .{ 10, 0, 0, 1 };
    var buf: [256]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .channel_bind, .request, txn);
    builder.appendChannelNumber(0x4002);
    builder.appendXorPeerAddress(.{ .v4 = peer_ip4 }, 5004);
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    const dt = try decodeMessageType(parsed.header.msg_type);
    try testing.expectEqual(Method.channel_bind, dt.method);
    try testing.expectEqual(Class.request, dt.class);
    var iter = AttrIter.init(parsed.attrs);
    var found_ch: bool = false;
    var found_peer: bool = false;
    while (try iter.next()) |attr| {
        if (attr.attr_type == @backingInt(AttrType.channel_number)) {
            try testing.expectEqual(@as(ChannelNumber, 0x4002), try decodeChannelNumber(attr.value));
            found_ch = true;
        } else if (attr.attr_type == @backingInt(AttrType.xor_peer_address)) {
            const dec = try decodeXorAddr(attr.value, &txn);
            try testing.expectEqual(@as(u16, 5004), dec.port);
            try testing.expectEqualSlices(u8, &peer_ip4, &dec.addr.v4);
            found_peer = true;
        }
    }
    try testing.expect(found_ch);
    try testing.expect(found_peer);
}

test "Send indication with DATA attribute round-trip" {
    const txn: TxnId = @splat(0x55);
    var buf: [256]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .send, .indication, txn);
    builder.appendData("hello peer");
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    const dt = try decodeMessageType(parsed.header.msg_type);
    try testing.expectEqual(Method.send, dt.method);
    try testing.expectEqual(Class.indication, dt.class);
    var iter = AttrIter.init(parsed.attrs);
    const attr = (try iter.next()).?;
    try testing.expectEqual(@backingInt(AttrType.data), attr.attr_type);
    try testing.expectEqualSlices(u8, "hello peer", attr.value);
}

test "Data indication round-trip" {
    const txn: TxnId = @splat(0x77);
    const payload: []const u8 = &.{ 0x01, 0x02, 0x03 };
    var buf: [256]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .data, .indication, txn);
    builder.appendData(payload);
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    const dt = try decodeMessageType(parsed.header.msg_type);
    try testing.expectEqual(Method.data, dt.method);
    try testing.expectEqual(Class.indication, dt.class);
    var iter = AttrIter.init(parsed.attrs);
    const attr = (try iter.next()).?;
    try testing.expectEqualSlices(u8, payload, attr.value);
}

test "ChannelData round-trip with max payload boundary" {
    const channel: ChannelNumber = 0x7FFF;
    var payload: [0xFFFF]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    var buf: [0xFFFF + channel_data_header_len]u8 = undefined;
    const written = encodeChannelData(&buf, channel, &payload);
    try testing.expectEqual(@as(usize, 0xFFFF + channel_data_header_len), written);

    const frame = try decodeChannelData(buf[0..written]);
    try testing.expectEqual(channel, frame.channel);
    try testing.expectEqualSlices(u8, &payload, frame.data);
}

test "Refresh request round-trip" {
    const txn: TxnId = @splat(0x11);
    var buf: [64]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .refresh, .request, txn);
    builder.appendLifetime(0); // lifetime=0 means deallocate
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    const dt = try decodeMessageType(parsed.header.msg_type);
    try testing.expectEqual(Method.refresh, dt.method);
    try testing.expectEqual(Class.request, dt.class);
    var iter = AttrIter.init(parsed.attrs);
    try testing.expectEqual(@as(u32, 0), try decodeLifetime((try iter.next()).?.value));
}

test "CreatePermission request round-trip" {
    const txn: TxnId = @splat(0x22);
    const peer_ip4: [4]u8 = .{ 198, 51, 100, 7 };
    var buf: [128]u8 = undefined;
    var builder = MessageBuilder.init(&buf, .create_permission, .request, txn);
    builder.appendXorPeerAddress(.{ .v4 = peer_ip4 }, 0);
    const msg = builder.finish();
    const parsed = try decodeStunHeader(msg);
    const dt = try decodeMessageType(parsed.header.msg_type);
    try testing.expectEqual(Method.create_permission, dt.method);
    try testing.expectEqual(Class.request, dt.class);
    var iter = AttrIter.init(parsed.attrs);
    const attr = (try iter.next()).?;
    try testing.expectEqual(@backingInt(AttrType.xor_peer_address), attr.attr_type);
    const dec = try decodeXorAddr(attr.value, &txn);
    try testing.expectEqualSlices(u8, &peer_ip4, &dec.addr.v4);
}

test "attrPaddedLen: padding multiples" {
    try testing.expectEqual(@as(usize, 0), attrPaddedLen(0));
    try testing.expectEqual(@as(usize, 4), attrPaddedLen(1));
    try testing.expectEqual(@as(usize, 4), attrPaddedLen(4));
    try testing.expectEqual(@as(usize, 8), attrPaddedLen(5));
    try testing.expectEqual(@as(usize, 8), attrPaddedLen(8));
    try testing.expectEqual(@as(usize, 12), attrPaddedLen(9));
}

test "MalformedAttribute: truncated TLV" {
    var buf: [6]u8 = undefined;
    mem.writeInt(u16, buf[0..2], 0x0001, .big);
    mem.writeInt(u16, buf[2..4], 8, .big); // claims 8 bytes but only 2 follow
    buf[4] = 0;
    buf[5] = 0;
    var iter = AttrIter.init(&buf);
    try testing.expectError(error.MalformedAttribute, iter.next());
}
