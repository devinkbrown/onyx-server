// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! STUN message framing and common RFC 5389 attributes.
//!
//! This module is intentionally transport-free: callers provide/consume whole
//! datagrams, and parsed string/raw attributes borrow the input buffer.
const std = @import("std");

pub const header_len = 20;
pub const transaction_id_len = 12;
pub const magic_cookie: u32 = 0x2112A442;
pub const message_integrity_len = 20;
pub const fingerprint_xor: u32 = 0x5354554e;

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

pub const Error = error{
    Truncated,
    TrailingBytes,
    BadCookie,
    BadLength,
    BadTypeBits,
    LengthOverflow,
    UnknownAddressFamily,
    BadAddressLength,
    BadMessageIntegrityLength,
    BadFingerprintLength,
    MessageIntegrityMissing,
    FingerprintMissing,
    FingerprintNotLast,
};

pub const MessageType = enum(u16) {
    binding_request = 0x0001,
    binding_success_response = 0x0101,
    binding_error_response = 0x0111,
    _,
};

pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    xor_mapped_address = 0x0020,
    fingerprint = 0x8028,
    _,
};

pub const TransactionId = [transaction_id_len]u8;

pub const Ipv4Address = struct {
    ip: [4]u8,
    port: u16,
};

pub const Ipv6Address = struct {
    ip: [16]u8,
    port: u16,
};

pub const Address = union(enum) {
    ipv4: Ipv4Address,
    ipv6: Ipv6Address,

    pub fn valueLen(self: Address) u16 {
        return switch (self) {
            .ipv4 => 8,
            .ipv6 => 20,
        };
    }

    pub fn port(self: Address) u16 {
        return switch (self) {
            .ipv4 => |a| a.port,
            .ipv6 => |a| a.port,
        };
    }
};

pub const RawAttribute = struct {
    typ: u16,
    value: []const u8,
};

pub const Attribute = union(enum) {
    mapped_address: Address,
    xor_mapped_address: Address,
    username: []const u8,
    message_integrity: [message_integrity_len]u8,
    fingerprint: u32,
    unknown: RawAttribute,
};

pub const Message = struct {
    typ: MessageType,
    transaction_id: TransactionId,
    attributes: []Attribute,

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.attributes);
        self.* = undefined;
    }
};

pub const EncodeAttribute = union(enum) {
    mapped_address: Address,
    xor_mapped_address: Address,
    username: []const u8,
    message_integrity: []const u8,
    fingerprint,
    raw: RawAttribute,
};

pub const BindingRequestOptions = struct {
    username: ?[]const u8 = null,
    integrity_key: ?[]const u8 = null,
    fingerprint: bool = true,
};

pub const BindingResponseOptions = struct {
    mapped_address: ?Address = null,
    xor_mapped_address: ?Address = null,
    username: ?[]const u8 = null,
    integrity_key: ?[]const u8 = null,
    fingerprint: bool = true,
};

pub fn buildBindingRequest(
    allocator: std.mem.Allocator,
    transaction_id: TransactionId,
    options: BindingRequestOptions,
) ![]u8 {
    var attrs: [4]EncodeAttribute = undefined;
    var n: usize = 0;
    if (options.username) |username| {
        attrs[n] = .{ .username = username };
        n += 1;
    }
    if (options.integrity_key) |key| {
        attrs[n] = .{ .message_integrity = key };
        n += 1;
    }
    if (options.fingerprint) {
        attrs[n] = .fingerprint;
        n += 1;
    }
    return encodeMessage(allocator, .binding_request, transaction_id, attrs[0..n]);
}

pub fn buildBindingSuccessResponse(
    allocator: std.mem.Allocator,
    transaction_id: TransactionId,
    options: BindingResponseOptions,
) ![]u8 {
    var attrs: [6]EncodeAttribute = undefined;
    var n: usize = 0;
    if (options.mapped_address) |address| {
        attrs[n] = .{ .mapped_address = address };
        n += 1;
    }
    if (options.xor_mapped_address) |address| {
        attrs[n] = .{ .xor_mapped_address = address };
        n += 1;
    }
    if (options.username) |username| {
        attrs[n] = .{ .username = username };
        n += 1;
    }
    if (options.integrity_key) |key| {
        attrs[n] = .{ .message_integrity = key };
        n += 1;
    }
    if (options.fingerprint) {
        attrs[n] = .fingerprint;
        n += 1;
    }
    return encodeMessage(allocator, .binding_success_response, transaction_id, attrs[0..n]);
}

pub fn encodeMessage(
    allocator: std.mem.Allocator,
    typ: MessageType,
    transaction_id: TransactionId,
    attrs: []const EncodeAttribute,
) ![]u8 {
    const body_len = try encodedAttributesLen(attrs);
    var out = try allocator.alloc(u8, header_len + body_len);
    errdefer allocator.free(out);

    writeHeader(out[0..header_len], typ, @intCast(body_len), transaction_id);

    var cursor: usize = header_len;
    for (attrs, 0..) |attr, index| {
        switch (attr) {
            .mapped_address => |address| try writeAddressAttr(out, &cursor, .mapped_address, address, transaction_id),
            .xor_mapped_address => |address| try writeAddressAttr(out, &cursor, .xor_mapped_address, address, transaction_id),
            .username => |username| writeBytesAttr(out, &cursor, .username, username),
            .raw => |raw| writeRawAttr(out, &cursor, raw.typ, raw.value),
            .message_integrity => |key| {
                const mac_offset = cursor;
                writeAttrHeader(out, &cursor, .message_integrity, message_integrity_len);
                const mac_body_len: u16 = @intCast((mac_offset - header_len) + 4 + message_integrity_len);
                const mac = computeIntegrityPrefix(out[0..mac_offset], mac_body_len, key);
                @memcpy(out[cursor..][0..message_integrity_len], &mac);
                cursor += message_integrity_len;
            },
            .fingerprint => {
                if (index + 1 != attrs.len) return error.FingerprintNotLast;
                const fp_offset = cursor;
                writeAttrHeader(out, &cursor, .fingerprint, 4);
                const fp_body_len: u16 = @intCast((fp_offset - header_len) + 8);
                const value = computeFingerprintPrefix(out[0..fp_offset], fp_body_len);
                writeU32(out[cursor..][0..4], value);
                cursor += 4;
            },
        }
        zeroPadding(out, &cursor, attrValueLen(attr));
    }

    std.debug.assert(cursor == out.len);
    return out;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Message {
    const header = try readHeader(bytes);
    var list: std.ArrayList(Attribute) = .empty;
    errdefer list.deinit(allocator);

    var cursor: usize = header_len;
    const end = header_len + header.body_len;
    while (cursor < end) {
        if (end - cursor < 4) return error.Truncated;
        const raw_type = readU16(bytes[cursor..][0..2]);
        const value_len = readU16(bytes[cursor + 2 ..][0..2]);
        cursor += 4;
        const padded = paddedLen(value_len);
        if (cursor + padded > end) return error.Truncated;
        const value = bytes[cursor..][0..value_len];
        cursor += padded;

        const attr: Attribute = switch (@as(AttributeType, @fromBackingInt(@intCast(raw_type)))) {
            .mapped_address => .{ .mapped_address = try decodeAddressValue(value, header.transaction_id, false) },
            .xor_mapped_address => .{ .xor_mapped_address = try decodeAddressValue(value, header.transaction_id, true) },
            .username => .{ .username = value },
            .message_integrity => blk: {
                if (value.len != message_integrity_len) return error.BadMessageIntegrityLength;
                var mac: [message_integrity_len]u8 = undefined;
                @memcpy(&mac, value);
                break :blk .{ .message_integrity = mac };
            },
            .fingerprint => blk: {
                if (value.len != 4) return error.BadFingerprintLength;
                break :blk .{ .fingerprint = readU32(value[0..4]) };
            },
            _ => .{ .unknown = .{ .typ = raw_type, .value = value } },
        };
        try list.append(allocator, attr);
    }

    return .{
        .typ = header.typ,
        .transaction_id = header.transaction_id,
        .attributes = try list.toOwnedSlice(allocator),
    };
}

pub fn computeMessageIntegrity(bytes: []const u8, key: []const u8) Error![message_integrity_len]u8 {
    const found = try findAttribute(bytes, @backingInt(AttributeType.message_integrity));
    if (found.value_len != message_integrity_len) return error.BadMessageIntegrityLength;
    const body_len_for_mac: u16 = @intCast((found.attr_offset - header_len) + 4 + message_integrity_len);
    return computeIntegrityPrefix(bytes[0..found.attr_offset], body_len_for_mac, key);
}

pub fn verifyMessageIntegrity(bytes: []const u8, key: []const u8) Error!bool {
    const found = try findAttribute(bytes, @backingInt(AttributeType.message_integrity));
    const expected = try computeMessageIntegrity(bytes, key);
    const actual = bytes[found.value_offset..][0..message_integrity_len];
    return timingSafeEql(&expected, actual);
}

pub fn computeFingerprint(bytes: []const u8) Error!u32 {
    const found = try findAttribute(bytes, @backingInt(AttributeType.fingerprint));
    if (found.value_len != 4) return error.BadFingerprintLength;
    const body_len_for_fp: u16 = @intCast((found.attr_offset - header_len) + 8);
    return computeFingerprintPrefix(bytes[0..found.attr_offset], body_len_for_fp);
}

pub fn verifyFingerprint(bytes: []const u8) Error!bool {
    const found = try findAttribute(bytes, @backingInt(AttributeType.fingerprint));
    if (found.value_len != 4) return error.BadFingerprintLength;
    const header = try readHeader(bytes);
    if (found.value_offset + 4 != header_len + header.body_len) return false;
    return try computeFingerprint(bytes) == readU32(bytes[found.value_offset..][0..4]);
}

pub fn xorAddress(address: Address, transaction_id: TransactionId) Address {
    const cookie = cookieBytes();
    return switch (address) {
        .ipv4 => |a| blk: {
            var ip = a.ip;
            for (&ip, 0..) |*b, i| b.* ^= cookie[i];
            break :blk .{ .ipv4 = .{ .ip = ip, .port = a.port ^ cookiePortMask() } };
        },
        .ipv6 => |a| blk: {
            var ip = a.ip;
            for (ip[0..4], 0..) |*b, i| b.* ^= cookie[i];
            for (ip[4..16], 0..) |*b, i| b.* ^= transaction_id[i];
            break :blk .{ .ipv6 = .{ .ip = ip, .port = a.port ^ cookiePortMask() } };
        },
    };
}

const Header = struct {
    typ: MessageType,
    body_len: u16,
    transaction_id: TransactionId,
};

const FoundAttribute = struct {
    attr_offset: usize,
    value_offset: usize,
    value_len: u16,
};

fn readHeader(bytes: []const u8) Error!Header {
    if (bytes.len < header_len) return error.Truncated;
    const raw_type = readU16(bytes[0..2]);
    if ((raw_type & 0xc000) != 0) return error.BadTypeBits;
    const body_len = readU16(bytes[2..4]);
    if ((body_len % 4) != 0) return error.BadLength;
    if (readU32(bytes[4..8]) != magic_cookie) return error.BadCookie;
    const total_len = header_len + @as(usize, body_len);
    if (bytes.len < total_len) return error.Truncated;
    if (bytes.len != total_len) return error.TrailingBytes;

    var transaction_id: TransactionId = undefined;
    @memcpy(&transaction_id, bytes[8..20]);
    return .{
        .typ = @fromBackingInt(@intCast(raw_type)),
        .body_len = body_len,
        .transaction_id = transaction_id,
    };
}

fn writeHeader(out: []u8, typ: MessageType, body_len: u16, transaction_id: TransactionId) void {
    std.debug.assert(out.len == header_len);
    writeU16(out[0..2], @backingInt(typ));
    writeU16(out[2..4], body_len);
    writeU32(out[4..8], magic_cookie);
    @memcpy(out[8..20], &transaction_id);
}

fn findAttribute(bytes: []const u8, wanted_type: u16) Error!FoundAttribute {
    const header = try readHeader(bytes);
    var cursor: usize = header_len;
    const end = header_len + header.body_len;
    while (cursor < end) {
        if (end - cursor < 4) return error.Truncated;
        const attr_offset = cursor;
        const raw_type = readU16(bytes[cursor..][0..2]);
        const value_len = readU16(bytes[cursor + 2 ..][0..2]);
        cursor += 4;
        const padded = paddedLen(value_len);
        if (cursor + padded > end) return error.Truncated;
        if (raw_type == wanted_type) {
            return .{
                .attr_offset = attr_offset,
                .value_offset = cursor,
                .value_len = value_len,
            };
        }
        cursor += padded;
    }
    return switch (@as(AttributeType, @fromBackingInt(@intCast(wanted_type)))) {
        .message_integrity => error.MessageIntegrityMissing,
        .fingerprint => error.FingerprintMissing,
        else => error.Truncated,
    };
}

fn encodedAttributesLen(attrs: []const EncodeAttribute) Error!usize {
    var len: usize = 0;
    for (attrs, 0..) |attr, index| {
        if (attr == .fingerprint and index + 1 != attrs.len) return error.FingerprintNotLast;
        len += 4 + paddedLen(attrValueLen(attr));
        if (len > std.math.maxInt(u16)) return error.LengthOverflow;
    }
    return len;
}

fn attrValueLen(attr: EncodeAttribute) u16 {
    return switch (attr) {
        .mapped_address => |address| address.valueLen(),
        .xor_mapped_address => |address| address.valueLen(),
        .username => |username| @intCast(username.len),
        .message_integrity => message_integrity_len,
        .fingerprint => 4,
        .raw => |raw| @intCast(raw.value.len),
    };
}

fn writeAddressAttr(
    out: []u8,
    cursor: *usize,
    typ: AttributeType,
    address: Address,
    transaction_id: TransactionId,
) Error!void {
    const wire_address = if (typ == .xor_mapped_address) xorAddress(address, transaction_id) else address;
    writeAttrHeader(out, cursor, typ, wire_address.valueLen());
    switch (wire_address) {
        .ipv4 => |a| {
            out[cursor.*] = 0;
            out[cursor.* + 1] = 0x01;
            writeU16(out[cursor.* + 2 ..][0..2], a.port);
            @memcpy(out[cursor.* + 4 ..][0..4], &a.ip);
            cursor.* += 8;
        },
        .ipv6 => |a| {
            out[cursor.*] = 0;
            out[cursor.* + 1] = 0x02;
            writeU16(out[cursor.* + 2 ..][0..2], a.port);
            @memcpy(out[cursor.* + 4 ..][0..16], &a.ip);
            cursor.* += 20;
        },
    }
}

fn writeBytesAttr(out: []u8, cursor: *usize, typ: AttributeType, value: []const u8) void {
    writeAttrHeader(out, cursor, typ, @intCast(value.len));
    @memcpy(out[cursor.*..][0..value.len], value);
    cursor.* += value.len;
}

fn writeRawAttr(out: []u8, cursor: *usize, raw_type: u16, value: []const u8) void {
    writeU16(out[cursor.*..][0..2], raw_type);
    writeU16(out[cursor.* + 2 ..][0..2], @intCast(value.len));
    cursor.* += 4;
    @memcpy(out[cursor.*..][0..value.len], value);
    cursor.* += value.len;
}

fn writeAttrHeader(out: []u8, cursor: *usize, typ: AttributeType, value_len: u16) void {
    writeU16(out[cursor.*..][0..2], @backingInt(typ));
    writeU16(out[cursor.* + 2 ..][0..2], value_len);
    cursor.* += 4;
}

fn decodeAddressValue(value: []const u8, transaction_id: TransactionId, is_xor: bool) Error!Address {
    if (value.len < 4 or value[0] != 0) return error.BadAddressLength;
    const port = readU16(value[2..4]);
    const address: Address = switch (value[1]) {
        0x01 => blk: {
            if (value.len != 8) return error.BadAddressLength;
            var ip: [4]u8 = undefined;
            @memcpy(&ip, value[4..8]);
            break :blk .{ .ipv4 = .{ .ip = ip, .port = port } };
        },
        0x02 => blk: {
            if (value.len != 20) return error.BadAddressLength;
            var ip: [16]u8 = undefined;
            @memcpy(&ip, value[4..20]);
            break :blk .{ .ipv6 = .{ .ip = ip, .port = port } };
        },
        else => return error.UnknownAddressFamily,
    };
    return if (is_xor) xorAddress(address, transaction_id) else address;
}

fn computeIntegrityPrefix(prefix: []const u8, body_len_for_header: u16, key: []const u8) [message_integrity_len]u8 {
    std.debug.assert(prefix.len >= header_len);
    var header: [header_len]u8 = undefined;
    @memcpy(&header, prefix[0..header_len]);
    writeU16(header[2..4], body_len_for_header);

    var mac: [message_integrity_len]u8 = undefined;
    var h = HmacSha1.init(key);
    h.update(&header);
    h.update(prefix[header_len..]);
    h.final(&mac);
    return mac;
}

fn computeFingerprintPrefix(prefix: []const u8, body_len_for_header: u16) u32 {
    std.debug.assert(prefix.len >= header_len);
    var header: [header_len]u8 = undefined;
    @memcpy(&header, prefix[0..header_len]);
    writeU16(header[2..4], body_len_for_header);

    var crc = std.hash.Crc32.init();
    crc.update(&header);
    crc.update(prefix[header_len..]);
    return crc.final() ^ fingerprint_xor;
}

fn zeroPadding(out: []u8, cursor: *usize, value_len: u16) void {
    const padding = paddedLen(value_len) - value_len;
    if (padding > 0) {
        @memset(out[cursor.*..][0..padding], 0);
        cursor.* += padding;
    }
}

fn paddedLen(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

fn cookieBytes() [4]u8 {
    return .{ 0x21, 0x12, 0xa4, 0x42 };
}

fn cookiePortMask() u16 {
    return @intCast(magic_cookie >> 16);
}

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .big);
}

fn writeU32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .big);
}

test "header round-trip" {
    const allocator = std.testing.allocator;
    const tx: TransactionId = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const bytes = try encodeMessage(allocator, .binding_request, tx, &.{});
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(usize, header_len), bytes.len);
    try std.testing.expectEqual(@as(u16, 0x0001), readU16(bytes[0..2]));
    try std.testing.expectEqual(@as(u16, 0), readU16(bytes[2..4]));
    try std.testing.expectEqual(magic_cookie, readU32(bytes[4..8]));

    var msg = try decode(allocator, bytes);
    defer msg.deinit(allocator);
    try std.testing.expectEqual(MessageType.binding_request, msg.typ);
    try std.testing.expectEqualSlices(u8, &tx, &msg.transaction_id);
    try std.testing.expectEqual(@as(usize, 0), msg.attributes.len);
}

test "XOR-MAPPED-ADDRESS encode/decode for IPv4 verifies transform" {
    const allocator = std.testing.allocator;
    const tx: TransactionId = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 1, 2, 3, 4, 5 };
    const address = Address{ .ipv4 = .{ .ip = .{ 192, 0, 2, 1 }, .port = 54321 } };
    const bytes = try buildBindingSuccessResponse(allocator, tx, .{
        .xor_mapped_address = address,
        .fingerprint = false,
    });
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(u16, 0x0020), readU16(bytes[20..22]));
    try std.testing.expectEqual(@as(u16, 8), readU16(bytes[22..24]));
    try std.testing.expectEqual(@as(u8, 0x01), bytes[25]);
    try std.testing.expectEqual(@as(u16, 54321 ^ cookiePortMask()), readU16(bytes[26..28]));
    try std.testing.expectEqual(@as(u8, 192 ^ 0x21), bytes[28]);
    try std.testing.expectEqual(@as(u8, 0 ^ 0x12), bytes[29]);
    try std.testing.expectEqual(@as(u8, 2 ^ 0xa4), bytes[30]);
    try std.testing.expectEqual(@as(u8, 1 ^ 0x42), bytes[31]);

    var msg = try decode(allocator, bytes);
    defer msg.deinit(allocator);
    const decoded = msg.attributes[0].xor_mapped_address.ipv4;
    try std.testing.expectEqual(@as(u16, 54321), decoded.port);
    try std.testing.expectEqualSlices(u8, &address.ipv4.ip, &decoded.ip);
}

test "XOR-MAPPED-ADDRESS encode/decode for IPv6 verifies transform" {
    const allocator = std.testing.allocator;
    const tx: TransactionId = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 1, 2, 3, 4, 5 };
    const ip: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const address = Address{ .ipv6 = .{ .ip = ip, .port = 3478 } };
    const bytes = try buildBindingSuccessResponse(allocator, tx, .{
        .xor_mapped_address = address,
        .fingerprint = false,
    });
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(u16, 0x0020), readU16(bytes[20..22]));
    try std.testing.expectEqual(@as(u16, 20), readU16(bytes[22..24]));
    try std.testing.expectEqual(@as(u8, 0x02), bytes[25]);
    try std.testing.expectEqual(@as(u16, 3478 ^ cookiePortMask()), readU16(bytes[26..28]));
    const cookie = cookieBytes();
    for (ip[0..4], 0..) |plain, i| try std.testing.expectEqual(plain ^ cookie[i], bytes[28 + i]);
    for (ip[4..16], 0..) |plain, i| try std.testing.expectEqual(plain ^ tx[i], bytes[32 + i]);

    var msg = try decode(allocator, bytes);
    defer msg.deinit(allocator);
    const decoded = msg.attributes[0].xor_mapped_address.ipv6;
    try std.testing.expectEqual(@as(u16, 3478), decoded.port);
    try std.testing.expectEqualSlices(u8, &ip, &decoded.ip);
}

test "attribute padding is encoded and skipped" {
    const allocator = std.testing.allocator;
    const tx: TransactionId = .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    const bytes = try buildBindingRequest(allocator, tx, .{
        .username = "abc",
        .fingerprint = false,
    });
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(u16, 8), readU16(bytes[2..4]));
    try std.testing.expectEqual(@as(u16, 0x0006), readU16(bytes[20..22]));
    try std.testing.expectEqual(@as(u16, 3), readU16(bytes[22..24]));
    try std.testing.expectEqualSlices(u8, "abc", bytes[24..27]);
    try std.testing.expectEqual(@as(u8, 0), bytes[27]);

    var msg = try decode(allocator, bytes);
    defer msg.deinit(allocator);
    try std.testing.expectEqualSlices(u8, "abc", msg.attributes[0].username);
}

test "MESSAGE-INTEGRITY compute and verify rejects tampering" {
    const allocator = std.testing.allocator;
    const tx: TransactionId = .{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2 };
    const bytes = try buildBindingRequest(allocator, tx, .{
        .username = "user:peer",
        .integrity_key = "shared-secret",
        .fingerprint = false,
    });
    defer allocator.free(bytes);

    try std.testing.expect(try verifyMessageIntegrity(bytes, "shared-secret"));
    const expected = try computeMessageIntegrity(bytes, "shared-secret");
    const found = try findAttribute(bytes, @backingInt(AttributeType.message_integrity));
    try std.testing.expectEqualSlices(u8, &expected, bytes[found.value_offset..][0..message_integrity_len]);

    const tampered = try allocator.dupe(u8, bytes);
    defer allocator.free(tampered);
    tampered[24] ^= 0x01;
    try std.testing.expect(!try verifyMessageIntegrity(tampered, "shared-secret"));
}

test "FINGERPRINT compute and verify rejects tampering" {
    const allocator = std.testing.allocator;
    const tx: TransactionId = .{ 3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8 };
    const bytes = try buildBindingRequest(allocator, tx, .{
        .username = "abc",
        .fingerprint = true,
    });
    defer allocator.free(bytes);

    try std.testing.expect(try verifyFingerprint(bytes));
    const expected = try computeFingerprint(bytes);
    const found = try findAttribute(bytes, @backingInt(AttributeType.fingerprint));
    try std.testing.expectEqual(expected, readU32(bytes[found.value_offset..][0..4]));

    const tampered = try allocator.dupe(u8, bytes);
    defer allocator.free(tampered);
    tampered[24] ^= 0x80;
    try std.testing.expect(!try verifyFingerprint(tampered));
}

test "truncation and bad-cookie errors" {
    const allocator = std.testing.allocator;
    const tx: TransactionId = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectError(error.Truncated, decode(allocator, &.{ 0, 1, 0 }));

    const bytes = try encodeMessage(allocator, .binding_request, tx, &.{});
    defer allocator.free(bytes);

    const bad_cookie = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_cookie);
    bad_cookie[4] ^= 0xff;
    try std.testing.expectError(error.BadCookie, decode(allocator, bad_cookie));

    var truncated_with_len = bytes[0..header_len].*;
    writeU16(truncated_with_len[2..4], 4);
    try std.testing.expectError(error.Truncated, decode(allocator, &truncated_with_len));
}
