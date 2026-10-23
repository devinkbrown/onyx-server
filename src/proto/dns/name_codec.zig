// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded DNS presentation names and compression decoding shared by UDP/TCP.

const std = @import("std");

pub const max_text_len: usize = 253;
pub const max_wire_len: usize = 255;
pub const max_pointer_hops: usize = 128;

pub const EncodeError = error{ OutputTooSmall, InvalidName, NameTooLong };
pub const DecodeError = error{ TruncatedMessage, OversizeMessage, InvalidName, NameTooLong, CompressionLoop };

pub fn encode(out: []u8, raw: []const u8) EncodeError!usize {
    if (raw.len == 0) return error.InvalidName;
    if (std.mem.eql(u8, raw, ".")) {
        if (out.len == 0) return error.OutputTooSmall;
        out[0] = 0;
        return 1;
    }
    const name = trimRootDot(raw);
    if (name.len > max_text_len) return error.NameTooLong;
    var pos: usize = 0;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0) return error.InvalidName;
        if (label.len > 63) return error.NameTooLong;
        for (label) |byte| if (!isLabelByte(byte)) return error.InvalidName;
        if (pos + 1 + label.len + 1 > max_wire_len) return error.NameTooLong;
        if (pos + 1 + label.len > out.len) return error.OutputTooSmall;
        out[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(out[pos..][0..label.len], label);
        pos += label.len;
    }
    if (pos == out.len) return error.OutputTooSmall;
    out[pos] = 0;
    return pos + 1;
}

/// Returns the first byte after the encoded name at `start`, even when its
/// suffix was compressed. Expanded length and pointer work have separate caps:
/// compression pointers do not consume the 255-byte expanded-name allowance.
pub fn decode(comptime max_packet_len: usize, packet: []const u8, start: usize, out: []u8, out_len: *usize) DecodeError!usize {
    if (packet.len > max_packet_len) return error.OversizeMessage;
    if (start >= packet.len) return error.TruncatedMessage;
    var seen = std.StaticBitSet(max_packet_len).empty;
    var cursor = start;
    var next_offset: ?usize = null;
    var expanded_len: usize = 0;
    var text_len: usize = 0;
    var pointer_hops: usize = 0;
    while (true) {
        if (cursor >= packet.len) return error.TruncatedMessage;
        if (seen.isSet(cursor)) return error.CompressionLoop;
        seen.set(cursor);
        const len = packet[cursor];
        if ((len & 0xc0) == 0xc0) {
            if (cursor + 1 >= packet.len) return error.TruncatedMessage;
            const ptr = (@as(usize, len & 0x3f) << 8) | packet[cursor + 1];
            if (ptr >= packet.len) return error.InvalidName;
            if (next_offset == null) next_offset = cursor + 2;
            pointer_hops += 1;
            if (pointer_hops > max_pointer_hops) return error.CompressionLoop;
            cursor = ptr;
            continue;
        }
        if ((len & 0xc0) != 0) return error.InvalidName;
        cursor += 1;
        expanded_len += 1 + len;
        if (expanded_len > max_wire_len) return error.NameTooLong;
        if (len == 0) {
            if (text_len == 0) {
                if (out.len == 0) return error.NameTooLong;
                out[0] = '.';
                text_len = 1;
            }
            out_len.* = text_len;
            return next_offset orelse cursor;
        }
        if (len > packet.len - cursor) return error.TruncatedMessage;
        for (packet[cursor..][0..len]) |byte| if (!isLabelByte(byte)) return error.InvalidName;
        if (text_len != 0) {
            if (text_len >= out.len) return error.NameTooLong;
            out[text_len] = '.';
            text_len += 1;
        }
        if (len > out.len - text_len) return error.NameTooLong;
        @memcpy(out[text_len..][0..len], packet[cursor..][0..len]);
        text_len += len;
        cursor += len;
    }
}

pub fn normalize(out: []u8, raw: []const u8) EncodeError![]const u8 {
    var encoded: [max_wire_len]u8 = undefined;
    _ = try encode(&encoded, raw);
    const name = trimRootDot(raw);
    if (name.len > out.len) return error.OutputTooSmall;
    for (name, 0..) |byte, index| out[index] = std.ascii.toLower(byte);
    return out[0..name.len];
}

pub fn equal(lhs: []const u8, rhs: []const u8) bool {
    return std.ascii.eqlIgnoreCase(trimRootDot(lhs), trimRootDot(rhs));
}

pub fn withinZone(name: []const u8, zone: []const u8) bool {
    const child = trimRootDot(name);
    const parent = trimRootDot(zone);
    if (std.mem.eql(u8, parent, ".")) return true;
    if (child.len < parent.len) return false;
    if (!std.ascii.eqlIgnoreCase(child[child.len - parent.len ..], parent)) return false;
    return child.len == parent.len or child[child.len - parent.len - 1] == '.';
}

fn trimRootDot(name: []const u8) []const u8 {
    return if (name.len > 1 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

fn isLabelByte(byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => true,
        else => false,
    };
}

test "DNS compressed maximal names preserve expanded length and TCP offsets" {
    var text: [max_text_len]u8 = @splat('a');
    text[63] = '.';
    text[127] = '.';
    text[191] = '.';
    var packet: [1024]u8 = @splat(0);
    const encoded_len = try encode(packet[600..], &text);
    try std.testing.expectEqual(max_wire_len, encoded_len);
    packet[12] = 0xc2;
    packet[13] = 0x58; // 600, beyond a legacy UDP-sized name bitmap.
    var decoded: [max_text_len]u8 = undefined;
    var len: usize = 0;
    try std.testing.expectEqual(@as(usize, 14), try decode(1024, packet[0 .. 600 + encoded_len], 12, &decoded, &len));
    try std.testing.expectEqualStrings(&text, decoded[0..len]);
    packet[600] = 0xc0;
    packet[601] = 12;
    try std.testing.expectError(error.CompressionLoop, decode(1024, &packet, 12, &decoded, &len));
}

test "DNS compression pointer work has a separate finite hop bound" {
    var packet: [2 * (max_pointer_hops + 1) + 1]u8 = @splat(0);
    for (0..max_pointer_hops + 1) |index| {
        const target = (index + 1) * 2;
        packet[index * 2] = 0xc0 | @as(u8, @intCast(target >> 8));
        packet[index * 2 + 1] = @truncate(target);
    }
    var decoded: [max_text_len]u8 = undefined;
    var length: usize = 0;
    try std.testing.expectError(error.CompressionLoop, decode(packet.len, &packet, 0, &decoded, &length));
    try std.testing.expectEqual(@as(usize, 4), try decode(packet.len, &packet, 2, &decoded, &length));
    try std.testing.expectEqualStrings(".", decoded[0..length]);
}
