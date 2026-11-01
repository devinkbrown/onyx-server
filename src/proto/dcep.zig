// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebRTC Data Channel Establishment Protocol (DCEP), RFC 8832.
const std = @import("std");

pub const PPID: u32 = 50;

pub const MessageType = enum(u8) {
    ack = 0x02,
    open = 0x03,
    _,
};

pub const ChannelType = enum(u8) {
    reliable = 0x00,
    partial_reliable_rexmit = 0x01,
    partial_reliable_timed = 0x02,
    reliable_unordered = 0x80,
    partial_reliable_rexmit_unordered = 0x81,
    partial_reliable_timed_unordered = 0x82,
    _,
};

pub const Open = struct {
    channel_type: ChannelType,
    priority: u16,
    reliability: u32,
    label: []const u8,
    protocol: []const u8,
};

pub const Error = error{
    Truncated,
    BadType,
    BufferTooSmall,
};

const open_header_len = 12;

pub fn encodeOpen(o: Open, out: []u8) Error![]const u8 {
    if (o.label.len > std.math.maxInt(u16) or o.protocol.len > std.math.maxInt(u16)) {
        return error.BufferTooSmall;
    }

    const total_len = open_header_len + o.label.len + o.protocol.len;
    if (out.len < total_len) return error.BufferTooSmall;

    out[0] = @backingInt(MessageType.open);
    out[1] = @backingInt(o.channel_type);
    std.mem.writeInt(u16, out[2..4], o.priority, .big);
    std.mem.writeInt(u32, out[4..8], o.reliability, .big);
    std.mem.writeInt(u16, out[8..10], @intCast(o.label.len), .big);
    std.mem.writeInt(u16, out[10..12], @intCast(o.protocol.len), .big);

    @memcpy(out[open_header_len .. open_header_len + o.label.len], o.label);
    @memcpy(out[open_header_len + o.label.len .. total_len], o.protocol);

    return out[0..total_len];
}

pub fn parseOpen(bytes: []const u8) Error!Open {
    if (bytes.len < 1) return error.Truncated;
    if (try messageType(bytes) != .open) return error.BadType;
    if (bytes.len < open_header_len) return error.Truncated;

    const label_len = std.mem.readInt(u16, bytes[8..10], .big);
    const protocol_len = std.mem.readInt(u16, bytes[10..12], .big);
    const label_start = open_header_len;
    const protocol_start = label_start + @as(usize, label_len);
    const total_len = protocol_start + @as(usize, protocol_len);
    if (bytes.len < total_len) return error.Truncated;

    return .{
        .channel_type = @fromBackingInt(@intCast(bytes[1])),
        .priority = std.mem.readInt(u16, bytes[2..4], .big),
        .reliability = std.mem.readInt(u32, bytes[4..8], .big),
        .label = bytes[label_start..protocol_start],
        .protocol = bytes[protocol_start..total_len],
    };
}

pub fn encodeAck(out: []u8) Error![]const u8 {
    if (out.len < 1) return error.BufferTooSmall;
    out[0] = @backingInt(MessageType.ack);
    return out[0..1];
}

pub fn messageType(bytes: []const u8) Error!MessageType {
    if (bytes.len < 1) return error.Truncated;
    return switch (bytes[0]) {
        @backingInt(MessageType.ack) => .ack,
        @backingInt(MessageType.open) => .open,
        else => error.BadType,
    };
}

test "encodeOpen with label and protocol parses back to the same fields" {
    const original = Open{
        .channel_type = .partial_reliable_rexmit_unordered,
        .priority = 7,
        .reliability = 1234,
        .label = "chat",
        .protocol = "json",
    };
    var buf: [64]u8 = undefined;

    const encoded = try encodeOpen(original, &buf);
    try std.testing.expectEqual(@as(usize, 20), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x03), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x81), encoded[1]);

    const parsed = try parseOpen(encoded);
    try std.testing.expectEqual(original.channel_type, parsed.channel_type);
    try std.testing.expectEqual(original.priority, parsed.priority);
    try std.testing.expectEqual(original.reliability, parsed.reliability);
    try std.testing.expectEqualSlices(u8, original.label, parsed.label);
    try std.testing.expectEqualSlices(u8, original.protocol, parsed.protocol);
}

test "ack encodes to one byte and messageType detects it" {
    var buf: [4]u8 = undefined;

    const encoded = try encodeAck(&buf);
    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x02), encoded[0]);
    try std.testing.expectEqual(MessageType.ack, try messageType(encoded));
}

test "short buffers report Truncated" {
    try std.testing.expectError(error.Truncated, messageType(""));
    try std.testing.expectError(error.Truncated, parseOpen(&.{0x03}));
}

test "unknown message type reports BadType" {
    try std.testing.expectError(error.BadType, messageType(&.{0xff}));
    try std.testing.expectError(error.BadType, parseOpen(&.{ 0x02, 0x00, 0x00, 0x00 }));
}
