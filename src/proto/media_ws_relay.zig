// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded S2S payload for mesh-cascaded browser Cadence WebSocket media.
//!
//! Origin nodes that already admitted a binary `onyx.irc-media.v1` datagram fan
//! the **opaque** bytes to secured mesh peers. Receivers re-wrap locally for
//! their own WS call participants and never re-mesh (loop prevention is
//! origin-only emit). The payload is never decrypted or re-encoded: E2EE
//! stays end-to-end between browsers.
//!
//! Wire layout (little-endian lengths):
//!   [u16 channel_len][channel bytes][datagram bytes…]
//!
//! Datagram length is implicit (remainder of the payload). Bounds match the
//! live WS media ceiling (`ws_snapshot.max_frame_payload` = 4 MiB) and the
//! membership channel-name ceiling (128).
const std = @import("std");

/// Must stay equal to `daemon/helix/ws_snapshot.max_frame_payload` / WsState.
pub const max_datagram_len: usize = 4 * 1024 * 1024;
/// Matches membership / topic channel bounds.
pub const max_channel_len: usize = 128;
/// Fixed prefix: channel length only; datagram fills the rest.
pub const header_len: usize = 2;
pub const max_encoded_len: usize = header_len + max_channel_len + max_datagram_len;

pub const Error = error{
    InvalidField,
    BufferTooSmall,
    Malformed,
};

pub const MediaWsDatagram = struct {
    channel: []const u8,
    datagram: []const u8,
};

pub fn encode(ev: MediaWsDatagram, out: []u8) Error![]const u8 {
    if (ev.channel.len == 0 or ev.channel.len > max_channel_len) return error.InvalidField;
    if (ev.datagram.len == 0 or ev.datagram.len > max_datagram_len) return error.InvalidField;

    const total = header_len + ev.channel.len + ev.datagram.len;
    if (out.len < total) return error.BufferTooSmall;

    std.mem.writeInt(u16, out[0..2], @intCast(ev.channel.len), .little);
    @memcpy(out[header_len..][0..ev.channel.len], ev.channel);
    @memcpy(out[header_len + ev.channel.len ..][0..ev.datagram.len], ev.datagram);
    return out[0..total];
}

pub fn decode(bytes: []const u8) Error!MediaWsDatagram {
    if (bytes.len < header_len) return error.Malformed;
    const channel_len: usize = std.mem.readInt(u16, bytes[0..2], .little);
    if (channel_len == 0 or channel_len > max_channel_len) return error.Malformed;
    if (bytes.len < header_len + channel_len) return error.Malformed;
    const datagram = bytes[header_len + channel_len ..];
    if (datagram.len == 0 or datagram.len > max_datagram_len) return error.Malformed;
    return .{
        .channel = bytes[header_len..][0..channel_len],
        .datagram = datagram,
    };
}

/// Upper bound on a complete S2S frame carrying a max-size signed media
/// datagram: s2s header (5) + signed-frame envelope (96) + max codec payload.
/// Used to size `s2s_frame.default_max_frame_size` and peer sendq floors.
pub const signed_envelope_overhead: usize = 96; // signed_frame.header_len
pub const s2s_header_overhead: usize = 5; // s2s_frame.header_len
pub const required_max_frame_size: usize =
    s2s_header_overhead + signed_envelope_overhead + max_encoded_len;

test "media ws relay encode decode round-trip" {
    // Keep the encode scratch small — max_encoded_len is ~4 MiB and must not
    // live on the test stack.
    var buf: [256]u8 = undefined;
    const payload = "opaque-e2ee-cadence-bytes";
    const wire = try encode(.{ .channel = "#call", .datagram = payload }, &buf);
    const got = try decode(wire);
    try std.testing.expectEqualStrings("#call", got.channel);
    try std.testing.expectEqualStrings(payload, got.datagram);
}

test "media ws relay rejects empty oversize and truncated input" {
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidField, encode(.{ .channel = "", .datagram = "x" }, &buf));
    try std.testing.expectError(error.InvalidField, encode(.{ .channel = "#c", .datagram = "" }, &buf));

    var long_chan_buf: [max_channel_len + 1]u8 = undefined;
    @memset(&long_chan_buf, 'x');
    long_chan_buf[0] = '#';
    try std.testing.expectError(error.InvalidField, encode(.{ .channel = &long_chan_buf, .datagram = "x" }, &buf));

    try std.testing.expectError(error.Malformed, decode(&.{}));
    try std.testing.expectError(error.Malformed, decode(&.{ 0, 0 }));
    // channel_len claims 1 byte but only header present
    try std.testing.expectError(error.Malformed, decode(&.{ 1, 0 }));
    // empty datagram after a valid channel
    var short: [3]u8 = .{ 1, 0, '#' };
    try std.testing.expectError(error.Malformed, decode(&short));
}

test "media ws relay bounds match WS media ceiling" {
    try std.testing.expectEqual(@as(usize, 4 * 1024 * 1024), max_datagram_len);
    try std.testing.expect(required_max_frame_size > max_datagram_len);
}
