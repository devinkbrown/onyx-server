// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const WireError = error{
    BufferTooShort,
    InvalidVarInt,
    NonCanonicalVarInt,
    InvalidFrame,
    UnknownFrameType,
    TrailingBytes,
    InvalidPacketNumberLength,
};

pub const DecodedVarInt = struct {
    value: u64,
    len: usize,
};

pub const AckRange = struct {
    gap: u64,
    len: u64,
};

pub const AckFrame = struct {
    largest: u64,
    delay: u64 = 0,
    first_range: u64 = 0,
    ranges: []const AckRange = &.{},
};

pub const CryptoFrame = struct {
    offset: u64,
    len: u64,
    data: []const u8,
};

pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64 = 0,
    fin: bool = false,
    len: u64,
    data: []const u8,
};

pub const DatagramFrame = struct {
    len: u64,
    data: []const u8,
};

pub const ConnectionCloseFrame = struct {
    error_code: u64,
    reason_len: u64,
    reason: []const u8,
};

/// PATH_CHALLENGE (0x1a) / PATH_RESPONSE (0x1b) carry an 8-byte opaque value
/// (RFC 9000 §19.17 / §19.18). The challenger picks unpredictable `data`; the
/// peer echoes the exact bytes in a PATH_RESPONSE to prove it can both receive
/// on and send from the new path. The value is fixed-width (never length-
/// prefixed on the wire), so the codec carries it inline.
pub const PathChallengeData = [8]u8;

pub const Frame = union(enum) {
    PADDING: void,
    PING: void,
    ACK: AckFrame,
    CRYPTO: CryptoFrame,
    STREAM: StreamFrame,
    DATAGRAM: DatagramFrame,
    CONNECTION_CLOSE: ConnectionCloseFrame,
    /// RFC 9000 §19.17 — path-validation challenge (8 opaque bytes).
    PATH_CHALLENGE: PathChallengeData,
    /// RFC 9000 §19.18 — path-validation response (echoes the challenge).
    PATH_RESPONSE: PathChallengeData,
    /// HANDSHAKE_DONE (RFC 9000 §19.20, type 0x1e): the server signals the
    /// handshake is confirmed. Ack-eliciting, no payload.
    HANDSHAKE_DONE: void,
    /// MAX_DATA (RFC 9000 §19.9, type 0x10): the peer raises the connection-level
    /// flow-control limit (total stream-data offset it will accept). We honor it
    /// on the send side to pace large responses within the peer's credit.
    MAX_DATA: u64,
    /// MAX_STREAM_DATA (RFC 9000 §19.10, type 0x11): the peer raises the per-
    /// stream flow-control limit for `stream_id`.
    MAX_STREAM_DATA: struct { stream_id: u64, limit: u64 },
    /// Any other well-formed transport frame we parse-and-skip rather than act
    /// on (RFC 9000 §12.4 requires every frame type to be processed, but a
    /// minimal endpoint MAY treat flow-control / connection-id management frames
    /// as no-ops as long as it consumes their bytes correctly so packet framing
    /// and coalescing stay intact). `frame_type` is the leading type byte; it is
    /// ack-eliciting unless it is purely informational. We carry the type so the
    /// engine can decide ack-elicitation. The fields are fully parsed off the
    /// wire (bounds-checked) but discarded.
    OTHER: OtherFrame,
};

/// A parsed-but-unhandled transport frame (see `Frame.OTHER`). RFC 9000 §13.2.1:
/// all frames except ACK, PADDING, and CONNECTION_CLOSE are ack-eliciting; we
/// record that so the receiver still schedules an ACK.
pub const OtherFrame = struct {
    frame_type: u64,
    ack_eliciting: bool,
};

/// Whether `frame` may appear in a 0-RTT packet (RFC 9000 §12.4 Table 3 and
/// §17.2.3). ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE and
/// RETIRE_CONNECTION_ID are forbidden; a receiver MUST treat any of them in
/// 0-RTT as a connection error of type PROTOCOL_VIOLATION.
pub fn permittedInZeroRtt(frame: Frame) bool {
    return switch (frame) {
        .ACK, .CRYPTO, .HANDSHAKE_DONE, .PATH_RESPONSE => false,
        .OTHER => |o| o.frame_type != 0x07 and o.frame_type != 0x19,
        else => true,
    };
}

test "permittedInZeroRtt follows RFC 9000 §12.4 Table 3" {
    try std.testing.expect(permittedInZeroRtt(.{ .PING = {} }));
    try std.testing.expect(permittedInZeroRtt(.{ .STREAM = .{ .stream_id = 0, .offset = 0, .fin = false, .len = 0, .data = "" } }));
    try std.testing.expect(permittedInZeroRtt(.{ .MAX_DATA = 1 }));
    try std.testing.expect(permittedInZeroRtt(.{ .PATH_CHALLENGE = @splat(0) }));
    try std.testing.expect(permittedInZeroRtt(.{ .OTHER = .{ .frame_type = 0x04, .ack_eliciting = true } })); // RESET_STREAM
    try std.testing.expect(!permittedInZeroRtt(.{ .ACK = .{ .largest = 0, .delay = 0, .first_range = 0, .ranges = &.{} } }));
    try std.testing.expect(!permittedInZeroRtt(.{ .CRYPTO = .{ .offset = 0, .len = 0, .data = "" } }));
    try std.testing.expect(!permittedInZeroRtt(.{ .HANDSHAKE_DONE = {} }));
    try std.testing.expect(!permittedInZeroRtt(.{ .PATH_RESPONSE = @splat(0) }));
    try std.testing.expect(!permittedInZeroRtt(.{ .OTHER = .{ .frame_type = 0x07, .ack_eliciting = true } })); // NEW_TOKEN
    try std.testing.expect(!permittedInZeroRtt(.{ .OTHER = .{ .frame_type = 0x19, .ack_eliciting = true } })); // RETIRE_CONNECTION_ID
}

pub const DecodedFrame = struct {
    frame: Frame,
    len: usize,
};

pub const DecodedFrames = struct {
    allocator: std.mem.Allocator,
    frames: []Frame,

    pub fn deinit(self: *DecodedFrames) void {
        for (self.frames) |frame| freeFrame(self.allocator, frame);
        self.allocator.free(self.frames);
        self.* = .{ .allocator = self.allocator, .frames = &.{} };
    }
};

pub const max_varint: u64 = (1 << 62) - 1;

pub fn varIntLen(value: u64) WireError!usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= max_varint) return 8;
    return WireError.InvalidVarInt;
}

pub fn encodeVarInt(value: u64, out: []u8) WireError!usize {
    const len = try varIntLen(value);
    if (out.len < len) return WireError.BufferTooShort;

    switch (len) {
        1 => out[0] = @as(u8, @intCast(value)),
        2 => {
            const v = value | 0x4000;
            out[0] = @as(u8, @intCast(v >> 8));
            out[1] = @as(u8, @intCast(v & 0xff));
        },
        4 => {
            const v = value | 0x80000000;
            out[0] = @as(u8, @intCast(v >> 24));
            out[1] = @as(u8, @intCast((v >> 16) & 0xff));
            out[2] = @as(u8, @intCast((v >> 8) & 0xff));
            out[3] = @as(u8, @intCast(v & 0xff));
        },
        8 => {
            const v = value | 0xc000000000000000;
            out[0] = @as(u8, @intCast(v >> 56));
            out[1] = @as(u8, @intCast((v >> 48) & 0xff));
            out[2] = @as(u8, @intCast((v >> 40) & 0xff));
            out[3] = @as(u8, @intCast((v >> 32) & 0xff));
            out[4] = @as(u8, @intCast((v >> 24) & 0xff));
            out[5] = @as(u8, @intCast((v >> 16) & 0xff));
            out[6] = @as(u8, @intCast((v >> 8) & 0xff));
            out[7] = @as(u8, @intCast(v & 0xff));
        },
        else => unreachable,
    }

    return len;
}

pub fn appendVarInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var buf: [8]u8 = undefined;
    const len = try encodeVarInt(value, &buf);
    try out.appendSlice(allocator, buf[0..len]);
}

pub fn decodeVarInt(input: []const u8) WireError!DecodedVarInt {
    if (input.len == 0) return WireError.BufferTooShort;

    const tag = input[0] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (input.len < len) return WireError.BufferTooShort;

    var value: u64 = input[0] & 0x3f;
    for (input[1..len]) |byte| value = (value << 8) | byte;

    if ((try varIntLen(value)) != len) return WireError.NonCanonicalVarInt;
    return .{ .value = value, .len = len };
}

pub fn encodeFrame(out: *std.ArrayList(u8), allocator: std.mem.Allocator, frame: Frame) !void {
    switch (frame) {
        .PADDING => try out.append(allocator, 0x00),
        .PING => try out.append(allocator, 0x01),
        .ACK => |ack| {
            try out.append(allocator, 0x02);
            try appendVarInt(out, allocator, ack.largest);
            try appendVarInt(out, allocator, ack.delay);
            try appendVarInt(out, allocator, ack.ranges.len);
            try appendVarInt(out, allocator, ack.first_range);
            for (ack.ranges) |range| {
                try appendVarInt(out, allocator, range.gap);
                try appendVarInt(out, allocator, range.len);
            }
        },
        .CRYPTO => |crypto| {
            try ensureLenMatches(crypto.len, crypto.data);
            try out.append(allocator, 0x06);
            try appendVarInt(out, allocator, crypto.offset);
            try appendVarInt(out, allocator, crypto.len);
            try out.appendSlice(allocator, crypto.data);
        },
        .STREAM => |stream| {
            try ensureLenMatches(stream.len, stream.data);
            var ty: u8 = 0x08 | 0x02;
            if (stream.offset != 0) ty |= 0x04;
            if (stream.fin) ty |= 0x01;
            try out.append(allocator, ty);
            try appendVarInt(out, allocator, stream.stream_id);
            if (stream.offset != 0) try appendVarInt(out, allocator, stream.offset);
            try appendVarInt(out, allocator, stream.len);
            try out.appendSlice(allocator, stream.data);
        },
        .DATAGRAM => |datagram| {
            try ensureLenMatches(datagram.len, datagram.data);
            try out.append(allocator, 0x31);
            try appendVarInt(out, allocator, datagram.len);
            try out.appendSlice(allocator, datagram.data);
        },
        .CONNECTION_CLOSE => |close| {
            try ensureLenMatches(close.reason_len, close.reason);
            try out.append(allocator, 0x1c);
            try appendVarInt(out, allocator, close.error_code);
            try appendVarInt(out, allocator, 0);
            try appendVarInt(out, allocator, close.reason_len);
            try out.appendSlice(allocator, close.reason);
        },
        .PATH_CHALLENGE => |data| {
            try out.append(allocator, 0x1a);
            try out.appendSlice(allocator, &data);
        },
        .PATH_RESPONSE => |data| {
            try out.append(allocator, 0x1b);
            try out.appendSlice(allocator, &data);
        },
        .HANDSHAKE_DONE => try out.append(allocator, 0x1e),
        // We never *originate* MAX_DATA / MAX_STREAM_DATA / OTHER frames here
        // (they only ever result from decoding an inbound frame); re-encoding one
        // is unsupported.
        .MAX_DATA, .MAX_STREAM_DATA, .OTHER => return WireError.UnknownFrameType,
    }
}

pub fn encodeFrames(allocator: std.mem.Allocator, frames: []const Frame) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (frames) |frame| try encodeFrame(&out, allocator, frame);
    return out.toOwnedSlice(allocator);
}

pub fn decodeFrame(allocator: std.mem.Allocator, input: []const u8) !DecodedFrame {
    if (input.len == 0) return WireError.BufferTooShort;

    const ty = input[0];
    var pos: usize = 1;

    switch (ty) {
        0x00 => return .{ .frame = .{ .PADDING = {} }, .len = 1 },
        0x01 => return .{ .frame = .{ .PING = {} }, .len = 1 },
        0x02 => {
            const largest = try takeVarInt(input, &pos);
            const delay = try takeVarInt(input, &pos);
            const range_count = try takeVarInt(input, &pos);
            const first_range = try takeVarInt(input, &pos);

            // Each ACK range needs >= 2 bytes on the wire (gap + len varints).
            // Reject a count that cannot possibly fit the remaining input so a
            // tiny packet cannot trigger a huge allocation.
            if (range_count > (input.len - pos) / 2) return WireError.InvalidFrame;
            const ranges = try allocator.alloc(AckRange, @intCast(range_count));
            errdefer allocator.free(ranges);
            for (ranges) |*range| {
                range.* = .{
                    .gap = try takeVarInt(input, &pos),
                    .len = try takeVarInt(input, &pos),
                };
            }

            return .{
                .frame = .{ .ACK = .{
                    .largest = largest,
                    .delay = delay,
                    .first_range = first_range,
                    .ranges = ranges,
                } },
                .len = pos,
            };
        },
        0x06 => {
            const offset = try takeVarInt(input, &pos);
            const len = try takeVarInt(input, &pos);
            const data = try takeBytes(input, &pos, len);
            return .{
                .frame = .{ .CRYPTO = .{ .offset = offset, .len = len, .data = data } },
                .len = pos,
            };
        },
        // RESET_STREAM (RFC 9000 §19.4): Stream ID, App Error Code, Final Size.
        0x04 => {
            _ = try takeVarInt(input, &pos); // stream id
            _ = try takeVarInt(input, &pos); // app error code
            _ = try takeVarInt(input, &pos); // final size
            return .{ .frame = .{ .OTHER = .{ .frame_type = ty, .ack_eliciting = true } }, .len = pos };
        },
        // STOP_SENDING (RFC 9000 §19.5): Stream ID, App Error Code.
        0x05 => {
            _ = try takeVarInt(input, &pos); // stream id
            _ = try takeVarInt(input, &pos); // app error code
            return .{ .frame = .{ .OTHER = .{ .frame_type = ty, .ack_eliciting = true } }, .len = pos };
        },
        // NEW_TOKEN (RFC 9000 §19.7): Token Length, Token.
        0x07 => {
            const tok_len = try takeVarInt(input, &pos);
            _ = try takeBytes(input, &pos, tok_len);
            return .{ .frame = .{ .OTHER = .{ .frame_type = ty, .ack_eliciting = true } }, .len = pos };
        },
        // MAX_DATA (0x10, RFC 9000 §19.9): a single varint, the new connection-
        // level send limit. Surfaced so the driver can pace within the peer's
        // credit.
        0x10 => {
            const limit = try takeVarInt(input, &pos);
            return .{ .frame = .{ .MAX_DATA = limit }, .len = pos };
        },
        // MAX_STREAMS bidi/uni (0x12/0x13), DATA_BLOCKED (0x14), STREAMS_BLOCKED
        // bidi/uni (0x16/0x17): a single varint field. Stream-count / blocked
        // signals we honor implicitly via our own generous windows; parse-and-skip.
        0x12, 0x13, 0x14, 0x16, 0x17 => {
            _ = try takeVarInt(input, &pos);
            return .{ .frame = .{ .OTHER = .{ .frame_type = ty, .ack_eliciting = true } }, .len = pos };
        },
        // MAX_STREAM_DATA (0x11, RFC 9000 §19.10): Stream ID + new per-stream send
        // limit. Surfaced for send-side pacing.
        0x11 => {
            const sid = try takeVarInt(input, &pos);
            const limit = try takeVarInt(input, &pos);
            return .{ .frame = .{ .MAX_STREAM_DATA = .{ .stream_id = sid, .limit = limit } }, .len = pos };
        },
        // STREAM_DATA_BLOCKED (0x15): two varints (Stream ID + offset). A blocked
        // signal we parse-and-skip.
        0x15 => {
            _ = try takeVarInt(input, &pos); // stream id
            _ = try takeVarInt(input, &pos); // offset
            return .{ .frame = .{ .OTHER = .{ .frame_type = ty, .ack_eliciting = true } }, .len = pos };
        },
        // NEW_CONNECTION_ID (RFC 9000 §19.15): Seq, Retire Prior To, CID Length
        // (1 byte), CID, 16-byte Stateless Reset Token. We keep one connection id
        // per connection, so we acknowledge but do not act on these.
        0x18 => {
            _ = try takeVarInt(input, &pos); // sequence number
            _ = try takeVarInt(input, &pos); // retire prior to
            if (pos >= input.len) return WireError.BufferTooShort;
            const cid_len = input[pos];
            pos += 1;
            if (cid_len > 20) return WireError.InvalidFrame; // RFC 9000 §19.15
            _ = try takeBytes(input, &pos, cid_len); // connection id
            _ = try takeBytes(input, &pos, 16); // stateless reset token
            return .{ .frame = .{ .OTHER = .{ .frame_type = ty, .ack_eliciting = true } }, .len = pos };
        },
        // RETIRE_CONNECTION_ID (RFC 9000 §19.16): a single varint (sequence).
        0x19 => {
            _ = try takeVarInt(input, &pos);
            return .{ .frame = .{ .OTHER = .{ .frame_type = ty, .ack_eliciting = true } }, .len = pos };
        },
        // HANDSHAKE_DONE (RFC 9000 §19.20): no payload, ack-eliciting.
        0x1e => return .{ .frame = .{ .HANDSHAKE_DONE = {} }, .len = pos },
        // CONNECTION_CLOSE: transport (0x1c) carries a Frame Type field; the
        // application variant (0x1d, RFC 9000 §19.19) does NOT. Both then carry
        // Reason Phrase Length + Reason. Neither is ack-eliciting (§13.2.1).
        0x1c, 0x1d => {
            const error_code = try takeVarInt(input, &pos);
            if (ty == 0x1c) _ = try takeVarInt(input, &pos); // transport: frame type
            const reason_len = try takeVarInt(input, &pos);
            const reason = try takeBytes(input, &pos, reason_len);
            return .{
                .frame = .{ .CONNECTION_CLOSE = .{
                    .error_code = error_code,
                    .reason_len = reason_len,
                    .reason = reason,
                } },
                .len = pos,
            };
        },
        0x1a, 0x1b => {
            // PATH_CHALLENGE / PATH_RESPONSE: a fixed 8-byte opaque value
            // (RFC 9000 §19.17 / §19.18). No length prefix on the wire.
            const data = try takeBytes(input, &pos, 8);
            var value: PathChallengeData = undefined;
            @memcpy(&value, data);
            return .{
                .frame = if (ty == 0x1a)
                    .{ .PATH_CHALLENGE = value }
                else
                    .{ .PATH_RESPONSE = value },
                .len = pos,
            };
        },
        0x30, 0x31 => {
            const has_len = (ty & 0x01) != 0;
            const len = if (has_len) try takeVarInt(input, &pos) else input.len - pos;
            const data = try takeBytes(input, &pos, len);
            return .{
                .frame = .{ .DATAGRAM = .{ .len = len, .data = data } },
                .len = pos,
            };
        },
        else => {
            if ((ty & 0xf8) == 0x08) {
                const has_fin = (ty & 0x01) != 0;
                const has_len = (ty & 0x02) != 0;
                const has_offset = (ty & 0x04) != 0;
                const stream_id = try takeVarInt(input, &pos);
                const offset = if (has_offset) try takeVarInt(input, &pos) else 0;
                const len = if (has_len) try takeVarInt(input, &pos) else input.len - pos;
                const data = try takeBytes(input, &pos, len);
                return .{
                    .frame = .{ .STREAM = .{
                        .stream_id = stream_id,
                        .offset = offset,
                        .fin = has_fin,
                        .len = len,
                        .data = data,
                    } },
                    .len = pos,
                };
            }
            return WireError.UnknownFrameType;
        },
    }
}

pub fn decodeFrameExact(allocator: std.mem.Allocator, input: []const u8) !Frame {
    const decoded = try decodeFrame(allocator, input);
    errdefer freeFrame(allocator, decoded.frame);
    if (decoded.len != input.len) return WireError.TrailingBytes;
    return decoded.frame;
}

pub fn decodeFrames(allocator: std.mem.Allocator, payload: []const u8) !DecodedFrames {
    var frames: std.ArrayList(Frame) = .empty;
    errdefer {
        for (frames.items) |frame| freeFrame(allocator, frame);
        frames.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos < payload.len) {
        const decoded = try decodeFrame(allocator, payload[pos..]);
        errdefer freeFrame(allocator, decoded.frame);
        if (decoded.len == 0) return WireError.InvalidFrame;
        try frames.append(allocator, decoded.frame);
        pos += decoded.len;
    }

    return .{
        .allocator = allocator,
        .frames = try frames.toOwnedSlice(allocator),
    };
}

pub fn freeFrame(allocator: std.mem.Allocator, frame: Frame) void {
    switch (frame) {
        .ACK => |ack| allocator.free(ack.ranges),
        else => {},
    }
}

pub fn packetNumberLen(full_pn: u64, largest_acked: ?u64) WireError!usize {
    if (full_pn > max_varint) return WireError.InvalidFrame;
    const gap = if (largest_acked) |largest| blk: {
        if (full_pn <= largest) break :blk 1;
        break :blk full_pn - largest;
    } else full_pn;

    if (gap <= 0x80) return 1;
    if (gap <= 0x8000) return 2;
    if (gap <= 0x800000) return 3;
    return 4;
}

pub fn truncatePacketNumber(full_pn: u64, len: usize) WireError!u64 {
    try checkPacketNumberLen(len);
    const bits: u6 = @intCast(len * 8);
    const mask = (@as(u64, 1) << bits) - 1;
    return full_pn & mask;
}

pub fn encodePacketNumber(full_pn: u64, len: usize, out: []u8) WireError!usize {
    try checkPacketNumberLen(len);
    if (out.len < len) return WireError.BufferTooShort;
    const truncated = try truncatePacketNumber(full_pn, len);
    for (0..len) |i| {
        const shift: u6 = @intCast((len - 1 - i) * 8);
        out[i] = @as(u8, @intCast((truncated >> shift) & 0xff));
    }
    return len;
}

pub fn decodePacketNumber(truncated: u64, len: usize, largest_pn: u64) WireError!u64 {
    try checkPacketNumberLen(len);
    const bits: u6 = @intCast(len * 8);
    const pn_win = @as(u64, 1) << bits;
    if (truncated >= pn_win) return WireError.InvalidFrame;

    const expected = largest_pn + 1;
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;
    var candidate = (expected & ~pn_mask) | truncated;

    if (candidate + pn_hwin <= expected and candidate <= max_varint - pn_win) {
        candidate += pn_win;
    } else if (candidate > expected + pn_hwin and candidate >= pn_win) {
        candidate -= pn_win;
    }

    return candidate;
}

fn ensureLenMatches(len: u64, data: []const u8) WireError!void {
    if (len != data.len) return WireError.InvalidFrame;
}

fn takeVarInt(input: []const u8, pos: *usize) WireError!u64 {
    const decoded = try decodeVarInt(input[pos.*..]);
    pos.* += decoded.len;
    return decoded.value;
}

fn takeBytes(input: []const u8, pos: *usize, len: u64) WireError![]const u8 {
    if (len > std.math.maxInt(usize)) return WireError.InvalidFrame;
    const n: usize = @intCast(len);
    if (input.len - pos.* < n) return WireError.BufferTooShort;
    defer pos.* += n;
    return input[pos.*..][0..n];
}

fn checkPacketNumberLen(len: usize) WireError!void {
    if (len < 1 or len > 4) return WireError.InvalidPacketNumberLength;
}

fn expectFrameEqual(expected: Frame, actual: Frame) !void {
    switch (expected) {
        .PADDING => try std.testing.expect(actual == .PADDING),
        .PING => try std.testing.expect(actual == .PING),
        .ACK => |e| {
            const a = actual.ACK;
            try std.testing.expectEqual(e.largest, a.largest);
            try std.testing.expectEqual(e.delay, a.delay);
            try std.testing.expectEqual(e.first_range, a.first_range);
            try std.testing.expectEqualSlices(AckRange, e.ranges, a.ranges);
        },
        .CRYPTO => |e| {
            const a = actual.CRYPTO;
            try std.testing.expectEqual(e.offset, a.offset);
            try std.testing.expectEqual(e.len, a.len);
            try std.testing.expectEqualSlices(u8, e.data, a.data);
        },
        .STREAM => |e| {
            const a = actual.STREAM;
            try std.testing.expectEqual(e.stream_id, a.stream_id);
            try std.testing.expectEqual(e.offset, a.offset);
            try std.testing.expectEqual(e.fin, a.fin);
            try std.testing.expectEqual(e.len, a.len);
            try std.testing.expectEqualSlices(u8, e.data, a.data);
        },
        .DATAGRAM => |e| {
            const a = actual.DATAGRAM;
            try std.testing.expectEqual(e.len, a.len);
            try std.testing.expectEqualSlices(u8, e.data, a.data);
        },
        .CONNECTION_CLOSE => |e| {
            const a = actual.CONNECTION_CLOSE;
            try std.testing.expectEqual(e.error_code, a.error_code);
            try std.testing.expectEqual(e.reason_len, a.reason_len);
            try std.testing.expectEqualSlices(u8, e.reason, a.reason);
        },
        .PATH_CHALLENGE => |e| {
            try std.testing.expect(actual == .PATH_CHALLENGE);
            try std.testing.expectEqualSlices(u8, &e, &actual.PATH_CHALLENGE);
        },
        .PATH_RESPONSE => |e| {
            try std.testing.expect(actual == .PATH_RESPONSE);
            try std.testing.expectEqualSlices(u8, &e, &actual.PATH_RESPONSE);
        },
        .HANDSHAKE_DONE => try std.testing.expect(actual == .HANDSHAKE_DONE),
        .MAX_DATA => |e| {
            try std.testing.expect(actual == .MAX_DATA);
            try std.testing.expectEqual(e, actual.MAX_DATA);
        },
        .MAX_STREAM_DATA => |e| {
            try std.testing.expect(actual == .MAX_STREAM_DATA);
            try std.testing.expectEqual(e.stream_id, actual.MAX_STREAM_DATA.stream_id);
            try std.testing.expectEqual(e.limit, actual.MAX_STREAM_DATA.limit);
        },
        .OTHER => |e| {
            const a = actual.OTHER;
            try std.testing.expectEqual(e.frame_type, a.frame_type);
            try std.testing.expectEqual(e.ack_eliciting, a.ack_eliciting);
        },
    }
}

test "varint round-trip for all four lengths" {
    const cases = [_]struct {
        value: u64,
        len: usize,
    }{
        .{ .value = 37, .len = 1 },
        .{ .value = 15293, .len = 2 },
        .{ .value = 494878333, .len = 4 },
        .{ .value = 151288809941952652, .len = 8 },
    };

    for (cases) |case| {
        var buf: [8]u8 = undefined;
        const encoded_len = try encodeVarInt(case.value, &buf);
        try std.testing.expectEqual(case.len, encoded_len);
        const decoded = try decodeVarInt(buf[0..encoded_len]);
        try std.testing.expectEqual(case.value, decoded.value);
        try std.testing.expectEqual(case.len, decoded.len);
    }
}

test "varint rejects non-minimal encodings" {
    try std.testing.expectError(WireError.NonCanonicalVarInt, decodeVarInt(&.{ 0x40, 0x25 }));
    try std.testing.expectError(WireError.NonCanonicalVarInt, decodeVarInt(&.{ 0x80, 0x00, 0x3f, 0xff }));
    try std.testing.expectError(WireError.NonCanonicalVarInt, decodeVarInt(&.{ 0xc0, 0x00, 0x00, 0x00, 0x3f, 0xff, 0xff, 0xff }));
}

test "padding frame round-trip" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .PADDING = {} };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    var decoded = try decodeFrames(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), decoded.frames.len);
    try expectFrameEqual(frame, decoded.frames[0]);
}

test "ping frame round-trip" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .PING = {} };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "ack frame round-trip" {
    const allocator = std.testing.allocator;
    const ranges = [_]AckRange{
        .{ .gap = 0, .len = 3 },
        .{ .gap = 2, .len = 7 },
    };
    const frame = Frame{ .ACK = .{
        .largest = 100,
        .delay = 25,
        .first_range = 8,
        .ranges = &ranges,
    } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "crypto frame round-trip" {
    const allocator = std.testing.allocator;
    const data = "crypto bytes";
    const frame = Frame{ .CRYPTO = .{ .offset = 64, .len = data.len, .data = data } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
    try std.testing.expect(@intFromPtr(decoded.CRYPTO.data.ptr) >= @intFromPtr(encoded.ptr));
}

test "stream frame round-trip" {
    const allocator = std.testing.allocator;
    const data = "stream payload";
    const frame = Frame{ .STREAM = .{
        .stream_id = 9,
        .offset = 1024,
        .fin = true,
        .len = data.len,
        .data = data,
    } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "datagram frame round-trip" {
    const allocator = std.testing.allocator;
    const data = "datagram payload";
    const frame = Frame{ .DATAGRAM = .{ .len = data.len, .data = data } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "connection close frame round-trip" {
    const allocator = std.testing.allocator;
    const reason = "done";
    const frame = Frame{ .CONNECTION_CLOSE = .{
        .error_code = 0x10,
        .reason_len = reason.len,
        .reason = reason,
    } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "path challenge frame round-trip" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .PATH_CHALLENGE = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    // Wire shape: type byte 0x1a then exactly 8 opaque bytes.
    try std.testing.expectEqual(@as(usize, 9), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x1a), encoded[0]);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "path response frame round-trip" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .PATH_RESPONSE = .{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 9), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x1b), encoded[0]);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "path frames echo: a response carries the challenge bytes verbatim" {
    const allocator = std.testing.allocator;
    const challenge = Frame{ .PATH_CHALLENGE = .{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 } };
    const enc = try encodeFrames(allocator, &.{challenge});
    defer allocator.free(enc);
    const dec = try decodeFrameExact(allocator, enc);
    defer freeFrame(allocator, dec);

    // The receiver echoes the exact data in a PATH_RESPONSE.
    const response = Frame{ .PATH_RESPONSE = dec.PATH_CHALLENGE };
    try std.testing.expectEqualSlices(u8, &challenge.PATH_CHALLENGE, &response.PATH_RESPONSE);
}

test "path challenge decode rejects a truncated value" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(WireError.BufferTooShort, decodeFrame(allocator, &.{ 0x1a, 0x00, 0x01, 0x02 }));
    try std.testing.expectError(WireError.BufferTooShort, decodeFrame(allocator, &.{0x1b}));
}

test "multi-frame payload round-trip" {
    const allocator = std.testing.allocator;
    const crypto_data = "hello";
    const stream_data = "world";
    const frames = [_]Frame{
        .{ .PADDING = {} },
        .{ .PING = {} },
        .{ .CRYPTO = .{ .offset = 0, .len = crypto_data.len, .data = crypto_data } },
        .{ .STREAM = .{ .stream_id = 1, .offset = 0, .fin = false, .len = stream_data.len, .data = stream_data } },
    };
    const encoded = try encodeFrames(allocator, &frames);
    defer allocator.free(encoded);

    var decoded = try decodeFrames(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(frames.len, decoded.frames.len);
    for (frames, decoded.frames) |expected, actual| try expectFrameEqual(expected, actual);
}

test "decode rejects truncation and trailing bytes" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(WireError.BufferTooShort, decodeFrame(allocator, &.{0x06}));
    try std.testing.expectError(WireError.BufferTooShort, decodeFrame(allocator, &.{ 0x31, 0x05, 0xaa }));
    try std.testing.expectError(WireError.TrailingBytes, decodeFrameExact(allocator, &.{ 0x01, 0x00 }));
}

test "packet number truncation encoding and reconstruction" {
    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), try packetNumberLen(0xabe8bc, 0xabe700));
    try std.testing.expectEqual(@as(u64, 0xe8bc), try truncatePacketNumber(0xabe8bc, 2));
    try std.testing.expectEqual(@as(usize, 2), try encodePacketNumber(0xabe8bc, 2, &buf));
    try std.testing.expectEqualSlices(u8, &.{ 0xe8, 0xbc }, buf[0..2]);
    try std.testing.expectEqual(@as(u64, 0xabe8bc), try decodePacketNumber(0xe8bc, 2, 0xabe700));
    try std.testing.expectError(WireError.InvalidPacketNumberLength, encodePacketNumber(1, 0, &buf));
}
