// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Kind = enum(u8) {
    nack = 1,
    keyframe_request = 2,
    receiver_report = 3,
    _,
};

pub const Error = error{
    Truncated,
    BadKind,
    BadMagic,
    BadVersion,
    BadTag,
    BufferTooSmall,
    TooMany,
};

pub const ReceiverReport = struct {
    stream_id: u32,
    fraction_lost: u8,
    cumulative_lost: u32,
    jitter: u32,
    highest_seq: u32,
};

pub const Message = union(Kind) {
    nack: struct {
        stream_id: u32,
        seqs: []const u32,
    },
    keyframe_request: struct {
        stream_id: u32,
    },
    receiver_report: ReceiverReport,
};

const nack_header_len = 1 + 4 + 2;
const keyframe_request_len = 1 + 4;
const receiver_report_len = 1 + 4 + 1 + 4 + 4 + 4;
pub const envelope_magic = [_]u8{ 'O', 'N', 'F', 'B' };
pub const envelope_version: u8 = 1;
pub const envelope_header_len = envelope_magic.len + 1 + 4 + 2;
pub const envelope_tag_len = 16;
pub const envelope_key_len = 32;

pub const Envelope = struct {
    sender_stream_id: u32,
    payload: []const u8,
};

pub fn isEnvelope(bytes: []const u8) bool {
    return bytes.len >= envelope_magic.len and std.mem.eql(u8, bytes[0..envelope_magic.len], &envelope_magic);
}

pub fn encodeNack(stream_id: u32, seqs: []const u32, out: []u8) Error![]const u8 {
    if (seqs.len > std.math.maxInt(u16)) return Error.TooMany;

    const needed = nack_header_len + seqs.len * 4;
    if (out.len < needed) return Error.BufferTooSmall;

    out[0] = @backingInt(Kind.nack);
    std.mem.writeInt(u32, out[1..][0..4], stream_id, .big);
    std.mem.writeInt(u16, out[5..][0..2], @intCast(seqs.len), .big);

    var pos: usize = nack_header_len;
    for (seqs) |seq| {
        std.mem.writeInt(u32, out[pos..][0..4], seq, .big);
        pos += 4;
    }

    return out[0..needed];
}

pub fn encodeKeyframeRequest(stream_id: u32, out: []u8) Error![]const u8 {
    if (out.len < keyframe_request_len) return Error.BufferTooSmall;

    out[0] = @backingInt(Kind.keyframe_request);
    std.mem.writeInt(u32, out[1..][0..4], stream_id, .big);

    return out[0..keyframe_request_len];
}

pub fn encodeReceiverReport(rr: ReceiverReport, out: []u8) Error![]const u8 {
    if (out.len < receiver_report_len) return Error.BufferTooSmall;

    out[0] = @backingInt(Kind.receiver_report);
    std.mem.writeInt(u32, out[1..][0..4], rr.stream_id, .big);
    out[5] = rr.fraction_lost;
    std.mem.writeInt(u32, out[6..][0..4], rr.cumulative_lost, .big);
    std.mem.writeInt(u32, out[10..][0..4], rr.jitter, .big);
    std.mem.writeInt(u32, out[14..][0..4], rr.highest_seq, .big);

    return out[0..receiver_report_len];
}

pub fn parse(bytes: []const u8, seq_out: []u32) Error!Message {
    if (bytes.len < 1) return Error.Truncated;

    const kind: Kind = switch (bytes[0]) {
        @backingInt(Kind.nack) => .nack,
        @backingInt(Kind.keyframe_request) => .keyframe_request,
        @backingInt(Kind.receiver_report) => .receiver_report,
        else => return Error.BadKind,
    };

    return switch (kind) {
        .nack => parseNack(bytes, seq_out),
        .keyframe_request => parseKeyframeRequest(bytes),
        .receiver_report => parseReceiverReport(bytes),
        _ => Error.BadKind,
    };
}

pub fn peekEnvelope(bytes: []const u8) Error!Envelope {
    if (bytes.len < envelope_header_len + envelope_tag_len) return Error.Truncated;
    if (!std.mem.eql(u8, bytes[0..envelope_magic.len], &envelope_magic)) return Error.BadMagic;
    if (bytes[envelope_magic.len] != envelope_version) return Error.BadVersion;

    const sender_off = envelope_magic.len + 1;
    const sender_stream_id = std.mem.readInt(u32, bytes[sender_off..][0..4], .big);
    const len_off = sender_off + 4;
    const payload_len = std.mem.readInt(u16, bytes[len_off..][0..2], .big);
    const total = envelope_header_len + @as(usize, payload_len) + envelope_tag_len;
    if (bytes.len < total) return Error.Truncated;
    if (bytes.len != total) return Error.Truncated;
    return .{
        .sender_stream_id = sender_stream_id,
        .payload = bytes[envelope_header_len .. envelope_header_len + payload_len],
    };
}

fn tag(key: *const [envelope_key_len]u8, authenticated: []const u8) [envelope_tag_len]u8 {
    var mac = HmacSha256.init(key);
    mac.update(authenticated);
    var full: [HmacSha256.mac_length]u8 = undefined;
    mac.final(&full);
    var out: [envelope_tag_len]u8 = undefined;
    @memcpy(out[0..], full[0..envelope_tag_len]);
    return out;
}

fn constantTimeTagEql(a: []const u8, b: []const u8) bool {
    const len_diff = a.len ^ b.len;
    const n = @min(a.len, b.len);
    var folded = len_diff;
    folded |= folded >> 32;
    folded |= folded >> 16;
    folded |= folded >> 8;
    var diff: u8 = @truncate(folded);
    var i: usize = 0;
    while (i < n) : (i += 1) diff |= a[i] ^ b[i];
    return diff == 0;
}

pub fn encodeEnvelope(sender_stream_id: u32, payload: []const u8, key: *const [envelope_key_len]u8, out: []u8) Error![]const u8 {
    if (payload.len > std.math.maxInt(u16)) return Error.TooMany;
    const total = envelope_header_len + payload.len + envelope_tag_len;
    if (out.len < total) return Error.BufferTooSmall;

    @memcpy(out[0..envelope_magic.len], &envelope_magic);
    out[envelope_magic.len] = envelope_version;
    const sender_off = envelope_magic.len + 1;
    std.mem.writeInt(u32, out[sender_off..][0..4], sender_stream_id, .big);
    const len_off = sender_off + 4;
    std.mem.writeInt(u16, out[len_off..][0..2], @intCast(payload.len), .big);
    @memcpy(out[envelope_header_len..][0..payload.len], payload);

    const mac = tag(key, out[0 .. envelope_header_len + payload.len]);
    @memcpy(out[envelope_header_len + payload.len .. total], mac[0..]);
    return out[0..total];
}

pub fn openEnvelope(bytes: []const u8, key: *const [envelope_key_len]u8) Error!Envelope {
    const env = try peekEnvelope(bytes);
    const auth_len = envelope_header_len + env.payload.len;
    const got = bytes[auth_len..][0..envelope_tag_len];
    const expected = tag(key, bytes[0..auth_len]);
    if (!constantTimeTagEql(expected[0..], got)) return Error.BadTag;
    return env;
}

fn parseNack(bytes: []const u8, seq_out: []u32) Error!Message {
    if (bytes.len < nack_header_len) return Error.Truncated;

    const stream_id = std.mem.readInt(u32, bytes[1..][0..4], .big);
    const count = std.mem.readInt(u16, bytes[5..][0..2], .big);
    const needed = nack_header_len + @as(usize, count) * 4;
    if (bytes.len < needed) return Error.Truncated;
    if (seq_out.len < count) return Error.TooMany;

    var pos: usize = nack_header_len;
    for (seq_out[0..count]) |*seq| {
        seq.* = std.mem.readInt(u32, bytes[pos..][0..4], .big);
        pos += 4;
    }

    return .{
        .nack = .{
            .stream_id = stream_id,
            .seqs = seq_out[0..count],
        },
    };
}

fn parseKeyframeRequest(bytes: []const u8) Error!Message {
    if (bytes.len < keyframe_request_len) return Error.Truncated;

    return .{
        .keyframe_request = .{
            .stream_id = std.mem.readInt(u32, bytes[1..][0..4], .big),
        },
    };
}

fn parseReceiverReport(bytes: []const u8) Error!Message {
    if (bytes.len < receiver_report_len) return Error.Truncated;

    return .{
        .receiver_report = .{
            .stream_id = std.mem.readInt(u32, bytes[1..][0..4], .big),
            .fraction_lost = bytes[5],
            .cumulative_lost = std.mem.readInt(u32, bytes[6..][0..4], .big),
            .jitter = std.mem.readInt(u32, bytes[10..][0..4], .big),
            .highest_seq = std.mem.readInt(u32, bytes[14..][0..4], .big),
        },
    };
}

test "nack with 3 seqs round-trips" {
    const testing = std.testing;

    const seqs = [_]u32{ 7, 42, 0xfeed_beef };
    var out: [64]u8 = undefined;
    const encoded = try encodeNack(0x0102_0304, &seqs, &out);

    try testing.expectEqual(@as(usize, 19), encoded.len);
    try testing.expectEqual(@backingInt(Kind.nack), encoded[0]);

    var parsed_seqs: [3]u32 = undefined;
    const msg = try parse(encoded, &parsed_seqs);

    switch (msg) {
        .nack => |nack| {
            try testing.expectEqual(@as(u32, 0x0102_0304), nack.stream_id);
            try testing.expectEqualSlices(u32, &seqs, nack.seqs);
        },
        else => return error.WrongMessage,
    }
}

test "keyframe_request round-trips" {
    const testing = std.testing;

    var out: [8]u8 = undefined;
    const encoded = try encodeKeyframeRequest(0x1122_3344, &out);

    try testing.expectEqual(@as(usize, 5), encoded.len);

    var parsed_seqs: [1]u32 = undefined;
    const msg = try parse(encoded, &parsed_seqs);

    switch (msg) {
        .keyframe_request => |keyframe_request| {
            try testing.expectEqual(@as(u32, 0x1122_3344), keyframe_request.stream_id);
        },
        else => return error.WrongMessage,
    }
}

test "receiver_report all fields round-trip" {
    const testing = std.testing;

    const rr = ReceiverReport{
        .stream_id = 0x0102_0304,
        .fraction_lost = 19,
        .cumulative_lost = 0x0001_0203,
        .jitter = 0x1020_3040,
        .highest_seq = 0xa0b0_c0d0,
    };
    var out: [32]u8 = undefined;
    const encoded = try encodeReceiverReport(rr, &out);

    try testing.expectEqual(@as(usize, 18), encoded.len);

    var parsed_seqs: [1]u32 = undefined;
    const msg = try parse(encoded, &parsed_seqs);

    switch (msg) {
        .receiver_report => |parsed| {
            try testing.expectEqual(rr.stream_id, parsed.stream_id);
            try testing.expectEqual(rr.fraction_lost, parsed.fraction_lost);
            try testing.expectEqual(rr.cumulative_lost, parsed.cumulative_lost);
            try testing.expectEqual(rr.jitter, parsed.jitter);
            try testing.expectEqual(rr.highest_seq, parsed.highest_seq);
        },
        else => return error.WrongMessage,
    }
}

test "authenticated envelope carries feedback payload and sender stream" {
    const key = @as([envelope_key_len]u8, @splat(0x44));
    var payload_buf: [32]u8 = undefined;
    const payload = try encodeKeyframeRequest(0xAABB_CCDD, &payload_buf);

    var env_buf: [64]u8 = undefined;
    const encoded = try encodeEnvelope(0x0102_0304, payload, &key, &env_buf);
    const peeked = try peekEnvelope(encoded);
    try std.testing.expectEqual(@as(u32, 0x0102_0304), peeked.sender_stream_id);
    try std.testing.expectEqualSlices(u8, payload, peeked.payload);

    const opened = try openEnvelope(encoded, &key);
    try std.testing.expectEqual(@as(u32, 0x0102_0304), opened.sender_stream_id);
    try std.testing.expectEqualSlices(u8, payload, opened.payload);
}

test "authenticated envelope rejects tampered payload or wrong key" {
    const key = @as([envelope_key_len]u8, @splat(0x44));
    const wrong_key = @as([envelope_key_len]u8, @splat(0x45));
    var payload_buf: [32]u8 = undefined;
    const payload = try encodeKeyframeRequest(7, &payload_buf);

    var env_buf: [64]u8 = undefined;
    const encoded = try encodeEnvelope(1, payload, &key, &env_buf);
    try std.testing.expectError(Error.BadTag, openEnvelope(encoded, &wrong_key));

    env_buf[envelope_header_len] ^= 0x01;
    try std.testing.expectError(Error.BadTag, openEnvelope(encoded, &key));
}

test "BadKind on unknown first byte" {
    var seq_out: [1]u32 = undefined;
    try std.testing.expectError(Error.BadKind, parse(&[_]u8{99}, &seq_out));
}

test "Truncated on cut" {
    var out: [64]u8 = undefined;
    const encoded = try encodeReceiverReport(.{
        .stream_id = 1,
        .fraction_lost = 2,
        .cumulative_lost = 3,
        .jitter = 4,
        .highest_seq = 5,
    }, &out);

    var seq_out: [1]u32 = undefined;
    try std.testing.expectError(Error.Truncated, parse(encoded[0 .. encoded.len - 1], &seq_out));
}

test "TooMany when seq_out small" {
    const seqs = [_]u32{ 10, 11, 12 };
    var out: [64]u8 = undefined;
    const encoded = try encodeNack(9, &seqs, &out);

    var parsed_seqs: [2]u32 = undefined;
    try std.testing.expectError(Error.TooMany, parse(encoded, &parsed_seqs));
}
