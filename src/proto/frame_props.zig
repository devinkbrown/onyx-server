// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for the UNDERTOW frame layer.
const std = @import("std");
const frame = @import("frame.zig");

const max_wire_len = frame.header_len + frame.max_payload_len;
const seed: u64 = 0x511d_a06d_17c0_de;

fn expectTypedDecodeError(err: frame.DecodeError) !void {
    switch (err) {
        error.Truncated,
        error.VarintTooLong,
        error.VarintOverflow,
        error.NonCanonicalVarint,
        error.LengthTooLarge,
        error.InvalidBool,
        error.PayloadTooLarge,
        error.HopExpired,
        error.UnknownRequiredType,
        error.TrailingBytes,
        => {},
    }
}

fn expectPayloadWithinInput(input: []const u8, decoded: frame.Frame) !void {
    try std.testing.expect(input.len >= frame.header_len);
    try std.testing.expect(decoded.payload.len <= frame.max_payload_len);
    try std.testing.expectEqual(input.len - frame.header_len, decoded.payload.len);

    const input_start = @intFromPtr(input.ptr);
    const input_end = input_start + input.len;
    const payload_start = @intFromPtr(decoded.payload.ptr);
    const payload_end = payload_start + decoded.payload.len;

    try std.testing.expect(payload_start >= input_start);
    try std.testing.expect(payload_end <= input_end);
}

fn expectFrameEqual(expected: frame.Frame, actual: frame.Frame) !void {
    try std.testing.expectEqual(expected.type.byte(), actual.type.byte());
    try std.testing.expectEqual(expected.ctrl.toByte(), actual.ctrl.toByte());
    try std.testing.expectEqual(expected.stream_id, actual.stream_id);
    try std.testing.expectEqual(expected.hop, actual.hop);
    try std.testing.expectEqualSlices(u8, expected.payload, actual.payload);
}

fn decodeOkOrTypedError(input: []const u8) !void {
    const decoded = frame.Frame.decode(input) catch |err| {
        try expectTypedDecodeError(err);
        return;
    };

    try std.testing.expect(decoded.hop != 0);
    try expectPayloadWithinInput(input, decoded);
}

fn variedLen(random: std.Random, iteration: usize, comptime max_len: usize) usize {
    return switch (iteration % 23) {
        0 => 0,
        1 => 1,
        2 => @min(frame.header_len - 1, max_len),
        3 => @min(frame.header_len, max_len),
        4 => @min(frame.header_len + 1, max_len),
        5 => @min(127, max_len),
        6 => @min(128, max_len),
        7 => @min(1024, max_len),
        8 => max_len,
        else => random.intRangeAtMost(usize, 0, @min(max_len, 4096)),
    };
}

fn addInterestingBytes(buf: []u8, iteration: usize) void {
    const interesting = [_]u8{
        0x00, 0x01, 0x7f, 0x80, 0xc0, 0xe2, 0xff,
        '\r', '\n', ' ',  ':',  ';',  '@',  0x2c,
    };
    for (interesting, 0..) |byte, i| {
        if (buf.len == 0) break;
        const pos = (iteration * 31 + i * 17) % buf.len;
        buf[pos] = byte;
    }
}

fn randomFrameType(random: std.Random, iteration: usize) frame.FrameType {
    const types = [_]u8{
        @backingInt(frame.FrameType.ping),
        @backingInt(frame.FrameType.privmsg),
        @backingInt(frame.FrameType.irc_line),
        @backingInt(frame.FrameType.concord_delta),
        @backingInt(frame.FrameType.cap_grant),
        @backingInt(frame.FrameType.mooring_ratchet),
        @backingInt(frame.FrameType.voice_data),
        0x1f,
        0x8c,
        0xd1,
    };
    return frame.FrameType.fromByte(types[(iteration + random.int(usize)) % types.len]);
}

fn randomCtrl(random: std.Random) frame.Ctrl {
    return frame.Ctrl.init(
        random.int(u4),
        @fromBackingInt(@intCast(random.int(u3))),
        random.boolean(),
    );
}

fn randomPayloadLen(random: std.Random, iteration: usize) usize {
    return switch (iteration % 29) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 127,
        4 => 128,
        5 => 1024,
        6 => frame.max_payload_len,
        else => random.intRangeAtMost(usize, 0, 2048),
    };
}

fn assertCreditInvariants(window: frame.CreditWindow) !void {
    try std.testing.expect(window.remote_available <= std.math.maxInt(u32));
    try std.testing.expect(window.local_available <= std.math.maxInt(u32));
    try std.testing.expect(window.pending_grant <= std.math.maxInt(u32));
}

test "deframer accepts or returns typed errors for arbitrary byte streams" {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var input: [max_wire_len + 1]u8 = undefined;
    var i: usize = 0;
    while (i < 1600) : (i += 1) {
        const len = if (i % 31 == 0)
            max_wire_len + 1
        else
            variedLen(random, i, max_wire_len);

        random.bytes(input[0..len]);
        addInterestingBytes(input[0..len], i);
        try decodeOkOrTypedError(input[0..len]);
    }
}

test "deframer handles structured corrupt frames without crashing" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xa11c_e5);
    const random = prng.random();

    var payload: [256]u8 = undefined;
    random.bytes(&payload);

    var encoded: [frame.header_len + payload.len + 16]u8 = undefined;
    const written = try (frame.Frame{
        .type = .privmsg,
        .ctrl = frame.Ctrl.init(frame.CtrlFlag.fin, .high, false),
        .stream_id = 0x00babe,
        .hop = 5,
        .payload = &payload,
    }).encode(&encoded);

    var prefix_len: usize = 0;
    while (prefix_len < written) : (prefix_len += 1) {
        try decodeOkOrTypedError(encoded[0..prefix_len]);
    }

    var trailing = encoded;
    random.bytes(trailing[written .. written + 16]);
    try decodeOkOrTypedError(trailing[0 .. written + 16]);

    var hop_zero = encoded;
    hop_zero[frame.header_len - 1] = 0;
    try decodeOkOrTypedError(hop_zero[0..written]);

    var unknown_required = encoded;
    unknown_required[0] = 0xfe;
    try decodeOkOrTypedError(unknown_required[0..written]);

    var declared_too_long = encoded;
    declared_too_long[2] = 0xff;
    declared_too_long[3] = 0xff;
    try decodeOkOrTypedError(declared_too_long[0..written]);
}

test "frame encode decode round trips random payloads canonically" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x70ad_7a1c);
    const random = prng.random();

    var payload: [frame.max_payload_len + 1]u8 = undefined;
    var encoded: [max_wire_len]u8 = undefined;
    var canonical: [max_wire_len]u8 = undefined;

    var i: usize = 0;
    while (i < 450) : (i += 1) {
        const payload_len = randomPayloadLen(random, i);
        random.bytes(payload[0..payload_len]);

        const original = frame.Frame{
            .type = randomFrameType(random, i),
            .ctrl = randomCtrl(random),
            .stream_id = random.int(u24),
            .hop = random.intRangeAtMost(u8, 1, std.math.maxInt(u8)),
            .payload = payload[0..payload_len],
        };

        const written = try original.encode(&encoded);
        try std.testing.expectEqual(frame.header_len + payload_len, written);

        const decoded = try frame.Frame.decode(encoded[0..written]);
        try expectFrameEqual(original, decoded);
        try expectPayloadWithinInput(encoded[0..written], decoded);

        const rewritten = try decoded.encode(&canonical);
        try std.testing.expectEqual(written, rewritten);
        try std.testing.expectEqualSlices(u8, encoded[0..written], canonical[0..rewritten]);
    }

    random.bytes(&payload);
    const oversize = frame.Frame{
        .type = .privmsg,
        .ctrl = frame.Ctrl.init(0, .normal, false),
        .payload = &payload,
    };
    try std.testing.expectError(error.PayloadTooLarge, oversize.encode(&encoded));
}

test "one byte fragmentation yields the same frames as whole frame decode" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xf1a6_8170);
    const random = prng.random();

    var payloads: [8][512]u8 = undefined;
    var stream: [8 * (frame.header_len + 512)]u8 = undefined;
    var starts: [8]usize = undefined;
    var ends: [8]usize = undefined;

    var stream_len: usize = 0;
    for (&payloads, 0..) |*payload, i| {
        const payload_len = random.intRangeAtMost(usize, 0, payload.len);
        random.bytes(payload[0..payload_len]);

        starts[i] = stream_len;
        const written = try (frame.Frame{
            .type = randomFrameType(random, i),
            .ctrl = randomCtrl(random),
            .stream_id = random.int(u24),
            .hop = random.intRangeAtMost(u8, 1, std.math.maxInt(u8)),
            .payload = payload[0..payload_len],
        }).encode(stream[stream_len..]);
        stream_len += written;
        ends[i] = stream_len;
    }

    var incremental: [frame.header_len + 512]u8 = undefined;
    var incremental_len: usize = 0;
    var decoded_count: usize = 0;

    var pos: usize = 0;
    while (pos < stream_len) : (pos += 1) {
        incremental[incremental_len] = stream[pos];
        incremental_len += 1;

        const maybe_frame = frame.Frame.decode(incremental[0..incremental_len]) catch |err| switch (err) {
            error.Truncated => continue,
            else => return err,
        };

        const whole = try frame.Frame.decode(stream[starts[decoded_count]..ends[decoded_count]]);
        try expectFrameEqual(whole, maybe_frame);
        decoded_count += 1;
        incremental_len = 0;
    }

    try std.testing.expectEqual(starts.len, decoded_count);
    try std.testing.expectEqual(@as(usize, 0), incremental_len);
}

test "credit flow accounting never underflows or overflows silently" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xc4ed_17);
    const random = prng.random();

    var window = frame.CreditWindow.init();
    var payload: [frame.max_payload_len + 1]u8 = undefined;
    random.bytes(&payload);

    var i: usize = 0;
    while (i < 900) : (i += 1) {
        const payload_len = randomPayloadLen(random, i) + @as(usize, if (i % 113 == 0) 1 else 0);
        const frame_type: frame.FrameType = switch (i % 9) {
            0 => .ping,
            1 => .mooring_ratchet,
            else => randomFrameType(random, i),
        };
        const candidate = frame.Frame{
            .type = frame_type,
            .ctrl = randomCtrl(random),
            .stream_id = random.int(u24),
            .hop = random.intRangeAtMost(u8, 1, std.math.maxInt(u8)),
            .payload = payload[0..payload_len],
        };
        const cost = frame.creditCost(candidate);
        try std.testing.expect(cost <= frame.header_len + frame.max_payload_len);

        switch (i % 4) {
            0 => {
                const before = window.remote_available;
                if (cost > before) {
                    try std.testing.expectError(error.InsufficientCredit, window.debitSend(candidate));
                    try std.testing.expectEqual(before, window.remote_available);
                } else {
                    try window.debitSend(candidate);
                    try std.testing.expectEqual(before - cost, window.remote_available);
                }
            },
            1 => {
                const before = window.remote_available;
                const grant: u32 = if (i % 37 == 0) std.math.maxInt(u32) else random.int(u20);
                if (@as(u64, before) + grant > std.math.maxInt(u32)) {
                    try std.testing.expectError(error.CreditOverflow, window.applyCredit(grant));
                    try std.testing.expectEqual(before, window.remote_available);
                } else {
                    try window.applyCredit(grant);
                    try std.testing.expectEqual(before + grant, window.remote_available);
                }
            },
            2 => {
                const before_local = window.local_available;
                const before_pending = window.pending_grant;
                if (cost > before_local) {
                    try std.testing.expectError(error.InsufficientCredit, window.debitReceive(candidate));
                    try std.testing.expectEqual(before_local, window.local_available);
                    try std.testing.expectEqual(before_pending, window.pending_grant);
                } else {
                    const grant = try window.debitReceive(candidate);
                    if (cost == 0) {
                        try std.testing.expectEqual(@as(?u32, null), grant);
                        try std.testing.expectEqual(before_local, window.local_available);
                        try std.testing.expectEqual(before_pending, window.pending_grant);
                    } else if (before_pending + cost >= frame.credit_grant_threshold) {
                        try std.testing.expectEqual(@as(?u32, before_pending + cost), grant);
                        try std.testing.expectEqual(before_local + before_pending, window.local_available);
                        try std.testing.expectEqual(@as(u32, 0), window.pending_grant);
                    } else {
                        try std.testing.expectEqual(@as(?u32, null), grant);
                        try std.testing.expectEqual(before_local - cost, window.local_available);
                        try std.testing.expectEqual(before_pending + cost, window.pending_grant);
                    }
                }
            },
            else => {
                const before_local = window.local_available;
                const before_pending = window.pending_grant;
                const grant = window.flushGrant();
                if (before_pending == 0) {
                    try std.testing.expectEqual(@as(?u32, null), grant);
                    try std.testing.expectEqual(before_local, window.local_available);
                } else {
                    try std.testing.expectEqual(@as(?u32, before_pending), grant);
                    try std.testing.expectEqual(before_local + before_pending, window.local_available);
                    try std.testing.expectEqual(@as(u32, 0), window.pending_grant);
                }
            },
        }

        try assertCreditInvariants(window);
    }
}
