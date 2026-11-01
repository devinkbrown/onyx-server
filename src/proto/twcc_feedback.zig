// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RTCP Transport-Wide Congestion Control feedback packet codec.
//!
//! Implements the transport-cc feedback message from
//! draft-holmer-rmcat-transport-wide-cc-extensions: an RTPFB packet
//! (PT=205) carrying FMT=15 transport feedback FCI.
//!
//! The wire layout, after the 12-byte RTCP common header
//! (V/P/FMT, PT, length, sender SSRC, media SSRC), is:
//!   - base sequence number   (u16 BE)
//!   - packet status count    (u16 BE)
//!   - reference time         (u24 BE, 64ms units)
//!   - feedback packet count  (u8)
//!   - packet status chunks   (each u16 BE: run-length if top bit 0,
//!                             status-vector if top bit 1)
//!   - recv deltas            (u8 per small delta, i16 BE per large/negative)
//!   - padding to a 32-bit boundary
//!
//! This module is allocation-free for parsing (see `StatusIterator`) and
//! builds packets into a caller-supplied buffer.
//!
//! In the in-tree build (module rooted at `src/root.zig`) this file shares the
//! `Status` enum and unit constants with `substrate/twcc.zig`; switch the alias
//! below to `@import("../substrate/twcc.zig")` to use that single definition.
//! The mirrored definitions here are byte-identical (Status is the same u2
//! enum, deltas are 250us, reference time is 64ms) so the FCI wire format and
//! `Status` discriminants round-trip with the substrate codec, while keeping
//! this file independently testable via `zig test src/proto/twcc_feedback.zig`.

const std = @import("std");

/// 12-byte RTCP common header + 8 bytes of transport-cc fixed FCI fields
/// (base seq, status count, reference time, fb pkt count).
pub const header_len: usize = 20;

/// Per-packet status symbol. Discriminants match the transport-cc wire
/// encoding and `substrate/twcc.zig`'s `Status` (u2).
pub const Status = enum(u2) {
    not_received = 0,
    small_delta = 1,
    large_delta = 2,
    reserved = 3,

    pub fn isReceived(self: Status) bool {
        return self == .small_delta or self == .large_delta;
    }
};

/// Recv-delta quantization unit (microseconds per tick).
pub const delta_unit_us: i64 = 250;
/// Reference-time unit (microseconds per tick).
pub const reference_time_unit_us: i64 = 64_000;

const payload_type: u8 = 205; // RTPFB
const feedback_format: u5 = 15; // transport-cc FMT
const max_run_length: u16 = (1 << 13) - 1;

pub const Error = error{
    Truncated,
    BadFormat,
    TooMany,
    BufferTooSmall,
};

/// Decoded fixed header / FCI fields of a transport-cc feedback packet.
pub const Packet = struct {
    sender_ssrc: u32,
    media_ssrc: u32,
    base_seq: u16,
    packet_status_count: u16,
    reference_time: u24,
    fb_pkt_count: u8,

    pub fn referenceTimeUs(self: Packet) i64 {
        return @as(i64, self.reference_time) * reference_time_unit_us;
    }
};

/// One decoded per-packet feedback element produced by `StatusIterator`.
pub const Item = struct {
    seq: u16,
    status: Status,
    /// Arrival delta relative to the previous received packet, in
    /// microseconds (quantized to 250us). Null for not-received packets.
    delta_us: ?i64,
};

// -- builder ---------------------------------------------------------------

/// Encode a transport-cc feedback packet into `out`.
///
/// `statuses` holds one `Status` per covered sequence number starting at
/// `base_seq`. `deltas_us` supplies an arrival delta (microseconds, relative
/// to the previous received packet) for each received packet, consumed in
/// order: a `.small_delta` or `.large_delta` status takes the next value;
/// `.not_received` (and `.reserved`) consume nothing.
///
/// Small deltas must quantize into [0, 255] ticks of 250us; large deltas into
/// an i16 tick range, otherwise `BadFormat` is returned. Returns the written
/// RTCP packet (a sub-slice of `out`).
pub fn build(
    sender_ssrc: u32,
    media_ssrc: u32,
    base_seq: u16,
    reference_time: u24,
    fb_pkt_count: u8,
    statuses: []const Status,
    deltas_us: []const i64,
    out: []u8,
) Error![]const u8 {
    if (statuses.len == 0) return Error.BadFormat;
    if (statuses.len > std.math.maxInt(u16)) return Error.TooMany;

    // Validate status symbols and that we have enough deltas up front.
    var needed_deltas: usize = 0;
    for (statuses) |s| {
        switch (s) {
            .reserved => return Error.BadFormat,
            .small_delta, .large_delta => needed_deltas += 1,
            .not_received => {},
        }
    }
    if (needed_deltas > deltas_us.len) return Error.BadFormat;

    if (out.len < header_len) return Error.BufferTooSmall;

    // -- fixed header / FCI fields (written after chunks/deltas so we can
    //    backfill the RTCP length word) --
    var pos: usize = header_len;

    // Chunk encoding: walk statuses, prefer run-length for long same-symbol
    // runs, otherwise pack a two-bit status vector covering 7 packets.
    var idx: usize = 0;
    while (idx < statuses.len) {
        const run = sameRun(statuses[idx..]);
        if (run >= 7 or idx + run == statuses.len) {
            const emit: u16 = @intCast(@min(run, max_run_length));
            try writeChunk(out, &pos, runLengthChunk(statuses[idx], emit));
            idx += emit;
            continue;
        }
        const span: usize = @min(@as(usize, 7), statuses.len - idx);
        try writeChunk(out, &pos, twoBitVectorChunk(statuses[idx .. idx + span]));
        idx += span;
    }

    // -- recv deltas --
    var di: usize = 0;
    for (statuses) |s| {
        switch (s) {
            .small_delta => {
                const ticks = try quantize(deltas_us[di]);
                di += 1;
                if (ticks < 0 or ticks > std.math.maxInt(u8)) return Error.BadFormat;
                if (pos + 1 > out.len) return Error.BufferTooSmall;
                out[pos] = @intCast(ticks);
                pos += 1;
            },
            .large_delta => {
                const ticks = try quantize(deltas_us[di]);
                di += 1;
                if (ticks < std.math.minInt(i16) or ticks > std.math.maxInt(i16)) {
                    return Error.BadFormat;
                }
                if (pos + 2 > out.len) return Error.BufferTooSmall;
                std.mem.writeInt(i16, out[pos..][0..2], @intCast(ticks), .big);
                pos += 2;
            },
            .not_received, .reserved => {},
        }
    }

    // -- pad to 32-bit boundary --
    while (pos % 4 != 0) {
        if (pos + 1 > out.len) return Error.BufferTooSmall;
        out[pos] = 0;
        pos += 1;
    }

    // -- backfill the fixed header now that the total length is known --
    const length_words = pos / 4;
    if (length_words == 0 or length_words - 1 > std.math.maxInt(u16)) return Error.BadFormat;

    out[0] = 0x80 | @as(u8, feedback_format); // V=2, P=0, FMT=15
    out[1] = payload_type; // 205
    std.mem.writeInt(u16, out[2..4], @intCast(length_words - 1), .big);
    std.mem.writeInt(u32, out[4..8], sender_ssrc, .big);
    std.mem.writeInt(u32, out[8..12], media_ssrc, .big);
    std.mem.writeInt(u16, out[12..14], base_seq, .big);
    std.mem.writeInt(u16, out[14..16], @intCast(statuses.len), .big);
    writeU24(out[16..19], reference_time);
    out[19] = fb_pkt_count;

    return out[0..pos];
}

fn writeChunk(out: []u8, pos: *usize, chunk: u16) Error!void {
    if (pos.* + 2 > out.len) return Error.BufferTooSmall;
    std.mem.writeInt(u16, out[pos.*..][0..2], chunk, .big);
    pos.* += 2;
}

fn runLengthChunk(status: Status, run_length: u16) u16 {
    // top bit 0 => run length; bits 14..13 = symbol; bits 12..0 = length
    return (@as(u16, @backingInt(status)) << 13) | (run_length & max_run_length);
}

fn twoBitVectorChunk(statuses: []const Status) u16 {
    // top two bits 11 => two-bit status vector, 7 symbols of 2 bits each.
    var chunk: u16 = 0xc000;
    for (statuses, 0..) |s, i| {
        const shift: u4 = @intCast(12 - i * 2);
        chunk |= @as(u16, @backingInt(s)) << shift;
    }
    return chunk;
}

fn sameRun(statuses: []const Status) usize {
    const status = statuses[0];
    var len: usize = 1;
    while (len < statuses.len and len < max_run_length and statuses[len] == status) {
        len += 1;
    }
    return len;
}

fn quantize(delta_us: i64) Error!i64 {
    return @divTrunc(delta_us, delta_unit_us);
}

fn writeU24(out: []u8, value: u24) void {
    out[0] = @intCast((value >> 16) & 0xff);
    out[1] = @intCast((value >> 8) & 0xff);
    out[2] = @intCast(value & 0xff);
}

fn readU24(data: []const u8) u24 {
    return (@as(u24, data[0]) << 16) | (@as(u24, data[1]) << 8) | data[2];
}

// -- parser ----------------------------------------------------------------

/// Parse the fixed header / FCI fields of a transport-cc feedback packet.
/// Validates version/format/PT and that the advertised length fits.
pub fn parse(bytes: []const u8) Error!Packet {
    if (bytes.len < header_len) return Error.Truncated;

    const b0 = bytes[0];
    if (b0 >> 6 != 2) return Error.BadFormat; // version must be 2
    if (b0 & 0x20 != 0) return Error.BadFormat; // padding not handled here
    if (b0 & 0x1f != feedback_format) return Error.BadFormat; // FMT=15
    if (bytes[1] != payload_type) return Error.BadFormat; // PT=205

    const packet_len = (@as(usize, std.mem.readInt(u16, bytes[2..4], .big)) + 1) * 4;
    if (packet_len < header_len or packet_len > bytes.len) return Error.Truncated;

    return .{
        .sender_ssrc = std.mem.readInt(u32, bytes[4..8], .big),
        .media_ssrc = std.mem.readInt(u32, bytes[8..12], .big),
        .base_seq = std.mem.readInt(u16, bytes[12..14], .big),
        .packet_status_count = std.mem.readInt(u16, bytes[14..16], .big),
        .reference_time = readU24(bytes[16..19]),
        .fb_pkt_count = bytes[19],
    };
}

/// Allocation-free iterator over the per-packet feedback elements.
///
/// Create one with `iterate(bytes)`; call `next()` until it returns null.
/// `next()` returns `Error.Truncated`/`Error.BadFormat` if the chunk or
/// delta region is malformed.
pub const StatusIterator = struct {
    bytes: []const u8,
    packet: Packet,
    /// number of statuses emitted so far
    emitted: u16 = 0,
    /// offset of the next chunk word to decode
    chunk_off: usize,
    /// offset of the next delta byte(s) to consume
    delta_off: usize,

    // Decode state for the current run-length chunk: when `run_left > 0` the
    // iterator emits `run_status` that many more times before reading another
    // chunk. This keeps run-length decoding allocation-free regardless of run
    // length, without buffering every symbol.
    run_status: Status = .not_received,
    run_left: usize = 0,

    // Buffered symbols from the current status-vector chunk (max 14).
    pending: [14]Status = undefined,
    pending_len: u8 = 0,
    pending_idx: u8 = 0,

    pub fn next(self: *StatusIterator) Error!?Item {
        if (self.emitted >= self.packet.packet_status_count) return null;

        const status = try self.nextStatus();
        const seq = self.packet.base_seq +% self.emitted;
        self.emitted += 1;

        const delta_us: ?i64 = switch (status) {
            .small_delta => blk: {
                if (self.delta_off + 1 > self.bytes.len) return Error.Truncated;
                const ticks: i64 = self.bytes[self.delta_off];
                self.delta_off += 1;
                break :blk ticks * delta_unit_us;
            },
            .large_delta => blk: {
                if (self.delta_off + 2 > self.bytes.len) return Error.Truncated;
                const ticks: i64 = std.mem.readInt(i16, self.bytes[self.delta_off..][0..2], .big);
                self.delta_off += 2;
                break :blk ticks * delta_unit_us;
            },
            .not_received => null,
            .reserved => return Error.BadFormat,
        };

        return .{ .seq = seq, .status = status, .delta_us = delta_us };
    }

    fn nextStatus(self: *StatusIterator) Error!Status {
        // Drain an in-progress run first.
        if (self.run_left > 0) {
            self.run_left -= 1;
            return self.run_status;
        }
        // Drain buffered status-vector symbols.
        if (self.pending_idx < self.pending_len) {
            const s = self.pending[self.pending_idx];
            self.pending_idx += 1;
            return s;
        }
        // Otherwise load the next chunk.
        return self.loadChunk();
    }

    fn loadChunk(self: *StatusIterator) Error!Status {
        if (self.chunk_off + 2 > self.bytes.len) return Error.Truncated;
        const chunk = std.mem.readInt(u16, self.bytes[self.chunk_off..][0..2], .big);
        self.chunk_off += 2;

        const remaining: usize = self.packet.packet_status_count - self.emitted;
        self.pending_idx = 0;
        self.pending_len = 0;

        if (chunk & 0x8000 == 0) {
            // run-length chunk
            const status = try statusFromBits(@intCast((chunk >> 13) & 0x3));
            const run: usize = @min(@as(usize, chunk & 0x1fff), remaining);
            if (run == 0) return Error.BadFormat;
            // Emit one now; carry the rest.
            self.run_status = status;
            self.run_left = run - 1;
            return status;
        }

        if (chunk & 0x4000 == 0) {
            // one-bit status vector: 14 symbols
            const count: usize = @min(@as(usize, 14), remaining);
            var i: usize = 0;
            while (i < count) : (i += 1) {
                const shift: u4 = @intCast(13 - i);
                const bit: u2 = @intCast((chunk >> shift) & 0x1);
                self.pending[i] = try statusFromBits(bit);
            }
            self.pending_len = @intCast(count);
        } else {
            // two-bit status vector: 7 symbols
            const count: usize = @min(@as(usize, 7), remaining);
            var i: usize = 0;
            while (i < count) : (i += 1) {
                const shift: u4 = @intCast(12 - i * 2);
                const bits: u2 = @intCast((chunk >> shift) & 0x3);
                self.pending[i] = try statusFromBits(bits);
            }
            self.pending_len = @intCast(count);
        }

        if (self.pending_len == 0) return Error.BadFormat;
        const s = self.pending[0];
        self.pending_idx = 1;
        return s;
    }
};

fn statusFromBits(bits: u2) Error!Status {
    return switch (bits) {
        0 => .not_received,
        1 => .small_delta,
        2 => .large_delta,
        3 => Error.BadFormat,
    };
}

/// Begin an allocation-free iteration over a transport-cc feedback packet.
pub fn iterate(bytes: []const u8) Error!StatusIterator {
    const packet = try parse(bytes);
    return .{
        .bytes = bytes,
        .packet = packet,
        .chunk_off = header_len,
        .delta_off = 0, // resolved on first next() via deltaStart
    };
}

// -- tests -----------------------------------------------------------------

const testing = std.testing;

// Helper: compute where the delta region starts by decoding all chunks once.
// The builder/parser store deltas immediately after the chunk region, so the
// iterator must know that boundary before reading deltas. We recompute it by
// scanning chunks until packet_status_count symbols are covered.
fn deltaRegionStart(bytes: []const u8, packet: Packet) Error!usize {
    var off: usize = header_len;
    var covered: usize = 0;
    while (covered < packet.packet_status_count) {
        if (off + 2 > bytes.len) return Error.Truncated;
        const chunk = std.mem.readInt(u16, bytes[off..][0..2], .big);
        off += 2;
        const remaining = packet.packet_status_count - covered;
        if (chunk & 0x8000 == 0) {
            covered += @min(@as(usize, chunk & 0x1fff), remaining);
        } else if (chunk & 0x4000 == 0) {
            covered += @min(@as(usize, 14), remaining);
        } else {
            covered += @min(@as(usize, 7), remaining);
        }
    }
    return off;
}

/// Convenience iterator factory that resolves the delta region start.
fn iterateFull(bytes: []const u8) Error!StatusIterator {
    var it = try iterate(bytes);
    it.delta_off = try deltaRegionStart(bytes, it.packet);
    return it;
}

test "build then parse round-trips header fields" {
    var buf: [256]u8 = undefined;
    const statuses = [_]Status{ .small_delta, .not_received, .large_delta, .small_delta };
    // one delta per RECEIVED packet, in order: small, large, small
    const deltas = [_]i64{ 250, -500, 500 };

    const pkt = try build(0x01020304, 0x11223344, 1000, 7, 42, &statuses, &deltas, &buf);

    const parsed = try parse(pkt);
    try testing.expectEqual(@as(u8, 205), pkt[1]);
    try testing.expectEqual(@as(u8, 15), pkt[0] & 0x1f);
    try testing.expectEqual(@as(u8, 2), pkt[0] >> 6);
    try testing.expectEqual(@as(u32, 0x01020304), parsed.sender_ssrc);
    try testing.expectEqual(@as(u32, 0x11223344), parsed.media_ssrc);
    try testing.expectEqual(@as(u16, 1000), parsed.base_seq);
    try testing.expectEqual(@as(u16, 4), parsed.packet_status_count);
    try testing.expectEqual(@as(u24, 7), parsed.reference_time);
    try testing.expectEqual(@as(u8, 42), parsed.fb_pkt_count);
    try testing.expectEqual(@as(usize, 0), pkt.len % 4);
}

test "iterator yields sequence, status, and quantized deltas" {
    var buf: [256]u8 = undefined;
    const statuses = [_]Status{ .small_delta, .not_received, .large_delta, .small_delta };
    // one delta per received packet (small, large, small), on 250us boundaries
    const deltas = [_]i64{ 250, -500, 750 };

    const pkt = try build(0x0a0b0c0d, 0xdeadbeef, 5000, 3, 9, &statuses, &deltas, &buf);

    var it = try iterateFull(pkt);

    const want_status = [_]Status{ .small_delta, .not_received, .large_delta, .small_delta };
    // per-position expected delta (not_received => null)
    const want_delta = [_]?i64{ 250, null, -500, 750 };

    var i: usize = 0;
    while (try it.next()) |item| : (i += 1) {
        try testing.expectEqual(@as(u16, @intCast(5000 + i)), item.seq);
        try testing.expectEqual(want_status[i], item.status);
        if (want_delta[i]) |d| {
            // within 250us quantization
            try testing.expect(@abs(d - item.delta_us.?) < delta_unit_us);
        } else {
            try testing.expectEqual(@as(?i64, null), item.delta_us);
        }
    }
    try testing.expectEqual(@as(usize, 4), i);
}

test "mixed run of received and not-received" {
    var buf: [256]u8 = undefined;
    // a long run of not_received forces a run-length chunk
    var statuses: [20]Status = undefined;
    for (&statuses, 0..) |*s, i| {
        s.* = if (i % 2 == 0) .small_delta else .not_received;
    }
    var deltas: [10]i64 = undefined;
    for (&deltas) |*d| d.* = 250;

    const pkt = try build(1, 2, 0, 0, 0, &statuses, &deltas, &buf);
    const parsed = try parse(pkt);
    try testing.expectEqual(@as(u16, 20), parsed.packet_status_count);

    var it = try iterateFull(pkt);
    var i: usize = 0;
    while (try it.next()) |item| : (i += 1) {
        const expect_status: Status = if (i % 2 == 0) .small_delta else .not_received;
        try testing.expectEqual(expect_status, item.status);
        if (i % 2 == 0) {
            try testing.expectEqual(@as(i64, 250), item.delta_us.?);
        } else {
            try testing.expectEqual(@as(?i64, null), item.delta_us);
        }
    }
    try testing.expectEqual(@as(usize, 20), i);
}

test "long run-length chunk exceeding pending buffer" {
    var buf: [512]u8 = undefined;
    // 40 not_received in a row -> single run-length chunk, run > pending cap
    var statuses: [40]Status = undefined;
    for (&statuses) |*s| s.* = .not_received;
    const deltas = [_]i64{};

    const pkt = try build(1, 2, 100, 0, 0, &statuses, &deltas, &buf);
    var it = try iterateFull(pkt);
    var count: usize = 0;
    while (try it.next()) |item| : (count += 1) {
        try testing.expectEqual(Status.not_received, item.status);
        try testing.expectEqual(@as(u16, @intCast(100 + count)), item.seq);
    }
    try testing.expectEqual(@as(usize, 40), count);
}

test "parse rejects truncated buffer" {
    var buf: [256]u8 = undefined;
    const statuses = [_]Status{ .small_delta, .small_delta };
    const deltas = [_]i64{ 250, 250 };
    const pkt = try build(1, 2, 0, 0, 0, &statuses, &deltas, &buf);

    try testing.expectError(Error.Truncated, parse(pkt[0..3]));
    try testing.expectError(Error.Truncated, parse(pkt[0 .. header_len - 1]));

    // advertise a longer length than the buffer holds
    var lie = buf;
    const lie_pkt = lie[0..pkt.len];
    @memcpy(lie_pkt, pkt);
    std.mem.writeInt(u16, lie_pkt[2..4], std.mem.readInt(u16, lie_pkt[2..4], .big) + 1, .big);
    try testing.expectError(Error.Truncated, parse(lie_pkt));
}

test "build rejects bad format and insufficient deltas" {
    var buf: [64]u8 = undefined;
    const reserved = [_]Status{.reserved};
    try testing.expectError(Error.BadFormat, build(1, 2, 0, 0, 0, &reserved, &.{}, &buf));

    const needs_delta = [_]Status{.small_delta};
    try testing.expectError(Error.BadFormat, build(1, 2, 0, 0, 0, &needs_delta, &.{}, &buf));

    try testing.expectError(Error.BadFormat, build(1, 2, 0, 0, 0, &.{}, &.{}, &buf));
}

test "build rejects undersized output buffer" {
    var small: [8]u8 = undefined;
    const statuses = [_]Status{.small_delta};
    const deltas = [_]i64{250};
    try testing.expectError(Error.BufferTooSmall, build(1, 2, 0, 0, 0, &statuses, &deltas, &small));
}
