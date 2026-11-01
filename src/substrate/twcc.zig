// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport-wide congestion control feedback helpers.
//!
//! This module implements the RTP transport-wide sequence number extension and
//! the RTCP transport-cc feedback packet described by
//! draft-holmer-rmcat-transport-wide-cc. All timestamps are caller-provided and
//! expressed in microseconds.
const std = @import("std");

pub const rtp_extension_len = 2;
pub const rtcp_payload_type_transport_feedback: u8 = 205;
pub const transport_cc_feedback_format: u5 = 15;
pub const delta_unit_us: i64 = 250;
pub const reference_time_unit_us: i64 = 64_000;
pub const max_packet_status_count: usize = std.math.maxInt(u16);

const rtcp_fixed_header_len = 20;
const max_run_length: u13 = std.math.maxInt(u13);

pub const Error = error{
    BadRtpExtension,
    BadRtcpPacket,
    BadStatusSymbol,
    CountTooLarge,
    DeltaNotAligned,
    DuplicateSequence,
    EmptyFeedback,
    NoPackets,
    ReservedStatusSymbol,
    RunLengthTooLarge,
    Truncated,
    UnrepresentableDelta,
};

pub const Status = enum(u2) {
    not_received = 0,
    small_delta = 1,
    large_delta = 2,
    reserved = 3,

    pub fn isReceived(self: Status) bool {
        return self == .small_delta or self == .large_delta;
    }
};

pub const Sender = struct {
    next_seq: u16 = 0,

    pub fn init(first_seq: u16) Sender {
        return .{ .next_seq = first_seq };
    }

    pub fn assign(self: *Sender) u16 {
        const seq = self.next_seq;
        self.next_seq +%= 1;
        return seq;
    }

    pub fn writeExtension(self: *Sender, out: []u8) Error!u16 {
        const seq = self.assign();
        try writeRtpExtension(seq, out);
        return seq;
    }
};

pub const Entry = struct {
    seq: u16,
    status: Status,
    /// Arrival time relative to the decoded RTCP reference time. Null when the
    /// packet was not received.
    arrival_delta_us: ?i64 = null,
};

pub const Feedback = struct {
    sender_ssrc: u32,
    media_ssrc: u32,
    base_seq: u16,
    packet_status_count: u16,
    reference_time: u32,
    fb_pkt_count: u8,
    entries: []Entry,

    pub fn deinit(self: Feedback, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }

    pub fn referenceTimeUs(self: Feedback) i64 {
        return @as(i64, self.reference_time) * reference_time_unit_us;
    }

    pub fn find(self: Feedback, seq: u16) ?Entry {
        for (self.entries) |entry| {
            if (entry.seq == seq) return entry;
        }
        return null;
    }

    pub fn encode(self: Feedback, allocator: std.mem.Allocator) ![]u8 {
        if (self.entries.len == 0) return Error.EmptyFeedback;
        if (self.entries.len != self.packet_status_count) return Error.BadRtcpPacket;
        if (self.entries.len > max_packet_status_count) return Error.CountTooLarge;
        if (self.reference_time > 0x00ff_ffff) return Error.BadRtcpPacket;

        var statuses: std.ArrayList(Status) = .empty;
        defer statuses.deinit(allocator);
        try statuses.ensureTotalCapacity(allocator, self.entries.len);
        for (self.entries, 0..) |entry, i| {
            if (entry.seq != addSeq(self.base_seq, i)) return Error.BadRtcpPacket;
            if (entry.status == .reserved) return Error.ReservedStatusSymbol;
            if (entry.status.isReceived() and entry.arrival_delta_us == null) {
                return Error.BadRtcpPacket;
            }
            if (!entry.status.isReceived() and entry.arrival_delta_us != null) {
                return Error.BadRtcpPacket;
            }
            statuses.appendAssumeCapacity(entry.status);
        }

        var chunks: std.ArrayList(u16) = .empty;
        defer chunks.deinit(allocator);
        try encodeChunks(allocator, statuses.items, &chunks);

        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(allocator);
        try body.ensureTotalCapacity(
            allocator,
            rtcp_fixed_header_len + chunks.items.len * 2 + self.entries.len * 2 + 3,
        );

        try appendZeroes(allocator, &body, rtcp_fixed_header_len);
        writeU32(body.items[4..8], self.sender_ssrc);
        writeU32(body.items[8..12], self.media_ssrc);
        writeU16(body.items[12..14], self.base_seq);
        writeU16(body.items[14..16], self.packet_status_count);
        writeU24(body.items[16..19], self.reference_time);
        body.items[19] = self.fb_pkt_count;

        for (chunks.items) |chunk| {
            try appendU16(allocator, &body, chunk);
        }

        var previous_arrival_delta_us: i64 = 0;
        for (self.entries) |entry| {
            if (!entry.status.isReceived()) continue;
            const arrival_delta_us = entry.arrival_delta_us.?;
            const step_us = arrival_delta_us - previous_arrival_delta_us;
            const ticks = try deltaTicks(step_us);
            switch (entry.status) {
                .small_delta => {
                    if (ticks < 0 or ticks > std.math.maxInt(u8)) {
                        return Error.UnrepresentableDelta;
                    }
                    const byte: u8 = @intCast(ticks);
                    try body.append(allocator, byte);
                },
                .large_delta => {
                    if (ticks < std.math.minInt(i16) or ticks > std.math.maxInt(i16)) {
                        return Error.UnrepresentableDelta;
                    }
                    const signed: i16 = @intCast(ticks);
                    try appendU16(allocator, &body, @bitCast(signed));
                },
                .not_received, .reserved => unreachable,
            }
            previous_arrival_delta_us = arrival_delta_us;
        }

        while (body.items.len % 4 != 0) {
            try body.append(allocator, 0);
        }
        const length_words = body.items.len / 4;
        if (length_words == 0 or length_words - 1 > std.math.maxInt(u16)) {
            return Error.BadRtcpPacket;
        }
        body.items[0] = 0x80 | @as(u8, transport_cc_feedback_format);
        body.items[1] = rtcp_payload_type_transport_feedback;
        writeU16(body.items[2..4], @intCast(length_words - 1));

        return body.toOwnedSlice(allocator);
    }
};

const RecordedPacket = struct {
    seq: u16,
    ext_seq: u32,
    arrival_us: u64,
};

pub const Receiver = struct {
    allocator: std.mem.Allocator,
    packets: std.ArrayList(RecordedPacket) = .empty,
    base_seq: ?u16 = null,
    fb_pkt_count: u8 = 0,

    pub fn init(allocator: std.mem.Allocator) Receiver {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Receiver) void {
        self.packets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn record(self: *Receiver, seq: u16, arrival_us: u64) !void {
        if (self.base_seq == null) self.base_seq = seq;
        const ext_seq = extendFromBase(self.base_seq.?, seq);

        var index: usize = 0;
        while (index < self.packets.items.len) : (index += 1) {
            const stored = self.packets.items[index];
            if (stored.seq == seq) return Error.DuplicateSequence;
            if (ext_seq < stored.ext_seq) break;
        }

        try self.packets.insert(self.allocator, index, .{
            .seq = seq,
            .ext_seq = ext_seq,
            .arrival_us = arrival_us,
        });
    }

    pub fn buildFeedback(
        self: *Receiver,
        allocator: std.mem.Allocator,
        sender_ssrc: u32,
        media_ssrc: u32,
    ) !Feedback {
        if (self.packets.items.len == 0) return Error.NoPackets;

        const first = self.packets.items[0];
        const last = self.packets.items[self.packets.items.len - 1];
        const count_u32 = last.ext_seq - first.ext_seq + 1;
        if (count_u32 > max_packet_status_count) return Error.CountTooLarge;
        const count: u16 = @intCast(count_u32);

        var reference_arrival_us = first.arrival_us;
        for (self.packets.items) |packet| {
            reference_arrival_us = @min(reference_arrival_us, packet.arrival_us);
        }
        const reference_time = referenceTimeField(reference_arrival_us);
        const reference_us = @as(i64, reference_time) * reference_time_unit_us;

        var entries: std.ArrayList(Entry) = .empty;
        errdefer entries.deinit(allocator);
        try entries.ensureTotalCapacity(allocator, count);

        var packet_index: usize = 0;
        var previous_arrival_delta_us: i64 = 0;
        var offset: u32 = 0;
        while (offset < count_u32) : (offset += 1) {
            const seq = addSeq(first.seq, offset);
            if (packet_index < self.packets.items.len and
                self.packets.items[packet_index].ext_seq == first.ext_seq + offset)
            {
                const packet = self.packets.items[packet_index];
                const arrival_delta_us = @as(i64, @intCast(packet.arrival_us)) - reference_us;
                const step_us = arrival_delta_us - previous_arrival_delta_us;
                const ticks = try deltaTicks(step_us);
                const status = try statusForDeltaTicks(ticks);
                entries.appendAssumeCapacity(.{
                    .seq = seq,
                    .status = status,
                    .arrival_delta_us = arrival_delta_us,
                });
                previous_arrival_delta_us = arrival_delta_us;
                packet_index += 1;
            } else {
                entries.appendAssumeCapacity(.{
                    .seq = seq,
                    .status = .not_received,
                    .arrival_delta_us = null,
                });
            }
        }

        const owned_entries = try entries.toOwnedSlice(allocator);
        self.fb_pkt_count +%= 1;
        return .{
            .sender_ssrc = sender_ssrc,
            .media_ssrc = media_ssrc,
            .base_seq = first.seq,
            .packet_status_count = count,
            .reference_time = reference_time,
            .fb_pkt_count = self.fb_pkt_count -% 1,
            .entries = owned_entries,
        };
    }

    pub fn buildPacket(
        self: *Receiver,
        allocator: std.mem.Allocator,
        sender_ssrc: u32,
        media_ssrc: u32,
    ) ![]u8 {
        const feedback = try self.buildFeedback(allocator, sender_ssrc, media_ssrc);
        defer feedback.deinit(allocator);
        return feedback.encode(allocator);
    }
};

pub fn writeRtpExtension(seq: u16, out: []u8) Error!void {
    if (out.len < rtp_extension_len) return Error.BadRtpExtension;
    writeU16(out[0..2], seq);
}

pub fn readRtpExtension(data: []const u8) Error!u16 {
    if (data.len < rtp_extension_len) return Error.BadRtpExtension;
    return readU16(data[0..2]);
}

pub fn encodeRunLengthChunk(status: Status, run_length: u16) Error!u16 {
    if (status == .reserved) return Error.ReservedStatusSymbol;
    if (run_length == 0 or run_length > max_run_length) return Error.RunLengthTooLarge;
    return (@as(u16, @backingInt(status)) << 13) | run_length;
}

pub fn encodeOneBitStatusVector(statuses: []const Status) Error!u16 {
    if (statuses.len == 0 or statuses.len > 14) return Error.CountTooLarge;
    var chunk: u16 = 0x8000;
    for (statuses, 0..) |status, i| {
        if (status == .large_delta or status == .reserved) return Error.BadStatusSymbol;
        if (status == .small_delta) {
            const shift: u4 = @intCast(13 - i);
            chunk |= @as(u16, 1) << shift;
        }
    }
    return chunk;
}

pub fn encodeTwoBitStatusVector(statuses: []const Status) Error!u16 {
    if (statuses.len == 0 or statuses.len > 7) return Error.CountTooLarge;
    var chunk: u16 = 0xc000;
    for (statuses, 0..) |status, i| {
        if (status == .reserved) return Error.ReservedStatusSymbol;
        const shift: u4 = @intCast(12 - i * 2);
        chunk |= @as(u16, @backingInt(status)) << shift;
    }
    return chunk;
}

pub fn parseFeedback(allocator: std.mem.Allocator, data: []const u8) !Feedback {
    if (data.len < rtcp_fixed_header_len) return Error.Truncated;
    const first = data[0];
    if (first >> 6 != 2 or first & 0x20 != 0) return Error.BadRtcpPacket;
    if (first & 0x1f != transport_cc_feedback_format) return Error.BadRtcpPacket;
    if (data[1] != rtcp_payload_type_transport_feedback) return Error.BadRtcpPacket;

    const packet_len = (@as(usize, readU16(data[2..4])) + 1) * 4;
    if (packet_len < rtcp_fixed_header_len or packet_len > data.len) return Error.Truncated;
    const packet = data[0..packet_len];

    const sender_ssrc = readU32(packet[4..8]);
    const media_ssrc = readU32(packet[8..12]);
    const base_seq = readU16(packet[12..14]);
    const count = readU16(packet[14..16]);
    const reference_time = readU24(packet[16..19]);
    const fb_pkt_count = packet[19];

    var statuses: std.ArrayList(Status) = .empty;
    defer statuses.deinit(allocator);
    try statuses.ensureTotalCapacity(allocator, count);

    var offset: usize = rtcp_fixed_header_len;
    while (statuses.items.len < count) {
        if (offset + 2 > packet.len) return Error.Truncated;
        const chunk = readU16(packet[offset .. offset + 2]);
        offset += 2;
        try decodeChunk(allocator, chunk, count, &statuses);
    }

    var entries: std.ArrayList(Entry) = .empty;
    errdefer entries.deinit(allocator);
    try entries.ensureTotalCapacity(allocator, count);

    var arrival_delta_us: i64 = 0;
    for (statuses.items, 0..) |status, i| {
        if (status == .reserved) return Error.ReservedStatusSymbol;
        const seq = addSeq(base_seq, i);
        if (!status.isReceived()) {
            entries.appendAssumeCapacity(.{
                .seq = seq,
                .status = .not_received,
                .arrival_delta_us = null,
            });
            continue;
        }

        const ticks: i64 = switch (status) {
            .small_delta => blk: {
                if (offset + 1 > packet.len) return Error.Truncated;
                const byte = packet[offset];
                offset += 1;
                break :blk byte;
            },
            .large_delta => blk: {
                if (offset + 2 > packet.len) return Error.Truncated;
                const raw = readU16(packet[offset .. offset + 2]);
                offset += 2;
                const signed: i16 = @bitCast(raw);
                break :blk signed;
            },
            .not_received, .reserved => unreachable,
        };
        arrival_delta_us += ticks * delta_unit_us;
        entries.appendAssumeCapacity(.{
            .seq = seq,
            .status = status,
            .arrival_delta_us = arrival_delta_us,
        });
    }

    return .{
        .sender_ssrc = sender_ssrc,
        .media_ssrc = media_ssrc,
        .base_seq = base_seq,
        .packet_status_count = count,
        .reference_time = reference_time,
        .fb_pkt_count = fb_pkt_count,
        .entries = try entries.toOwnedSlice(allocator),
    };
}

fn encodeChunks(
    allocator: std.mem.Allocator,
    statuses: []const Status,
    chunks: *std.ArrayList(u16),
) !void {
    var index: usize = 0;
    while (index < statuses.len) {
        const run_len = sameStatusRun(statuses[index..]);
        if (run_len >= 7 or index + run_len == statuses.len) {
            const emit_len = @min(run_len, max_run_length);
            try chunks.append(allocator, try encodeRunLengthChunk(statuses[index], @intCast(emit_len)));
            index += emit_len;
            continue;
        }

        const one_bit_len = oneBitVectorLen(statuses[index..]);
        if (one_bit_len >= 7 or one_bit_len == statuses.len - index) {
            try chunks.append(allocator, try encodeOneBitStatusVector(statuses[index .. index + one_bit_len]));
            index += one_bit_len;
            continue;
        }

        const two_bit_len = @min(@as(usize, 7), statuses.len - index);
        try chunks.append(allocator, try encodeTwoBitStatusVector(statuses[index .. index + two_bit_len]));
        index += two_bit_len;
    }
}

fn decodeChunk(
    allocator: std.mem.Allocator,
    chunk: u16,
    wanted_count: u16,
    statuses: *std.ArrayList(Status),
) !void {
    const remaining = @as(usize, wanted_count) - statuses.items.len;
    if (chunk & 0x8000 == 0) {
        const status = try statusFromBits(@intCast((chunk >> 13) & 0x3));
        const run_len = @min(@as(usize, chunk & 0x1fff), remaining);
        if (run_len == 0) return Error.BadRtcpPacket;
        var i: usize = 0;
        while (i < run_len) : (i += 1) {
            try statuses.append(allocator, status);
        }
        return;
    }

    if (chunk & 0x4000 == 0) {
        const count = @min(@as(usize, 14), remaining);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const shift: u4 = @intCast(13 - i);
            const bit: u2 = @intCast((chunk >> shift) & 0x1);
            try statuses.append(allocator, try statusFromBits(bit));
        }
        return;
    }

    const count = @min(@as(usize, 7), remaining);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const shift: u4 = @intCast(12 - i * 2);
        const bits: u2 = @intCast((chunk >> shift) & 0x3);
        try statuses.append(allocator, try statusFromBits(bits));
    }
}

fn statusFromBits(bits: u2) Error!Status {
    return switch (bits) {
        0 => .not_received,
        1 => .small_delta,
        2 => .large_delta,
        3 => Error.ReservedStatusSymbol,
    };
}

fn sameStatusRun(statuses: []const Status) usize {
    const status = statuses[0];
    var len: usize = 1;
    while (len < statuses.len and len < max_run_length and statuses[len] == status) {
        len += 1;
    }
    return len;
}

fn oneBitVectorLen(statuses: []const Status) usize {
    var len: usize = 0;
    while (len < statuses.len and len < 14) : (len += 1) {
        if (statuses[len] == .large_delta or statuses[len] == .reserved) break;
    }
    return len;
}

fn statusForDeltaTicks(ticks: i64) Error!Status {
    if (ticks >= 0 and ticks <= std.math.maxInt(u8)) return .small_delta;
    if (ticks >= std.math.minInt(i16) and ticks <= std.math.maxInt(i16)) return .large_delta;
    return Error.UnrepresentableDelta;
}

fn deltaTicks(delta_us: i64) Error!i64 {
    if (@mod(delta_us, delta_unit_us) != 0) return Error.DeltaNotAligned;
    return @divExact(delta_us, delta_unit_us);
}

fn referenceTimeField(arrival_us: u64) u32 {
    const units = arrival_us / @as(u64, @intCast(reference_time_unit_us));
    return @intCast(units & 0x00ff_ffff);
}

fn extendFromBase(base_seq: u16, seq: u16) u32 {
    return @as(u32, seq -% base_seq);
}

fn addSeq(base_seq: u16, offset: anytype) u16 {
    const narrowed: u16 = @truncate(@as(u64, @intCast(offset)));
    return base_seq +% narrowed;
}

fn appendZeroes(allocator: std.mem.Allocator, list: *std.ArrayList(u8), count: usize) !void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try list.append(allocator, 0);
    }
}

fn appendU16(allocator: std.mem.Allocator, list: *std.ArrayList(u8), value: u16) !void {
    try list.append(allocator, @intCast(value >> 8));
    try list.append(allocator, @intCast(value & 0xff));
}

fn writeU16(out: []u8, value: u16) void {
    out[0] = @intCast(value >> 8);
    out[1] = @intCast(value & 0xff);
}

fn writeU24(out: []u8, value: u32) void {
    out[0] = @intCast((value >> 16) & 0xff);
    out[1] = @intCast((value >> 8) & 0xff);
    out[2] = @intCast(value & 0xff);
}

fn writeU32(out: []u8, value: u32) void {
    out[0] = @intCast((value >> 24) & 0xff);
    out[1] = @intCast((value >> 16) & 0xff);
    out[2] = @intCast((value >> 8) & 0xff);
    out[3] = @intCast(value & 0xff);
}

fn readU16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | data[1];
}

fn readU24(data: []const u8) u32 {
    return (@as(u32, data[0]) << 16) | (@as(u32, data[1]) << 8) | data[2];
}

fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        data[3];
}

test "sender assigns and writes RTP transport-wide sequence numbers" {
    var sender = Sender.init(0xfffe);
    var ext: [2]u8 = undefined;

    try std.testing.expectEqual(@as(u16, 0xfffe), try sender.writeExtension(&ext));
    try std.testing.expectEqual(@as(u16, 0xfffe), try readRtpExtension(&ext));
    try std.testing.expectEqual(@as(u16, 0xffff), sender.assign());
    try std.testing.expectEqual(@as(u16, 0x0000), sender.assign());
    try std.testing.expectError(Error.BadRtpExtension, writeRtpExtension(1, ext[0..1]));
}

test "run-length chunk encodes status and length" {
    try std.testing.expectEqual(@as(u16, 0x2005), try encodeRunLengthChunk(.small_delta, 5));
    try std.testing.expectEqual(@as(u16, 0x4004), try encodeRunLengthChunk(.large_delta, 4));
    try std.testing.expectEqual(@as(u16, 0x000a), try encodeRunLengthChunk(.not_received, 10));
    try std.testing.expectError(Error.RunLengthTooLarge, encodeRunLengthChunk(.small_delta, 0));
    try std.testing.expectError(Error.ReservedStatusSymbol, encodeRunLengthChunk(.reserved, 1));
}

test "status-vector chunks encode one-bit and two-bit forms" {
    const one_bit = [_]Status{ .small_delta, .not_received, .small_delta };
    try std.testing.expectEqual(@as(u16, 0xa800), try encodeOneBitStatusVector(&one_bit));

    const two_bit = [_]Status{ .small_delta, .large_delta, .not_received, .small_delta };
    try std.testing.expectEqual(@as(u16, 0xd840), try encodeTwoBitStatusVector(&two_bit));
    try std.testing.expectError(Error.BadStatusSymbol, encodeOneBitStatusVector(two_bit[0..2]));
}

test "build feedback for received run and parse recovered arrival deltas" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    try receiver.record(100, 128_000);
    try receiver.record(101, 128_250);
    try receiver.record(102, 128_500);
    try receiver.record(103, 128_750);

    const packet = try receiver.buildPacket(allocator, 0x01020304, 0x11223344);
    defer allocator.free(packet);
    const parsed = try parseFeedback(allocator, packet);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 0x11223344), parsed.media_ssrc);
    try std.testing.expectEqual(@as(u16, 100), parsed.base_seq);
    try std.testing.expectEqual(@as(u16, 4), parsed.packet_status_count);
    try std.testing.expectEqual(@as(u32, 2), parsed.reference_time);
    try std.testing.expectEqual(@as(usize, 4), parsed.entries.len);

    for (parsed.entries, 0..) |entry, i| {
        try std.testing.expectEqual(addSeq(100, i), entry.seq);
        try std.testing.expectEqual(Status.small_delta, entry.status);
        try std.testing.expectEqual(@as(i64, @intCast(i)) * 250, entry.arrival_delta_us.?);
    }
}

test "missing packets are represented as not-received statuses" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    try receiver.record(10, 64_000);
    try receiver.record(11, 64_250);
    try receiver.record(13, 65_000);

    const feedback = try receiver.buildFeedback(allocator, 7, 9);
    defer feedback.deinit(allocator);
    const packet = try feedback.encode(allocator);
    defer allocator.free(packet);
    const parsed = try parseFeedback(allocator, packet);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 4), parsed.entries.len);
    try std.testing.expectEqual(Status.small_delta, parsed.entries[0].status);
    try std.testing.expectEqual(Status.small_delta, parsed.entries[1].status);
    try std.testing.expectEqual(Status.not_received, parsed.entries[2].status);
    try std.testing.expectEqual(Status.small_delta, parsed.entries[3].status);
    try std.testing.expectEqual(@as(?i64, null), parsed.entries[2].arrival_delta_us);
    try std.testing.expectEqual(@as(i64, 1_000), parsed.entries[3].arrival_delta_us.?);
}

test "reference time and positive plus negative delta arithmetic round-trip" {
    const allocator = std.testing.allocator;
    var entries = [_]Entry{
        .{ .seq = 500, .status = .small_delta, .arrival_delta_us = 1_000 },
        .{ .seq = 501, .status = .large_delta, .arrival_delta_us = 500 },
        .{ .seq = 502, .status = .small_delta, .arrival_delta_us = 750 },
    };
    const owned = try allocator.dupe(Entry, &entries);
    defer allocator.free(owned);

    const feedback = Feedback{
        .sender_ssrc = 1,
        .media_ssrc = 2,
        .base_seq = 500,
        .packet_status_count = 3,
        .reference_time = 3,
        .fb_pkt_count = 77,
        .entries = owned,
    };
    const packet = try feedback.encode(allocator);
    defer allocator.free(packet);
    const parsed = try parseFeedback(allocator, packet);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(i64, 192_000), parsed.referenceTimeUs());
    try std.testing.expectEqual(Status.small_delta, parsed.entries[0].status);
    try std.testing.expectEqual(Status.large_delta, parsed.entries[1].status);
    try std.testing.expectEqual(@as(i64, 1_000), parsed.entries[0].arrival_delta_us.?);
    try std.testing.expectEqual(@as(i64, 500), parsed.entries[1].arrival_delta_us.?);
    try std.testing.expectEqual(@as(i64, 750), parsed.entries[2].arrival_delta_us.?);
}

test "parser detects truncation in header chunks and deltas" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    try receiver.record(1, 64_000);
    try receiver.record(2, 64_250);
    const packet = try receiver.buildPacket(allocator, 1, 2);
    defer allocator.free(packet);

    try std.testing.expectError(Error.Truncated, parseFeedback(allocator, packet[0..3]));

    const truncated_len = packet[0 .. packet.len - 1];
    try std.testing.expectError(Error.Truncated, parseFeedback(allocator, truncated_len));

    var advertised_too_long = try allocator.dupe(u8, packet);
    defer allocator.free(advertised_too_long);
    writeU16(advertised_too_long[2..4], readU16(advertised_too_long[2..4]) + 1);
    try std.testing.expectError(Error.Truncated, parseFeedback(allocator, advertised_too_long));
}
