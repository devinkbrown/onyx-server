// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compound RTCP packet parser/builder for RFC 3550 packet types used by Onyx Server.
const std = @import("std");
const rtp_profile = @import("rtp_profile.zig");

const header_len: usize = 4;
const report_block_len: usize = 24;
const rtcp_version: u8 = 2;

pub const Error = error{ Truncated, BadVersion, BadLength };

pub const PacketType = enum(u8) {
    sr = 200,
    rr = 201,
    sdes = 202,
    bye = 203,
    other = 0,
    _,
};

pub const ReportBlock = rtp_profile.ReportBlock;

pub const ReportBlocks = struct {
    bytes: []const u8,

    pub fn len(self: ReportBlocks) usize {
        return self.bytes.len / report_block_len;
    }

    pub fn get(self: ReportBlocks, index: usize) ?ReportBlock {
        if (index >= self.len()) return null;
        const start = index * report_block_len;
        return readReportBlock(self.bytes[start .. start + report_block_len]);
    }

    pub fn at(self: ReportBlocks, index: usize) ReportBlock {
        return self.get(index) orelse unreachable;
    }
};

pub const SenderReport = struct {
    sender_ssrc: u32,
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    report_blocks: ReportBlocks,
};

pub const ReceiverReport = struct {
    sender_ssrc: u32,
    report_blocks: ReportBlocks,
};

pub const Bye = struct {
    ssrc_bytes: []const u8,
    reason: []const u8,

    pub fn sourceCount(self: Bye) usize {
        return self.ssrc_bytes.len / 4;
    }

    pub fn sourceSsrc(self: Bye, index: usize) ?u32 {
        if (index >= self.sourceCount()) return null;
        const start = index * 4;
        return readU32(self.ssrc_bytes[start .. start + 4]);
    }
};

pub const Sdes = struct {
    source_count: u5,
    chunks: []const u8,

    pub fn iterator(self: Sdes) SdesIterator {
        return .{
            .remaining = self.chunks,
            .left = self.source_count,
        };
    }
};

pub const SdesChunk = struct {
    ssrc: u32,
    items: []const u8,
};

pub const SdesIterator = struct {
    remaining: []const u8,
    left: u5,

    pub fn next(self: *SdesIterator) Error!?SdesChunk {
        if (self.left == 0) return null;
        if (self.remaining.len < 5) return error.BadLength;

        const ssrc = readU32(self.remaining[0..4]);
        var pos: usize = 4;
        while (true) {
            if (pos >= self.remaining.len) return error.BadLength;
            const item_type = self.remaining[pos];
            pos += 1;
            if (item_type == 0) break;
            if (pos >= self.remaining.len) return error.BadLength;
            const item_len = self.remaining[pos];
            pos += 1;
            if (self.remaining.len - pos < item_len) return error.BadLength;
            pos += item_len;
        }

        const items_end = pos - 1;
        pos = align4(pos);
        if (pos > self.remaining.len) return error.BadLength;

        const chunk = SdesChunk{
            .ssrc = ssrc,
            .items = self.remaining[4..items_end],
        };
        self.remaining = self.remaining[pos..];
        self.left -= 1;
        return chunk;
    }
};

pub const View = union(PacketType) {
    sr: SenderReport,
    rr: ReceiverReport,
    sdes: Sdes,
    bye: Bye,
    other: struct {
        pt: u8,
        body: []const u8,
    },
};

pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) Error!?View {
        if (self.pos == self.bytes.len) return null;
        if (self.bytes.len - self.pos < header_len) return error.Truncated;

        const packet = self.bytes[self.pos..];
        const first = packet[0];
        if ((first >> 6) != rtcp_version) return error.BadVersion;

        const count: u5 = @intCast(first & 0x1f);
        const padded = (first & 0x20) != 0;
        const packet_type = packet[1];
        const words_minus_one = readU16(packet[2..4]);
        const packet_len = (@as(usize, words_minus_one) + 1) * 4;
        if (packet_len < header_len) return error.BadLength;
        if (packet.len < packet_len) return error.Truncated;

        var body = packet[header_len..packet_len];
        if (padded) {
            if (body.len == 0) return error.BadLength;
            const padding_len = body[body.len - 1];
            if (padding_len == 0 or padding_len > body.len) return error.BadLength;
            body = body[0 .. body.len - padding_len];
        }

        const view = switch (packet_type) {
            @backingInt(PacketType.sr) => try parseSenderReportBody(count, body),
            @backingInt(PacketType.rr) => try parseReceiverReportBody(count, body),
            @backingInt(PacketType.sdes) => try parseSdesBody(count, body),
            @backingInt(PacketType.bye) => try parseByeBody(count, body),
            else => View{ .other = .{
                .pt = packet_type,
                .body = body,
            } },
        };
        self.pos += packet_len;
        return view;
    }
};

pub fn parse(bytes: []const u8) Iterator {
    return .{ .bytes = bytes };
}

pub fn buildReceiverReport(sender_ssrc: u32, blocks: []const ReportBlock, out: []u8) Error![]const u8 {
    if (blocks.len > 31) return error.BadLength;

    const total_len = header_len + 4 + blocks.len * report_block_len;
    if (out.len < total_len) return error.BadLength;

    writeHeader(out[0..header_len], @intCast(blocks.len), @backingInt(PacketType.rr), total_len);
    writeU32(out[4..8], sender_ssrc);
    for (blocks, 0..) |block, index| {
        const start = 8 + index * report_block_len;
        try writeReportBlock(block, out[start .. start + report_block_len]);
    }
    return out[0..total_len];
}

pub fn buildBye(ssrcs: []const u32, reason: []const u8, out: []u8) Error![]const u8 {
    if (ssrcs.len > 31 or reason.len > std.math.maxInt(u8)) return error.BadLength;

    const reason_len = if (reason.len == 0) @as(usize, 0) else 1 + reason.len;
    const unpadded_len = header_len + ssrcs.len * 4 + reason_len;
    const total_len = align4(unpadded_len);
    if (out.len < total_len) return error.BadLength;

    writeHeader(out[0..header_len], @intCast(ssrcs.len), @backingInt(PacketType.bye), total_len);

    var pos: usize = header_len;
    for (ssrcs) |ssrc| {
        writeU32(out[pos .. pos + 4], ssrc);
        pos += 4;
    }

    if (reason.len != 0) {
        out[pos] = @intCast(reason.len);
        pos += 1;
        @memcpy(out[pos .. pos + reason.len], reason);
        pos += reason.len;
    }
    @memset(out[pos..total_len], 0);

    return out[0..total_len];
}

fn parseSenderReportBody(count: u5, body: []const u8) Error!View {
    const expected_len = 24 + @as(usize, count) * report_block_len;
    if (body.len != expected_len) return error.BadLength;
    return View{ .sr = .{
        .sender_ssrc = readU32(body[0..4]),
        .ntp_timestamp = readU64(body[4..12]),
        .rtp_timestamp = readU32(body[12..16]),
        .packet_count = readU32(body[16..20]),
        .octet_count = readU32(body[20..24]),
        .report_blocks = .{ .bytes = body[24..] },
    } };
}

fn parseReceiverReportBody(count: u5, body: []const u8) Error!View {
    const expected_len = 4 + @as(usize, count) * report_block_len;
    if (body.len != expected_len) return error.BadLength;
    return View{ .rr = .{
        .sender_ssrc = readU32(body[0..4]),
        .report_blocks = .{ .bytes = body[4..] },
    } };
}

fn parseByeBody(count: u5, body: []const u8) Error!View {
    const ssrc_len = @as(usize, count) * 4;
    if (body.len < ssrc_len) return error.BadLength;

    const tail = body[ssrc_len..];
    const reason = if (tail.len == 0) tail else reason: {
        const reason_len = tail[0];
        if (tail.len - 1 < reason_len) return error.BadLength;
        if (!allZero(tail[1 + reason_len ..])) return error.BadLength;
        break :reason tail[1 .. 1 + reason_len];
    };

    return View{ .bye = .{
        .ssrc_bytes = body[0..ssrc_len],
        .reason = reason,
    } };
}

fn parseSdesBody(count: u5, body: []const u8) Error!View {
    var iter = SdesIterator{
        .remaining = body,
        .left = count,
    };
    while (try iter.next()) |_| {}
    if (!allZero(iter.remaining)) return error.BadLength;

    return View{ .sdes = .{
        .source_count = count,
        .chunks = body[0 .. body.len - iter.remaining.len],
    } };
}

fn writeHeader(out: []u8, count: u5, packet_type: u8, total_len: usize) void {
    std.debug.assert(out.len >= header_len);
    std.debug.assert(total_len % 4 == 0);

    out[0] = (@as(u8, rtcp_version) << 6) | @as(u8, count);
    out[1] = packet_type;
    writeU16(out[2..4], @intCast((total_len / 4) - 1));
}

fn writeReportBlock(block: ReportBlock, out: []u8) Error!void {
    std.debug.assert(out.len >= report_block_len);

    writeU32(out[0..4], block.ssrc);
    out[4] = block.fraction_lost;
    try writeI24(block.cumulative_lost, out[5..8]);
    writeU32(out[8..12], block.highest_seq_with_cycles);
    writeU32(out[12..16], block.jitter);
    writeU32(out[16..20], block.lsr);
    writeU32(out[20..24], block.dlsr);
}

fn readReportBlock(input: []const u8) ReportBlock {
    std.debug.assert(input.len >= report_block_len);

    return .{
        .ssrc = readU32(input[0..4]),
        .fraction_lost = input[4],
        .cumulative_lost = readI24(input[5..8]),
        .highest_seq_with_cycles = readU32(input[8..12]),
        .jitter = readU32(input[12..16]),
        .lsr = readU32(input[16..20]),
        .dlsr = readU32(input[20..24]),
    };
}

fn writeI24(value: i32, out: []u8) Error!void {
    if (value < -0x800000 or value > 0x7fffff) return error.BadLength;

    const raw: u32 = if (value < 0)
        @intCast(0x1000000 + value)
    else
        @intCast(value);
    out[0] = @intCast((raw >> 16) & 0xff);
    out[1] = @intCast((raw >> 8) & 0xff);
    out[2] = @intCast(raw & 0xff);
}

fn readI24(input: []const u8) i32 {
    const raw = (@as(u32, input[0]) << 16) | (@as(u32, input[1]) << 8) | @as(u32, input[2]);
    if ((raw & 0x800000) != 0) return @as(i32, @intCast(raw)) - 0x1000000;
    return @intCast(raw);
}

fn align4(value: usize) usize {
    return (value + 3) & ~@as(usize, 3);
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn readU16(bytes: []const u8) u16 {
    std.debug.assert(bytes.len >= 2);
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn readU32(bytes: []const u8) u32 {
    std.debug.assert(bytes.len >= 4);
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        @as(u32, bytes[3]);
}

fn readU64(bytes: []const u8) u64 {
    std.debug.assert(bytes.len >= 8);
    return (@as(u64, bytes[0]) << 56) |
        (@as(u64, bytes[1]) << 48) |
        (@as(u64, bytes[2]) << 40) |
        (@as(u64, bytes[3]) << 32) |
        (@as(u64, bytes[4]) << 24) |
        (@as(u64, bytes[5]) << 16) |
        (@as(u64, bytes[6]) << 8) |
        @as(u64, bytes[7]);
}

fn writeU16(bytes: []u8, value: u16) void {
    std.debug.assert(bytes.len >= 2);
    bytes[0] = @intCast(value >> 8);
    bytes[1] = @intCast(value & 0xff);
}

fn writeU32(bytes: []u8, value: u32) void {
    std.debug.assert(bytes.len >= 4);
    bytes[0] = @intCast((value >> 24) & 0xff);
    bytes[1] = @intCast((value >> 16) & 0xff);
    bytes[2] = @intCast((value >> 8) & 0xff);
    bytes[3] = @intCast(value & 0xff);
}

const testing = std.testing;

test "receiver report with two report blocks round-trips through iterator" {
    const blocks = [_]ReportBlock{
        .{
            .ssrc = 0x01020304,
            .fraction_lost = 7,
            .cumulative_lost = -3,
            .highest_seq_with_cycles = 0x0001fffe,
            .jitter = 77,
            .lsr = 0x10203040,
            .dlsr = 0x50607080,
        },
        .{
            .ssrc = 0x11121314,
            .fraction_lost = 12,
            .cumulative_lost = 0x1234,
            .highest_seq_with_cycles = 0x21222324,
            .jitter = 9000,
            .lsr = 0x31323334,
            .dlsr = 0x41424344,
        },
    };

    var buf: [header_len + 4 + blocks.len * report_block_len]u8 = undefined;
    const encoded = try buildReceiverReport(0xaabbccdd, &blocks, &buf);

    var iter = parse(encoded);
    const view = (try iter.next()).?;
    switch (view) {
        .rr => |rr| {
            try testing.expectEqual(@as(u32, 0xaabbccdd), rr.sender_ssrc);
            try testing.expectEqual(@as(usize, 2), rr.report_blocks.len());

            const block = rr.report_blocks.at(1);
            try testing.expectEqual(blocks[1].ssrc, block.ssrc);
            try testing.expectEqual(blocks[1].fraction_lost, block.fraction_lost);
            try testing.expectEqual(blocks[1].cumulative_lost, block.cumulative_lost);
            try testing.expectEqual(blocks[1].highest_seq_with_cycles, block.highest_seq_with_cycles);
            try testing.expectEqual(blocks[1].jitter, block.jitter);
            try testing.expectEqual(blocks[1].lsr, block.lsr);
            try testing.expectEqual(blocks[1].dlsr, block.dlsr);
        },
        else => return error.BadLength,
    }
    try testing.expectEqual(@as(?View, null), try iter.next());
}

test "bye with reason round-trips through iterator" {
    const ssrcs = [_]u32{ 0x01020304, 0xaabbccdd };
    const reason = "session ending";

    var buf: [64]u8 = undefined;
    const encoded = try buildBye(&ssrcs, reason, &buf);

    var iter = parse(encoded);
    const view = (try iter.next()).?;
    switch (view) {
        .bye => |bye| {
            try testing.expectEqual(@as(usize, 2), bye.sourceCount());
            try testing.expectEqual(ssrcs[0], bye.sourceSsrc(0).?);
            try testing.expectEqual(ssrcs[1], bye.sourceSsrc(1).?);
            try testing.expectEqualSlices(u8, reason, bye.reason);
        },
        else => return error.BadLength,
    }
    try testing.expectEqual(@as(?View, null), try iter.next());
}

test "compound buffer iterates receiver report then bye" {
    const blocks = [_]ReportBlock{.{
        .ssrc = 0x01020304,
        .fraction_lost = 1,
        .cumulative_lost = 2,
        .highest_seq_with_cycles = 3,
        .jitter = 4,
    }};
    const ssrcs = [_]u32{0x01020304};

    var rr_buf: [header_len + 4 + report_block_len]u8 = undefined;
    const rr = try buildReceiverReport(0x11223344, &blocks, &rr_buf);

    var bye_buf: [16]u8 = undefined;
    const bye = try buildBye(&ssrcs, "", &bye_buf);

    var compound: [rr_buf.len + bye_buf.len]u8 = undefined;
    @memcpy(compound[0..rr.len], rr);
    @memcpy(compound[rr.len .. rr.len + bye.len], bye);

    var iter = parse(compound[0 .. rr.len + bye.len]);
    try testing.expect((try iter.next()).? == .rr);
    try testing.expect((try iter.next()).? == .bye);
    try testing.expectEqual(@as(?View, null), try iter.next());
}

test "truncated cut buffer returns Truncated" {
    const blocks = [_]ReportBlock{.{
        .ssrc = 1,
        .fraction_lost = 2,
        .cumulative_lost = 3,
        .highest_seq_with_cycles = 4,
        .jitter = 5,
    }};

    var buf: [header_len + 4 + report_block_len]u8 = undefined;
    const encoded = try buildReceiverReport(0x11223344, &blocks, &buf);
    var iter = parse(encoded[0 .. encoded.len - 1]);

    try testing.expectError(error.Truncated, iter.next());
}

test "bad version returns BadVersion" {
    const blocks = [_]ReportBlock{.{
        .ssrc = 1,
        .fraction_lost = 2,
        .cumulative_lost = 3,
        .highest_seq_with_cycles = 4,
        .jitter = 5,
    }};

    var buf: [header_len + 4 + report_block_len]u8 = undefined;
    const encoded = try buildReceiverReport(0x11223344, &blocks, &buf);
    buf[0] = encoded[0] & 0x3f;

    var iter = parse(encoded);
    try testing.expectError(error.BadVersion, iter.next());
}
