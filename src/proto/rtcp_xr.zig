// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RTCP Extended Reports (RFC 3611), packet type 207.
const std = @import("std");

const endian = .big;
const rtcp_version: u8 = 2;
const rtcp_xr_packet_type: u8 = 207;
const rtcp_header_len: usize = 4;
const xr_sender_ssrc_len: usize = 4;
const xr_fixed_len: usize = rtcp_header_len + xr_sender_ssrc_len;
const block_header_len: usize = 4;
const rrt_body_len: usize = 8;
const dlrr_sub_len: usize = 12;
const max_rtcp_packet_len: usize = (@as(usize, std.math.maxInt(u16)) + 1) * 4;
const max_dlrr_subs: usize = (max_rtcp_packet_len - xr_fixed_len - block_header_len) / dlrr_sub_len;

pub const Error = error{ Truncated, BadVersion, BufferTooSmall, TooMany };

pub const BlockType = enum(u8) {
    loss_rle = 1,
    dup_rle = 2,
    pkt_receipt_times = 3,
    receiver_reference_time = 4,
    dlrr = 5,
    _,
};

pub const Block = struct {
    typ: BlockType,
    type_specific: u8,
    body: []const u8,
};

pub const BlockIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *BlockIterator) Error!?Block {
        if (self.pos == self.bytes.len) return null;
        if (self.bytes.len - self.pos < block_header_len) return error.Truncated;

        const header = self.bytes[self.pos..][0..block_header_len];
        const body_words = std.mem.readInt(u16, header[2..4], endian);
        const body_len = @as(usize, body_words) * 4;
        const body_start = self.pos + block_header_len;
        const body_end = body_start + body_len;
        if (body_end > self.bytes.len) return error.Truncated;

        self.pos = body_end;
        return .{
            .typ = @fromBackingInt(@intCast(header[0])),
            .type_specific = header[1],
            .body = self.bytes[body_start..body_end],
        };
    }
};

pub const LossRleHeader = struct {
    source_ssrc: u32,
    begin_seq: u16,
    end_seq: u16,
    chunks: []const u8,
};

pub const DlrrSub = struct {
    ssrc: u32,
    lrr: u32,
    dlrr: u32,
};

pub fn parse(bytes: []const u8) Error!struct { sender_ssrc: u32, blocks: BlockIterator } {
    if (bytes.len < rtcp_header_len) return error.Truncated;
    if ((bytes[0] >> 6) != rtcp_version) return error.BadVersion;
    if (bytes[1] != rtcp_xr_packet_type) return error.BadVersion;

    const words_minus_one = std.mem.readInt(u16, bytes[2..4], endian);
    const packet_len = (@as(usize, words_minus_one) + 1) * 4;
    if (packet_len < xr_fixed_len) return error.Truncated;
    if (bytes.len < packet_len) return error.Truncated;

    const packet = bytes[0..packet_len];
    return .{
        .sender_ssrc = std.mem.readInt(u32, packet[4..8], endian),
        .blocks = .{ .bytes = packet[xr_fixed_len..] },
    };
}

pub fn parseLossRleBody(body: []const u8) Error!LossRleHeader {
    if (body.len < 8) return error.Truncated;
    return .{
        .source_ssrc = std.mem.readInt(u32, body[0..4], endian),
        .begin_seq = std.mem.readInt(u16, body[4..6], endian),
        .end_seq = std.mem.readInt(u16, body[6..8], endian),
        .chunks = body[8..],
    };
}

pub fn parseReceiverReferenceTimeBody(body: []const u8) Error!u64 {
    if (body.len != rrt_body_len) return error.Truncated;
    return std.mem.readInt(u64, body[0..8], endian);
}

pub fn parseDlrrSub(body: []const u8, index: usize) Error!DlrrSub {
    const start = index * dlrr_sub_len;
    const end = start + dlrr_sub_len;
    if (end > body.len) return error.Truncated;
    return readDlrrSub(body[start..end]);
}

pub fn buildReceiverReferenceTime(sender_ssrc: u32, ntp: u64, out: []u8) Error![]const u8 {
    const total_len = xr_fixed_len + block_header_len + rrt_body_len;
    if (out.len < total_len) return error.BufferTooSmall;

    writeRtcpXrHeader(out[0..rtcp_header_len], total_len);
    std.mem.writeInt(u32, out[4..8], sender_ssrc, endian);
    writeBlockHeader(.receiver_reference_time, 0, rrt_body_len, out[8..12]);
    std.mem.writeInt(u64, out[12..20], ntp, endian);
    return out[0..total_len];
}

pub fn buildDlrr(sender_ssrc: u32, subs: []const DlrrSub, out: []u8) Error![]const u8 {
    if (subs.len > max_dlrr_subs) return error.TooMany;

    const body_len = subs.len * dlrr_sub_len;
    const total_len = xr_fixed_len + block_header_len + body_len;
    if (out.len < total_len) return error.BufferTooSmall;

    writeRtcpXrHeader(out[0..rtcp_header_len], total_len);
    std.mem.writeInt(u32, out[4..8], sender_ssrc, endian);
    writeBlockHeader(.dlrr, 0, body_len, out[8..12]);

    var off: usize = 12;
    for (subs) |sub| {
        std.mem.writeInt(u32, out[off..][0..4], sub.ssrc, endian);
        std.mem.writeInt(u32, out[off + 4 ..][0..4], sub.lrr, endian);
        std.mem.writeInt(u32, out[off + 8 ..][0..4], sub.dlrr, endian);
        off += dlrr_sub_len;
    }

    return out[0..total_len];
}

fn readDlrrSub(bytes: []const u8) DlrrSub {
    std.debug.assert(bytes.len >= dlrr_sub_len);
    return .{
        .ssrc = std.mem.readInt(u32, bytes[0..4], endian),
        .lrr = std.mem.readInt(u32, bytes[4..8], endian),
        .dlrr = std.mem.readInt(u32, bytes[8..12], endian),
    };
}

fn writeRtcpXrHeader(out: []u8, total_len: usize) void {
    std.debug.assert(out.len >= rtcp_header_len);
    std.debug.assert(total_len >= xr_fixed_len);
    std.debug.assert(total_len % 4 == 0);
    std.debug.assert(total_len <= max_rtcp_packet_len);

    out[0] = rtcp_version << 6;
    out[1] = rtcp_xr_packet_type;
    std.mem.writeInt(u16, out[2..4], @intCast((total_len / 4) - 1), endian);
}

fn writeBlockHeader(typ: BlockType, type_specific: u8, body_len: usize, out: []u8) void {
    std.debug.assert(out.len >= block_header_len);
    std.debug.assert(body_len % 4 == 0);
    std.debug.assert(body_len / 4 <= std.math.maxInt(u16));

    out[0] = @backingInt(typ);
    out[1] = type_specific;
    std.mem.writeInt(u16, out[2..4], @intCast(body_len / 4), endian);
}

test "receiver reference time round-trip" {
    const testing = std.testing;
    const sender_ssrc: u32 = 0x11223344;
    const ntp: u64 = 0x0102030405060708;

    var buf: [20]u8 = undefined;
    const encoded = try buildReceiverReferenceTime(sender_ssrc, ntp, &buf);

    var parsed = try parse(encoded);
    try testing.expectEqual(sender_ssrc, parsed.sender_ssrc);

    const block = (try parsed.blocks.next()).?;
    try testing.expectEqual(BlockType.receiver_reference_time, block.typ);
    try testing.expectEqual(@as(u8, 0), block.type_specific);
    try testing.expectEqual(ntp, try parseReceiverReferenceTimeBody(block.body));
    try testing.expectEqual(@as(?Block, null), try parsed.blocks.next());
}

test "dlrr two sub-blocks round-trip" {
    const testing = std.testing;
    const sender_ssrc: u32 = 0xaabbccdd;
    const subs = [_]DlrrSub{
        .{ .ssrc = 0x01020304, .lrr = 0x11121314, .dlrr = 0x21222324 },
        .{ .ssrc = 0x31323334, .lrr = 0x41424344, .dlrr = 0x51525354 },
    };

    var buf: [36]u8 = undefined;
    const encoded = try buildDlrr(sender_ssrc, &subs, &buf);

    var parsed = try parse(encoded);
    try testing.expectEqual(sender_ssrc, parsed.sender_ssrc);

    const block = (try parsed.blocks.next()).?;
    try testing.expectEqual(BlockType.dlrr, block.typ);
    try testing.expectEqual(@as(usize, 24), block.body.len);

    const first = try parseDlrrSub(block.body, 0);
    const second = try parseDlrrSub(block.body, 1);
    try testing.expectEqual(subs[0].ssrc, first.ssrc);
    try testing.expectEqual(subs[0].lrr, first.lrr);
    try testing.expectEqual(subs[0].dlrr, first.dlrr);
    try testing.expectEqual(subs[1].ssrc, second.ssrc);
    try testing.expectEqual(subs[1].lrr, second.lrr);
    try testing.expectEqual(subs[1].dlrr, second.dlrr);
    try testing.expectEqual(@as(?Block, null), try parsed.blocks.next());
}

test "compound xr iterates receiver reference time then dlrr" {
    const testing = std.testing;
    const sender_ssrc: u32 = 0x55667788;
    const ntp: u64 = 0x0102030405060708;
    const subs = [_]DlrrSub{
        .{ .ssrc = 0x10111213, .lrr = 0x20212223, .dlrr = 0x30313233 },
    };

    var packet: [36]u8 = undefined;
    writeRtcpXrHeader(packet[0..4], packet.len);
    std.mem.writeInt(u32, packet[4..8], sender_ssrc, endian);
    writeBlockHeader(.receiver_reference_time, 0, rrt_body_len, packet[8..12]);
    std.mem.writeInt(u64, packet[12..20], ntp, endian);
    writeBlockHeader(.dlrr, 0, dlrr_sub_len, packet[20..24]);
    std.mem.writeInt(u32, packet[24..28], subs[0].ssrc, endian);
    std.mem.writeInt(u32, packet[28..32], subs[0].lrr, endian);
    std.mem.writeInt(u32, packet[32..36], subs[0].dlrr, endian);

    var parsed = try parse(&packet);
    try testing.expectEqual(sender_ssrc, parsed.sender_ssrc);

    const first = (try parsed.blocks.next()).?;
    try testing.expectEqual(BlockType.receiver_reference_time, first.typ);
    try testing.expectEqual(ntp, try parseReceiverReferenceTimeBody(first.body));

    const second = (try parsed.blocks.next()).?;
    try testing.expectEqual(BlockType.dlrr, second.typ);
    const sub = try parseDlrrSub(second.body, 0);
    try testing.expectEqual(subs[0].ssrc, sub.ssrc);
    try testing.expectEqual(subs[0].lrr, sub.lrr);
    try testing.expectEqual(subs[0].dlrr, sub.dlrr);

    try testing.expectEqual(@as(?Block, null), try parsed.blocks.next());
}

test "truncated packet and block cuts" {
    const testing = std.testing;
    var buf: [20]u8 = undefined;
    const encoded = try buildReceiverReferenceTime(0x01020304, 0x05060708090a0b0c, &buf);

    try testing.expectError(error.Truncated, parse(encoded[0 .. encoded.len - 1]));

    var cut_block = buf;
    std.mem.writeInt(u16, cut_block[2..4], 4, endian);
    std.mem.writeInt(u16, cut_block[10..12], 3, endian);
    var parsed = try parse(&cut_block);
    try testing.expectError(error.Truncated, parsed.blocks.next());
}

test "bad version" {
    const testing = std.testing;
    var buf: [20]u8 = undefined;
    const encoded = try buildReceiverReferenceTime(0x01020304, 0x05060708090a0b0c, &buf);

    buf[0] = (1 << 6) | (encoded[0] & 0x3f);
    try testing.expectError(error.BadVersion, parse(&buf));
}
