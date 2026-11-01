// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const Error = error{ Truncated, BadLength, BufferTooSmall };

pub const ChunkType = enum(u8) {
    data = 0,
    init = 1,
    init_ack = 2,
    sack = 3,
    heartbeat = 4,
    abort = 6,
    shutdown = 7,
    cookie_echo = 10,
    cookie_ack = 11,
    _,
};

pub const CommonHeader = struct {
    pub const len = 12;

    src_port: u16,
    dst_port: u16,
    verification_tag: u32,
    checksum: u32,

    pub fn encode(self: CommonHeader, out: []u8) Error!void {
        if (out.len < len) return error.BufferTooSmall;

        writeU16(out[0..2], self.src_port);
        writeU16(out[2..4], self.dst_port);
        writeU32(out[4..8], self.verification_tag);
        writeU32(out[8..12], self.checksum);
    }

    pub fn decode(buf: []const u8) Error!CommonHeader {
        if (buf.len < len) return error.Truncated;

        return .{
            .src_port = readU16(buf[0..2]),
            .dst_port = readU16(buf[2..4]),
            .verification_tag = readU32(buf[4..8]),
            .checksum = readU32(buf[8..12]),
        };
    }
};

pub const Chunk = struct {
    typ: ChunkType,
    flags: u8,
    value: []const u8,
};

pub const ChunkIterator = struct {
    body: []const u8,
    offset: usize = 0,

    pub fn init(body: []const u8) ChunkIterator {
        return .{ .body = body };
    }

    pub fn next(self: *ChunkIterator) Error!?Chunk {
        if (self.offset == self.body.len) return null;
        if (self.offset > self.body.len or self.body.len - self.offset < 4) {
            return error.Truncated;
        }

        const start = self.offset;
        const chunk_len = readU16(self.body[start + 2 .. start + 4]);
        if (chunk_len < 4) return error.BadLength;
        if (chunk_len > self.body.len - start) return error.Truncated;

        const padded_len = paddedLength(chunk_len) orelse return error.BadLength;
        if (padded_len > self.body.len - start) return error.Truncated;

        self.offset = start + padded_len;
        return .{
            .typ = @fromBackingInt(@intCast(self.body[start])),
            .flags = self.body[start + 1],
            .value = self.body[start + 4 .. start + chunk_len],
        };
    }
};

pub const DataHeader = struct {
    pub const len = 12;

    tsn: u32,
    stream_id: u16,
    stream_seq: u16,
    ppid: u32,
};

pub const DataChunk = struct {
    hdr: DataHeader,
    user_data: []const u8,
};

pub fn parseData(chunk_value: []const u8) Error!DataChunk {
    if (chunk_value.len < DataHeader.len) return error.Truncated;

    return .{
        .hdr = .{
            .tsn = readU32(chunk_value[0..4]),
            .stream_id = readU16(chunk_value[4..6]),
            .stream_seq = readU16(chunk_value[6..8]),
            .ppid = readU32(chunk_value[8..12]),
        },
        .user_data = chunk_value[DataHeader.len..],
    };
}

pub fn encodeDataHeader(hdr: DataHeader, out: []u8) Error!void {
    if (out.len < DataHeader.len) return error.BufferTooSmall;

    writeU32(out[0..4], hdr.tsn);
    writeU16(out[4..6], hdr.stream_id);
    writeU16(out[6..8], hdr.stream_seq);
    writeU32(out[8..12], hdr.ppid);
}

pub const SackHeader = struct {
    pub const len = 12;

    cumulative_tsn_ack: u32,
    advertised_receiver_window_credit: u32,
    gap_ack_block_count: u16,
    duplicate_tsn_count: u16,
};

pub fn parseSack(chunk_value: []const u8) Error!SackHeader {
    if (chunk_value.len < SackHeader.len) return error.Truncated;

    return .{
        .cumulative_tsn_ack = readU32(chunk_value[0..4]),
        .advertised_receiver_window_credit = readU32(chunk_value[4..8]),
        .gap_ack_block_count = readU16(chunk_value[8..10]),
        .duplicate_tsn_count = readU16(chunk_value[10..12]),
    };
}

pub fn encodeSackHeader(hdr: SackHeader, out: []u8) Error!void {
    if (out.len < SackHeader.len) return error.BufferTooSmall;

    writeU32(out[0..4], hdr.cumulative_tsn_ack);
    writeU32(out[4..8], hdr.advertised_receiver_window_credit);
    writeU16(out[8..10], hdr.gap_ack_block_count);
    writeU16(out[10..12], hdr.duplicate_tsn_count);
}

pub const InitHeader = struct {
    pub const len = 16;

    initiate_tag: u32,
    advertised_receiver_window_credit: u32,
    outbound_streams: u16,
    inbound_streams: u16,
    initial_tsn: u32,
};

pub fn parseInit(chunk_value: []const u8) Error!InitHeader {
    if (chunk_value.len < InitHeader.len) return error.Truncated;

    return .{
        .initiate_tag = readU32(chunk_value[0..4]),
        .advertised_receiver_window_credit = readU32(chunk_value[4..8]),
        .outbound_streams = readU16(chunk_value[8..10]),
        .inbound_streams = readU16(chunk_value[10..12]),
        .initial_tsn = readU32(chunk_value[12..16]),
    };
}

pub fn encodeInitHeader(hdr: InitHeader, out: []u8) Error!void {
    if (out.len < InitHeader.len) return error.BufferTooSmall;

    writeU32(out[0..4], hdr.initiate_tag);
    writeU32(out[4..8], hdr.advertised_receiver_window_credit);
    writeU16(out[8..10], hdr.outbound_streams);
    writeU16(out[10..12], hdr.inbound_streams);
    writeU32(out[12..16], hdr.initial_tsn);
}

pub fn encodeChunkHeader(typ: ChunkType, flags: u8, value_len: usize, out: []u8) Error!void {
    if (out.len < 4) return error.BufferTooSmall;
    if (value_len > std.math.maxInt(u16) - 4) return error.BadLength;

    out[0] = @backingInt(typ);
    out[1] = flags;
    writeU16(out[2..4], @intCast(value_len + 4));
}

pub fn crc32c(bytes: []const u8) u32 {
    var crc: u32 = 0xffffffff;

    for (bytes) |byte| {
        crc ^= byte;
        var bit: u8 = 0;
        while (bit < 8) : (bit += 1) {
            const mask: u32 = 0 -% (crc & 1);
            crc = (crc >> 1) ^ (0x82f63b78 & mask);
        }
    }

    return ~crc;
}

pub fn setChecksum(packet: []u8) void {
    if (packet.len < CommonHeader.len) return;

    @memset(packet[8..12], 0);
    const checksum = crc32c(packet);
    writeU32(packet[8..12], checksum);
}

fn paddedLength(len: usize) ?usize {
    const added = std.math.add(usize, len, 3) catch return null;
    return added & ~@as(usize, 3);
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

fn readU32(bytes: []const u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        bytes[3];
}

fn writeU16(out: []u8, value: u16) void {
    out[0] = @truncate(value >> 8);
    out[1] = @truncate(value);
}

fn writeU32(out: []u8, value: u32) void {
    out[0] = @truncate(value >> 24);
    out[1] = @truncate(value >> 16);
    out[2] = @truncate(value >> 8);
    out[3] = @truncate(value);
}

test "common header and DATA chunk round trip" {
    const user_data = "example";
    const data_len = DataHeader.len + user_data.len;
    const chunk_len = 4 + data_len;
    const packet_len = CommonHeader.len + chunk_len + 1;
    var packet: [packet_len]u8 = @splat(0);

    try (CommonHeader{
        .src_port = 5000,
        .dst_port = 5001,
        .verification_tag = 0x11223344,
        .checksum = 0,
    }).encode(packet[0..CommonHeader.len]);
    try encodeChunkHeader(.data, 0x03, data_len, packet[CommonHeader.len .. CommonHeader.len + 4]);
    try encodeDataHeader(.{
        .tsn = 0xaabbccdd,
        .stream_id = 7,
        .stream_seq = 9,
        .ppid = 51,
    }, packet[CommonHeader.len + 4 .. CommonHeader.len + 4 + DataHeader.len]);
    @memcpy(packet[CommonHeader.len + 4 + DataHeader.len .. CommonHeader.len + chunk_len], user_data);

    const common = try CommonHeader.decode(packet[0..CommonHeader.len]);
    try std.testing.expectEqual(@as(u16, 5000), common.src_port);
    try std.testing.expectEqual(@as(u16, 5001), common.dst_port);
    try std.testing.expectEqual(@as(u32, 0x11223344), common.verification_tag);
    try std.testing.expectEqual(@as(u32, 0), common.checksum);

    var it = ChunkIterator.init(packet[CommonHeader.len..]);
    const chunk = (try it.next()).?;
    try std.testing.expectEqual(ChunkType.data, chunk.typ);
    try std.testing.expectEqual(@as(u8, 0x03), chunk.flags);

    const parsed = try parseData(chunk.value);
    try std.testing.expectEqual(@as(u32, 0xaabbccdd), parsed.hdr.tsn);
    try std.testing.expectEqual(@as(u16, 7), parsed.hdr.stream_id);
    try std.testing.expectEqual(@as(u16, 9), parsed.hdr.stream_seq);
    try std.testing.expectEqual(@as(u32, 51), parsed.hdr.ppid);
    try std.testing.expectEqualStrings(user_data, parsed.user_data);
    try std.testing.expectEqual(@as(?Chunk, null), try it.next());
}

test "crc32c known vector" {
    try std.testing.expectEqual(@as(u32, 0xe3069283), crc32c("123456789"));
}

test "setChecksum writes the packet crc with checksum field zeroed" {
    var packet: [CommonHeader.len + 4 + DataHeader.len]u8 = @splat(0);
    try (CommonHeader{
        .src_port = 1,
        .dst_port = 2,
        .verification_tag = 3,
        .checksum = 0xffffffff,
    }).encode(packet[0..CommonHeader.len]);
    try encodeChunkHeader(.data, 0, DataHeader.len, packet[CommonHeader.len .. CommonHeader.len + 4]);
    try encodeDataHeader(.{
        .tsn = 4,
        .stream_id = 5,
        .stream_seq = 6,
        .ppid = 7,
    }, packet[CommonHeader.len + 4 ..]);

    setChecksum(&packet);
    const written = readU32(packet[8..12]);

    var verify = packet;
    @memset(verify[8..12], 0);
    try std.testing.expectEqual(crc32c(&verify), written);
}

test "truncated buffers are rejected" {
    try std.testing.expectError(error.Truncated, CommonHeader.decode(&@as([11]u8, @splat(0))));

    var body = [_]u8{ 0, 0, 0, 8, 1, 2, 3 };
    var it = ChunkIterator.init(&body);
    try std.testing.expectError(error.Truncated, it.next());

    try std.testing.expectError(error.Truncated, parseData(&@as([11]u8, @splat(0))));
    try std.testing.expectError(error.Truncated, parseSack(&@as([11]u8, @splat(0))));
    try std.testing.expectError(error.Truncated, parseInit(&@as([15]u8, @splat(0))));
}
