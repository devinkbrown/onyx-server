// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 8285 RTP header-extension codec for Onyx Server media bands.
//!
//! This module is a pure, allocation-free codec for the RTP header-extension
//! block that may follow the 12-byte fixed RTP header when the X bit is set.
//! It mirrors the byte-level style of `rtp_profile.zig` and deliberately owns
//! no sockets, allocators, or scheduling.
//!
//! It supports both RFC 8285 forms:
//!   - one-byte form (profile 0xBEDE): each element is a single id/len byte
//!     `(id << 4) | (len - 1)` followed by `len` data bytes; id 0 is padding;
//!     id 15 is reserved and acts as a stop marker.
//!   - two-byte form (profile 0x100X): each element is `id`, `len`, then `len`
//!     data bytes; id 0 (with a present length byte) is padding.
//!
//! ASSUMPTION: parsing assumes the extension block begins immediately after the
//! 12-byte fixed header, i.e. there are no CSRC entries (CC == 0). This is true
//! for the SFU-forwarded streams Onyx Server cares about. Padding (P) and the CSRC
//! count are not consulted; callers that may see CSRCs must strip them first.
const std = @import("std");

const rtp_profile = @import("rtp_profile.zig");

/// Fixed RTP header length (no CSRCs assumed). Re-exported for clarity.
pub const header_len: usize = rtp_profile.header_len;

/// X bit in byte 0 of the RTP fixed header.
pub const ext_present_mask: u8 = 0x10;

/// One-byte header-extension profile identifier (RFC 8285).
pub const profile_one_byte: u16 = 0xBEDE;

/// Two-byte header-extension profiles occupy 0x1000..=0x100F (top 12 bits
/// 0x100, low 4 bits an "appbits" field that we accept but ignore).
pub const profile_two_byte_base: u16 = 0x1000;
pub const profile_two_byte_mask: u16 = 0xFFF0;

/// Reserved one-byte extension id that terminates element iteration.
pub const id_stop: u8 = 15;
/// Padding element id (skipped during iteration).
pub const id_padding: u8 = 0;

/// One-byte extension whose single data byte is the frame's spatial layer.
/// A packet with no such element is spatial layer 0.
pub const spatial_layer_id: u8 = 13;

const endian = .big;

pub const Error = error{ Truncated, BadProfile, NotPresent, TooLong };

/// Wire form of an extension block (which element encoding is in use).
pub const Form = enum { one_byte, two_byte };

/// A single parsed extension element. `data` borrows the source packet.
pub const Element = struct {
    id: u8,
    data: []const u8,
};

/// Iterates the elements within a single RFC 8285 extension block.
///
/// The iterator borrows the packet bytes; it performs no allocation. Construct
/// it via `parse`, which validates that the declared block fits in the packet.
pub const Iterator = struct {
    form: Form,
    /// Bytes of the extension element area (after profile + length words).
    block: []const u8,
    pos: usize = 0,

    /// Returns the next element, or null when the block is exhausted or a
    /// one-byte stop marker (id 15) is reached. Padding (id 0) is skipped.
    pub fn next(self: *Iterator) ?Element {
        switch (self.form) {
            .one_byte => return self.nextOneByte(),
            .two_byte => return self.nextTwoByte(),
        }
    }

    fn nextOneByte(self: *Iterator) ?Element {
        while (self.pos < self.block.len) {
            const tag = self.block[self.pos];
            // id 0 byte is a single padding byte.
            if (tag == 0) {
                self.pos += 1;
                continue;
            }
            const id: u8 = tag >> 4;
            // id 15 is reserved: stop parsing this block.
            if (id == id_stop) {
                self.pos = self.block.len;
                return null;
            }
            const len: usize = @as(usize, tag & 0x0f) + 1;
            const data_start = self.pos + 1;
            const data_end = data_start + len;
            // Malformed (claims more data than present): stop cleanly.
            if (data_end > self.block.len) {
                self.pos = self.block.len;
                return null;
            }
            self.pos = data_end;
            return .{ .id = id, .data = self.block[data_start..data_end] };
        }
        return null;
    }

    fn nextTwoByte(self: *Iterator) ?Element {
        while (self.pos < self.block.len) {
            const id = self.block[self.pos];
            // A lone id 0 with no length byte is trailing padding.
            if (id == 0) {
                self.pos += 1;
                continue;
            }
            if (self.pos + 1 >= self.block.len) {
                self.pos = self.block.len;
                return null;
            }
            const len: usize = self.block[self.pos + 1];
            const data_start = self.pos + 2;
            const data_end = data_start + len;
            if (data_end > self.block.len) {
                self.pos = self.block.len;
                return null;
            }
            self.pos = data_end;
            return .{ .id = id, .data = self.block[data_start..data_end] };
        }
        return null;
    }
};

/// Returns true if the RTP fixed header has the X (extension) bit set.
pub fn hasExtension(rtp_packet: []const u8) Error!bool {
    if (rtp_packet.len < header_len) return error.Truncated;
    return (rtp_packet[0] & ext_present_mask) != 0;
}

/// Parses the header-extension block of an RTP packet.
///
/// Returns null when the X bit is unset. Otherwise returns an `Iterator` over
/// the extension elements. The 4-byte profile+length preamble is validated and
/// the declared block size is checked against the packet length.
///
/// ASSUMPTION: no CSRCs (CC == 0); the block starts at byte 12.
pub fn parse(rtp_packet: []const u8) Error!?Iterator {
    if (rtp_packet.len < header_len) return error.Truncated;
    if ((rtp_packet[0] & ext_present_mask) == 0) return null;

    // Need the 4-byte extension preamble after the fixed header.
    const pre_start = header_len;
    if (rtp_packet.len < pre_start + 4) return error.Truncated;

    const profile = std.mem.readInt(u16, rtp_packet[pre_start .. pre_start + 2][0..2], endian);
    const words = std.mem.readInt(u16, rtp_packet[pre_start + 2 .. pre_start + 4][0..2], endian);

    const form: Form = if (profile == profile_one_byte)
        .one_byte
    else if ((profile & profile_two_byte_mask) == profile_two_byte_base)
        .two_byte
    else
        return error.BadProfile;

    const block_len: usize = @as(usize, words) * 4;
    const block_start = pre_start + 4;
    const block_end = block_start + block_len;
    if (rtp_packet.len < block_end) return error.Truncated;

    return Iterator{ .form = form, .block = rtp_packet[block_start..block_end] };
}

/// Returns the data bytes for the given one-byte extension `id`, or null when
/// the packet has no extension block or the id is absent. Returns null if the
/// extension block is in two-byte form (use `parse` directly for that case).
pub fn find(rtp_packet: []const u8, id: u8) Error!?[]const u8 {
    var it = (try parse(rtp_packet)) orelse return null;
    if (it.form != .one_byte) return null;
    while (it.next()) |element| {
        if (element.id == id) return element.data;
    }
    return null;
}

/// Reads a transport-wide congestion-control sequence number (a u16 BE) from
/// the one-byte extension with the given `id`. Returns null when absent.
pub fn readTransportSeq(rtp_packet: []const u8, id: u8) Error!?u16 {
    const data = (try find(rtp_packet, id)) orelse return null;
    if (data.len != 2) return error.Truncated;
    return std.mem.readInt(u16, data[0..2], endian);
}

/// Reads the abs-send-time extension (3 bytes, 6.18 fixed point) from the
/// one-byte extension with the given `id`. The raw 24-bit value is returned
/// zero-extended into a u32. Returns null when absent.
pub fn readAbsSendTime(rtp_packet: []const u8, id: u8) Error!?u32 {
    const data = (try find(rtp_packet, id)) orelse return null;
    if (data.len != 3) return error.Truncated;
    return (@as(u32, data[0]) << 16) | (@as(u32, data[1]) << 8) | @as(u32, data[2]);
}

/// Encodes the abs-send-time wire value from a raw 24-bit fixed-point value.
/// Useful for building packets in tests and a future rewriting SFU.
pub fn absSendTimeBytes(value: u32) [3]u8 {
    return .{
        @intCast((value >> 16) & 0xff),
        @intCast((value >> 8) & 0xff),
        @intCast(value & 0xff),
    };
}

/// Number of bytes a one-byte element occupies on the wire (1 id/len byte plus
/// the data). Returns TooLong if data does not fit a one-byte element.
fn oneByteElementLen(data_len: usize) Error!usize {
    if (data_len < 1 or data_len > 16) return error.TooLong;
    return 1 + data_len;
}

/// Builds a complete one-byte (0xBEDE) extension block into `out`: the 4-byte
/// profile+length preamble, the elements, and 32-bit zero padding to round the
/// element area to a whole number of words. Returns the written slice.
///
/// Each element id must be in 1..=14 and its data length in 1..=16 bytes.
pub fn buildOneByteExtension(elements: []const Element, out: []u8) Error![]const u8 {
    // First pass: compute the element-area length.
    var elems_len: usize = 0;
    for (elements) |element| {
        if (element.id < 1 or element.id > 14) return error.BadProfile;
        elems_len += try oneByteElementLen(element.data.len);
    }

    // Round element area up to a 32-bit word boundary.
    const padded_len = (elems_len + 3) & ~@as(usize, 3);
    const words = padded_len / 4;
    if (words > std.math.maxInt(u16)) return error.TooLong;

    const total = 4 + padded_len;
    if (out.len < total) return error.Truncated;

    std.mem.writeInt(u16, out[0..2], profile_one_byte, endian);
    std.mem.writeInt(u16, out[2..4], @intCast(words), endian);

    var pos: usize = 4;
    for (elements) |element| {
        const len_field: u8 = @intCast(element.data.len - 1);
        out[pos] = (element.id << 4) | len_field;
        pos += 1;
        @memcpy(out[pos .. pos + element.data.len], element.data);
        pos += element.data.len;
    }

    // Zero-fill the trailing padding bytes.
    while (pos < total) : (pos += 1) out[pos] = 0;

    return out[0..total];
}

const testing = std.testing;

/// Builds a minimal RTP packet: a 12-byte fixed header (X bit per `with_ext`)
/// followed by `ext_block` (the full extension block) and `payload`.
fn buildTestPacket(
    with_ext: bool,
    ext_block: []const u8,
    payload: []const u8,
    out: []u8,
) []const u8 {
    var hdr = rtp_profile.Header{
        .payload_type = 96,
        .sequence = 7,
        .timestamp = 1000,
        .ssrc = 0xdeadbeef,
    };
    _ = &hdr;
    _ = rtp_profile.encodeHeader(hdr, out[0..header_len]) catch unreachable;
    if (with_ext) out[0] |= ext_present_mask;
    var pos: usize = header_len;
    @memcpy(out[pos .. pos + ext_block.len], ext_block);
    pos += ext_block.len;
    @memcpy(out[pos .. pos + payload.len], payload);
    pos += payload.len;
    return out[0..pos];
}

test "build and round-trip a one-byte extension via iterator" {
    const seq_bytes = [_]u8{ 0x12, 0x34 };
    const ast_bytes = absSendTimeBytes(0x0ABCDE);
    const elements = [_]Element{
        .{ .id = 5, .data = &seq_bytes },
        .{ .id = 3, .data = &ast_bytes },
    };

    var block_buf: [64]u8 = undefined;
    const block = try buildOneByteExtension(&elements, &block_buf);

    // profile must be 0xBEDE.
    try testing.expectEqual(profile_one_byte, std.mem.readInt(u16, block[0..2], endian));
    // Element area: 3 + 4 = 7 bytes -> rounds to 8 -> 2 words.
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, block[2..4], endian));
    try testing.expectEqual(@as(usize, 12), block.len);

    var pkt_buf: [128]u8 = undefined;
    const packet = buildTestPacket(true, block, "media", &pkt_buf);

    var it = (try parse(packet)).?;
    try testing.expectEqual(Form.one_byte, it.form);

    const first = it.next().?;
    try testing.expectEqual(@as(u8, 5), first.id);
    try testing.expectEqualSlices(u8, &seq_bytes, first.data);

    const second = it.next().?;
    try testing.expectEqual(@as(u8, 3), second.id);
    try testing.expectEqualSlices(u8, &ast_bytes, second.data);

    try testing.expectEqual(@as(?Element, null), it.next());
}

test "find and typed helpers read transport-cc and abs-send-time" {
    const seq_bytes = [_]u8{ 0x12, 0x34 };
    const ast_bytes = absSendTimeBytes(0x0ABCDE);
    const elements = [_]Element{
        .{ .id = 5, .data = &seq_bytes },
        .{ .id = 3, .data = &ast_bytes },
    };

    var block_buf: [64]u8 = undefined;
    const block = try buildOneByteExtension(&elements, &block_buf);

    var pkt_buf: [128]u8 = undefined;
    const packet = buildTestPacket(true, block, "x", &pkt_buf);

    const found = (try find(packet, 5)).?;
    try testing.expectEqualSlices(u8, &seq_bytes, found);

    try testing.expectEqual(@as(?u16, 0x1234), try readTransportSeq(packet, 5));
    try testing.expectEqual(@as(?u32, 0x0ABCDE), try readAbsSendTime(packet, 3));

    // Absent id returns null.
    try testing.expectEqual(@as(?[]const u8, null), try find(packet, 9));
    try testing.expectEqual(@as(?u16, null), try readTransportSeq(packet, 9));
    try testing.expectEqual(@as(?u32, null), try readAbsSendTime(packet, 9));
}

test "packet without X bit returns null from parse" {
    var pkt_buf: [64]u8 = undefined;
    const packet = buildTestPacket(false, &.{}, "no-extensions", &pkt_buf);
    try testing.expectEqual(@as(?Iterator, null), try parse(packet));
    try testing.expectEqual(@as(?[]const u8, null), try find(packet, 5));
}

test "truncated extension block (claims more words than present)" {
    // Preamble claims 4 words (16 bytes) but only 4 follow.
    var ext: [8]u8 = undefined;
    std.mem.writeInt(u16, ext[0..2], profile_one_byte, endian);
    std.mem.writeInt(u16, ext[2..4], 4, endian); // 4 words = 16 bytes
    ext[4] = 0;
    ext[5] = 0;
    ext[6] = 0;
    ext[7] = 0;

    var pkt_buf: [64]u8 = undefined;
    const packet = buildTestPacket(true, &ext, "", &pkt_buf);
    try testing.expectError(error.Truncated, parse(packet));
}

test "bad profile is rejected" {
    var ext: [8]u8 = undefined;
    std.mem.writeInt(u16, ext[0..2], 0xABCD, endian); // not 0xBEDE nor 0x100X
    std.mem.writeInt(u16, ext[2..4], 1, endian);
    @memset(ext[4..8], 0);

    var pkt_buf: [64]u8 = undefined;
    const packet = buildTestPacket(true, &ext, "", &pkt_buf);
    try testing.expectError(error.BadProfile, parse(packet));
}

test "two-byte form iterates and find returns null" {
    // Build a two-byte block by hand: profile 0x1000, 1 word (4 bytes).
    // Element id=10, len=2, data {0xAA,0xBB}.
    var ext: [8]u8 = undefined;
    std.mem.writeInt(u16, ext[0..2], profile_two_byte_base, endian);
    std.mem.writeInt(u16, ext[2..4], 1, endian);
    ext[4] = 10; // id
    ext[5] = 2; // len
    ext[6] = 0xAA;
    ext[7] = 0xBB;

    var pkt_buf: [64]u8 = undefined;
    const packet = buildTestPacket(true, &ext, "", &pkt_buf);

    var it = (try parse(packet)).?;
    try testing.expectEqual(Form.two_byte, it.form);
    const el = it.next().?;
    try testing.expectEqual(@as(u8, 10), el.id);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, el.data);
    try testing.expectEqual(@as(?Element, null), it.next());

    // find() only serves one-byte form.
    try testing.expectEqual(@as(?[]const u8, null), try find(packet, 10));
}

test "one-byte iterator skips padding and stops at id 15" {
    // Element area: pad(0), id=2 len=1 data{0x7F}, stop(0xF0), then junk.
    var ext: [8]u8 = undefined;
    std.mem.writeInt(u16, ext[0..2], profile_one_byte, endian);
    std.mem.writeInt(u16, ext[2..4], 1, endian);
    ext[4] = 0x00; // padding
    ext[5] = (2 << 4) | 0; // id 2, len 1
    ext[6] = 0x7F;
    ext[7] = 0xF0; // id 15 stop marker

    var pkt_buf: [64]u8 = undefined;
    const packet = buildTestPacket(true, &ext, "", &pkt_buf);

    var it = (try parse(packet)).?;
    const el = it.next().?;
    try testing.expectEqual(@as(u8, 2), el.id);
    try testing.expectEqualSlices(u8, &[_]u8{0x7F}, el.data);
    try testing.expectEqual(@as(?Element, null), it.next());
}

test "buildOneByteExtension rejects invalid ids and oversized data" {
    var out: [64]u8 = undefined;

    const bad_id = [_]Element{.{ .id = 15, .data = &[_]u8{0x01} }};
    try testing.expectError(error.BadProfile, buildOneByteExtension(&bad_id, &out));

    const zero_id = [_]Element{.{ .id = 0, .data = &[_]u8{0x01} }};
    try testing.expectError(error.BadProfile, buildOneByteExtension(&zero_id, &out));

    const too_long = [_]Element{.{ .id = 1, .data = &@as([17]u8, @splat(0)) }};
    try testing.expectError(error.TooLong, buildOneByteExtension(&too_long, &out));

    const empty = [_]Element{.{ .id = 1, .data = &.{} }};
    try testing.expectError(error.TooLong, buildOneByteExtension(&empty, &out));
}

test "buildOneByteExtension reports Truncated when out is too small" {
    const elements = [_]Element{.{ .id = 1, .data = &[_]u8{ 0x01, 0x02 } }};
    var tiny: [4]u8 = undefined; // needs 4 preamble + 4 padded = 8
    try testing.expectError(error.Truncated, buildOneByteExtension(&elements, &tiny));
}

test "readTransportSeq/readAbsSendTime reject wrong data length" {
    // id 5 has 3 bytes (wrong for transport-seq, which wants 2).
    // id 3 has 2 bytes (wrong for abs-send-time, which wants 3).
    const elements = [_]Element{
        .{ .id = 5, .data = &[_]u8{ 1, 2, 3 } },
        .{ .id = 3, .data = &[_]u8{ 1, 2 } },
    };
    var block_buf: [32]u8 = undefined;
    const block = try buildOneByteExtension(&elements, &block_buf);
    var pkt_buf: [64]u8 = undefined;
    const packet = buildTestPacket(true, block, "", &pkt_buf);
    try testing.expectError(error.Truncated, readTransportSeq(packet, 5));
    try testing.expectError(error.Truncated, readAbsSendTime(packet, 3));
}
