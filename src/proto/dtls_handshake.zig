// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.2 handshake message layer (RFC 6347 §4.2.2).
//!
//! This is protocol framing only: 12-byte handshake headers, fragmentation
//! across records, fragment reassembly, and HelloVerifyRequest cookie bodies.
//! No cryptographic handshake state is implemented here.
const std = @import("std");

// Keep this module colocated with the DTLS record layer.  The DTLS 1.2
// handshake sequence number is epoch-local and record framing drives transport.
const record = @import("dtls_record.zig");

pub const handshake_header_len: usize = 12;
pub const max_u24: usize = 0x00ff_ffff;
pub const dtls12_version: u16 = 0xfefd;
pub const default_reassembler_ranges: usize = record.window_bits;

pub const Error = error{
    Truncated,
    BadLength,
    Overflow,
    Incomplete,
    FragmentOverlap,
};

pub const HandshakeType = enum(u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,
    encrypted_extensions = 8, // TLS 1.3 / DTLS 1.3
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    _,
};

pub const Header = struct {
    msg_type: HandshakeType,
    length: u24,
    message_seq: u16,
    fragment_offset: u24,
    fragment_length: u24,

    pub fn encode(self: Header, out: []u8) Error![]u8 {
        if (out.len < handshake_header_len) return error.Truncated;
        if (@as(usize, self.fragment_offset) + @as(usize, self.fragment_length) > @as(usize, self.length)) {
            return error.BadLength;
        }

        out[0] = @backingInt(self.msg_type);
        std.mem.writeInt(u24, out[1..][0..3], self.length, .big);
        std.mem.writeInt(u16, out[4..][0..2], self.message_seq, .big);
        std.mem.writeInt(u24, out[6..][0..3], self.fragment_offset, .big);
        std.mem.writeInt(u24, out[9..][0..3], self.fragment_length, .big);
        return out[0..handshake_header_len];
    }

    pub fn decode(buf: []const u8) Error!struct { hdr: Header, consumed: usize } {
        if (buf.len < handshake_header_len) return error.Truncated;

        const hdr = Header{
            .msg_type = @fromBackingInt(@intCast(buf[0])),
            .length = std.mem.readInt(u24, buf[1..][0..3], .big),
            .message_seq = std.mem.readInt(u16, buf[4..][0..2], .big),
            .fragment_offset = std.mem.readInt(u24, buf[6..][0..3], .big),
            .fragment_length = std.mem.readInt(u24, buf[9..][0..3], .big),
        };
        if (@as(usize, hdr.fragment_offset) + @as(usize, hdr.fragment_length) > @as(usize, hdr.length)) {
            return error.BadLength;
        }
        return .{ .hdr = hdr, .consumed = handshake_header_len };
    }
};

pub fn fragmentCount(body_len: usize, max_fragment: usize) Error!usize {
    if (max_fragment == 0) return error.BadLength;
    if (body_len > max_u24) return error.Overflow;
    if (body_len == 0) return 1;
    return (body_len + max_fragment - 1) / max_fragment;
}

pub fn fragment(
    msg_type: HandshakeType,
    message_seq: u16,
    body: []const u8,
    max_fragment: usize,
    out: []u8,
) Error![]const u8 {
    const count = try fragmentCount(body.len, max_fragment);
    const headers_len = std.math.mul(usize, count, handshake_header_len) catch return error.Overflow;
    const total_len = std.math.add(usize, headers_len, body.len) catch return error.Overflow;
    if (out.len < total_len) return error.Truncated;

    const full_len: u24 = @intCast(body.len);
    var body_off: usize = 0;
    var out_off: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const remaining = body.len - body_off;
        const take = if (body.len == 0) 0 else @min(remaining, max_fragment);
        const hdr = Header{
            .msg_type = msg_type,
            .length = full_len,
            .message_seq = message_seq,
            .fragment_offset = @intCast(body_off),
            .fragment_length = @intCast(take),
        };

        _ = try hdr.encode(out[out_off..][0..handshake_header_len]);
        out_off += handshake_header_len;
        if (take != 0) {
            @memcpy(out[out_off..][0..take], body[body_off..][0..take]);
            out_off += take;
            body_off += take;
        }
    }

    return out[0..out_off];
}

const Range = struct {
    start: usize,
    end: usize,
};

pub const Reassembler = struct {
    initialised: bool = false,
    msg_type: HandshakeType = .hello_request,
    message_seq: u16 = 0,
    length: usize = 0,
    ranges: [default_reassembler_ranges]Range = undefined,
    range_count: usize = 0,

    pub fn offer(self: *Reassembler, hdr: Header, frag: []const u8, body_buf: []u8) Error!?[]const u8 {
        const length = @as(usize, hdr.length);
        const start = @as(usize, hdr.fragment_offset);
        const frag_len = @as(usize, hdr.fragment_length);
        if (frag.len != frag_len) return error.BadLength;
        if (start + frag_len > length) return error.BadLength;
        if (body_buf.len < length) return error.Truncated;

        if (!self.initialised) {
            self.initialised = true;
            self.msg_type = hdr.msg_type;
            self.message_seq = hdr.message_seq;
            self.length = length;
            self.range_count = 0;
        } else if (self.msg_type != hdr.msg_type or
            self.message_seq != hdr.message_seq or
            self.length != length)
        {
            return error.BadLength;
        }

        if (length == 0) return body_buf[0..0];

        try self.checkOverlap(start, frag, body_buf);
        @memcpy(body_buf[start..][0..frag_len], frag);
        try self.addRange(start, start + frag_len);

        if (self.range_count == 1 and self.ranges[0].start == 0 and self.ranges[0].end == self.length) {
            return body_buf[0..self.length];
        }
        return null;
    }

    fn checkOverlap(self: *const Reassembler, start: usize, frag: []const u8, body_buf: []const u8) Error!void {
        const end = start + frag.len;
        for (self.ranges[0..self.range_count]) |r| {
            const overlap_start = @max(start, r.start);
            const overlap_end = @min(end, r.end);
            if (overlap_start >= overlap_end) continue;
            const frag_start = overlap_start - start;
            const n = overlap_end - overlap_start;
            if (!std.mem.eql(u8, body_buf[overlap_start..][0..n], frag[frag_start..][0..n])) {
                return error.FragmentOverlap;
            }
        }
    }

    fn addRange(self: *Reassembler, start: usize, end: usize) Error!void {
        if (start == end) return;

        var new_start = start;
        var new_end = end;
        var i: usize = 0;
        while (i < self.range_count) {
            const r = self.ranges[i];
            if (new_end < r.start) {
                try self.insertRange(i, .{ .start = new_start, .end = new_end });
                return;
            }
            if (new_start > r.end) {
                i += 1;
                continue;
            }

            new_start = @min(new_start, r.start);
            new_end = @max(new_end, r.end);
            self.removeRange(i);
        }

        try self.insertRange(self.range_count, .{ .start = new_start, .end = new_end });
    }

    fn insertRange(self: *Reassembler, index: usize, r: Range) Error!void {
        if (self.range_count == self.ranges.len) return error.Overflow;
        var i = self.range_count;
        while (i > index) : (i -= 1) {
            self.ranges[i] = self.ranges[i - 1];
        }
        self.ranges[index] = r;
        self.range_count += 1;
    }

    fn removeRange(self: *Reassembler, index: usize) void {
        var i = index;
        while (i + 1 < self.range_count) : (i += 1) {
            self.ranges[i] = self.ranges[i + 1];
        }
        self.range_count -= 1;
    }
};

pub fn encodeHelloVerifyRequest(cookie: []const u8, out: []u8) Error![]const u8 {
    if (cookie.len > 0xff) return error.BadLength;
    const total_len = 2 + 1 + cookie.len;
    if (out.len < total_len) return error.Truncated;

    std.mem.writeInt(u16, out[0..][0..2], dtls12_version, .big);
    out[2] = @intCast(cookie.len);
    @memcpy(out[3..][0..cookie.len], cookie);
    return out[0..total_len];
}

pub fn parseHelloVerifyRequest(body: []const u8) Error![]const u8 {
    if (body.len < 3) return error.Truncated;
    if (std.mem.readInt(u16, body[0..][0..2], .big) != dtls12_version) return error.BadLength;
    const cookie_len: usize = body[2];
    if (body.len != 3 + cookie_len) return error.BadLength;
    return body[3..][0..cookie_len];
}

const testing = std.testing;

test "header encode/decode round-trip" {
    const orig = Header{
        .msg_type = .client_hello,
        .length = 0x010203,
        .message_seq = 0x4455,
        .fragment_offset = 0x000102,
        .fragment_length = 0x000304,
    };

    var buf: [handshake_header_len]u8 = undefined;
    const encoded = try orig.encode(&buf);
    try testing.expectEqual(@as(usize, handshake_header_len), encoded.len);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x01, 0x02, 0x03, 0x44, 0x55, 0x00, 0x01, 0x02, 0x00, 0x03, 0x04 }, encoded);

    const decoded = try Header.decode(encoded);
    try testing.expectEqual(@as(usize, handshake_header_len), decoded.consumed);
    try testing.expectEqual(orig.msg_type, decoded.hdr.msg_type);
    try testing.expectEqual(orig.length, decoded.hdr.length);
    try testing.expectEqual(orig.message_seq, decoded.hdr.message_seq);
    try testing.expectEqual(orig.fragment_offset, decoded.hdr.fragment_offset);
    try testing.expectEqual(orig.fragment_length, decoded.hdr.fragment_length);
}

test "fragment 1000-byte body into 300-byte fragments and reassemble" {
    var body: [1000]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @truncate(i);

    const count = try fragmentCount(body.len, 300);
    try testing.expectEqual(@as(usize, 4), count);

    var wire: [1000 + 4 * handshake_header_len]u8 = undefined;
    const fragments = try fragment(.client_hello, 7, &body, 300, &wire);

    var reassembler = Reassembler{};
    var reassembled: [body.len]u8 = undefined;
    var off: usize = 0;
    var seen: usize = 0;
    while (off < fragments.len) {
        const decoded = try Header.decode(fragments[off..]);
        off += decoded.consumed;
        const frag_len = @as(usize, decoded.hdr.fragment_length);
        const frag = fragments[off..][0..frag_len];
        off += frag_len;
        seen += 1;

        const result = try reassembler.offer(decoded.hdr, frag, &reassembled);
        if (seen < count) {
            try testing.expect(result == null);
        } else {
            const full = result orelse return error.Incomplete;
            try testing.expectEqualSlices(u8, &body, full);
        }
    }

    try testing.expectEqual(count, seen);
}

test "HelloVerifyRequest cookie round-trip" {
    const cookie = "onyx-cookie";
    var buf: [64]u8 = undefined;
    const body = try encodeHelloVerifyRequest(cookie, &buf);

    try testing.expectEqual(@as(usize, 3 + cookie.len), body.len);
    try testing.expectEqual(@as(u8, 0xfe), body[0]);
    try testing.expectEqual(@as(u8, 0xfd), body[1]);
    try testing.expectEqual(@as(u8, cookie.len), body[2]);
    try testing.expectEqualSlices(u8, cookie, try parseHelloVerifyRequest(body));
}

test "Truncated on short buffers" {
    try testing.expectError(error.Truncated, Header.decode(&.{ 0x01, 0x00 }));

    const hdr = Header{
        .msg_type = .server_hello_done,
        .length = 0,
        .message_seq = 1,
        .fragment_offset = 0,
        .fragment_length = 0,
    };
    var short_header: [handshake_header_len - 1]u8 = undefined;
    try testing.expectError(error.Truncated, hdr.encode(&short_header));

    var short_fragment: [handshake_header_len]u8 = undefined;
    try testing.expectError(error.Truncated, fragment(.finished, 2, "abc", 2, &short_fragment));

    var short_hvr: [2]u8 = undefined;
    try testing.expectError(error.Truncated, encodeHelloVerifyRequest("x", &short_hvr));
    try testing.expectError(error.Truncated, parseHelloVerifyRequest(&.{ 0xfe, 0xfd }));
}
