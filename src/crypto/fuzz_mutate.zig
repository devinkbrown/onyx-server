// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic, structure-aware mutation helpers shared by the engine-level
//! fuzz harnesses (`tls_engine_fuzz.zig`, `proto/quic_fuzz.zig`,
//! `proto/dtls_fuzz.zig`).
//!
//! Everything here is driven by a caller-seeded `std.Random`, so a given seed
//! always yields the same mutation schedule. The helpers only rearrange bytes in
//! caller-provided buffers; they never allocate.
//!
//! Two layers:
//!   * `mutateRaw` applies 1..4 byte-level operators (bit flip, interesting
//!     byte, interesting 16/24-bit length overwrite, truncate, insert, delete,
//!     duplicate) to a buffer.
//!   * `Hello` parses a TLS/DTLS ClientHello or ServerHello body into its
//!     fixed fields and extension list, and `mutateHello` performs
//!     extension-level operators (drop, duplicate, reorder, body mutation,
//!     truncation, foreign insertion, HRR sentinel random) and re-encodes the
//!     message with CORRECT length prefixes. Correct framing is the point: it
//!     carries the mutation past the outer length checks into the per-extension
//!     parsers, where random bytes rarely reach.
const std = @import("std");

pub const Random = std.Random;

/// Values that tend to sit on bounds checks.
const interesting_u8 = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x16, 0x17, 0x20, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xfe, 0xff };
const interesting_u16 = [_]u16{ 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x00ff, 0x0100, 0x3fff, 0x4000, 0x4001, 0x7fff, 0x8000, 0xfffe, 0xffff };

/// Apply 1..4 byte-level mutations to `buf[0..len]` in place, growing into
/// `buf[len..]` when an operator inserts. Returns the new length (<= buf.len).
pub fn mutateRaw(rand: Random, buf: []u8, len_in: usize) usize {
    var len = @min(len_in, buf.len);
    const ops = rand.intRangeAtMost(usize, 1, 4);
    var i: usize = 0;
    while (i < ops) : (i += 1) len = mutateOnce(rand, buf, len);
    return len;
}

fn mutateOnce(rand: Random, buf: []u8, len: usize) usize {
    if (len == 0) {
        // Grow an empty input with a few random bytes.
        const n = @min(buf.len, rand.intRangeAtMost(usize, 1, 8));
        rand.bytes(buf[0..n]);
        return n;
    }
    switch (rand.uintLessThan(u8, 9)) {
        0 => { // bit flip
            const p = rand.uintLessThan(usize, len);
            buf[p] ^= @as(u8, 1) << rand.int(u3);
        },
        1 => { // interesting byte
            buf[rand.uintLessThan(usize, len)] = interesting_u8[rand.uintLessThan(usize, interesting_u8.len)];
        },
        2 => { // random byte
            buf[rand.uintLessThan(usize, len)] = rand.int(u8);
        },
        3 => { // interesting big-endian u16 (length / type fields)
            if (len >= 2) {
                const p = rand.uintLessThan(usize, len - 1);
                std.mem.writeInt(u16, buf[p..][0..2], interesting_u16[rand.uintLessThan(usize, interesting_u16.len)], .big);
            }
        },
        4 => { // interesting big-endian u24 (handshake lengths)
            if (len >= 3) {
                const p = rand.uintLessThan(usize, len - 2);
                const v: u24 = switch (rand.uintLessThan(u8, 4)) {
                    0 => 0,
                    1 => 0xffffff,
                    2 => @intCast(@min(len, 0xffffff)),
                    else => @intCast(@min(len + 1, 0xffffff)),
                };
                std.mem.writeInt(u24, buf[p..][0..3], v, .big);
            }
        },
        5 => { // truncate
            return rand.uintLessThan(usize, len);
        },
        6 => { // insert random bytes
            const n = @min(buf.len - len, rand.intRangeAtMost(usize, 1, 16));
            if (n == 0) return len;
            const p = rand.uintAtMost(usize, len);
            std.mem.copyBackwards(u8, buf[p + n .. len + n], buf[p..len]);
            rand.bytes(buf[p .. p + n]);
            return len + n;
        },
        7 => { // delete a range
            const p = rand.uintLessThan(usize, len);
            const n = @min(len - p, rand.intRangeAtMost(usize, 1, 16));
            std.mem.copyForwards(u8, buf[p .. len - n], buf[p + n .. len]);
            return len - n;
        },
        else => { // duplicate a range in place (shifts the tail)
            const p = rand.uintLessThan(usize, len);
            const n = @min(@min(len - p, buf.len - len), rand.intRangeAtMost(usize, 1, 32));
            if (n == 0) return len;
            std.mem.copyBackwards(u8, buf[p + n .. len + n], buf[p..len]);
            return len + n;
        },
    }
    return len;
}

/// Split `total` bytes into random chunk boundaries for transport-level
/// delivery: fills `cuts` with strictly increasing end offsets, the last one
/// always `total`. Returns the number of chunks (>= 1).
pub fn randomCuts(rand: Random, total: usize, cuts: []usize) usize {
    std.debug.assert(cuts.len > 0);
    if (total == 0) {
        cuts[0] = 0;
        return 1;
    }
    var n: usize = 0;
    var pos: usize = 0;
    // One-shot delivery a quarter of the time; otherwise random splits,
    // including 1-byte dribbles.
    const one_shot = rand.uintLessThan(u8, 4) == 0;
    while (pos < total and n + 1 < cuts.len and !one_shot) {
        const step = switch (rand.uintLessThan(u8, 3)) {
            0 => 1,
            1 => rand.intRangeAtMost(usize, 1, 16),
            else => rand.intRangeAtMost(usize, 1, @max(1, total / 2)),
        };
        pos = @min(total, pos + step);
        cuts[n] = pos;
        n += 1;
    }
    if (n == 0 or cuts[n - 1] != total) {
        cuts[n] = total;
        n += 1;
    }
    return n;
}

pub const max_extensions = 48;

/// A parsed Client/ServerHello body (TLS 1.3 or DTLS layout), borrowing the
/// source bytes. `prefix` is everything before the extensions block (version,
/// random, session id, cookie (DTLS 1.2 only), suites, compression).
pub const Hello = struct {
    prefix: []const u8,
    exts: [max_extensions]Ext = undefined,
    n: usize = 0,

    pub const Ext = struct { typ: u16, body: []const u8 };

    pub const Kind = enum { client_hello, server_hello, dtls_client_hello };

    /// Parse a hello BODY (no handshake header). Returns null when the body is
    /// not a well-formed hello (the caller then falls back to raw mutation).
    pub fn parse(kind: Kind, body: []const u8) ?Hello {
        var p: usize = 2 + 32; // legacy_version + random
        if (body.len < p + 1) return null;
        p += 1 + @as(usize, body[p]); // session id
        if (kind == .dtls_client_hello) {
            if (body.len < p + 1) return null;
            p += 1 + @as(usize, body[p]); // cookie
        }
        switch (kind) {
            .client_hello, .dtls_client_hello => {
                if (body.len < p + 2) return null;
                p += 2 + @as(usize, std.mem.readInt(u16, body[p..][0..2], .big));
                if (body.len < p + 1) return null;
                p += 1 + @as(usize, body[p]);
            },
            .server_hello => p += 3, // suite + compression
        }
        if (body.len < p + 2) return null;
        const ext_len = std.mem.readInt(u16, body[p..][0..2], .big);
        if (body.len != p + 2 + ext_len) return null;
        var h: Hello = .{ .prefix = body[0..p] };
        var e = p + 2;
        while (e < body.len) {
            if (body.len - e < 4 or h.n == max_extensions) return null;
            const typ = std.mem.readInt(u16, body[e..][0..2], .big);
            const l = std.mem.readInt(u16, body[e + 2 ..][0..2], .big);
            if (body.len - e - 4 < l) return null;
            h.exts[h.n] = .{ .typ = typ, .body = body[e + 4 .. e + 4 + l] };
            h.n += 1;
            e += 4 + l;
        }
        return h;
    }

    /// Re-encode with correct lengths into `out`. Returns null if it does not fit.
    pub fn encode(self: *const Hello, out: []u8) ?[]u8 {
        var w: usize = 0;
        if (out.len < self.prefix.len + 2) return null;
        @memcpy(out[0..self.prefix.len], self.prefix);
        w = self.prefix.len + 2;
        for (self.exts[0..self.n]) |x| {
            if (out.len - w < 4 + x.body.len or x.body.len > 0xffff) return null;
            std.mem.writeInt(u16, out[w..][0..2], x.typ, .big);
            std.mem.writeInt(u16, out[w + 2 ..][0..2], @intCast(x.body.len), .big);
            @memcpy(out[w + 4 ..][0..x.body.len], x.body);
            w += 4 + x.body.len;
        }
        const ext_total = w - self.prefix.len - 2;
        if (ext_total > 0xffff) return null;
        std.mem.writeInt(u16, out[self.prefix.len..][0..2], @intCast(ext_total), .big);
        return out[0..w];
    }
};

/// RFC 8446 §4.1.3 HelloRetryRequest sentinel random (SHA-256("HelloRetryRequest")).
pub const hrr_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// Extension types worth injecting (TLS 1.3 + QUIC + DTLS-SRTP + ECH + PSK).
const foreign_ext_types = [_]u16{ 0, 5, 10, 11, 13, 14, 16, 18, 21, 27, 28, 34, 35, 41, 42, 43, 44, 45, 47, 49, 50, 51, 57, 0x0039, 0x4469, 0xfe0d, 0xff01, 0xffff };

/// Structure-aware mutation of a hello body (`kind` layout). Writes the mutated
/// body into `out` and returns it. `scratch` backs mutated extension bodies and
/// must be at least as large as the source. Falls back to raw mutation when the
/// source does not parse or the re-encode does not fit.
pub fn mutateHello(rand: Random, kind: Hello.Kind, body: []const u8, out: []u8, scratch: []u8) []u8 {
    var h = Hello.parse(kind, body) orelse return rawCopyMutate(rand, body, out);
    var sw: usize = 0; // scratch write cursor
    var prefix_copy: []u8 = &.{};
    const ops = rand.intRangeAtMost(usize, 1, 3);
    var i: usize = 0;
    while (i < ops) : (i += 1) {
        switch (rand.uintLessThan(u8, 9)) {
            0 => if (h.n > 0) { // drop an extension
                const k = rand.uintLessThan(usize, h.n);
                std.mem.copyForwards(Hello.Ext, h.exts[k .. h.n - 1], h.exts[k + 1 .. h.n]);
                h.n -= 1;
            },
            1 => if (h.n > 0 and h.n < max_extensions) { // duplicate an extension
                h.exts[h.n] = h.exts[rand.uintLessThan(usize, h.n)];
                h.n += 1;
            },
            2 => if (h.n > 1) { // swap two extensions (PSK must be last, etc.)
                const a = rand.uintLessThan(usize, h.n);
                const b = rand.uintLessThan(usize, h.n);
                std.mem.swap(Hello.Ext, &h.exts[a], &h.exts[b]);
            },
            3, 4 => if (h.n > 0) { // mutate one extension body (length re-fixed)
                const k = rand.uintLessThan(usize, h.n);
                const src = h.exts[k].body;
                const room = scratch.len - sw;
                if (room < src.len + 32) continue;
                const dst = scratch[sw .. sw + src.len + 32];
                @memcpy(dst[0..src.len], src);
                const nl = mutateRaw(rand, dst, src.len);
                h.exts[k].body = dst[0..nl];
                sw += src.len + 32;
            },
            5 => if (h.n > 0) { // truncate one extension body
                const k = rand.uintLessThan(usize, h.n);
                h.exts[k].body = h.exts[k].body[0..rand.uintAtMost(usize, h.exts[k].body.len)];
            },
            6 => if (h.n < max_extensions) { // insert a foreign/unknown extension
                const blen = rand.uintAtMost(usize, @min(24, scratch.len - sw));
                const dst = scratch[sw .. sw + blen];
                rand.bytes(dst);
                sw += blen;
                const at = rand.uintAtMost(usize, h.n);
                std.mem.copyBackwards(Hello.Ext, h.exts[at + 1 .. h.n + 1], h.exts[at..h.n]);
                h.exts[at] = .{ .typ = foreign_ext_types[rand.uintLessThan(usize, foreign_ext_types.len)], .body = dst };
                h.n += 1;
            },
            7 => { // mutate the fixed prefix (version, random, sid, suites...)
                if (scratch.len - sw < h.prefix.len + 32) continue;
                const dst = scratch[sw .. sw + h.prefix.len + 32];
                @memcpy(dst[0..h.prefix.len], h.prefix);
                // Byte-level only (no insert/delete) half the time so the prefix
                // still lines up with the extension block.
                const nl = if (rand.boolean()) blk: {
                    var t: usize = 0;
                    while (t < 2) : (t += 1) dst[rand.uintLessThan(usize, h.prefix.len)] ^= rand.int(u8) | 1;
                    break :blk h.prefix.len;
                } else mutateRaw(rand, dst, h.prefix.len);
                prefix_copy = dst[0..nl];
                h.prefix = prefix_copy;
                sw += h.prefix.len + 32;
            },
            else => { // HRR sentinel random (ServerHello) / zero random (ClientHello)
                if (h.prefix.len < 34 or scratch.len - sw < h.prefix.len) continue;
                const dst = scratch[sw .. sw + h.prefix.len];
                @memcpy(dst, h.prefix);
                if (kind == .server_hello) @memcpy(dst[2..34], &hrr_random) else @memset(dst[2..34], 0);
                h.prefix = dst;
                sw += dst.len;
            },
        }
    }
    const enc = h.encode(out) orelse return rawCopyMutate(rand, body, out);
    // Occasionally stack raw noise on top of the well-framed result.
    if (rand.uintLessThan(u8, 5) == 0) {
        const extra = @min(out.len - enc.len, 16);
        return out[0..mutateRaw(rand, out[0 .. enc.len + extra], enc.len)];
    }
    return enc;
}

fn rawCopyMutate(rand: Random, body: []const u8, out: []u8) []u8 {
    const n = @min(body.len, out.len);
    @memcpy(out[0..n], body[0..n]);
    return out[0..mutateRaw(rand, out, n)];
}

test "fuzz_mutate: Hello parse/encode round-trips and mutation stays in bounds" {
    // A minimal well-formed ClientHello body with two extensions.
    var body: [128]u8 = undefined;
    var w: usize = 0;
    body[0] = 3;
    body[1] = 3;
    w = 2;
    @memset(body[w .. w + 32], 0xab);
    w += 32;
    body[w] = 0; // sid
    w += 1;
    std.mem.writeInt(u16, body[w..][0..2], 2, .big);
    w += 2;
    body[w] = 0x13;
    body[w + 1] = 0x01;
    w += 2;
    body[w] = 1;
    body[w + 1] = 0;
    w += 2;
    const exts = [_]u8{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0a, 0x00, 0x00 };
    std.mem.writeInt(u16, body[w..][0..2], exts.len, .big);
    w += 2;
    @memcpy(body[w .. w + exts.len], &exts);
    w += exts.len;

    const h = Hello.parse(.client_hello, body[0..w]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), h.n);
    var out: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, body[0..w], h.encode(&out).?);

    var prng = std.Random.DefaultPrng.init(1);
    var scratch: [1024]u8 = undefined;
    var big: [512]u8 = undefined;
    for (0..2000) |_| {
        const m = mutateHello(prng.random(), .client_hello, body[0..w], &big, &scratch);
        try std.testing.expect(m.len <= big.len);
        var cuts: [16]usize = undefined;
        const n = randomCuts(prng.random(), m.len, &cuts);
        try std.testing.expectEqual(m.len, cuts[n - 1]);
    }
}
