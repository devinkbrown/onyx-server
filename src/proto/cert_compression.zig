// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 8879 TLS Certificate Compression — the pieces shared by the send and
//! receive paths: the algorithm registry, the ClientHello `compress_certificate`
//! (extension 27) negotiation, and the zlib (RFC 1950) codec built on the
//! in-tree `std.compress.flate` (the same compressor `permessage_deflate.zig`
//! uses, but in its `.zlib` container mode rather than `.raw`).
//!
//! Only **zlib(1)** is producible: Zig 0.16's std has no brotli, and its zstd is
//! decompress-only — so `pickSupported` accepts zlib and ignores brotli/zstd.
//!
//! Security (RFC 8879 §6 — why this is not CRIME/BREACH): the Certificate
//! message is fixed server data, not an attacker-adjacent secret concatenated
//! with chosen plaintext, so compressing it leaks nothing. That reasoning does
//! NOT extend to TLS-level record compression, which stays disabled.
//!
//! Pure logic + allocation: no sockets, no clock, no RNG. Callers own every
//! returned buffer. The decompressor carries the mandatory §4/§5 bomb guard.

const std = @import("std");
const flate = std.compress.flate;
const Allocator = std.mem.Allocator;

pub const Error = error{
    /// The zlib compressor failed to produce a stream (e.g. writer OOM).
    CompressFailed,
    /// The compressed stream was not valid zlib / could not be inflated.
    DecompressFailed,
    /// A decompression-bomb guard tripped: the declared length was zero or
    /// above the policy cap, the stream over-produced past the declared length,
    /// or the inflated size did not match the declared length exactly.
    CertBomb,
} || Allocator.Error;

/// The `compress_certificate` extension code point (RFC 8879 §3).
pub const extension_type: u16 = 27;

/// The `compressed_certificate` handshake message type (RFC 8879 §5).
pub const handshake_type: u8 = 25;

/// RFC 8879 §7.3 CertificateCompressionAlgorithm registry. Non-exhaustive: a
/// peer may advertise algorithms we neither produce nor accept.
pub const Algorithm = enum(u16) {
    zlib = 1,
    brotli = 2,
    zstd = 3,
    _,

    pub fn toInt(self: Algorithm) u16 {
        return @backingInt(self);
    }
};

/// Upper bound on a *declared* uncompressed Certificate body (the bomb guard's
/// pre-allocation cap, RFC 8879 §4). 64 KiB comfortably covers an RSA chain
/// with intermediates plus embedded SCT/OCSP data; `writeHandshake`'s own u24
/// body limit is far larger, so this is the binding policy limit on receive.
pub const max_uncompressed_len: usize = 64 * 1024;

/// Parse a ClientHello `compress_certificate` extension body and return the
/// first algorithm we can *produce* — only zlib. The body is
/// `uint8 algorithms_length (=2n)` followed by `n × uint16 algorithm`. A
/// malformed, empty, or odd-length vector, or one that lists only algorithms we
/// cannot produce, yields `null` (⇒ the server simply sends a plain Certificate).
pub fn pickSupported(ext_data: []const u8) ?Algorithm {
    if (ext_data.len < 1) return null;
    const list_len = ext_data[0];
    if (list_len == 0 or list_len % 2 != 0) return null;
    if (1 + @as(usize, list_len) != ext_data.len) return null;
    var i: usize = 1;
    while (i + 2 <= ext_data.len) : (i += 2) {
        const alg = std.mem.readInt(u16, ext_data[i..][0..2], .big);
        if (alg == Algorithm.zlib.toInt()) return .zlib;
    }
    return null;
}

/// zlib-compress `body` (RFC 1950 container: 2-byte header + DEFLATE + Adler-32).
/// Caller owns the returned slice. Never mutates `body`.
pub fn deflateZlib(allocator: Allocator, body: []const u8) Error![]u8 {
    // Seed capacity with a rough estimate; the Allocating writer grows as needed.
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, body.len / 2 + 64);
    defer out.deinit();

    const window = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window);

    var comp = flate.Compress.init(&out.writer, window, .zlib, flate.Compress.Options.level_6) catch
        return error.CompressFailed;
    comp.writer.writeAll(body) catch return error.CompressFailed;
    comp.finish() catch return error.CompressFailed;

    return allocator.dupe(u8, out.writer.buffered());
}

/// zlib-decompress `compressed` under the RFC 8879 §4/§5 three-layer bomb guard:
///   1. reject a declared length of 0 or above `max_uncompressed_len` *before*
///      allocating anything,
///   2. cap actual output at `declared_len` (over-production ⇒ `CertBomb`),
///   3. require the inflated size to equal `declared_len` exactly.
/// `declared_len` is the message's `uncompressed_length` field. Caller owns the
/// returned slice.
pub fn inflateZlib(allocator: Allocator, compressed: []const u8, declared_len: usize) Error![]u8 {
    if (declared_len == 0 or declared_len > max_uncompressed_len) return error.CertBomb;

    var in: std.Io.Reader = .fixed(compressed);
    const window = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window);

    var decomp = flate.Decompress.init(&in, .zlib, window);
    const decoded = decomp.reader.allocRemaining(allocator, .limited(declared_len + 1)) catch |err| switch (err) {
        error.StreamTooLong => return error.CertBomb,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.DecompressFailed,
    };
    errdefer allocator.free(decoded);
    if (decoded.len != declared_len) return error.CertBomb;
    return decoded;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "pickSupported selects zlib and ignores brotli/zstd" {
    // {len=2, zlib}
    try testing.expectEqual(@as(?Algorithm, .zlib), pickSupported(&.{ 0x02, 0x00, 0x01 }));
    // {len=6, brotli, zstd, zlib} — zlib present anywhere is enough
    try testing.expectEqual(@as(?Algorithm, .zlib), pickSupported(&.{ 0x06, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01 }));
    // brotli only → null (cannot produce)
    try testing.expectEqual(@as(?Algorithm, null), pickSupported(&.{ 0x02, 0x00, 0x02 }));
    // zstd only → null
    try testing.expectEqual(@as(?Algorithm, null), pickSupported(&.{ 0x02, 0x00, 0x03 }));
}

test "pickSupported rejects malformed vectors" {
    try testing.expectEqual(@as(?Algorithm, null), pickSupported(&.{})); // empty
    try testing.expectEqual(@as(?Algorithm, null), pickSupported(&.{0x00})); // len=0
    try testing.expectEqual(@as(?Algorithm, null), pickSupported(&.{ 0x03, 0x00, 0x01, 0x00 })); // odd list_len
    try testing.expectEqual(@as(?Algorithm, null), pickSupported(&.{ 0x04, 0x00, 0x01 })); // length mismatch
    try testing.expectEqual(@as(?Algorithm, null), pickSupported(&.{ 0x02, 0x00 })); // truncated
}

test "deflateZlib then inflateZlib round-trips a certificate-shaped body" {
    const alloc = testing.allocator;
    // Repetitive DER-ish bytes so compression clearly shrinks.
    var body: [1024]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast((i * 7) % 251);
    // Duplicate a prefix so there is real redundancy to exploit.
    @memcpy(body[512..1024], body[0..512]);

    const compressed = try deflateZlib(alloc, &body);
    defer alloc.free(compressed);
    try testing.expect(compressed.len < body.len);
    try testing.expectEqual(@as(u8, 0x78), compressed[0]); // RFC 1950 zlib header

    const restored = try inflateZlib(alloc, compressed, body.len);
    defer alloc.free(restored);
    try testing.expectEqualSlices(u8, &body, restored);
}

test "inflateZlib rejects a declared length above the cap before allocating" {
    const alloc = testing.allocator;
    const compressed = try deflateZlib(alloc, "small");
    defer alloc.free(compressed);
    try testing.expectError(error.CertBomb, inflateZlib(alloc, compressed, max_uncompressed_len + 1));
    try testing.expectError(error.CertBomb, inflateZlib(alloc, compressed, 0));
}

test "inflateZlib caps output at the declared length (bomb) and requires exact match" {
    const alloc = testing.allocator;
    // A highly compressible body: 8 KiB of zeros deflates to a handful of bytes.
    const bomb = try alloc.alloc(u8, 8 * 1024);
    defer alloc.free(bomb);
    @memset(bomb, 0);
    const compressed = try deflateZlib(alloc, bomb);
    defer alloc.free(compressed);

    // Understating the declared length trips the over-production cap.
    try testing.expectError(error.CertBomb, inflateZlib(alloc, compressed, 100));
    // Overstating it (still ≤ cap) trips the exact-length check.
    try testing.expectError(error.CertBomb, inflateZlib(alloc, compressed, bomb.len + 1));
    // The exact length succeeds.
    const ok = try inflateZlib(alloc, compressed, bomb.len);
    defer alloc.free(ok);
    try testing.expectEqual(bomb.len, ok.len);
}

test "inflateZlib rejects a non-zlib stream" {
    const alloc = testing.allocator;
    try testing.expectError(error.DecompressFailed, inflateZlib(alloc, "not a zlib stream at all", 32));
}

test "deflateZlib expands tiny incompressible input (writeCertificate fallback premise)" {
    // A handful of high-entropy bytes cannot beat zlib's fixed header + Adler-32
    // overhead, so the compressed form is larger than the input — which is
    // exactly when tls_server's `writeCertificate` keeps the plain Certificate
    // instead of a CompressedCertificate. This nails down that fallback premise
    // deterministically (real certs, by contrast, always deflate smaller).
    const alloc = testing.allocator;
    const tiny = [_]u8{ 0x9e, 0x37, 0x79, 0xb1 };
    const compressed = try deflateZlib(alloc, &tiny);
    defer alloc.free(compressed);
    try testing.expect(compressed.len >= tiny.len);
}
