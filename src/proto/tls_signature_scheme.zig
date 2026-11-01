// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 `signature_algorithms` extension inner codec (RFC 8446 §4.2.3).
//!
//! This module decodes and encodes the *inner data* of the
//! `signature_algorithms` extension only — the outer extension envelope (type
//! tag + 2-byte length) is handled by the generic extension-list codec in a
//! sibling module.  The inner data is a single `SignatureSchemeList`:
//!
//!     struct {
//!         SignatureScheme supported_signature_algorithms<2..2^16-2>;
//!     } SignatureSchemeList;
//!
//! On the wire that is a 2-byte big-endian list length, followed by that many
//! bytes of packed big-endian `u16` scheme codes; the list length must be even.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  Callers own every
//! buffer.  Every length is bounds-checked; a truncated or malformed block
//! yields `error.Truncated` rather than reading past the slice.
const std = @import("std");

/// Width of a single wire scheme field in bytes.
const scheme_len: usize = 2;

/// Width of the list-length prefix in bytes.
const list_prefix_len: usize = 2;

/// TLS 1.3 SignatureScheme registry values (RFC 8446 §4.2.3 and the IANA
/// registry).  Non-exhaustive on purpose: peers advertise schemes we do not
/// model, and those must round-trip untouched.  Use `fromInt` / `@intFromEnum`
/// to move between the wire `u16` and this enum.
pub const SignatureScheme = enum(u16) {
    /// EdDSA over edwards25519.
    ed25519 = 0x0807,
    /// ECDSA over NIST P-256 with SHA-256.
    ecdsa_secp256r1_sha256 = 0x0403,
    /// ECDSA over NIST P-384 with SHA-384 (common in CA intermediates).
    ecdsa_secp384r1_sha384 = 0x0503,
    /// RSASSA-PSS with public-key OID rsaEncryption, SHA-256.
    rsa_pss_rsae_sha256 = 0x0804,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    rsa_pkcs1_sha256 = 0x0401,
    _,

    /// Wrap a raw wire `u16` as a `SignatureScheme` (total over the enum).
    pub fn fromInt(value: u16) SignatureScheme {
        return @fromBackingInt(@intCast(value));
    }

    /// The raw wire `u16` for this scheme.
    pub fn toInt(self: SignatureScheme) u16 {
        return @backingInt(self);
    }
};

/// Errors produced while parsing or building a `signature_algorithms` body.
pub const Error = error{
    /// The block ended mid-field, declared more bytes than it carried, or had
    /// an odd-length scheme list.
    Truncated,
    /// A build target buffer ran out of room.  Matches `std`'s spelling so
    /// callers can mix our writes with `std` writers if they like.
    NoSpaceLeft,
    /// More schemes were offered than fit in the 2-byte list length field
    /// (65534 bytes => 32767 schemes).
    TooManySchemes,
};

/// Read a big-endian `u16` from the first two bytes of `b` (caller guarantees
/// `b.len >= 2`).
fn readU16(b: []const u8) u16 {
    return (@as(u16, b[0]) << 8) | @as(u16, b[1]);
}

/// Write a big-endian `u16` into the first two bytes of `out` (caller
/// guarantees `out.len >= 2`).
fn writeU16(out: []u8, value: u16) void {
    out[0] = @intCast(value >> 8);
    out[1] = @intCast(value & 0xff);
}

/// Cursor over the scheme list of a `signature_algorithms` body.  Yields each
/// offered `SignatureScheme` in wire order.  Constructed by `parse`, which
/// validates the framing up front, so iteration itself cannot fail.
pub const Iterator = struct {
    /// The scheme bytes only (the 2-byte list-length prefix already stripped).
    schemes: []const u8,
    /// Byte offset of the next scheme to yield.
    pos: usize = 0,

    /// Return the next offered scheme, or `null` once the list is exhausted.
    /// Unknown wire codes are preserved via the non-exhaustive enum.
    pub fn next(self: *Iterator) ?SignatureScheme {
        if (self.pos + scheme_len > self.schemes.len) return null;
        const v = readU16(self.schemes[self.pos..]);
        self.pos += scheme_len;
        return SignatureScheme.fromInt(v);
    }

    /// Like `next`, but yields the raw `u16` wire code instead of the enum.
    pub fn nextRaw(self: *Iterator) ?u16 {
        if (self.pos + scheme_len > self.schemes.len) return null;
        const v = readU16(self.schemes[self.pos..]);
        self.pos += scheme_len;
        return v;
    }

    /// Number of schemes remaining (does not advance the cursor).
    pub fn remaining(self: *const Iterator) usize {
        return (self.schemes.len - self.pos) / scheme_len;
    }
};

/// Parse a `signature_algorithms` body and return an `Iterator` over its
/// schemes.
///
/// Validates that the declared 2-byte list length matches the bytes present
/// and that the list is an even number of bytes.  Aliases `block`; copies
/// nothing.
pub fn parse(block: []const u8) Error!Iterator {
    if (block.len < list_prefix_len) return Error.Truncated;
    const list_len: usize = readU16(block[0..list_prefix_len]);
    const body = block[list_prefix_len..];
    if (body.len != list_len) return Error.Truncated;
    if (list_len % scheme_len != 0) return Error.Truncated;
    return Iterator{ .schemes = body };
}

/// Return `true` iff `block` offers `scheme`.  A malformed block offers
/// nothing, so returns `false` on parse failure.
pub fn offers(block: []const u8, scheme: SignatureScheme) bool {
    var it = parse(block) catch return false;
    const want = scheme.toInt();
    while (it.nextRaw()) |v| {
        if (v == want) return true;
    }
    return false;
}

/// Encode `schemes` into `out` as a `signature_algorithms` body and return the
/// written prefix of `out`.  Writes a 2-byte big-endian list length followed
/// by each scheme big-endian.
pub fn build(out: []u8, schemes: []const SignatureScheme) Error![]const u8 {
    const body_len = schemes.len * scheme_len;
    if (body_len > 0xffff) return Error.TooManySchemes;
    const total = list_prefix_len + body_len;
    if (out.len < total) return Error.NoSpaceLeft;
    writeU16(out[0..list_prefix_len], @intCast(body_len));
    var off: usize = list_prefix_len;
    for (schemes) |s| {
        writeU16(out[off..], s.toInt());
        off += scheme_len;
    }
    return out[0..total];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "build then parse round-trips [ed25519, ecdsa] in order" {
    // Arrange
    var buf: [16]u8 = undefined;
    const offered = [_]SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256 };

    // Act
    const body = try build(&buf, &offered);
    var it = try parse(body);
    const first = it.next();
    const second = it.next();
    const third = it.next();

    // Assert
    try testing.expectEqual(@as(usize, 6), body.len); // 2 len + 2*2 schemes
    try testing.expectEqual(@as(u16, 4), readU16(body[0..2])); // body length
    try testing.expectEqual(@as(?SignatureScheme, .ed25519), first);
    try testing.expectEqual(@as(?SignatureScheme, .ecdsa_secp256r1_sha256), second);
    try testing.expectEqual(@as(?SignatureScheme, null), third);
}

test "offers finds an offered scheme and misses an unoffered one" {
    // Arrange
    var buf: [16]u8 = undefined;
    const body = try build(&buf, &[_]SignatureScheme{ .ed25519, .rsa_pss_rsae_sha256 });

    // Act
    const hasEd = offers(body, .ed25519);
    const hasPss = offers(body, .rsa_pss_rsae_sha256);
    const hasEcdsa = offers(body, .ecdsa_secp256r1_sha256); // not offered

    // Assert
    try testing.expect(hasEd);
    try testing.expect(hasPss);
    try testing.expect(!hasEcdsa);
}

test "parse rejects a declared length mismatch" {
    // Arrange: declares 4 bytes of schemes but only carries 2.
    const block = [_]u8{ 0x00, 0x04, 0x08, 0x07 };

    // Act
    const result = parse(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "parse rejects an odd-length scheme list" {
    // Arrange: declares 3 bytes of schemes (odd, cannot be whole u16s).
    const block = [_]u8{ 0x00, 0x03, 0x08, 0x07, 0x04 };

    // Act
    const result = parse(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "parse rejects a truncated block with no full length prefix" {
    // Arrange
    const block = [_]u8{0x00};

    // Act
    const result = parse(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "unknown scheme code is preserved through parse" {
    // Arrange: a vendor/private scheme not modeled by the enum.
    const unknown: u16 = 0xFE00;
    var buf: [8]u8 = undefined;
    const body = try build(&buf, &[_]SignatureScheme{SignatureScheme.fromInt(unknown)});

    // Act
    var it = try parse(body);
    const got = it.nextRaw();
    const exhausted = it.nextRaw();

    // Assert
    try testing.expectEqual(@as(?u16, unknown), got);
    try testing.expectEqual(@as(?u16, null), exhausted);
}

test "build reports NoSpaceLeft when the buffer is too small" {
    // Arrange
    var tiny: [3]u8 = undefined; // needs 6 for two schemes

    // Act
    const result = build(&tiny, &[_]SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256 });

    // Assert
    try testing.expectError(Error.NoSpaceLeft, result);
}

test "offers returns false on a malformed block" {
    // Arrange: length prefix claims more than is present.
    const block = [_]u8{ 0x00, 0x08, 0x08, 0x07 };

    // Act
    const found = offers(&block, .ed25519);

    // Assert
    try testing.expect(!found);
}

test "empty scheme list round-trips" {
    // Arrange
    var buf: [4]u8 = undefined;

    // Act
    const body = try build(&buf, &[_]SignatureScheme{});
    var it = try parse(body);
    const first = it.next();

    // Assert
    try testing.expectEqual(@as(usize, 2), body.len);
    try testing.expectEqual(@as(usize, 0), it.remaining());
    try testing.expectEqual(@as(?SignatureScheme, null), first);
}

test "SignatureScheme enum values match the IANA wire codes" {
    // Arrange / Act / Assert
    try testing.expectEqual(@as(u16, 0x0807), SignatureScheme.ed25519.toInt());
    try testing.expectEqual(@as(u16, 0x0403), SignatureScheme.ecdsa_secp256r1_sha256.toInt());
    try testing.expectEqual(@as(u16, 0x0804), SignatureScheme.rsa_pss_rsae_sha256.toInt());
    try testing.expectEqual(@as(u16, 0x0401), SignatureScheme.rsa_pkcs1_sha256.toInt());
}
