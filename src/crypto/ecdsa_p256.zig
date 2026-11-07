// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ECDSA over NIST P-256 with SHA-256 for Onyx Server's TLS and X.509 surfaces.
//!
//! This module wraps Zig 0.16's `std.crypto.sign.ecdsa.EcdsaP256Sha256`,
//! exposing the curve that TLS 1.2/1.3 ECDHE_ECDSA cipher suites and ECDSA
//! X.509 certificates require. It adds:
//!
//!   * a `bool`-returning `verify` that swallows the verifier error set,
//!   * SEC1 uncompressed public-key parsing (`0x04 || X32 || Y32`), and
//!   * an explicit ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` codec that
//!     applies the DER INTEGER minimal-length and sign-bit (leading 0x00)
//!     rules used by certificate and TLS signature encodings.
//!
//! Everything is `std.crypto`-only: no I/O and no clock. `sign()` uses the
//! primitive's deterministic path (null noise), which yields RFC 6979-style
//! reproducible signatures with no entropy dependency.

const std = @import("std");

/// Backing primitive: ECDSA / P-256 / SHA-256.
const Impl = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// -- Re-exported types -------------------------------------------------------

pub const PublicKey = Impl.PublicKey;
pub const SecretKey = Impl.SecretKey;
pub const KeyPair = Impl.KeyPair;
pub const Signature = Impl.Signature;

/// Byte length of a raw (r || s) signature: two 32-byte big-endian scalars.
pub const raw_signature_length = Impl.Signature.encoded_length;

/// Byte length of an uncompressed SEC1 point: 0x04 || X(32) || Y(32).
pub const sec1_uncompressed_length = Impl.PublicKey.uncompressed_sec1_encoded_length;

/// Scalar size in bytes (32 for P-256).
const scalar_len = raw_signature_length / 2;

/// SEC1 tag byte marking an uncompressed point.
const sec1_uncompressed_tag: u8 = 0x04;

// -- Errors ------------------------------------------------------------------

pub const DerError = error{
    /// The DER bytes are not a well-formed SEQUENCE{INTEGER,INTEGER}.
    InvalidDerEncoding,
    /// An INTEGER value does not fit in a P-256 scalar.
    ScalarTooLong,
    /// The provided output buffer is too small for the encoding.
    NoSpaceLeft,
};

pub const Sec1Error = error{
    /// Wrong length for an uncompressed SEC1 point.
    InvalidSec1Length,
    /// First byte was not the uncompressed-point tag (0x04).
    InvalidSec1Prefix,
    /// The (X, Y) pair is not a valid point on P-256.
    InvalidSec1Point,
};

// -- Secret-key hygiene ------------------------------------------------------

/// Securely zero a P-256 secret scalar in place. The std `SecretKey` is a plain
/// value type with no destructor, so every holder of one must call this (or
/// `wipeKeyPair`) when the scalar is no longer needed.
pub fn wipeSecretKey(sk: *SecretKey) void {
    std.crypto.secureZero(u8, &sk.bytes);
}

/// Securely zero the secret half of `kp` in place. The public key is left
/// intact so callers may still read it after wiping.
pub fn wipeKeyPair(kp: *KeyPair) void {
    wipeSecretKey(&kp.secret_key);
}

// -- Signing / verification --------------------------------------------------

/// Sign `msg` with `key_pair`. Uses the primitive's deterministic (null-noise)
/// path, so the signature is reproducible and requires no entropy source.
pub fn sign(msg: []const u8, key_pair: KeyPair) !Signature {
    return key_pair.sign(msg, null);
}

/// Verify `sig` over `msg` against `public_key`. Returns `true` on success;
/// any verification or decoding error from the primitive maps to `false`.
pub fn verify(sig: Signature, msg: []const u8, public_key: PublicKey) bool {
    sig.verify(msg, public_key) catch return false;
    return true;
}

/// SHA-256 digest length (the P-256/SHA-256 pre-hash size).
pub const prehash_len = std.crypto.hash.sha2.Sha256.digest_length;

/// Verify `sig` against an already-computed SHA-256 `msg_hash` and `public_key`.
/// Equivalent to `verify(sig, m, pk)` when `msg_hash = SHA-256(m)`, but lets a
/// caller that maintains a running transcript hash (e.g. the TLS/DTLS 1.2
/// CertificateVerify, whose signature covers the raw handshake transcript)
/// verify without re-materialising those bytes. Returns `true` on success; any
/// verification error maps to `false`.
pub fn verifyPrehashed(sig: Signature, msg_hash: [prehash_len]u8, public_key: PublicKey) bool {
    sig.verifyPrehashed(msg_hash, public_key) catch return false;
    return true;
}

// -- SEC1 public-key parsing -------------------------------------------------

/// Parse an uncompressed SEC1 point (`0x04 || X32 || Y32`) into a `PublicKey`.
pub fn parsePublicKeySec1(bytes: []const u8) Sec1Error!PublicKey {
    if (bytes.len != sec1_uncompressed_length) return error.InvalidSec1Length;
    if (bytes[0] != sec1_uncompressed_tag) return error.InvalidSec1Prefix;
    return Impl.PublicKey.fromSec1(bytes) catch error.InvalidSec1Point;
}

// -- DER signature codec -----------------------------------------------------

const der_integer_tag: u8 = 0x02;
const der_sequence_tag: u8 = 0x30;

/// Length of the minimal DER INTEGER encoding (sans tag) of `scalar`:
/// leading zero bytes are stripped, and a single 0x00 prefix is added when
/// the high bit of the leading content byte is set (to keep the value
/// positive), per X.690 DER rules.
fn derIntegerLen(scalar: *const [scalar_len]u8) usize {
    var first: usize = 0;
    while (first < scalar_len - 1 and scalar[first] == 0) first += 1;
    const content = scalar_len - first;
    return content + @intFromBool(scalar[first] & 0x80 != 0);
}

/// Write the DER INTEGER (tag + length + content) for `scalar` at `buf`,
/// returning the number of bytes written. `buf` must hold the full integer.
fn writeDerInteger(scalar: *const [scalar_len]u8, buf: []u8) usize {
    var first: usize = 0;
    while (first < scalar_len - 1 and scalar[first] == 0) first += 1;
    const needs_pad = scalar[first] & 0x80 != 0;
    const content_len = (scalar_len - first) + @intFromBool(needs_pad);

    buf[0] = der_integer_tag;
    buf[1] = @intCast(content_len);
    var pos: usize = 2;
    if (needs_pad) {
        buf[pos] = 0;
        pos += 1;
    }
    @memcpy(buf[pos .. pos + (scalar_len - first)], scalar[first..]);
    return pos + (scalar_len - first);
}

/// Encode `sig` as ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` into `out`,
/// returning the populated prefix slice. P-256 r/s always fit a 1-byte length,
/// so the SEQUENCE length stays in short form.
pub fn signatureToDer(sig: Signature, out: []u8) DerError![]const u8 {
    const r = sig.r;
    const s = sig.s;

    const r_total = 2 + derIntegerLen(&r);
    const s_total = 2 + derIntegerLen(&s);
    const body_len = r_total + s_total;
    const total = 2 + body_len;
    if (out.len < total) return error.NoSpaceLeft;

    out[0] = der_sequence_tag;
    out[1] = @intCast(body_len);
    var pos: usize = 2;
    pos += writeDerInteger(&r, out[pos..]);
    pos += writeDerInteger(&s, out[pos..]);
    return out[0..pos];
}

/// Read one DER INTEGER at `der[pos]`, returning the right-aligned 32-byte
/// big-endian scalar and the position just past the INTEGER.
fn readDerInteger(der: []const u8, pos: usize) DerError!struct { scalar: [scalar_len]u8, next: usize } {
    if (pos + 2 > der.len) return error.InvalidDerEncoding;
    if (der[pos] != der_integer_tag) return error.InvalidDerEncoding;

    const len = der[pos + 1];
    if (len & 0x80 != 0) return error.InvalidDerEncoding; // long form not used by P-256
    if (len == 0) return error.InvalidDerEncoding;
    const content_start = pos + 2;
    const content_end = content_start + len;
    if (content_end > der.len) return error.InvalidDerEncoding;

    var content = der[content_start..content_end];
    // A single leading 0x00 is only allowed to clear the sign bit.
    if (content.len > 1 and content[0] == 0) {
        if (content[1] & 0x80 == 0) return error.InvalidDerEncoding;
        content = content[1..];
    } else if (content[0] & 0x80 != 0) {
        return error.InvalidDerEncoding; // negative integer is invalid here
    }
    if (content.len > scalar_len) return error.ScalarTooLong;

    var scalar = @as([scalar_len]u8, @splat(0));
    @memcpy(scalar[scalar_len - content.len ..], content);
    return .{ .scalar = scalar, .next = content_end };
}

/// Decode an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` into a `Signature`.
pub fn signatureFromDer(der: []const u8) DerError!Signature {
    if (der.len < 2) return error.InvalidDerEncoding;
    if (der[0] != der_sequence_tag) return error.InvalidDerEncoding;

    const body_len = der[1];
    if (body_len & 0x80 != 0) return error.InvalidDerEncoding; // long form not expected
    if (2 + @as(usize, body_len) != der.len) return error.InvalidDerEncoding;

    const r = try readDerInteger(der, 2);
    const s = try readDerInteger(der, r.next);
    if (s.next != der.len) return error.InvalidDerEncoding; // trailing garbage

    return Signature.fromBytes(r.scalar ++ s.scalar);
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

test "sign then verify round-trips to true" {
    // Arrange
    const kp = KeyPair.generate(testing.io);
    const msg = "onyx ecdsa p256 message";

    // Act
    const sig = try sign(msg, kp);
    const ok = verify(sig, msg, kp.public_key);

    // Assert
    try testing.expect(ok);
}

test "verifyPrehashed agrees with verify over the same message" {
    // Arrange
    const kp = KeyPair.generate(testing.io);
    const msg = "onyx dtls 1.2 certificateverify transcript";
    const sig = try sign(msg, kp);
    var digest: [prehash_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});

    // Act / Assert: prehashed verify of SHA-256(msg) matches full verify of msg.
    try testing.expect(verifyPrehashed(sig, digest, kp.public_key));
    // A single-bit flip in the digest fails closed.
    digest[0] ^= 0x01;
    try testing.expect(!verifyPrehashed(sig, digest, kp.public_key));
}

test "verify of a tampered message returns false" {
    // Arrange
    const kp = KeyPair.generate(testing.io);
    const sig = try sign("authentic payload", kp);

    // Act
    const ok = verify(sig, "tampered payload", kp.public_key);

    // Assert
    try testing.expect(!ok);
}

test "DER encode then decode round-trips a signature" {
    // Arrange
    const kp = KeyPair.generate(testing.io);
    const sig = try sign("der round trip", kp);

    // Act
    var buf: [Signature.der_encoded_length_max]u8 = undefined;
    const der = try signatureToDer(sig, &buf);
    const decoded = try signatureFromDer(der);

    // Assert
    try testing.expect(der[0] == der_sequence_tag);
    try testing.expectEqualSlices(u8, &sig.toBytes(), &decoded.toBytes());
}

test "DER codec handles a high-bit scalar with sign-bit padding" {
    // Arrange: r has its top bit set, forcing a 0x00 pad; s starts with a zero
    // byte that must be stripped on the minimal encoding.
    var r = @as([scalar_len]u8, @splat(0));
    var s = @as([scalar_len]u8, @splat(0));
    r[0] = 0xFF;
    r[scalar_len - 1] = 0x01;
    s[1] = 0x80;
    s[scalar_len - 1] = 0x02;
    const sig = Signature.fromBytes(r ++ s);

    // Act
    var buf: [Signature.der_encoded_length_max]u8 = undefined;
    const der = try signatureToDer(sig, &buf);
    const decoded = try signatureFromDer(der);

    // Assert: r gets a leading 0x00 pad (33-byte content); decode restores it.
    try testing.expect(der[2] == der_integer_tag);
    try testing.expect(der[3] == scalar_len + 1);
    try testing.expect(der[4] == 0x00);
    try testing.expectEqualSlices(u8, &sig.toBytes(), &decoded.toBytes());
}

test "signatureToDer reports NoSpaceLeft on a short buffer" {
    // Arrange
    const kp = KeyPair.generate(testing.io);
    const sig = try sign("too small", kp);

    // Act
    var tiny: [4]u8 = undefined;
    const result = signatureToDer(sig, &tiny);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "signatureFromDer rejects malformed encodings" {
    // Arrange / Act / Assert
    try testing.expectError(error.InvalidDerEncoding, signatureFromDer(&[_]u8{0x30}));
    // Wrong outer tag.
    try testing.expectError(error.InvalidDerEncoding, signatureFromDer(&[_]u8{ 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }));
    // SEQUENCE body length disagrees with buffer.
    try testing.expectError(error.InvalidDerEncoding, signatureFromDer(&[_]u8{ 0x30, 0x10, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }));
}

test "SEC1 parse accepts a generated key's uncompressed point" {
    // Arrange
    const kp = KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();

    // Act
    const parsed = try parsePublicKeySec1(&sec1);

    // Assert: parsed key verifies a signature from the original key pair.
    const sig = try sign("sec1 parse", kp);
    try testing.expect(verify(sig, "sec1 parse", parsed));
    try testing.expectEqual(@as(usize, sec1_uncompressed_length), sec1.len);
}

test "parsePublicKeySec1 rejects a bad prefix" {
    // Arrange: valid-length buffer but wrong leading tag.
    const kp = KeyPair.generate(testing.io);
    var sec1 = kp.public_key.toUncompressedSec1();
    sec1[0] = 0x03; // compressed-point tag, not accepted here

    // Act
    const result = parsePublicKeySec1(&sec1);

    // Assert
    try testing.expectError(error.InvalidSec1Prefix, result);
}

test "parsePublicKeySec1 rejects a wrong length" {
    // Arrange / Act / Assert
    try testing.expectError(error.InvalidSec1Length, parsePublicKeySec1(&[_]u8{ 0x04, 0x00, 0x01 }));
}

test "wipeKeyPair zeroes the secret scalar and keeps the public key" {
    const seed: [KeyPair.seed_length]u8 = @splat(0x42);
    var kp = try KeyPair.generateDeterministic(seed);
    const public_before = kp.public_key.toUncompressedSec1();
    try std.testing.expect(!std.mem.allEqual(u8, &kp.secret_key.bytes, 0));

    wipeKeyPair(&kp);
    try std.testing.expect(std.mem.allEqual(u8, &kp.secret_key.bytes, 0));
    try std.testing.expectEqualSlices(u8, &public_before, &kp.public_key.toUncompressedSec1());

    var sk = try SecretKey.fromBytes(@splat(0x11));
    wipeSecretKey(&sk);
    try std.testing.expect(std.mem.allEqual(u8, &sk.toBytes(), 0));
}
