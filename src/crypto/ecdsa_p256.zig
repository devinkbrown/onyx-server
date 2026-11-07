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
//! Signing does NOT use the std signer. `zig build ct-check` measured
//! `std.crypto.ecc.P256.mul` leaking timing on the secret nonce under
//! ReleaseFast: LLVM compiles some of its select masks into conditional
//! branches (see `p256_ct.zig`). `sign`, `signHedged` and `signPrehashed` run
//! on the constant-time arithmetic in `p256_ct.zig` (fixed-window [k]G with
//! masked table scans, Fermat inversion in F_p and F_n, value-barrier masks).
//! The nonce derivation is the same as std's, so with null noise the output
//! is byte-identical to `std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.sign`,
//! and existing reproducible signatures do not change. Verification stays on
//! std, because every verify input is public.
//!
//! No I/O and no clock. With null noise, `sign()` is deterministic and needs
//! no entropy. The nonce is
//! derived with HMAC-SHA256 from the key and the message hash. Like std, this
//! follows the RFC 6979 sec. 3.2 HMAC_DRBG shape with an added 32-byte noise
//! block. It is NOT RFC 6979's exact k, so RFC 6979 (r, s) values are pinned by
//! injecting the RFC's k (see the tests) and by `ecdsa_kat.zig` on verify.

const std = @import("std");
const p256_ct = @import("p256_ct.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

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

/// Errors a constant-time signing call can return. The names match std's
/// `IdentityElementError || NonCanonicalError` so callers do not change.
pub const SignError = error{
    /// The secret scalar is zero, or the signature hit r == 0 or s == 0
    /// (probability ~2^-256 for a valid key).
    IdentityElement,
    /// The secret scalar is not below the group order n.
    NonCanonical,
};

/// Length of the optional hedging noise (one P-256 scalar).
pub const noise_length = scalar_len;

/// Sign `msg` with `key_pair` (constant time, deterministic). The output is
/// reproducible, needs no entropy source, and is byte-identical to std's
/// null-noise `KeyPair.sign`.
pub fn sign(msg: []const u8, key_pair: KeyPair) SignError!Signature {
    return signHedged(msg, key_pair, null);
}

/// Sign `msg` with optional hedging `noise`, mixed into the nonce derivation
/// next to the key and the message hash. Fresh random noise gives
/// non-reproducible signatures that still stay safe with a broken RNG,
/// because the nonce also depends on the key and the message. It also helps
/// against fault attacks. Null noise is the same as `sign`.
pub fn signHedged(msg: []const u8, key_pair: KeyPair, noise: ?[noise_length]u8) SignError!Signature {
    var h: [prehash_len]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    return signPrehashed(h, key_pair, noise);
}

/// Sign an already-computed SHA-256 digest (constant time). The result matches
/// `signHedged(m, key_pair, noise)` when `msg_hash = SHA-256(m)`.
pub fn signPrehashed(msg_hash: [prehash_len]u8, key_pair: KeyPair, noise: ?[noise_length]u8) SignError!Signature {
    // SEC 1 v2 sec. 3.2.1: a private key is an integer in [1, n-1]. Reject
    // anything else (fail closed). The verdict is the same for every call on
    // a valid key, so branching on it reveals nothing.
    var d = p256_ct.Scalar.fromBytes(key_pair.secret_key.bytes) orelse return error.NonCanonical;
    defer d.wipe();
    if (d.isZeroBit() == 1) return error.IdentityElement;

    var k = deriveNonce(msg_hash, key_pair.secret_key.bytes, noise);
    defer std.crypto.secureZero(u8, &k);
    return signWithNonce(msg_hash, d, k);
}

/// SEC 1 v2 sec. 4.1.3 steps 1-6 for a given nonce `k_bytes` in [1, n-1].
/// Every secret-dependent step (k*G, k^-1, r*d, the products) runs in
/// constant time.
fn signWithNonce(msg_hash: [prehash_len]u8, d: p256_ct.Scalar, k_bytes: [scalar_len]u8) SignError!Signature {
    var k = p256_ct.Scalar.fromBytes(k_bytes) orelse return error.NonCanonical;
    defer k.wipe();
    if (k.isZeroBit() == 1) return error.IdentityElement;

    // Steps 1-3: R = kG, r = x_R mod n. x_R < p < 2n, so one reduction is enough.
    const big_r = p256_ct.mulBaseCt(k_bytes);
    const r_aff = big_r.affine() orelse return error.IdentityElement;
    const r = p256_ct.Scalar.fromBytesReduce(r_aff.x);
    if (r.isZeroBit() == 1) return error.IdentityElement;

    // Steps 4-5: e = the leftmost 256 bits of the hash (all of SHA-256), mod n.
    const e = p256_ct.Scalar.fromBytesReduce(msg_hash);

    // Step 6: s = k^-1 (e + r d) mod n.
    var k_inv = k.invert();
    defer k_inv.wipe();
    var rd = r.mul(d);
    defer rd.wipe();
    const s = k_inv.mul(e.add(rd));
    if (s.isZeroBit() == 1) return error.IdentityElement;

    return .{ .r = r.toBytes(), .s = s.toBytes() };
}

/// Nonce derivation, identical to Zig std's `Ecdsa.deterministicScalar` for
/// P-256/SHA-256. It is the RFC 6979 sec. 3.2 HMAC_DRBG construction (steps
/// b-h) with a 32-byte noise block (zeros when null) placed before the key:
///
///   K = HMAC_K(V || 0x00 || Z || x || h1); V = HMAC_K(V)
///   K = HMAC_K(V || 0x01 || Z || x || h1); V = HMAC_K(V)
///   loop: V = HMAC_K(V); accept V if 1 <= V < n, else K = HMAC_K(V || 0x00); V = HMAC_K(V)
///
/// HMAC-SHA256 over fixed-length inputs runs in constant time. The rejection
/// test is the RFC's step h.3, and it fails only with probability ~2^-32.
fn deriveNonce(h: [prehash_len]u8, secret_key: [scalar_len]u8, noise: ?[noise_length]u8) [scalar_len]u8 {
    const v_len = HmacSha256.mac_length;
    var key: [v_len]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &key);
    var m: [v_len + 1 + noise_length + scalar_len + prehash_len]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &m);
    const m_v = m[0..v_len];
    const m_i = &m[v_len];
    @memset(m_v, 0x01);
    m_i.* = 0x00;
    if (noise) |n| @memcpy(m[v_len + 1 ..][0..noise_length], &n);
    @memcpy(m[v_len + 1 + noise_length ..][0..scalar_len], &secret_key);
    @memcpy(m[m.len - prehash_len ..], &h);

    var tmp: [v_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &tmp);
    HmacSha256.create(&tmp, &m, &key);
    key = tmp;
    HmacSha256.create(&tmp, m_v, &key);
    m_v.* = tmp;
    m_i.* = 0x01;
    HmacSha256.create(&tmp, &m, &key);
    key = tmp;
    HmacSha256.create(&tmp, m_v, &key);
    m_v.* = tmp;
    while (true) {
        HmacSha256.create(&tmp, m_v, &key);
        m_v.* = tmp;
        if (p256_ct.Scalar.fromBytes(m_v.*)) |cand| {
            if (cand.isZeroBit() == 0) return m_v.*;
        }
        m_i.* = 0x00;
        HmacSha256.create(&tmp, m[0 .. v_len + 1], &key);
        key = tmp;
        HmacSha256.create(&tmp, m_v, &key);
        m_v.* = tmp;
    }
}

/// Derive the key pair for `secret_key` in constant time. This replaces std's
/// `KeyPair.fromSecretKey`, whose [d]G runs on the same leaky `P256.mul`.
/// Fails closed unless 1 <= d < n (SEC 1 v2 sec. 3.2.1).
pub fn keyPairFromSecretKey(secret_key: SecretKey) SignError!KeyPair {
    var d = p256_ct.Scalar.fromBytes(secret_key.bytes) orelse return error.NonCanonical;
    defer d.wipe();
    if (d.isZeroBit() == 1) return error.IdentityElement;
    const q = p256_ct.mulBaseCt(secret_key.bytes);
    const aff = q.affine() orelse return error.IdentityElement;
    const sec1 = [_]u8{sec1_uncompressed_tag} ++ aff.x ++ aff.y;
    // The point is public; std's on-curve check is a free self-test.
    const public_key = Impl.PublicKey.fromSec1(&sec1) catch return error.IdentityElement;
    return .{ .secret_key = secret_key, .public_key = public_key };
}

/// Length of the seed taken by `generateDeterministic` (same as std's
/// `KeyPair.seed_length`).
pub const seed_length = Impl.KeyPair.seed_length;

/// Derive a key pair from `seed` in constant time. Byte-identical to std's
/// `KeyPair.generateDeterministic`: d is the RFC 6979 sec. 3.2 HMAC_DRBG
/// output with h = 0^32, x = 0x01^32 and the seed as the extra-noise block,
/// which is exactly std's `deterministicScalar(0^32, 0x01^32, seed)`. Unlike
/// std, Q = [d]G runs on `p256_ct` instead of the leaky `P256.mul`.
pub fn generateDeterministic(seed: [seed_length]u8) SignError!KeyPair {
    const zero_h: [prehash_len]u8 = @splat(0x00);
    const k0: [scalar_len]u8 = @splat(0x01);
    var d = deriveNonce(zero_h, k0, seed);
    defer std.crypto.secureZero(u8, &d);
    return keyPairFromSecretKey(.{ .bytes = d });
}

/// Generate a fresh random key pair in constant time. Same construction as
/// std's `KeyPair.generate` (fresh `io.random` seed into
/// `generateDeterministic`), but [d]G runs on `p256_ct`.
pub fn generate(io: std.Io) KeyPair {
    var seed: [seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    while (true) {
        io.random(&seed);
        return generateDeterministic(seed) catch {
            @branchHint(.unlikely);
            continue;
        };
    }
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

test {
    // Pull the constant-time arithmetic's own tests into every build that
    // tests this module, even before `tools/genroots.sh` lists p256_ct.zig in
    // crypto/root.zig.
    _ = p256_ct;
}

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

fn testHex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "constant-time sign is byte-identical to std's signer (deterministic and hedged)" {
    // Differential KAT against the std implementation this path replaces: same
    // nonce derivation, so the same (r, s) for every key, message and noise.
    var prng = std.Random.DefaultPrng.init(0x65636473);
    const rnd = prng.random();
    var msg_buf: [200]u8 = undefined;
    for (0..64) |i| {
        var seed: [KeyPair.seed_length]u8 = undefined;
        rnd.bytes(&seed);
        const kp = try KeyPair.generateDeterministic(seed);
        const msg = msg_buf[0 .. i * 3];
        rnd.bytes(msg);

        const ours = try sign(msg, kp);
        const theirs = try kp.sign(msg, null);
        try testing.expectEqualSlices(u8, &theirs.toBytes(), &ours.toBytes());
        try testing.expect(verify(ours, msg, kp.public_key));

        var noise: [noise_length]u8 = undefined;
        rnd.bytes(&noise);
        const ours_h = try signHedged(msg, kp, noise);
        const theirs_h = try kp.sign(msg, noise);
        try testing.expectEqualSlices(u8, &theirs_h.toBytes(), &ours_h.toBytes());
        try testing.expect(verify(ours_h, msg, kp.public_key));
        // Hedging changes the nonce, so the signature differs.
        try testing.expect(!std.mem.eql(u8, &ours.toBytes(), &ours_h.toBytes()));

        var digest: [prehash_len]u8 = undefined;
        Sha256.hash(msg, &digest, .{});
        const ours_p = try signPrehashed(digest, kp, null);
        try testing.expectEqualSlices(u8, &ours.toBytes(), &ours_p.toBytes());
        try testing.expect(verifyPrehashed(ours_p, digest, kp.public_key));
    }
}

test "RFC 6979 A.2.5 P-256/SHA-256 (r, s) reproduced from the RFC's nonce k" {
    // The nonce derivation differs from RFC 6979 (see module doc). Injecting
    // the RFC's published k pins the constant-time signing arithmetic, and the
    // nonce-to-signature mapping (kG, k^-1, r*d), to the RFC's exact outputs.
    const x = testHex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    const d = p256_ct.Scalar.fromBytes(x).?;
    const Row = struct { msg: []const u8, k: [32]u8, r: [32]u8, s: [32]u8 };
    const rows = [_]Row{
        .{
            .msg = "sample",
            .k = testHex("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"),
            .r = testHex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
            .s = testHex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        },
        .{
            .msg = "test",
            .k = testHex("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0"),
            .r = testHex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"),
            .s = testHex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
        },
    };
    for (rows) |row| {
        var h: [prehash_len]u8 = undefined;
        Sha256.hash(row.msg, &h, .{});
        const sig = try signWithNonce(h, d, row.k);
        try testing.expectEqualSlices(u8, &row.r, &sig.r);
        try testing.expectEqualSlices(u8, &row.s, &sig.s);
    }
    // RFC 6979 A.2.5 public key U = xG, derived with the constant-time path.
    const kp = try keyPairFromSecretKey(try SecretKey.fromBytes(x));
    const sec1 = kp.public_key.toUncompressedSec1();
    try testing.expectEqualSlices(u8, &testHex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"), sec1[1..33]);
    try testing.expectEqualSlices(u8, &testHex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"), sec1[33..65]);
}

test "sign fails closed on a secret scalar outside [1, n-1]" {
    // std's signer accepted d = 0 and produced a signature under the identity
    // "public key". The constant-time path rejects it (SEC 1 v2 sec. 3.2.1).
    const other_pk = (try KeyPair.generateDeterministic(@splat(1))).public_key;
    const zero_kp: KeyPair = .{ .secret_key = try SecretKey.fromBytes(@splat(0)), .public_key = other_pk };
    try testing.expectError(error.IdentityElement, sign("m", zero_kp));
    var n_bytes: [scalar_len]u8 = undefined;
    std.mem.writeInt(u256, &n_bytes, p256_ct.n_int, .big);
    const n_kp: KeyPair = .{ .secret_key = try SecretKey.fromBytes(n_bytes), .public_key = other_pk };
    try testing.expectError(error.NonCanonical, sign("m", n_kp));
    try testing.expectError(error.IdentityElement, keyPairFromSecretKey(try SecretKey.fromBytes(@splat(0))));
    try testing.expectError(error.NonCanonical, keyPairFromSecretKey(try SecretKey.fromBytes(n_bytes)));
}

test "keyPairFromSecretKey matches std's KeyPair.fromSecretKey" {
    var prng = std.Random.DefaultPrng.init(0x6b657967);
    const rnd = prng.random();
    for (0..32) |_| {
        var seed: [KeyPair.seed_length]u8 = undefined;
        rnd.bytes(&seed);
        const want = try KeyPair.generateDeterministic(seed);
        const got = try keyPairFromSecretKey(want.secret_key);
        try testing.expectEqualSlices(u8, &want.public_key.toUncompressedSec1(), &got.public_key.toUncompressedSec1());
        try testing.expectEqualSlices(u8, &want.secret_key.bytes, &got.secret_key.bytes);
    }
}

test "generateDeterministic is byte-identical to std's KeyPair.generateDeterministic" {
    var prng = std.Random.DefaultPrng.init(0x67656e64);
    const rnd = prng.random();
    for (0..32) |_| {
        var seed: [seed_length]u8 = undefined;
        rnd.bytes(&seed);
        const want = try KeyPair.generateDeterministic(seed);
        const got = try generateDeterministic(seed);
        try testing.expectEqualSlices(u8, &want.secret_key.bytes, &got.secret_key.bytes);
        try testing.expectEqualSlices(u8, &want.public_key.toUncompressedSec1(), &got.public_key.toUncompressedSec1());
    }
}

test "generate yields a usable key pair whose signature std verifies" {
    const kp = generate(testing.io);
    const derived = try KeyPair.fromSecretKey(kp.secret_key);
    try testing.expectEqualSlices(u8, &derived.public_key.toUncompressedSec1(), &kp.public_key.toUncompressedSec1());
    const sig = try sign("onyx generate", kp);
    try sig.verify("onyx generate", kp.public_key);
}
