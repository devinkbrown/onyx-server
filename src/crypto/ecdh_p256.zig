// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ephemeral ECDH over NIST P-256 (secp256r1) for TLS ECDHE key exchange.
//!
//! This module provides ephemeral Elliptic Curve Diffie-Hellman key agreement
//! on the NIST P-256 curve. It is the curve component used by the
//! `ecdhe_ecdsa`/`ecdhe_rsa` TLS 1.2 cipher suites and by the TLS 1.3
//! `secp256r1` named group.
//!
//! Every operation on the secret scalar (public-key derivation [d]G and the
//! shared secret [d]Q) runs on the constant-time arithmetic in `p256_ct.zig`.
//! `std.crypto.ecc.P256.mul` is NOT used for secret scalars: `zig build
//! ct-check` measured it leaking the scalar through branch timing under
//! ReleaseFast (see `p256_ct.zig`). std is still used for public-point SEC1
//! parsing, where every input is public.
//!
//! Conventions:
//!   * Scalars (private keys) are 32-byte big-endian, in the range [1, n-1].
//!   * Public keys are 65-byte uncompressed SEC1 points: `0x04 || X || Y`.
//!   * The ECDH shared secret is the 32-byte big-endian X coordinate of the
//!     scalar multiplication result, exactly as TLS specifies.
//!
//! Constraints: pure `std.crypto` (plus an OS entropy syscall to seed the
//! CSPRNG inside `generate`), 64-bit targets only.

const std = @import("std");
const random_mod = @import("random.zig");
const p256_ct = @import("p256_ct.zig");

const P256 = std.crypto.ecc.P256;
const scalar = P256.scalar;

/// Length of a P-256 scalar / shared secret coordinate in bytes.
pub const scalar_length: usize = 32;
/// Length of an uncompressed SEC1 public key (`0x04 || X || Y`).
pub const public_length: usize = 65;
/// SEC1 prefix byte for an uncompressed point.
const sec1_uncompressed_prefix: u8 = 0x04;

/// Errors produced by this module's key-agreement operations.
pub const EcdhError = error{
    /// The supplied scalar was zero or otherwise not a valid private key.
    InvalidPrivateKey,
    /// The supplied SEC1 public key was malformed (bad prefix/encoding).
    InvalidPublicKey,
    /// The supplied point or a computed point was the identity element.
    IdentityElement,
    /// No source of cryptographic entropy was available.
    EntropyUnavailable,
};

/// An ephemeral P-256 ECDH key pair.
pub const KeyPair = struct {
    /// 32-byte big-endian private scalar in [1, n-1].
    secret: [scalar_length]u8,
    /// 65-byte uncompressed SEC1 public key: `0x04 || X || Y`.
    public_sec1: [public_length]u8,
};

comptime {
    // 64-bit only (the wasm32 browser codec is the sole non-64-bit exception
    // elsewhere and does not use this server-side module).
    if (@bitSizeOf(usize) != 64) {
        @compileError("ecdh_p256 targets 64-bit platforms only");
    }
}

/// Fill `buf` with cryptographically secure entropy from the operating system.
///
/// Always makes a fresh syscall rather than depending on stored process state.
fn osEntropy(buf: []u8) EcdhError!void {
    random_mod.fillOsEntropy(buf) catch return error.EntropyUnavailable;
}

/// Derive the public key for a validated private scalar.
///
/// Returns `error.InvalidPrivateKey` if the scalar yields the identity element
/// (which cannot happen for a canonical non-zero scalar, but is checked anyway).
fn derivePublic(secret: [scalar_length]u8) EcdhError![public_length]u8 {
    // Constant-time [d]G (the scalar is secret).
    var point = p256_ct.mulBaseCt(secret);
    defer point.wipe();
    const aff = point.affine() orelse return error.InvalidPrivateKey;
    return [_]u8{sec1_uncompressed_prefix} ++ aff.x ++ aff.y;
}

/// Validate that `secret` is a canonical, non-zero P-256 scalar.
fn validateScalar(secret: [scalar_length]u8) EcdhError!void {
    scalar.rejectNonCanonical(secret, .big) catch return error.InvalidPrivateKey;
    var is_zero: u8 = 0;
    for (secret) |b| is_zero |= b;
    if (is_zero == 0) return error.InvalidPrivateKey;
}

/// Generate a fresh ephemeral key pair using OS-seeded CSPRNG entropy.
///
/// The private scalar is drawn uniformly from [1, n-1] via rejection sampling
/// over canonical scalars; the public key is `scalar * G` encoded as
/// uncompressed SEC1.
pub fn generate() EcdhError!KeyPair {
    var seed: [32]u8 = undefined;
    try osEntropy(&seed);

    var csprng = std.Random.DefaultCsprng.init(seed);
    const rng = csprng.random();

    // Rejection-sample a canonical, non-zero scalar.
    var attempts: usize = 0;
    while (attempts < 128) : (attempts += 1) {
        var candidate: [scalar_length]u8 = undefined;
        rng.bytes(&candidate);
        validateScalar(candidate) catch continue;
        const public_sec1 = try derivePublic(candidate);
        return KeyPair{ .secret = candidate, .public_sec1 = public_sec1 };
    }
    return error.EntropyUnavailable;
}

/// Generate a deterministic key pair from a fixed 32-byte seed.
///
/// Intended for tests and key derivation contexts. The seed is reduced into a
/// canonical scalar; a seed that reduces to zero is rejected.
pub fn generateDeterministic(seed: [scalar_length]u8) EcdhError!KeyPair {
    // Reduce the seed modulo the curve order to obtain a canonical scalar.
    // reduce48 expects 48 bytes; left-pad the 32-byte seed with zeros.
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = seed;
    const secret = scalar.reduce48(wide, .big);

    try validateScalar(secret);
    const public_sec1 = try derivePublic(secret);
    return KeyPair{ .secret = secret, .public_sec1 = public_sec1 };
}

/// Parse an uncompressed SEC1 public key into a validated curve point.
///
/// Rejects any non-`0x04` prefix, off-curve points, and the identity element.
pub fn parsePoint(sec1: [public_length]u8) EcdhError!P256 {
    if (sec1[0] != sec1_uncompressed_prefix) return error.InvalidPublicKey;
    // fromSec1 validates the point lies on the curve for the 0x04 form.
    const point = P256.fromSec1(&sec1) catch return error.InvalidPublicKey;
    point.rejectIdentity() catch return error.IdentityElement;
    return point;
}

/// Compute the ECDH shared secret from our scalar and the peer's SEC1 point.
///
/// Returns the 32-byte big-endian X coordinate of `my_secret * peerPoint`,
/// which is the value TLS uses as the pre-master / IKM input.
pub fn sharedSecret(
    my_secret: [scalar_length]u8,
    peer_sec1: [public_length]u8,
) EcdhError![scalar_length]u8 {
    try validateScalar(my_secret);
    // Public-key validation (SEC 1 v2 sec. 3.2.2.1): prefix, on-curve, not the
    // identity. The peer point is public, so std's parser is fine here.
    _ = try parsePoint(peer_sec1);
    // Lift into the constant-time representation. fromAffine re-checks the
    // curve equation, so this cannot disagree with parsePoint (fail closed).
    const peer = p256_ct.Point.fromAffine(peer_sec1[1..33].*, peer_sec1[33..65].*) orelse
        return error.InvalidPublicKey;
    // SEC 1 v2 sec. 3.3.1: z = x_P of [d]Q, rejecting the identity. Constant
    // time in the secret scalar.
    return p256_ct.ecdhX(peer, my_secret) orelse error.IdentityElement;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "two key pairs derive the same shared secret" {
    // Arrange: generate two independent ephemeral key pairs.
    const a = try generate();
    const b = try generate();

    // Act: each side computes the shared secret from its own scalar and the
    // peer's public key.
    const ab = try sharedSecret(a.secret, b.public_sec1);
    const ba = try sharedSecret(b.secret, a.public_sec1);

    // Assert: ECDH agreement holds.
    try testing.expectEqualSlices(u8, &ab, &ba);
}

test "deterministic key generation is reproducible" {
    // Arrange: a fixed seed.
    const seed = @as([32]u8, @splat(0x42));

    // Act: derive the key pair twice.
    const kp1 = try generateDeterministic(seed);
    const kp2 = try generateDeterministic(seed);

    // Assert: identical scalar and public key each time.
    try testing.expectEqualSlices(u8, &kp1.secret, &kp2.secret);
    try testing.expectEqualSlices(u8, &kp1.public_sec1, &kp2.public_sec1);
}

test "deterministic key pairs still perform valid ECDH" {
    // Arrange: two distinct deterministic key pairs.
    const a = try generateDeterministic(@as([32]u8, @splat(0x01)));
    const b = try generateDeterministic(@as([32]u8, @splat(0x02)));

    // Act
    const ab = try sharedSecret(a.secret, b.public_sec1);
    const ba = try sharedSecret(b.secret, a.public_sec1);

    // Assert: agreement, and distinct key pairs produce a non-zero secret.
    try testing.expectEqualSlices(u8, &ab, &ba);
    var nonzero: u8 = 0;
    for (ab) |x| nonzero |= x;
    try testing.expect(nonzero != 0);
}

test "generated public key is uncompressed SEC1 form" {
    // Arrange + Act
    const kp = try generate();

    // Assert: 65 bytes beginning with the uncompressed prefix.
    try testing.expectEqual(@as(usize, public_length), kp.public_sec1.len);
    try testing.expectEqual(sec1_uncompressed_prefix, kp.public_sec1[0]);
}

test "parsePoint rejects an invalid prefix byte" {
    // Arrange: a valid point with the prefix corrupted to a compressed tag.
    const kp = try generateDeterministic(@as([32]u8, @splat(0x07)));
    var bad = kp.public_sec1;
    bad[0] = 0x02;

    // Act + Assert
    try testing.expectError(error.InvalidPublicKey, parsePoint(bad));
}

test "parsePoint rejects an off-curve point" {
    // Arrange: keep a valid prefix and X but flip a byte in Y so the point is
    // no longer on the curve.
    const kp = try generateDeterministic(@as([32]u8, @splat(0x09)));
    var bad = kp.public_sec1;
    bad[64] ^= 0x01;

    // Act + Assert
    try testing.expectError(error.InvalidPublicKey, parsePoint(bad));
}

test "parsePoint rejects the identity element" {
    // Arrange: all-zero body with valid uncompressed prefix is not a valid
    // affine point and must be rejected.
    var sec1 = @as([public_length]u8, @splat(0));
    sec1[0] = sec1_uncompressed_prefix;

    // Act + Assert
    const result = parsePoint(sec1);
    try testing.expect(std.meta.isError(result));
}

test "parsePoint accepts a well-formed point" {
    // Arrange
    const kp = try generateDeterministic(@as([32]u8, @splat(0x11)));

    // Act
    const point = try parsePoint(kp.public_sec1);

    // Assert: round-trips back to the same SEC1 encoding.
    const reencoded = point.toUncompressedSec1();
    try testing.expectEqualSlices(u8, &kp.public_sec1, &reencoded);
}

test "shared secret is the 32-byte X coordinate of the product point" {
    // Arrange: two deterministic key pairs.
    const a = try generateDeterministic(@as([32]u8, @splat(0x21)));
    const b = try generateDeterministic(@as([32]u8, @splat(0x22)));

    // Act: compute via the API, and independently via the raw point math.
    const secret = try sharedSecret(a.secret, b.public_sec1);

    const peer = try parsePoint(b.public_sec1);
    const product = try peer.mul(a.secret, .big);
    const expected_x = product.affineCoordinates().x.toBytes(.big);

    // Assert: length is 32 and equals the X coordinate.
    try testing.expectEqual(@as(usize, scalar_length), secret.len);
    try testing.expectEqualSlices(u8, &expected_x, &secret);
}

test "constant-time derivation and shared secret match std P256.mul" {
    // Interop: the constant-time path must agree bit-for-bit with std's
    // (variable-time) reference over many scalars.
    var prng = std.Random.DefaultPrng.init(0x65636468);
    const rnd = prng.random();
    for (0..24) |_| {
        var sa: [32]u8 = undefined;
        var sb: [32]u8 = undefined;
        rnd.bytes(&sa);
        rnd.bytes(&sb);
        const a = try generateDeterministic(sa);
        const b = try generateDeterministic(sb);
        const want_pub = (try P256.basePoint.mul(a.secret, .big)).toUncompressedSec1();
        try testing.expectEqualSlices(u8, &want_pub, &a.public_sec1);
        const peer = try parsePoint(b.public_sec1);
        const want = (try peer.mul(a.secret, .big)).affineCoordinates().x.toBytes(.big);
        try testing.expectEqualSlices(u8, &want, &(try sharedSecret(a.secret, b.public_sec1)));
    }
}

test "RFC 5903 sec. 8.1 ECDH P-256 known-answer test" {
    // RFC 5903 sec. 8.1 (256-bit Random ECP Group) test vector.
    const i_secret = hexArray(32, "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    const i_pub = hexArray(65, "04" ++
        "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180" ++
        "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3");
    const r_secret = hexArray(32, "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
    const r_pub = hexArray(65, "04" ++
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63" ++
        "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");
    const shared_x = hexArray(32, "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

    const i = try generateFromSecretForTest(i_secret);
    const r = try generateFromSecretForTest(r_secret);
    try testing.expectEqualSlices(u8, &i_pub, &i.public_sec1);
    try testing.expectEqualSlices(u8, &r_pub, &r.public_sec1);
    try testing.expectEqualSlices(u8, &shared_x, &(try sharedSecret(i_secret, r_pub)));
    try testing.expectEqualSlices(u8, &shared_x, &(try sharedSecret(r_secret, i_pub)));
}

fn hexArray(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn generateFromSecretForTest(secret: [scalar_length]u8) EcdhError!KeyPair {
    try validateScalar(secret);
    return .{ .secret = secret, .public_sec1 = try derivePublic(secret) };
}

test "sharedSecret rejects a zero scalar" {
    // Arrange
    const kp = try generateDeterministic(@as([32]u8, @splat(0x31)));
    const zero_secret = @as([scalar_length]u8, @splat(0));

    // Act + Assert
    try testing.expectError(error.InvalidPrivateKey, sharedSecret(zero_secret, kp.public_sec1));
}
