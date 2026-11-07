// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.2 ECDHE key agreement primitives.
//!
//! This module is intentionally only the crypto math that a DTLS handshake
//! layer needs: deterministic ephemeral P-256 key generation for tests, ECDH
//! shared-secret computation, and the TLS 1.2 PRF calls for master_secret and
//! Finished verify_data. Record and handshake message wiring live elsewhere.
//!
//! Secret-scalar operations ([d]G and [d]Q) run on the constant-time P-256
//! arithmetic in `crypto/p256_ct.zig`, never on `std.crypto.ecc.P256.mul`,
//! which `zig build ct-check` measured leaking the scalar under ReleaseFast.
const std = @import("std");
const dtls_srtp = @import("dtls_srtp.zig");
const p256_ct = @import("../crypto/p256_ct.zig");

const P256 = std.crypto.ecc.P256;
const scalar = P256.scalar;

pub const curve_name = "secp256r1";
pub const secret_length: usize = 32;
pub const public_length: usize = 65;
pub const shared_secret_length: usize = 32;
pub const master_secret_length: usize = 48;
pub const verify_data_length: usize = 12;

const sec1_uncompressed_prefix: u8 = 0x04;

pub const Error = error{ InvalidPublicKey, IdentityElement, Weak };

pub const KeyPair = struct {
    secret: [secret_length]u8,
    public: [public_length]u8,
};

fn validScalar(secret: [secret_length]u8) bool {
    scalar.rejectNonCanonical(secret, .big) catch return false;
    var nonzero: u8 = 0;
    for (secret) |b| nonzero |= b;
    return nonzero != 0;
}

fn derivePublic(secret: [secret_length]u8) [public_length]u8 {
    return publicFromSecret(secret) orelse unreachable;
}

/// Constant-time SEC1 public key `[secret]G` for a canonical non-zero
/// scalar, or null when `secret` is not in [1, n-1] (fail closed). Used to
/// re-validate a carried ECDHE secret against its public half.
pub fn publicFromSecret(secret: [secret_length]u8) ?[public_length]u8 {
    if (!validScalar(secret)) return null;
    var point = p256_ct.mulBaseCt(secret);
    defer point.wipe();
    const aff = point.affine() orelse return null;
    return [_]u8{sec1_uncompressed_prefix} ++ aff.x ++ aff.y;
}

fn parsePublicKey(public: [public_length]u8) Error!P256 {
    if (public[0] != sec1_uncompressed_prefix) return error.InvalidPublicKey;
    const point = P256.fromSec1(&public) catch return error.InvalidPublicKey;
    point.rejectIdentity() catch return error.IdentityElement;
    return point;
}

/// Deterministically generate a P-256 ECDHE key pair from `seed`.
///
/// The seed drives Zig's default CSPRNG and the private scalar is rejection
/// sampled into the canonical non-zero P-256 scalar range.
pub fn generateKeyPair(seed: [32]u8) KeyPair {
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rng = csprng.random();

    while (true) {
        var candidate: [secret_length]u8 = undefined;
        rng.bytes(&candidate);
        if (!validScalar(candidate)) continue;
        return .{
            .secret = candidate,
            .public = derivePublic(candidate),
        };
    }
}

/// Compute the P-256 ECDH shared secret.
///
/// Returns the 32-byte big-endian X coordinate of
/// `my_secret * peer_public`, which is the ECDHE pre-master secret for TLS
/// 1.2 ECDHE suites.
pub fn computeSharedSecret(
    my_secret: [secret_length]u8,
    peer_public: [public_length]u8,
) Error![shared_secret_length]u8 {
    if (!validScalar(my_secret)) return error.Weak;
    // The peer point is public: std's SEC1 parser validates it.
    _ = try parsePublicKey(peer_public);
    const peer = p256_ct.Point.fromAffine(peer_public[1..33].*, peer_public[33..65].*) orelse
        return error.InvalidPublicKey;
    // SEC 1 v2 sec. 3.3.1, constant time in the secret scalar.
    return p256_ct.ecdhX(peer, my_secret) orelse error.IdentityElement;
}

/// TLS 1.2 master_secret derivation (RFC 5246 §8.1):
/// PRF(pre_master, "master secret", ClientHello.random || ServerHello.random).
pub fn masterSecret(
    pre_master: []const u8,
    client_random: [32]u8,
    server_random: [32]u8,
) [master_secret_length]u8 {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &client_random);
    @memcpy(seed[32..64], &server_random);

    var out: [master_secret_length]u8 = undefined;
    dtls_srtp.prfSha256(pre_master, "master secret", &seed, &out);
    return out;
}

/// TLS 1.2 Finished verify_data:
/// PRF(master_secret, finished_label, Hash(handshake_messages))[0..12].
pub fn verifyData(
    master: []const u8,
    label: []const u8,
    handshake_hash: [32]u8,
) [verify_data_length]u8 {
    var out: [verify_data_length]u8 = undefined;
    dtls_srtp.prfSha256(master, label, &handshake_hash, &out);
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn countingBytes(comptime len: usize, start: u8) [len]u8 {
    var out: [len]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = start +% @as(u8, @intCast(i));
    return out;
}

test "deterministic P-256 ECDH key agreement matches on both sides" {
    const alice = generateKeyPair(@as([32]u8, @splat(0x11)));
    const bob = generateKeyPair(@as([32]u8, @splat(0x22)));

    try testing.expect(!std.mem.eql(u8, &alice.secret, &bob.secret));
    try testing.expect(!std.mem.eql(u8, &alice.public, &bob.public));

    const alice_shared = try computeSharedSecret(alice.secret, bob.public);
    const bob_shared = try computeSharedSecret(bob.secret, alice.public);

    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "constant-time ECDH matches std P256.mul and rejects non-canonical secrets" {
    var prng = std.Random.DefaultPrng.init(0x64746c73);
    const rnd = prng.random();
    for (0..16) |_| {
        var sa: [32]u8 = undefined;
        var sb: [32]u8 = undefined;
        rnd.bytes(&sa);
        rnd.bytes(&sb);
        const a = generateKeyPair(sa);
        const b = generateKeyPair(sb);
        try testing.expectEqualSlices(u8, &(try P256.basePoint.mul(a.secret, .big)).toUncompressedSec1(), &a.public);
        const peer = try P256.fromSec1(&b.public);
        const want = (try peer.mul(a.secret, .big)).affineCoordinates().x.toBytes(.big);
        try testing.expectEqualSlices(u8, &want, &(try computeSharedSecret(a.secret, b.public)));
    }
    try testing.expect(publicFromSecret(@splat(0)) == null);
    try testing.expect(publicFromSecret(@splat(0xff)) == null);
}

test "master secret is 48 bytes, deterministic, and input-sensitive" {
    const pre_master = countingBytes(32, 0xa0);
    const client_random = countingBytes(32, 0x10);
    var server_random = countingBytes(32, 0x80);

    const first = masterSecret(&pre_master, client_random, server_random);
    const second = masterSecret(&pre_master, client_random, server_random);

    try testing.expectEqual(@as(usize, master_secret_length), first.len);
    try testing.expectEqualSlices(u8, &first, &second);

    server_random[0] ^= 0xff;
    const changed = masterSecret(&pre_master, client_random, server_random);
    try testing.expect(!std.mem.eql(u8, &first, &changed));
}

test "verify data is 12 bytes and label-sensitive" {
    const master = countingBytes(master_secret_length, 0x31);
    const handshake_hash = countingBytes(32, 0x42);

    const client = verifyData(&master, "client finished", handshake_hash);
    const server = verifyData(&master, "server finished", handshake_hash);
    const client_again = verifyData(&master, "client finished", handshake_hash);

    try testing.expectEqual(@as(usize, verify_data_length), client.len);
    try testing.expectEqualSlices(u8, &client, &client_again);
    try testing.expect(!std.mem.eql(u8, &client, &server));
}
