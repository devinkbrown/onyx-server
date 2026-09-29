// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon node identity: derive the Mooring handshake material from config.
//!
//! The sovereign identity is a 32-byte Ed25519 seed (config `node.secret_key`,
//! hex). From it we deterministically derive everything `SecureLink` needs to run
//! the PQ-hybrid AKE on the live S2S path:
//!   * the Ed25519 static keypair (signs prekeys + transcripts),
//!   * an X-Wing KEM keypair (seed = BLAKE3("MZ-KEM" ++ seed), domain-separated
//!     so the KEM key can't be confused with the signing key),
//!   * the 20-byte node id = BLAKE3-160(Ed25519 public key) — Onyx Server's sole
//!     identity (matches mooring_handshake's convention),
//!   * the realm id = BLAKE3(realm string), so an operator can name a realm
//!     ("local") and get a stable 32-byte RealmId.
//!
//! Holding the seed, both peers derive identical prekeys, so the handshake is
//! reproducible and the derived `node_id`/`shortId` agree across the mesh.
const std = @import("std");

const sign = @import("../crypto/sign.zig");
const xwing = @import("../crypto/xwing.zig");
const hs = @import("../crypto/mooring_handshake.zig");
const node_short_id = @import("../crypto/node_short_id.zig");

const Blake3 = std.crypto.hash.Blake3;

pub const Error = error{ BadSeed, BadRealm, SecretPageUnavailable } || std.crypto.errors.IdentityElementError || xwing.Error;

pub const NodeIdentity = struct {
    sign_kp: sign.KeyPair,
    kem_kp: xwing.KeyPair,
    node_id: [20]u8,
    realm: [32]u8,

    pub fn deinit(self: *NodeIdentity) void {
        self.sign_kp.deinit();
        self.kem_kp.wipe();
        self.* = undefined;
    }

    /// The u64 mesh routing handle for this node (matches the peer-side bridge).
    pub fn shortId(self: *const NodeIdentity) u64 {
        return node_short_id.shortId(self.node_id);
    }

    /// Build a signed prekey for this node (the AKE's transport prekey).
    pub fn signedPrekey(
        self: *const NodeIdentity,
        prekey_id: u64,
        now_ms: u64,
        ttl_ms: u64,
        bands: u128,
        features: u128,
    ) hs.Error!hs.SignedPrekey {
        return hs.SignedPrekey.create(&self.sign_kp, &self.kem_kp, self.realm, prekey_id, now_ms, ttl_ms, 1, bands, features);
    }
};

fn realmId(realm: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Blake3.hash(realm, &out, .{});
    return out;
}

fn nodeIdFromKey(pk: sign.PublicKey) [20]u8 {
    var full: [32]u8 = undefined;
    Blake3.hash(&pk, &full, .{});
    return full[0..20].*;
}

/// Derive Onyx Server's canonical 20-byte node id from an Ed25519 public key.
pub fn nodeIdFromPublicKey(pk: sign.PublicKey) [20]u8 {
    return nodeIdFromKey(pk);
}

fn kemSeed(seed: [32]u8) [32]u8 {
    var h = Blake3.init(.{});
    h.update("MZ-KEM");
    h.update(&seed);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Derive a full identity from a raw 32-byte Ed25519 seed and a realm name.
pub fn fromSeed(seed: [32]u8, realm: []const u8) Error!NodeIdentity {
    const sign_kp = try sign.KeyPair.fromSeed(seed);
    const kem_kp = try xwing.KeyPair.generateDeterministic(kemSeed(seed));
    return .{
        .sign_kp = sign_kp,
        .kem_kp = kem_kp,
        .node_id = nodeIdFromKey(sign_kp.public_key),
        .realm = realmId(realm),
    };
}

/// Derive an identity from config: `secret_hex` is the 64-char hex of the 32-byte
/// seed (`node.secret_key`); `realm` is `mesh.realm`.
pub fn fromConfig(secret_hex: []const u8, realm: []const u8) Error!NodeIdentity {
    if (secret_hex.len != 64) return error.BadSeed;
    var seed: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&seed, secret_hex) catch return error.BadSeed;
    return fromSeed(seed, realm);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "fromSeed is deterministic and yields a usable, verifiable prekey" {
    const seed = @as([32]u8, @splat(0x42));
    var id1 = try fromSeed(seed, "local");
    defer id1.deinit();
    var id2 = try fromSeed(seed, "local");
    defer id2.deinit();

    try testing.expectEqualSlices(u8, &id1.node_id, &id2.node_id);
    try testing.expectEqual(id1.shortId(), id2.shortId());
    try testing.expectEqualSlices(u8, &id1.realm, &id2.realm);

    // The derived prekey verifies against its own embedded identity.
    const pre = try id1.signedPrekey(1, 1000, 10_000, 0b1111, 0b1);
    try pre.verify(1500);
    try testing.expectEqualSlices(u8, &id1.node_id, &pre.node_id);
}

test "distinct seeds give distinct node ids; distinct realms give distinct realm ids" {
    var a = try fromSeed(@as([32]u8, @splat(1)), "local");
    defer a.deinit();
    var b = try fromSeed(@as([32]u8, @splat(2)), "local");
    defer b.deinit();
    try testing.expect(!std.mem.eql(u8, &a.node_id, &b.node_id));

    var c = try fromSeed(@as([32]u8, @splat(1)), "other-realm");
    defer c.deinit();
    try testing.expectEqualSlices(u8, &a.node_id, &c.node_id); // same seed -> same node id
    try testing.expect(!std.mem.eql(u8, &a.realm, &c.realm)); // different realm
}

test "fromConfig parses a hex seed and rejects bad input" {
    const hex = &repeatBytes("42", 32); // 64 hex chars
    var id = try fromConfig(hex, "local");
    defer id.deinit();
    try testing.expectEqual((try fromSeed(@as([32]u8, @splat(0x42)), "local")).shortId(), id.shortId());

    try testing.expectError(error.BadSeed, fromConfig("abcd", "local")); // too short
    try testing.expectError(error.BadSeed, fromConfig(&repeatBytes("zz", 32), "local")); // non-hex
}

fn repeatBytes(comptime s: []const u8, comptime n: usize) [s.len * n]u8 {
    var b: [s.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(b[i * s.len ..][0..s.len], s);
    return b;
}
