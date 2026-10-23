// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! X-Wing hybrid KEM: ML-KEM-768 + X25519.
//!
//! This follows draft-connolly-cfrg-xwing-kem-10:
//!   sk        = 32-byte decapsulation seed
//!   pk        = ML-KEM-768 public key || X25519 public key
//!   ct        = ML-KEM-768 ciphertext || X25519 ephemeral public key
//!   shared    = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
//!
//! The ML-KEM public key and ciphertext are bound through ML-KEM's FIPS 203
//! Fujisaki-Okamoto transform; X-Wing deliberately hashes only the X25519
//! ciphertext and public key in the final combiner.
const std = @import("std");
const Secret = @import("secret.zig").Secret;
const zig_compat = @import("zig_compat.zig");

const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const Shake256 = std.crypto.hash.sha3.Shake256;
const X25519 = std.crypto.dh.X25519;
const MlKem768 = std.crypto.kem.ml_kem.MLKem768;

pub const mlkem_public_len = MlKem768.PublicKey.encoded_length;
pub const mlkem_secret_len = MlKem768.SecretKey.encoded_length;
pub const mlkem_ciphertext_len = MlKem768.ciphertext_length;
pub const mlkem_shared_len = MlKem768.shared_length;

pub const x25519_public_len = X25519.public_length;
pub const x25519_secret_len = X25519.secret_length;
pub const x25519_shared_len = X25519.shared_length;

pub const secret_key_len = 32;
pub const public_key_len = mlkem_public_len + x25519_public_len;
pub const ciphertext_len = mlkem_ciphertext_len + x25519_public_len;
pub const shared_len = 32;
pub const expanded_secret_len = MlKem768.seed_length + x25519_secret_len;
pub const encaps_seed_len = MlKem768.encaps_seed_length + x25519_secret_len;

pub const PublicKey = [public_key_len]u8;
pub const SecretKey = Secret([secret_key_len]u8);
pub const Ciphertext = [ciphertext_len]u8;
pub const SharedSecret = Secret([shared_len]u8);

pub const Error = std.crypto.errors.NonCanonicalError || error{
    LowOrderPoint,
};

const xwing_label = "\x5c\x2e\x2f\x2f\x5e\x5c";

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    pub fn generate(rng: std.Io) KeyPair {
        var seed: [secret_key_len]u8 = undefined;
        while (true) {
            rng.random(&seed);
            return generateDeterministic(seed) catch {
                @branchHint(.unlikely);
                continue;
            };
        }
    }

    pub fn generateDeterministic(seed: [secret_key_len]u8) Error!KeyPair {
        const expanded = try expandDecapsulationKey(seed);
        return .{
            .public_key = publicKeyFromExpanded(&expanded),
            .secret_key = SecretKey.init(seed),
        };
    }

    pub fn wipe(self: *KeyPair) void {
        self.secret_key.wipe();
    }
};

pub const Encapsulation = struct {
    ciphertext: Ciphertext,
    shared: SharedSecret,

    pub fn wipe(self: *Encapsulation) void {
        self.shared.wipe();
    }
};

pub fn encapsulate(pk: PublicKey, rng: std.Io) Error!Encapsulation {
    var seed: [encaps_seed_len]u8 = undefined;
    rng.random(&seed);
    defer secureZero(&seed);
    return encapsulateDeterministic(pk, seed);
}

pub fn encapsulateDeterministic(pk: PublicKey, seed: [encaps_seed_len]u8) Error!Encapsulation {
    const pk_m = try MlKem768.PublicKey.fromBytes(pk[0..mlkem_public_len]);
    const pk_x = pk[mlkem_public_len..public_key_len].*;

    var pq = pk_m.encapsDeterministic(seed[0..MlKem768.encaps_seed_length]);
    defer secureZero(&pq.shared_secret);

    const ek_x = seed[MlKem768.encaps_seed_length..encaps_seed_len].*;
    const ct_x = zig_compat.x25519RecoverPublicKey(ek_x) catch return error.LowOrderPoint;
    const ss_x = X25519.scalarmult(ek_x, pk_x) catch return error.LowOrderPoint;
    try rejectAllZero(ss_x);

    var ct: Ciphertext = undefined;
    ct[0..mlkem_ciphertext_len].* = pq.ciphertext;
    ct[mlkem_ciphertext_len..ciphertext_len].* = ct_x;

    return .{
        .ciphertext = ct,
        .shared = combine(pq.shared_secret, ss_x, ct_x, pk_x),
    };
}

pub fn decapsulate(sk: *const SecretKey, ct: Ciphertext) Error!SharedSecret {
    var expanded = try expandDecapsulationKey(sk.declassify());
    defer expanded.wipe();

    const ct_m = ct[0..mlkem_ciphertext_len].*;
    const ct_x = ct[mlkem_ciphertext_len..ciphertext_len].*;

    var ss_m = try expanded.sk_m.decaps(&ct_m);
    defer secureZero(&ss_m);

    const ss_x = X25519.scalarmult(expanded.sk_x, ct_x) catch return error.LowOrderPoint;
    try rejectAllZero(ss_x);

    return combine(ss_m, ss_x, ct_x, expanded.pk_x);
}

pub fn combine(
    ss_m: [mlkem_shared_len]u8,
    ss_x: [x25519_shared_len]u8,
    ct_x: [x25519_public_len]u8,
    pk_x: [x25519_public_len]u8,
) SharedSecret {
    var hasher = Sha3_256.init(.{});
    hasher.update(&ss_m);
    hasher.update(&ss_x);
    hasher.update(&ct_x);
    hasher.update(&pk_x);
    hasher.update(xwing_label);

    var out: [shared_len]u8 = undefined;
    hasher.final(&out);
    return SharedSecret.init(out);
}

const ExpandedSecret = struct {
    sk_m: MlKem768.SecretKey,
    sk_x: [x25519_secret_len]u8,
    pk_m: [mlkem_public_len]u8,
    pk_x: [x25519_public_len]u8,

    fn wipe(self: *ExpandedSecret) void {
        secureZero(&self.sk_m);
        secureZero(&self.sk_x);
    }
};

fn expandDecapsulationKey(seed: [secret_key_len]u8) Error!ExpandedSecret {
    var expanded_bytes: [expanded_secret_len]u8 = undefined;
    defer secureZero(&expanded_bytes);

    var xof = Shake256.init(.{});
    xof.update(&seed);
    xof.squeeze(&expanded_bytes);

    var mlkem_seed = expanded_bytes[0..MlKem768.seed_length].*;
    defer secureZero(&mlkem_seed);
    const kp_m = try MlKem768.KeyPair.generateDeterministic(mlkem_seed);

    const sk_x = expanded_bytes[MlKem768.seed_length..expanded_secret_len].*;
    const pk_x = zig_compat.x25519RecoverPublicKey(sk_x) catch return error.LowOrderPoint;

    return .{
        .sk_m = kp_m.secret_key,
        .sk_x = sk_x,
        .pk_m = kp_m.public_key.toBytes(),
        .pk_x = pk_x,
    };
}

fn publicKeyFromExpanded(expanded: *const ExpandedSecret) PublicKey {
    var pk: PublicKey = undefined;
    pk[0..mlkem_public_len].* = expanded.pk_m;
    pk[mlkem_public_len..public_key_len].* = expanded.pk_x;
    return pk;
}

fn rejectAllZero(bytes: [32]u8) Error!void {
    var acc: u8 = 0;
    for (bytes) |b| {
        acc |= b;
    }
    if (acc == 0) return error.LowOrderPoint;
}

fn secureZero(value: anytype) void {
    const bytes = std.mem.asBytes(value);
    for (bytes) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectEqualSecret(a: *const SharedSecret, b: *const SharedSecret) !void {
    try std.testing.expect(std.crypto.timing_safe.eql(
        [shared_len]u8,
        a.declassify(),
        b.declassify(),
    ));
}

fn expectDifferentSecret(a: *const SharedSecret, b: *const SharedSecret) !void {
    try std.testing.expect(!std.crypto.timing_safe.eql(
        [shared_len]u8,
        a.declassify(),
        b.declassify(),
    ));
}

test "X-Wing encapsulate/decapsulate round-trip" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, 1);
    defer allocator.free(scratch);

    var kp = try KeyPair.generateDeterministic(hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    defer kp.wipe();

    var enc = try encapsulateDeterministic(kp.public_key, hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"));
    defer enc.wipe();

    var dec = try decapsulate(&kp.secret_key, enc.ciphertext);
    defer dec.wipe();

    try expectEqualSecret(&enc.shared, &dec);
}

test "X-Wing tampered ML-KEM ciphertext implicitly rejects to a different secret" {
    const allocator = std.testing.allocator;

    var kp = try KeyPair.generateDeterministic(@as([secret_key_len]u8, @splat(0x11)));
    defer kp.wipe();

    var enc = try encapsulateDeterministic(kp.public_key, @as([encaps_seed_len]u8, @splat(0x22)));
    defer enc.wipe();

    const tampered_buf = try allocator.dupe(u8, &enc.ciphertext);
    defer allocator.free(tampered_buf);
    tampered_buf[0] ^= 0x01;

    const tampered = tampered_buf[0..ciphertext_len].*;
    var dec = try decapsulate(&kp.secret_key, tampered);
    defer dec.wipe();

    try expectDifferentSecret(&enc.shared, &dec);
}

test "X-Wing combiner is deterministic for fixed inputs" {
    var a = combine(
        @as([mlkem_shared_len]u8, @splat(0x01)),
        @as([x25519_shared_len]u8, @splat(0x02)),
        @as([x25519_public_len]u8, @splat(0x03)),
        @as([x25519_public_len]u8, @splat(0x04)),
    );
    defer a.wipe();
    var b = combine(
        @as([mlkem_shared_len]u8, @splat(0x01)),
        @as([x25519_shared_len]u8, @splat(0x02)),
        @as([x25519_public_len]u8, @splat(0x03)),
        @as([x25519_public_len]u8, @splat(0x04)),
    );
    defer b.wipe();

    try expectEqualSecret(&a, &b);
}

test "X-Wing combiner binds X25519 public key and ciphertext" {
    var baseline = combine(
        @as([mlkem_shared_len]u8, @splat(0x01)),
        @as([x25519_shared_len]u8, @splat(0x02)),
        @as([x25519_public_len]u8, @splat(0x03)),
        @as([x25519_public_len]u8, @splat(0x04)),
    );
    defer baseline.wipe();

    var changed_ct = combine(
        @as([mlkem_shared_len]u8, @splat(0x01)),
        @as([x25519_shared_len]u8, @splat(0x02)),
        @as([x25519_public_len]u8, @splat(0x7f)),
        @as([x25519_public_len]u8, @splat(0x04)),
    );
    defer changed_ct.wipe();

    var changed_pk = combine(
        @as([mlkem_shared_len]u8, @splat(0x01)),
        @as([x25519_shared_len]u8, @splat(0x02)),
        @as([x25519_public_len]u8, @splat(0x03)),
        @as([x25519_public_len]u8, @splat(0x80)),
    );
    defer changed_pk.wipe();

    try expectDifferentSecret(&baseline, &changed_ct);
    try expectDifferentSecret(&baseline, &changed_pk);
}

test "X-Wing public key binding changes encapsulated secret" {
    var a = try KeyPair.generateDeterministic(@as([secret_key_len]u8, @splat(0x33)));
    defer a.wipe();
    var b = try KeyPair.generateDeterministic(@as([secret_key_len]u8, @splat(0x34)));
    defer b.wipe();

    var enc_a = try encapsulateDeterministic(a.public_key, @as([encaps_seed_len]u8, @splat(0x35)));
    defer enc_a.wipe();
    var enc_b = try encapsulateDeterministic(b.public_key, @as([encaps_seed_len]u8, @splat(0x35)));
    defer enc_b.wipe();

    try expectDifferentSecret(&enc_a.shared, &enc_b.shared);
}

test {
    std.testing.refAllDecls(@This());
}
