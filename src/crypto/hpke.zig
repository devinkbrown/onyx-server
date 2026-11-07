// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HPKE base mode for DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256, parameterized
//! at comptime over the AEAD suite. Two instantiations are provided:
//! ChaCha20-Poly1305 (`aead_id` 0x0003, the default — the pre-existing
//! top-level API is exactly this instantiation) and AES-128-GCM (`aead_id`
//! 0x0001, as advertised by BoringSSL-style ECH configs).
//!
//! This module is intentionally self-contained and imports only Zig's standard
//! library. It implements the RFC 9180 base-mode path: DHKEM encapsulation,
//! key schedule, sequence-number nonces, and single-shot seal/open helpers.
//! The KEM half is AEAD-independent and shared by every instantiation; only
//! the key schedule (whose HPKE suite_id folds in the AEAD id, and whose key
//! length is the AEAD's Nk) and the seal/open context are per-suite.
//!
//! Wire change (Armor audit A6, 2026-11-07): DHKEM `ExtractAndExpand` now uses
//! the RFC 9180 §4.1 label `"eae_prk"`. Earlier builds used the non-standard
//! label `"dh"`, so every DHKEM shared secret changed: HPKE ciphertexts (and ECH
//! payloads, see `ech_seal.zig`) sealed by a pre-A6 build do not open on this
//! build and vice versa, while standard RFC 9180 / ECH peers now interoperate.
//! The RFC 9180 Appendix A known-answer tests at the bottom of this file pin
//! the byte-exact behavior for both AEAD suites.
const std = @import("std");
const zig_compat = @import("zig_compat.zig");

const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const testing = std.testing;

pub const kem_id: u16 = 0x0020;
pub const kdf_id: u16 = 0x0001;
pub const aead_id_aes128_gcm: u16 = 0x0001;
pub const aead_id_chacha20_poly1305: u16 = 0x0003;
/// The default instantiation's AEAD id (ChaCha20-Poly1305), kept so existing
/// callers reading `hpke.aead_id` keep their exact meaning.
pub const aead_id: u16 = aead_id_chacha20_poly1305;

pub const public_key_len = X25519.public_length;
pub const secret_key_len = X25519.secret_length;
pub const enc_len = X25519.public_length;
pub const shared_secret_len = 32;
pub const max_exporter_secret_len = 32;

pub const PublicKey = [public_key_len]u8;
pub const SecretKey = [secret_key_len]u8;
pub const Enc = [enc_len]u8;
pub const SharedSecret = [shared_secret_len]u8;
pub const ExporterSecret = [max_exporter_secret_len]u8;

const kem_suite_id = "KEM" ++ i2osp2(kem_id);
const hpke_version_label = "HPKE-v1";

pub const Error = error{
    AuthenticationFailed,
    InvalidPublicKey,
    InvalidEncapsulatedKey,
    MessageLimitReached,
};

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    pub fn generate(io: std.Io) KeyPair {
        const kp = X25519.KeyPair.generate(io);
        return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    pub fn generateDeterministic(key_seed: [X25519.seed_length]u8) Error!KeyPair {
        const kp = zig_compat.x25519GenerateDeterministic(key_seed) catch return error.InvalidPublicKey;
        return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
    }

    pub fn wipe(self: *KeyPair) void {
        secureZero(&self.secret_key);
    }
};

pub const Encapsulation = struct {
    shared_secret: SharedSecret,
    enc: Enc,

    pub fn wipe(self: *Encapsulation) void {
        secureZero(&self.shared_secret);
    }
};

pub const Ciphertext = struct {
    bytes: []u8,

    pub fn deinit(self: Ciphertext, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

pub const Plaintext = struct {
    bytes: []u8,

    pub fn deinit(self: Plaintext, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

pub const SealedBase = struct {
    enc: Enc,
    ct: []u8,

    pub fn deinit(self: SealedBase, allocator: std.mem.Allocator) void {
        allocator.free(self.ct);
    }
};

pub fn encap(pk_r: PublicKey, io: std.Io) Error!Encapsulation {
    const eph = KeyPair.generate(io);
    return encapWithKeyPair(pk_r, eph);
}

pub fn encapDeterministic(pk_r: PublicKey, eph_seed: [X25519.seed_length]u8) Error!Encapsulation {
    const eph = try KeyPair.generateDeterministic(eph_seed);
    return encapWithKeyPair(pk_r, eph);
}

pub fn decap(enc: Enc, sk_r: SecretKey) Error!SharedSecret {
    const pk_r = zig_compat.x25519RecoverPublicKey(sk_r) catch return error.InvalidPublicKey;
    var zz = X25519.scalarmult(sk_r, enc) catch return error.InvalidEncapsulatedKey;
    defer secureZero(&zz);
    return extractAndExpand(zz, enc, pk_r);
}

fn encapWithKeyPair(pk_r: PublicKey, eph: KeyPair) Error!Encapsulation {
    var zz = X25519.scalarmult(eph.secret_key, pk_r) catch return error.InvalidPublicKey;
    defer secureZero(&zz);
    return .{
        .shared_secret = extractAndExpand(zz, eph.public_key, pk_r),
        .enc = eph.public_key,
    };
}

fn extractAndExpand(zz: [X25519.shared_length]u8, enc: Enc, pk_r: PublicKey) SharedSecret {
    // RFC 9180 §4.1: eae_prk = LabeledExtract("", "eae_prk", dh). Pre-A6
    // builds used the non-standard label "dh" here (see the module header).
    var eae_prk = labeledExtractWithSuite(kem_suite_id, "", "eae_prk", &zz);
    defer secureZero(&eae_prk);

    var kem_context: [enc_len + public_key_len]u8 = undefined;
    @memcpy(kem_context[0..enc_len], &enc);
    @memcpy(kem_context[enc_len..], &pk_r);

    var shared_secret: SharedSecret = undefined;
    labeledExpandWithSuite(kem_suite_id, &shared_secret, eae_prk, "shared_secret", &kem_context);
    return shared_secret;
}

/// RFC 9180 §7.1.3 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256):
///   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
///   sk      = LabeledExpand(dkp_prk, "sk", "", Nsk)
/// Deterministic; reproduces published vectors from their `ikm` and lets a
/// caller derive an HPKE key pair from seed material.
pub fn deriveKeyPair(ikm: []const u8) Error!KeyPair {
    var dkp_prk = labeledExtractWithSuite(kem_suite_id, "", "dkp_prk", ikm);
    defer secureZero(&dkp_prk);
    var sk: SecretKey = undefined;
    labeledExpandWithSuite(kem_suite_id, &sk, dkp_prk, "sk", "");
    errdefer secureZero(&sk);
    const pk = zig_compat.x25519RecoverPublicKey(sk) catch return error.InvalidPublicKey;
    return .{ .public_key = pk, .secret_key = sk };
}

// HPKE labeled KDF inputs (version label + suite id + label + ikm/info) are all
// small and bounded, so build them in a fixed stack buffer — no allocator, no
// page_allocator+catch-unreachable DoS/panic surface.
const labeled_buf_len = 1024;

fn concatInto(buf: []u8, parts: []const []const u8) []const u8 {
    var n: usize = 0;
    for (parts) |p| {
        std.debug.assert(n + p.len <= buf.len);
        @memcpy(buf[n..][0..p.len], p);
        n += p.len;
    }
    return buf[0..n];
}

fn labeledExtractWithSuite(
    comptime label_suite_id: []const u8,
    salt: []const u8,
    label: []const u8,
    ikm: []const u8,
) [HkdfSha256.prk_length]u8 {
    var buf: [labeled_buf_len]u8 = undefined;
    const labeled_ikm = concatInto(&buf, &.{ hpke_version_label, label_suite_id, label, ikm });
    return HkdfSha256.extract(salt, labeled_ikm);
}

fn labeledExpandWithSuite(
    comptime label_suite_id: []const u8,
    out: []u8,
    prk: [HkdfSha256.prk_length]u8,
    label: []const u8,
    info: []const u8,
) void {
    std.debug.assert(out.len <= std.math.maxInt(u16));
    var len_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_bytes, @intCast(out.len), .big);
    var buf: [labeled_buf_len]u8 = undefined;
    const labeled_info = concatInto(&buf, &.{ &len_bytes, hpke_version_label, label_suite_id, label, info });
    HkdfSha256.expand(out, labeled_info, prk);
}

fn i2osp2(comptime value: u16) [2]u8 {
    return .{ @intCast(value >> 8), @intCast(value & 0xff) };
}

fn secureZero(ptr: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(ptr));
}

/// One HPKE AEAD-suite instantiation: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256
/// with the given AEAD. `AeadType` must expose the std AEAD shape
/// (`key_length`/`nonce_length`/`tag_length`/`encrypt`/`decrypt`).
pub fn Suite(comptime AeadType: type, comptime suite_aead_id: u16) type {
    return struct {
        const SuiteSelf = @This();
        pub const Aead = AeadType;
        pub const aead_id = suite_aead_id;
        pub const key_len = Aead.key_length;
        pub const nonce_len = Aead.nonce_length;
        pub const tag_len = Aead.tag_length;

        pub const Key = [Aead.key_length]u8;
        pub const Nonce = [Aead.nonce_length]u8;
        pub const Tag = [Aead.tag_length]u8;

        const suite_id = "HPKE" ++ i2osp2(kem_id) ++ i2osp2(kdf_id) ++ i2osp2(suite_aead_id);
        const max_sequence: u128 = (@as(u128, 1) << (8 * Aead.nonce_length)) - 1;

        pub fn labeledExtract(salt: []const u8, label: []const u8, ikm: []const u8) [HkdfSha256.prk_length]u8 {
            return labeledExtractWithSuite(suite_id, salt, label, ikm);
        }

        pub fn labeledExpand(
            out: []u8,
            prk: [HkdfSha256.prk_length]u8,
            label: []const u8,
            info: []const u8,
        ) void {
            labeledExpandWithSuite(suite_id, out, prk, label, info);
        }

        pub const KeySchedule = struct {
            key: SuiteSelf.Key,
            base_nonce: SuiteSelf.Nonce,
            exporter_secret: ExporterSecret,

            pub fn derive(shared_secret: SharedSecret, info: []const u8) @This() {
                const zero = [_]u8{};
                var psk_id_hash = SuiteSelf.labeledExtract(&zero, "psk_id_hash", &zero);
                defer secureZero(&psk_id_hash);
                var info_hash = SuiteSelf.labeledExtract(&zero, "info_hash", info);
                defer secureZero(&info_hash);

                var context: [1 + HkdfSha256.prk_length + HkdfSha256.prk_length]u8 = undefined;
                context[0] = 0;
                @memcpy(context[1..][0..HkdfSha256.prk_length], &psk_id_hash);
                @memcpy(context[1 + HkdfSha256.prk_length ..], &info_hash);

                var secret = SuiteSelf.labeledExtract(&shared_secret, "secret", &zero);
                defer secureZero(&secret);

                var schedule: @This() = undefined;
                SuiteSelf.labeledExpand(&schedule.key, secret, "key", &context);
                SuiteSelf.labeledExpand(&schedule.base_nonce, secret, "base_nonce", &context);
                SuiteSelf.labeledExpand(&schedule.exporter_secret, secret, "exp", &context);
                return schedule;
            }

            /// RFC 9180 §5.3 secret export:
            ///   Export(exporter_context, L) =
            ///       LabeledExpand(exporter_secret, "sec", exporter_context, L)
            /// `out.len` (L) must not exceed 255 * Nh (HKDF-SHA256: 8160).
            pub fn exportSecret(self: *const @This(), out: []u8, exporter_context: []const u8) void {
                std.debug.assert(out.len <= 255 * HkdfSha256.prk_length);
                SuiteSelf.labeledExpand(out, self.exporter_secret, "sec", exporter_context);
            }

            pub fn wipe(self: *@This()) void {
                secureZero(&self.key);
                secureZero(&self.base_nonce);
                secureZero(&self.exporter_secret);
            }
        };

        pub const Context = struct {
            key: SuiteSelf.Key,
            base_nonce: SuiteSelf.Nonce,
            seq: u128 = 0,

            pub fn init(schedule: SuiteSelf.KeySchedule) @This() {
                return .{ .key = schedule.key, .base_nonce = schedule.base_nonce };
            }

            pub fn setupBaseS(shared_secret: SharedSecret, info: []const u8) @This() {
                return @This().init(SuiteSelf.KeySchedule.derive(shared_secret, info));
            }

            pub fn setupBaseR(shared_secret: SharedSecret, info: []const u8) @This() {
                return @This().init(SuiteSelf.KeySchedule.derive(shared_secret, info));
            }

            pub fn seal(
                self: *@This(),
                allocator: std.mem.Allocator,
                aad: []const u8,
                pt: []const u8,
            ) (std.mem.Allocator.Error || Error)!Ciphertext {
                const nonce = try self.nextNonce();
                const out = try allocator.alloc(u8, pt.len + SuiteSelf.tag_len);
                const tag: *[SuiteSelf.tag_len]u8 = out[pt.len..][0..SuiteSelf.tag_len];
                SuiteSelf.Aead.encrypt(out[0..pt.len], tag, pt, aad, nonce, self.key);
                return .{ .bytes = out };
            }

            pub fn open(
                self: *@This(),
                allocator: std.mem.Allocator,
                aad: []const u8,
                ct: []const u8,
            ) (std.mem.Allocator.Error || Error)!Plaintext {
                if (ct.len < SuiteSelf.tag_len) return error.AuthenticationFailed;
                const msg_len = ct.len - SuiteSelf.tag_len;
                const nonce = try self.nextNonce();
                const out = try allocator.alloc(u8, msg_len);
                errdefer allocator.free(out);
                const tag: [SuiteSelf.tag_len]u8 = ct[msg_len..][0..SuiteSelf.tag_len].*;
                SuiteSelf.Aead.decrypt(out, ct[0..msg_len], tag, aad, nonce, self.key) catch {
                    return error.AuthenticationFailed;
                };
                return .{ .bytes = out };
            }

            pub fn wipe(self: *@This()) void {
                secureZero(&self.key);
                secureZero(&self.base_nonce);
                self.seq = 0;
            }

            fn nextNonce(self: *@This()) Error!SuiteSelf.Nonce {
                if (self.seq > SuiteSelf.max_sequence) return error.MessageLimitReached;
                const nonce = SuiteSelf.nonceFromSeq(self.base_nonce, self.seq);
                self.seq += 1;
                return nonce;
            }
        };

        pub fn sealBase(
            allocator: std.mem.Allocator,
            pk_r: PublicKey,
            info: []const u8,
            aad: []const u8,
            pt: []const u8,
            io: std.Io,
        ) (std.mem.Allocator.Error || Error)!SealedBase {
            var kem = try encap(pk_r, io);
            defer kem.wipe();
            var ctx = SuiteSelf.Context.setupBaseS(kem.shared_secret, info);
            defer ctx.wipe();
            const ct = try ctx.seal(allocator, aad, pt);
            return .{ .enc = kem.enc, .ct = ct.bytes };
        }

        pub fn sealBaseDeterministic(
            allocator: std.mem.Allocator,
            pk_r: PublicKey,
            info: []const u8,
            aad: []const u8,
            pt: []const u8,
            eph_seed: [X25519.seed_length]u8,
        ) (std.mem.Allocator.Error || Error)!SealedBase {
            var kem = try encapDeterministic(pk_r, eph_seed);
            defer kem.wipe();
            var ctx = SuiteSelf.Context.setupBaseS(kem.shared_secret, info);
            defer ctx.wipe();
            const ct = try ctx.seal(allocator, aad, pt);
            return .{ .enc = kem.enc, .ct = ct.bytes };
        }

        pub fn openBase(
            allocator: std.mem.Allocator,
            enc: Enc,
            sk_r: SecretKey,
            info: []const u8,
            aad: []const u8,
            ct: []const u8,
        ) (std.mem.Allocator.Error || Error)!Plaintext {
            var shared_secret = try decap(enc, sk_r);
            defer secureZero(&shared_secret);
            var ctx = SuiteSelf.Context.setupBaseR(shared_secret, info);
            defer ctx.wipe();
            return ctx.open(allocator, aad, ct);
        }

        pub fn nonceFromSeq(base_nonce: SuiteSelf.Nonce, seq: u128) SuiteSelf.Nonce {
            std.debug.assert(seq <= max_sequence);
            var nonce = base_nonce;
            var seq_bytes: [Aead.nonce_length]u8 = @splat(0);
            var remaining = seq;
            var i: usize = Aead.nonce_length;
            while (i > 0) {
                i -= 1;
                seq_bytes[i] = @truncate(remaining);
                remaining >>= 8;
            }
            for (&nonce, seq_bytes) |*n, s| n.* ^= s;
            return nonce;
        }
    };
}

/// ChaCha20-Poly1305 instantiation (Nk=32, Nn=12, Nt=16) — the default.
pub const ChaCha20Poly1305 = Suite(std.crypto.aead.chacha_poly.ChaCha20Poly1305, aead_id_chacha20_poly1305);
/// AES-128-GCM instantiation (Nk=16, Nn=12, Nt=16).
pub const Aes128Gcm = Suite(std.crypto.aead.aes_gcm.Aes128Gcm, aead_id_aes128_gcm);
/// The default instantiation; the top-level API below is exactly this suite,
/// so pre-existing callers (ech_seal, tls*, secure_channel) are unchanged.
pub const Default = ChaCha20Poly1305;

pub const key_len = Default.key_len;
pub const nonce_len = Default.nonce_len;
pub const tag_len = Default.tag_len;
pub const Key = Default.Key;
pub const Nonce = Default.Nonce;
pub const Tag = Default.Tag;
pub const KeySchedule = Default.KeySchedule;
pub const Context = Default.Context;
pub const labeledExtract = Default.labeledExtract;
pub const labeledExpand = Default.labeledExpand;
pub const sealBase = Default.sealBase;
pub const sealBaseDeterministic = Default.sealBaseDeterministic;
pub const openBase = Default.openBase;
const nonceFromSeq = Default.nonceFromSeq;

fn testSeed(byte: u8) [X25519.seed_length]u8 {
    return @as([X25519.seed_length]u8, @splat(byte));
}

fn expectOpenFails(err: anyerror!Plaintext) !void {
    try testing.expectError(error.AuthenticationFailed, err);
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "encap and decap agree on shared secret" {
    const r = try KeyPair.generateDeterministic(testSeed(0x11));
    var kem = try encapDeterministic(r.public_key, testSeed(0x22));
    defer kem.wipe();

    var decapped = try decap(kem.enc, r.secret_key);
    defer secureZero(&decapped);
    try testing.expectEqualSlices(u8, &kem.shared_secret, &decapped);
}

test "single-shot base mode round trip" {
    const allocator = testing.allocator;
    const r = try KeyPair.generateDeterministic(testSeed(0x33));
    var sealed = try sealBaseDeterministic(
        allocator,
        r.public_key,
        "onyx hpke info",
        "aad",
        "hello hpke",
        testSeed(0x44),
    );
    defer sealed.deinit(allocator);

    const opened = try openBase(allocator, sealed.enc, r.secret_key, "onyx hpke info", "aad", sealed.ct);
    defer opened.deinit(allocator);
    try testing.expectEqualSlices(u8, "hello hpke", opened.bytes);
}

test "multiple seals increment nonce and open in order" {
    const allocator = testing.allocator;
    const r = try KeyPair.generateDeterministic(testSeed(0x55));
    var kem = try encapDeterministic(r.public_key, testSeed(0x66));
    defer kem.wipe();
    var shared_r = try decap(kem.enc, r.secret_key);
    defer secureZero(&shared_r);

    var sender = Context.setupBaseS(kem.shared_secret, "ordered");
    defer sender.wipe();
    var receiver = Context.setupBaseR(shared_r, "ordered");
    defer receiver.wipe();

    const ct1 = try sender.seal(allocator, "aad1", "one");
    defer ct1.deinit(allocator);
    const ct2 = try sender.seal(allocator, "aad2", "two");
    defer ct2.deinit(allocator);
    try testing.expect(!std.mem.eql(u8, ct1.bytes, ct2.bytes));

    const pt1 = try receiver.open(allocator, "aad1", ct1.bytes);
    defer pt1.deinit(allocator);
    const pt2 = try receiver.open(allocator, "aad2", ct2.bytes);
    defer pt2.deinit(allocator);
    try testing.expectEqualSlices(u8, "one", pt1.bytes);
    try testing.expectEqualSlices(u8, "two", pt2.bytes);

    var out_of_order = Context.setupBaseR(shared_r, "ordered");
    defer out_of_order.wipe();
    try expectOpenFails(out_of_order.open(allocator, "aad2", ct2.bytes));
}

test "tamper of ciphertext or aad is rejected" {
    const allocator = testing.allocator;
    const r = try KeyPair.generateDeterministic(testSeed(0x77));
    var sealed = try sealBaseDeterministic(allocator, r.public_key, "info", "aad", "message", testSeed(0x88));
    defer sealed.deinit(allocator);

    var tampered = try allocator.dupe(u8, sealed.ct);
    defer allocator.free(tampered);
    tampered[0] ^= 0x80;
    try expectOpenFails(openBase(allocator, sealed.enc, r.secret_key, "info", "aad", tampered));
    try expectOpenFails(openBase(allocator, sealed.enc, r.secret_key, "info", "wrong aad", sealed.ct));
}

test "decap with wrong key fails to open" {
    const allocator = testing.allocator;
    const r = try KeyPair.generateDeterministic(testSeed(0x99));
    const wrong = try KeyPair.generateDeterministic(testSeed(0xaa));
    var sealed = try sealBaseDeterministic(allocator, r.public_key, "info", "aad", "message", testSeed(0xbb));
    defer sealed.deinit(allocator);

    try expectOpenFails(openBase(allocator, sealed.enc, wrong.secret_key, "info", "aad", sealed.ct));
}

test "info binding rejects different info" {
    const allocator = testing.allocator;
    const r = try KeyPair.generateDeterministic(testSeed(0xcc));
    var sealed = try sealBaseDeterministic(allocator, r.public_key, "correct info", "aad", "message", testSeed(0xdd));
    defer sealed.deinit(allocator);

    try expectOpenFails(openBase(allocator, sealed.enc, r.secret_key, "different info", "aad", sealed.ct));
}

test "nonce construction xors sequence into the low 64 bits" {
    const base = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b };
    const nonce0 = nonceFromSeq(base, 0);
    const nonce1 = nonceFromSeq(base, 1);
    try testing.expectEqualSlices(u8, &base, &nonce0);
    try testing.expectEqualSlices(u8, base[0..4], nonce1[0..4]);
    try testing.expectEqual(@as(u8, base[11] ^ 1), nonce1[11]);
}

test "tls HPKE AES-128-GCM suite single-shot round trip and tamper rejection" {
    const allocator = testing.allocator;
    try testing.expectEqual(@as(u16, 0x0001), Aes128Gcm.aead_id);
    try testing.expectEqual(@as(usize, 16), Aes128Gcm.key_len);
    try testing.expectEqual(@as(usize, 12), Aes128Gcm.nonce_len);
    try testing.expectEqual(@as(usize, 16), Aes128Gcm.tag_len);

    const r = try KeyPair.generateDeterministic(testSeed(0x21));
    var sealed = try Aes128Gcm.sealBaseDeterministic(allocator, r.public_key, "info", "aad", "hello aes-gcm hpke", testSeed(0x32));
    defer sealed.deinit(allocator);

    const opened = try Aes128Gcm.openBase(allocator, sealed.enc, r.secret_key, "info", "aad", sealed.ct);
    defer opened.deinit(allocator);
    try testing.expectEqualSlices(u8, "hello aes-gcm hpke", opened.bytes);

    var tampered = try allocator.dupe(u8, sealed.ct);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try expectOpenFails(Aes128Gcm.openBase(allocator, sealed.enc, r.secret_key, "info", "aad", tampered));
    try expectOpenFails(Aes128Gcm.openBase(allocator, sealed.enc, r.secret_key, "info", "wrong aad", sealed.ct));
}

test "tls HPKE cross-suite mismatch: ChaCha seal does not open as AES-128-GCM and vice versa" {
    const allocator = testing.allocator;
    const r = try KeyPair.generateDeterministic(testSeed(0x43));

    var chacha_sealed = try ChaCha20Poly1305.sealBaseDeterministic(allocator, r.public_key, "info", "aad", "message", testSeed(0x54));
    defer chacha_sealed.deinit(allocator);
    try expectOpenFails(Aes128Gcm.openBase(allocator, chacha_sealed.enc, r.secret_key, "info", "aad", chacha_sealed.ct));

    var aes_sealed = try Aes128Gcm.sealBaseDeterministic(allocator, r.public_key, "info", "aad", "message", testSeed(0x54));
    defer aes_sealed.deinit(allocator);
    try expectOpenFails(ChaCha20Poly1305.openBase(allocator, aes_sealed.enc, r.secret_key, "info", "aad", aes_sealed.ct));
    // Same KEM inputs => same enc; the suites diverge only from the key schedule on.
    try testing.expectEqualSlices(u8, &chacha_sealed.enc, &aes_sealed.enc);
    try testing.expect(!std.mem.eql(u8, chacha_sealed.ct, aes_sealed.ct));
}

// RFC 9180 Appendix A known-answer tests (base mode, mode=0). Every byte
// string below is transcribed from https://www.rfc-editor.org/rfc/rfc9180.txt
// (A.1.1 / A.1.1.1 / A.1.1.2 and A.2.1 / A.2.1.1 / A.2.1.2); they agree with
// the CFRG test-vectors.json (github.com/cfrg/draft-irtf-cfrg-hpke).
const Rfc9180Encryption = struct { seq: u128, aad: []const u8, nonce: []const u8, ct: []const u8 };
const Rfc9180Export = struct { context: []const u8, value: []const u8 };
const Rfc9180BaseVector = struct {
    info: []const u8,
    ikm_e: []const u8,
    pk_em: []const u8,
    sk_em: []const u8,
    ikm_r: []const u8,
    pk_rm: []const u8,
    sk_rm: []const u8,
    enc: []const u8,
    shared_secret: []const u8,
    key: []const u8,
    base_nonce: []const u8,
    exporter_secret: []const u8,
    pt: []const u8,
    encryptions: []const Rfc9180Encryption,
    exports: []const Rfc9180Export,
};

const rfc9180_pt = "4265617574792069732074727574682c20747275746820626561757479";
const rfc9180_info = "4f6465206f6e2061204772656369616e2055726e";

/// RFC 9180 A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
const rfc9180_a_1_1 = Rfc9180BaseVector{
    .info = rfc9180_info,
    .ikm_e = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
    .pk_em = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    .sk_em = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
    .ikm_r = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
    .pk_rm = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
    .sk_rm = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
    .enc = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    .shared_secret = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    .key = "4531685d41d65f03dc48f6b8302c05b0",
    .base_nonce = "56d890e5accaaf011cff4b7d",
    .exporter_secret = "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
    .pt = rfc9180_pt,
    .encryptions = &.{
        .{ .seq = 0, .aad = "436f756e742d30", .nonce = "56d890e5accaaf011cff4b7d", .ct = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a" },
        .{ .seq = 1, .aad = "436f756e742d31", .nonce = "56d890e5accaaf011cff4b7c", .ct = "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84" },
        .{ .seq = 2, .aad = "436f756e742d32", .nonce = "56d890e5accaaf011cff4b7f", .ct = "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180" },
        .{ .seq = 4, .aad = "436f756e742d34", .nonce = "56d890e5accaaf011cff4b79", .ct = "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d" },
        .{ .seq = 255, .aad = "436f756e742d323535", .nonce = "56d890e5accaaf011cff4b82", .ct = "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a" },
        .{ .seq = 256, .aad = "436f756e742d323536", .nonce = "56d890e5accaaf011cff4a7d", .ct = "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2" },
    },
    .exports = &.{
        .{ .context = "", .value = "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee" },
        .{ .context = "00", .value = "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5" },
        .{ .context = "54657374436f6e74657874", .value = "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931" },
    },
};

/// RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
const rfc9180_a_2_1 = Rfc9180BaseVector{
    .info = rfc9180_info,
    .ikm_e = "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
    .pk_em = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    .sk_em = "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
    .ikm_r = "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
    .pk_rm = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
    .sk_rm = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    .enc = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    .shared_secret = "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    .key = "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
    .base_nonce = "5c4d98150661b848853b547f",
    .exporter_secret = "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
    .pt = rfc9180_pt,
    .encryptions = &.{
        .{ .seq = 0, .aad = "436f756e742d30", .nonce = "5c4d98150661b848853b547f", .ct = "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28" },
        .{ .seq = 1, .aad = "436f756e742d31", .nonce = "5c4d98150661b848853b547e", .ct = "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c" },
        .{ .seq = 2, .aad = "436f756e742d32", .nonce = "5c4d98150661b848853b547d", .ct = "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b" },
        .{ .seq = 4, .aad = "436f756e742d34", .nonce = "5c4d98150661b848853b547b", .ct = "63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16" },
        .{ .seq = 255, .aad = "436f756e742d323535", .nonce = "5c4d98150661b848853b5480", .ct = "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c" },
        .{ .seq = 256, .aad = "436f756e742d323536", .nonce = "5c4d98150661b848853b557f", .ct = "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b" },
    },
    .exports = &.{
        .{ .context = "", .value = "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e" },
        .{ .context = "00", .value = "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69" },
        .{ .context = "54657374436f6e74657874", .value = "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53" },
    },
};

/// Runtime hex decode into an owned buffer (vector fields are runtime slices).
fn hexAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hexArray(comptime N: usize, hex: []const u8) ![N]u8 {
    if (hex.len != 2 * N) return error.BadVectorLength;
    var out: [N]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

fn expectHex(allocator: std.mem.Allocator, expected_hex: []const u8, actual: []const u8) !void {
    const expected = try hexAlloc(allocator, expected_hex);
    defer allocator.free(expected);
    try testing.expectEqualSlices(u8, expected, actual);
}

fn checkRfc9180BaseVector(comptime S: type, v: Rfc9180BaseVector) !void {
    const allocator = testing.allocator;
    const ikm_e = try hexArray(32, v.ikm_e);
    const ikm_r = try hexArray(32, v.ikm_r);
    const sk_em = try hexArray(secret_key_len, v.sk_em);
    const sk_rm = try hexArray(secret_key_len, v.sk_rm);
    const pk_rm = try hexArray(public_key_len, v.pk_rm);
    const info = try hexAlloc(allocator, v.info);
    defer allocator.free(info);
    const pt = try hexAlloc(allocator, v.pt);
    defer allocator.free(pt);

    // DeriveKeyPair(ikm) reproduces both published key pairs.
    var eph = try deriveKeyPair(&ikm_e);
    defer eph.wipe();
    try testing.expectEqualSlices(u8, &sk_em, &eph.secret_key);
    try expectHex(allocator, v.pk_em, &eph.public_key);
    var rcp = try deriveKeyPair(&ikm_r);
    defer rcp.wipe();
    try testing.expectEqualSlices(u8, &sk_rm, &rcp.secret_key);
    try testing.expectEqualSlices(u8, &pk_rm, &rcp.public_key);

    // Encap (sender, skEm as the ephemeral) and Decap (recipient) both yield
    // the RFC's enc and DHKEM shared_secret byte for byte.
    var kem = try encapDeterministic(pk_rm, sk_em);
    defer kem.wipe();
    try expectHex(allocator, v.enc, &kem.enc);
    try expectHex(allocator, v.shared_secret, &kem.shared_secret);
    var decapped = try decap(kem.enc, sk_rm);
    defer secureZero(&decapped);
    try expectHex(allocator, v.shared_secret, &decapped);

    // Key schedule.
    var schedule = S.KeySchedule.derive(kem.shared_secret, info);
    defer schedule.wipe();
    try expectHex(allocator, v.key, &schedule.key);
    try expectHex(allocator, v.base_nonce, &schedule.base_nonce);
    try expectHex(allocator, v.exporter_secret, &schedule.exporter_secret);

    // Exported values (L = 32).
    for (v.exports) |e| {
        const ctx_bytes = try hexAlloc(allocator, e.context);
        defer allocator.free(ctx_bytes);
        var exported: [32]u8 = undefined;
        schedule.exportSecret(&exported, ctx_bytes);
        try expectHex(allocator, e.value, &exported);
    }

    // Encryptions at the published sequence numbers (0,1,2,4,255,256): the
    // sender seals and the recipient opens, each from its own setup.
    var sender = S.Context.setupBaseS(kem.shared_secret, info);
    defer sender.wipe();
    var receiver = S.Context.setupBaseR(decapped, info);
    defer receiver.wipe();
    for (v.encryptions) |e| {
        const aad = try hexAlloc(allocator, e.aad);
        defer allocator.free(aad);
        const nonce = S.nonceFromSeq(sender.base_nonce, e.seq);
        try expectHex(allocator, e.nonce, &nonce);
        sender.seq = e.seq;
        const sealed = try sender.seal(allocator, aad, pt);
        defer sealed.deinit(allocator);
        try expectHex(allocator, e.ct, sealed.bytes);

        receiver.seq = e.seq;
        const opened = try receiver.open(allocator, aad, sealed.bytes);
        defer opened.deinit(allocator);
        try testing.expectEqualSlices(u8, pt, opened.bytes);
    }

    // Single-shot API: sealBaseDeterministic/openBase under the same inputs
    // emit the sequence-0 ciphertext.
    const aad0 = try hexAlloc(allocator, v.encryptions[0].aad);
    defer allocator.free(aad0);
    var one_shot = try S.sealBaseDeterministic(allocator, pk_rm, info, aad0, pt, sk_em);
    defer one_shot.deinit(allocator);
    try expectHex(allocator, v.enc, &one_shot.enc);
    try expectHex(allocator, v.encryptions[0].ct, one_shot.ct);
    const opened0 = try S.openBase(allocator, one_shot.enc, sk_rm, info, aad0, one_shot.ct);
    defer opened0.deinit(allocator);
    try testing.expectEqualSlices(u8, pt, opened0.bytes);
}

test "tls HPKE RFC 9180 Appendix A.1.1 AES-128-GCM base-mode vectors" {
    try testing.expectEqual(@as(u16, 0x0001), Aes128Gcm.aead_id);
    try checkRfc9180BaseVector(Aes128Gcm, rfc9180_a_1_1);
}

test "tls HPKE RFC 9180 Appendix A.2.1 ChaCha20-Poly1305 base-mode vectors" {
    try testing.expectEqual(@as(u16, 0x0003), ChaCha20Poly1305.aead_id);
    try checkRfc9180BaseVector(ChaCha20Poly1305, rfc9180_a_2_1);
    // The default top-level API is this suite, so it is pinned by the same vector.
    try testing.expect(Default == ChaCha20Poly1305);
}

test "tls HPKE DHKEM uses the RFC 9180 eae_prk label (A6 regression)" {
    // Recompute the DHKEM shared secret by hand from the RFC A.2.1 inputs with
    // both candidate labels: decap must match "eae_prk" (and the RFC value),
    // never the legacy pre-A6 "dh" label.
    const sk_rm = hexBytes("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    const pk_rm = hexBytes("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    const enc = hexBytes("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    var zz = try X25519.scalarmult(sk_rm, enc);
    defer secureZero(&zz);
    var kem_context: [enc_len + public_key_len]u8 = undefined;
    @memcpy(kem_context[0..enc_len], &enc);
    @memcpy(kem_context[enc_len..], &pk_rm);

    var by_label: [2]SharedSecret = undefined;
    for ([_][]const u8{ "eae_prk", "dh" }, &by_label) |label, *out| {
        var prk = labeledExtractWithSuite(kem_suite_id, "", label, &zz);
        defer secureZero(&prk);
        labeledExpandWithSuite(kem_suite_id, out, prk, "shared_secret", &kem_context);
    }
    var got = try decap(enc, sk_rm);
    defer secureZero(&got);
    try testing.expectEqualSlices(u8, &hexBytes("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"), &by_label[0]);
    try testing.expectEqualSlices(u8, &by_label[0], &got);
    try testing.expect(!std.mem.eql(u8, &by_label[1], &got));
}
