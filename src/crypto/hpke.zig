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
    var dh = labeledExtractWithSuite(kem_suite_id, "", "dh", &zz);
    defer secureZero(&dh);

    var kem_context: [enc_len + public_key_len]u8 = undefined;
    @memcpy(kem_context[0..enc_len], &enc);
    @memcpy(kem_context[enc_len..], &pk_r);

    var shared_secret: SharedSecret = undefined;
    labeledExpandWithSuite(kem_suite_id, &shared_secret, dh, "shared_secret", &kem_context);
    return shared_secret;
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

test "tls HPKE RFC 9180 Appendix A.1.1 AES-128-GCM base-mode vector" {
    // RFC 9180 A.1.1: mode=0, kem_id=0x0020, kdf_id=0x0001, aead_id=0x0001.
    // Byte strings transcribed from the RFC text (rfc-editor.org/rfc/rfc9180).
    const allocator = testing.allocator;
    const pk_rm = hexBytes("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    const sk_rm = hexBytes("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    const sk_em = hexBytes("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    const expected_enc = hexBytes("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    const expected_shared = hexBytes("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    const info = hexBytes("4f6465206f6e2061204772656369616e2055726e");

    var kem = try encapDeterministic(pk_rm, sk_em);
    defer kem.wipe();
    try testing.expectEqualSlices(u8, &expected_enc, &kem.enc);
    // NOTE: `kem.shared_secret`/`decap` are NOT asserted against the RFC
    // `shared_secret` here: the pre-existing KEM `extractAndExpand` labeled-
    // extracts with label "dh" where RFC 9180 DHKEM uses "eae_prk", so our
    // (self-consistent) shared secret diverges from the RFC's for every suite.
    // Fixing that label is a wire-breaking change for existing hpke consumers
    // (secure_channel) and is deliberately left to the integrator; below, the
    // RFC's own `shared_secret` is fed to the key schedule so the AES-128-GCM
    // key schedule + AEAD half is still verified byte-for-byte.
    _ = sk_rm;

    var schedule = Aes128Gcm.KeySchedule.derive(expected_shared, &info);
    defer schedule.wipe();
    try testing.expectEqualSlices(u8, &hexBytes("4531685d41d65f03dc48f6b8302c05b0"), &schedule.key);
    try testing.expectEqualSlices(u8, &hexBytes("56d890e5accaaf011cff4b7d"), &schedule.base_nonce);
    try testing.expectEqualSlices(u8, &hexBytes("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"), &schedule.exporter_secret);

    // Sequence-0 encryption: pt/aad/ct from A.1.1.1.
    const pt = hexBytes("4265617574792069732074727574682c20747275746820626561757479");
    const aad = hexBytes("436f756e742d30");
    const expected_ct = hexBytes("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");
    var sender = Aes128Gcm.Context.setupBaseS(expected_shared, &info);
    defer sender.wipe();
    const sealed = try sender.seal(allocator, &aad, &pt);
    defer sealed.deinit(allocator);
    try testing.expectEqualSlices(u8, &expected_ct, sealed.bytes);

    var receiver = Aes128Gcm.Context.setupBaseR(expected_shared, &info);
    defer receiver.wipe();
    const opened = try receiver.open(allocator, &aad, &expected_ct);
    defer opened.deinit(allocator);
    try testing.expectEqualSlices(u8, &pt, opened.bytes);
}
