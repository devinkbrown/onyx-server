// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HPKE base mode for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
//! ChaCha20-Poly1305.
//!
//! This module is intentionally self-contained and imports only Zig's standard
//! library. It implements the RFC 9180 base-mode path: DHKEM encapsulation,
//! key schedule, sequence-number nonces, and single-shot seal/open helpers.
const std = @import("std");
const zig_compat = @import("zig_compat.zig");

const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const testing = std.testing;

pub const kem_id: u16 = 0x0020;
pub const kdf_id: u16 = 0x0001;
pub const aead_id: u16 = 0x0003;

pub const public_key_len = X25519.public_length;
pub const secret_key_len = X25519.secret_length;
pub const enc_len = X25519.public_length;
pub const shared_secret_len = 32;
pub const key_len = Aead.key_length;
pub const nonce_len = Aead.nonce_length;
pub const tag_len = Aead.tag_length;
pub const max_exporter_secret_len = 32;
const max_sequence: u128 = (@as(u128, 1) << (8 * nonce_len)) - 1;

pub const PublicKey = [public_key_len]u8;
pub const SecretKey = [secret_key_len]u8;
pub const Enc = [enc_len]u8;
pub const SharedSecret = [shared_secret_len]u8;
pub const Key = [key_len]u8;
pub const Nonce = [nonce_len]u8;
pub const Tag = [tag_len]u8;
pub const ExporterSecret = [max_exporter_secret_len]u8;

const suite_id = "HPKE" ++ i2osp2(kem_id) ++ i2osp2(kdf_id) ++ i2osp2(aead_id);
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

pub const KeySchedule = struct {
    key: Key,
    base_nonce: Nonce,
    exporter_secret: ExporterSecret,

    pub fn derive(shared_secret: SharedSecret, info: []const u8) KeySchedule {
        const zero = [_]u8{};
        var psk_id_hash = labeledExtract(&zero, "psk_id_hash", &zero);
        defer secureZero(&psk_id_hash);
        var info_hash = labeledExtract(&zero, "info_hash", info);
        defer secureZero(&info_hash);

        var context: [1 + HkdfSha256.prk_length + HkdfSha256.prk_length]u8 = undefined;
        context[0] = 0;
        @memcpy(context[1..][0..HkdfSha256.prk_length], &psk_id_hash);
        @memcpy(context[1 + HkdfSha256.prk_length ..], &info_hash);

        var secret = labeledExtract(&shared_secret, "secret", &zero);
        defer secureZero(&secret);

        var schedule: KeySchedule = undefined;
        labeledExpand(&schedule.key, secret, "key", &context);
        labeledExpand(&schedule.base_nonce, secret, "base_nonce", &context);
        labeledExpand(&schedule.exporter_secret, secret, "exp", &context);
        return schedule;
    }

    pub fn wipe(self: *KeySchedule) void {
        secureZero(&self.key);
        secureZero(&self.base_nonce);
        secureZero(&self.exporter_secret);
    }
};

pub const Context = struct {
    key: Key,
    base_nonce: Nonce,
    seq: u128 = 0,

    pub fn init(schedule: KeySchedule) Context {
        return .{ .key = schedule.key, .base_nonce = schedule.base_nonce };
    }

    pub fn setupBaseS(shared_secret: SharedSecret, info: []const u8) Context {
        return Context.init(KeySchedule.derive(shared_secret, info));
    }

    pub fn setupBaseR(shared_secret: SharedSecret, info: []const u8) Context {
        return Context.init(KeySchedule.derive(shared_secret, info));
    }

    pub fn seal(
        self: *Context,
        allocator: std.mem.Allocator,
        aad: []const u8,
        pt: []const u8,
    ) (std.mem.Allocator.Error || Error)!Ciphertext {
        const nonce = try self.nextNonce();
        const out = try allocator.alloc(u8, pt.len + tag_len);
        const tag: *[tag_len]u8 = out[pt.len..][0..tag_len];
        Aead.encrypt(out[0..pt.len], tag, pt, aad, nonce, self.key);
        return .{ .bytes = out };
    }

    pub fn open(
        self: *Context,
        allocator: std.mem.Allocator,
        aad: []const u8,
        ct: []const u8,
    ) (std.mem.Allocator.Error || Error)!Plaintext {
        if (ct.len < tag_len) return error.AuthenticationFailed;
        const msg_len = ct.len - tag_len;
        const nonce = try self.nextNonce();
        const out = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(out);
        const tag: [tag_len]u8 = ct[msg_len..][0..tag_len].*;
        Aead.decrypt(out, ct[0..msg_len], tag, aad, nonce, self.key) catch {
            return error.AuthenticationFailed;
        };
        return .{ .bytes = out };
    }

    pub fn wipe(self: *Context) void {
        secureZero(&self.key);
        secureZero(&self.base_nonce);
        self.seq = 0;
    }

    fn nextNonce(self: *Context) Error!Nonce {
        if (self.seq > max_sequence) return error.MessageLimitReached;
        const nonce = nonceFromSeq(self.base_nonce, self.seq);
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
    var ctx = Context.setupBaseS(kem.shared_secret, info);
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
    var ctx = Context.setupBaseS(kem.shared_secret, info);
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
    var ctx = Context.setupBaseR(shared_secret, info);
    defer ctx.wipe();
    return ctx.open(allocator, aad, ct);
}

fn nonceFromSeq(base_nonce: Nonce, seq: u128) Nonce {
    std.debug.assert(seq <= max_sequence);
    var nonce = base_nonce;
    var seq_bytes: [nonce_len]u8 = @splat(0);
    var remaining = seq;
    var i: usize = nonce_len;
    while (i > 0) {
        i -= 1;
        seq_bytes[i] = @truncate(remaining);
        remaining >>= 8;
    }
    for (&nonce, seq_bytes) |*n, s| n.* ^= s;
    return nonce;
}

fn i2osp2(comptime value: u16) [2]u8 {
    return .{ @intCast(value >> 8), @intCast(value & 0xff) };
}

fn secureZero(ptr: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(ptr));
}

fn testSeed(byte: u8) [X25519.seed_length]u8 {
    return @as([X25519.seed_length]u8, @splat(byte));
}

fn expectOpenFails(err: anyerror!Plaintext) !void {
    try testing.expectError(error.AuthenticationFailed, err);
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
