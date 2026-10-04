// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.2 primitives for Onyx Server's clean-room socketless handshakes.
//!
//! This module deliberately contains no handshake state machine. It owns only
//! the TLS 1.2 PRF, ECDHE-AEAD key schedule, Finished verify_data, and the
//! RFC 5288 / RFC 7905 AEAD record layer used by the new TLS 1.2 client and
//! server modules.

const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

pub const tls_version: u16 = 0x0303;
pub const record_header_len: usize = 5;
pub const max_plaintext_len: usize = 16 * 1024;
pub const max_ciphertext_len: usize = max_plaintext_len + 256;
pub const master_secret_len: usize = 48;
pub const verify_data_len: usize = 12;
pub const max_hash_len: usize = 48;

pub const Error = error{
    AeadAuthFailed,
    BadRecord,
    BufferTooSmall,
    CiphertextTooLong,
    InputTooLarge,
    PlaintextTooLong,
    RecordOverflow,
    SequenceExhausted,
    UnsupportedCipherSuite,
} || std.mem.Allocator.Error;

/// Refuse sequence `2^64 - 1`. Callers increment only after a successful seal
/// or open, so the counter never wraps to nonce 0 under one traffic key.
pub fn reserveAppSeq(seq: u64) Error!u64 {
    if (seq == std.math.maxInt(u64)) return error.SequenceExhausted;
    return seq;
}

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,

    pub fn fromWire(v: u8) ?ContentType {
        return switch (v) {
            20 => .change_cipher_spec,
            21 => .alert,
            22 => .handshake,
            23 => .application_data,
            else => null,
        };
    }
};

pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    certificate = 11,
    certificate_status = 22,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    _,
};

pub const HashAlg = enum {
    sha256,
    sha384,

    pub fn len(self: HashAlg) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
        };
    }
};

pub const AeadKind = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
};

/// Hardened TLS 1.2 ECDHE-AEAD allow-list. RSA names mean RSA certificate
/// authentication only; static-RSA key exchange is never represented here.
pub const CipherSuite = enum(u16) {
    tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b,
    tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c,
    tls_ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f,
    tls_ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030,
    tls_ecdhe_rsa_with_chacha20_poly1305_sha256 = 0xcca8,
    tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 = 0xcca9,

    pub fn fromWire(v: u16) Error!CipherSuite {
        return switch (v) {
            0xc02b => .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            0xc02c => .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            0xc02f => .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
            0xc030 => .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
            0xcca8 => .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
            0xcca9 => .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            else => error.UnsupportedCipherSuite,
        };
    }

    pub fn isEcdsa(self: CipherSuite) bool {
        return switch (self) {
            .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            => true,
            else => false,
        };
    }

    /// IANA registry name of the suite (static string, e.g.
    /// "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") — surfaced in WHOIS 671.
    pub fn name(self: CipherSuite) []const u8 {
        return switch (self) {
            .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            .tls_ecdhe_rsa_with_aes_128_gcm_sha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            .tls_ecdhe_rsa_with_aes_256_gcm_sha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            .tls_ecdhe_rsa_with_chacha20_poly1305_sha256 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        };
    }

    pub fn aead(self: CipherSuite) AeadKind {
        return switch (self) {
            .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
            => .aes_128_gcm,
            .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
            => .aes_256_gcm,
            .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
            .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            => .chacha20_poly1305,
        };
    }

    pub fn hashAlg(self: CipherSuite) HashAlg {
        return switch (self) {
            .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
            => .sha384,
            else => .sha256,
        };
    }

    pub fn keyLen(self: CipherSuite) usize {
        return switch (self.aead()) {
            .aes_128_gcm => Aes128Gcm.key_length,
            .aes_256_gcm => Aes256Gcm.key_length,
            .chacha20_poly1305 => ChaCha20Poly1305.key_length,
        };
    }

    pub fn fixedIvLen(self: CipherSuite) usize {
        return switch (self.aead()) {
            .aes_128_gcm, .aes_256_gcm => 4,
            .chacha20_poly1305 => ChaCha20Poly1305.nonce_length,
        };
    }

    pub fn explicitNonceLen(self: CipherSuite) usize {
        return switch (self.aead()) {
            .aes_128_gcm, .aes_256_gcm => 8,
            .chacha20_poly1305 => 0,
        };
    }

    pub fn tagLen(self: CipherSuite) usize {
        return switch (self.aead()) {
            .aes_128_gcm => Aes128Gcm.tag_length,
            .aes_256_gcm => Aes256Gcm.tag_length,
            .chacha20_poly1305 => ChaCha20Poly1305.tag_length,
        };
    }
};

pub const allowed_suites = [_]CipherSuite{
    .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
    .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
};

pub const Record = struct {
    content_type: ContentType,
    version: u16,
    fragment: []const u8,
    wire_len: usize,
};

pub const OpenedRecord = struct {
    content_type: ContentType,
    plaintext: []u8,
};

pub const DirectionKeys = struct {
    key: [ChaCha20Poly1305.key_length]u8 = @splat(0),
    iv: [ChaCha20Poly1305.nonce_length]u8 = @splat(0),

    pub fn wipe(self: *DirectionKeys) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
    }
};

pub const KeyMaterial = struct {
    client_write: DirectionKeys = .{},
    server_write: DirectionKeys = .{},

    pub fn wipe(self: *KeyMaterial) void {
        self.client_write.wipe();
        self.server_write.wipe();
    }
};

/// TLS 1.2 P_hash based PRF, where `seed` is concatenated after `label`.
pub fn prf(
    alg: HashAlg,
    secret: []const u8,
    label: []const u8,
    seed: []const u8,
    out: []u8,
) Error!void {
    var seed_buf: [256]u8 = undefined;
    if (label.len + seed.len > seed_buf.len) return error.InputTooLarge;
    @memcpy(seed_buf[0..label.len], label);
    @memcpy(seed_buf[label.len .. label.len + seed.len], seed);
    const full_seed = seed_buf[0 .. label.len + seed.len];
    switch (alg) {
        .sha256 => pHash(HmacSha256, secret, full_seed, out),
        .sha384 => pHash(HmacSha384, secret, full_seed, out),
    }
}

fn pHash(comptime Hmac: type, secret: []const u8, seed: []const u8, out: []u8) void {
    var a: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&a, seed, secret);
    var done: usize = 0;
    while (done < out.len) {
        var block_input: [Hmac.mac_length + 256]u8 = undefined;
        @memcpy(block_input[0..Hmac.mac_length], &a);
        @memcpy(block_input[Hmac.mac_length .. Hmac.mac_length + seed.len], seed);
        var block: [Hmac.mac_length]u8 = undefined;
        Hmac.create(&block, block_input[0 .. Hmac.mac_length + seed.len], secret);
        const n = @min(block.len, out.len - done);
        @memcpy(out[done .. done + n], block[0..n]);
        done += n;
        Hmac.create(&a, &a, secret);
    }
}

pub fn transcriptHash(alg: HashAlg, messages: []const u8, out: *[max_hash_len]u8) []const u8 {
    return switch (alg) {
        .sha256 => {
            var digest: [32]u8 = undefined;
            Sha256.hash(messages, &digest, .{});
            @memcpy(out[0..32], &digest);
            return out[0..32];
        },
        .sha384 => {
            var digest: [48]u8 = undefined;
            Sha384.hash(messages, &digest, .{});
            @memcpy(out[0..48], &digest);
            return out[0..48];
        },
    };
}

pub fn deriveMasterSecret(
    suite: CipherSuite,
    pre_master_secret: []const u8,
    client_random: *const [32]u8,
    server_random: *const [32]u8,
) Error![master_secret_len]u8 {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], client_random);
    @memcpy(seed[32..64], server_random);
    var out: [master_secret_len]u8 = undefined;
    try prf(suite.hashAlg(), pre_master_secret, "master secret", &seed, &out);
    return out;
}

/// RFC 7627 extended master secret:
///   master_secret = PRF(pre_master_secret, "extended master secret", session_hash)
/// where session_hash = Hash(ClientHello .. ClientKeyExchange inclusive) under
/// the suite's PRF hash. Binds the master secret to the full handshake log,
/// closing the Triple-Handshake master-secret-synchronization class.
pub fn deriveExtendedMasterSecret(
    suite: CipherSuite,
    pre_master_secret: []const u8,
    session_hash: []const u8,
) Error![master_secret_len]u8 {
    var out: [master_secret_len]u8 = undefined;
    try prf(suite.hashAlg(), pre_master_secret, "extended master secret", session_hash, &out);
    return out;
}

pub fn deriveKeyMaterial(
    suite: CipherSuite,
    master_secret: *const [master_secret_len]u8,
    client_random: *const [32]u8,
    server_random: *const [32]u8,
) Error!KeyMaterial {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], server_random);
    @memcpy(seed[32..64], client_random);

    const key_len = suite.keyLen();
    const iv_len = suite.fixedIvLen();
    const block_len = key_len * 2 + iv_len * 2;
    var block: [128]u8 = undefined;
    try prf(suite.hashAlg(), master_secret, "key expansion", &seed, block[0..block_len]);

    var keys: KeyMaterial = .{};
    var off: usize = 0;
    @memcpy(keys.client_write.key[0..key_len], block[off .. off + key_len]);
    off += key_len;
    @memcpy(keys.server_write.key[0..key_len], block[off .. off + key_len]);
    off += key_len;
    @memcpy(keys.client_write.iv[0..iv_len], block[off .. off + iv_len]);
    off += iv_len;
    @memcpy(keys.server_write.iv[0..iv_len], block[off .. off + iv_len]);
    return keys;
}

pub fn finishedVerifyData(
    suite: CipherSuite,
    master_secret: *const [master_secret_len]u8,
    label: []const u8,
    handshake_messages: []const u8,
) Error![verify_data_len]u8 {
    var hash_buf: [max_hash_len]u8 = undefined;
    const th = transcriptHash(suite.hashAlg(), handshake_messages, &hash_buf);
    var out: [verify_data_len]u8 = undefined;
    try prf(suite.hashAlg(), master_secret, label, th, &out);
    return out;
}

pub fn completeRecord(buf: []const u8) Error!?Record {
    if (buf.len < record_header_len) return null;
    const ct = ContentType.fromWire(buf[0]) orelse return error.BadRecord;
    const version = std.mem.readInt(u16, buf[1..3], .big);
    // The record-layer ProtocolVersion is a legacy field (RFC 5246 §E.1): real
    // clients send the initial ClientHello record as TLS 1.0 (0x0301) for maximum
    // backward compatibility, then TLS 1.2 (0x0303) afterward. Servers MUST NOT
    // reject a record for its legacy version — the negotiated version comes from
    // the handshake, not this byte. Accept the TLS 1.x family (0x0301–0x0303) and
    // refuse only an obviously wrong major (e.g. SSLv2/3 or TLS 1.3 record
    // framing), which keeps the surface tight without breaking standard clients.
    if (version != 0x0301 and version != 0x0302 and version != tls_version) return error.BadRecord;
    const len = std.mem.readInt(u16, buf[3..5], .big);
    if (len > max_ciphertext_len) return error.CiphertextTooLong;
    const total = record_header_len + @as(usize, len);
    if (buf.len < total) return null;
    return .{
        .content_type = ct,
        .version = version,
        .fragment = buf[record_header_len..total],
        .wire_len = total,
    };
}

pub fn writePlainRecord(
    allocator: std.mem.Allocator,
    content_type: ContentType,
    plaintext: []const u8,
) Error![]u8 {
    if (plaintext.len > max_plaintext_len) return error.PlaintextTooLong;
    const out = try allocator.alloc(u8, record_header_len + plaintext.len);
    out[0] = @intFromEnum(content_type);
    std.mem.writeInt(u16, out[1..3], tls_version, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(plaintext.len), .big);
    @memcpy(out[record_header_len..], plaintext);
    return out;
}

pub fn sealRecordAlloc(
    allocator: std.mem.Allocator,
    suite: CipherSuite,
    keys: *const DirectionKeys,
    seq: u64,
    content_type: ContentType,
    plaintext: []const u8,
) Error![]u8 {
    if (seq == std.math.maxInt(u64)) return error.SequenceExhausted;
    if (plaintext.len > max_plaintext_len) return error.PlaintextTooLong;
    const tag_len = suite.tagLen();
    const explicit_len = suite.explicitNonceLen();
    const fragment_len = explicit_len + plaintext.len + tag_len;
    if (fragment_len > max_ciphertext_len) return error.CiphertextTooLong;
    const out = try allocator.alloc(u8, record_header_len + fragment_len);
    errdefer allocator.free(out);

    out[0] = @intFromEnum(content_type);
    std.mem.writeInt(u16, out[1..3], tls_version, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(fragment_len), .big);

    const nonce = makeNonce(suite, keys.iv, seq);
    var aad = makeAad(seq, content_type, @intCast(plaintext.len));
    const ciphertext = out[record_header_len + explicit_len ..][0..plaintext.len];
    const tag_out = out[record_header_len + explicit_len + plaintext.len ..][0..tag_len];
    if (explicit_len != 0) std.mem.writeInt(u64, out[record_header_len..][0..8], seq, .big);

    switch (suite.aead()) {
        .aes_128_gcm => {
            var key: [Aes128Gcm.key_length]u8 = undefined;
            @memcpy(&key, keys.key[0..Aes128Gcm.key_length]);
            var tag: [Aes128Gcm.tag_length]u8 = undefined;
            Aes128Gcm.encrypt(ciphertext, &tag, plaintext, &aad, nonce, key);
            @memcpy(tag_out, &tag);
        },
        .aes_256_gcm => {
            var key: [Aes256Gcm.key_length]u8 = undefined;
            @memcpy(&key, keys.key[0..Aes256Gcm.key_length]);
            var tag: [Aes256Gcm.tag_length]u8 = undefined;
            Aes256Gcm.encrypt(ciphertext, &tag, plaintext, &aad, nonce, key);
            @memcpy(tag_out, &tag);
        },
        .chacha20_poly1305 => {
            var key: [ChaCha20Poly1305.key_length]u8 = undefined;
            @memcpy(&key, keys.key[0..ChaCha20Poly1305.key_length]);
            var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
            ChaCha20Poly1305.encrypt(ciphertext, &tag, plaintext, &aad, nonce, key);
            @memcpy(tag_out, &tag);
        },
    }
    return out;
}

pub fn openRecordAlloc(
    allocator: std.mem.Allocator,
    suite: CipherSuite,
    keys: *const DirectionKeys,
    seq: u64,
    record: []const u8,
) Error!OpenedRecord {
    if (seq == std.math.maxInt(u64)) return error.SequenceExhausted;
    const parsed = (try completeRecord(record)) orelse return error.BadRecord;
    if (parsed.wire_len != record.len) return error.BadRecord;
    const tag_len = suite.tagLen();
    const explicit_len = suite.explicitNonceLen();
    if (parsed.fragment.len < explicit_len + tag_len) return error.AeadAuthFailed;
    const cipher_len = parsed.fragment.len - explicit_len - tag_len;
    if (cipher_len > max_plaintext_len) return error.RecordOverflow;
    const ciphertext = parsed.fragment[explicit_len .. explicit_len + cipher_len];
    const tag = parsed.fragment[explicit_len + cipher_len ..];
    // AES-GCM (RFC 5288): the 8-byte explicit nonce is chosen by the SENDER and
    // need not equal the record sequence number — the receiver MUST take it from
    // the wire (salt ‖ explicit). Reconstructing it from `seq` and demanding they
    // match rejected every client (OpenSSL, browsers) that picks a different
    // explicit nonce. ChaCha20-Poly1305 (RFC 7905) carries no explicit nonce, so
    // it is still derived from `seq` ⊕ iv. The AAD/anti-replay still bind `seq`.
    const nonce = if (explicit_len != 0) blk: {
        var n: [12]u8 = undefined;
        @memcpy(n[0..4], keys.iv[0..4]);
        @memcpy(n[4..12], parsed.fragment[0..8]);
        break :blk n;
    } else makeNonce(suite, keys.iv, seq);
    var aad = makeAad(seq, parsed.content_type, @intCast(cipher_len));
    const plaintext = try allocator.alloc(u8, cipher_len);
    errdefer allocator.free(plaintext);

    switch (suite.aead()) {
        .aes_128_gcm => {
            var key: [Aes128Gcm.key_length]u8 = undefined;
            @memcpy(&key, keys.key[0..Aes128Gcm.key_length]);
            var tag_arr: [Aes128Gcm.tag_length]u8 = undefined;
            @memcpy(&tag_arr, tag);
            Aes128Gcm.decrypt(plaintext, ciphertext, tag_arr, &aad, nonce, key) catch return error.AeadAuthFailed;
        },
        .aes_256_gcm => {
            var key: [Aes256Gcm.key_length]u8 = undefined;
            @memcpy(&key, keys.key[0..Aes256Gcm.key_length]);
            var tag_arr: [Aes256Gcm.tag_length]u8 = undefined;
            @memcpy(&tag_arr, tag);
            Aes256Gcm.decrypt(plaintext, ciphertext, tag_arr, &aad, nonce, key) catch return error.AeadAuthFailed;
        },
        .chacha20_poly1305 => {
            var key: [ChaCha20Poly1305.key_length]u8 = undefined;
            @memcpy(&key, keys.key[0..ChaCha20Poly1305.key_length]);
            var tag_arr: [ChaCha20Poly1305.tag_length]u8 = undefined;
            @memcpy(&tag_arr, tag);
            ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag_arr, &aad, nonce, key) catch return error.AeadAuthFailed;
        },
    }
    return .{ .content_type = parsed.content_type, .plaintext = plaintext };
}

fn makeNonce(suite: CipherSuite, fixed_iv: [12]u8, seq: u64) [12]u8 {
    var nonce: [12]u8 = @splat(0);
    switch (suite.aead()) {
        .aes_128_gcm, .aes_256_gcm => {
            @memcpy(nonce[0..4], fixed_iv[0..4]);
            std.mem.writeInt(u64, nonce[4..12], seq, .big);
        },
        .chacha20_poly1305 => {
            nonce = fixed_iv;
            var seq_bytes: [12]u8 = @splat(0);
            std.mem.writeInt(u64, seq_bytes[4..12], seq, .big);
            for (&nonce, seq_bytes) |*dst, rhs| dst.* ^= rhs;
        },
    }
    return nonce;
}

fn makeAad(seq: u64, content_type: ContentType, plaintext_len: u16) [13]u8 {
    var aad: [13]u8 = undefined;
    std.mem.writeInt(u64, aad[0..8], seq, .big);
    aad[8] = @intFromEnum(content_type);
    std.mem.writeInt(u16, aad[9..11], tls_version, .big);
    std.mem.writeInt(u16, aad[11..13], plaintext_len, .big);
    return aad;
}

pub fn constantTimeEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

test "completeRecord accepts the legacy ClientHello record version" {
    // Real clients (OpenSSL, browsers) frame the initial ClientHello record with
    // legacy version TLS 1.0 (0x0301). The server must accept it — rejecting it
    // dropped every standards-compliant TLS 1.2 handshake.
    const legacy = [_]u8{ 22, 0x03, 0x01, 0x00, 0x01, 0xff };
    const got = (try completeRecord(&legacy)).?;
    try std.testing.expectEqual(ContentType.handshake, got.content_type);
    try std.testing.expectEqual(@as(usize, 6), got.wire_len);

    // TLS 1.1 (0x0302) and 1.2 (0x0303) are also accepted.
    const v11 = [_]u8{ 22, 0x03, 0x02, 0x00, 0x01, 0xff };
    _ = (try completeRecord(&v11)).?;
    const v12 = [_]u8{ 22, 0x03, 0x03, 0x00, 0x01, 0xff };
    _ = (try completeRecord(&v12)).?;

    // A non-TLS major (SSLv2-style 0x0200) is still rejected.
    const bad = [_]u8{ 22, 0x02, 0x00, 0x00, 0x01, 0xff };
    try std.testing.expectError(error.BadRecord, completeRecord(&bad));
}

test "TLS 1.2 SHA-256 PRF RFC vector" {
    const secret = [_]u8{
        0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
        0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
    };
    const seed = [_]u8{
        0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
        0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c,
    };
    const expected = [_]u8{
        0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b,
        0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53,
        0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95,
        0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e, 0xdb, 0x5a,
        0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9,
        0xc9, 0xa4, 0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf,
        0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
        0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab,
        0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b,
        0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba,
        0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5,
        0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01,
        0x87, 0x34, 0x7b, 0x66,
    };
    var out: [expected.len]u8 = undefined;
    try prf(.sha256, &secret, "test label", &seed, &out);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "tls12 EMS derivation matches an independent P_hash implementation (RFC 7627 KAT)" {
    // Expected values computed with an INDEPENDENT P_SHA256/P_SHA384
    // implementation (Python stdlib hmac/hashlib), not this module's PRF:
    //   master = P_hash(pms, "extended master secret" || session_hash)[0..48].
    // The PRF primitive itself is separately pinned by the RFC 5246 vector above.
    var pms: [32]u8 = undefined;
    for (&pms, 0..) |*b, i| b.* = @intCast(i + 1); // 0x01..0x20

    // SHA-256 suite (session_hash is 32 bytes).
    var sh256: [32]u8 = undefined;
    for (&sh256, 0..) |*b, i| b.* = @intCast(0xa0 + (i % 16));
    const expected256 = [_]u8{
        0x68, 0x42, 0xac, 0x6b, 0x95, 0x5c, 0x45, 0xaa, 0xe1, 0x57, 0x39, 0x4d,
        0xac, 0xb1, 0xab, 0x79, 0xfd, 0x69, 0x83, 0xf7, 0x9b, 0x71, 0x69, 0x0d,
        0x20, 0x2c, 0x76, 0xcc, 0x64, 0xf4, 0xbf, 0x7e, 0x4b, 0x53, 0xaf, 0x11,
        0xca, 0x30, 0xdb, 0x95, 0xa0, 0xcb, 0xd4, 0x72, 0x7d, 0xdb, 0xd1, 0x22,
    };
    const got256 = try deriveExtendedMasterSecret(.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256, &pms, &sh256);
    try std.testing.expectEqualSlices(u8, &expected256, &got256);

    // SHA-384 suite (session_hash is 48 bytes).
    var sh384: [48]u8 = undefined;
    for (&sh384, 0..) |*b, i| b.* = @intCast(0xb0 ^ (i & 0xff));
    const expected384 = [_]u8{
        0x01, 0x17, 0xd1, 0x2e, 0xdd, 0xfc, 0x3c, 0x83, 0x9d, 0x4f, 0xf3, 0xca,
        0x0e, 0x66, 0x09, 0x4d, 0x57, 0x7e, 0xb9, 0x54, 0x77, 0x33, 0xb3, 0x46,
        0xec, 0xb3, 0x74, 0xed, 0x92, 0x97, 0x9f, 0xbb, 0xfe, 0xa4, 0x7e, 0x3e,
        0xf0, 0xb0, 0x80, 0xfa, 0xf0, 0x92, 0x48, 0xce, 0x61, 0xbb, 0xa0, 0x7a,
    };
    const got384 = try deriveExtendedMasterSecret(.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384, &pms, &sh384);
    try std.testing.expectEqualSlices(u8, &expected384, &got384);
}

test "TLS 1.2 AEAD record round trips GCM and ChaCha" {
    const allocator = std.testing.allocator;
    var keys: DirectionKeys = .{};
    for (&keys.key, 0..) |*b, i| b.* = @intCast(i);
    for (&keys.iv, 0..) |*b, i| b.* = @intCast(0xa0 + i);

    inline for (.{ CipherSuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256, CipherSuite.tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 }) |suite| {
        const sealed = try sealRecordAlloc(allocator, suite, &keys, 7, .application_data, "hello tls12");
        defer allocator.free(sealed);
        const opened = try openRecordAlloc(allocator, suite, &keys, 7, sealed);
        defer allocator.free(opened.plaintext);
        try std.testing.expectEqual(ContentType.application_data, opened.content_type);
        try std.testing.expectEqualSlices(u8, "hello tls12", opened.plaintext);
    }
}
