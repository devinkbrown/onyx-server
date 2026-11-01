// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encrypted Client Hello (ECH) sealing + acceptance machinery — the crypto and
//! wire half of client-side ECH (roadmap 5.1). The `ECHConfigList` parsing lives
//! in `src/proto/ech_config.zig`; this module builds the HPKE `info`, pads the
//! EncodedClientHelloInner, HPKE-seals it under a selected config, serializes the
//! outer `encrypted_client_hello` extension body, and computes the ECH
//! acceptance-confirmation signal the server stamps into `ServerHello.random`.
//!
//! (Named `ech_seal` rather than `ech` to avoid clashing with the pre-existing,
//! unwired `src/proto/ech.zig` config-framing library — see `ech_config.zig`'s
//! header for why the live path uses `ech_config` + this module instead.)
//!
//! HPKE suite: the reused `hpke.zig` implements DHKEM(X25519, HKDF-SHA256) /
//! HKDF-SHA256 with either ChaCha20-Poly1305 or AES-128-GCM, so ECH here
//! supports a config advertising KEM `0x0020`, KDF `0x0001`, and AEAD `0x0003`
//! or `0x0001` (the suite BoringSSL-style ECH configs advertise). A config
//! requiring any other suite is rejected up front (the caller then omits ECH —
//! a byte-identical ClientHello).
//!
//! References: draft-ietf-tls-esni §5.2 (encryption + `info`), §6.1.3 (padding),
//! §7.2 (acceptance confirmation).
const std = @import("std");

const hpke = @import("hpke.zig");
const hkdf_tls13 = @import("hkdf_tls13.zig");
const ech_config = @import("../proto/ech_config.zig");

const Allocator = std.mem.Allocator;

/// The HPKE ids this module (via `hpke.zig`) can seal under.
pub const kem_id: u16 = hpke.kem_id; // DHKEM(X25519, HKDF-SHA256) = 0x0020
pub const kdf_id: u16 = hpke.kdf_id; // HKDF-SHA256 = 0x0001
/// Default/preferred AEAD id, kept for existing callers.
pub const aead_id: u16 = hpke.aead_id; // ChaCha20-Poly1305 = 0x0003
pub const aead_id_aes128_gcm: u16 = hpke.aead_id_aes128_gcm; // AES-128-GCM = 0x0001

/// The AEAD id `beginSeal` will use for `cfg`, or null when the config
/// advertises no `{kdf_id, aead}` suite this module can seal under.
/// ChaCha20-Poly1305 is preferred when both are advertised, preserving the
/// exact wire behavior configs usable before AES-128-GCM support produced.
pub fn selectAeadId(cfg: ech_config.Config) ?u16 {
    if (cfg.supportsSuite(kdf_id, aead_id)) return aead_id;
    if (cfg.supportsSuite(kdf_id, aead_id_aes128_gcm)) return aead_id_aes128_gcm;
    return null;
}

/// Expected HPKE recipient public-key length for our KEM (X25519 = 32). A
/// KEM-`0x0020` config whose `public_key` is any other length is not sealable;
/// the client checks this before offering ECH so `beginSeal` never fails on it.
pub const hpke_public_key_len: usize = hpke.public_key_len;

/// The `encrypted_client_hello` extension type (draft-ietf-tls-esni).
pub const extension_type: u16 = 0xfe0d;

/// AEAD tag length of the ECH HPKE suites (16 for both ChaCha20-Poly1305 and
/// AES-128-GCM). The sealed ECH payload is `len(EncodedClientHelloInner) + tag_len`.
pub const tag_len: usize = hpke.tag_len;

/// HPKE `info` label prefix: the 7-byte ASCII string "tls ech" then a 0x00.
pub const info_prefix = "tls ech\x00";

/// Length of the ECH acceptance-confirmation signal (`ServerHello.random[24..32]`).
pub const confirmation_len: usize = 8;

/// The ECHClientHello inner marker: `ECHClientHelloType.inner` (=1) with an empty
/// body. This single byte is the entire inner `encrypted_client_hello` extension
/// data placed in the ClientHelloInner.
pub const inner_ext_body = [_]u8{0x01};

/// `ECHClientHelloType` (draft-ietf-tls-esni §5).
pub const ClientHelloType = enum(u8) { outer = 0, inner = 1 };

/// Which acceptance-confirmation label to use.
pub const ConfirmationKind = enum { server_hello, hello_retry_request };

pub const Error = error{
    /// The config's HPKE suite is not one this module can seal under.
    UnsupportedEchSuite,
    /// A supplied buffer/length is inconsistent with what was requested.
    BadLength,
} || hpke.Error || Allocator.Error || hkdf_tls13.Error;

/// Result of `seal`: the HPKE encapsulated key (`enc`) placed in the outer ECH
/// extension of ClientHello1, and the AEAD ciphertext (`payload`, owned by the
/// caller). Only ClientHello1 carries a non-empty `enc`; an HRR retry reuses the
/// same context and sends an empty `enc` (a deferred follow-up).
pub const SealResult = struct {
    enc: [hpke.enc_len]u8,
    payload: []u8,
    /// The AEAD id actually sealed under (0x0003 or 0x0001); serialize it with
    /// `writeOuterExtBodyForSuite` so the outer extension names the true suite.
    aead_id: u16 = aead_id,

    pub fn deinit(self: SealResult, allocator: Allocator) void {
        allocator.free(self.payload);
    }
};

/// Build the HPKE `info` for a selected config: `"tls ech"‖0x00‖ECHConfig`, where
/// `ECHConfig` is the full serialized entry (`cfg.raw`). Caller owns the result.
pub fn buildInfo(allocator: Allocator, cfg: ech_config.Config) Allocator.Error![]u8 {
    const info = try allocator.alloc(u8, info_prefix.len + cfg.raw.len);
    @memcpy(info[0..info_prefix.len], info_prefix);
    @memcpy(info[info_prefix.len..], cfg.raw);
    return info;
}

/// Number of zero bytes to append to a pre-padding EncodedClientHelloInner so its
/// length does not leak the true server name (draft-ietf-tls-esni §6.1.3). This
/// is the SNI-present branch: the ClientHelloInner always carries a real SNI.
///
///   pad = max(0, maximum_name_length - server_name_len)
///   L   = encoded_len + pad
///   pad += 31 - ((L - 1) % 32)      // round the total up to a multiple of 32
pub fn paddingLen(encoded_len: usize, server_name_len: usize, maximum_name_length: usize) usize {
    std.debug.assert(encoded_len > 0);
    var pad: usize = if (server_name_len < maximum_name_length)
        maximum_name_length - server_name_len
    else
        0;
    const l = encoded_len + pad;
    pad += 31 - ((l - 1) % 32);
    return pad;
}

/// A prepared HPKE sender context. The ECH `enc` (HPKE encapsulated key) is
/// derived purely from `eph_seed` and the recipient key — independent of the
/// plaintext and AAD — so `enc` is available *before* the ClientHelloOuterAAD is
/// built. That is what breaks the AAD's apparent circularity: the AAD contains
/// `enc` but not the (as-yet-unsealed) payload, so the caller reads `enc` here,
/// builds the AAD with a zeroed payload placeholder, then calls `seal`.
pub const Sealer = struct {
    enc: [hpke.enc_len]u8,
    /// The AEAD id this sealer seals under (0x0003 or 0x0001), selected from
    /// the config by `beginSeal`. Serialize it via `writeOuterExtBodyForSuite`.
    aead_id: u16 = aead_id,
    ctx: union(enum) {
        chacha20_poly1305: hpke.ChaCha20Poly1305.Context,
        aes128_gcm: hpke.Aes128Gcm.Context,
    },

    /// Seal `pt` (the padded EncodedClientHelloInner) under `aad` (the
    /// ClientHelloOuterAAD). Single-use: the context is wiped afterward. Returns
    /// the owned ciphertext payload.
    pub fn seal(self: *Sealer, allocator: Allocator, aad: []const u8, pt: []const u8) Error![]u8 {
        const ct = switch (self.ctx) {
            .chacha20_poly1305 => |*c| try c.seal(allocator, aad, pt),
            .aes128_gcm => |*c| try c.seal(allocator, aad, pt),
        };
        self.wipe();
        return ct.bytes;
    }

    /// Wipe the sender context without sealing (error-path cleanup).
    pub fn wipe(self: *Sealer) void {
        switch (self.ctx) {
            .chacha20_poly1305 => |*c| c.wipe(),
            .aes128_gcm => |*c| c.wipe(),
        }
    }
};

/// Set up the HPKE sender context for a selected config and ephemeral seed,
/// exposing `enc` up front. Deterministic in `eph_seed` (the caller supplies
/// fresh OS entropy) so the ephemeral is testable and never touches a hidden RNG.
/// Rejects a config whose suite `hpke.zig` cannot seal under.
pub fn beginSeal(
    allocator: Allocator,
    cfg: ech_config.Config,
    eph_seed: [hpke.secret_key_len]u8,
) Error!Sealer {
    if (cfg.kem_id != kem_id) return error.UnsupportedEchSuite;
    const selected_aead_id = selectAeadId(cfg) orelse return error.UnsupportedEchSuite;
    if (cfg.public_key.len != hpke.public_key_len) return error.UnsupportedEchSuite;

    var pk_r: hpke.PublicKey = undefined;
    @memcpy(&pk_r, cfg.public_key);

    const info = try buildInfo(allocator, cfg);
    defer allocator.free(info);

    // A config whose public key is not a usable X25519 point (e.g. all-zero /
    // small-order) is not a config this module can seal under.
    var kem = hpke.encapDeterministic(pk_r, eph_seed) catch return error.UnsupportedEchSuite;
    defer kem.wipe();
    if (selected_aead_id == aead_id_aes128_gcm) {
        return .{
            .enc = kem.enc,
            .aead_id = selected_aead_id,
            .ctx = .{ .aes128_gcm = hpke.Aes128Gcm.Context.setupBaseS(kem.shared_secret, info) },
        };
    }
    return .{
        .enc = kem.enc,
        .aead_id = selected_aead_id,
        .ctx = .{ .chacha20_poly1305 = hpke.ChaCha20Poly1305.Context.setupBaseS(kem.shared_secret, info) },
    };
}

/// One-shot convenience: `beginSeal` then `seal`. The ECH client path uses the
/// two-step form (it needs `enc` before the AAD); tests use this.
pub fn seal(
    allocator: Allocator,
    cfg: ech_config.Config,
    encoded_inner: []const u8,
    aad: []const u8,
    eph_seed: [hpke.secret_key_len]u8,
) Error!SealResult {
    var sealer = try beginSeal(allocator, cfg, eph_seed);
    errdefer sealer.wipe();
    const payload = try sealer.seal(allocator, aad, encoded_inner);
    return .{ .enc = sealer.enc, .payload = payload, .aead_id = sealer.aead_id };
}

/// Exact serialized length of the outer `encrypted_client_hello` extension *body*
/// (the extension data, without the 2-byte type + 2-byte length header).
pub fn outerExtBodyLen(enc_len: usize, payload_len: usize) usize {
    // type(1) + kdf(2) + aead(2) + config_id(1) + enc_vec(2+enc) + payload_vec(2+payload)
    return 1 + 2 + 2 + 1 + 2 + enc_len + 2 + payload_len;
}

/// Serialize the outer `encrypted_client_hello` extension body into `out`, which
/// must be exactly `outerExtBodyLen(enc.len, payload.len)` bytes. Returns the
/// filled slice. Structure (draft-ietf-tls-esni §5, ECHClientHello, outer):
///
///   ECHClientHelloType type = outer(0)
///   HpkeSymmetricCipherSuite cipher_suite { kdf_id, aead_id }
///   uint8  config_id
///   opaque enc<0..2^16-1>
///   opaque payload<1..2^16-1>
pub fn writeOuterExtBody(
    out: []u8,
    config_id: u8,
    enc: []const u8,
    payload: []const u8,
) Error![]const u8 {
    return writeOuterExtBodyForSuite(out, config_id, enc, payload, aead_id);
}

/// As `writeOuterExtBody`, but stamps `suite_aead_id` (the AEAD actually
/// sealed under, e.g. `Sealer.aead_id`) into the cipher_suite field. Rejects
/// an AEAD id this module cannot seal under.
pub fn writeOuterExtBodyForSuite(
    out: []u8,
    config_id: u8,
    enc: []const u8,
    payload: []const u8,
    suite_aead_id: u16,
) Error![]const u8 {
    if (suite_aead_id != aead_id and suite_aead_id != aead_id_aes128_gcm) return error.UnsupportedEchSuite;
    if (enc.len > std.math.maxInt(u16) or payload.len > std.math.maxInt(u16)) return error.BadLength;
    if (payload.len == 0) return error.BadLength; // payload<1..2^16-1>
    const need = outerExtBodyLen(enc.len, payload.len);
    if (out.len != need) return error.BadLength;

    var n: usize = 0;
    out[n] = @backingInt(ClientHelloType.outer);
    n += 1;
    std.mem.writeInt(u16, out[n..][0..2], kdf_id, .big);
    n += 2;
    std.mem.writeInt(u16, out[n..][0..2], suite_aead_id, .big);
    n += 2;
    out[n] = config_id;
    n += 1;
    std.mem.writeInt(u16, out[n..][0..2], @intCast(enc.len), .big);
    n += 2;
    @memcpy(out[n..][0..enc.len], enc);
    n += enc.len;
    std.mem.writeInt(u16, out[n..][0..2], @intCast(payload.len), .big);
    n += 2;
    @memcpy(out[n..][0..payload.len], payload);
    n += payload.len;
    std.debug.assert(n == need);
    return out[0..need];
}

/// Compute the ECH acceptance confirmation (draft-ietf-tls-esni §7.2):
///
///   accept_confirmation =
///       HKDF-Expand-Label(
///           HKDF-Extract(0, ClientHelloInner.random),
///           "ech accept confirmation" | "hrr ech accept confirmation",
///           transcript_hash,   // Transcript-Hash(ClientHelloInner..ServerHelloECHConf)
///           8)
///
/// `KS` is the negotiated cipher suite's `hkdf_tls13.KeySchedule` (SHA-256 or
/// SHA-384). `transcript_hash` must be that suite's hash length. The server
/// stamps this value into `ServerHello.random[24..32]` iff it accepted ECH; the
/// client recomputes it over the ClientHelloInner transcript and compares.
pub fn acceptConfirmation(
    comptime KS: type,
    inner_random: []const u8,
    transcript_hash: []const u8,
    kind: ConfirmationKind,
    out: *[confirmation_len]u8,
) Error!void {
    if (inner_random.len != 32) return error.BadLength;
    if (transcript_hash.len != KS.hash_len) return error.BadLength;

    // HKDF-Extract(0, ClientHelloInner.random): earlySecret uses a HashLen zero
    // salt and the given IKM — exactly the "0 salt" extract the ECH spec calls for.
    var early = KS.earlySecret(inner_random);
    defer early.wipe();

    switch (kind) {
        .server_hello => try KS.hkdfExpandLabel(&early, "ech accept confirmation", transcript_hash, out[0..]),
        .hello_retry_request => try KS.hkdfExpandLabel(&early, "hrr ech accept confirmation", transcript_hash, out[0..]),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const testing = std.testing;
const Sha256 = hkdf_tls13.Sha256;
const Sha384 = hkdf_tls13.Sha384;

/// Assemble a one-entry ECHConfigList around `pk` and parse it back into a
/// `Config`. The returned `Config` borrows `list_buf`, so keep it alive.
fn testConfig(list_buf: []u8, config_id: u8, pk: []const u8, public_name: []const u8) !ech_config.Config {
    return testConfigForAead(list_buf, config_id, pk, public_name, aead_id);
}

fn testConfigForAead(list_buf: []u8, config_id: u8, pk: []const u8, public_name: []const u8, suite_aead_id: u16) !ech_config.Config {
    var contents: [512]u8 = undefined;
    var n: usize = 0;
    contents[n] = config_id;
    n += 1;
    std.mem.writeInt(u16, contents[n..][0..2], kem_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], @intCast(pk.len), .big);
    n += 2;
    @memcpy(contents[n..][0..pk.len], pk);
    n += pk.len;
    std.mem.writeInt(u16, contents[n..][0..2], 4, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], kdf_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], suite_aead_id, .big);
    n += 2;
    contents[n] = 64;
    n += 1; // maximum_name_length
    contents[n] = @intCast(public_name.len);
    n += 1;
    @memcpy(contents[n..][0..public_name.len], public_name);
    n += public_name.len;
    std.mem.writeInt(u16, contents[n..][0..2], 0, .big);
    n += 2; // extensions

    var entry: [560]u8 = undefined;
    var m: usize = 0;
    std.mem.writeInt(u16, entry[m..][0..2], ech_config.version_draft13, .big);
    m += 2;
    std.mem.writeInt(u16, entry[m..][0..2], @intCast(n), .big);
    m += 2;
    @memcpy(entry[m..][0..n], contents[0..n]);
    m += n;

    std.mem.writeInt(u16, list_buf[0..2], @intCast(m), .big);
    @memcpy(list_buf[2..][0..m], entry[0..m]);
    return (try ech_config.selectSupported(list_buf[0 .. 2 + m], kem_id, kdf_id, suite_aead_id)).?;
}

test "seal round-trips: a test 'server' opens the ECH payload" {
    const allocator = testing.allocator;
    // A deterministic HPKE recipient keypair (the config holder / server).
    const kp = try hpke.KeyPair.generateDeterministic(@splat(0x51));

    var list_buf: [600]u8 = undefined;
    const cfg = try testConfig(&list_buf, 3, &kp.public_key, "cover.example");

    const encoded_inner = "this stands in for the EncodedClientHelloInner bytes, padded";
    const aad = "ClientHelloOuterAAD with payload zeroed";
    var sealed = try seal(allocator, cfg, encoded_inner, aad, @splat(0x62));
    defer sealed.deinit(allocator);

    // The server re-derives the same HPKE info from the config and opens.
    const info = try buildInfo(allocator, cfg);
    defer allocator.free(info);
    const opened = try hpke.openBase(allocator, sealed.enc, kp.secret_key, info, aad, sealed.payload);
    defer opened.deinit(allocator);
    try testing.expectEqualSlices(u8, encoded_inner, opened.bytes);
}

test "seal rejects wrong AAD (bound to ClientHelloOuterAAD)" {
    const allocator = testing.allocator;
    const kp = try hpke.KeyPair.generateDeterministic(@splat(0x71));
    var list_buf: [600]u8 = undefined;
    const cfg = try testConfig(&list_buf, 1, &kp.public_key, "a.example");

    var sealed = try seal(allocator, cfg, "inner", "correct aad", @splat(0x11));
    defer sealed.deinit(allocator);

    const info = try buildInfo(allocator, cfg);
    defer allocator.free(info);
    try testing.expectError(
        error.AuthenticationFailed,
        hpke.openBase(allocator, sealed.enc, kp.secret_key, info, "WRONG aad", sealed.payload),
    );
}

test "seal rejects an unsupported HPKE suite config" {
    const allocator = testing.allocator;
    // Forge a Config that advertises a different KEM.
    const zero_pk: [32]u8 = @splat(0);
    var cfg = ech_config.Config{
        .raw = &.{},
        .version = ech_config.version_draft13,
        .config_id = 0,
        .kem_id = 0x0010, // P-256 KEM — unsupported here
        .public_key = &zero_pk,
        .cipher_suites = &[_]u8{ 0x00, 0x01, 0x00, 0x03 },
        .maximum_name_length = 16,
        .public_name = "a.example",
        .extensions = &.{},
    };
    try testing.expectError(error.UnsupportedEchSuite, seal(allocator, cfg, "inner", "aad", @splat(0)));
    // Also reject a supported KEM but wrong AEAD.
    cfg.kem_id = kem_id;
    cfg.cipher_suites = &[_]u8{ 0x00, 0x01, 0x00, 0x02 };
    try testing.expectError(error.UnsupportedEchSuite, seal(allocator, cfg, "inner", "aad", @splat(0)));
}

test "tls Encrypted Client Hello seal accepts an AES-128-GCM config and rejects a bogus aead_id" {
    const allocator = testing.allocator;
    const kp = try hpke.KeyPair.generateDeterministic(@splat(0x2E));

    var list_buf: [600]u8 = undefined;
    const cfg = try testConfigForAead(&list_buf, 9, &kp.public_key, "cover.example", aead_id_aes128_gcm);
    try testing.expectEqual(@as(?u16, aead_id_aes128_gcm), selectAeadId(cfg));

    const encoded_inner = "EncodedClientHelloInner bytes for the AES-GCM ECH config";
    const aad = "ClientHelloOuterAAD with payload zeroed";
    var sealed = try seal(allocator, cfg, encoded_inner, aad, @splat(0x3D));
    defer sealed.deinit(allocator);
    try testing.expectEqual(aead_id_aes128_gcm, sealed.aead_id);

    // A server holding the config key opens it under the AES-128-GCM suite...
    const info = try buildInfo(allocator, cfg);
    defer allocator.free(info);
    const opened = try hpke.Aes128Gcm.openBase(allocator, sealed.enc, kp.secret_key, info, aad, sealed.payload);
    defer opened.deinit(allocator);
    try testing.expectEqualSlices(u8, encoded_inner, opened.bytes);
    // ...and not under the ChaCha20-Poly1305 suite.
    try testing.expectError(
        error.AuthenticationFailed,
        hpke.openBase(allocator, sealed.enc, kp.secret_key, info, aad, sealed.payload),
    );

    // The outer extension stamps the suite actually sealed under.
    var body_buf: [256]u8 = undefined;
    const body = try writeOuterExtBodyForSuite(
        body_buf[0..outerExtBodyLen(sealed.enc.len, sealed.payload.len)],
        cfg.config_id,
        &sealed.enc,
        sealed.payload,
        sealed.aead_id,
    );
    try testing.expectEqual(kdf_id, std.mem.readInt(u16, body[1..3], .big));
    try testing.expectEqual(aead_id_aes128_gcm, std.mem.readInt(u16, body[3..5], .big));
    try testing.expectError(
        error.UnsupportedEchSuite,
        writeOuterExtBodyForSuite(body_buf[0..outerExtBodyLen(sealed.enc.len, sealed.payload.len)], cfg.config_id, &sealed.enc, sealed.payload, 0x0002),
    );

    // A bogus aead_id (and an unsupported KDF pairing) is rejected up front.
    var bogus = cfg;
    bogus.cipher_suites = &[_]u8{ 0x00, 0x01, 0x99, 0x99 };
    try testing.expectEqual(@as(?u16, null), selectAeadId(bogus));
    try testing.expectError(error.UnsupportedEchSuite, seal(allocator, bogus, "inner", "aad", @splat(0x3D)));
    bogus.cipher_suites = &[_]u8{ 0x00, 0x03, 0x00, 0x01 }; // AES-GCM but HKDF-SHA512
    try testing.expectError(error.UnsupportedEchSuite, seal(allocator, bogus, "inner", "aad", @splat(0x3D)));
}

test "outer extension body round-trips through the parser" {
    const enc: [hpke.enc_len]u8 = @splat(0xAA);
    const payload: [40]u8 = @splat(0xBB);
    var buf: [200]u8 = undefined;
    const body = try writeOuterExtBody(buf[0..outerExtBodyLen(enc.len, payload.len)], 0x2A, &enc, &payload);

    // Parse it back.
    try testing.expectEqual(@as(u8, 0), body[0]); // type = outer
    try testing.expectEqual(kdf_id, std.mem.readInt(u16, body[1..3], .big));
    try testing.expectEqual(aead_id, std.mem.readInt(u16, body[3..5], .big));
    try testing.expectEqual(@as(u8, 0x2A), body[5]);
    const el = std.mem.readInt(u16, body[6..8], .big);
    try testing.expectEqual(@as(u16, hpke.enc_len), el);
    try testing.expectEqualSlices(u8, &enc, body[8 .. 8 + el]);
    const pl = std.mem.readInt(u16, body[8 + el ..][0..2], .big);
    try testing.expectEqual(@as(u16, payload.len), pl);
    try testing.expectEqualSlices(u8, &payload, body[8 + el + 2 ..][0..pl]);
}

test "writeOuterExtBody rejects an empty payload and a wrong-size buffer" {
    const enc: [hpke.enc_len]u8 = @splat(0);
    var buf: [200]u8 = undefined;
    try testing.expectError(error.BadLength, writeOuterExtBody(buf[0..outerExtBodyLen(enc.len, 0)], 0, &enc, ""));
    // Buffer too small.
    try testing.expectError(error.BadLength, writeOuterExtBody(buf[0..3], 0, &enc, "abc"));
}

test "padding rounds the encoded inner up to a multiple of 32" {
    // server_name shorter than max ⇒ pad up to max, then round to 32.
    // encoded_len=100, name=11 ("cover.examp"), max=64: pad = 53; L=153; +(31-(152%32))
    // 152%32 = 24 ⇒ +7 ⇒ pad=60 ⇒ total 160 (multiple of 32).
    const pad = paddingLen(100, 11, 64);
    try testing.expectEqual(@as(usize, 60), pad);
    try testing.expectEqual(@as(usize, 0), (100 + pad) % 32);

    // name longer than max ⇒ no name-based pad, still round to 32.
    // encoded_len=50, name=200, max=64: pad0=0; L=50; 49%32=17 ⇒ +14 ⇒ 64.
    const pad2 = paddingLen(50, 200, 64);
    try testing.expectEqual(@as(usize, 0), (50 + pad2) % 32);

    // exact multiple already ⇒ zero extra rounding when name==max.
    const pad3 = paddingLen(64, 64, 64);
    try testing.expectEqual(@as(usize, 0), pad3);
}

test "acceptConfirmation is deterministic and label/transcript sensitive" {
    const inner_random: [32]u8 = @splat(0x5A);
    const th: [Sha256.hash_len]u8 = @splat(0x33);

    var a: [confirmation_len]u8 = undefined;
    var b: [confirmation_len]u8 = undefined;
    try acceptConfirmation(Sha256, &inner_random, &th, .server_hello, &a);
    try acceptConfirmation(Sha256, &inner_random, &th, .server_hello, &b);
    try testing.expectEqualSlices(u8, &a, &b); // deterministic

    // Different transcript ⇒ different signal.
    var th2: [Sha256.hash_len]u8 = @splat(0x33);
    th2[0] ^= 0x01;
    var c: [confirmation_len]u8 = undefined;
    try acceptConfirmation(Sha256, &inner_random, &th2, .server_hello, &c);
    try testing.expect(!std.mem.eql(u8, &a, &c));

    // HRR label ⇒ different signal from the ServerHello label.
    var d: [confirmation_len]u8 = undefined;
    try acceptConfirmation(Sha256, &inner_random, &th, .hello_retry_request, &d);
    try testing.expect(!std.mem.eql(u8, &a, &d));

    // Different inner random ⇒ different signal.
    var inner2: [32]u8 = @splat(0x5A);
    inner2[31] ^= 0x80;
    var e: [confirmation_len]u8 = undefined;
    try acceptConfirmation(Sha256, &inner2, &th, .server_hello, &e);
    try testing.expect(!std.mem.eql(u8, &a, &e));
}

test "acceptConfirmation SHA-384 length checks" {
    const inner_random: [32]u8 = @splat(1);
    // Wrong transcript-hash length for the schedule ⇒ BadLength.
    const short: [Sha256.hash_len]u8 = @splat(2);
    var out: [confirmation_len]u8 = undefined;
    try testing.expectError(error.BadLength, acceptConfirmation(Sha384, &inner_random, &short, .server_hello, &out));
    // Correct SHA-384 length works.
    const th384: [Sha384.hash_len]u8 = @splat(2);
    try acceptConfirmation(Sha384, &inner_random, &th384, .server_hello, &out);
}
