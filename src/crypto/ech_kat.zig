// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Known-answer tests for the ECH seal (`ech_seal.zig`) and the ECH
//! acceptance confirmation.
//!
//! Provenance: draft-ietf-tls-esni-25 (checked 2026-11-07) publishes no test
//! vectors, so these are cross-implementation vectors derived with OpenSSL
//! 3.5.9 (libcrypto), independent of `hpke.zig` and `hkdf_tls13.zig`:
//!   * Seal: OpenSSL's RFC 9180 HPKE (`OSSL_HPKE_encap`/`OSSL_HPKE_seal`, base
//!     mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256) with the ephemeral fixed
//!     through `OSSL_HPKE_CTX_set1_ikme`, `info = "tls ech" || 0x00 ||
//!     ECHConfig` (draft-ietf-tls-esni §6.1) over the ECHConfig bytes below.
//!     The derivation harness first reproduced RFC 9180 A.1.1 through the same
//!     OpenSSL calls. The ephemeral secret Onyx is handed is RFC 9180
//!     DeriveKeyPair(ikmE), which `hpke.deriveKeyPair` computes (and the RFC
//!     9180 vectors in hpke.zig pin).
//!   * Outer extension body: the draft §5 `ECHClientHello` (outer) encoding of
//!     that suite, config_id, enc and payload.
//!   * Acceptance confirmation (draft §7.2): OpenSSL `kdf HKDF` (extract,
//!     zero salt, IKM = ClientHelloInner.random) then `kdf TLS13-KDF`
//!     (HKDF-Expand-Label, "tls13 " prefix) for both labels and both hashes.
//! These pin the ECH wire after the A6 HPKE label fix: a standard RFC 9180
//! HPKE implementation opens what Onyx seals, and vice versa.
const std = @import("std");
const hpke = @import("hpke.zig");
const ech_seal = @import("ech_seal.zig");
const ech_config = @import("../proto/ech_config.zig");
const hkdf_tls13 = @import("hkdf_tls13.zig");

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// Recipient (ECH config holder) X25519 key pair.
const sk_r = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
const pk_r = hex("605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c");
/// OpenSSL's `ikmE` and the RFC 9180 DeriveKeyPair(ikmE) secret it implies.
const ikm_e = hex("404346494c4f5255585b5e6164676a6d707376797c7f8285888b8e9194979a9d");
const sk_e = hex("d87a80f69db6ce4acb065c4176ac7727cabe026e498fcf61ca60d1e887338045");
/// Stand-in EncodedClientHelloInner (64 bytes) and ClientHelloOuterAAD.
const encoded_inner = hex("456e636f646564436c69656e7448656c6c6f496e6e6572207374616e642d696e2c207a65726f2d70616464656420746f20363420627974657300000000000000");
const outer_aad = hex("436c69656e7448656c6c6f4f75746572414144207769746820746865207061796c6f6164207a65726f6564206f7574");

const SealVector = struct {
    aead_id: u16,
    config_id: u8,
    /// One-entry ECHConfigList (version 0xfe0d, public_name "cover.example").
    config_list: []const u8,
    enc: [hpke.enc_len]u8,
    payload: []const u8,
    outer_body: []const u8,
};

const seal_chacha20_poly1305 = SealVector{
    .aead_id = 0x0003,
    .config_id = 7,
    .config_list = &hex("0040fe0d003c0700200020605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c000400010003400d636f7665722e6578616d706c65" ++ "0000"),
    .enc = hex("efff69db6f6e69d58e302e8d51ff5471d65680cb474137409a0b7ebb01e4596c"),
    .payload = &hex("e0b8897745d4de6067df0467fbbbb4b5a11cf04612a86e2a9fd4360df26db74036dffd3ec50d1dd0249d72310dc847106c66c59bf2a65f804fb4a90d6063479a" ++ "d04fea3ee4694aef07183555fece0136"),
    .outer_body = &hex("0000010003070020efff69db6f6e69d58e302e8d51ff5471d65680cb474137409a0b7ebb01e4596c0050e0b8897745d4de6067df0467fbbbb4b5a11cf04612a8" ++ "6e2a9fd4360df26db74036dffd3ec50d1dd0249d72310dc847106c66c59bf2a65f804fb4a90d6063479ad04fea3ee4694aef07183555fece0136"),
};

const seal_aes128_gcm = SealVector{
    .aead_id = 0x0001,
    .config_id = 9,
    .config_list = &hex("0040fe0d003c0900200020605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c000400010001400d636f7665722e6578616d706c65" ++ "0000"),
    .enc = hex("efff69db6f6e69d58e302e8d51ff5471d65680cb474137409a0b7ebb01e4596c"),
    .payload = &hex("f5f37dd70247a2cc35cc2862f9069be78675c233525a31462ce167f5b3aa0f17d2de92b2348fa41006fd57e9592b896a317841c006789491192be19d3d455429" ++ "82fe9ef41d8d7ff9279ecd5738b85fd0"),
    .outer_body = &hex("0000010001090020efff69db6f6e69d58e302e8d51ff5471d65680cb474137409a0b7ebb01e4596c0050f5f37dd70247a2cc35cc2862f9069be78675c233525a" ++ "31462ce167f5b3aa0f17d2de92b2348fa41006fd57e9592b896a317841c006789491192be19d3d45542982fe9ef41d8d7ff9279ecd5738b85fd0"),
};

fn checkSeal(v: SealVector) !void {
    const allocator = testing.allocator;
    const cfg = (try ech_config.selectSupported(v.config_list, ech_seal.kem_id, ech_seal.kdf_id, v.aead_id)).?;
    try testing.expectEqual(v.config_id, cfg.config_id);
    try testing.expectEqualSlices(u8, &pk_r, cfg.public_key);
    try testing.expectEqual(@as(?u16, v.aead_id), ech_seal.selectAeadId(cfg));

    var eph = try hpke.deriveKeyPair(&ikm_e);
    defer eph.wipe();
    try testing.expectEqualSlices(u8, &sk_e, &eph.secret_key);

    // Seal: byte-identical to OpenSSL's RFC 9180 HPKE.
    var sealed = try ech_seal.seal(allocator, cfg, &encoded_inner, &outer_aad, sk_e);
    defer sealed.deinit(allocator);
    try testing.expectEqual(v.aead_id, sealed.aead_id);
    try testing.expectEqualSlices(u8, &v.enc, &sealed.enc);
    try testing.expectEqualSlices(u8, v.payload, sealed.payload);

    var body_buf: [256]u8 = undefined;
    const body = try ech_seal.writeOuterExtBodyForSuite(
        body_buf[0..ech_seal.outerExtBodyLen(sealed.enc.len, sealed.payload.len)],
        cfg.config_id,
        &sealed.enc,
        sealed.payload,
        sealed.aead_id,
    );
    try testing.expectEqualSlices(u8, v.outer_body, body);

    // Open: the server-side HPKE open accepts the OpenSSL-sealed payload.
    const info = try ech_seal.buildInfo(allocator, cfg);
    defer allocator.free(info);
    const opened = switch (v.aead_id) {
        hpke.aead_id_chacha20_poly1305 => try hpke.ChaCha20Poly1305.openBase(allocator, v.enc, sk_r, info, &outer_aad, v.payload),
        hpke.aead_id_aes128_gcm => try hpke.Aes128Gcm.openBase(allocator, v.enc, sk_r, info, &outer_aad, v.payload),
        else => unreachable,
    };
    defer opened.deinit(allocator);
    try testing.expectEqualSlices(u8, &encoded_inner, opened.bytes);
}

test "ECH seal KAT: ChaCha20-Poly1305 config matches OpenSSL RFC 9180 HPKE" {
    try checkSeal(seal_chacha20_poly1305);
}

test "ECH seal KAT: AES-128-GCM config matches OpenSSL RFC 9180 HPKE" {
    try checkSeal(seal_aes128_gcm);
}

const inner_random = hex("5a5b58595e5f5c5d52535051565754554a4b48494e4f4c4d4243404146474445");

test "ECH acceptance confirmation KAT: SHA-256 (ServerHello and HRR labels)" {
    const th = hex("0782b9c604c3d1c65c318f187c9e68baf014805735b5f95716a143a8b05112ec");
    var out: [ech_seal.confirmation_len]u8 = undefined;
    try ech_seal.acceptConfirmation(hkdf_tls13.Sha256, &inner_random, &th, .server_hello, &out);
    try testing.expectEqualSlices(u8, &hex("86027dae71ee1661"), &out);
    try ech_seal.acceptConfirmation(hkdf_tls13.Sha256, &inner_random, &th, .hello_retry_request, &out);
    try testing.expectEqualSlices(u8, &hex("1ec460d54a2d73c0"), &out);
}

test "ECH acceptance confirmation KAT: SHA-384 (ServerHello and HRR labels)" {
    const th = hex("fa18d3a5b3c568b4b3d593f28f5b451356818c8f9f1d009a50bb44c5acc1db1f8d26a3a72d9863a8ae943102cbd36207");
    var out: [ech_seal.confirmation_len]u8 = undefined;
    try ech_seal.acceptConfirmation(hkdf_tls13.Sha384, &inner_random, &th, .server_hello, &out);
    try testing.expectEqualSlices(u8, &hex("d27ee614fc0810d4"), &out);
    try ech_seal.acceptConfirmation(hkdf_tls13.Sha384, &inner_random, &th, .hello_retry_request, &out);
    try testing.expectEqualSlices(u8, &hex("a4fc376eb8a485c1"), &out);
}
