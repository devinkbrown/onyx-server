// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! QUIC v1 address validation: Retry, validation tokens, Version Negotiation,
//! and the stateless-reset token derivation (RFC 9000 §8 / §17.2.1 / §17.2.5,
//! RFC 9001 §5.8, RFC 9000 §10.3).
//!
//! This module is the server-side anti-reflection / anti-amplification toolkit
//! for the public WebTransport UDP endpoint. It is socketless and (almost)
//! allocation-light: every encoder writes into a caller-owned buffer and reports
//! the number of bytes used. The one stateful object is `Secret`, a per-process
//! key bundle minted from `secure_fns.randomBytes` that keys the
//! address-validation token AEAD and the stateless-reset HMAC.
//!
//! What lives here
//! ---------------
//!   * `retryIntegrityTag` / `encodeRetry` — the Retry packet (RFC 9000 §17.2.5)
//!     and its 16-byte integrity tag (RFC 9001 §5.8). The tag is an
//!     AEAD_AES_128_GCM over the *Retry pseudo-packet* using the FIXED v1 key
//!     `be0c690b9f66575a1d766b54e368c84e` and nonce `461599d35d632bf2239825bb`.
//!     This is a wire contract: the bytes are reproduced exactly, and the test
//!     at the bottom checks them against the RFC 9001 §A.4 vector.
//!   * `Token` (`seal` / `verify`) — an address-validation token (RFC 9000
//!     §8.1.2). It binds the client IP, the original Destination Connection ID
//!     the client chose, and an issue timestamp, sealed with AES-256-GCM under
//!     the per-process token key. A client that echoes the token in its next
//!     Initial is address-validated immediately (no 3× amplification limit). The
//!     verifier rejects a token from a different IP, an expired token, or a
//!     replayed token (a small bounded replay cache).
//!   * `encodeVersionNegotiation` — the Version Negotiation packet (RFC 9000
//!     §17.2.1): when an Initial arrives with an unsupported QUIC version the
//!     server replies with a VN packet listing the versions it supports (just
//!     v1). It is never larger than the triggering packet's wire length, so it
//!     cannot be used as an amplifier.
//!   * `statelessResetToken` / `statelessResetTokenWithKey` — the 16-byte
//!     stateless-reset token (RFC 9000 §10.3) derived as
//!     HMAC-SHA256(reset_key, connection_id)[0..16]. RFC 9000 §10.3.2
//!     recommends a *static* key so tokens survive a restart (the case a reset
//!     exists for); `deriveStaticResetKey` turns long-lived operator material
//!     into such a key with domain separation.
//!   * `encodeStatelessReset`, `statelessResetLen`, `RecentResets` — the send
//!     path's packet format and its loop/amplification guards: a reset is
//!     always strictly shorter than its trigger (§10.3.3, so two endpoints can
//!     never reset each other forever) and is never sent in response to a
//!     packet that ends in a token we derive or recently emitted (it could be
//!     one of our own resets reflected back). The listener adds rate limiting.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;

const quic_packet = @import("quic_packet.zig");
const secure_fns = @import("secure_fns.zig");

const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

/// QUIC v1 (RFC 9000 §15). The only version we support.
pub const quic_version_1: u32 = 0x0000_0001;

/// AEAD tag length shared by the Retry integrity tag, token AEAD, and reset
/// token (16 bytes for AES-GCM and the truncated HMAC).
pub const tag_len: usize = 16;

/// Length of an address-validation / stateless-reset token's authentication tag.
pub const stateless_reset_token_len: usize = 16;

pub const RetryError = error{
    /// The output buffer was too small for the encoded packet.
    BufferTooSmall,
    /// A connection id exceeded the QUIC maximum (20 bytes).
    ConnectionIdTooLong,
    /// A supplied client-IP slice exceeded 16 bytes (IPv6) on token seal/verify.
    AddressTooLong,
};

pub const TokenError = error{
    /// The token is shorter than the fixed framing requires, or malformed.
    Malformed,
    /// AEAD verification failed (forged or corrupted token).
    BadTag,
    /// The token authenticated but was minted for a different client IP.
    AddressMismatch,
    /// The token authenticated but its issue time is outside the validity window.
    Expired,
    /// The token authenticated but was already presented (replay).
    Replayed,
};

// ===========================================================================
// RFC 9001 §5.8 — Retry integrity tag (the fixed-vector wire contract)
// ===========================================================================

/// The fixed AEAD_AES_128_GCM key for the QUIC v1 Retry integrity tag
/// (RFC 9001 §5.8). This is a published constant, NOT a secret.
pub const retry_integrity_key = [16]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

/// The fixed AEAD_AES_128_GCM nonce for the QUIC v1 Retry integrity tag
/// (RFC 9001 §5.8). Published constant, NOT a secret.
pub const retry_integrity_nonce = [12]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
    0x23, 0x98, 0x25, 0xbb,
};

/// Compute the 16-byte Retry integrity tag (RFC 9001 §5.8).
///
/// The tag is `AEAD_AES_128_GCM(retry_integrity_key, retry_integrity_nonce, "",
/// retry_pseudo_packet)` — i.e. the *associated data* is the Retry pseudo-packet
/// and the plaintext is empty, so the AEAD output is exactly the 16-byte tag.
///
/// The Retry pseudo-packet (RFC 9000 §17.2.5.2) is:
///   ODCIL(1) ‖ Original Destination Connection ID ‖ <Retry packet without tag>
/// where the Retry packet without tag is:
///   first_byte(1) ‖ version(4) ‖ DCIDL(1) ‖ DCID ‖ SCIDL(1) ‖ SCID ‖ Token.
///
/// `original_dcid` is the DCID from the client's Initial that triggered the
/// Retry; `retry_without_tag` is the encoded Retry packet up to (not including)
/// the integrity tag.
pub fn retryIntegrityTag(
    original_dcid: []const u8,
    retry_without_tag: []const u8,
) RetryError![tag_len]u8 {
    if (original_dcid.len > quic_packet.max_connection_id_len) return error.ConnectionIdTooLong;

    // Assemble the pseudo-packet on the stack. Max size: 1 (ODCIL) + 20 (ODCID)
    // + the retry-without-tag, which is itself bounded by header + token.
    var pseudo_buf: [pseudo_packet_max]u8 = undefined;
    var pos: usize = 0;
    pseudo_buf[pos] = @intCast(original_dcid.len);
    pos += 1;
    @memcpy(pseudo_buf[pos..][0..original_dcid.len], original_dcid);
    pos += original_dcid.len;
    if (pos + retry_without_tag.len > pseudo_buf.len) return error.BufferTooSmall;
    @memcpy(pseudo_buf[pos..][0..retry_without_tag.len], retry_without_tag);
    pos += retry_without_tag.len;

    var tag: [tag_len]u8 = undefined;
    // Empty ciphertext output: encrypting an empty plaintext yields only the tag.
    var empty_ct: [0]u8 = undefined;
    Aes128Gcm.encrypt(empty_ct[0..0], &tag, &.{}, pseudo_buf[0..pos], retry_integrity_nonce, retry_integrity_key);
    return tag;
}

/// Upper bound on the Retry pseudo-packet:
///   1 (ODCIL) + 20 (ODCID)
/// + 1 (first) + 4 (version) + 1 + 20 (DCID) + 1 + 20 (SCID) + max_token_len.
const pseudo_packet_max: usize = 1 + 20 + 1 + 4 + 1 + 20 + 1 + 20 + max_token_len;

// ===========================================================================
// RFC 9000 §17.2.5 — Retry packet encode
// ===========================================================================

/// Maximum bytes an encoded Retry packet can occupy (header + token + tag).
pub const retry_packet_max: usize = 1 + 4 + 1 + 20 + 1 + 20 + max_token_len + tag_len;

/// Encode a Retry packet (RFC 9000 §17.2.5) into `out`, returning the number of
/// bytes written. The Retry integrity tag (RFC 9001 §5.8) is appended over the
/// pseudo-packet built from `original_dcid` (the DCID from the client Initial).
///
/// Layout: first_byte ‖ version ‖ DCIDL ‖ DCID ‖ SCIDL ‖ SCID ‖ Token ‖ tag.
///   * first byte = long-header form (0x80) | fixed bit (0x40) | Retry type
///     (0b11 << 4) | unused 4 bits (we set 0).
///   * DCID = the client's SCID (so the client recognises the reply).
///   * SCID = a fresh server-chosen connection id.
///   * Token = the opaque address-validation token the client must echo.
pub fn encodeRetry(
    out: []u8,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    original_dcid: []const u8,
) RetryError!usize {
    if (dcid.len > quic_packet.max_connection_id_len or
        scid.len > quic_packet.max_connection_id_len)
        return error.ConnectionIdTooLong;

    const needed = 1 + 4 + 1 + dcid.len + 1 + scid.len + token.len + tag_len;
    if (out.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    // Retry: header form + fixed bit + type 0b11. The low 4 bits ("Unused",
    // RFC 9000 §17.2.5.1) may be any value; we set them to 0b1111 to match the
    // canonical RFC 9001 §A.4 example (0xff), so a known Retry encodes byte-for-
    // byte. The integrity tag (§5.8) covers this first byte, so it must be fixed.
    out[pos] = 0x80 | 0x40 | (@as(u8, @backingInt(quic_packet.LongPacketType.retry)) << 4) | 0x0f;
    pos += 1;

    std.mem.writeInt(u32, out[pos..][0..4], quic_version_1, .big);
    pos += 4;

    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos..][0..scid.len], scid);
    pos += scid.len;

    @memcpy(out[pos..][0..token.len], token);
    pos += token.len;

    // Tag over the pseudo-packet = ODCID framing ‖ everything written so far.
    const tag = try retryIntegrityTag(original_dcid, out[0..pos]);
    @memcpy(out[pos..][0..tag_len], &tag);
    pos += tag_len;
    return pos;
}

// ===========================================================================
// RFC 9000 §17.2.1 — Version Negotiation packet encode
// ===========================================================================

/// The single supported QUIC version we advertise in Version Negotiation.
pub const supported_versions = [_]u32{quic_version_1};

/// Encode a Version Negotiation packet (RFC 9000 §17.2.1) into `out`, returning
/// the number of bytes written.
///
/// A VN packet has a long header with the version field set to 0x00000000, the
/// connection ids *swapped* relative to the triggering packet (its SCID becomes
/// our DCID and vice versa — RFC 9000 §17.2.1), and a list of supported
/// versions. The first byte's lower 7 bits are unused; we set the long-header
/// form bit (0x80) and an arbitrary fixed pattern (0x40) per the RFC's "set to
/// arbitrary value" guidance.
///
/// This NEVER amplifies: a VN packet's size is `7 + dcid + scid + 4*versions`,
/// which for a single supported version and the connection ids echoed from a
/// ≥1200-byte client Initial is far smaller than the trigger. The caller MUST
/// only send this in response to a packet large enough that the VN reply is no
/// larger (a client Initial is padded to ≥1200, so this always holds).
pub fn encodeVersionNegotiation(
    out: []u8,
    dcid: []const u8,
    scid: []const u8,
) RetryError!usize {
    if (dcid.len > quic_packet.max_connection_id_len or
        scid.len > quic_packet.max_connection_id_len)
        return error.ConnectionIdTooLong;

    const needed = 1 + 4 + 1 + dcid.len + 1 + scid.len + 4 * supported_versions.len;
    if (out.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    // Long-header form bit set; remaining bits arbitrary (RFC 9000 §17.2.1).
    out[pos] = 0x80 | 0x40;
    pos += 1;

    // Version 0x00000000 marks a Version Negotiation packet.
    std.mem.writeInt(u32, out[pos..][0..4], 0, .big);
    pos += 4;

    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos..][0..scid.len], scid);
    pos += scid.len;

    for (supported_versions) |v| {
        std.mem.writeInt(u32, out[pos..][0..4], v, .big);
        pos += 4;
    }
    return pos;
}

/// Whether the server supports `version` (RFC 9000 §6). Only v1.
pub fn supportsVersion(version: u32) bool {
    return version == quic_version_1;
}

// ===========================================================================
// RFC 9000 §8.1.2 — address-validation token (seal / verify)
// ===========================================================================

/// AES-256-GCM nonce length used for the token AEAD.
const token_nonce_len: usize = 12;

/// Plaintext sealed into the token: client IP (len-prefixed, ≤16) + 8-byte issue
/// timestamp (ns) + the original DCID (len-prefixed, ≤20). The original DCID is
/// carried *in the encrypted plaintext* (not just AAD) so the stateless server
/// can recover it on `verify` — it is the `original_destination_connection_id`
/// transport parameter the server MUST echo after a Retry (RFC 9000 §7.3). The
/// plaintext is AEAD-encrypted, so the DCID stays confidential and authenticated.
const token_plaintext_max: usize = 1 + 16 + 8 + 1 + quic_packet.max_connection_id_len;

/// Maximum encoded token length: 12-byte nonce ‖ ciphertext(plaintext) ‖ tag.
pub const max_token_len: usize = token_nonce_len + token_plaintext_max + tag_len;

/// Default token validity window (RFC 9000 §8.1.3 recommends a short lifetime).
pub const default_token_lifetime_ns: u64 = 30 * std.time.ns_per_s;

/// Per-process secret bundle: keys the address-validation token AEAD and the
/// stateless-reset HMAC. Mint once at startup via `Secret.generate`; the keys
/// never leave the process and rotate on restart (so tokens from a previous
/// process instance simply fail to authenticate — a safe default).
pub const Secret = struct {
    /// AES-256-GCM key for sealing/verifying address-validation tokens.
    token_key: [32]u8,
    /// HMAC-SHA256 key for deriving stateless-reset tokens.
    reset_key: [32]u8,

    /// Mint a fresh per-process secret from the OS CSPRNG.
    pub fn generate() Secret {
        var s: Secret = undefined;
        secure_fns.randomBytes(&s.token_key);
        secure_fns.randomBytes(&s.reset_key);
        return s;
    }

    /// Build a deterministic secret from a 64-byte seed (tests only).
    pub fn fromSeed(seed: [64]u8) Secret {
        var s: Secret = undefined;
        @memcpy(&s.token_key, seed[0..32]);
        @memcpy(&s.reset_key, seed[32..64]);
        return s;
    }
};

/// A sealed address-validation token plus the decoded fields a verifier needs.
pub const Token = struct {
    /// Seal an address-validation token binding `client_ip`, `original_dcid`,
    /// and the issue time `now_ns`, into `out`. Returns the token length.
    ///
    /// The token = nonce(12, random) ‖ AES-256-GCM-seal(plaintext), where
    ///   plaintext = ip_len(1) ‖ ip ‖ now_ns(8 be) ‖ odcid_len(1) ‖ odcid
    /// The original DCID is sealed *inside* the plaintext (encrypted +
    /// authenticated) so a stateless server recovers it on `verify` to set the
    /// `original_destination_connection_id` transport parameter (RFC 9000 §7.3).
    pub fn seal(
        out: []u8,
        secret: *const Secret,
        client_ip: []const u8,
        original_dcid: []const u8,
        now_ns: u64,
    ) RetryError!usize {
        if (client_ip.len > 16) return error.AddressTooLong;
        if (original_dcid.len > quic_packet.max_connection_id_len) return error.ConnectionIdTooLong;

        var plaintext: [token_plaintext_max]u8 = undefined;
        var pl: usize = 0;
        plaintext[pl] = @intCast(client_ip.len);
        pl += 1;
        @memcpy(plaintext[pl..][0..client_ip.len], client_ip);
        pl += client_ip.len;
        std.mem.writeInt(u64, plaintext[pl..][0..8], now_ns, .big);
        pl += 8;
        plaintext[pl] = @intCast(original_dcid.len);
        pl += 1;
        @memcpy(plaintext[pl..][0..original_dcid.len], original_dcid);
        pl += original_dcid.len;

        const needed = token_nonce_len + pl + tag_len;
        if (out.len < needed) return error.BufferTooSmall;

        // Fresh random nonce per token (the AES-256-GCM (key,nonce) pair must be
        // unique; a 96-bit random nonce makes a repeat negligibly unlikely).
        var nonce: [token_nonce_len]u8 = undefined;
        secure_fns.randomBytes(&nonce);
        @memcpy(out[0..token_nonce_len], &nonce);

        const ct = out[token_nonce_len .. token_nonce_len + pl];
        var tag: [tag_len]u8 = undefined;
        // No associated data: everything bound is inside the encrypted plaintext.
        Aes256Gcm.encrypt(ct, &tag, plaintext[0..pl], &.{}, nonce, secret.token_key);
        @memcpy(out[token_nonce_len + pl ..][0..tag_len], &tag);
        return needed;
    }

    /// The decoded result of a successful `verify`.
    pub const Verified = struct {
        /// The issue timestamp recovered from the token (ns).
        issued_ns: u64,
        /// The original DCID recovered from the token — the DCID of the client's
        /// first Initial (before the Retry). Borrows `out_dcid` (caller-provided).
        original_dcid: []const u8,
    };

    /// Verify a token presented in a client Initial. Authenticates it under the
    /// per-process key, confirms it was minted for `client_ip`, recovers the
    /// original DCID it bound, and checks it is within `[now-lifetime, now]`.
    /// The recovered original DCID is written into `out_dcid` and returned as a
    /// sub-slice of it (so the caller owns the storage).
    ///
    /// Returns `Verified` on success; one of the `TokenError` members otherwise.
    /// Replay is NOT checked here (it needs mutable state) — use `ReplayCache`.
    pub fn verify(
        token: []const u8,
        secret: *const Secret,
        client_ip: []const u8,
        out_dcid: *[quic_packet.max_connection_id_len]u8,
        now_ns: u64,
        lifetime_ns: u64,
    ) TokenError!Verified {
        if (token.len < token_nonce_len + tag_len + 1) return error.Malformed;
        const nonce: [token_nonce_len]u8 = token[0..token_nonce_len].*;
        const body = token[token_nonce_len..];
        if (body.len < tag_len) return error.Malformed;
        const ct_len = body.len - tag_len;
        const ct = body[0..ct_len];
        const tag: [tag_len]u8 = body[ct_len..][0..tag_len].*;

        var plaintext: [token_plaintext_max]u8 = undefined;
        if (ct_len > plaintext.len) return error.Malformed;
        Aes256Gcm.decrypt(
            plaintext[0..ct_len],
            ct,
            tag,
            &.{}, // no associated data
            nonce,
            secret.token_key,
        ) catch return error.BadTag;

        // Decode plaintext: ip_len(1) ‖ ip ‖ now_ns(8) ‖ odcid_len(1) ‖ odcid.
        if (ct_len < 1) return error.Malformed;
        const ip_len = plaintext[0];
        if (ip_len > 16) return error.Malformed;
        var pos: usize = 1 + @as(usize, ip_len);
        if (ct_len < pos + 8 + 1) return error.Malformed;
        const ip = plaintext[1..pos];
        const issued_ns = std.mem.readInt(u64, plaintext[pos..][0..8], .big);
        pos += 8;
        const odcid_len = plaintext[pos];
        pos += 1;
        if (odcid_len > quic_packet.max_connection_id_len) return error.Malformed;
        if (ct_len != pos + @as(usize, odcid_len)) return error.Malformed;
        @memcpy(out_dcid[0..odcid_len], plaintext[pos..][0..odcid_len]);

        // IP must match the address the Initial actually arrived from.
        if (!secure_fns.ctEq(ip, client_ip)) return error.AddressMismatch;

        // Time window: not from the future (clock skew tolerance is the caller's;
        // we require issued <= now) and not older than the lifetime.
        if (issued_ns > now_ns) return error.Expired;
        if (now_ns - issued_ns > lifetime_ns) return error.Expired;

        return .{ .issued_ns = issued_ns, .original_dcid = out_dcid[0..odcid_len] };
    }
};

/// A small bounded replay cache for address-validation tokens (RFC 9000 §8.1.4
/// notes a Retry token SHOULD be single-use). Records a short fingerprint of
/// each accepted token; a second presentation of the same token is rejected.
///
/// Fixed-capacity ring (no allocation): a flood of distinct tokens evicts the
/// oldest entries rather than growing without bound — the worst case is that a
/// very old token could be replayed once after eviction, which is acceptable
/// because the token's own time window already bounds its usefulness.
pub const ReplayCache = struct {
    /// 16-byte fingerprints (the token's AEAD tag is a strong, fixed-size
    /// summary of the whole token; we use it as the replay key).
    entries: [capacity][tag_len]u8 = @splat(@as([tag_len]u8, @splat(0))),
    valid: [capacity]bool = @splat(false),
    next: usize = 0,

    pub const capacity: usize = 256;

    /// Fingerprint = the token's trailing 16-byte AEAD tag (unique per token).
    fn fingerprint(token: []const u8) ?[tag_len]u8 {
        if (token.len < tag_len) return null;
        return token[token.len - tag_len ..][0..tag_len].*;
    }

    /// Returns true if `token` was already seen (a replay). Pure query.
    pub fn seen(self: *const ReplayCache, token: []const u8) bool {
        const fp = fingerprint(token) orelse return false;
        for (self.entries, self.valid) |e, v| {
            if (v and secure_fns.ctEq(&e, &fp)) return true;
        }
        return false;
    }

    /// Record `token` as used. Idempotent for an already-recorded token.
    pub fn record(self: *ReplayCache, token: []const u8) void {
        const fp = fingerprint(token) orelse return;
        if (self.seen(token)) return;
        self.entries[self.next] = fp;
        self.valid[self.next] = true;
        self.next = (self.next + 1) % capacity;
    }

    /// Check-and-record in one step: returns `error.Replayed` if already seen,
    /// otherwise records it and returns. Use after `Token.verify` succeeds.
    pub fn checkAndRecord(self: *ReplayCache, token: []const u8) TokenError!void {
        if (self.seen(token)) return error.Replayed;
        self.record(token);
    }
};

// ===========================================================================
// RFC 9000 §10.3 — stateless-reset token (derivation + packet format)
// ===========================================================================

/// Derive the 16-byte stateless-reset token for `connection_id` (RFC 9000
/// §10.3): HMAC-SHA256(reset_key, connection_id) truncated to 16 bytes. The
/// per-process `reset_key` makes the token unforgeable and uncorrelatable across
/// connection ids without the key.
pub fn statelessResetToken(secret: *const Secret, connection_id: []const u8) [stateless_reset_token_len]u8 {
    return statelessResetTokenWithKey(&secret.reset_key, connection_id);
}

/// `statelessResetToken` under an explicit 32-byte key (e.g. a static key from
/// `deriveStaticResetKey`).
pub fn statelessResetTokenWithKey(key: *const [32]u8, connection_id: []const u8) [stateless_reset_token_len]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, connection_id, key);
    defer std.crypto.secureZero(u8, &mac);
    var token: [stateless_reset_token_len]u8 = undefined;
    @memcpy(&token, mac[0..stateless_reset_token_len]);
    return token;
}

/// Derive a static stateless-reset key (RFC 9000 §10.3.2: "a single static
/// key ... used to generate stateless reset tokens for all connections") from
/// long-lived secret input key material, e.g. an operator-configured secret or
/// the TLS private key. HKDF-SHA256 with a fixed, versioned label so the
/// output is unrelated to any other use of the same material.
pub fn deriveStaticResetKey(ikm: []const u8) [32]u8 {
    const Hkdf = crypto.kdf.hkdf.HkdfSha256;
    var prk = Hkdf.extract("onyx quic stateless reset key v1", ikm);
    defer std.crypto.secureZero(u8, &prk);
    var out: [32]u8 = undefined;
    Hkdf.expand(&out, "stateless-reset", prk);
    return out;
}

/// RFC 9000 §10.3.3 sizing: a reset MUST be smaller than the packet that
/// triggered it (strictly shorter, so a reset can never trigger an equally
/// sized reset and two endpoints cannot loop), no larger than `cap`, and at
/// least `min_stateless_reset_len`. Null means "send nothing".
pub fn statelessResetLen(trigger_len: usize, cap: usize) ?usize {
    if (trigger_len == 0) return null;
    const len = @min(trigger_len - 1, cap);
    if (len < min_stateless_reset_len) return null;
    return len;
}

/// A bounded ring of the stateless-reset tokens this endpoint recently put on
/// the wire. A trigger whose trailing 16 bytes match one of them is very likely
/// one of our own resets reflected back (or bounced by a peer sharing our static
/// key) and must not be answered. Comparisons are constant-time.
pub const RecentResets = struct {
    pub const capacity: usize = 32;
    tokens: [capacity][stateless_reset_token_len]u8 = @splat(@splat(0)),
    len: usize = 0,
    next: usize = 0,

    pub fn record(self: *RecentResets, token: [stateless_reset_token_len]u8) void {
        self.tokens[self.next] = token;
        self.next = (self.next + 1) % capacity;
        if (self.len < capacity) self.len += 1;
    }

    pub fn contains(self: *const RecentResets, tail: []const u8) bool {
        if (tail.len != stateless_reset_token_len) return false;
        var hit = false;
        for (self.tokens[0..self.len]) |*t| hit = secure_fns.ctEq(t, tail) or hit;
        return hit;
    }
};

/// Whether a short-header datagram addressed to `dcid` could itself be a
/// stateless reset of ours: it ends in the token we would emit for `dcid`
/// (e.g. a reset bounced between two nodes sharing the static key) or in one
/// we recently emitted. Such a packet MUST NOT be answered with a reset.
pub fn mightBeOwnReset(key: *const [32]u8, recent: *const RecentResets, dcid: []const u8, datagram: []const u8) bool {
    if (datagram.len < stateless_reset_token_len) return false;
    const tail = datagram[datagram.len - stateless_reset_token_len ..];
    const own = statelessResetTokenWithKey(key, dcid);
    return secure_fns.ctEq(&own, tail) or recent.contains(tail);
}

/// Minimum length of a packet that may carry a stateless reset (RFC 9000
/// §10.3): 5 random bytes + 16-byte token = 21, but the RFC requires the packet
/// be at least as long as a minimal short header carrying the token so it is
/// indistinguishable from a 1-RTT packet. We emit at least this many bytes.
pub const min_stateless_reset_len: usize = 21;

/// Format a stateless-reset packet (RFC 9000 §10.3) into `out`, returning the
/// length. The packet is `out.len` bytes of unpredictable data whose final 16
/// bytes are the stateless-reset `token`, and whose first two bits are 01 (so it
/// is shaped like a short-header 1-RTT packet). `out.len` MUST be at least
/// `min_stateless_reset_len`; the caller sizes it to mimic a plausible 1-RTT
/// packet (and never larger than the triggering packet, to avoid amplification).
pub fn encodeStatelessReset(
    out: []u8,
    token: [stateless_reset_token_len]u8,
) RetryError!usize {
    if (out.len < min_stateless_reset_len) return error.BufferTooSmall;
    // Fill the whole packet with unpredictable bytes…
    secure_fns.randomBytes(out);
    // …then shape the first byte like a short header (form bit 0, fixed bit 1)
    // and append the token in the last 16 bytes.
    out[0] = (out[0] & 0x3f) | 0x40;
    @memcpy(out[out.len - stateless_reset_token_len ..][0..stateless_reset_token_len], &token);
    return out.len;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn fromHex(comptime N: usize, comptime hex: []const u8) [N]u8 {
    comptime assert(hex.len == N * 2);
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn hexAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

// ---------------------------------------------------------------------------
// RFC 9001 §A.4 — the Retry integrity tag interop vector
//
//   ODCID (from the client Initial) = 8394c8f03e515708
//   Retry packet (with tag) =
//     ff000000010008f067a5502a4262b5746f6b656e + <16-byte tag>
//   where:
//     ff           = first byte (long header, Retry type, low bits arbitrary)
//     00000001     = version 1
//     00           = DCIDL 0 (empty DCID)
//     08 f067...b5 = SCIDL 8 + SCID
//     746f6b656e   = the token "token" (5 bytes)
//
// The 16-byte tag is AEAD_AES_128_GCM(fixed v1 key, fixed v1 nonce, aad =
// pseudo-packet, plaintext = ""). For this ODCID + Retry the tag is
// 04a265ba2eff4d829058fb3f0f2496ba — independently reproduced with a vetted
// AES-128-GCM implementation over the exact §5.8 construction (the fixed v1
// key be0c...c84e and nonce 4615...25bb). This is the wire contract the
// implementation must satisfy byte-for-byte.
// ---------------------------------------------------------------------------

const a4_odcid = "8394c8f03e515708";
const a4_retry_without_tag = "ff000000010008f067a5502a4262b5746f6b656e";
const a4_expected_tag = "04a265ba2eff4d829058fb3f0f2496ba";

test "RFC 9001 A.4 — Retry integrity tag matches the published vector" {
    const allocator = testing.allocator;
    const odcid = try hexAlloc(allocator, a4_odcid);
    defer allocator.free(odcid);
    const retry = try hexAlloc(allocator, a4_retry_without_tag);
    defer allocator.free(retry);

    const tag = try retryIntegrityTag(odcid, retry);
    try testing.expectEqualSlices(u8, &fromHex(16, a4_expected_tag), &tag);
}

test "encodeRetry produces a packet whose tag verifies against the pseudo-packet" {
    const allocator = testing.allocator;
    const odcid = try hexAlloc(allocator, a4_odcid);
    defer allocator.free(odcid);

    // DCID = empty (the client used an empty SCID in A.4), SCID + token as in A.4.
    const scid = try hexAlloc(allocator, "f067a5502a4262b5");
    defer allocator.free(scid);
    const token = "token";

    var out: [retry_packet_max]u8 = undefined;
    const n = try encodeRetry(&out, &.{}, scid, token, odcid);

    // The encoded packet must equal A.4's retry-without-tag ‖ expected tag.
    const expected_body = try hexAlloc(allocator, a4_retry_without_tag);
    defer allocator.free(expected_body);
    try testing.expectEqualSlices(u8, expected_body, out[0 .. n - tag_len]);
    try testing.expectEqualSlices(u8, &fromHex(16, a4_expected_tag), out[n - tag_len .. n]);
}

test "Retry token round-trips: seal then verify for the same IP and DCID" {
    const secret = Secret.fromSeed(@as([64]u8, @splat(0x5a)));
    const client_ip = [_]u8{ 192, 0, 2, 33 };
    const odcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const now: u64 = 1_000_000_000;

    var tok: [max_token_len]u8 = undefined;
    const n = try Token.seal(&tok, &secret, &client_ip, &odcid, now);

    var out_dcid: [quic_packet.max_connection_id_len]u8 = undefined;
    const v = try Token.verify(tok[0..n], &secret, &client_ip, &out_dcid, now + 1000, default_token_lifetime_ns);
    try testing.expectEqual(now, v.issued_ns);
    // The original DCID is recovered byte-exact from the sealed plaintext (it is
    // the ODCID the server must echo after a Retry — RFC 9000 §7.3).
    try testing.expectEqualSlices(u8, &odcid, v.original_dcid);
}

test "Retry token verify — rejects a different client IP (AddressMismatch)" {
    const secret = Secret.fromSeed(@as([64]u8, @splat(0x5a)));
    const client_ip = [_]u8{ 192, 0, 2, 33 };
    const wrong_ip = [_]u8{ 198, 51, 100, 7 };
    const odcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const now: u64 = 1_000_000_000;

    var tok: [max_token_len]u8 = undefined;
    const n = try Token.seal(&tok, &secret, &client_ip, &odcid, now);

    var out_dcid: [quic_packet.max_connection_id_len]u8 = undefined;
    try testing.expectError(
        error.AddressMismatch,
        Token.verify(tok[0..n], &secret, &wrong_ip, &out_dcid, now, default_token_lifetime_ns),
    );
}

test "Retry token verify — rejects an expired token" {
    const secret = Secret.fromSeed(@as([64]u8, @splat(0x77)));
    const client_ip = [_]u8{ 10, 0, 0, 1 };
    const odcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const now: u64 = 1_000_000_000;

    var tok: [max_token_len]u8 = undefined;
    const n = try Token.seal(&tok, &secret, &client_ip, &odcid, now);

    // now advanced well past the lifetime.
    const later = now + default_token_lifetime_ns + 1;
    var out_dcid: [quic_packet.max_connection_id_len]u8 = undefined;
    try testing.expectError(
        error.Expired,
        Token.verify(tok[0..n], &secret, &client_ip, &out_dcid, later, default_token_lifetime_ns),
    );
}

test "Retry token verify — rejects a forged tag; recovers the bound DCID intact" {
    const secret = Secret.fromSeed(@as([64]u8, @splat(0x33)));
    const client_ip = [_]u8{ 10, 0, 0, 1 };
    const odcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const now: u64 = 1_000_000_000;

    var tok: [max_token_len]u8 = undefined;
    const n = try Token.seal(&tok, &secret, &client_ip, &odcid, now);

    var out_dcid: [quic_packet.max_connection_id_len]u8 = undefined;

    // Corrupt a ciphertext byte → BadTag (the sealed plaintext, incl. the DCID,
    // is authenticated, so any tampering is detected).
    var forged = tok;
    forged[token_nonce_len] ^= 0x80;
    try testing.expectError(
        error.BadTag,
        Token.verify(forged[0..n], &secret, &client_ip, &out_dcid, now, default_token_lifetime_ns),
    );

    // The untampered token verifies and yields the exact original DCID back; an
    // attacker cannot substitute a different DCID without breaking the AEAD tag.
    const v = try Token.verify(tok[0..n], &secret, &client_ip, &out_dcid, now, default_token_lifetime_ns);
    try testing.expectEqualSlices(u8, &odcid, v.original_dcid);
}

test "ReplayCache — a token is accepted once and rejected on replay" {
    const secret = Secret.fromSeed(@as([64]u8, @splat(0x12)));
    const client_ip = [_]u8{ 203, 0, 113, 9 };
    const odcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const now: u64 = 1_000_000_000;

    var tok: [max_token_len]u8 = undefined;
    const n = try Token.seal(&tok, &secret, &client_ip, &odcid, now);

    var cache = ReplayCache{};
    try testing.expect(!cache.seen(tok[0..n]));
    try cache.checkAndRecord(tok[0..n]); // first use OK
    try testing.expect(cache.seen(tok[0..n]));
    try testing.expectError(error.Replayed, cache.checkAndRecord(tok[0..n]));
}

test "Version Negotiation — encodes 0x00000000 version and lists v1, swaps CIDs" {
    // Trigger: client picked DCID=cafe, SCID=babe. The VN swaps them.
    const trigger_dcid = [_]u8{ 0xca, 0xfe };
    const trigger_scid = [_]u8{ 0xba, 0xbe, 0xba, 0xbe };

    var out: [64]u8 = undefined;
    // We respond with our DCID = the client's SCID, our SCID = the client's DCID.
    const n = try encodeVersionNegotiation(&out, &trigger_scid, &trigger_dcid);

    // first byte has the high bit set; version field is 0.
    try testing.expect((out[0] & 0x80) != 0);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[1..5], .big));
    // DCIDL + DCID = client SCID.
    try testing.expectEqual(@as(u8, trigger_scid.len), out[5]);
    try testing.expectEqualSlices(u8, &trigger_scid, out[6 .. 6 + trigger_scid.len]);
    // Then SCIDL + SCID = client DCID.
    const scidl_off = 6 + trigger_scid.len;
    try testing.expectEqual(@as(u8, trigger_dcid.len), out[scidl_off]);
    try testing.expectEqualSlices(u8, &trigger_dcid, out[scidl_off + 1 .. scidl_off + 1 + trigger_dcid.len]);
    // Final 4 bytes = the one supported version, 0x00000001.
    try testing.expectEqual(quic_version_1, std.mem.readInt(u32, out[n - 4 ..][0..4], .big));

    try testing.expect(supportsVersion(quic_version_1));
    try testing.expect(!supportsVersion(0xff00_0099));
}

test "Version Negotiation never amplifies relative to a 1200-byte trigger" {
    // A client Initial is padded to ≥1200 bytes; the VN reply must be far smaller.
    const dcid = @as([8]u8, @splat(0xaa));
    const scid = @as([8]u8, @splat(0xbb));
    var out: [64]u8 = undefined;
    const n = try encodeVersionNegotiation(&out, &dcid, &scid);
    try testing.expect(n < 1200);
}

test "statelessResetToken — deterministic per key+CID, differs across CIDs and keys" {
    const secret = Secret.fromSeed(@as([64]u8, @splat(0x99)));
    const cid_a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const cid_b = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };

    const t1 = statelessResetToken(&secret, &cid_a);
    const t2 = statelessResetToken(&secret, &cid_a);
    try testing.expectEqualSlices(u8, &t1, &t2); // deterministic

    const t3 = statelessResetToken(&secret, &cid_b);
    try testing.expect(!std.mem.eql(u8, &t1, &t3)); // CID-sensitive

    const other = Secret.fromSeed(@as([64]u8, @splat(0x11)));
    const t4 = statelessResetToken(&other, &cid_a);
    try testing.expect(!std.mem.eql(u8, &t1, &t4)); // key-sensitive
}

test "encodeStatelessReset embeds the token in the trailing 16 bytes and looks 1-RTT" {
    const token = @as([stateless_reset_token_len]u8, @splat(0xab));
    var out: [40]u8 = undefined;
    const n = try encodeStatelessReset(&out, token);
    try testing.expectEqual(@as(usize, 40), n);
    // short-header shape: high bit clear, fixed bit set.
    try testing.expectEqual(@as(u8, 0x00), out[0] & 0x80);
    try testing.expectEqual(@as(u8, 0x40), out[0] & 0x40);
    try testing.expectEqualSlices(u8, &token, out[n - stateless_reset_token_len .. n]);
    // Too-small output is rejected.
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeStatelessReset(&tiny, token));
}

test "static stateless-reset key is deterministic, domain-separated, and keys the token" {
    const a = deriveStaticResetKey("operator secret");
    try testing.expectEqualSlices(u8, &a, &deriveStaticResetKey("operator secret"));
    try testing.expect(!std.mem.eql(u8, &a, &deriveStaticResetKey("operator secreT")));
    const cid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const t1 = statelessResetTokenWithKey(&a, &cid);
    // Same key across a "restart": the same CID yields the same token.
    const b = deriveStaticResetKey("operator secret");
    try testing.expectEqualSlices(u8, &t1, &statelessResetTokenWithKey(&b, &cid));
    // A forged token under another key does not match.
    const other = deriveStaticResetKey("attacker");
    try testing.expect(!std.mem.eql(u8, &t1, &statelessResetTokenWithKey(&other, &cid)));
    // The Secret-based API is the same HMAC.
    var seed: [64]u8 = @splat(0);
    @memcpy(seed[32..], &a);
    const secret = Secret.fromSeed(seed);
    try testing.expectEqualSlices(u8, &t1, &statelessResetToken(&secret, &cid));
}

test "stateless reset is always strictly shorter than its trigger and bounded (RFC 9000 §10.3.3)" {
    try testing.expectEqual(@as(?usize, null), statelessResetLen(0, 64));
    try testing.expectEqual(@as(?usize, null), statelessResetLen(21, 64)); // would need 21 < 21
    try testing.expectEqual(@as(?usize, 21), statelessResetLen(22, 64));
    try testing.expectEqual(@as(?usize, 42), statelessResetLen(43, 64));
    try testing.expectEqual(@as(?usize, 64), statelessResetLen(1200, 64));
    // A reset answering a reset shrinks every round, so a loop terminates.
    var len: usize = 64;
    var rounds: usize = 0;
    while (statelessResetLen(len, 64)) |next| : (rounds += 1) {
        try testing.expect(next < len);
        len = next;
    }
    try testing.expect(rounds < 64);
}

test "a datagram ending in our own (or a recently sent) reset token is recognised as possibly ours" {
    const key = deriveStaticResetKey("k");
    var recent: RecentResets = .{};
    const dcid = [_]u8{ 9, 9, 9, 9, 9, 9, 9, 9 };
    var dg: [40]u8 = @splat(0x41);
    try testing.expect(!mightBeOwnReset(&key, &recent, &dcid, &dg));
    // Ends in the token we would emit for this very DCID.
    dg[24..40].* = statelessResetTokenWithKey(&key, &dcid);
    try testing.expect(mightBeOwnReset(&key, &recent, &dcid, &dg));
    // Ends in a token we recently emitted for some other DCID.
    const other_tok = statelessResetTokenWithKey(&key, "other-cid");
    dg[24..40].* = other_tok;
    try testing.expect(!mightBeOwnReset(&key, &recent, &dcid, &dg));
    recent.record(other_tok);
    try testing.expect(mightBeOwnReset(&key, &recent, &dcid, &dg));
    // The ring is bounded.
    for (0..RecentResets.capacity) |i| recent.record(@splat(@intCast(i + 1)));
    try testing.expect(!recent.contains(&other_tok));
}
