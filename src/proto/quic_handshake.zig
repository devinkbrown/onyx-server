// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socketless TLS 1.3-over-QUIC server handshake (RFC 8446 + RFC 9001 §4–§5).
//!
//! QUIC carries the TLS 1.3 handshake as *raw* handshake messages inside CRYPTO
//! frames — there is no TLS record layer (RFC 9001 §4): handshake messages are
//! concatenated `HandshakeType ‖ uint24 length ‖ body` structures, and the
//! transcript hash runs over those raw bytes exactly as on TCP. Three
//! differences from TLS-over-TCP drive this module:
//!
//!   1. No record framing. The server emits raw handshake bytes per encryption
//!      level; the connection driver wraps them in CRYPTO frames + packets.
//!   2. A mandatory `quic_transport_parameters` TLS extension (ext type 0x39,
//!      RFC 9001 §8.2) appears in ClientHello and EncryptedExtensions.
//!   3. Keys are installed at three encryption levels: Initial (from the DCID,
//!      handled by the caller via `quic_protect.KeySet.initInitial`), Handshake
//!      (from the *_handshake_traffic secrets), and 1-RTT / Application (from
//!      the *_application_traffic secrets). This module installs the Handshake
//!      and Application `KeySet`s and exposes them.
//!
//! Reuse, not reinvention:
//!   * `hkdf_tls13.KeySchedule(alg)` — the full TLS 1.3 key schedule
//!     (early/handshake/master secrets, traffic secrets, HKDF-Expand-Label).
//!   * `tls_keyshare` / `tls_extension` / `tls_supported_versions` / `tls_alpn`
//!     / `tls_signature_scheme` — the ClientHello/ServerHello/EncryptedExtensions
//!     extension codecs (identical to the TCP path).
//!   * `tls_finished` — Finished verify_data (SHA-256 + SHA-384).
//!   * `kx.X25519Kx` / Ed25519 / ECDSA-P256 / RSA-PSS — key exchange + the
//!     CertificateVerify signing primitives.
//!   * `quic_protect.KeySet` + `quic_tls.PacketKeys` — QUIC packet keys; for
//!     SHA-256 suites via `KeySet.fromTrafficSecrets`, and for the SHA-384 suite
//!     via this module's schedule-aware `quic key`/`quic iv`/`quic hp` derivation
//!     (the SHA-256-only `quic_tls` helper is wrong for a 48-byte secret).
//!
//! Flow (server side, full 1-RTT, X25519):
//!   ClientHello  →  ServerHello                                    (Initial level)
//!                   install Handshake keys (both directions)
//!                →  EncryptedExtensions, Certificate,
//!                   CertificateVerify, Finished                    (Handshake level)
//!                   install Application keys (both directions)
//!   client Finished (verified)                                     (Handshake level)
//!                   handshake complete
//!
//! Also implemented (server side, each fail-closed):
//!   * HelloRetryRequest (RFC 8446 §4.1.4): when the ClientHello carries no
//!     usable key_share but `supported_groups` lists a group we implement, the
//!     server answers with an HRR naming the best group in `Config.group_order`
//!     (default X25519MLKEM768 > X25519). The transcript restarts from
//!     `message_hash(ClientHello1)` (§4.4.1). Only one HRR per connection.
//!   * Session resumption (RFC 8446 §2.2 / §4.6.1, RFC 9001 §4.5): once the
//!     client Finished verifies, a server with a `ticket_key` and a clock issues
//!     one NewSessionTicket at the 1-RTT level, sealed with
//!     `tls_resumption.sealTicket` (rotation via `previous_ticket_key`). A later
//!     ClientHello offering that ticket with `psk_dhe_ke` (§4.2.9) and a valid
//!     binder (§4.2.11.2) resumes: no Certificate/CertificateVerify, PSK fed into
//!     the Early Secret. A binder that fails to verify aborts (§4.2.11).
//!   * 0-RTT (RFC 9001 §4.6, RFC 8446 §4.2.10): OFF unless
//!     `Config.enable_early_data` and a `replay_guard` are set. Tickets then
//!     advertise `max_early_data_size = 0xffffffff` (RFC 9001 §4.6.1) and carry
//!     the server's remembered transport parameters and ALPN (RFC 9000 §7.4.1).
//!     Early data is accepted only for the first PSK, inside the ticket-age
//!     window, with unchanged ALPN, no reduced limits, and a fresh binder in the
//!     replay guard; otherwise it is *rejected* (EncryptedExtensions omits
//!     `early_data`) and the handshake continues at 1-RTT.
//!
//! Intentionally deferred (out of scope): client certificates / mTLS, psk_ke
//! (PSK without (EC)DHE), external PSKs. The 1-RTT key update itself is a
//! packet-layer mechanism and lives in `quic_conn.zig` (both hash widths).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const hkdf = @import("../crypto/hkdf_tls13.zig");
const kx = @import("../crypto/kx.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const rsa_sign = @import("../crypto/rsa_sign.zig");

const tls_keyshare = @import("tls_keyshare.zig");
const tls_extension = @import("tls_extension.zig");
const tls_supported_versions = @import("tls_supported_versions.zig");
const tls_signature_scheme = @import("tls_signature_scheme.zig");
const tls_finished = @import("tls_finished.zig");
const tls_alpn = @import("tls_alpn.zig");
const tls_psk = @import("tls_psk.zig");
const tls_session_ticket = @import("tls_session_ticket.zig");
const supported_groups = @import("supported_groups.zig");
const tls_resumption = @import("../crypto/tls_resumption.zig");
const quic_transport_params = @import("quic_transport_params.zig");
const quic_frame = @import("quic_frame.zig");
const quic_protect = @import("quic_protect.zig");
const quic_tls = @import("quic_tls.zig");

const Sha256 = hkdf.Sha256;
const Sha384 = hkdf.Sha384;
const max_hash_len = Sha384.hash_len;

const Ed25519 = std.crypto.sign.Ed25519;
const MlKem768 = std.crypto.kem.ml_kem.MLKem768;

// ── X25519MLKEM768 (TLS named group 0x11ec) wire sizes ──────────────────────
// Per the spec the ML-KEM-768 part comes first, then X25519, in the client
// share, the server share, and the combined shared secret. Chrome/Edge offer
// this as their sole QUIC key_share, so the server must accept it.
const mlkem_ek_len = MlKem768.PublicKey.encoded_length; // 1184 — client encapsulation key
const mlkem_ct_len = MlKem768.ciphertext_length; // 1088 — server ciphertext
const x25519_pub_len = kx.X25519Kx.public_len; // 32
const hybrid_client_share_len = mlkem_ek_len + x25519_pub_len; // 1216
const hybrid_server_share_len = mlkem_ct_len + x25519_pub_len; // 1120

/// Result of the QUIC/TLS 1.3 (EC)DHE / hybrid key exchange: 32 bytes for a
/// classical group (x25519) or 64 bytes for X25519MLKEM768 (mlkem_ss ‖ x25519_ss).
const KexShared = struct { buf: [64]u8 = undefined, len: usize = 0 };

/// Selected key-exchange group for this handshake, determining the ServerHello
/// key_share wire format.
const SelectedGroup = enum { x25519, x25519mlkem768 };

pub const EncryptionLevel = quic_protect.EncryptionLevel;
pub const KeySet = quic_protect.KeySet;
pub const PacketKeys = quic_tls.PacketKeys;
pub const QuicCipherSuite = quic_protect.CipherSuite;

/// The 1-RTT (application) traffic secrets the connection driver needs to seed
/// RFC 9001 §6 key updates: `write` is this endpoint's own secret, `read` is the
/// peer's. Only the first `hash_len` bytes are live (32 for the SHA-256 suites,
/// 48 for TLS_AES_256_GCM_SHA384). `suite` selects the AEAD/header-protection
/// used to re-derive the next-generation packet keys. Read-only snapshot;
/// copying these out does not affect the handshake.
pub const AppTrafficSecrets = struct {
    write: [max_hash_len]u8,
    read: [max_hash_len]u8,
    hash_len: u8,
    suite: QuicCipherSuite,
};

/// Key-exchange groups this QUIC server implements, for `Config.group_order`.
pub const KeyExchangeGroup = enum {
    x25519mlkem768,
    x25519,

    fn named(self: KeyExchangeGroup) supported_groups.NamedGroup {
        return switch (self) {
            .x25519mlkem768 => .x25519mlkem768,
            .x25519 => .x25519,
        };
    }

    fn keyShareGroup(self: KeyExchangeGroup) tls_keyshare.NamedGroup {
        return switch (self) {
            .x25519mlkem768 => .x25519mlkem768,
            .x25519 => .x25519,
        };
    }
};

/// Default server group preference: the post-quantum hybrid first so modern
/// browsers that offer both shares get X25519MLKEM768, then classical X25519.
pub const default_group_order = [_]KeyExchangeGroup{ .x25519mlkem768, .x25519 };

/// RFC 8446 §4.1.3: ServerHello.random marking a HelloRetryRequest, the SHA-256
/// of "HelloRetryRequest".
const hello_retry_request_random = [_]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// RFC 8446 §4.6.1: a ticket lifetime MUST NOT exceed seven days.
pub const max_ticket_lifetime_seconds: u32 = 604_800;

/// RFC 9001 §4.6.1: a QUIC server that permits 0-RTT sends `early_data` with
/// `max_early_data_size` 0xffffffff; any other value is a PROTOCOL_VIOLATION.
pub const quic_max_early_data_size: u32 = 0xffff_ffff;

/// Upper bound on PSK identities examined per ClientHello (each costs one
/// ticket AEAD open). Identities past this are ignored, never an error.
const max_psk_identities_examined: usize = 4;

/// The ticket nonce doubles as an authenticated container for the state a
/// 0-RTT acceptance must compare against (RFC 9000 §7.4.1, RFC 8446 §4.2.10):
/// `version(1) ‖ random(8) ‖ alpn_digest(32) ‖ 8 × u64 remembered limits`.
/// The nonce is sealed inside the ticket by `tls_resumption.sealTicket`, so it
/// is authenticated by the ticket key; it is also sent to the client in
/// NewSessionTicket (RFC 8446 §4.6.1 permits any per-ticket-unique value), which
/// discloses nothing the client did not already receive in EncryptedExtensions.
const ticket_state_version: u8 = 1;
const ticket_random_len: usize = 8;
const remembered_param_count: usize = 8;
pub const ticket_state_len: usize = 1 + ticket_random_len + 32 + 8 * remembered_param_count;

/// The server transport parameters a client remembers for 0-RTT (RFC 9000
/// §7.4.1 list, plus RFC 9221 §3 `max_datagram_frame_size`). An absent value
/// takes its RFC 9000 §18.2 default (0, or 2 for `active_connection_id_limit`).
fn rememberedParams(tp: quic_transport_params.TransportParameters) [remembered_param_count]u64 {
    return .{
        tp.initial_max_data orelse 0,
        tp.initial_max_stream_data_bidi_local orelse 0,
        tp.initial_max_stream_data_bidi_remote orelse 0,
        tp.initial_max_stream_data_uni orelse 0,
        tp.initial_max_streams_bidi orelse 0,
        tp.initial_max_streams_uni orelse 0,
        tp.active_connection_id_limit orelse 2,
        tp.max_datagram_frame_size orelse 0,
    };
}

/// Domain-separated digest of the negotiated ALPN (or its absence).
fn alpnDigest(alpn: ?[]const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx quic 0-rtt alpn v1");
    if (alpn) |a| {
        h.update(&.{ 1, @intCast(@min(a.len, 255)) });
        h.update(a);
    } else {
        h.update(&.{0});
    }
    return h.finalResult();
}

/// The TLS 1.3 / QUIC `quic_transport_parameters` extension type (RFC 9001 §8.2).
pub const quic_transport_parameters_ext: u16 = 0x39;

/// TLS 1.3 legacy record version echoed in ClientHello/ServerHello (RFC 8446).
const legacy_version: u16 = 0x0303;

pub const Error = error{
    BadState,
    BadHandshake,
    UnsupportedGroup,
    UnsupportedCipherSuite,
    ProtocolVersion,
    MissingExtension,
    FinishedMismatch,
    NoCertificate,
    NoSigningKey,
    SignatureFailed,
    Entropy,
    /// A peer declared or streamed more handshake bytes than any legitimate
    /// flight needs (pre-authentication memory-exhaustion guard).
    HandshakeTooLarge,
    /// The server's connection-id transport parameters did not authenticate
    /// the connection ids the client actually observed (RFC 9000 §7.3):
    /// `original_destination_connection_id`, `initial_source_connection_id`,
    /// or `retry_source_connection_id` was missing, unexpected, or different.
    ConnectionIdMismatch,
    /// A PSK binder for a ticket this server sealed did not verify
    /// (RFC 8446 §4.2.11: the server MUST abort, decrypt_error).
    PskBinderMismatch,
    /// Invalid server configuration (e.g. an empty or unknown group order).
    BadConfig,
} || Allocator.Error || hkdf.Error ||
    tls_extension.Error || tls_alpn.Error || tls_keyshare.Error ||
    tls_supported_versions.Error || tls_signature_scheme.Error ||
    quic_transport_params.Error;

/// TLS 1.3 cipher suites for the QUIC handshake. The schedule hash follows the
/// suite (SHA-256 for AES-128-GCM and ChaCha20-Poly1305, SHA-384 for AES-256).
pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,

    fn hashLen(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_256_gcm_sha384 => Sha384.hash_len,
            else => Sha256.hash_len,
        };
    }

    /// Map onto the QUIC packet-protection suite (AEAD + header protection).
    fn quicSuite(self: CipherSuite) QuicCipherSuite {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => .aes128gcm,
            .tls_aes_256_gcm_sha384 => .aes256gcm,
            .tls_chacha20_poly1305_sha256 => .chacha20poly1305,
        };
    }

    /// IANA registry name of the suite.
    pub fn name(self: CipherSuite) []const u8 {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => "TLS_AES_128_GCM_SHA256",
            .tls_aes_256_gcm_sha384 => "TLS_AES_256_GCM_SHA384",
            .tls_chacha20_poly1305_sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        };
    }
};

/// The signing key for CertificateVerify. Exactly one variant is used; the leaf
/// certificate's SPKI must match.
pub const SigningKey = union(enum) {
    ed25519: Ed25519.KeyPair,
    ecdsa_p256: ecdsa_p256.KeyPair,
    rsa: rsa_sign.PrivateKey,
};

pub const Config = struct {
    /// DER certificate chain, leaf first; the leaf SPKI must match `signing_key`.
    cert_chain: []const []const u8,
    /// The CertificateVerify signing key (Ed25519, ECDSA-P256, or RSA-PSS).
    signing_key: SigningKey,
    /// ALPN protocols the server will select from, in preference order. QUIC
    /// requires ALPN (RFC 9001 §8.1); empty disables negotiation (test only).
    alpn_protocols: []const []const u8 = &.{},
    /// The server's QUIC transport parameters, emitted in EncryptedExtensions.
    transport_params: quic_transport_params.TransportParameters = .{},
    /// Deterministic X25519 seed (tests). When null a fresh seed is drawn from
    /// the OS at `init`.
    x25519_seed: ?[kx.X25519Kx.seed_len]u8 = null,
    /// Deterministic ServerHello random (tests). When null a fresh 32-byte
    /// random is drawn from the OS.
    server_random: ?[32]u8 = null,
    /// Server key-exchange group preference (RFC 8446 §4.2.7). Used both to pick
    /// among offered key_shares and to choose the HelloRetryRequest group when
    /// none is usable. Must be non-empty and duplicate-free.
    group_order: []const KeyExchangeGroup = &default_group_order,
    /// Ticket sealing key (RFC 8446 §4.6.1). Null disables resumption entirely:
    /// no NewSessionTicket is issued and offered PSKs are ignored.
    ticket_key: ?tls_resumption.TicketKey = null,
    /// Previous ticket key kept across a rotation; tickets that fail under
    /// `ticket_key` are retried under it (`tls_resumption.openTicketWithRotation`).
    previous_ticket_key: ?tls_resumption.TicketKey = null,
    /// Lifetime advertised in NewSessionTicket (capped at 7 days, §4.6.1).
    ticket_lifetime_seconds: u32 = 86_400,
    /// Wall-clock Unix seconds supplied by the caller (this engine reads no
    /// clock). Required for both issuing and accepting tickets: without it a
    /// ticket's lifetime cannot be enforced, so resumption stays off.
    now_unix_seconds: ?i64 = null,
    /// Allow 0-RTT (RFC 9001 §4.6). OFF by default; also requires a
    /// `replay_guard` and `now_unix_seconds` or early data is always rejected.
    enable_early_data: bool = false,
    /// Shared single-use binder guard (RFC 8446 §8). Borrowed; must outlive the
    /// handshake and be shared by every connection that accepts 0-RTT.
    replay_guard: ?*tls_resumption.ReplayGuard = null,
    /// RFC 8446 §8.3 ticket-age freshness tolerance for 0-RTT, milliseconds.
    early_data_age_skew_ms: u32 = 10_000,
    /// The stateless-reset token for this connection's server CID (RFC 9000
    /// §10.3 / §18.2 `stateless_reset_token`, 0x02). Emitted in
    /// EncryptedExtensions when set.
    stateless_reset_token: ?[16]u8 = null,
};

const State = enum {
    wait_client_hello,
    wait_client_finished,
    connected,
};

/// One handshake message (`type ‖ uint24 length ‖ body`) plus its raw bytes.
const HandshakeMsg = struct { typ: HandshakeType, body: []const u8, raw: []const u8 };

const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
    /// RFC 8446 §4.4.1 synthetic transcript entry replacing ClientHello1.
    message_hash = 254,
    _,
};

/// Outcome of processing one ClientHello: build the flight, or ask the client
/// to retry with a group (RFC 8446 §4.1.4).
const HelloOutcome = union(enum) {
    proceed: KexShared,
    retry: KeyExchangeGroup,
};

/// CRYPTO bytes the server wants to send at one encryption level, owned by the
/// caller after `takeFlight`.
pub const LevelBytes = struct {
    level: EncryptionLevel,
    bytes: []u8,
};

pub const Server = struct {
    allocator: Allocator,
    config: Config,
    state: State = .wait_client_hello,

    suite: ?CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    peer_params: ?quic_transport_params.TransportParameters = null,
    /// Owned copy of the peer's transport-parameter byte strings (cids) so they
    /// outlive the consumed CRYPTO input.
    peer_params_storage: std.ArrayList(u8) = .empty,

    x25519_pair: kx.X25519Kx.KeyPair,
    server_random: [32]u8,

    /// Key-exchange group negotiated from the ClientHello key_share.
    selected_group: SelectedGroup = .x25519,
    /// Server X25519MLKEM768 key_share (ml-kem_ct(1088) ‖ x25519_pk(32)),
    /// populated only when `selected_group == .x25519mlkem768`.
    hybrid_keyshare: [hybrid_server_share_len]u8 = undefined,

    /// Running transcript of raw handshake messages (RFC 8446 §4.4.1).
    transcript: std.ArrayList(u8) = .empty,
    /// Reassembled client CRYPTO bytes at the level we currently expect input on.
    recv: std.ArrayList(u8) = .empty,

    /// Server CRYPTO output buffered per level until the caller drains it.
    out_initial: std.ArrayList(u8) = .empty,
    out_handshake: std.ArrayList(u8) = .empty,

    // Secrets stored at SHA-384 width; only the live (hash-length) prefix is
    // used. The Handshake secret is retained so the Master secret (and thus the
    // application traffic secrets) can be derived after the server flight.
    handshake_secret: [max_hash_len]u8 = @splat(0),
    client_hs_secret: [max_hash_len]u8 = @splat(0),
    server_hs_secret: [max_hash_len]u8 = @splat(0),
    client_ap_secret: [max_hash_len]u8 = @splat(0),
    server_ap_secret: [max_hash_len]u8 = @splat(0),

    handshake_keys: ?KeySet = null,
    application_keys: ?KeySet = null,

    /// HelloRetryRequest state (RFC 8446 §4.1.4): set once the HRR is sent; the
    /// second ClientHello must use `hrr_group` and keep `hrr_suite`.
    hrr_sent: bool = false,
    hrr_group: KeyExchangeGroup = .x25519,
    hrr_suite: ?CipherSuite = null,

    /// PSK resumption state (RFC 8446 §4.2.11). `accepted_psk` feeds the Early
    /// Secret; `selected_identity` is echoed in ServerHello.pre_shared_key.
    resumed: bool = false,
    selected_identity: u16 = 0,
    accepted_psk: [max_hash_len]u8 = @splat(0),
    accepted_psk_len: usize = 0,

    /// 0-RTT state (RFC 9001 §4.6). `early_read_keys` are the client
    /// early-traffic packet keys, present only when early data was accepted.
    early_data_offered: bool = false,
    early_data_accepted: bool = false,
    early_read_keys: ?PacketKeys = null,

    /// Post-handshake CRYPTO output (1-RTT level): the NewSessionTicket.
    out_application: std.ArrayList(u8) = .empty,
    ticket_issued: bool = false,

    pub fn init(allocator: Allocator, config: Config) Error!Server {
        if (config.cert_chain.len == 0) return error.NoCertificate;
        try validateGroupOrder(config.group_order);
        var seed: [kx.X25519Kx.seed_len]u8 = undefined;
        if (config.x25519_seed) |s| {
            seed = s;
        } else {
            try osEntropy(&seed);
        }
        defer secureZero(&seed);
        var server_random: [32]u8 = undefined;
        if (config.server_random) |r| {
            server_random = r;
        } else {
            try osEntropy(&server_random);
        }
        return .{
            .allocator = allocator,
            .config = config,
            .x25519_pair = kx.X25519Kx.generateDeterministic(seed) catch return error.BadState,
            .server_random = server_random,
        };
    }

    pub fn deinit(self: *Server) void {
        self.x25519_pair.wipe();
        secureZero(&self.handshake_secret);
        secureZero(&self.client_hs_secret);
        secureZero(&self.server_hs_secret);
        secureZero(&self.client_ap_secret);
        secureZero(&self.server_ap_secret);
        secureZero(&self.accepted_psk);
        if (self.early_read_keys) |*k| secureZero(std.mem.asBytes(k));
        self.transcript.deinit(self.allocator);
        self.recv.deinit(self.allocator);
        self.out_initial.deinit(self.allocator);
        self.out_handshake.deinit(self.allocator);
        self.out_application.deinit(self.allocator);
        self.peer_params_storage.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isComplete(self: *const Server) bool {
        return self.state == .connected;
    }

    /// Whether this handshake resumed a session via a PSK (RFC 8446 §2.2).
    pub fn isResumed(self: *const Server) bool {
        return self.resumed;
    }

    /// Whether a HelloRetryRequest was sent on this connection.
    pub fn sentHelloRetryRequest(self: *const Server) bool {
        return self.hrr_sent;
    }

    /// Whether 0-RTT was accepted (EncryptedExtensions carries `early_data`).
    pub fn earlyDataAccepted(self: *const Server) bool {
        return self.early_data_accepted;
    }

    /// The client early-traffic packet keys (RFC 9001 §5.1, 0-RTT read keys),
    /// or null when early data was not accepted or the keys were discarded.
    pub fn earlyDataReadKeys(self: *const Server) ?PacketKeys {
        return self.early_read_keys;
    }

    /// Discard the 0-RTT keys (RFC 9001 §4.9.3).
    pub fn discardEarlyDataKeys(self: *Server) void {
        if (self.early_read_keys) |*k| secureZero(std.mem.asBytes(k));
        self.early_read_keys = null;
    }

    pub fn selectedAlpn(self: *const Server) ?[]const u8 {
        return self.selected_alpn;
    }

    pub fn peerTransportParams(self: *const Server) ?quic_transport_params.TransportParameters {
        return self.peer_params;
    }

    pub fn cipherName(self: *const Server) ?[]const u8 {
        const s = self.suite orelse return null;
        return s.name();
    }

    /// The installed Handshake-level `KeySet` (write = server, read = client),
    /// available once the ClientHello has been processed.
    pub fn handshakeKeys(self: *const Server) ?KeySet {
        return self.handshake_keys;
    }

    /// The installed 1-RTT / Application-level `KeySet`, available once the
    /// server flight has been produced.
    pub fn applicationKeys(self: *const Server) ?KeySet {
        return self.application_keys;
    }

    /// The 1-RTT (application) traffic secrets used to seed key updates
    /// (RFC 9001 §6). `write` is this endpoint's own secret (server_ap_secret),
    /// `read` is the peer's (client_ap_secret); `hash_len` is 32 or 48 per the
    /// suite's hash. Returns null until the application keys are installed.
    /// This is a pure read-only accessor; it changes no state.
    pub fn appTrafficSecrets(self: *const Server) ?AppTrafficSecrets {
        if (self.application_keys == null) return null;
        const suite = self.suite orelse return null;
        return .{
            .write = self.server_ap_secret,
            .read = self.client_ap_secret,
            .hash_len = @intCast(suite.hashLen()),
            .suite = suite.quicSuite(),
        };
    }

    /// Feed reassembled client CRYPTO bytes for `level`. Returns nothing; the
    /// caller then drains any produced server CRYPTO via `takeFlight` and reads
    /// installed keys via `handshakeKeys`/`applicationKeys`.
    ///
    /// `level` must be Initial for the ClientHello and Handshake for the client
    /// Finished. Bytes are appended to the per-phase reassembly buffer so a
    /// ClientHello split across CRYPTO frames still reassembles.
    pub fn feedCrypto(self: *Server, level: EncryptionLevel, data: []const u8) Error!void {
        switch (self.state) {
            .wait_client_hello => {
                if (level != .initial) return error.BadState;
                try appendBounded(self.allocator, &self.recv, data);
                try self.driveClientHello();
            },
            .wait_client_finished => {
                if (level != .handshake) return error.BadState;
                try appendBounded(self.allocator, &self.recv, data);
                try self.driveClientFinished();
            },
            .connected => return error.BadState,
        }
    }

    /// Take ownership of all buffered server CRYPTO bytes at `level`. Returns an
    /// empty slice (caller still owns it) when nothing is queued. The
    /// application level carries the post-handshake NewSessionTicket.
    pub fn takeFlight(self: *Server, level: EncryptionLevel) Error![]u8 {
        const buf = switch (level) {
            .initial => &self.out_initial,
            .handshake => &self.out_handshake,
            .application => &self.out_application,
        };
        return buf.toOwnedSlice(self.allocator);
    }

    // --- ClientHello → server flight -------------------------------------

    fn driveClientHello(self: *Server) Error!void {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(self.recv.items, &off) orelse return; // need more
        if (msg.typ != .client_hello) return error.BadHandshake;
        // Nothing may follow a ClientHello at the Initial level: the client
        // cannot send ClientHello2 before it has seen our HelloRetryRequest, and
        // its Finished travels at the Handshake level (RFC 9001 §4.1.3).
        if (off != self.recv.items.len) return error.BadHandshake;
        try self.appendTranscript(msg.raw);
        switch (try self.processClientHello(msg.body, msg.raw)) {
            .retry => |group| {
                try self.sendHelloRetryRequest(group, msg.raw.len);
                consumePrefix(&self.recv, off);
            },
            .proceed => |shared_value| {
                var shared = shared_value;
                defer secureZero(&shared.buf);
                try self.buildServerFlight(shared);
                consumePrefix(&self.recv, off);
                self.state = .wait_client_finished;
            },
        }
    }

    fn buildServerFlight(self: *Server, shared: KexShared) Error!void {
        const suite = self.suite orelse return error.UnsupportedCipherSuite;

        // ServerHello (Initial level), folded into the transcript.
        try self.writeServerHello(&self.out_initial);

        // Handshake keys derive over CH + SH. The (EC)DHE secret is 32 bytes for
        // a classical group or 64 for the X25519MLKEM768 hybrid; a resumed
        // handshake also feeds the PSK into the Early Secret (RFC 8446 §7.1).
        try self.deriveAndInstallHandshakeKeys(shared.buf[0..shared.len], suite);

        // The encrypted flight (Handshake level): EncryptedExtensions, then for
        // a full handshake Certificate + CertificateVerify, then Finished. A PSK
        // handshake authenticates via the PSK and omits the certificate
        // messages (RFC 8446 §2.2).
        try self.writeEncryptedExtensions(&self.out_handshake);
        if (!self.resumed) {
            try self.writeCertificate(&self.out_handshake);
            try self.writeCertificateVerify(&self.out_handshake);
        }
        try self.writeServerFinished(&self.out_handshake);

        // Application keys derive over CH..server Finished.
        try self.deriveAndInstallApplicationKeys(suite);
    }

    /// Send a HelloRetryRequest (RFC 8446 §4.1.4) asking for `group`. The
    /// transcript restarts as `message_hash(ClientHello1) ‖ HRR` (§4.4.1); the
    /// HRR rides the Initial level like a ServerHello (RFC 9001 §4.1.3).
    fn sendHelloRetryRequest(self: *Server, group: KeyExchangeGroup, ch1_len: usize) Error!void {
        const suite = self.suite orelse return error.UnsupportedCipherSuite;
        if (self.transcript.items.len != ch1_len) return error.BadState;
        var digest: [max_hash_len]u8 = undefined;
        const hlen = hashFor(suite, self.transcript.items, &digest);
        self.transcript.clearRetainingCapacity();
        try self.transcript.appendSlice(self.allocator, &.{ @backingInt(HandshakeType.message_hash), 0, 0, @intCast(hlen) });
        try self.transcript.appendSlice(self.allocator, digest[0..hlen]);

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU16(self.allocator, &body, legacy_version);
        try body.appendSlice(self.allocator, &hello_retry_request_random);
        try body.append(self.allocator, 0); // legacy_session_id_echo (QUIC: empty)
        try appendU16(self.allocator, &body, @backingInt(suite));
        try body.append(self.allocator, 0); // null compression
        var ext_storage: [64]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        var ver_buf: [2]u8 = undefined;
        try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildServer(&ver_buf, tls_supported_versions.tls13));
        // RFC 8446 §4.2.8: the HRR key_share body is the bare selected group.
        var ks_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &ks_buf, group.keyShareGroup().toInt(), .big);
        try ext_builder.addTyped(.key_share, &ks_buf);
        try body.appendSlice(self.allocator, try ext_builder.finish());
        try self.emit(&self.out_initial, .server_hello, body.items);

        self.hrr_sent = true;
        self.hrr_group = group;
        self.hrr_suite = suite;
    }

    fn processClientHello(self: *Server, body: []const u8, raw: []const u8) Error!HelloOutcome {
        var c = Cursor.init(body);
        if (try c.readU16() != legacy_version) return error.ProtocolVersion;
        _ = try c.take(32); // client random (unused by the key schedule)
        // RFC 9001 §8.4: a QUIC ClientHello MUST carry an empty
        // legacy_session_id; a server SHOULD treat anything else as a
        // PROTOCOL_VIOLATION.
        if ((try c.take(try c.readU8())).len != 0) return error.BadHandshake;

        const suites_block = try c.take(try c.readU16());
        const negotiated = pickSuite(suites_block) orelse return error.UnsupportedCipherSuite;

        const comp = try c.take(try c.readU8());
        var null_comp = false;
        for (comp) |m| if (m == 0) {
            null_comp = true;
        };
        if (!null_comp) return error.BadHandshake;

        const ext_block = try c.take(try c.readU16());
        if (c.remaining() != 0) return error.BadHandshake;

        var offered_tls13 = false;
        var x25519_share: ?[]const u8 = null;
        var hybrid_share: ?[]const u8 = null; // X25519MLKEM768 (post-quantum)
        var groups_block: ?[]const u8 = null;
        var psk_dhe_ke = false;
        var psk_ext: ?[]const u8 = null;
        var offered_early_data = false;
        var have_params = false;
        // RFC 8446 §4.2: at most one extension of each type per block. A
        // 65536-bit set makes the check exact for every wire type value.
        var seen = std.bit_set.StaticBitSet(std.math.maxInt(u16) + 1).empty;
        self.selected_alpn = null;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            if (seen.isSet(ext.ext_type)) return error.BadHandshake;
            seen.set(ext.ext_type);
            switch (ext.ext_type) {
                @backingInt(tls_extension.ExtensionType.supported_versions) => {
                    if (tls_supported_versions.clientOffers(ext.data, tls_supported_versions.tls13)) offered_tls13 = true;
                },
                @backingInt(tls_extension.ExtensionType.supported_groups) => groups_block = ext.data,
                @backingInt(tls_extension.ExtensionType.key_share) => {
                    var shares = tls_keyshare.parseClientShares(ext.data) catch continue;
                    while (shares.next() catch null) |entry| {
                        if (entry.group == .x25519 and entry.key_exchange.len == kx.X25519Kx.public_len) {
                            if (x25519_share == null) x25519_share = entry.key_exchange;
                        } else if (entry.group == .x25519mlkem768 and entry.key_exchange.len == hybrid_client_share_len) {
                            if (hybrid_share == null) hybrid_share = entry.key_exchange;
                        }
                    }
                },
                @backingInt(tls_extension.ExtensionType.alpn) => self.maybeSelectAlpn(ext.data),
                @backingInt(tls_extension.ExtensionType.psk_key_exchange_modes) => psk_dhe_ke = pskModesAllowDhe(ext.data),
                @backingInt(tls_extension.ExtensionType.early_data) => {
                    // RFC 8446 §4.2.10: empty in ClientHello.
                    if (ext.data.len != 0) return error.BadHandshake;
                    offered_early_data = true;
                },
                @backingInt(tls_extension.ExtensionType.pre_shared_key) => {
                    // RFC 8446 §4.2.11: MUST be the last extension.
                    if (it.remaining() != 0) return error.BadHandshake;
                    psk_ext = ext.data;
                },
                quic_transport_parameters_ext => {
                    try self.capturePeerParams(ext.data);
                    have_params = true;
                },
                else => {},
            }
        }

        if (!offered_tls13) return error.ProtocolVersion;
        if (!have_params) return error.MissingExtension;

        if (self.hrr_sent) {
            // RFC 8446 §4.1.2: ClientHello2 MUST NOT offer early data, and
            // (§4.1.4) the cipher suite the HRR committed to must not change.
            if (offered_early_data) return error.BadHandshake;
            const committed = self.hrr_suite orelse return error.BadHandshake;
            if (committed != negotiated) return error.BadHandshake;
            // RFC 8446 §4.1.2: the retried key_share must be exactly the group
            // the HRR selected; ignore shares for any other group.
            switch (self.hrr_group) {
                .x25519 => hybrid_share = null,
                .x25519mlkem768 => x25519_share = null,
            }
        }
        self.suite = negotiated;

        // Choose the key share in server preference order.
        var chosen: ?KeyExchangeGroup = null;
        for (self.config.group_order) |g| {
            const have = switch (g) {
                .x25519mlkem768 => hybrid_share != null,
                .x25519 => x25519_share != null,
            };
            if (have) {
                chosen = g;
                break;
            }
        }
        const group = chosen orelse {
            if (self.hrr_sent) return error.BadHandshake; // §4.1.4: at most one HRR
            // RFC 8446 §4.1.4: no usable share, but a group we implement is
            // advertised → HelloRetryRequest for our most preferred such group.
            // Decided BEFORE any PSK / 0-RTT processing so early data is never
            // accepted on a hello we are about to bounce.
            if (groups_block) |groups| {
                for (self.config.group_order) |g| {
                    if (supported_groups.offers(groups, g.named())) return .{ .retry = g };
                }
            }
            return error.UnsupportedGroup;
        };

        // PSK resumption + 0-RTT (RFC 8446 §4.2.9–§4.2.11). Only psk_dhe_ke is
        // supported; a PSK offered without it falls back to a full handshake.
        self.resumed = false;
        self.early_data_offered = offered_early_data;
        self.early_data_accepted = false;
        self.discardEarlyDataKeys();
        if (psk_ext) |ext| {
            if (psk_dhe_ke) try self.tryAcceptPsk(suites_block, raw, ext, offered_early_data);
        }

        return .{ .proceed = try self.keyExchange(group, x25519_share, hybrid_share) };
    }

    /// Run the (EC)DHE / hybrid exchange for the chosen group.
    fn keyExchange(self: *Server, group: KeyExchangeGroup, x25519_share: ?[]const u8, hybrid_share: ?[]const u8) Error!KexShared {
        switch (group) {
            .x25519mlkem768 => {
                const peer = hybrid_share orelse return error.BadState;
                // X25519MLKEM768 (0x11ec): client share = ml-kem_ek(1184) ‖ x25519_pk(32).
                self.selected_group = .x25519mlkem768;

                // X25519 ECDH against the classical half of the client share.
                var x_peer: kx.PublicKey = undefined;
                @memcpy(&x_peer, peer[mlkem_ek_len .. mlkem_ek_len + x25519_pub_len]);
                var x_secret = kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, x_peer) catch return error.BadHandshake;
                defer x_secret.wipe();

                // ML-KEM-768 encapsulate against the PQ half, with fresh entropy.
                var ek: [mlkem_ek_len]u8 = undefined;
                @memcpy(&ek, peer[0..mlkem_ek_len]);
                const mlkem_pk = MlKem768.PublicKey.fromBytes(&ek) catch return error.BadHandshake;
                var seed: [MlKem768.encaps_seed_length]u8 = undefined;
                try osEntropy(&seed);
                var enc = mlkem_pk.encapsDeterministic(&seed);
                secureZero(&seed);
                defer secureZero(&enc.shared_secret);

                // Server share (emitted in ServerHello): ml-kem_ct(1088) ‖ x25519_pk(32).
                @memcpy(self.hybrid_keyshare[0..mlkem_ct_len], &enc.ciphertext);
                @memcpy(self.hybrid_keyshare[mlkem_ct_len..], &self.x25519_pair.public_key);

                // Combined (EC)DHE secret fed to the key schedule: ml-kem_ss ‖ x25519_ss.
                var out = KexShared{ .len = 64 };
                @memcpy(out.buf[0..32], &enc.shared_secret);
                const x_ss = x_secret.declassify();
                @memcpy(out.buf[32..64], &x_ss);
                return out;
            },
            .x25519 => {
                const peer = x25519_share orelse return error.BadState;
                self.selected_group = .x25519;
                var peer_pub: kx.PublicKey = undefined;
                @memcpy(&peer_pub, peer);
                var secret = kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer_pub) catch return error.BadHandshake;
                defer secret.wipe();
                var out = KexShared{ .len = 32 };
                const ss = secret.declassify();
                @memcpy(out.buf[0..32], &ss);
                return out;
            },
        }
    }

    // --- PSK resumption + 0-RTT -------------------------------------------

    /// Examine the offered PSK identities (RFC 8446 §4.2.11). The first identity
    /// whose ticket this server sealed, for a cipher suite the client offered,
    /// inside its lifetime, carrying QUIC remembered state, is selected; its
    /// binder MUST verify or the handshake aborts. Unknown/stale tickets fall
    /// back to a full handshake. 0-RTT is then accepted only per
    /// `earlyDataAcceptable`.
    fn tryAcceptPsk(self: *Server, suites_block: []const u8, raw: []const u8, psk_ext: []const u8, offered_early_data: bool) Error!void {
        const ticket_key = self.config.ticket_key orelse return;
        const now_s = self.config.now_unix_seconds orelse return;
        var parsed = tls_psk.parseClientPsk(psk_ext) catch return error.BadHandshake;

        // RFC 8446 §4.2.11: one binder per identity, matched by index.
        var count_ids = parsed;
        var n_ids: usize = 0;
        while (count_ids.identities.next() catch return error.BadHandshake) |_| n_ids += 1;
        var n_binders: usize = 0;
        while (count_ids.binders.next() catch return error.BadHandshake) |_| n_binders += 1;
        if (n_ids == 0 or n_ids != n_binders) return error.BadHandshake;

        var index: usize = 0;
        while (index < @min(n_ids, max_psk_identities_examined)) : (index += 1) {
            const identity = (parsed.identities.next() catch return error.BadHandshake) orelse return;
            const binder = (parsed.binders.next() catch return error.BadHandshake) orelse return;

            const opened = tls_resumption.openTicketWithRotation(self.allocator, ticket_key, self.config.previous_ticket_key, identity.identity) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue, // not one of ours (or forged): ignore
            };
            defer {
                secureZero(opened.plain);
                self.allocator.free(opened.plain);
            }
            const t = opened.opened;
            const suite = suiteFromWire(t.suite) orelse continue;
            if (!clientOfferedSuite(suites_block, suite)) continue;
            if (self.hrr_sent and suite != self.hrr_suite.?) continue;
            if (t.psk.len != suite.hashLen() or binder.len != suite.hashLen()) continue;
            if (!ticketFresh(t, now_s)) continue; // stale or undated: full handshake
            if (t.ticket_nonce.len != ticket_state_len or t.ticket_nonce[0] != ticket_state_version) continue;

            // RFC 8446 §4.2.11.2: binder over Transcript-so-far ‖ Truncate(CH).
            if (!self.verifyPskBinder(suite, t.psk, raw, psk_ext, binder)) return error.PskBinderMismatch;

            self.resumed = true;
            self.selected_identity = @intCast(index);
            self.suite = suite;
            @memcpy(self.accepted_psk[0..t.psk.len], t.psk);
            self.accepted_psk_len = t.psk.len;

            // RFC 8446 §4.2.10: early data is only for the FIRST identity.
            if (offered_early_data and index == 0 and
                self.earlyDataAcceptable(t, identity.obfuscated_ticket_age, now_s, binder))
            {
                self.early_data_accepted = true;
                try self.deriveEarlyReadKeys();
            }
            return;
        }
    }

    /// Every RFC 9001 §4.6.2 / RFC 8446 §4.2.10 / RFC 9000 §7.4.1 condition for
    /// accepting 0-RTT. Any failure REJECTS early data (the handshake still
    /// resumes at 1-RTT). The replay guard runs last so a refused attempt does
    /// not consume a guard slot.
    fn earlyDataAcceptable(self: *Server, t: tls_resumption.OpenedTicket, obfuscated_age: u32, now_s: i64, binder: []const u8) bool {
        if (!self.config.enable_early_data) return false;
        const guard = self.config.replay_guard orelse return false;
        if (t.max_early_data_size != quic_max_early_data_size) return false;
        if (!self.ticketAgeWithinWindow(t, obfuscated_age, now_s)) return false;
        // The 0-RTT ALPN must equal the one the ticket was issued under.
        const state = t.ticket_nonce;
        const alpn_now = alpnDigest(self.selected_alpn);
        if (!std.crypto.timing_safe.eql([32]u8, alpn_now, state[1 + ticket_random_len ..][0..32].*)) return false;
        // RFC 9000 §7.4.1: a server MUST NOT accept 0-RTT if it would reduce
        // any limit the client remembered from the ticket's connection.
        const now_params = rememberedParams(self.config.transport_params);
        const base = 1 + ticket_random_len + 32;
        for (now_params, 0..) |cur, i| {
            const was = std.mem.readInt(u64, state[base + i * 8 ..][0..8], .big);
            if (cur < was) return false;
        }
        return guard.checkAndRecord(binder);
    }

    /// RFC 8446 §8.3: the client's reported ticket age (un-obfuscated with the
    /// sealed `ticket_age_add`) must be within `early_data_age_skew_ms` of the
    /// server-measured age. Public values only.
    fn ticketAgeWithinWindow(self: *const Server, t: tls_resumption.OpenedTicket, obfuscated_age: u32, now_s: i64) bool {
        const age_add = t.ticket_age_add orelse return false;
        const reported_ms: u32 = obfuscated_age -% age_add;
        const server_ms: i64 = now_s * 1000 - t.issued_unix_ms;
        if (server_ms < 0) return false;
        const diff: i64 = @as(i64, reported_ms) - server_ms;
        const abs_diff: i64 = if (diff < 0) -diff else diff;
        return abs_diff <= @as(i64, self.config.early_data_age_skew_ms);
    }

    fn verifyPskBinder(self: *Server, suite: CipherSuite, psk: []const u8, raw: []const u8, psk_ext: []const u8, binder: []const u8) bool {
        // `driveClientHello` appended the full ClientHello before this runs; the
        // binder covers everything before it (after an HRR: message_hash(CH1) ‖
        // HRR) and the ClientHello truncated before the binders list.
        const items = self.transcript.items;
        if (raw.len > items.len) return false;
        const prefix_end = items.len - raw.len;
        if (!std.mem.eql(u8, items[prefix_end..], raw)) return false;
        const binder_list_offset = tls_psk.binderListOffset(psk_ext) catch return false;
        const psk_body_offset = findPskExtensionBodyOffset(raw) catch return false;
        const truncated_len = psk_body_offset + binder_list_offset;
        if (truncated_len > raw.len) return false;
        return switch (suite) {
            .tls_aes_256_gcm_sha384 => binderMatches(Sha384, self.allocator, psk, items[0..prefix_end], raw[0..truncated_len], binder),
            else => binderMatches(Sha256, self.allocator, psk, items[0..prefix_end], raw[0..truncated_len], binder),
        };
    }

    fn deriveEarlyReadKeys(self: *Server) Error!void {
        const suite = self.suite orelse return error.BadState;
        const psk = self.accepted_psk[0..self.accepted_psk_len];
        self.early_read_keys = switch (suite) {
            .tls_aes_256_gcm_sha384 => try earlyTrafficKeys(Sha384, suite, psk, self.transcript.items),
            else => try earlyTrafficKeys(Sha256, suite, psk, self.transcript.items),
        };
    }

    /// Issue one NewSessionTicket (RFC 8446 §4.6.1) at the 1-RTT level once the
    /// client Finished verified. `client_finished` is the raw Finished message,
    /// which the resumption master secret's transcript must include (§7.1).
    fn queueNewSessionTicket(self: *Server, client_finished: []const u8) Error!void {
        if (self.ticket_issued) return;
        const ticket_key = self.config.ticket_key orelse return;
        const now_s = self.config.now_unix_seconds orelse return;
        if (now_s <= 0) return;
        const suite = self.suite orelse return error.BadState;

        var state: [ticket_state_len]u8 = undefined;
        state[0] = ticket_state_version;
        try osEntropy(state[1 .. 1 + ticket_random_len]);
        state[1 + ticket_random_len ..][0..32].* = alpnDigest(self.selected_alpn);
        const params = rememberedParams(self.config.transport_params);
        for (params, 0..) |v, i| std.mem.writeInt(u64, state[1 + ticket_random_len + 32 + i * 8 ..][0..8], v, .big);

        var age_add_bytes: [4]u8 = undefined;
        try osEntropy(&age_add_bytes);
        const age_add = std.mem.readInt(u32, &age_add_bytes, .big);
        var aead_nonce: [12]u8 = undefined;
        try osEntropy(&aead_nonce);

        var psk: [max_hash_len]u8 = undefined;
        defer secureZero(&psk);
        const hl = suite.hashLen();
        switch (suite) {
            .tls_aes_256_gcm_sha384 => try self.ticketPskT(Sha384, client_finished, &state, psk[0..hl]),
            else => try self.ticketPskT(Sha256, client_finished, &state, psk[0..hl]),
        }

        const lifetime = @min(self.config.ticket_lifetime_seconds, max_ticket_lifetime_seconds);
        const early_limit: u32 = if (self.config.enable_early_data and self.config.replay_guard != null) quic_max_early_data_size else 0;
        const sealed = tls_resumption.sealTicket(
            self.allocator,
            ticket_key,
            aead_nonce,
            @backingInt(suite),
            psk[0..hl],
            &state,
            now_s * 1000,
            early_limit,
            age_add,
            lifetime,
        ) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadState,
        };
        defer self.allocator.free(sealed);

        // RFC 9001 §4.6.1: early_data advertises 0xffffffff, only when enabled.
        var ext_storage: [16]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        if (early_limit != 0) {
            var early_ext: [4]u8 = undefined;
            std.mem.writeInt(u32, &early_ext, early_limit, .big);
            try ext_builder.addTyped(.early_data, &early_ext);
        }
        const exts = try ext_builder.finish();

        var body_buf: [1024]u8 = undefined;
        const body = tls_session_ticket.encode(&body_buf, .{
            .ticket_lifetime = lifetime,
            .ticket_age_add = age_add,
            .ticket_nonce = &state,
            .ticket = sealed,
            .extensions = exts[2..],
        }) catch return error.BadState;
        try writeHandshake(self.allocator, &self.out_application, .new_session_ticket, body);
        self.ticket_issued = true;
    }

    fn ticketPskT(self: *Server, comptime KS: type, client_finished: []const u8, nonce: []const u8, out: []u8) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.handshake_secret[0..KS.hash_len]);
        var hs = KS.SecretBytes.init(sk);
        defer hs.wipe();
        secureZero(&sk);
        var master = try KS.masterSecret(&hs);
        defer master.wipe();
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(self.allocator);
        try joined.appendSlice(self.allocator, self.transcript.items);
        try joined.appendSlice(self.allocator, client_finished);
        const th = KS.transcriptHash(joined.items);
        var rms = try KS.deriveSecret(&master, "res master", &th);
        defer rms.wipe();
        try KS.hkdfExpandLabel(&rms, "resumption", nonce, out[0..KS.hash_len]);
    }

    /// Decode + copy the peer's transport parameters so the cids outlive the
    /// consumed CRYPTO buffer.
    fn capturePeerParams(self: *Server, data: []const u8) Error!void {
        // Validate first (rejects malformed input before we keep a copy).
        _ = try quic_transport_params.decode(data);
        self.peer_params_storage.clearRetainingCapacity();
        try self.peer_params_storage.appendSlice(self.allocator, data);
        self.peer_params = try quic_transport_params.decode(self.peer_params_storage.items);
    }

    /// Select an ALPN protocol with *server* preference (RFC 7301 lets the
    /// server choose; HTTP/3 over QUIC conventionally honors server order). For
    /// each server preference in order, accept it if the client offered it.
    fn maybeSelectAlpn(self: *Server, data: []const u8) void {
        if (self.config.alpn_protocols.len == 0) return;
        for (self.config.alpn_protocols) |pref| {
            var names = tls_alpn.Iterator.fromBlock(data) catch return;
            while (names.next() catch null) |offered| {
                if (std.mem.eql(u8, pref, offered)) {
                    self.selected_alpn = pref;
                    return;
                }
            }
        }
    }

    fn writeServerHello(self: *Server, out: *std.ArrayList(u8)) Error!void {
        const suite = self.suite.?;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);

        try appendU16(self.allocator, &body, legacy_version);
        try body.appendSlice(self.allocator, &self.server_random);
        try body.append(self.allocator, 0); // legacy_session_id_echo: empty (QUIC)
        try appendU16(self.allocator, &body, @backingInt(suite));
        try body.append(self.allocator, 0); // null compression

        // Sized to hold the X25519MLKEM768 server key_share (1120 bytes) plus the
        // supported_versions extension.
        var ext_storage: [hybrid_server_share_len + 256]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        var ver_buf: [2]u8 = undefined;
        try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildServer(&ver_buf, tls_supported_versions.tls13));
        var ks_buf: [hybrid_server_share_len + 8]u8 = undefined;
        const ks = switch (self.selected_group) {
            .x25519mlkem768 => try tls_keyshare.buildServerShare(&ks_buf, .{ .group = .x25519mlkem768, .key_exchange = &self.hybrid_keyshare }),
            .x25519 => try tls_keyshare.buildServerShare(&ks_buf, .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key }),
        };
        try ext_builder.addTyped(.key_share, ks);
        if (self.resumed) {
            // RFC 8446 §4.2.11: echo the selected PSK identity index.
            var psk_buf: [tls_psk.server_psk_len]u8 = undefined;
            try ext_builder.addTyped(.pre_shared_key, tls_psk.buildServerPsk(&psk_buf, self.selected_identity) catch return error.BadState);
        }
        try body.appendSlice(self.allocator, try ext_builder.finish());

        try self.emit(out, .server_hello, body.items);
    }

    fn writeEncryptedExtensions(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var ext_storage: [1024]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);

        if (self.selected_alpn) |proto| {
            var alpn_buf: [260]u8 = undefined;
            var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
            try alpn_builder.add(proto);
            try ext_builder.addTyped(.alpn, try alpn_builder.finish());
        }

        // RFC 8446 §4.2.10: an empty early_data in EE signals 0-RTT acceptance.
        if (self.early_data_accepted) try ext_builder.addTyped(.early_data, "");

        // The server's quic_transport_parameters (mandatory in EE for QUIC).
        var tp_body: std.ArrayList(u8) = .empty;
        defer tp_body.deinit(self.allocator);
        try quic_transport_params.encode(&tp_body, self.allocator, self.config.transport_params);
        if (self.config.stateless_reset_token) |token| {
            // RFC 9000 §18.2 stateless_reset_token (0x02): a 16-byte value for
            // the CID in initial_source_connection_id. The transport-parameter
            // model has no field for it, so append the raw TLV (id, len, value).
            try tp_body.appendSlice(self.allocator, &.{ 0x02, 16 });
            try tp_body.appendSlice(self.allocator, &token);
        }
        try ext_builder.add(quic_transport_parameters_ext, tp_body.items);

        try self.emit(out, .encrypted_extensions, try ext_builder.finish());
    }

    fn writeCertificate(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.append(self.allocator, 0); // certificate_request_context: empty

        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.allocator);
        for (self.config.cert_chain) |der| {
            try appendU24(self.allocator, &list, der.len);
            try list.appendSlice(self.allocator, der);
            try appendU16(self.allocator, &list, 0); // per-cert extensions: empty
        }
        try appendU24(self.allocator, &body, list.items.len);
        try body.appendSlice(self.allocator, list.items);
        try self.emit(out, .certificate, body.items);
    }

    fn writeCertificateVerify(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, server_cert_verify_context, th[0..th_len]);

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        switch (self.config.signing_key) {
            .ed25519 => |key| {
                const sig = (key.sign(input, null) catch return error.SignatureFailed).toBytes();
                try appendU16(self.allocator, &body, @backingInt(tls_signature_scheme.SignatureScheme.ed25519));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, &sig);
            },
            .ecdsa_p256 => |key| {
                const sig = ecdsa_p256.sign(input, key) catch return error.SignatureFailed;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = ecdsa_p256.signatureToDer(sig, &der_buf) catch return error.SignatureFailed;
                try appendU16(self.allocator, &body, @backingInt(tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256));
                try appendU16(self.allocator, &body, @intCast(der.len));
                try body.appendSlice(self.allocator, der);
            },
            .rsa => |key| {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
                var salt: [32]u8 = undefined;
                try osEntropy(&salt);
                defer secureZero(&salt);
                var sig_buf: [512]u8 = undefined;
                const sig = rsa_sign.signPss(key, .sha256, &digest, &salt, &sig_buf) catch return error.SignatureFailed;
                try appendU16(self.allocator, &body, @backingInt(tls_signature_scheme.SignatureScheme.rsa_pss_rsae_sha256));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, sig);
            },
        }
        try self.emit(out, .certificate_verify, body.items);
    }

    fn writeServerFinished(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var vd_buf: [max_hash_len]u8 = undefined;
        const vd_len = self.finishedVerifyData(&self.server_hs_secret, &vd_buf);
        try self.emit(out, .finished, vd_buf[0..vd_len]);
    }

    // --- client Finished -------------------------------------------------

    fn driveClientFinished(self: *Server) Error!void {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(self.recv.items, &off) orelse return; // need more
        if (msg.typ != .finished) return error.BadHandshake;
        if (off != self.recv.items.len) return error.BadHandshake; // nothing follows Finished
        if (!self.finishedVerify(&self.client_hs_secret, msg.body)) return error.FinishedMismatch;
        // The client Finished is NOT folded into the stored transcript; the
        // resumption master secret hashes it in explicitly (RFC 8446 §7.1).
        try self.queueNewSessionTicket(msg.raw);
        consumePrefix(&self.recv, off);
        self.state = .connected;
        // RFC 9001 §4.9.3: 0-RTT packets are never valid after the handshake.
        // The connection driver may retain the keys briefly via its own copy.
    }

    // --- key schedule + transcript ---------------------------------------

    fn deriveAndInstallHandshakeKeys(self: *Server, shared_secret: []const u8, suite: CipherSuite) Error!void {
        switch (suite) {
            .tls_aes_256_gcm_sha384 => try self.deriveHandshakeKeysT(Sha384, suite, shared_secret),
            else => try self.deriveHandshakeKeysT(Sha256, suite, shared_secret),
        }
    }

    fn deriveHandshakeKeysT(self: *Server, comptime KS: type, suite: CipherSuite, shared_secret: []const u8) Error!void {
        const psk: []const u8 = if (self.resumed) blk: {
            if (self.accepted_psk_len != KS.hash_len) return error.BadState;
            break :blk self.accepted_psk[0..self.accepted_psk_len];
        } else "";
        var early = KS.earlySecret(psk);
        defer early.wipe();
        var handshake = try KS.handshakeSecret(&early, shared_secret);
        defer handshake.wipe();
        // Retain the handshake secret so the master secret (and the application
        // traffic secrets) can be derived after the server flight is folded in.
        self.handshake_secret[0..KS.hash_len].* = handshake.declassify();
        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.handshakeTrafficSecrets(&handshake, &th);
        defer traffic.wipe();
        self.client_hs_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_hs_secret[0..KS.hash_len].* = traffic.server.declassify();
        self.handshake_keys = installKeys(KS, .handshake, suite, &self.server_hs_secret, &self.client_hs_secret);
    }

    fn deriveAndInstallApplicationKeys(self: *Server, suite: CipherSuite) Error!void {
        switch (suite) {
            .tls_aes_256_gcm_sha384 => try self.deriveApplicationKeysT(Sha384, suite),
            else => try self.deriveApplicationKeysT(Sha256, suite),
        }
    }

    fn deriveApplicationKeysT(self: *Server, comptime KS: type, suite: CipherSuite) Error!void {
        // master = Extract(Derive-Secret(Handshake, "derived", ""), 0); the
        // application traffic secrets are taken over CH..server Finished.
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.handshake_secret[0..KS.hash_len]);
        var hs = KS.SecretBytes.init(sk);
        defer hs.wipe();
        var master = try KS.masterSecret(&hs);
        defer master.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.applicationTrafficSecrets(&master, &th);
        defer traffic.wipe();
        self.client_ap_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_ap_secret[0..KS.hash_len].* = traffic.server.declassify();
        self.application_keys = installKeys(KS, .application, suite, &self.server_ap_secret, &self.client_ap_secret);
    }

    fn appendTranscript(self: *Server, bytes: []const u8) Error!void {
        try self.transcript.appendSlice(self.allocator, bytes);
    }

    /// Append a handshake message to `out` AND fold it into the transcript.
    fn emit(self: *Server, out: *std.ArrayList(u8), typ: HandshakeType, body: []const u8) Error!void {
        const start = out.items.len;
        try writeHandshake(self.allocator, out, typ, body);
        try self.appendTranscript(out.items[start..]);
    }

    fn transcriptHash(self: *const Server, out: *[max_hash_len]u8) usize {
        const suite = self.suite orelse return 0;
        switch (suite) {
            .tls_aes_256_gcm_sha384 => {
                const d = Sha384.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                return d.len;
            },
            else => {
                const d = Sha256.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                return d.len;
            },
        }
    }

    fn finishedVerify(self: *const Server, base_key: *const [max_hash_len]u8, received: []const u8) bool {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        const suite = self.suite orelse return false;
        return switch (suite) {
            .tls_aes_256_gcm_sha384 => tls_finished.Sha384F.verify(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*, received),
            else => tls_finished.Sha256F.verify(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*, received),
        };
    }

    fn finishedVerifyData(self: *const Server, base_key: *const [max_hash_len]u8, out: *[max_hash_len]u8) usize {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        const suite = self.suite orelse return 0;
        switch (suite) {
            .tls_aes_256_gcm_sha384 => {
                const v = tls_finished.Sha384F.verifyData(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
            else => {
                const v = tls_finished.Sha256F.verifyData(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
        }
    }
};

// ---------------------------------------------------------------------------
// QUIC packet-key installation from TLS traffic secrets
// ---------------------------------------------------------------------------

/// Build a `KeySet` for a level from this endpoint's own (write) and the peer's
/// (read) traffic secret, deriving the QUIC `quic key`/`quic iv`/`quic hp`
/// packet keys with the schedule's hash (SHA-256 or SHA-384). For SHA-256 this
/// is equivalent to `quic_protect.KeySet.fromTrafficSecrets`; for SHA-384 the
/// 48-byte secret requires SHA-384 HKDF-Expand-Label (the `quic_tls` helper is
/// SHA-256-only), which is why this is computed here over the schedule type.
fn installKeys(
    comptime KS: type,
    level: EncryptionLevel,
    suite: CipherSuite,
    own_secret: *const [max_hash_len]u8,
    peer_secret: *const [max_hash_len]u8,
) KeySet {
    return .{
        .level = level,
        .write = derivePacketKeys(KS, suite, own_secret[0..KS.hash_len]),
        .read = derivePacketKeys(KS, suite, peer_secret[0..KS.hash_len]),
    };
}

/// Derive QUIC `PacketKeys` from a TLS traffic secret using the schedule's
/// HKDF-Expand-Label and the QUIC labels (RFC 9001 §5.1). `secret` is the live
/// (hash-length) secret prefix.
fn derivePacketKeys(comptime KS: type, suite: CipherSuite, secret: []const u8) PacketKeys {
    const qsuite = suite.quicSuite();
    var sk: [KS.hash_len]u8 = undefined;
    @memcpy(&sk, secret[0..KS.hash_len]);
    var sb = KS.SecretBytes.init(sk);
    defer sb.wipe();

    var pk: PacketKeys = .{
        .suite = qsuite,
        .key = @as([quic_tls.max_key_len]u8, @splat(0)),
        .iv = undefined,
        .hp = @as([quic_tls.max_key_len]u8, @splat(0)),
    };
    const klen = qsuite.keyLen();
    const hlen = qsuite.hpKeyLen();
    // HKDF-Expand-Label with empty context and these bounded lengths never errs.
    KS.hkdfExpandLabel(&sb, "quic key", "", pk.key[0..klen]) catch unreachable;
    KS.hkdfExpandLabel(&sb, "quic iv", "", &pk.iv) catch unreachable;
    KS.hkdfExpandLabel(&sb, "quic hp", "", pk.hp[0..hlen]) catch unreachable;
    return pk;
}

// ---------------------------------------------------------------------------
// Handshake-message + extension helpers (raw, no record layer)
// ---------------------------------------------------------------------------

const server_cert_verify_context = "TLS 1.3, server CertificateVerify";
const client_cert_verify_context = "TLS 1.3, client CertificateVerify";
const cert_verify_input_max = 64 + server_cert_verify_context.len + 1 + max_hash_len;

/// CertificateVerify signed content (RFC 8446 §4.4.3): 64 0x20 bytes, the
/// context string, a 0x00 separator, then the transcript hash. Returns the
/// written prefix of `out`.
fn buildCertVerifyInput(out: *[cert_verify_input_max]u8, context: []const u8, transcript_hash: []const u8) []const u8 {
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..context.len], context);
    out[64 + context.len] = 0;
    const tail = 64 + context.len + 1;
    @memcpy(out[tail..][0..transcript_hash.len], transcript_hash);
    return out[0 .. tail + transcript_hash.len];
}

fn pickSuite(block: []const u8) ?CipherSuite {
    if (block.len % 2 != 0) return null;
    // Prefer AES-128-GCM, then AES-256-GCM, then ChaCha20-Poly1305.
    var has_aes256 = false;
    var has_chacha = false;
    var i: usize = 0;
    while (i + 1 < block.len) : (i += 2) {
        const v = std.mem.readInt(u16, block[i..][0..2], .big);
        if (v == @backingInt(CipherSuite.tls_aes_128_gcm_sha256)) return .tls_aes_128_gcm_sha256;
        if (v == @backingInt(CipherSuite.tls_aes_256_gcm_sha384)) has_aes256 = true;
        if (v == @backingInt(CipherSuite.tls_chacha20_poly1305_sha256)) has_chacha = true;
    }
    if (has_aes256) return .tls_aes_256_gcm_sha384;
    if (has_chacha) return .tls_chacha20_poly1305_sha256;
    return null;
}

fn validateGroupOrder(order: []const KeyExchangeGroup) Error!void {
    if (order.len == 0 or order.len > 8) return error.BadConfig;
    for (order, 0..) |g, i| {
        for (order[0..i]) |prior| if (prior == g) return error.BadConfig;
    }
}

fn suiteFromWire(v: u16) ?CipherSuite {
    return switch (v) {
        0x1301 => .tls_aes_128_gcm_sha256,
        0x1302 => .tls_aes_256_gcm_sha384,
        0x1303 => .tls_chacha20_poly1305_sha256,
        else => null,
    };
}

/// Hash `bytes` with the suite's transcript hash into `out`; returns the length.
fn hashFor(suite: CipherSuite, bytes: []const u8, out: *[max_hash_len]u8) usize {
    switch (suite) {
        .tls_aes_256_gcm_sha384 => {
            const d = Sha384.transcriptHash(bytes);
            @memcpy(out[0..d.len], &d);
            return d.len;
        },
        else => {
            const d = Sha256.transcriptHash(bytes);
            @memcpy(out[0..d.len], &d);
            return d.len;
        },
    }
}

fn clientOfferedSuite(block: []const u8, suite: CipherSuite) bool {
    if (block.len % 2 != 0) return false;
    var i: usize = 0;
    while (i + 1 < block.len) : (i += 2) {
        if (std.mem.readInt(u16, block[i..][0..2], .big) == @backingInt(suite)) return true;
    }
    return false;
}

/// RFC 8446 §4.2.9: whether `psk_key_exchange_modes` lists psk_dhe_ke (1).
fn pskModesAllowDhe(data: []const u8) bool {
    if (data.len < 2) return false;
    if (data.len != 1 + @as(usize, data[0])) return false;
    for (data[1..]) |mode| if (mode == 1) return true;
    return false;
}

/// Offset, within a raw ClientHello message (header included), of the
/// pre_shared_key extension body. Fully bounds-checked.
fn findPskExtensionBodyOffset(raw: []const u8) Error!usize {
    if (raw.len < 4 or raw[0] != @backingInt(HandshakeType.client_hello)) return error.BadHandshake;
    const body_len = (@as(usize, raw[1]) << 16) | (@as(usize, raw[2]) << 8) | raw[3];
    if (raw.len != 4 + body_len) return error.BadHandshake;
    var c = Cursor.init(raw[4..]);
    _ = try c.take(2);
    _ = try c.take(32);
    _ = try c.take(try c.readU8());
    _ = try c.take(try c.readU16());
    _ = try c.take(try c.readU8());
    const ext_len = try c.readU16();
    const ext_body_start = 4 + c.pos;
    const ext_body = try c.take(ext_len);
    if (c.remaining() != 0) return error.BadHandshake;
    var pos: usize = 0;
    while (pos < ext_body.len) {
        if (ext_body.len - pos < 4) return error.BadHandshake;
        const typ = std.mem.readInt(u16, ext_body[pos..][0..2], .big);
        const len = std.mem.readInt(u16, ext_body[pos + 2 ..][0..2], .big);
        const data_start = pos + 4;
        if (ext_body.len - data_start < len) return error.BadHandshake;
        if (typ == @backingInt(tls_extension.ExtensionType.pre_shared_key)) return ext_body_start + data_start;
        pos = data_start + len;
    }
    return error.MissingExtension;
}

/// Ticket lifetime (RFC 8446 §4.6.1): issued with a real clock, not in the
/// future, and within min(sealed lifetime, 7 days). Tickets without a sealed
/// lifetime (legacy formats) cannot prove their window and never resume.
fn ticketFresh(t: tls_resumption.OpenedTicket, now_s: i64) bool {
    const lifetime = t.ticket_lifetime orelse return false;
    const issued_s = @divTrunc(t.issued_unix_ms, 1000);
    if (issued_s <= 0 or now_s < issued_s) return false;
    return now_s - issued_s <= @as(i64, @min(lifetime, max_ticket_lifetime_seconds));
}

/// RFC 8446 §4.2.11.2 binder check: HMAC(finished_key(binder_key),
/// Hash(prefix ‖ truncated_ch)), constant-time compared.
fn binderMatches(comptime KS: type, allocator: Allocator, psk: []const u8, prefix: []const u8, truncated_ch: []const u8, binder: []const u8) bool {
    const expected = computeBinder(KS, allocator, psk, prefix, truncated_ch) catch return false;
    if (binder.len != KS.hash_len) return false;
    return std.crypto.timing_safe.eql([KS.hash_len]u8, expected, binder[0..KS.hash_len].*);
}

fn computeBinder(comptime KS: type, allocator: Allocator, psk: []const u8, prefix: []const u8, truncated_ch: []const u8) Error![KS.hash_len]u8 {
    if (psk.len != KS.hash_len) return error.BadState;
    var early = KS.earlySecret(psk);
    defer early.wipe();
    var binder_key = try KS.deriveSecret(&early, "res binder", &KS.emptyTranscriptHash());
    defer binder_key.wipe();
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(allocator);
    try joined.appendSlice(allocator, prefix);
    try joined.appendSlice(allocator, truncated_ch);
    const th = KS.transcriptHash(joined.items);
    return tls_finished.For(KS).verifyData(binder_key.declassify(), th);
}

/// client_early_traffic_secret = Derive-Secret(Early(psk), "c e traffic",
/// ClientHello) (RFC 8446 §7.1) → QUIC 0-RTT packet keys (RFC 9001 §5.1).
fn earlyTrafficKeys(comptime KS: type, suite: CipherSuite, psk: []const u8, client_hello: []const u8) Error!PacketKeys {
    if (psk.len != KS.hash_len) return error.BadState;
    var early = KS.earlySecret(psk);
    defer early.wipe();
    const th = KS.transcriptHash(client_hello);
    var traffic = try KS.deriveSecret(&early, "c e traffic", &th);
    defer traffic.wipe();
    var secret: [max_hash_len]u8 = @splat(0);
    defer secureZero(&secret);
    secret[0..KS.hash_len].* = traffic.declassify();
    return derivePacketKeys(KS, suite, secret[0..KS.hash_len]);
}

/// RFC 9001 §6.1 key update: next = HKDF-Expand-Label(secret, "quic ku", "",
/// Hash.length) with the suite's hash. `secret.len` selects SHA-256 (32) or
/// SHA-384 (48); `out` must be the same length.
pub fn nextTrafficSecret(secret: []const u8, out: []u8) void {
    std.debug.assert(out.len == secret.len);
    switch (secret.len) {
        Sha384.hash_len => {
            var sb = Sha384.SecretBytes.init(secret[0..Sha384.hash_len].*);
            defer sb.wipe();
            Sha384.hkdfExpandLabel(&sb, "quic ku", "", out[0..Sha384.hash_len]) catch unreachable;
        },
        Sha256.hash_len => {
            var sb = Sha256.SecretBytes.init(secret[0..Sha256.hash_len].*);
            defer sb.wipe();
            Sha256.hkdfExpandLabel(&sb, "quic ku", "", out[0..Sha256.hash_len]) catch unreachable;
        },
        else => unreachable,
    }
}

/// QUIC packet keys (`quic key` / `quic iv` / `quic hp`, RFC 9001 §5.1) from a
/// traffic secret whose length selects the hash (32 → SHA-256, 48 → SHA-384).
pub fn packetKeysFromSecret(qsuite: QuicCipherSuite, secret: []const u8) PacketKeys {
    const suite: CipherSuite = switch (qsuite) {
        .aes128gcm => .tls_aes_128_gcm_sha256,
        .aes256gcm => .tls_aes_256_gcm_sha384,
        .chacha20poly1305 => .tls_chacha20_poly1305_sha256,
    };
    return switch (secret.len) {
        Sha384.hash_len => derivePacketKeys(Sha384, suite, secret),
        else => derivePacketKeys(Sha256, suite, secret),
    };
}

/// RFC 9001 §6.1: a key update rolls the AEAD key and IV but never the
/// header-protection key.
pub fn keyUpdateDirection(prev: PacketKeys, next_secret: []const u8) PacketKeys {
    var pk = packetKeysFromSecret(prev.suite, next_secret);
    pk.hp = prev.hp;
    return pk;
}

/// Scan an encoded transport-parameters body for `stateless_reset_token`
/// (0x02, RFC 9000 §18.2). Returns null when absent or malformed.
pub fn findStatelessResetToken(tp: []const u8) ?[16]u8 {
    var pos: usize = 0;
    while (pos < tp.len) {
        const id = quic_frame.decodeVarInt(tp[pos..]) catch return null;
        pos += id.len;
        if (pos > tp.len) return null;
        const len = quic_frame.decodeVarInt(tp[pos..]) catch return null;
        pos += len.len;
        const n = std.math.cast(usize, len.value) orelse return null;
        if (n > tp.len - pos) return null;
        if (id.value == 0x02) {
            if (n != 16) return null;
            return tp[pos..][0..16].*;
        }
        pos += n;
    }
    return null;
}

fn writeHandshake(allocator: Allocator, out: *std.ArrayList(u8), typ: HandshakeType, body: []const u8) Error!void {
    if (body.len > 0x00ff_ffff) return error.BadHandshake;
    try out.append(allocator, @backingInt(typ));
    try appendU24(allocator, out, body.len);
    try out.appendSlice(allocator, body);
}

/// Upper bound on buffered, not-yet-consumed handshake bytes per encryption
/// level. A ClientHello (even with an X25519MLKEM768 share and ECH) or a
/// server flight with a full certificate chain is far below this; without it a
/// peer could declare a 16 MiB ClientHello and stream it in order, pinning
/// memory per connection before any authentication.
pub const max_handshake_buffer: usize = 64 * 1024;

/// Append peer CRYPTO bytes to a per-level buffer, refusing growth past
/// `max_handshake_buffer` and any declared message length that could not fit.
fn appendBounded(allocator: Allocator, buf: *std.ArrayList(u8), data: []const u8) Error!void {
    if (data.len > max_handshake_buffer - @min(buf.items.len, max_handshake_buffer)) return error.HandshakeTooLarge;
    try buf.appendSlice(allocator, data);
    if (buf.items.len >= 4) {
        const declared = (@as(usize, buf.items[1]) << 16) | (@as(usize, buf.items[2]) << 8) | buf.items[3];
        if (4 + declared > max_handshake_buffer) return error.HandshakeTooLarge;
    }
}

/// Parse one handshake message, or null when fewer than a whole message is
/// buffered. Fully bounds-checked: a declared length overrunning the buffer
/// returns null (wait for more) rather than reading out of bounds.
fn parseHandshakeMaybe(input: []const u8, offset: *usize) ?HandshakeMsg {
    if (input.len < 4) return null;
    const len = (@as(usize, input[1]) << 16) | (@as(usize, input[2]) << 8) | input[3];
    const body_end = 4 + len;
    if (input.len < body_end) return null;
    const typ: HandshakeType = @fromBackingInt(@intCast(input[0]));
    offset.* = body_end;
    return .{ .typ = typ, .body = input[4..body_end], .raw = input[0..body_end] };
}

fn appendU16(allocator: Allocator, out: *std.ArrayList(u8), value: u16) Allocator.Error!void {
    try out.append(allocator, @intCast(value >> 8));
    try out.append(allocator, @intCast(value & 0xff));
}

fn appendU24(allocator: Allocator, out: *std.ArrayList(u8), value: usize) Error!void {
    if (value > 0x00ff_ffff) return error.BadHandshake;
    try out.append(allocator, @intCast((value >> 16) & 0xff));
    try out.append(allocator, @intCast((value >> 8) & 0xff));
    try out.append(allocator, @intCast(value & 0xff));
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const remain = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..remain], list.items[n..]);
    list.shrinkRetainingCapacity(remain);
}

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(buf: []const u8) Cursor {
        return .{ .buf = buf };
    }
    fn remaining(self: Cursor) usize {
        return self.buf.len - self.pos;
    }
    fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.BadHandshake;
        const out = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }
    fn readU8(self: *Cursor) Error!u8 {
        return (try self.take(1))[0];
    }
    fn readU16(self: *Cursor) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }
};

fn osEntropy(buf: []u8) Error!void {
    // Central CSPRNG root covers every target (Linux, OpenBSD, Windows, macOS).
    @import("../crypto/random.zig").fillOsEntropy(buf) catch return error.Entropy;
}

fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

/// Coerce any error from the stepwise client methods (whose inferred error set
/// is broad) into a member of this module's `Error` set. The structured
/// failures we care about (handshake / finished / version / crypto) are passed
/// through; everything else collapses to `BadHandshake`, which the connection
/// driver maps to a fatal CONNECTION_CLOSE.
fn mapClientError(e: anyerror) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.BadState => error.BadState,
        error.BadHandshake => error.BadHandshake,
        error.UnsupportedGroup => error.UnsupportedGroup,
        error.UnsupportedCipherSuite => error.UnsupportedCipherSuite,
        error.ProtocolVersion => error.ProtocolVersion,
        error.MissingExtension => error.MissingExtension,
        error.FinishedMismatch => error.FinishedMismatch,
        error.NoCertificate => error.NoCertificate,
        error.SignatureFailed => error.SignatureFailed,
        error.Entropy => error.Entropy,
        error.HandshakeTooLarge => error.HandshakeTooLarge,
        error.ConnectionIdMismatch => error.ConnectionIdMismatch,
        error.DuplicateParameter => error.DuplicateParameter,
        else => error.BadHandshake,
    };
}

/// Scan a buffered Handshake-level CRYPTO flight for a complete Finished message
/// (handshake type 20). Returns true once every message up to and including the
/// Finished is fully present, so the client can process the flight in one pass.
/// Fully bounds-checked: a truncated trailing message returns false (wait).
fn flightHasFinished(buf: []const u8) bool {
    var pos: usize = 0;
    while (pos + 4 <= buf.len) {
        const len = (@as(usize, buf[pos + 1]) << 16) | (@as(usize, buf[pos + 2]) << 8) | buf[pos + 3];
        const end = pos + 4 + len;
        if (end > buf.len) return false; // message not fully buffered yet
        if (buf[pos] == @backingInt(HandshakeType.finished)) return true;
        pos = end;
    }
    return false;
}

/// Append server Handshake-level CRYPTO bytes to the client's flight buffer.
/// The client buffers the whole server flight (EE..Finished) before processing,
/// so — unlike `appendBounded`, which inspects only the leading message — every
/// message header already present is checked: any declared length whose end
/// would land past `max_handshake_buffer` is refused at once instead of being
/// streamed up to the cap.
fn appendFlightBounded(allocator: Allocator, buf: *std.ArrayList(u8), data: []const u8) Error!void {
    if (data.len > max_handshake_buffer - @min(buf.items.len, max_handshake_buffer)) return error.HandshakeTooLarge;
    try buf.appendSlice(allocator, data);
    var pos: usize = 0;
    while (pos + 4 <= buf.items.len) {
        const declared = (@as(usize, buf.items[pos + 1]) << 16) | (@as(usize, buf.items[pos + 2]) << 8) | buf.items[pos + 3];
        const end = pos + 4 + declared;
        if (end > max_handshake_buffer) return error.HandshakeTooLarge;
        if (end > buf.items.len) break;
        pos = end;
    }
}

/// A connection id held inline (QUIC v1 caps them at 20 bytes).
const CidBuf = struct {
    bytes: [quic_transport_params.max_connection_id_len]u8 = undefined,
    len: u8 = 0,

    fn init(cid: []const u8) Error!CidBuf {
        if (cid.len > quic_transport_params.max_connection_id_len) return error.Malformed;
        var out: CidBuf = .{ .len = @intCast(cid.len) };
        @memcpy(out.bytes[0..cid.len], cid);
        return out;
    }
    fn slice(self: *const CidBuf) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn cidEql(expected: *const CidBuf, got: ?[]const u8) bool {
    const g = got orelse return false;
    return std.mem.eql(u8, expected.slice(), g);
}

// ===========================================================================
// QUIC TLS 1.3 client — the symmetric loopback peer of `Server`
// ===========================================================================
//
// A client just sufficient to bring up a connection end to end: it emits a
// ClientHello (x25519 + supported_versions + ALPN + transport params),
// processes the server flight (ServerHello → install handshake keys; then the
// encrypted flight: EncryptedExtensions, Certificate, CertificateVerify,
// Finished), verifies the server CertificateVerify (Ed25519) and Finished, and
// emits the client Finished. It derives the same traffic secrets so both sides
// agree on the handshake AND application keys.
//
// It exposes the same socketless surface as `Server` — `feedCrypto(level,
// bytes)` / `takeFlight(level)` / `isComplete()` / `handshakeKeys()` /
// `applicationKeys()` — so the connection driver in `quic_conn.zig` can drive
// either role through one interface. The lower-level `start` / `feedInitial` /
// `feedHandshake` methods remain for direct stepwise tests.

/// Client-side handshake configuration. Mirrors the relevant `Server` fields.
pub const ClientConfig = struct {
    /// ALPN protocols to offer, in preference order (server chooses). QUIC
    /// requires ALPN; empty disables the extension (test only).
    alpn_protocols: []const []const u8 = &.{},
    /// The client's QUIC transport parameters, emitted in the ClientHello.
    transport_params: quic_transport_params.TransportParameters = .{},
    /// Deterministic X25519 seed (tests). When null a fresh seed is drawn from
    /// the OS at `init`.
    x25519_seed: ?[kx.X25519Kx.seed_len]u8 = null,
    /// Deterministic ClientHello random (tests). When null a fresh 32-byte
    /// random is drawn from the OS.
    client_random: ?[32]u8 = null,
    /// The Destination Connection ID of the client's very first Initial packet
    /// (before any Retry). When set, the client authenticates the server's
    /// connection-id transport parameters (RFC 9000 §7.3): the server MUST echo
    /// this as `original_destination_connection_id`, MUST send
    /// `initial_source_connection_id` equal to the SCID the driver reports via
    /// `Client.setServerInitialScid`, and MUST send `retry_source_connection_id`
    /// exactly when the driver reported a Retry via `Client.setRetryScid`.
    /// A connection driver always sets this; null skips the check and is only
    /// for socketless stepwise tests that have no packet layer.
    original_dcid: ?[]const u8 = null,
    /// Cipher suites offered, in order (server chooses).
    cipher_suites: []const CipherSuite = &default_client_suites,
    /// Send an X25519 key_share in the first ClientHello. False forces the
    /// server into a HelloRetryRequest (tests / HRR interop).
    offer_key_share: bool = true,
    /// Groups listed in `supported_groups` (RFC 8446 §4.2.7). This client can
    /// only complete X25519, so an HRR for any other group aborts.
    advertise_groups: []const tls_keyshare.NamedGroup = &.{.x25519},
    /// A session to resume (RFC 8446 §4.2.11); the ticket slice is borrowed.
    session: ?Session = null,
    /// Milliseconds since the session's ticket was received (§4.2.11.1).
    ticket_age_ms: u32 = 0,
    /// Offer 0-RTT with `session` (only when its ticket allows it, RFC 9001
    /// §4.6.1). The packet layer seals early data with `earlyDataWriteKeys`.
    offer_early_data: bool = false,
};

const default_client_suites = [_]CipherSuite{ .tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384, .tls_chacha20_poly1305_sha256 };

/// A resumable session learned from a NewSessionTicket (RFC 8446 §4.6.1).
/// `ticket` borrows the issuing `Client`'s storage (copy it to keep it).
pub const Session = struct {
    suite: CipherSuite,
    psk: [max_hash_len]u8,
    psk_len: u8,
    ticket: []const u8,
    ticket_age_add: u32,
    lifetime: u32,
    max_early_data_size: u32,
};

pub const Client = struct {
    allocator: Allocator,
    suite: ?CipherSuite = null,
    x25519_pair: kx.X25519Kx.KeyPair,
    client_random: [32]u8,
    leaf_pubkey: ?Ed25519.PublicKey = null,
    selected_alpn: ?[]const u8 = null,
    /// Owned copy of the selected ALPN bytes so `selectedAlpn()` stays valid
    /// after the EncryptedExtensions CRYPTO buffer it was parsed from is freed.
    selected_alpn_storage: [256]u8 = undefined,
    peer_params: ?quic_transport_params.TransportParameters = null,
    peer_params_storage: std.ArrayList(u8) = .empty,

    alpn_protocols: []const []const u8,
    transport_params: quic_transport_params.TransportParameters,

    transcript: std.ArrayList(u8) = .empty,
    done: bool = false,

    /// Driver state for the `feedCrypto`/`takeFlight` surface.
    started: bool = false,
    hs_done: bool = false,
    /// Reassembled server CRYPTO at the level we currently expect input on.
    recv_initial: std.ArrayList(u8) = .empty,
    recv_handshake: std.ArrayList(u8) = .empty,
    /// Client CRYPTO output buffered per level until the caller drains it.
    out_initial: std.ArrayList(u8) = .empty,
    out_handshake: std.ArrayList(u8) = .empty,

    client_hs_secret: [max_hash_len]u8 = @splat(0),
    server_hs_secret: [max_hash_len]u8 = @splat(0),
    client_ap_secret: [max_hash_len]u8 = @splat(0),
    server_ap_secret: [max_hash_len]u8 = @splat(0),
    handshake_secret: [max_hash_len]u8 = @splat(0),

    handshake_keys: ?KeySet = null,
    application_keys: ?KeySet = null,

    /// RFC 9000 §7.3 connection-id authentication inputs. `expected_odcid`
    /// non-null turns the check on; the others are reported by the driver as
    /// it observes server packets.
    expected_odcid: ?CidBuf = null,
    server_initial_scid: ?CidBuf = null,
    retry_scid: ?CidBuf = null,

    cipher_suites: []const CipherSuite = &default_client_suites,
    offer_key_share: bool = true,
    advertise_groups: []const tls_keyshare.NamedGroup = &.{.x25519},
    session: ?Session = null,
    ticket_age_ms: u32 = 0,
    offer_early_data: bool = false,

    /// HelloRetryRequest handling (RFC 8446 §4.1.4).
    hrr_received: bool = false,
    /// PSK / 0-RTT state.
    psk_offered: bool = false,
    psk_accepted: bool = false,
    early_data_offered: bool = false,
    early_data_accepted: bool = false,
    early_write_keys: ?PacketKeys = null,
    /// Server authentication messages observed in a full handshake.
    saw_certificate: bool = false,
    saw_certificate_verify: bool = false,
    /// resumption_master_secret (RFC 8446 §7.1) and the last ticket received.
    resumption_master_secret: [max_hash_len]u8 = @splat(0),
    recv_application: std.ArrayList(u8) = .empty,
    ticket_storage: std.ArrayList(u8) = .empty,
    received_session: ?Session = null,

    /// Construct a client from a `ClientConfig` (the public path).
    pub fn initConfig(allocator: Allocator, config: ClientConfig) Error!Client {
        var seed: [kx.X25519Kx.seed_len]u8 = undefined;
        if (config.x25519_seed) |s| {
            seed = s;
        } else {
            try osEntropy(&seed);
        }
        defer secureZero(&seed);
        var random: [32]u8 = undefined;
        if (config.client_random) |r| {
            random = r;
        } else {
            try osEntropy(&random);
        }
        const expected_odcid: ?CidBuf = if (config.original_dcid) |d| try CidBuf.init(d) else null;
        return .{
            .allocator = allocator,
            .x25519_pair = kx.X25519Kx.generateDeterministic(seed) catch return error.BadState,
            .client_random = random,
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
            .expected_odcid = expected_odcid,
            .cipher_suites = config.cipher_suites,
            .offer_key_share = config.offer_key_share,
            .advertise_groups = config.advertise_groups,
            .session = config.session,
            .ticket_age_ms = config.ticket_age_ms,
            .offer_early_data = config.offer_early_data,
        };
    }

    /// Whether the server accepted our PSK (resumed handshake).
    pub fn isResumed(self: *const Client) bool {
        return self.psk_accepted;
    }

    /// Whether the server accepted 0-RTT (EncryptedExtensions.early_data).
    pub fn earlyDataAccepted(self: *const Client) bool {
        return self.early_data_accepted;
    }

    /// The 0-RTT write keys (client early traffic), when early data was offered.
    pub fn earlyDataWriteKeys(self: *const Client) ?PacketKeys {
        return self.early_write_keys;
    }

    /// The session from the most recent NewSessionTicket, if any. The ticket
    /// slice is valid until the next ticket or `deinit`.
    pub fn resumptionSession(self: *const Client) ?Session {
        return self.received_session;
    }

    /// The server's `stateless_reset_token` transport parameter (RFC 9000
    /// §10.3 / §18.2), once EncryptedExtensions was processed.
    pub fn peerStatelessResetToken(self: *const Client) ?[16]u8 {
        if (self.peer_params == null) return null;
        return findStatelessResetToken(self.peer_params_storage.items);
    }

    /// Record the Source Connection ID of the first server packet the driver
    /// accepted (RFC 9000 §7.2). The server's `initial_source_connection_id`
    /// transport parameter must equal it. Must be called before the server's
    /// EncryptedExtensions are processed; later calls with a different value
    /// are refused so the authenticated id cannot be swapped.
    pub fn setServerInitialScid(self: *Client, scid: []const u8) Error!void {
        const cid = try CidBuf.init(scid);
        if (self.server_initial_scid) |prev| {
            if (!std.mem.eql(u8, prev.slice(), cid.slice())) return error.ConnectionIdMismatch;
            return;
        }
        if (self.peer_params != null) return error.BadState;
        self.server_initial_scid = cid;
    }

    /// Record that the client processed a Retry whose SCID was `scid`
    /// (RFC 9000 §17.2.5). The server must then echo it as
    /// `retry_source_connection_id`; without a call, that parameter must be
    /// absent. At most one Retry is accepted per connection.
    pub fn setRetryScid(self: *Client, scid: []const u8) Error!void {
        if (self.retry_scid != null or self.peer_params != null) return error.BadState;
        self.retry_scid = try CidBuf.init(scid);
    }

    /// RFC 9000 §7.3 — authenticate the server's connection-id transport
    /// parameters against what this client observed. A no-op when the driver
    /// did not configure `original_dcid` (stepwise tests only).
    fn authenticateConnectionIds(self: *const Client, params: quic_transport_params.TransportParameters) Error!void {
        const odcid = self.expected_odcid orelse return;
        if (!cidEql(&odcid, params.original_destination_connection_id)) return error.ConnectionIdMismatch;
        const iscid = self.server_initial_scid orelse return error.ConnectionIdMismatch;
        if (!cidEql(&iscid, params.initial_source_connection_id)) return error.ConnectionIdMismatch;
        if (self.retry_scid) |rs| {
            if (!cidEql(&rs, params.retry_source_connection_id)) return error.ConnectionIdMismatch;
        } else if (params.retry_source_connection_id != null) {
            return error.ConnectionIdMismatch;
        }
    }

    fn init(
        allocator: Allocator,
        seed: [kx.X25519Kx.seed_len]u8,
        alpn_protocols: []const []const u8,
        transport_params: quic_transport_params.TransportParameters,
    ) !Client {
        return .{
            .allocator = allocator,
            .x25519_pair = try kx.X25519Kx.generateDeterministic(seed),
            .client_random = @as([32]u8, @splat(0x11)),
            .alpn_protocols = alpn_protocols,
            .transport_params = transport_params,
        };
    }

    pub fn deinit(self: *Client) void {
        self.x25519_pair.wipe();
        secureZero(&self.handshake_secret);
        secureZero(&self.client_hs_secret);
        secureZero(&self.server_hs_secret);
        secureZero(&self.client_ap_secret);
        secureZero(&self.server_ap_secret);
        secureZero(&self.resumption_master_secret);
        if (self.early_write_keys) |*k| secureZero(std.mem.asBytes(k));
        if (self.received_session) |*s| secureZero(&s.psk);
        self.recv_application.deinit(self.allocator);
        self.ticket_storage.deinit(self.allocator);
        self.transcript.deinit(self.allocator);
        self.peer_params_storage.deinit(self.allocator);
        self.recv_initial.deinit(self.allocator);
        self.recv_handshake.deinit(self.allocator);
        self.out_initial.deinit(self.allocator);
        self.out_handshake.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isComplete(self: *const Client) bool {
        return self.done;
    }

    pub fn selectedAlpn(self: *const Client) ?[]const u8 {
        return self.selected_alpn;
    }

    pub fn peerTransportParams(self: *const Client) ?quic_transport_params.TransportParameters {
        return self.peer_params;
    }

    pub fn cipherName(self: *const Client) ?[]const u8 {
        const s = self.suite orelse return null;
        return s.name();
    }

    pub fn handshakeKeys(self: *const Client) ?KeySet {
        return self.handshake_keys;
    }

    pub fn applicationKeys(self: *const Client) ?KeySet {
        return self.application_keys;
    }

    /// The 1-RTT (application) traffic secrets used to seed key updates
    /// (RFC 9001 §6). `write` is this endpoint's own secret (client_ap_secret),
    /// `read` is the peer's (server_ap_secret). Pure read-only accessor.
    pub fn appTrafficSecrets(self: *const Client) ?AppTrafficSecrets {
        if (self.application_keys == null) return null;
        const suite = self.suite orelse return null;
        return .{
            .write = self.client_ap_secret,
            .read = self.server_ap_secret,
            .hash_len = @intCast(suite.hashLen()),
            .suite = suite.quicSuite(),
        };
    }

    /// Produce the ClientHello into the Initial output buffer if not yet sent.
    /// The connection driver calls this once before its first send so a
    /// `takeFlight(.initial)` yields the ClientHello CRYPTO bytes.
    pub fn startHandshake(self: *Client) Error!void {
        if (self.started) return;
        var ch = try self.start();
        defer ch.deinit(self.allocator);
        try self.out_initial.appendSlice(self.allocator, ch.items);
        self.started = true;
    }

    /// Feed reassembled server CRYPTO bytes for `level`. Initial carries the
    /// ServerHello; Handshake carries EE/Certificate/CertificateVerify/Finished.
    /// Drives the handshake forward, buffering the client Finished into the
    /// Handshake output buffer once the server flight is verified.
    pub fn feedCrypto(self: *Client, level: EncryptionLevel, data: []const u8) Error!void {
        if (!self.started) try self.startHandshake();
        switch (level) {
            .initial => {
                if (self.handshake_keys != null) return; // ServerHello already done
                try appendBounded(self.allocator, &self.recv_initial, data);
                // Possibly HelloRetryRequest then ServerHello (RFC 8446 §4.1.4).
                while (self.handshake_keys == null) {
                    var off: usize = 0;
                    if (parseHandshakeMaybe(self.recv_initial.items, &off) == null) return;
                    self.feedInitial(self.recv_initial.items[0..off]) catch |e| return mapClientError(e);
                    consumePrefix(&self.recv_initial, off);
                }
            },
            .handshake => {
                if (self.hs_done) return;
                try appendFlightBounded(self.allocator, &self.recv_handshake, data);
                // Need the entire server flight (through Finished) buffered. Scan
                // for a Finished message; until it arrives, wait for more.
                if (!flightHasFinished(self.recv_handshake.items)) return;
                var cfin = self.feedHandshake(self.recv_handshake.items) catch |e| return mapClientError(e);
                defer cfin.deinit(self.allocator);
                try self.out_handshake.appendSlice(self.allocator, cfin.items);
                self.recv_handshake.clearRetainingCapacity();
                self.hs_done = true;
            },
            .application => {
                // Post-handshake messages (RFC 8446 §4.6): only
                // NewSessionTicket is valid from a QUIC server (RFC 9001 §4.1.3
                // forbids KeyUpdate; this client never requests auth).
                if (!self.done) return error.BadState;
                try appendBounded(self.allocator, &self.recv_application, data);
                while (true) {
                    var off: usize = 0;
                    const msg = parseHandshakeMaybe(self.recv_application.items, &off) orelse return;
                    if (msg.typ != .new_session_ticket) return error.BadHandshake;
                    self.processNewSessionTicket(msg.body) catch |e| return mapClientError(e);
                    consumePrefix(&self.recv_application, off);
                }
            },
        }
    }

    /// RFC 8446 §4.6.1: derive the ticket PSK from the resumption master secret
    /// and keep the most recent ticket.
    fn processNewSessionTicket(self: *Client, body: []const u8) !void {
        const nst = tls_session_ticket.parse(body) catch return error.BadHandshake;
        const suite = self.suite orelse return error.BadState;
        var max_early: u32 = 0;
        var it = tls_extension.Iterator.init(nst.extensions);
        while (try it.next()) |ext| {
            if (ext.ext_type == @backingInt(tls_extension.ExtensionType.early_data)) {
                if (ext.data.len != 4) return error.BadHandshake;
                max_early = std.mem.readInt(u32, ext.data[0..4], .big);
                // RFC 9001 §4.6.1: any other value is a PROTOCOL_VIOLATION.
                if (max_early != quic_max_early_data_size) return error.BadHandshake;
            }
        }
        if (nst.ticket_lifetime == 0 or nst.ticket.len == 0) return; // §4.6.1: discard
        if (nst.ticket_lifetime > max_ticket_lifetime_seconds) return error.BadHandshake;
        var s: Session = .{
            .suite = suite,
            .psk = @splat(0),
            .psk_len = @intCast(suite.hashLen()),
            .ticket = &.{},
            .ticket_age_add = nst.ticket_age_add,
            .lifetime = nst.ticket_lifetime,
            .max_early_data_size = max_early,
        };
        const hl = suite.hashLen();
        switch (suite) {
            .tls_aes_256_gcm_sha384 => {
                var rms = Sha384.SecretBytes.init(self.resumption_master_secret[0..48].*);
                defer rms.wipe();
                try Sha384.hkdfExpandLabel(&rms, "resumption", nst.ticket_nonce, s.psk[0..hl]);
            },
            else => {
                var rms = Sha256.SecretBytes.init(self.resumption_master_secret[0..32].*);
                defer rms.wipe();
                try Sha256.hkdfExpandLabel(&rms, "resumption", nst.ticket_nonce, s.psk[0..hl]);
            },
        }
        self.ticket_storage.clearRetainingCapacity();
        try self.ticket_storage.appendSlice(self.allocator, nst.ticket);
        s.ticket = self.ticket_storage.items;
        if (self.received_session) |*old| secureZero(&old.psk);
        self.received_session = s;
    }

    /// Take ownership of all buffered client CRYPTO bytes at `level`.
    pub fn takeFlight(self: *Client, level: EncryptionLevel) Error![]u8 {
        const buf = switch (level) {
            .initial => &self.out_initial,
            .handshake => &self.out_handshake,
            .application => return self.allocator.alloc(u8, 0),
        };
        return buf.toOwnedSlice(self.allocator);
    }

    /// Build the ClientHello CRYPTO bytes (Initial level), fold it into the
    /// transcript, and (when 0-RTT is offered) derive the early write keys.
    fn start(self: *Client) !std.ArrayList(u8) {
        var out = try self.buildClientHello();
        errdefer out.deinit(self.allocator);
        try self.transcript.appendSlice(self.allocator, out.items);
        if (self.early_data_offered) {
            const s = self.session.?;
            self.early_write_keys = switch (s.suite) {
                .tls_aes_256_gcm_sha384 => try earlyTrafficKeys(Sha384, s.suite, s.psk[0..s.psk_len], self.transcript.items),
                else => try earlyTrafficKeys(Sha256, s.suite, s.psk[0..s.psk_len], self.transcript.items),
            };
        }
        return out;
    }

    /// Encode a ClientHello. After an HRR this is ClientHello2: it always
    /// carries the X25519 share and never offers early data (RFC 8446 §4.1.2).
    /// A resumable `session` is offered with psk_dhe_ke and a binder computed
    /// over the transcript so far ‖ the truncated hello (§4.2.11.2).
    fn buildClientHello(self: *Client) !std.ArrayList(u8) {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU16(self.allocator, &body, legacy_version);
        try body.appendSlice(self.allocator, &self.client_random);
        try body.append(self.allocator, 0); // legacy_session_id: empty

        if (self.cipher_suites.len == 0 or self.cipher_suites.len > 8) return error.BadState;
        try appendU16(self.allocator, &body, @intCast(self.cipher_suites.len * 2));
        for (self.cipher_suites) |s| try appendU16(self.allocator, &body, @backingInt(s));

        try body.append(self.allocator, 1); // legacy_compression_methods len
        try body.append(self.allocator, 0); // null

        // A session is usable only for a suite we offer (§4.2.11).
        var psk_session: ?Session = null;
        if (self.session) |s| {
            for (self.cipher_suites) |cs| if (cs == s.suite and s.psk_len == s.suite.hashLen() and s.ticket.len > 0) {
                psk_session = s;
            };
        }
        self.psk_offered = psk_session != null;
        self.early_data_offered = psk_session != null and self.offer_early_data and !self.hrr_received and
            psk_session.?.max_early_data_size == quic_max_early_data_size;

        var ext_storage: [4096]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        var sv_buf: [8]u8 = undefined;
        try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildClient(&sv_buf, &.{tls_supported_versions.tls13}));
        if (self.advertise_groups.len > 0) {
            if (self.advertise_groups.len > 16) return error.BadState;
            var groups: [16]supported_groups.NamedGroup = undefined;
            for (self.advertise_groups, 0..) |g, i| groups[i] = supported_groups.NamedGroup.fromInt(g.toInt());
            var sg_buf: [64]u8 = undefined;
            try ext_builder.addTyped(.supported_groups, supported_groups.build(&sg_buf, groups[0..self.advertise_groups.len]) catch return error.BadState);
        }
        var ks_inner: [64]u8 = undefined;
        const ks = if (self.offer_key_share or self.hrr_received)
            try tls_keyshare.buildClientShares(&ks_inner, &.{.{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key }})
        else
            try tls_keyshare.buildClientShares(&ks_inner, &.{});
        try ext_builder.addTyped(.key_share, ks);
        if (self.alpn_protocols.len > 0) {
            var alpn_buf: [260]u8 = undefined;
            var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
            for (self.alpn_protocols) |p| try alpn_builder.add(p);
            try ext_builder.addTyped(.alpn, try alpn_builder.finish());
        }
        var tp_body: std.ArrayList(u8) = .empty;
        defer tp_body.deinit(self.allocator);
        try quic_transport_params.encode(&tp_body, self.allocator, self.transport_params);
        try ext_builder.add(quic_transport_parameters_ext, tp_body.items);
        var binder_len: usize = 0;
        if (psk_session) |s| {
            if (self.early_data_offered) try ext_builder.addTyped(.early_data, "");
            try ext_builder.addTyped(.psk_key_exchange_modes, &.{ 1, 1 }); // [psk_dhe_ke]
            // pre_shared_key MUST be last (§4.2.11); binder patched below.
            binder_len = s.psk_len;
            const zero_binder: [max_hash_len]u8 = @splat(0);
            var psk_buf: [2048]u8 = undefined;
            const psk_ext = tls_psk.buildClientPsk(&psk_buf, &.{.{
                .identity = s.ticket,
                .obfuscated_ticket_age = tls_session_ticket.obfuscatedAge(self.ticket_age_ms, s.ticket_age_add),
            }}, &.{zero_binder[0..binder_len]}) catch return error.BadState;
            try ext_builder.addTyped(.pre_shared_key, psk_ext);
        }
        try body.appendSlice(self.allocator, try ext_builder.finish());

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try writeHandshake(self.allocator, &out, .client_hello, body.items);
        if (psk_session) |s| {
            // binders list = u16 len ‖ u8 len ‖ binder, at the very end.
            const truncated_len = out.items.len - (2 + 1 + binder_len);
            const binder_slot = out.items[out.items.len - binder_len ..];
            switch (s.suite) {
                .tls_aes_256_gcm_sha384 => binder_slot[0..48].* = try computeBinder(Sha384, self.allocator, s.psk[0..48], self.transcript.items, out.items[0..truncated_len]),
                else => binder_slot[0..32].* = try computeBinder(Sha256, self.allocator, s.psk[0..32], self.transcript.items, out.items[0..truncated_len]),
            }
        }
        return out;
    }

    /// Process one server Initial-level message: a HelloRetryRequest (answered
    /// with ClientHello2) or the ServerHello.
    fn feedInitial(self: *Client, data: []const u8) !void {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(data, &off) orelse return error.BadHandshake;
        if (msg.typ != .server_hello) return error.BadHandshake;
        if (msg.body.len >= 34 and std.mem.eql(u8, msg.body[2..34], &hello_retry_request_random)) {
            return self.handleHelloRetryRequest(msg.body, msg.raw);
        }
        try self.transcript.appendSlice(self.allocator, msg.raw);
        const shared = try self.parseServerHello(msg.body);
        try self.installHandshakeKeys(shared);
    }

    /// RFC 8446 §4.1.4: validate the HRR, restart the transcript as
    /// message_hash(CH1) ‖ HRR, and queue ClientHello2.
    fn handleHelloRetryRequest(self: *Client, body: []const u8, raw: []const u8) !void {
        if (self.hrr_received) return error.BadHandshake; // a second HRR
        var c = Cursor.init(body);
        if (try c.readU16() != legacy_version) return error.ProtocolVersion;
        _ = try c.take(32);
        if ((try c.take(try c.readU8())).len != 0) return error.BadHandshake;
        const suite = suiteFromWire(try c.readU16()) orelse return error.UnsupportedCipherSuite;
        var offered = false;
        for (self.cipher_suites) |s| if (s == suite) {
            offered = true;
        };
        if (!offered) return error.UnsupportedCipherSuite;
        if (try c.readU8() != 0) return error.BadHandshake;
        const ext_block = try c.take(try c.readU16());
        if (c.remaining() != 0) return error.BadHandshake;
        var group: ?u16 = null;
        var tls13 = false;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            if (ext.ext_type == @backingInt(tls_extension.ExtensionType.key_share)) {
                if (ext.data.len != 2) return error.BadHandshake;
                group = std.mem.readInt(u16, ext.data[0..2], .big);
            } else if (ext.ext_type == @backingInt(tls_extension.ExtensionType.supported_versions)) {
                if (ext.data.len != 2 or std.mem.readInt(u16, ext.data[0..2], .big) != tls_supported_versions.tls13) return error.ProtocolVersion;
                tls13 = true;
            }
        }
        if (!tls13) return error.ProtocolVersion;
        // We can only complete X25519; it must be advertised and not already
        // shared (an HRR naming a group we sent a share for is illegal).
        const g = group orelse return error.BadHandshake;
        if (g != tls_keyshare.NamedGroup.x25519.toInt() or self.offer_key_share) return error.UnsupportedGroup;
        var advertised = false;
        for (self.advertise_groups) |a| if (a.toInt() == g) {
            advertised = true;
        };
        if (!advertised) return error.UnsupportedGroup;

        self.suite = suite;
        self.hrr_received = true;
        var digest: [max_hash_len]u8 = undefined;
        const hlen = hashFor(suite, self.transcript.items, &digest);
        self.transcript.clearRetainingCapacity();
        try self.transcript.appendSlice(self.allocator, &.{ @backingInt(HandshakeType.message_hash), 0, 0, @intCast(hlen) });
        try self.transcript.appendSlice(self.allocator, digest[0..hlen]);
        try self.transcript.appendSlice(self.allocator, raw);
        if (self.early_write_keys) |*k| secureZero(std.mem.asBytes(k));
        self.early_write_keys = null;

        var ch2 = try self.buildClientHello();
        defer ch2.deinit(self.allocator);
        try self.transcript.appendSlice(self.allocator, ch2.items);
        try self.out_initial.appendSlice(self.allocator, ch2.items);
    }

    /// Process the server's Handshake-level flight (EE, Cert, CertVerify,
    /// Finished). Verifies CertificateVerify + Finished. Returns the client
    /// Finished CRYPTO bytes (Handshake level).
    fn feedHandshake(self: *Client, data: []const u8) !std.ArrayList(u8) {
        var pos: usize = 0;
        var saw_ee = false;
        while (true) {
            var off: usize = 0;
            const msg = parseHandshakeMaybe(data[pos..], &off) orelse break;
            switch (msg.typ) {
                .encrypted_extensions => {
                    if (saw_ee) return error.BadHandshake;
                    saw_ee = true;
                    try self.parseEncryptedExtensions(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                },
                .certificate => {
                    // RFC 8446 §2.2: a PSK handshake carries no Certificate.
                    if (self.psk_accepted or !saw_ee or self.saw_certificate) return error.BadHandshake;
                    try self.parseCertificate(msg.body);
                    self.saw_certificate = true;
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                },
                .certificate_verify => {
                    if (!self.saw_certificate or self.saw_certificate_verify) return error.BadHandshake;
                    try self.verifyCertificateVerify(msg.body);
                    self.saw_certificate_verify = true;
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                },
                .finished => {
                    // RFC 8446 §4.4: a full handshake MUST authenticate the
                    // server (Certificate + CertificateVerify) before Finished.
                    if (!saw_ee) return error.BadHandshake;
                    if (!self.psk_accepted and !self.saw_certificate_verify) return error.BadHandshake;
                    if (!self.finishedVerify(&self.server_hs_secret, msg.body)) return error.FinishedMismatch;
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    // Application keys derive over CH..server Finished (now).
                    try self.installApplicationKeys();
                    pos += off;
                    break;
                },
                else => return error.BadHandshake,
            }
            pos += off;
        }

        // Build the client Finished over the transcript through server Finished.
        var vd_buf: [max_hash_len]u8 = undefined;
        const vd_len = self.finishedVerifyData(&self.client_hs_secret, &vd_buf);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try writeHandshake(self.allocator, &out, .finished, vd_buf[0..vd_len]);
        try self.deriveResumptionMasterSecret(out.items);
        self.done = true;
        return out;
    }

    /// resumption_master_secret = Derive-Secret(Master, "res master",
    /// Hash(ClientHello..client Finished)) (RFC 8446 §7.1).
    fn deriveResumptionMasterSecret(self: *Client, client_finished: []const u8) !void {
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(self.allocator);
        try joined.appendSlice(self.allocator, self.transcript.items);
        try joined.appendSlice(self.allocator, client_finished);
        switch (self.suite.?) {
            .tls_aes_256_gcm_sha384 => try rmsT(Sha384, &self.handshake_secret, joined.items, &self.resumption_master_secret),
            else => try rmsT(Sha256, &self.handshake_secret, joined.items, &self.resumption_master_secret),
        }
    }

    fn parseServerHello(self: *Client, body: []const u8) ![32]u8 {
        var c = Cursor.init(body);
        if (try c.readU16() != legacy_version) return error.ProtocolVersion;
        _ = try c.take(32); // server random
        _ = try c.take(try c.readU8()); // session id echo
        const suite = suiteFromWire(try c.readU16()) orelse return error.UnsupportedCipherSuite;
        var offered = false;
        for (self.cipher_suites) |s| if (s == suite) {
            offered = true;
        };
        if (!offered) return error.UnsupportedCipherSuite;
        // RFC 8446 §4.1.4: the ServerHello suite must match the HRR's.
        if (self.hrr_received and self.suite != suite) return error.BadHandshake;
        self.suite = suite;
        _ = try c.readU8(); // compression
        const ext_block = try c.take(try c.readU16());
        var it = tls_extension.Iterator.init(ext_block);
        var peer_share: ?[]const u8 = null;
        while (try it.next()) |ext| {
            if (ext.ext_type == @backingInt(tls_extension.ExtensionType.key_share)) {
                const entry = try tls_keyshare.parseServerShare(ext.data);
                if (entry.group == .x25519 and entry.key_exchange.len == kx.X25519Kx.public_len) peer_share = entry.key_exchange;
            } else if (ext.ext_type == @backingInt(tls_extension.ExtensionType.pre_shared_key)) {
                const idx = tls_psk.parseServerPsk(ext.data) catch return error.BadHandshake;
                // We offer exactly one identity; its suite must be negotiated.
                if (!self.psk_offered or idx != 0 or self.session.?.suite != suite) return error.BadHandshake;
                self.psk_accepted = true;
            }
        }
        const peer = peer_share orelse return error.UnsupportedGroup;
        var peer_pub: kx.PublicKey = undefined;
        @memcpy(&peer_pub, peer);
        var secret = try kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer_pub);
        defer secret.wipe();
        return secret.declassify();
    }

    fn parseEncryptedExtensions(self: *Client, body: []const u8) !void {
        var it = tls_extension.Iterator.init(try tls_extension.unwrap(body));
        var have_params = false;
        while (try it.next()) |ext| {
            if (ext.ext_type == @backingInt(tls_extension.ExtensionType.alpn)) {
                var names = tls_alpn.Iterator.fromBlock(ext.data) catch continue;
                if (names.next() catch null) |proto| {
                    if (proto.len <= self.selected_alpn_storage.len) {
                        @memcpy(self.selected_alpn_storage[0..proto.len], proto);
                        self.selected_alpn = self.selected_alpn_storage[0..proto.len];
                    }
                }
            } else if (ext.ext_type == @backingInt(tls_extension.ExtensionType.early_data)) {
                // RFC 8446 §4.2.10: only valid if we offered it and resumed.
                if (ext.data.len != 0 or !self.early_data_offered or !self.psk_accepted) return error.BadHandshake;
                self.early_data_accepted = true;
            } else if (ext.ext_type == quic_transport_parameters_ext) {
                // A second copy of the extension is a TLS decode error, not a
                // chance to overwrite the authenticated parameters.
                if (have_params) return error.BadHandshake;
                have_params = true;
                self.peer_params_storage.clearRetainingCapacity();
                try self.peer_params_storage.appendSlice(self.allocator, ext.data);
                const params = try quic_transport_params.decode(self.peer_params_storage.items);
                try self.authenticateConnectionIds(params);
                self.peer_params = params;
            }
        }
        // RFC 9001 §8.2: the server MUST send quic_transport_parameters.
        if (!have_params) return error.MissingExtension;
    }

    fn parseCertificate(self: *Client, body: []const u8) !void {
        var c = Cursor.init(body);
        const ctx = try c.take(try c.readU8());
        if (ctx.len != 0) return error.BadHandshake;
        const list_len = (@as(usize, (try c.take(1))[0]) << 16) | (@as(usize, (try c.take(1))[0]) << 8) | (try c.take(1))[0];
        const list = try c.take(list_len);
        var lc = Cursor.init(list);
        const der_len = (@as(usize, (try lc.take(1))[0]) << 16) | (@as(usize, (try lc.take(1))[0]) << 8) | (try lc.take(1))[0];
        const der = try lc.take(der_len);
        self.leaf_pubkey = try ed25519KeyFromCert(der);
    }

    fn verifyCertificateVerify(self: *Client, body: []const u8) !void {
        if (body.len < 4) return error.BadHandshake;
        const scheme = std.mem.readInt(u16, body[0..2], .big);
        const sig_len = std.mem.readInt(u16, body[2..4], .big);
        if (body.len != 4 + @as(usize, sig_len)) return error.BadHandshake;
        const sig = body[4..];
        if (scheme != @backingInt(tls_signature_scheme.SignatureScheme.ed25519)) return error.BadHandshake;
        if (sig.len != Ed25519.Signature.encoded_length) return error.BadHandshake;
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, server_cert_verify_context, th[0..th_len]);
        const pk = self.leaf_pubkey orelse return error.BadHandshake;
        var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
        @memcpy(&sig_bytes, sig[0..Ed25519.Signature.encoded_length]);
        Ed25519.Signature.fromBytes(sig_bytes).verify(input, pk) catch return error.FinishedMismatch;
    }

    fn installHandshakeKeys(self: *Client, shared: [32]u8) !void {
        const suite = self.suite.?;
        switch (suite) {
            .tls_aes_256_gcm_sha384 => try self.installHandshakeKeysT(Sha384, suite, shared),
            else => try self.installHandshakeKeysT(Sha256, suite, shared),
        }
    }

    fn installHandshakeKeysT(self: *Client, comptime KS: type, suite: CipherSuite, shared: [32]u8) !void {
        const psk: []const u8 = if (self.psk_accepted) blk: {
            const s = self.session.?;
            if (s.psk_len != KS.hash_len) return error.BadHandshake;
            break :blk s.psk[0..KS.hash_len];
        } else "";
        var early = KS.earlySecret(psk);
        defer early.wipe();
        var handshake = try KS.handshakeSecret(&early, &shared);
        defer handshake.wipe();
        self.handshake_secret[0..KS.hash_len].* = handshake.declassify();
        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.handshakeTrafficSecrets(&handshake, &th);
        defer traffic.wipe();
        self.client_hs_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_hs_secret[0..KS.hash_len].* = traffic.server.declassify();
        // From the client's view, write = client secret, read = server secret.
        self.handshake_keys = installKeys(KS, .handshake, suite, &self.client_hs_secret, &self.server_hs_secret);
    }

    fn installApplicationKeys(self: *Client) !void {
        const suite = self.suite.?;
        switch (suite) {
            .tls_aes_256_gcm_sha384 => try self.installApplicationKeysT(Sha384, suite),
            else => try self.installApplicationKeysT(Sha256, suite),
        }
    }

    fn installApplicationKeysT(self: *Client, comptime KS: type, suite: CipherSuite) !void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.handshake_secret[0..KS.hash_len]);
        var hs = KS.SecretBytes.init(sk);
        defer hs.wipe();
        var master = try KS.masterSecret(&hs);
        defer master.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.applicationTrafficSecrets(&master, &th);
        defer traffic.wipe();
        self.client_ap_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_ap_secret[0..KS.hash_len].* = traffic.server.declassify();
        self.application_keys = installKeys(KS, .application, suite, &self.client_ap_secret, &self.server_ap_secret);
    }

    fn transcriptHash(self: *const Client, out: *[max_hash_len]u8) usize {
        return switch (self.suite.?) {
            .tls_aes_256_gcm_sha384 => blk: {
                const d = Sha384.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                break :blk d.len;
            },
            else => blk: {
                const d = Sha256.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                break :blk d.len;
            },
        };
    }

    fn finishedVerify(self: *const Client, base_key: *const [max_hash_len]u8, received: []const u8) bool {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        return switch (self.suite.?) {
            .tls_aes_256_gcm_sha384 => tls_finished.Sha384F.verify(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*, received),
            else => tls_finished.Sha256F.verify(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*, received),
        };
    }

    fn finishedVerifyData(self: *const Client, base_key: *const [max_hash_len]u8, out: *[max_hash_len]u8) usize {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        switch (self.suite.?) {
            .tls_aes_256_gcm_sha384 => {
                const v = tls_finished.Sha384F.verifyData(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
            else => {
                const v = tls_finished.Sha256F.verifyData(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
        }
    }
};

fn rmsT(comptime KS: type, handshake_secret: *const [max_hash_len]u8, transcript: []const u8, out: *[max_hash_len]u8) !void {
    var hs = KS.SecretBytes.init(handshake_secret[0..KS.hash_len].*);
    defer hs.wipe();
    var master = try KS.masterSecret(&hs);
    defer master.wipe();
    const th = KS.transcriptHash(transcript);
    var rms = try KS.deriveSecret(&master, "res master", &th);
    defer rms.wipe();
    out[0..KS.hash_len].* = rms.declassify();
}

/// Extract the Ed25519 public key from a leaf certificate's DER SPKI (test-only;
/// the server's certs are Ed25519 self-signed). Reuses the x509 DER reader.
fn ed25519KeyFromCert(der: []const u8) !Ed25519.PublicKey {
    const x509 = @import("../crypto/x509.zig");
    const cert = x509.parse(der) catch return error.BadHandshake;
    var spki = x509.DerReader.init(cert.spki_value);
    _ = spki.readExpected(x509.Tag.sequence) catch return error.BadHandshake; // AlgorithmIdentifier
    const key_bits = spki.readExpected(x509.Tag.bit_string) catch return error.BadHandshake;
    if (key_bits.value.len == 0 or key_bits.value[0] != 0) return error.BadHandshake;
    const key_bytes = key_bits.value[1..];
    if (key_bytes.len != Ed25519.PublicKey.encoded_length) return error.BadHandshake;
    var raw: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    @memcpy(&raw, key_bytes);
    return Ed25519.PublicKey.fromBytes(raw) catch error.BadHandshake;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const x509_selfsign = @import("x509_selfsign.zig");

/// The loopback client used to be a test-only `TestClient`; it is now the public
/// `Client`. This alias keeps the stepwise handshake tests below unchanged.
const TestClient = Client;

fn mintEd25519Cert(out: *[1024]u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "quic.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = kp,
        .dns_names = &.{"quic.test"},
        .is_ca = true,
    });
}

const test_server_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
    .max_idle_timeout = 30_000,
    .initial_max_data = 1_048_576,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

const test_client_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &[_]u8{ 0x01, 0x02, 0x03 },
    .initial_max_data = 524_288,
    .initial_max_streams_uni = 3,
};

/// Drive a full loopback handshake for a fixed ClientHello suite preference,
/// asserting both sides install identical handshake AND application KeySets.
fn runLoopback(
    alloc: Allocator,
    client_suites_override: ?CipherSuite,
    alpn_server: []const []const u8,
    alpn_client: []const []const u8,
) !struct { server_suite: CipherSuite, server_alpn: ?[]const u8 } {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = alpn_server,
        .transport_params = test_server_params,
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x21)),
        .server_random = @as([32]u8, @splat(0x55)),
    });
    defer server.deinit();

    var client = try TestClient.init(alloc, @as([kx.X25519Kx.seed_len]u8, @splat(0x42)), alpn_client, test_client_params);
    defer client.deinit();

    var ch = try client.start();
    defer ch.deinit(alloc);
    try server.feedCrypto(.initial, ch.items);

    // If a specific suite was requested, the test asserts it below; we don't
    // restrict the ClientHello (it offers all three) — server preference picks.
    _ = client_suites_override;

    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);

    try client.feedInitial(s_initial);
    var cfin = try client.feedHandshake(s_handshake);
    defer cfin.deinit(alloc);
    try testing.expect(client.done);

    try server.feedCrypto(.handshake, cfin.items);
    try testing.expect(server.isComplete());

    const ss = server.suite.?;
    // Both sides agree on the handshake traffic secrets.
    const hl = ss.hashLen();
    try testing.expectEqualSlices(u8, server.client_hs_secret[0..hl], client.client_hs_secret[0..hl]);
    try testing.expectEqualSlices(u8, server.server_hs_secret[0..hl], client.server_hs_secret[0..hl]);
    // Both sides agree on the application traffic secrets.
    try testing.expectEqualSlices(u8, server.client_ap_secret[0..hl], client.client_ap_secret[0..hl]);
    try testing.expectEqualSlices(u8, server.server_ap_secret[0..hl], client.server_ap_secret[0..hl]);

    // The installed QUIC packet keys cross-match: the server's write keys equal
    // the client's read keys at both handshake and application levels, and the
    // server's read keys equal the client's write keys.
    const sk_hs = server.handshake_keys.?;
    const ck_hs = client.handshake_keys.?;
    try expectPacketKeysEqual(sk_hs.write, ck_hs.read);
    try expectPacketKeysEqual(sk_hs.read, ck_hs.write);
    const sk_ap = server.application_keys.?;
    const ck_ap = client.application_keys.?;
    try expectPacketKeysEqual(sk_ap.write, ck_ap.read);
    try expectPacketKeysEqual(sk_ap.read, ck_ap.write);

    // A 1-RTT packet sealed by the server opens under the client's read keys.
    try expectPacketRoundTrip(alloc, sk_ap.write, ck_ap.read);

    return .{ .server_suite = ss, .server_alpn = server.selected_alpn };
}

fn expectPacketKeysEqual(a: PacketKeys, b: PacketKeys) !void {
    try testing.expectEqual(a.suite, b.suite);
    try testing.expectEqualSlices(u8, a.keyBytes(), b.keyBytes());
    try testing.expectEqualSlices(u8, &a.iv, &b.iv);
    try testing.expectEqualSlices(u8, a.hpBytes(), b.hpBytes());
}

/// Seal a short-header 1-RTT packet with `write` keys and open it with `read`.
fn expectPacketRoundTrip(alloc: Allocator, write: PacketKeys, read: PacketKeys) !void {
    // Minimal short header: first byte 0x40 (fixed bit) | pn_len bits 00 (1-byte
    // pn), then a 1-byte pn. pn_offset = 1.
    const header = [_]u8{ 0x40, 0x07 };
    const plaintext = "quic 1-rtt payload";
    const out = try alloc.alloc(u8, header.len + plaintext.len + quic_protect.aead_tag_len);
    defer alloc.free(out);
    const sealed = try quic_protect.sealPacketSuite(out, &header, 1, 1, 7, plaintext, write);

    const recovered = try alloc.alloc(u8, plaintext.len);
    defer alloc.free(recovered);
    const opened = try quic_protect.openPacketSuite(recovered, out[0..sealed.len], 1, read, quic_protect.identityPacketNumber);
    try testing.expectEqualSlices(u8, plaintext, recovered[0..opened.plaintext_len]);
}

test "quic handshake loopback completes for TLS_AES_128_GCM_SHA256 with matching 1-RTT keys" {
    const r = try runLoopback(testing.allocator, null, &.{ "h3", "irc" }, &.{ "h3", "irc" });
    try testing.expectEqual(CipherSuite.tls_aes_128_gcm_sha256, r.server_suite);
    try testing.expectEqualStrings("h3", r.server_alpn.?);
}

test "quic handshake loopback agrees on keys for ChaCha20-Poly1305-SHA256" {
    // Offer only ChaCha20 so the server selects the SHA-256 ChaCha suite.
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x38)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    const alloc = testing.allocator;

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = test_server_params,
    });
    defer server.deinit();
    var client = try TestClient.init(alloc, @as([kx.X25519Kx.seed_len]u8, @splat(0x43)), &.{"h3"}, test_client_params);
    defer client.deinit();

    // ClientHello offering ONLY ChaCha20.
    var ch = try buildSingleSuiteHello(alloc, &client, .tls_chacha20_poly1305_sha256);
    defer ch.deinit(alloc);
    try server.feedCrypto(.initial, ch.items);
    try testing.expectEqual(CipherSuite.tls_chacha20_poly1305_sha256, server.suite.?);

    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);
    try client.feedInitial(s_initial);
    var cfin = try client.feedHandshake(s_handshake);
    defer cfin.deinit(alloc);
    try server.feedCrypto(.handshake, cfin.items);
    try testing.expect(server.isComplete());

    const hl = server.suite.?.hashLen();
    try testing.expectEqualSlices(u8, server.client_ap_secret[0..hl], client.client_ap_secret[0..hl]);
    try testing.expectEqualSlices(u8, server.server_ap_secret[0..hl], client.server_ap_secret[0..hl]);
    try expectPacketKeysEqual(server.application_keys.?.write, client.application_keys.?.read);
    try testing.expectEqual(QuicCipherSuite.chacha20poly1305, server.application_keys.?.write.suite);
}

test "quic handshake loopback agrees on keys for AES-256-GCM-SHA384" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x39)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    const alloc = testing.allocator;

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = test_server_params,
    });
    defer server.deinit();
    var client = try TestClient.init(alloc, @as([kx.X25519Kx.seed_len]u8, @splat(0x44)), &.{"h3"}, test_client_params);
    defer client.deinit();

    var ch = try buildSingleSuiteHello(alloc, &client, .tls_aes_256_gcm_sha384);
    defer ch.deinit(alloc);
    try server.feedCrypto(.initial, ch.items);
    try testing.expectEqual(CipherSuite.tls_aes_256_gcm_sha384, server.suite.?);

    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);
    try client.feedInitial(s_initial);
    var cfin = try client.feedHandshake(s_handshake);
    defer cfin.deinit(alloc);
    try server.feedCrypto(.handshake, cfin.items);
    try testing.expect(server.isComplete());

    // SHA-384 → 48-byte traffic secrets, 32-byte AES-256 packet keys.
    const hl = server.suite.?.hashLen();
    try testing.expectEqual(@as(usize, 48), hl);
    try testing.expectEqualSlices(u8, server.client_ap_secret[0..hl], client.client_ap_secret[0..hl]);
    try testing.expectEqualSlices(u8, server.server_ap_secret[0..hl], client.server_ap_secret[0..hl]);
    try expectPacketKeysEqual(server.application_keys.?.write, client.application_keys.?.read);
    try testing.expectEqual(QuicCipherSuite.aes256gcm, server.application_keys.?.write.suite);
    try expectPacketRoundTrip(alloc, server.application_keys.?.write, client.application_keys.?.read);
}

/// Rebuild the client's ClientHello offering exactly one cipher suite (so the
/// server's preference resolves to it). Mirrors `TestClient.start` but with a
/// single-element cipher_suites list.
fn buildSingleSuiteHello(alloc: Allocator, client: *Client, only: CipherSuite) !std.ArrayList(u8) {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);
    try appendU16(alloc, &body, legacy_version);
    try body.appendSlice(alloc, &client.client_random);
    try body.append(alloc, 0);
    try appendU16(alloc, &body, 2);
    try appendU16(alloc, &body, @backingInt(only));
    try body.append(alloc, 1);
    try body.append(alloc, 0);

    var ext_storage: [1024]u8 = undefined;
    var ext_builder = try tls_extension.Builder.begin(&ext_storage);
    var sv_buf: [8]u8 = undefined;
    try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildClient(&sv_buf, &.{tls_supported_versions.tls13}));
    var ks_inner: [64]u8 = undefined;
    const ks = try tls_keyshare.buildClientShares(&ks_inner, &.{.{ .group = .x25519, .key_exchange = &client.x25519_pair.public_key }});
    try ext_builder.addTyped(.key_share, ks);
    if (client.alpn_protocols.len > 0) {
        var alpn_buf: [260]u8 = undefined;
        var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
        for (client.alpn_protocols) |p| try alpn_builder.add(p);
        try ext_builder.addTyped(.alpn, try alpn_builder.finish());
    }
    var tp_body: std.ArrayList(u8) = .empty;
    defer tp_body.deinit(alloc);
    try quic_transport_params.encode(&tp_body, alloc, client.transport_params);
    try ext_builder.add(quic_transport_parameters_ext, tp_body.items);
    try body.appendSlice(alloc, try ext_builder.finish());

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try writeHandshake(alloc, &out, .client_hello, body.items);
    try client.transcript.appendSlice(alloc, out.items);
    return out;
}

test "quic handshake negotiates ALPN and exchanges transport parameters" {
    const r = try runLoopback(testing.allocator, null, &.{ "h3", "irc" }, &.{ "irc", "h3" });
    // Server preference order wins: it prefers "h3".
    try testing.expectEqualStrings("h3", r.server_alpn.?);
}

test "quic handshake surfaces peer transport params on both sides" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3a)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    const alloc = testing.allocator;

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = test_server_params,
    });
    defer server.deinit();
    var client = try TestClient.init(alloc, @as([kx.X25519Kx.seed_len]u8, @splat(0x45)), &.{"h3"}, test_client_params);
    defer client.deinit();

    var ch = try client.start();
    defer ch.deinit(alloc);
    try server.feedCrypto(.initial, ch.items);
    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);
    try client.feedInitial(s_initial);
    var cfin = try client.feedHandshake(s_handshake);
    defer cfin.deinit(alloc);
    try server.feedCrypto(.handshake, cfin.items);

    // The server saw the client's transport params.
    const sp = server.peerTransportParams().?;
    try testing.expectEqual(@as(?u64, 524_288), sp.initial_max_data);
    try testing.expectEqual(@as(?u64, 3), sp.initial_max_streams_uni);
    // The client saw the server's transport params.
    const cp = client.peer_params.?;
    try testing.expectEqual(@as(?u64, 1_048_576), cp.initial_max_data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }, cp.initial_source_connection_id.?);
}

test "quic handshake rejects a ClientHello with no transport parameters" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3b)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    const alloc = testing.allocator;
    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = test_server_params,
    });
    defer server.deinit();

    // Build a ClientHello WITHOUT the quic_transport_parameters extension.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);
    try appendU16(alloc, &body, legacy_version);
    try body.appendSlice(alloc, &(@as([32]u8, @splat(0x11))));
    try body.append(alloc, 0);
    try appendU16(alloc, &body, 2);
    try appendU16(alloc, &body, @backingInt(CipherSuite.tls_aes_128_gcm_sha256));
    try body.append(alloc, 1);
    try body.append(alloc, 0);
    var seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42));
    var pair = try kx.X25519Kx.generateDeterministic(seed);
    defer pair.wipe();
    seed = undefined;
    var ext_storage: [256]u8 = undefined;
    var ext_builder = try tls_extension.Builder.begin(&ext_storage);
    var sv_buf: [8]u8 = undefined;
    try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildClient(&sv_buf, &.{tls_supported_versions.tls13}));
    var ks_inner: [64]u8 = undefined;
    const ks = try tls_keyshare.buildClientShares(&ks_inner, &.{.{ .group = .x25519, .key_exchange = &pair.public_key }});
    try ext_builder.addTyped(.key_share, ks);
    try body.appendSlice(alloc, try ext_builder.finish());
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(alloc);
    try writeHandshake(alloc, &hello, .client_hello, body.items);

    try testing.expectError(error.MissingExtension, server.feedCrypto(.initial, hello.items));
}

test "quic handshake client rejects a tampered server Finished" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3c)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    const alloc = testing.allocator;
    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = test_server_params,
    });
    defer server.deinit();
    var client = try TestClient.init(alloc, @as([kx.X25519Kx.seed_len]u8, @splat(0x46)), &.{"h3"}, test_client_params);
    defer client.deinit();

    var ch = try client.start();
    defer ch.deinit(alloc);
    try server.feedCrypto(.initial, ch.items);
    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);
    try client.feedInitial(s_initial);

    // Flip the final byte of the server flight (inside the server Finished MAC).
    const tampered = try alloc.dupe(u8, s_handshake);
    defer alloc.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try testing.expectError(error.FinishedMismatch, client.feedHandshake(tampered));
}

test "quic handshake server rejects a tampered client Finished" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3d)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    const alloc = testing.allocator;
    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = test_server_params,
    });
    defer server.deinit();
    var client = try TestClient.init(alloc, @as([kx.X25519Kx.seed_len]u8, @splat(0x47)), &.{"h3"}, test_client_params);
    defer client.deinit();

    var ch = try client.start();
    defer ch.deinit(alloc);
    try server.feedCrypto(.initial, ch.items);
    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);
    try client.feedInitial(s_initial);
    var cfin = try client.feedHandshake(s_handshake);
    defer cfin.deinit(alloc);

    // Flip a byte inside the client Finished MAC.
    cfin.items[cfin.items.len - 1] ^= 0x01;
    try testing.expectError(error.FinishedMismatch, server.feedCrypto(.handshake, cfin.items));
    try testing.expect(!server.isComplete());
}

test "quic handshake feeds a ClientHello split across two CRYPTO chunks" {
    const r = blk: {
        const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3e)));
        var cert_buf: [1024]u8 = undefined;
        const der = try mintEd25519Cert(&cert_buf, kp);
        const alloc = testing.allocator;
        var server = try Server.init(alloc, .{
            .cert_chain = &.{der},
            .signing_key = .{ .ed25519 = kp },
            .alpn_protocols = &.{"h3"},
            .transport_params = test_server_params,
        });
        defer server.deinit();
        var client = try TestClient.init(alloc, @as([kx.X25519Kx.seed_len]u8, @splat(0x48)), &.{"h3"}, test_client_params);
        defer client.deinit();

        var ch = try client.start();
        defer ch.deinit(alloc);
        // Feed the ClientHello in two halves; the first must be insufficient.
        const mid = ch.items.len / 2;
        try server.feedCrypto(.initial, ch.items[0..mid]);
        try testing.expect(server.suite == null); // not yet processed
        try server.feedCrypto(.initial, ch.items[mid..]);
        try testing.expect(server.suite != null);

        const s_initial = try server.takeFlight(.initial);
        defer alloc.free(s_initial);
        const s_handshake = try server.takeFlight(.handshake);
        defer alloc.free(s_handshake);
        try client.feedInitial(s_initial);
        var cfin = try client.feedHandshake(s_handshake);
        defer cfin.deinit(alloc);
        try server.feedCrypto(.handshake, cfin.items);
        try testing.expect(server.isComplete());
        break :blk true;
    };
    try testing.expect(r);
}

test "quic handshake accepts an X25519MLKEM768 hybrid key_share and emits a hybrid server share" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x5a)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    const alloc = testing.allocator;
    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = test_server_params,
    });
    defer server.deinit();

    // Build a ClientHello that offers ONLY an X25519MLKEM768 key_share, exactly
    // as modern Chrome/Edge do for WebTransport. Client share = ek(1184) ‖ pk(32).
    var x_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x63));
    var x_pair = try kx.X25519Kx.generateDeterministic(x_seed);
    defer x_pair.wipe();
    x_seed = undefined;
    const mlkem_kp = try MlKem768.KeyPair.generateDeterministic(@as([MlKem768.seed_length]u8, @splat(0x29)));
    var client_share: [hybrid_client_share_len]u8 = undefined;
    client_share[0..mlkem_ek_len].* = mlkem_kp.public_key.toBytes();
    client_share[mlkem_ek_len..].* = x_pair.public_key;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);
    try appendU16(alloc, &body, legacy_version);
    try body.appendSlice(alloc, &(@as([32]u8, @splat(0x11))));
    try body.append(alloc, 0); // empty legacy_session_id
    try appendU16(alloc, &body, 2);
    try appendU16(alloc, &body, @backingInt(CipherSuite.tls_aes_128_gcm_sha256));
    try body.append(alloc, 1);
    try body.append(alloc, 0); // null compression

    var ext_storage: [hybrid_client_share_len + 512]u8 = undefined;
    var ext_builder = try tls_extension.Builder.begin(&ext_storage);
    var sv_buf: [8]u8 = undefined;
    try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildClient(&sv_buf, &.{tls_supported_versions.tls13}));
    var ks_inner: [hybrid_client_share_len + 16]u8 = undefined;
    const ks = try tls_keyshare.buildClientShares(&ks_inner, &.{.{ .group = .x25519mlkem768, .key_exchange = &client_share }});
    try ext_builder.addTyped(.key_share, ks);
    var alpn_buf: [16]u8 = undefined;
    var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
    try alpn_builder.add("h3");
    try ext_builder.addTyped(.alpn, try alpn_builder.finish());
    var tp_body: std.ArrayList(u8) = .empty;
    defer tp_body.deinit(alloc);
    try quic_transport_params.encode(&tp_body, alloc, test_client_params);
    try ext_builder.add(quic_transport_parameters_ext, tp_body.items);
    try body.appendSlice(alloc, try ext_builder.finish());

    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(alloc);
    try writeHandshake(alloc, &hello, .client_hello, body.items);

    try server.feedCrypto(.initial, hello.items);

    // The server selected the hybrid group and produced its flight.
    try testing.expect(server.suite != null);
    try testing.expectEqual(SelectedGroup.x25519mlkem768, server.selected_group);
    try testing.expect(server.handshakeKeys() != null);
    try testing.expect(server.applicationKeys() != null);

    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);
    try testing.expect(s_initial.len != 0);
    try testing.expect(s_handshake.len != 0);

    // The ServerHello key_share must echo the hybrid group with a 1120-byte share
    // (ml-kem_ct(1088) ‖ x25519_pk(32)) so the client can complete the exchange.
    var off: usize = 0;
    const sh = parseHandshakeMaybe(s_initial, &off) orelse return error.BadHandshake;
    try testing.expectEqual(HandshakeType.server_hello, sh.typ);
    var sc = Cursor.init(sh.body);
    _ = try sc.readU16(); // legacy_version
    _ = try sc.take(32); // server random
    _ = try sc.take(try sc.readU8()); // legacy_session_id_echo
    _ = try sc.readU16(); // cipher suite
    _ = try sc.take(1); // compression
    const sh_exts = try sc.take(try sc.readU16());
    var found_hybrid = false;
    var sh_it = tls_extension.Iterator.init(sh_exts);
    while (try sh_it.next()) |ext| {
        if (ext.ext_type == @backingInt(tls_extension.ExtensionType.key_share)) {
            const entry = try tls_keyshare.parseServerShare(ext.data);
            try testing.expectEqual(tls_keyshare.NamedGroup.x25519mlkem768, entry.group);
            try testing.expectEqual(@as(usize, hybrid_server_share_len), entry.key_exchange.len);
            found_hybrid = true;
        }
    }
    try testing.expect(found_hybrid);
}

test {
    std.testing.refAllDecls(@This());
}

fn testServerForLimits(alloc: Allocator, cert_buf: *[1024]u8) !Server {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x51)));
    const der = try mintEd25519Cert(cert_buf, kp);
    return Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = .{ .ed25519 = kp }, .alpn_protocols = &.{"h3"}, .transport_params = test_server_params });
}

test "quic handshake refuses an oversized in-order ClientHello before buffering it" {
    var cert_buf: [1024]u8 = undefined;
    var server = try testServerForLimits(testing.allocator, &cert_buf);
    defer server.deinit();
    // Declare a 16 MiB ClientHello, then stream filler in order.
    const header = [_]u8{ 1, 0xff, 0xff, 0xff };
    try testing.expectError(error.HandshakeTooLarge, server.feedCrypto(.initial, &header));
    try testing.expect(server.recv.items.len <= max_handshake_buffer);
}

test "quic handshake caps total buffered initial bytes even under the declared limit" {
    var cert_buf: [1024]u8 = undefined;
    var server = try testServerForLimits(testing.allocator, &cert_buf);
    defer server.deinit();
    // A declared length just under the cap is accepted while incomplete.
    const declared = max_handshake_buffer - 4;
    const header = [_]u8{ 1, @intCast(declared >> 16), @intCast((declared >> 8) & 0xff), @intCast(declared & 0xff) };
    try server.feedCrypto(.initial, &header);
    var chunk: [4096]u8 = @splat(0);
    var fed: usize = 4;
    while (fed + chunk.len < max_handshake_buffer) : (fed += chunk.len) try server.feedCrypto(.initial, &chunk);
    try testing.expect(server.recv.items.len <= max_handshake_buffer);
    try testing.expectError(error.HandshakeTooLarge, server.feedCrypto(.initial, &chunk));
}

// --- RFC 9000 §7.3 connection-id authentication (client) -------------------

const cid_test_odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const cid_test_server_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
const cid_test_retry_scid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75 };

const CidCase = struct {
    /// Server transport-parameter CIDs as sent on the wire.
    server_odcid: ?[]const u8 = &cid_test_odcid,
    server_iscid: ?[]const u8 = &cid_test_server_scid,
    server_retry_scid: ?[]const u8 = null,
    /// What the client driver observed and reports.
    observed_scid: ?[]const u8 = &cid_test_server_scid,
    observed_retry_scid: ?[]const u8 = null,
};

/// Drive the public `feedCrypto`/`takeFlight` client surface against a real
/// `Server` whose connection-id transport parameters are set from `case`.
fn runCidCase(case: CidCase) !void {
    const alloc = testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x61)));
    var cert_buf: [1024]u8 = undefined;
    const der = try mintEd25519Cert(&cert_buf, kp);
    var server_params = test_server_params;
    server_params.original_destination_connection_id = case.server_odcid;
    server_params.initial_source_connection_id = case.server_iscid;
    server_params.retry_source_connection_id = case.server_retry_scid;
    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = .{ .ed25519 = kp },
        .alpn_protocols = &.{"h3"},
        .transport_params = server_params,
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x21)),
        .server_random = @as([32]u8, @splat(0x55)),
    });
    defer server.deinit();

    var client = try Client.initConfig(alloc, .{
        .alpn_protocols = &.{"h3"},
        .transport_params = test_client_params,
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
        .original_dcid = &cid_test_odcid,
    });
    defer client.deinit();

    try client.startHandshake();
    const ch = try client.takeFlight(.initial);
    defer alloc.free(ch);
    try server.feedCrypto(.initial, ch);
    const s_initial = try server.takeFlight(.initial);
    defer alloc.free(s_initial);
    const s_handshake = try server.takeFlight(.handshake);
    defer alloc.free(s_handshake);

    if (case.observed_retry_scid) |rs| try client.setRetryScid(rs);
    if (case.observed_scid) |scid| try client.setServerInitialScid(scid);
    try client.feedCrypto(.initial, s_initial);
    try client.feedCrypto(.handshake, s_handshake);
    try testing.expect(client.isComplete());
    try testing.expectEqualSlices(u8, &cid_test_odcid, client.peerTransportParams().?.original_destination_connection_id.?);
}

test "quic client accepts server connection-id params that match what it observed" {
    try runCidCase(.{});
}

test "quic client accepts retry_source_connection_id that matches the Retry it processed" {
    try runCidCase(.{ .server_retry_scid = &cid_test_retry_scid, .observed_retry_scid = &cid_test_retry_scid });
}

test "quic client rejects a mismatched original_destination_connection_id" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{ .server_odcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x09 } }));
}

test "quic client rejects a missing original_destination_connection_id" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{ .server_odcid = null }));
}

test "quic client rejects an initial_source_connection_id that differs from the observed server SCID" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{ .observed_scid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xde } }));
}

test "quic client rejects a missing initial_source_connection_id" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{ .server_iscid = null }));
}

test "quic client fails closed when the driver never reported the server SCID" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{ .observed_scid = null }));
}

test "quic client rejects a missing retry_source_connection_id after a Retry" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{ .observed_retry_scid = &cid_test_retry_scid }));
}

test "quic client rejects a mismatched retry_source_connection_id" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{
        .server_retry_scid = &[_]u8{ 0x71, 0x72, 0x73, 0x74, 0x76 },
        .observed_retry_scid = &cid_test_retry_scid,
    }));
}

test "quic client rejects retry_source_connection_id when no Retry happened" {
    try testing.expectError(error.ConnectionIdMismatch, runCidCase(.{ .server_retry_scid = &cid_test_retry_scid }));
}

test "quic client refuses to swap the reported server SCID" {
    var client = try Client.initConfig(testing.allocator, .{
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
        .original_dcid = &cid_test_odcid,
    });
    defer client.deinit();
    try client.setServerInitialScid(&cid_test_server_scid);
    try client.setServerInitialScid(&cid_test_server_scid); // idempotent
    try testing.expectError(error.ConnectionIdMismatch, client.setServerInitialScid(&[_]u8{0x01}));
    try client.setRetryScid(&cid_test_retry_scid);
    try testing.expectError(error.BadState, client.setRetryScid(&cid_test_retry_scid));
}

/// Encode an EncryptedExtensions handshake message carrying `tp_body` as the
/// quic_transport_parameters extension (or no extension when null).
fn buildTestEncryptedExtensions(alloc: Allocator, out: *std.ArrayList(u8), tp_body: ?[]const u8) !void {
    var ext_storage: [512]u8 = undefined;
    var ext_builder = try tls_extension.Builder.begin(&ext_storage);
    if (tp_body) |b| try ext_builder.add(quic_transport_parameters_ext, b);
    try writeHandshake(alloc, out, .encrypted_extensions, try ext_builder.finish());
}

test "quic client rejects EncryptedExtensions without transport parameters" {
    const alloc = testing.allocator;
    var client = try Client.initConfig(alloc, .{
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
    });
    defer client.deinit();
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(alloc);
    try buildTestEncryptedExtensions(alloc, &flight, null);
    try writeHandshake(alloc, &flight, .finished, &(@as([32]u8, @splat(0))));
    try testing.expectError(error.MissingExtension, client.feedCrypto(.handshake, flight.items));
}

test "quic client surfaces a duplicated server transport parameter as a typed error" {
    const alloc = testing.allocator;
    var client = try Client.initConfig(alloc, .{
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
    });
    defer client.deinit();
    // initial_max_data (0x04) twice, each a 1-byte varint.
    const tp = [_]u8{ 0x04, 0x01, 0x07, 0x04, 0x01, 0x09 };
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(alloc);
    try buildTestEncryptedExtensions(alloc, &flight, &tp);
    try writeHandshake(alloc, &flight, .finished, &(@as([32]u8, @splat(0))));
    try testing.expectError(error.DuplicateParameter, client.feedCrypto(.handshake, flight.items));
    try testing.expect(client.peerTransportParams() == null);
}

// --- Client receive-buffer bounds -------------------------------------------

test "quic client refuses an oversized ServerHello declaration" {
    var client = try Client.initConfig(testing.allocator, .{
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
    });
    defer client.deinit();
    const header = [_]u8{ 2, 0xff, 0xff, 0xff };
    try testing.expectError(error.HandshakeTooLarge, client.feedCrypto(.initial, &header));
    try testing.expect(client.recv_initial.items.len <= max_handshake_buffer);
}

test "quic client refuses an oversized declaration behind a complete message in the server flight" {
    const alloc = testing.allocator;
    var client = try Client.initConfig(alloc, .{
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
    });
    defer client.deinit();
    // A small, complete EncryptedExtensions followed by a Certificate header
    // that declares 16 MiB: refused at once, not streamed up to the cap.
    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(alloc);
    try buildTestEncryptedExtensions(alloc, &flight, &.{});
    try flight.appendSlice(alloc, &.{ 11, 0xff, 0xff, 0xff });
    try testing.expectError(error.HandshakeTooLarge, client.feedCrypto(.handshake, flight.items));
}

test "quic client caps total buffered handshake-flight bytes" {
    var client = try Client.initConfig(testing.allocator, .{
        .x25519_seed = @as([kx.X25519Kx.seed_len]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
    });
    defer client.deinit();
    // A declared length just under the cap is accepted while incomplete.
    const declared = max_handshake_buffer - 4;
    const header = [_]u8{ 11, @intCast(declared >> 16), @intCast((declared >> 8) & 0xff), @intCast(declared & 0xff) };
    try client.feedCrypto(.handshake, &header);
    var chunk: [4096]u8 = @splat(0);
    var fed: usize = 4;
    while (fed + chunk.len < max_handshake_buffer) : (fed += chunk.len) try client.feedCrypto(.handshake, &chunk);
    try testing.expect(client.recv_handshake.items.len <= max_handshake_buffer);
    try testing.expectError(error.HandshakeTooLarge, client.feedCrypto(.handshake, &chunk));
}

// ===========================================================================
// HelloRetryRequest, resumption and 0-RTT (RFC 8446 §4.1.4 / §4.2.11 /
// §4.6.1, RFC 9001 §4.5–§4.6, RFC 9000 §7.4.1)
// ===========================================================================

const feat_ticket_key: tls_resumption.TicketKey = @splat(0x7a);
const feat_now: i64 = 1_800_000_000;

const FeatServer = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8 = undefined,
    der: [1][]const u8 = .{&.{}},

    fn init(self: *FeatServer) !void {
        self.kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x6c)));
        self.der[0] = try mintEd25519Cert(&self.cert_buf, self.kp);
    }

    fn config(self: *const FeatServer) Config {
        return .{
            .cert_chain = &self.der,
            .signing_key = .{ .ed25519 = self.kp },
            .alpn_protocols = &.{"h3"},
            .transport_params = test_server_params,
            .ticket_key = feat_ticket_key,
            .now_unix_seconds = feat_now,
        };
    }
};

fn featClient(alloc: Allocator, overrides: ClientConfig) !Client {
    var cfg = overrides;
    if (cfg.alpn_protocols.len == 0) cfg.alpn_protocols = &.{"h3"};
    cfg.transport_params = test_client_params;
    return Client.initConfig(alloc, cfg);
}

/// Pump the public `feedCrypto`/`takeFlight` surfaces until both sides are
/// complete, including an HRR round and the post-handshake ticket.
fn featPump(alloc: Allocator, server: *Server, client: *Client) !void {
    try client.startHandshake();
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        const c_init = try client.takeFlight(.initial);
        defer alloc.free(c_init);
        if (c_init.len > 0) try server.feedCrypto(.initial, c_init);
        const c_hs = try client.takeFlight(.handshake);
        defer alloc.free(c_hs);
        if (c_hs.len > 0) try server.feedCrypto(.handshake, c_hs);

        const s_init = try server.takeFlight(.initial);
        defer alloc.free(s_init);
        if (s_init.len > 0) try client.feedCrypto(.initial, s_init);
        const s_hs = try server.takeFlight(.handshake);
        defer alloc.free(s_hs);
        if (s_hs.len > 0) try client.feedCrypto(.handshake, s_hs);
        const s_app = try server.takeFlight(.application);
        defer alloc.free(s_app);
        if (s_app.len > 0) try client.feedCrypto(.application, s_app);
        if (server.isComplete() and client.isComplete() and c_init.len == 0 and c_hs.len == 0) return;
    }
    return error.TestUnexpectedResult;
}

/// Copy a session out of a client (its ticket slice borrows client storage).
const OwnedSession = struct {
    session: Session,
    ticket: [512]u8 = undefined,

    fn take(c: *const Client) !OwnedSession {
        const s = c.resumptionSession() orelse return error.TestUnexpectedResult;
        var out: OwnedSession = .{ .session = s };
        if (s.ticket.len > out.ticket.len) return error.TestUnexpectedResult;
        @memcpy(out.ticket[0..s.ticket.len], s.ticket);
        return out;
    }

    fn get(self: *const OwnedSession) Session {
        var s = self.session;
        s.ticket = self.ticket[0..self.session.ticket.len];
        return s;
    }
};

/// Run one full handshake against `cfg` and return the issued session.
fn featIssueSession(alloc: Allocator, cfg: Config) !OwnedSession {
    var server = try Server.init(alloc, cfg);
    defer server.deinit();
    var client = try featClient(alloc, .{});
    defer client.deinit();
    try featPump(alloc, &server, &client);
    try testing.expect(!server.isResumed());
    return OwnedSession.take(&client);
}

test "quic HRR: a ClientHello with no usable key_share gets a HelloRetryRequest and completes" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var server = try Server.init(alloc, fs.config());
    defer server.deinit();
    var client = try featClient(alloc, .{ .offer_key_share = false, .advertise_groups = &.{ .secp256r1, .x25519 } });
    defer client.deinit();
    try featPump(alloc, &server, &client);
    try testing.expect(server.sentHelloRetryRequest());
    try testing.expect(client.hrr_received);
    try testing.expectEqual(SelectedGroup.x25519, server.selected_group);
    try expectPacketKeysEqual(server.applicationKeys().?.write, client.applicationKeys().?.read);
    try expectPacketKeysEqual(server.applicationKeys().?.read, client.applicationKeys().?.write);
}

test "quic HRR: the requested group follows the configured order (hybrid > x25519 by default)" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    // Default order: a client advertising both groups without shares is asked
    // for the hybrid.
    {
        var server = try Server.init(alloc, fs.config());
        defer server.deinit();
        var client = try featClient(alloc, .{ .offer_key_share = false, .advertise_groups = &.{ .x25519, .x25519mlkem768 } });
        defer client.deinit();
        try client.startHandshake();
        const ch = try client.takeFlight(.initial);
        defer alloc.free(ch);
        try server.feedCrypto(.initial, ch);
        try testing.expect(server.sentHelloRetryRequest());
        try testing.expectEqual(KeyExchangeGroup.x25519mlkem768, server.hrr_group);
        // This client only implements X25519, so it refuses the hybrid HRR.
        const hrr = try server.takeFlight(.initial);
        defer alloc.free(hrr);
        try testing.expectError(error.UnsupportedGroup, client.feedCrypto(.initial, hrr));
    }
    // A configured x25519-first order asks for X25519.
    {
        var cfg = fs.config();
        cfg.group_order = &.{ .x25519, .x25519mlkem768 };
        var server = try Server.init(alloc, cfg);
        defer server.deinit();
        var client = try featClient(alloc, .{ .offer_key_share = false, .advertise_groups = &.{ .x25519mlkem768, .x25519 } });
        defer client.deinit();
        try featPump(alloc, &server, &client);
        try testing.expectEqual(KeyExchangeGroup.x25519, server.hrr_group);
    }
    // Invalid orders are refused at init.
    var bad = fs.config();
    bad.group_order = &.{};
    try testing.expectError(error.BadConfig, Server.init(alloc, bad));
    bad.group_order = &.{ .x25519, .x25519 };
    try testing.expectError(error.BadConfig, Server.init(alloc, bad));
}

test "quic HRR: no supported group advertised is a typed failure, and a second hello still lacking the share aborts" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    {
        var server = try Server.init(alloc, fs.config());
        defer server.deinit();
        var client = try featClient(alloc, .{ .offer_key_share = false, .advertise_groups = &.{.secp256r1} });
        defer client.deinit();
        try client.startHandshake();
        const ch = try client.takeFlight(.initial);
        defer alloc.free(ch);
        try testing.expectError(error.UnsupportedGroup, server.feedCrypto(.initial, ch));
    }
    {
        var server = try Server.init(alloc, fs.config());
        defer server.deinit();
        var client = try featClient(alloc, .{ .offer_key_share = false, .advertise_groups = &.{.x25519} });
        defer client.deinit();
        try client.startHandshake();
        const ch = try client.takeFlight(.initial);
        defer alloc.free(ch);
        try server.feedCrypto(.initial, ch);
        try testing.expect(server.sentHelloRetryRequest());
        // Replay the same share-less hello as "ClientHello2": fatal (§4.1.4).
        try testing.expectError(error.BadHandshake, server.feedCrypto(.initial, ch));
    }
}

test "quic resumption: the server issues a ticket and a later PSK handshake resumes without a certificate" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    const owned = try featIssueSession(alloc, fs.config());
    try testing.expectEqual(@as(u32, 0), owned.session.max_early_data_size); // 0-RTT off by default

    var server = try Server.init(alloc, fs.config());
    defer server.deinit();
    var client = try featClient(alloc, .{ .session = owned.get(), .ticket_age_ms = 1000 });
    defer client.deinit();
    try featPump(alloc, &server, &client);
    try testing.expect(server.isResumed());
    try testing.expect(client.isResumed());
    try testing.expect(!client.saw_certificate);
    try testing.expect(!server.earlyDataAccepted());
    try expectPacketKeysEqual(server.applicationKeys().?.write, client.applicationKeys().?.read);
    // The resumed connection issues a fresh ticket of its own.
    try testing.expect(client.resumptionSession() != null);
}

test "quic resumption: a rotated-out ticket key still opens via previous_ticket_key; an unknown key falls back" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    const owned = try featIssueSession(alloc, fs.config());
    var rotated = fs.config();
    rotated.ticket_key = @splat(0x11);
    rotated.previous_ticket_key = feat_ticket_key;
    {
        var server = try Server.init(alloc, rotated);
        defer server.deinit();
        var client = try featClient(alloc, .{ .session = owned.get() });
        defer client.deinit();
        try featPump(alloc, &server, &client);
        try testing.expect(server.isResumed());
    }
    rotated.previous_ticket_key = null;
    {
        var server = try Server.init(alloc, rotated);
        defer server.deinit();
        var client = try featClient(alloc, .{ .session = owned.get() });
        defer client.deinit();
        try featPump(alloc, &server, &client);
        try testing.expect(!server.isResumed()); // full handshake, not a failure
        try testing.expect(client.saw_certificate_verify);
    }
}

test "quic resumption: a PSK binder mismatch aborts the handshake" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var owned = try featIssueSession(alloc, fs.config());
    owned.session.psk[0] ^= 0x01; // wrong PSK ⇒ wrong binder for a valid ticket
    var server = try Server.init(alloc, fs.config());
    defer server.deinit();
    var client = try featClient(alloc, .{ .session = owned.get() });
    defer client.deinit();
    try client.startHandshake();
    const ch = try client.takeFlight(.initial);
    defer alloc.free(ch);
    try testing.expectError(error.PskBinderMismatch, server.feedCrypto(.initial, ch));
}

test "quic resumption: a stale, future-dated, or tampered ticket falls back to a full handshake" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    const owned = try featIssueSession(alloc, fs.config());
    const cases = [_]i64{
        feat_now + 86_400 + 1, // past the advertised lifetime
        feat_now - 10, // ticket from the future
    };
    for (cases) |now| {
        var cfg = fs.config();
        cfg.now_unix_seconds = now;
        var server = try Server.init(alloc, cfg);
        defer server.deinit();
        var client = try featClient(alloc, .{ .session = owned.get() });
        defer client.deinit();
        try featPump(alloc, &server, &client);
        try testing.expect(!server.isResumed());
    }
    // A forged ticket (one flipped ciphertext bit) is not ours.
    var forged = owned;
    forged.ticket[20] ^= 0x40;
    var server = try Server.init(alloc, fs.config());
    defer server.deinit();
    var client = try featClient(alloc, .{ .session = forged.get() });
    defer client.deinit();
    try featPump(alloc, &server, &client);
    try testing.expect(!server.isResumed());
    // No clock ⇒ resumption off (lifetime cannot be enforced) and no ticket.
    var no_clock = fs.config();
    no_clock.now_unix_seconds = null;
    var s2 = try Server.init(alloc, no_clock);
    defer s2.deinit();
    var c2 = try featClient(alloc, .{ .session = owned.get() });
    defer c2.deinit();
    try featPump(alloc, &s2, &c2);
    try testing.expect(!s2.isResumed());
    try testing.expect(c2.resumptionSession() == null);
}

test "quic resumption composes with HRR: the ClientHello2 binder covers message_hash ‖ HRR" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    const owned = try featIssueSession(alloc, fs.config());
    var server = try Server.init(alloc, fs.config());
    defer server.deinit();
    var client = try featClient(alloc, .{ .session = owned.get(), .offer_key_share = false });
    defer client.deinit();
    try featPump(alloc, &server, &client);
    try testing.expect(server.sentHelloRetryRequest());
    try testing.expect(server.isResumed());
}

fn earlyConfig(fs: *const FeatServer, guard: *tls_resumption.ReplayGuard) Config {
    var cfg = fs.config();
    cfg.enable_early_data = true;
    cfg.replay_guard = guard;
    return cfg;
}

const EarlyResult = struct { accepted: bool, resumed: bool, keys_match: bool };

fn featOffer0Rtt(alloc: Allocator, cfg: Config, session: Session, age_ms: u32) !EarlyResult {
    var server = try Server.init(alloc, cfg);
    defer server.deinit();
    var client = try featClient(alloc, .{ .session = session, .ticket_age_ms = age_ms, .offer_early_data = true });
    defer client.deinit();
    try featPump(alloc, &server, &client);
    const keys_match = if (server.earlyDataReadKeys()) |sk| blk: {
        const ck = client.earlyDataWriteKeys() orelse break :blk false;
        break :blk std.mem.eql(u8, sk.keyBytes(), ck.keyBytes()) and std.mem.eql(u8, &sk.iv, &ck.iv) and std.mem.eql(u8, sk.hpBytes(), ck.hpBytes());
    } else false;
    try testing.expectEqual(server.earlyDataAccepted(), client.earlyDataAccepted());
    return .{ .accepted = server.earlyDataAccepted(), .resumed = server.isResumed(), .keys_match = keys_match };
}

test "quic 0-RTT: accepted once with matching early keys; a replayed ClientHello is rejected but still resumes" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var guard: tls_resumption.ReplayGuard = .{};
    const cfg = earlyConfig(&fs, &guard);
    const owned = try featIssueSession(alloc, cfg);
    // RFC 9001 §4.6.1: the ticket advertises 0xffffffff.
    try testing.expectEqual(quic_max_early_data_size, owned.session.max_early_data_size);

    const first = try featOffer0Rtt(alloc, cfg, owned.get(), 0);
    try testing.expect(first.accepted and first.resumed and first.keys_match);

    // An attacker replays one captured ClientHello (byte-identical, so the
    // same binder) to a second server instance sharing the guard: the first
    // copy gets 0-RTT, the replay is rejected but still resumes at 1-RTT.
    var client = try featClient(alloc, .{ .session = owned.get(), .ticket_age_ms = 5, .offer_early_data = true });
    defer client.deinit();
    try client.startHandshake();
    const ch = try client.takeFlight(.initial);
    defer alloc.free(ch);
    var s1 = try Server.init(alloc, cfg);
    defer s1.deinit();
    try s1.feedCrypto(.initial, ch);
    try testing.expect(s1.earlyDataAccepted());
    try testing.expect(s1.earlyDataReadKeys() != null);
    var s2 = try Server.init(alloc, cfg);
    defer s2.deinit();
    try s2.feedCrypto(.initial, ch);
    try testing.expect(s2.isResumed());
    try testing.expect(!s2.earlyDataAccepted());
    try testing.expect(s2.earlyDataReadKeys() == null);
}

test "quic 0-RTT is off by default, needs a replay guard, and checks ticket age" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var guard: tls_resumption.ReplayGuard = .{};
    const owned = try featIssueSession(alloc, earlyConfig(&fs, &guard));
    // Default config (enable_early_data = false) rejects.
    const off = try featOffer0Rtt(alloc, fs.config(), owned.get(), 0);
    try testing.expect(!off.accepted and off.resumed);
    // Enabled without a guard rejects (fail closed); such a server also mints
    // tickets without the early_data grant.
    var no_guard = fs.config();
    no_guard.enable_early_data = true;
    const ng = try featOffer0Rtt(alloc, no_guard, owned.get(), 1);
    try testing.expect(!ng.accepted and ng.resumed);
    const ng_session = try featIssueSession(alloc, no_guard);
    try testing.expectEqual(@as(u32, 0), ng_session.session.max_early_data_size);
    // A reported age far outside the window rejects.
    const stale = try featOffer0Rtt(alloc, earlyConfig(&fs, &guard), owned.get(), 60_000);
    try testing.expect(!stale.accepted and stale.resumed);
    // A ticket minted without the grant never gets 0-RTT even on an enabled
    // server (the client does not even offer it).
    const plain = try featIssueSession(alloc, fs.config());
    const p = try featOffer0Rtt(alloc, earlyConfig(&fs, &guard), plain.get(), 0);
    try testing.expect(!p.accepted and p.resumed);
}

test "quic 0-RTT is rejected when remembered transport parameters would shrink or ALPN changes (RFC 9000 §7.4.1)" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var guard: tls_resumption.ReplayGuard = .{};
    const cfg = earlyConfig(&fs, &guard);
    const owned = try featIssueSession(alloc, cfg);

    var smaller = cfg;
    smaller.transport_params.initial_max_data = (test_server_params.initial_max_data orelse 0) - 1;
    const r1 = try featOffer0Rtt(alloc, smaller, owned.get(), 0);
    try testing.expect(!r1.accepted and r1.resumed);

    var larger = cfg;
    larger.transport_params.initial_max_data = (test_server_params.initial_max_data orelse 0) + 1;
    const r2 = try featOffer0Rtt(alloc, larger, owned.get(), 1);
    try testing.expect(r2.accepted); // raising a limit is allowed

    var other_alpn = cfg;
    other_alpn.alpn_protocols = &.{ "h3x", "h3" };
    var server = try Server.init(alloc, other_alpn);
    defer server.deinit();
    var client = try featClient(alloc, .{ .alpn_protocols = &.{ "h3x", "h3" }, .session = owned.get(), .ticket_age_ms = 2, .offer_early_data = true });
    defer client.deinit();
    try featPump(alloc, &server, &client);
    try testing.expect(server.isResumed());
    try testing.expect(!server.earlyDataAccepted());
}

test "quic 0-RTT: early_data in ClientHello2 after an HRR aborts (RFC 8446 §4.1.2)" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var guard: tls_resumption.ReplayGuard = .{};
    const cfg = earlyConfig(&fs, &guard);
    const owned = try featIssueSession(alloc, cfg);
    var server = try Server.init(alloc, cfg);
    defer server.deinit();
    var client = try featClient(alloc, .{ .session = owned.get(), .offer_early_data = true, .offer_key_share = false });
    defer client.deinit();
    try client.startHandshake();
    const ch1 = try client.takeFlight(.initial);
    defer alloc.free(ch1);
    try server.feedCrypto(.initial, ch1);
    try testing.expect(server.sentHelloRetryRequest());
    try testing.expect(!server.earlyDataAccepted());
    // Re-send ClientHello1 (which still offers early_data) as ClientHello2.
    try testing.expectError(error.BadHandshake, server.feedCrypto(.initial, ch1));
}

test "quic client rejects a NewSessionTicket advertising a non-QUIC max_early_data_size" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var server = try Server.init(alloc, fs.config());
    defer server.deinit();
    var client = try featClient(alloc, .{});
    defer client.deinit();
    try featPump(alloc, &server, &client);
    var nst: std.ArrayList(u8) = .empty;
    defer nst.deinit(alloc);
    // lifetime 60, age_add 1, nonce [9], ticket [0xaa], ext early_data(16384).
    const body = [_]u8{ 0, 0, 0, 60, 0, 0, 0, 1, 1, 9, 0, 1, 0xaa, 0, 8, 0, 42, 0, 4, 0, 0, 0x40, 0 };
    try writeHandshake(alloc, &nst, .new_session_ticket, &body);
    try testing.expectError(error.BadHandshake, client.feedCrypto(.application, nst.items));
}

test "quic client refuses a full-handshake flight that skips Certificate/CertificateVerify" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var server = try Server.init(alloc, fs.config());
    defer server.deinit();
    var client = try featClient(alloc, .{});
    defer client.deinit();
    try client.startHandshake();
    const ch = try client.takeFlight(.initial);
    defer alloc.free(ch);
    try server.feedCrypto(.initial, ch);
    const s_init = try server.takeFlight(.initial);
    defer alloc.free(s_init);
    const s_hs = try server.takeFlight(.handshake);
    defer alloc.free(s_hs);
    try client.feedCrypto(.initial, s_init);
    // Drop Certificate + CertificateVerify, keep EE + Finished.
    var stripped: std.ArrayList(u8) = .empty;
    defer stripped.deinit(alloc);
    var pos: usize = 0;
    while (pos < s_hs.len) {
        var o: usize = 0;
        const m = parseHandshakeMaybe(s_hs[pos..], &o).?;
        if (m.typ == .encrypted_extensions or m.typ == .finished) try stripped.appendSlice(alloc, m.raw);
        pos += o;
    }
    try testing.expectError(error.BadHandshake, client.feedCrypto(.handshake, stripped.items));
}

test "quic server advertises its stateless_reset_token transport parameter" {
    const alloc = testing.allocator;
    var fs: FeatServer = undefined;
    try fs.init();
    var cfg = fs.config();
    const token: [16]u8 = @splat(0x5e);
    cfg.stateless_reset_token = token;
    var server = try Server.init(alloc, cfg);
    defer server.deinit();
    var client = try featClient(alloc, .{});
    defer client.deinit();
    try featPump(alloc, &server, &client);
    try testing.expectEqualSlices(u8, &token, &(client.peerStatelessResetToken().?));
    const bad = [_]u8{ 0x02, 15 } ++ @as([15]u8, @splat(0));
    try testing.expect(findStatelessResetToken(&bad) == null);
}

test "quic key-update helpers match the SHA-256 quic_tls derivation and roll SHA-384 secrets" {
    const s32: [32]u8 = @splat(0x24);
    var n32: [32]u8 = undefined;
    nextTrafficSecret(&s32, &n32);
    try testing.expectEqualSlices(u8, &quic_tls.nextGenerationSecret(s32), &n32);
    const a = packetKeysFromSecret(.aes128gcm, &s32);
    const b = quic_tls.derivePacketKeys(s32, .aes128gcm);
    try expectPacketKeysEqual(a, b);
    const s48: [48]u8 = @splat(0x48);
    var n48: [48]u8 = undefined;
    nextTrafficSecret(&s48, &n48);
    try testing.expect(!std.mem.eql(u8, &s48, &n48));
    const k0 = packetKeysFromSecret(.aes256gcm, &s48);
    const k1 = keyUpdateDirection(k0, &n48);
    try testing.expect(!std.mem.eql(u8, k0.keyBytes(), k1.keyBytes()));
    try testing.expectEqualSlices(u8, k0.hpBytes(), k1.hpBytes()); // hp never rolls
}
