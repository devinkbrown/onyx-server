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
//! Intentionally deferred (typed-error or out of scope): HelloRetryRequest,
//! 0-RTT / early data, client certificates / mTLS, session resumption /
//! NewSessionTicket, key updates. The connection driver builds on this module.

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
const quic_transport_params = @import("quic_transport_params.zig");
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
/// peer's. Both are the 32-byte SHA-256 secret (the only width the driver's
/// "quic ku" roll supports). `suite` selects the AEAD/header-protection used to
/// re-derive the next-generation packet keys. Read-only snapshot; copying these
/// out does not affect the handshake.
pub const AppTrafficSecrets = struct {
    write: [32]u8,
    read: [32]u8,
    suite: QuicCipherSuite,
};

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
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
    _,
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

    pub fn init(allocator: Allocator, config: Config) Error!Server {
        if (config.cert_chain.len == 0) return error.NoCertificate;
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
        self.transcript.deinit(self.allocator);
        self.recv.deinit(self.allocator);
        self.out_initial.deinit(self.allocator);
        self.out_handshake.deinit(self.allocator);
        self.peer_params_storage.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isComplete(self: *const Server) bool {
        return self.state == .connected;
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
    /// `read` is the peer's (client_ap_secret). Returns null until the
    /// application keys are installed, or for a SHA-384 suite (the
    /// SHA-256 "quic ku" roll used by the driver is only valid for the 32-byte
    /// SHA-256 secrets). This is a pure read-only accessor; it changes no state.
    pub fn appTrafficSecrets(self: *const Server) ?AppTrafficSecrets {
        if (self.application_keys == null) return null;
        const suite = self.suite orelse return null;
        if (suite == .tls_aes_256_gcm_sha384) return null; // SHA-384: see doc
        return .{
            .write = self.server_ap_secret[0..32].*,
            .read = self.client_ap_secret[0..32].*,
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
                try self.recv.appendSlice(self.allocator, data);
                try self.driveClientHello();
            },
            .wait_client_finished => {
                if (level != .handshake) return error.BadState;
                try self.recv.appendSlice(self.allocator, data);
                try self.driveClientFinished();
            },
            .connected => return error.BadState,
        }
    }

    /// Take ownership of all buffered server CRYPTO bytes at `level`. Returns an
    /// empty slice (caller still owns it) when nothing is queued.
    pub fn takeFlight(self: *Server, level: EncryptionLevel) Error![]u8 {
        const buf = switch (level) {
            .initial => &self.out_initial,
            .handshake => &self.out_handshake,
            .application => return self.allocator.alloc(u8, 0),
        };
        return buf.toOwnedSlice(self.allocator);
    }

    // --- ClientHello → server flight -------------------------------------

    fn driveClientHello(self: *Server) Error!void {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(self.recv.items, &off) orelse return; // need more
        if (msg.typ != .client_hello) return error.BadHandshake;
        try self.appendTranscript(msg.raw);
        try self.buildServerFlight(msg.body);
        consumePrefix(&self.recv, off);
        self.state = .wait_client_finished;
    }

    fn buildServerFlight(self: *Server, client_hello_body: []const u8) Error!void {
        const shared = try self.processClientHello(client_hello_body);
        const suite = self.suite orelse return error.UnsupportedCipherSuite;

        // ServerHello (Initial level), folded into the transcript.
        try self.writeServerHello(&self.out_initial);

        // Handshake keys derive over CH + SH. The (EC)DHE secret is 32 bytes for
        // a classical group or 64 for the X25519MLKEM768 hybrid.
        try self.deriveAndInstallHandshakeKeys(shared.buf[0..shared.len], suite);

        // The encrypted flight (Handshake level): EncryptedExtensions,
        // Certificate, CertificateVerify, Finished — concatenated raw.
        try self.writeEncryptedExtensions(&self.out_handshake);
        try self.writeCertificate(&self.out_handshake);
        try self.writeCertificateVerify(&self.out_handshake);
        try self.writeServerFinished(&self.out_handshake);

        // Application keys derive over CH..server Finished.
        try self.deriveAndInstallApplicationKeys(suite);
    }

    fn processClientHello(self: *Server, body: []const u8) Error!KexShared {
        var c = Cursor.init(body);
        if (try c.readU16() != legacy_version) return error.ProtocolVersion;
        _ = try c.take(32); // client random (unused by the key schedule)
        _ = try c.take(try c.readU8()); // legacy_session_id (QUIC: MUST be empty, ignored)

        const suites_block = try c.take(try c.readU16());
        const suite = pickSuite(suites_block) orelse return error.UnsupportedCipherSuite;

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
        var have_params = false;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            switch (ext.ext_type) {
                @intFromEnum(tls_extension.ExtensionType.supported_versions) => {
                    if (tls_supported_versions.clientOffers(ext.data, tls_supported_versions.tls13)) offered_tls13 = true;
                },
                @intFromEnum(tls_extension.ExtensionType.key_share) => {
                    var shares = tls_keyshare.parseClientShares(ext.data) catch continue;
                    while (shares.next() catch null) |entry| {
                        if (entry.group == .x25519 and entry.key_exchange.len == kx.X25519Kx.public_len) {
                            if (x25519_share == null) x25519_share = entry.key_exchange;
                        } else if (entry.group == .x25519mlkem768 and entry.key_exchange.len == hybrid_client_share_len) {
                            if (hybrid_share == null) hybrid_share = entry.key_exchange;
                        }
                    }
                },
                @intFromEnum(tls_extension.ExtensionType.alpn) => self.maybeSelectAlpn(ext.data),
                quic_transport_parameters_ext => {
                    try self.capturePeerParams(ext.data);
                    have_params = true;
                },
                else => {},
            }
        }

        if (!offered_tls13) return error.ProtocolVersion;
        if (!have_params) return error.MissingExtension;
        self.suite = suite;

        // Prefer classical X25519; fall back to the X25519MLKEM768 hybrid (offered
        // as the sole QUIC key_share by modern Chrome/Edge).
        if (x25519_share) |peer| {
            self.selected_group = .x25519;
            var peer_pub: kx.PublicKey = undefined;
            @memcpy(&peer_pub, peer);
            var secret = kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer_pub) catch return error.BadHandshake;
            defer secret.wipe();
            var out = KexShared{ .len = 32 };
            const ss = secret.declassify();
            @memcpy(out.buf[0..32], &ss);
            return out;
        }
        if (hybrid_share) |peer| {
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
        }
        return error.UnsupportedGroup;
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
        try appendU16(self.allocator, &body, @intFromEnum(suite));
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

        // The server's quic_transport_parameters (mandatory in EE for QUIC).
        var tp_body: std.ArrayList(u8) = .empty;
        defer tp_body.deinit(self.allocator);
        try quic_transport_params.encode(&tp_body, self.allocator, self.config.transport_params);
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
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ed25519));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, &sig);
            },
            .ecdsa_p256 => |key| {
                const sig = ecdsa_p256.sign(input, key) catch return error.SignatureFailed;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = ecdsa_p256.signatureToDer(sig, &der_buf) catch return error.SignatureFailed;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256));
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
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.rsa_pss_rsae_sha256));
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
        if (!self.finishedVerify(&self.client_hs_secret, msg.body)) return error.FinishedMismatch;
        // The client Finished is NOT folded into the transcript the server uses
        // for its own outputs; the handshake is complete once verified.
        consumePrefix(&self.recv, off);
        self.state = .connected;
    }

    // --- key schedule + transcript ---------------------------------------

    fn deriveAndInstallHandshakeKeys(self: *Server, shared_secret: []const u8, suite: CipherSuite) Error!void {
        switch (suite) {
            .tls_aes_256_gcm_sha384 => try self.deriveHandshakeKeysT(Sha384, suite, shared_secret),
            else => try self.deriveHandshakeKeysT(Sha256, suite, shared_secret),
        }
    }

    fn deriveHandshakeKeysT(self: *Server, comptime KS: type, suite: CipherSuite, shared_secret: []const u8) Error!void {
        var early = KS.earlySecret("");
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
        if (v == @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256)) return .tls_aes_128_gcm_sha256;
        if (v == @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384)) has_aes256 = true;
        if (v == @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256)) has_chacha = true;
    }
    if (has_aes256) return .tls_aes_256_gcm_sha384;
    if (has_chacha) return .tls_chacha20_poly1305_sha256;
    return null;
}

fn writeHandshake(allocator: Allocator, out: *std.ArrayList(u8), typ: HandshakeType, body: []const u8) Error!void {
    if (body.len > 0x00ff_ffff) return error.BadHandshake;
    try out.append(allocator, @intFromEnum(typ));
    try appendU24(allocator, out, body.len);
    try out.appendSlice(allocator, body);
}

/// Parse one handshake message, or null when fewer than a whole message is
/// buffered. Fully bounds-checked: a declared length overrunning the buffer
/// returns null (wait for more) rather than reading out of bounds.
fn parseHandshakeMaybe(input: []const u8, offset: *usize) ?HandshakeMsg {
    if (input.len < 4) return null;
    const len = (@as(usize, input[1]) << 16) | (@as(usize, input[2]) << 8) | input[3];
    const body_end = 4 + len;
    if (input.len < body_end) return null;
    const typ: HandshakeType = @enumFromInt(input[0]);
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
        if (buf[pos] == @intFromEnum(HandshakeType.finished)) return true;
        pos = end;
    }
    return false;
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
        return .{
            .allocator = allocator,
            .x25519_pair = kx.X25519Kx.generateDeterministic(seed) catch return error.BadState,
            .client_random = random,
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
        };
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
    /// `read` is the peer's (server_ap_secret). See `Server.appTrafficSecrets`
    /// for the SHA-384 caveat. Pure read-only accessor.
    pub fn appTrafficSecrets(self: *const Client) ?AppTrafficSecrets {
        if (self.application_keys == null) return null;
        const suite = self.suite orelse return null;
        if (suite == .tls_aes_256_gcm_sha384) return null; // SHA-384: see doc
        return .{
            .write = self.client_ap_secret[0..32].*,
            .read = self.server_ap_secret[0..32].*,
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
                try self.recv_initial.appendSlice(self.allocator, data);
                var off: usize = 0;
                if (parseHandshakeMaybe(self.recv_initial.items, &off) == null) return;
                self.feedInitial(self.recv_initial.items[0..off]) catch |e| return mapClientError(e);
                consumePrefix(&self.recv_initial, off);
            },
            .handshake => {
                if (self.hs_done) return;
                try self.recv_handshake.appendSlice(self.allocator, data);
                // Need the entire server flight (through Finished) buffered. Scan
                // for a Finished message; until it arrives, wait for more.
                if (!flightHasFinished(self.recv_handshake.items)) return;
                var cfin = self.feedHandshake(self.recv_handshake.items) catch |e| return mapClientError(e);
                defer cfin.deinit(self.allocator);
                try self.out_handshake.appendSlice(self.allocator, cfin.items);
                self.recv_handshake.clearRetainingCapacity();
                self.hs_done = true;
            },
            .application => return error.BadState,
        }
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

    /// Build the ClientHello CRYPTO bytes (Initial level). Offers all three
    /// suites by default so the server picks per its preference.
    fn start(self: *Client) !std.ArrayList(u8) {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU16(self.allocator, &body, legacy_version);
        try body.appendSlice(self.allocator, &self.client_random);
        try body.append(self.allocator, 0); // legacy_session_id: empty

        // cipher_suites: all three.
        try appendU16(self.allocator, &body, 6);
        try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
        try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384));
        try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256));

        try body.append(self.allocator, 1); // legacy_compression_methods len
        try body.append(self.allocator, 0); // null

        // extensions
        var ext_storage: [1024]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        var sv_buf: [8]u8 = undefined;
        try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildClient(&sv_buf, &.{tls_supported_versions.tls13}));
        var ks_inner: [64]u8 = undefined;
        const ks = try tls_keyshare.buildClientShares(&ks_inner, &.{.{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key }});
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
        try body.appendSlice(self.allocator, try ext_builder.finish());

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try writeHandshake(self.allocator, &out, .client_hello, body.items);
        try self.transcript.appendSlice(self.allocator, out.items);
        return out;
    }

    /// Process the server's Initial-level flight (just ServerHello).
    fn feedInitial(self: *Client, data: []const u8) !void {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(data, &off) orelse return error.BadHandshake;
        if (msg.typ != .server_hello) return error.BadHandshake;
        try self.transcript.appendSlice(self.allocator, msg.raw);
        const shared = try self.parseServerHello(msg.body);
        try self.installHandshakeKeys(shared);
    }

    /// Process the server's Handshake-level flight (EE, Cert, CertVerify,
    /// Finished). Verifies CertificateVerify + Finished. Returns the client
    /// Finished CRYPTO bytes (Handshake level).
    fn feedHandshake(self: *Client, data: []const u8) !std.ArrayList(u8) {
        var pos: usize = 0;
        while (true) {
            var off: usize = 0;
            const msg = parseHandshakeMaybe(data[pos..], &off) orelse break;
            switch (msg.typ) {
                .encrypted_extensions => {
                    try self.parseEncryptedExtensions(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                },
                .certificate => {
                    try self.parseCertificate(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                },
                .certificate_verify => {
                    try self.verifyCertificateVerify(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                },
                .finished => {
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
        self.done = true;
        return out;
    }

    fn parseServerHello(self: *Client, body: []const u8) ![32]u8 {
        var c = Cursor.init(body);
        if (try c.readU16() != legacy_version) return error.ProtocolVersion;
        _ = try c.take(32); // server random
        _ = try c.take(try c.readU8()); // session id echo
        const suite_wire = try c.readU16();
        self.suite = switch (suite_wire) {
            0x1301 => .tls_aes_128_gcm_sha256,
            0x1302 => .tls_aes_256_gcm_sha384,
            0x1303 => .tls_chacha20_poly1305_sha256,
            else => return error.UnsupportedCipherSuite,
        };
        _ = try c.readU8(); // compression
        const ext_block = try c.take(try c.readU16());
        var it = tls_extension.Iterator.init(ext_block);
        var peer_share: ?[]const u8 = null;
        while (try it.next()) |ext| {
            if (ext.ext_type == @intFromEnum(tls_extension.ExtensionType.key_share)) {
                const entry = try tls_keyshare.parseServerShare(ext.data);
                if (entry.group == .x25519 and entry.key_exchange.len == kx.X25519Kx.public_len) peer_share = entry.key_exchange;
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
        while (try it.next()) |ext| {
            if (ext.ext_type == @intFromEnum(tls_extension.ExtensionType.alpn)) {
                var names = tls_alpn.Iterator.fromBlock(ext.data) catch continue;
                if (names.next() catch null) |proto| {
                    if (proto.len <= self.selected_alpn_storage.len) {
                        @memcpy(self.selected_alpn_storage[0..proto.len], proto);
                        self.selected_alpn = self.selected_alpn_storage[0..proto.len];
                    }
                }
            } else if (ext.ext_type == quic_transport_parameters_ext) {
                self.peer_params_storage.clearRetainingCapacity();
                try self.peer_params_storage.appendSlice(self.allocator, ext.data);
                self.peer_params = try quic_transport_params.decode(self.peer_params_storage.items);
            }
        }
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
        if (scheme != @intFromEnum(tls_signature_scheme.SignatureScheme.ed25519)) return error.BadHandshake;
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
        var early = KS.earlySecret("");
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
    try appendU16(alloc, &body, @intFromEnum(only));
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
    try appendU16(alloc, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
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
    try appendU16(alloc, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
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
        if (ext.ext_type == @intFromEnum(tls_extension.ExtensionType.key_share)) {
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
