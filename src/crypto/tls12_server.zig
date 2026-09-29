// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socketless TLS 1.2 server handshake state machine.
//!
//! The server is intentionally fail-closed: TLS 1.2 only, null compression,
//! secp256r1 ECDHE, ECDSA-P256 or RSA ServerKeyExchange signing, and the AEAD
//! suites listed in `tls12.zig`. The caller feeds raw record bytes and writes
//! returned flights; application records use `encrypt()` / `decrypt()` after
//! `handshakeDone()`.

const std = @import("std");
const builtin = @import("builtin");

const tls12 = @import("tls12.zig");
const tls12_client = @import("tls12_client.zig");
const tls_server = @import("tls_server.zig");
const tls_record = @import("tls_record.zig");
const tls_resumption = @import("tls_resumption.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_sign = @import("rsa_sign.zig");
const rsa_verify = @import("rsa_verify.zig");
const x509 = @import("x509.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");

const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const named_group_secp256r1: u16 = 0x0017;
const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;
const sig_rsa_pkcs1_sha256: u16 = 0x0401;

/// RFC 5077 SessionTicket extension type.
const ext_session_ticket: u16 = 0x0023;

/// RFC 7627 extended_master_secret extension type (always empty).
const ext_extended_master_secret: u16 = 0x0017;

/// RFC 7507 TLS_FALLBACK_SCSV pseudo cipher-suite value.
const suite_fallback_scsv: u16 = 0x5600;

/// Domain tag stamped into the first 4 bytes of the AEAD-sealed ticket_nonce of
/// every TLS 1.2 ticket this server issues. Tickets are only ever minted for
/// EMS-negotiated sessions (see `issuingTicket`), so on resume the tag proves —
/// under the ticket AEAD, unforgeably — that the original session used the
/// extended master secret (RFC 7627 §5.3). Tickets sealed by older builds lack
/// the tag and silently fall back to a full handshake.
const tls12_ems_ticket_tag = [4]u8{ 'E', 'M', '1', '2' };

/// RFC 8446 §4.1.3 downgrade-protection sentinel ("DOWNGRD" + 0x01). A server
/// that supports TLS 1.3 but negotiates TLS 1.2 MUST stamp the last 8 bytes of
/// ServerHello.random with this value. This daemon ALWAYS supports TLS 1.3 (the
/// 1.2 engine is only a fallback), so every 1.2 ServerHello carries it. A
/// genuine TLS 1.3 client whose supported_versions was stripped by a MITM sees
/// the sentinel and aborts the forced downgrade; the value is additionally
/// covered by the ServerKeyExchange signature over both randoms, so an active
/// attacker cannot rewrite it undetected.
pub const tls13_downgrade_sentinel = [8]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };

pub const Error = tls12.Error || ecdh_p256.EcdhError || ecdsa_p256.DerError ||
    Allocator.Error || error{
    BadHandshake,
    BadState,
    EmsRequired,
    FinishedMismatch,
    InappropriateFallback,
    NoCertificate,
    NoSigningKey,
    ProtocolVersion,
    TlsAlert,
    UnsupportedCipherSuite,
    UnsupportedGroup,
    EntropyUnavailable,
};

pub const Config = struct {
    /// DER certificates, leaf first.
    cert_chain: []const []const u8,
    /// ECDSA-P256 leaf key. TLS 1.2 ServerKeyExchange is signed with
    /// ecdsa_secp256r1_sha256.
    ecdsa_p256_signing_key: ?ecdsa_p256.KeyPair = null,
    /// RSA leaf key. TLS 1.2 ServerKeyExchange is signed with
    /// rsa_pkcs1_sha256, and an ECDHE_RSA AEAD suite is selected.
    rsa_signing_key: ?rsa_sign.PrivateKey = null,
    /// ALPN protocols in server preference order.
    alpn_protocols: []const []const u8 = &.{},
    /// Mutual TLS: when true the server sends a CertificateRequest and, if the
    /// client presents a cert, verifies its CertificateVerify possession proof
    /// and exposes the leaf via `clientCertDer()` (for certfp / SASL EXTERNAL).
    /// A client that declines (empty Certificate) still completes the handshake;
    /// `clientCertDer()` stays null. Only rsa_pkcs1_sha256 and
    /// ecdsa_secp256r1_sha256 client signatures are accepted (RFC 5246 §7.4.8).
    request_client_cert: bool = false,

    /// RFC 7627 Extended Master Secret policy. REQUIRED by default in this
    /// hardened profile: a ClientHello that does not offer the
    /// extended_master_secret extension aborts with `EmsRequired` — there is no
    /// silent fallback to the classic (Triple-Handshake-exposed) derivation.
    /// Set false only for legacy interop; even then EMS is negotiated and used
    /// whenever the client offers it, and session tickets are issued/resumed
    /// ONLY for EMS sessions (RFC 7627 §5.3).
    require_extended_master_secret: bool = true,

    // ---- RFC 5077 stateless session resumption (opt-in) ----
    //
    // OFF by default: when `enable_session_tickets` is false the server never
    // echoes a SessionTicket extension, never emits a NewSessionTicket, and
    // only ever runs a full handshake — byte-identical to a build without this
    // feature. On ANY ticket problem (absent, malformed, bad AEAD tag, expired,
    // replayed, or tickets disabled) the server silently falls back to a full
    // handshake; a ticket never fails the connection.

    /// Issue a NewSessionTicket on full handshakes (when the client offered an
    /// empty SessionTicket extension) and accept presented tickets for an
    /// abbreviated handshake. Requires `ticket_key`.
    enable_session_tickets: bool = false,
    /// AEAD key sealing/opening ticket blobs. Shared with the TLS 1.3 leg so a
    /// successor process resumes either. Required when tickets are enabled.
    ticket_key: ?tls_resumption.TicketKey = null,
    /// Optional PREVIOUS ticket key retained across a rotation (see the TLS 1.3
    /// `Config.previous_ticket_key`): new tickets seal under `ticket_key`; on
    /// open, a ticket failing under the current key is retried under this one.
    previous_ticket_key: ?tls_resumption.TicketKey = null,
    /// DER OCSPResponse to staple via CertificateStatus (RFC 6066) when the
    /// client offers status_request. Empty = no staple (byte-identical wire).
    ocsp_staple: []const u8 = &.{},
    /// Single-use guard against ticket replay. Shared with the TLS 1.3 leg.
    replay_guard: ?*tls_resumption.ReplayGuard = null,
    /// Wall-clock seconds at handshake time (the crypto layer takes no clock).
    /// Stamps issued tickets and bounds the accepted-ticket lifetime window.
    now_unix_seconds: i64 = 0,
    /// Lifetime advertised in NewSessionTicket and enforced on resume.
    ticket_lifetime_seconds: u32 = 7200,
};

pub const FeedResult = union(enum) {
    need_more,
    bytes_to_send: []u8,
};

const State = enum {
    wait_client_hello,
    // Full handshake with mTLS: the client's Certificate precedes its
    // ClientKeyExchange, and (when a cert was presented) a CertificateVerify
    // follows it. These two states are only entered when request_client_cert.
    wait_client_certificate,
    wait_client_certificate_verify,
    // Full handshake: ClientKeyExchange, then client CCS + Finished.
    wait_client_key_exchange,
    wait_client_ccs,
    wait_client_finished,
    // Abbreviated (RFC 5077 resumed) handshake: no ClientKeyExchange. The
    // server sends its flight first, then waits for the client CCS + Finished.
    wait_resumed_client_ccs,
    wait_resumed_client_finished,
    connected,
};

const CertificateAuth = enum {
    ecdsa_p256,
    rsa,
};

/// Public key parsed from a presented client leaf, used to verify the TLS 1.2
/// CertificateVerify possession proof. The rsa `n`/`e` slices borrow the owned
/// `client_cert_der`, which is held for the connection's lifetime.
const ClientLeafKey = union(enum) {
    ecdsa_p256: ecdsa_p256.PublicKey,
    rsa: rsa_verify.PublicKey,
};

const HandshakeMsg = struct {
    typ: tls12.HandshakeType,
    body: []const u8,
    raw: []const u8,
};

pub const Server = struct {
    allocator: Allocator,
    config: Config,
    state: State = .wait_client_hello,

    recv_buf: std.ArrayList(u8) = .empty,
    transcript: std.ArrayList(u8) = .empty,

    key_pair: ecdh_p256.KeyPair,
    client_random: [32]u8 = @splat(0),
    server_random: [32]u8,
    session_id: [32]u8 = @splat(0),
    session_id_len: usize = 0,
    /// The client offered status_request (wants an OCSP staple).
    client_requested_ocsp: bool = false,
    /// The client offered the RFC 7627 extended_master_secret extension.
    client_offered_ems: bool = false,
    /// EMS was negotiated: the ServerHello echoes the (empty) extension and the
    /// master secret is derived from the session hash instead of the randoms.
    /// Always equal to `client_offered_ems` — the server never declines EMS.
    ems_negotiated: bool = false,
    selected_suite: ?tls12.CipherSuite = null,
    selected_alpn: ?[]u8 = null,
    /// RFC 8449 record_size_limit advertised by the client: the max
    /// TLSPlaintext.fragment it will accept. Default 2^14+1 = "no restriction
    /// beyond the protocol max". Outbound application records are fragmented to
    /// honor it (see `encrypt`).
    peer_record_size_limit: usize = tls_record.max_plaintext_len + 1,
    /// The client offered a record_size_limit extension. Only then does the
    /// ServerHello echo the server's own limit (RFC 8446 §4.2: a server extension
    /// must be solicited), which also keeps the wire byte-identical for peers
    /// that never send it.
    client_offered_record_size_limit: bool = false,

    // ---- mTLS (only meaningful when config.request_client_cert) ----
    /// Owned copy of the presented client leaf DER, or null if the client
    /// declined or no cert was requested. Set only AFTER its CertificateVerify
    /// possession proof verifies; a failed proof clears it.
    client_cert_der: ?[]u8 = null,
    /// Public key parsed from `client_cert_der`, used to verify CertificateVerify.
    client_leaf_key: ?ClientLeafKey = null,

    // ---- RFC 5077 ticket negotiation (only meaningful when tickets enabled) ----
    /// The client sent an EMPTY SessionTicket extension: it supports tickets and
    /// wants the server to issue one on a full handshake.
    client_offered_empty_ticket: bool = false,
    /// Copy of a non-empty SessionTicket the client presented to resume. Owned;
    /// freed on deinit. Held across `parseClientHello` so the resume decision can
    /// be made after extension parsing completes.
    presented_ticket: ?[]u8 = null,
    /// True once a presented ticket opened, validated, and was accepted: the
    /// handshake takes the abbreviated path and the master_secret/suite come
    /// from the ticket rather than a fresh ECDHE exchange.
    resuming: bool = false,
    /// Raw offered cipher-suite octets from the ClientHello (aliases the live
    /// recv buffer for the duration of the ClientHello processing only). Used by
    /// the resume path to confirm the ticket's suite was actually offered.
    offered_suites: []const u8 = &.{},

    master_secret: [tls12.master_secret_len]u8 = @splat(0),
    keys: tls12.KeyMaterial = .{},
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,
    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,

    pub fn init(allocator: Allocator, config: Config) Error!Server {
        if (config.cert_chain.len == 0) return error.NoCertificate;
        if (activeCertificateAuth(config) == null) return error.NoSigningKey;
        var random: [32]u8 = undefined;
        try osEntropy(&random);
        // RFC 8446 §4.1.3 downgrade protection: this daemon always supports TLS
        // 1.3, so every ServerHello the 1.2 engine emits (full or resumed — both
        // reuse this server_random) must carry the "DOWNGRD\x01" sentinel in the
        // last 8 bytes of the 32-byte random. Stamp it here so it is present
        // wherever server_random is written to the wire and signed into the
        // ServerKeyExchange.
        @memcpy(random[24..32], &tls13_downgrade_sentinel);
        return .{
            .allocator = allocator,
            .config = config,
            .key_pair = try ecdh_p256.generate(),
            .server_random = random,
        };
    }

    pub fn deinit(self: *Server) void {
        self.recv_buf.deinit(self.allocator);
        self.transcript.deinit(self.allocator);
        if (self.selected_alpn) |p| self.allocator.free(p);
        if (self.presented_ticket) |t| self.allocator.free(t);
        if (self.client_cert_der) |d| self.allocator.free(d);
        std.crypto.secureZero(u8, &self.key_pair.secret);
        std.crypto.secureZero(u8, &self.master_secret);
        self.keys.wipe();
    }

    pub fn handshakeDone(self: *const Server) bool {
        return self.state == .connected;
    }

    /// A fatal TLS alert (RFC 5246 §7.2) to send for the handshake error `err`
    /// BEFORE closing, so the peer learns why instead of seeing a bare reset. The
    /// §6 AlertDescription mapping is shared with the TLS 1.3 leg
    /// (`tls_server.alertDescriptionForError`); the record encoding depends on
    /// whether the server has already sent its ChangeCipherSpec:
    ///   * Full-handshake wait states + the initial ClientHello wait
    ///     (`wait_client_hello`, `wait_client_certificate`,
    ///     `wait_client_certificate_verify`, `wait_client_key_exchange`,
    ///     `wait_client_ccs`, `wait_client_finished`) — the server's CCS is only
    ///     emitted in its final flight (which advances straight to `connected`),
    ///     so its write is still in the clear ⇒ a PLAINTEXT alert (content_type 21).
    ///   * Resumed/abbreviated wait states (`wait_resumed_client_ccs`,
    ///     `wait_resumed_client_finished`) — the server already sent CCS +
    ///     Finished in `buildResumedServerFlight`, so its write cipher is active
    ///     ⇒ the alert is sealed under `keys.server_write` at the next-unused
    ///     write seq (`hs_write_seq`), which is then bumped so the nonce is never
    ///     reused.
    ///   * `connected` — a post-handshake record fault is out of this path's
    ///     scope ⇒ null (bare close). Caller owns the returned buffer.
    pub fn takeAlert(self: *Server, err: anyerror) ?[]u8 {
        const desc = tls_server.alertDescriptionForError(err) orelse return null;
        const body = [_]u8{ @intFromEnum(tls_server.AlertLevel.fatal), @intFromEnum(desc) };
        switch (self.state) {
            .wait_resumed_client_ccs, .wait_resumed_client_finished => {
                const suite = self.selected_suite orelse return null;
                const rec = tls12.sealRecordAlloc(self.allocator, suite, &self.keys.server_write, self.hs_write_seq, .alert, &body) catch return null;
                self.hs_write_seq += 1;
                return rec;
            },
            .wait_client_hello,
            .wait_client_certificate,
            .wait_client_certificate_verify,
            .wait_client_key_exchange,
            .wait_client_ccs,
            .wait_client_finished,
            => return tls12.writePlainRecord(self.allocator, .alert, &body) catch null,
            .connected => return null,
        }
    }

    /// The presented client leaf DER whose CertificateVerify possession proof
    /// verified (mTLS), or null. Mirrors the TLS 1.3 engine's accessor.
    pub fn clientCertDer(self: *const Server) ?[]const u8 {
        return self.client_cert_der;
    }

    pub fn selectedAlpn(self: *const Server) ?[]const u8 {
        return if (self.selected_alpn) |p| p else null;
    }

    /// IANA name of the negotiated cipher suite, or null before the ClientHello
    /// selects one. The returned string is static.
    pub fn cipherName(self: *const Server) ?[]const u8 {
        const suite = self.selected_suite orelse return null;
        return suite.name();
    }

    pub fn feed(self: *Server, received: []const u8) Error!FeedResult {
        if (self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);
        while (true) {
            const rec = (try tls12.completeRecord(self.recv_buf.items)) orelse return .need_more;
            switch (self.state) {
                .wait_client_hello => {
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(rec.fragment, &off);
                    if (off != rec.fragment.len or msg.typ != .client_hello) return error.BadHandshake;
                    try self.parseClientHello(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    // A presented ticket that opens, validates, and is not
                    // replayed switches to the abbreviated flow; any failure
                    // (handled inside tryResume) falls back to a full handshake.
                    self.resuming = self.tryResume();
                    if (self.resuming) {
                        const reply = try self.buildResumedServerFlight();
                        consumePrefix(&self.recv_buf, rec.wire_len);
                        self.state = .wait_resumed_client_ccs;
                        return .{ .bytes_to_send = reply };
                    }
                    const reply = try self.buildServerFlight();
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = if (self.config.request_client_cert) .wait_client_certificate else .wait_client_key_exchange;
                    return .{ .bytes_to_send = reply };
                },
                .wait_client_certificate => {
                    // mTLS: the client's Certificate precedes its ClientKeyExchange.
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(rec.fragment, &off);
                    if (off != rec.fragment.len or msg.typ != .certificate) return error.BadHandshake;
                    try self.parseClientCertificate(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_client_key_exchange;
                },
                .wait_client_key_exchange => {
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(rec.fragment, &off);
                    if (off != rec.fragment.len or msg.typ != .client_key_exchange) return error.BadHandshake;
                    // RFC 7627: the session hash covers ClientHello THROUGH
                    // ClientKeyExchange inclusive, so the CKE must be in the
                    // transcript BEFORE the master secret is derived.
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    try self.parseClientKeyExchange(msg.body);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    // A presented client cert must prove key possession via
                    // CertificateVerify before CCS; a declined cert skips it.
                    self.state = if (self.client_leaf_key != null) .wait_client_certificate_verify else .wait_client_ccs;
                },
                .wait_client_certificate_verify => {
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(rec.fragment, &off);
                    if (off != rec.fragment.len or msg.typ != .certificate_verify) return error.BadHandshake;
                    try self.verifyClientCertificateVerify(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_client_ccs;
                },
                .wait_client_ccs => {
                    if (rec.content_type != .change_cipher_spec or rec.fragment.len != 1 or rec.fragment[0] != 1) return error.BadHandshake;
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_client_finished;
                },
                .wait_client_finished => {
                    const suite = self.selected_suite orelse return error.BadState;
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.client_write, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
                    self.hs_read_seq += 1;
                    defer self.allocator.free(opened.plaintext);
                    if (opened.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(opened.plaintext, &off);
                    if (off != opened.plaintext.len or msg.typ != .finished) return error.BadHandshake;
                    const expected = try tls12.finishedVerifyData(suite, &self.master_secret, "client finished", self.transcript.items);
                    if (!tls12.constantTimeEq(&expected, msg.body)) return error.FinishedMismatch;
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    const reply = try self.buildServerFinishedFlight();
                    // TLS 1.2 keeps ONE record sequence per direction per epoch:
                    // the encrypted Finished is seq 0 and application data continues
                    // from there (first app record is seq 1), it does NOT reset.
                    // Carry the handshake counters into the app counters so we agree
                    // with standards-compliant peers (OpenSSL, browsers); resetting
                    // to 0 only ever interoperated with our own client.
                    self.app_read_seq = self.hs_read_seq;
                    self.app_write_seq = self.hs_write_seq;
                    self.state = .connected;
                    return .{ .bytes_to_send = reply };
                },
                .wait_resumed_client_ccs => {
                    if (rec.content_type != .change_cipher_spec or rec.fragment.len != 1 or rec.fragment[0] != 1) return error.BadHandshake;
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_resumed_client_finished;
                },
                .wait_resumed_client_finished => {
                    // Abbreviated handshake: the server already sent CCS +
                    // Finished, so the only thing left is the client's encrypted
                    // Finished. Verify it over the abbreviated transcript
                    // (ClientHello, ServerHello[, NewSessionTicket], server
                    // Finished) and then the connection is established.
                    const suite = self.selected_suite orelse return error.BadState;
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.client_write, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
                    self.hs_read_seq += 1;
                    defer self.allocator.free(opened.plaintext);
                    if (opened.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(opened.plaintext, &off);
                    if (off != opened.plaintext.len or msg.typ != .finished) return error.BadHandshake;
                    const expected = try tls12.finishedVerifyData(suite, &self.master_secret, "client finished", self.transcript.items);
                    if (!tls12.constantTimeEq(&expected, msg.body)) return error.FinishedMismatch;
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    // Same single-sequence-per-epoch carry as the full path.
                    self.app_read_seq = self.hs_read_seq;
                    self.app_write_seq = self.hs_write_seq;
                    self.state = .connected;
                },
                .connected => return error.BadState,
            }
        }
    }

    pub fn encrypt(self: *Server, appdata: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const limit = tls_record.recordContentLimit12(self.peer_record_size_limit);
        if (appdata.len <= limit) {
            const seq = try tls12.reserveAppSeq(self.app_write_seq);
            const out = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.server_write, seq, .application_data, appdata);
            self.app_write_seq += 1;
            return out;
        }
        // RFC 8449: the peer advertised a smaller record_size_limit — fragment the
        // application data into multiple records, each TLSPlaintext.fragment within
        // its limit, and return them concatenated (one record per fragment, seq
        // bumped per record).
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        var off: usize = 0;
        while (off < appdata.len) {
            const n = @min(limit, appdata.len - off);
            const seq = try tls12.reserveAppSeq(self.app_write_seq);
            const rec = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.server_write, seq, .application_data, appdata[off .. off + n]);
            defer self.allocator.free(rec);
            try buf.appendSlice(self.allocator, rec);
            self.app_write_seq += 1;
            off += n;
        }
        return buf.toOwnedSlice(self.allocator);
    }

    pub fn decrypt(self: *Server, record: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const seq = try tls12.reserveAppSeq(self.app_read_seq);
        const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.client_write, seq, record);
        self.app_read_seq += 1;
        errdefer self.allocator.free(opened.plaintext);
        if (opened.content_type == .alert) return error.TlsAlert;
        if (opened.content_type != .application_data) return error.BadHandshake;
        return opened.plaintext;
    }

    /// Everything a successor process needs to keep driving an ESTABLISHED
    /// hardened TLS 1.2 connection: the negotiated suite, the derived directional
    /// AEAD key material, and the live record sequence numbers. There is no
    /// post-handshake re-keying in this profile, so the master secret and
    /// handshake transcript are deliberately NOT carried.
    pub const ResumeState = struct {
        suite: u16,
        keys: tls12.KeyMaterial,
        app_read_seq: u64,
        app_write_seq: u64,
    };

    /// Capture the connected-state snapshot for a Helix live upgrade. Only valid
    /// once the handshake completed; the key material in the returned struct is
    /// sensitive and must be handled accordingly by the caller.
    pub fn exportResume(self: *const Server) Error!ResumeState {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        return .{
            .suite = @intFromEnum(suite),
            .keys = self.keys,
            .app_read_seq = self.app_read_seq,
            .app_write_seq = self.app_write_seq,
        };
    }

    /// Successor side of a Helix live upgrade: rebuild a CONNECTED server from an
    /// exported `ResumeState`. The handshake machinery is never re-entered.
    pub fn resumeConnected(allocator: Allocator, config: Config, st: ResumeState) Error!Server {
        var self = try Server.init(allocator, config);
        errdefer self.deinit();
        self.selected_suite = tls12.CipherSuite.fromWire(st.suite) catch return error.UnsupportedCipherSuite;
        self.keys = st.keys;
        self.app_read_seq = st.app_read_seq;
        self.app_write_seq = st.app_write_seq;
        self.state = .connected;
        return self;
    }

    fn parseClientHello(self: *Server, body: []const u8) Error!void {
        var c = Cursor.init(body);
        if (try c.readU16() != tls12.tls_version) return error.ProtocolVersion;
        @memcpy(&self.client_random, try c.take(32));
        self.session_id_len = try c.readU8();
        if (self.session_id_len > self.session_id.len) return error.BadHandshake;
        @memcpy(self.session_id[0..self.session_id_len], try c.take(self.session_id_len));
        const suites_bytes = try c.take(try c.readU16());
        self.offered_suites = suites_bytes;
        const comp = try c.take(try c.readU8());
        if (comp.len != 1 or comp[0] != 0) return error.BadHandshake;

        const auth = activeCertificateAuth(self.config) orelse return error.NoSigningKey;
        var selected: ?tls12.CipherSuite = null;
        var s = Cursor.init(suites_bytes);
        while (s.remaining() != 0) {
            const wire = try s.readU16();
            // RFC 7507: TLS_FALLBACK_SCSV in a 1.2 ClientHello signals a client
            // that downgraded from a higher offer. This daemon always supports
            // TLS 1.3 (the 1.2 engine is a fallback), so the fallback is
            // inappropriate and MUST abort with inappropriate_fallback.
            if (wire == suite_fallback_scsv) return error.InappropriateFallback;
            const suite = tls12.CipherSuite.fromWire(wire) catch continue;
            if (!suiteMatchesAuth(suite, auth)) continue;
            if (selected == null) selected = suite;
        }
        self.selected_suite = selected orelse return error.UnsupportedCipherSuite;

        if (c.remaining() != 0) {
            const ext_len = try c.readU16();
            const exts = try c.take(ext_len);
            try self.parseClientExtensions(exts);
        }
        try c.expectEmpty();

        // RFC 7627: the hardened profile requires the extended master secret;
        // this fires whether the extension was absent from the list or the
        // ClientHello carried no extensions block at all. When the operator
        // loosened the requirement, EMS is still used whenever offered.
        if (self.config.require_extended_master_secret and !self.client_offered_ems) {
            return error.EmsRequired;
        }
        self.ems_negotiated = self.client_offered_ems;
    }

    fn parseClientExtensions(self: *Server, bytes: []const u8) Error!void {
        var saw_p256 = false;
        var c = Cursor.init(bytes);
        while (c.remaining() != 0) {
            const typ = try c.readU16();
            const body = try c.take(try c.readU16());
            switch (typ) {
                0x000a => {
                    var g = Cursor.init(body);
                    const list = try g.take(try g.readU16());
                    var groups = Cursor.init(list);
                    while (groups.remaining() != 0) {
                        if (try groups.readU16() == named_group_secp256r1) saw_p256 = true;
                    }
                    try g.expectEmpty();
                },
                0x0010 => try self.selectAlpn(body),
                0x0005 => self.client_requested_ocsp = true, // status_request (OCSP)
                ext_extended_master_secret => {
                    // RFC 7627: the extension is always empty.
                    if (body.len != 0) return error.BadHandshake;
                    self.client_offered_ems = true;
                },
                0xff01 => {
                    // RFC 5746 §3.6: on the initial handshake the client's
                    // renegotiated_connection MUST be empty (one zero length
                    // byte). Anything else is a renegotiation splice attempt —
                    // and this engine never renegotiates at all.
                    if (body.len != 1 or body[0] != 0) return error.BadHandshake;
                },
                0x001c => {
                    // RFC 8449 record_size_limit: a 2-byte value in [64, 2^14+1];
                    // anything else is illegal_parameter. Store it so our outbound
                    // records honor it and echo our own limit in the ServerHello.
                    if (body.len != 2) return error.BadHandshake;
                    const limit = std.mem.readInt(u16, body[0..2], .big);
                    if (limit < tls_record.record_size_limit_min or limit > tls_record.record_size_limit_max) return error.BadHandshake;
                    self.peer_record_size_limit = limit;
                    self.client_offered_record_size_limit = true;
                },
                ext_session_ticket => {
                    // RFC 5077: only honour the SessionTicket extension when the
                    // feature is enabled and a ticket key is configured. An empty
                    // body means "issue me a ticket"; a non-empty body is the
                    // ticket to resume — copy it so it outlives the ClientHello
                    // buffer (the resume decision runs after parsing).
                    if (self.config.enable_session_tickets and self.config.ticket_key != null) {
                        if (body.len == 0) {
                            self.client_offered_empty_ticket = true;
                        } else {
                            if (self.presented_ticket) |old| self.allocator.free(old);
                            self.presented_ticket = try self.allocator.dupe(u8, body);
                            // A client presenting a ticket also implicitly wants a
                            // fresh one issued if we fall back to a full handshake.
                            self.client_offered_empty_ticket = true;
                        }
                    }
                },
                0x002b => {
                    // supported_versions: real TLS 1.2 clients (OpenSSL, browsers)
                    // include this even when offering 1.2, since they also support
                    // 1.3. The version dispatcher already routed a 1.3-capable
                    // ClientHello (one listing 0x0304) to the 1.3 engine, so here we
                    // only require the list to actually offer TLS 1.2 (0x0303) and
                    // refuse a client that omits it. Rejecting the extension outright
                    // broke every standards-compliant 1.2 client.
                    var sv = Cursor.init(body);
                    const list = try sv.take(try sv.readU8());
                    var v = Cursor.init(list);
                    var offers_12 = false;
                    while (v.remaining() >= 2) {
                        if (try v.readU16() == tls12.tls_version) offers_12 = true;
                    }
                    if (!offers_12) return error.ProtocolVersion;
                },
                else => {},
            }
        }
        if (!saw_p256) return error.UnsupportedGroup;
    }

    fn selectAlpn(self: *Server, body: []const u8) Error!void {
        if (self.config.alpn_protocols.len == 0) return;
        var c = Cursor.init(body);
        const list = try c.take(try c.readU16());
        try c.expectEmpty();
        for (self.config.alpn_protocols) |server_proto| {
            var p = Cursor.init(list);
            while (p.remaining() != 0) {
                const client_proto = try p.take(try p.readU8());
                if (std.mem.eql(u8, server_proto, client_proto)) {
                    const copy = try self.allocator.dupe(u8, server_proto);
                    errdefer self.allocator.free(copy);
                    if (self.selected_alpn) |old| self.allocator.free(old);
                    self.selected_alpn = copy;
                    return;
                }
            }
        }
    }

    fn buildServerFlight(self: *Server) Error![]u8 {
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);

        var sh_body: std.ArrayList(u8) = .empty;
        defer sh_body.deinit(self.allocator);
        try appendU16(self.allocator, &sh_body, tls12.tls_version);
        try sh_body.appendSlice(self.allocator, &self.server_random);
        try sh_body.append(self.allocator, @intCast(self.session_id_len));
        try sh_body.appendSlice(self.allocator, self.session_id[0..self.session_id_len]);
        try appendU16(self.allocator, &sh_body, @intFromEnum(self.selected_suite orelse return error.BadState));
        try sh_body.append(self.allocator, 0);
        var exts: std.ArrayList(u8) = .empty;
        defer exts.deinit(self.allocator);
        // renegotiation_info (RFC 5746): an initial handshake carries an EMPTY
        // renegotiated_connection (a single 0x00 length byte). Clients that
        // enforce secure renegotiation — OpenSSL and browsers do by default —
        // abort with "unsafe legacy renegotiation" if the server omits this, so
        // it must always be present even though we never renegotiate.
        try writeExtension(self.allocator, &exts, 0xff01, &.{0x00});
        // RFC 7627: echo the (empty) extended_master_secret extension whenever
        // the client offered it; the master secret then derives from the
        // session hash (see parseClientKeyExchange).
        if (self.ems_negotiated) try writeExtension(self.allocator, &exts, ext_extended_master_secret, "");
        if (self.selected_alpn) |proto| {
            var alpn_body: [3 + 255]u8 = undefined;
            std.mem.writeInt(u16, alpn_body[0..2], @intCast(1 + proto.len), .big);
            alpn_body[2] = @intCast(proto.len);
            @memcpy(alpn_body[3 .. 3 + proto.len], proto);
            try writeExtension(self.allocator, &exts, 0x0010, alpn_body[0 .. 3 + proto.len]);
        }
        // RFC 5077: when we will issue a ticket, echo an EMPTY SessionTicket
        // extension in ServerHello to announce the upcoming NewSessionTicket.
        if (self.issuingTicket()) try writeExtension(self.allocator, &exts, ext_session_ticket, "");
        // RFC 6066: when we will staple, echo an EMPTY status_request in
        // ServerHello to announce the upcoming CertificateStatus message.
        const do_staple = self.client_requested_ocsp and self.config.ocsp_staple.len != 0;
        if (do_staple) try writeExtension(self.allocator, &exts, 0x0005, "");
        // RFC 8449: only when the client offered record_size_limit, echo the max
        // TLSPlaintext.fragment we accept (full-size records — our recv path
        // handles them). Enforcement of the PEER's limit is on our send path.
        if (self.client_offered_record_size_limit) {
            var rsl_buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &rsl_buf, tls_record.record_size_limit_max, .big);
            try writeExtension(self.allocator, &exts, 0x001c, &rsl_buf);
        }
        try appendU16(self.allocator, &sh_body, @intCast(exts.items.len));
        try sh_body.appendSlice(self.allocator, exts.items);
        try writeHandshake(self.allocator, &hs, .server_hello, sh_body.items);

        var cert_body: std.ArrayList(u8) = .empty;
        defer cert_body.deinit(self.allocator);
        var cert_list: std.ArrayList(u8) = .empty;
        defer cert_list.deinit(self.allocator);
        for (self.config.cert_chain) |der| {
            try appendU24(self.allocator, &cert_list, @intCast(der.len));
            try cert_list.appendSlice(self.allocator, der);
        }
        try appendU24(self.allocator, &cert_body, @intCast(cert_list.items.len));
        try cert_body.appendSlice(self.allocator, cert_list.items);
        try writeHandshake(self.allocator, &hs, .certificate, cert_body.items);

        // RFC 6066: CertificateStatus immediately follows Certificate when
        // stapling. Body = status_type(1=ocsp) || u24 len || OCSPResponse.
        if (do_staple) {
            var cs: std.ArrayList(u8) = .empty;
            defer cs.deinit(self.allocator);
            try cs.append(self.allocator, 1); // status_type = ocsp
            try appendU24(self.allocator, &cs, @intCast(self.config.ocsp_staple.len));
            try cs.appendSlice(self.allocator, self.config.ocsp_staple);
            try writeHandshake(self.allocator, &hs, .certificate_status, cs.items);
        }

        const ske_body = try self.buildServerKeyExchange();
        defer self.allocator.free(ske_body);
        try writeHandshake(self.allocator, &hs, .server_key_exchange, ske_body);
        if (self.config.request_client_cert) {
            const cr_body = try self.buildCertificateRequest();
            defer self.allocator.free(cr_body);
            try writeHandshake(self.allocator, &hs, .certificate_request, cr_body);
        }
        try writeHandshake(self.allocator, &hs, .server_hello_done, "");

        try self.transcript.appendSlice(self.allocator, hs.items);
        // F6: a sizeable cert chain (+ OCSP staple) can exceed the 16 KiB
        // single-record limit; fragment across records rather than erroring.
        return writeFragmentedHandshakeFlight(self.allocator, hs.items);
    }

    /// CertificateRequest (RFC 5246 §7.4.4): certificate_types (rsa_sign +
    /// ecdsa_sign), supported_signature_algorithms (rsa_pkcs1_sha256 +
    /// ecdsa_secp256r1_sha256 — the only client proofs we verify), and an empty
    /// certificate_authorities list.
    fn buildCertificateRequest(self: *Server) Error![]u8 {
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        // certificate_types<1..2^8-1>: 0x40 ecdsa_sign, 0x01 rsa_sign.
        try body.append(self.allocator, 2);
        try body.append(self.allocator, 0x40);
        try body.append(self.allocator, 0x01);
        // supported_signature_algorithms<2..2^16-1>: two 2-byte entries.
        try appendU16(self.allocator, &body, 4);
        try appendU16(self.allocator, &body, sig_ecdsa_secp256r1_sha256);
        try appendU16(self.allocator, &body, sig_rsa_pkcs1_sha256);
        // certificate_authorities<0..2^16-1>: empty.
        try appendU16(self.allocator, &body, 0);
        return body.toOwnedSlice(self.allocator);
    }

    /// Capture the presented client leaf (certfp pins the leaf only). An empty
    /// certificate_list = the client declined; `client_leaf_key` stays null and
    /// the handshake proceeds without client auth.
    fn parseClientCertificate(self: *Server, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const list = try c.take(try c.readU24());
        try c.expectEmpty();
        var certs = Cursor.init(list);
        if (certs.remaining() == 0) return; // declined
        const der = try certs.take(try certs.readU24());
        const leaf = try self.allocator.dupe(u8, der);
        errdefer self.allocator.free(leaf);
        self.client_leaf_key = try clientKeyFromCert(leaf);
        self.client_cert_der = leaf;
    }

    /// Verify the client's CertificateVerify (RFC 5246 §7.4.8): the signature
    /// covers all handshake messages exchanged so far (ClientHello through
    /// ClientKeyExchange — exactly `self.transcript` at this point). A failed
    /// proof clears the captured leaf so no untrusted fingerprint is exposed.
    fn verifyClientCertificateVerify(self: *Server, body: []const u8) Error!void {
        if (body.len < 4) return error.BadHandshake;
        const scheme = std.mem.readInt(u16, body[0..2], .big);
        const sig_len = std.mem.readInt(u16, body[2..4], .big);
        if (body.len != 4 + @as(usize, sig_len)) return error.BadHandshake;
        const sig = body[4..];
        const key = self.client_leaf_key orelse return error.BadHandshake;
        const signed = self.transcript.items;
        switch (key) {
            .ecdsa_p256 => |pk| {
                if (scheme != sig_ecdsa_secp256r1_sha256) return self.failClientCert();
                const decoded = ecdsa_p256.signatureFromDer(sig) catch return self.failClientCert();
                if (!ecdsa_p256.verify(decoded, signed, pk)) return self.failClientCert();
            },
            .rsa => |pk| {
                if (scheme != sig_rsa_pkcs1_sha256) return self.failClientCert();
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(signed, &digest, .{});
                if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, sig)) return self.failClientCert();
            },
        }
    }

    fn failClientCert(self: *Server) Error {
        if (self.client_cert_der) |d| self.allocator.free(d);
        self.client_cert_der = null;
        self.client_leaf_key = null;
        return error.BadHandshake;
    }

    fn buildServerKeyExchange(self: *Server) Error![]u8 {
        var params: [1 + 2 + 1 + ecdh_p256.public_length]u8 = undefined;
        params[0] = 3;
        std.mem.writeInt(u16, params[1..3], named_group_secp256r1, .big);
        params[3] = ecdh_p256.public_length;
        @memcpy(params[4..], &self.key_pair.public_sec1);

        var signed: std.ArrayList(u8) = .empty;
        defer signed.deinit(self.allocator);
        try signed.appendSlice(self.allocator, &self.client_random);
        try signed.appendSlice(self.allocator, &self.server_random);
        try signed.appendSlice(self.allocator, &params);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, &params);
        switch (activeCertificateAuth(self.config) orelse return error.NoSigningKey) {
            .ecdsa_p256 => {
                const sig = ecdsa_p256.sign(signed.items, self.config.ecdsa_p256_signing_key.?) catch return error.BadState;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = try ecdsa_p256.signatureToDer(sig, &der_buf);
                try appendU16(self.allocator, &out, sig_ecdsa_secp256r1_sha256);
                try appendU16(self.allocator, &out, @intCast(der.len));
                try out.appendSlice(self.allocator, der);
            },
            .rsa => {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(signed.items, &digest, .{});
                var sig_buf: [512]u8 = undefined;
                const key = self.config.rsa_signing_key.?;
                const sig = rsa_sign.signPkcs1v15(key, .sha256, &digest, &sig_buf) catch return error.BadState;
                try appendU16(self.allocator, &out, sig_rsa_pkcs1_sha256);
                try appendU16(self.allocator, &out, @intCast(sig.len));
                try out.appendSlice(self.allocator, sig);
            },
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn parseClientKeyExchange(self: *Server, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const point = try c.take(try c.readU8());
        try c.expectEmpty();
        if (point.len != ecdh_p256.public_length) return error.UnsupportedGroup;
        var client_pub: [ecdh_p256.public_length]u8 = undefined;
        @memcpy(&client_pub, point);
        var shared = try ecdh_p256.sharedSecret(self.key_pair.secret, client_pub);
        defer std.crypto.secureZero(u8, &shared);
        const suite = self.selected_suite orelse return error.BadState;
        if (self.ems_negotiated) {
            // RFC 7627: session_hash over the transcript, which the caller has
            // already extended with this ClientKeyExchange message.
            var hash_buf: [tls12.max_hash_len]u8 = undefined;
            const session_hash = tls12.transcriptHash(suite.hashAlg(), self.transcript.items, &hash_buf);
            self.master_secret = try tls12.deriveExtendedMasterSecret(suite, &shared, session_hash);
        } else {
            self.master_secret = try tls12.deriveMasterSecret(suite, &shared, &self.client_random, &self.server_random);
        }
        self.keys = try tls12.deriveKeyMaterial(suite, &self.master_secret, &self.client_random, &self.server_random);
    }

    fn buildServerFinishedFlight(self: *Server) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);

        // RFC 5077 (full handshake + issue): NewSessionTicket is the FIRST
        // message of the server's final flight — a plaintext handshake message
        // before the server CCS. It is hashed into the transcript ahead of the
        // server Finished.
        if (self.issuingTicket()) {
            const nst = try self.buildNewSessionTicket();
            defer self.allocator.free(nst);
            try self.transcript.appendSlice(self.allocator, nst);
            const nst_rec = try writeFragmentedHandshakeFlight(self.allocator, nst);
            defer self.allocator.free(nst_rec);
            try out.appendSlice(self.allocator, nst_rec);
        }

        const verify = try tls12.finishedVerifyData(suite, &self.master_secret, "server finished", self.transcript.items);
        var fin: std.ArrayList(u8) = .empty;
        defer fin.deinit(self.allocator);
        try writeHandshake(self.allocator, &fin, .finished, &verify);
        try self.transcript.appendSlice(self.allocator, fin.items);

        const ccs = try tls12.writePlainRecord(self.allocator, .change_cipher_spec, &.{1});
        defer self.allocator.free(ccs);
        try out.appendSlice(self.allocator, ccs);
        const fin_rec = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.server_write, self.hs_write_seq, .handshake, fin.items);
        self.hs_write_seq += 1;
        defer self.allocator.free(fin_rec);
        try out.appendSlice(self.allocator, fin_rec);
        return out.toOwnedSlice(self.allocator);
    }

    /// True when this connection should issue a NewSessionTicket on the current
    /// (full) handshake: tickets are enabled with a key, the client advertised
    /// SessionTicket support, and we are not on the abbreviated (resumed) path
    /// (a resumed connection already has the client's ticket).
    fn issuingTicket(self: *const Server) bool {
        // RFC 7627 §5.3: only EMS sessions are resumable — a non-EMS session
        // (possible only when the operator loosened require_extended_master_secret)
        // never gets a ticket, so an EMS/non-EMS resumption mismatch cannot arise.
        return self.config.enable_session_tickets and
            self.config.ticket_key != null and
            self.client_offered_empty_ticket and
            self.ems_negotiated and
            !self.resuming;
    }

    /// Seal the current session into an RFC 5077 NewSessionTicket message body.
    /// The sealed blob carries the negotiated suite and the 48-byte
    /// master_secret as its PSK; on resume the server recovers both.
    fn buildNewSessionTicket(self: *Server) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;
        const key = self.config.ticket_key orelse return error.BadState;

        var aead_nonce: [ChaCha20Poly1305.nonce_length]u8 = undefined;
        try osEntropy(&aead_nonce);
        var ticket_nonce: [tls_resumption.ticket_nonce_len]u8 = undefined;
        try osEntropy(&ticket_nonce);
        // Stamp the AEAD-protected EMS domain tag (see tls12_ems_ticket_tag):
        // tickets are only issued for EMS sessions, and tryResume requires the
        // tag, so a pre-EMS-build (or foreign) ticket can never take the
        // abbreviated path.
        @memcpy(ticket_nonce[0..tls12_ems_ticket_tag.len], &tls12_ems_ticket_tag);

        const sealed = tls_resumption.sealTicket(
            self.allocator,
            key,
            aead_nonce,
            @intFromEnum(suite),
            &self.master_secret,
            &ticket_nonce,
            self.config.now_unix_seconds * 1000,
            0, // no 0-RTT in TLS 1.2
            0, // ticket_age_add: unused (no 0-RTT freshness window in TLS 1.2)
            self.config.ticket_lifetime_seconds,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // sealTicket only rejects oversized inputs, which cannot occur with
            // the fixed 48-byte master_secret + 8-byte nonce above.
            else => return error.BadState,
        };
        defer self.allocator.free(sealed);

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU32(self.allocator, &body, self.config.ticket_lifetime_seconds);
        try appendU16(self.allocator, &body, @intCast(sealed.len));
        try body.appendSlice(self.allocator, sealed);

        var hs: std.ArrayList(u8) = .empty;
        errdefer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .new_session_ticket, body.items);
        return hs.toOwnedSlice(self.allocator);
    }

    /// Decide whether a presented ticket lets us resume. Opens and validates the
    /// ticket, enforces the lifetime window, runs the replay guard, recovers the
    /// master_secret + suite, and derives key material from a FRESH server_random
    /// (generated in `init`). Returns false on ANY problem so the caller falls
    /// back to a full handshake; it never fails the connection.
    fn tryResume(self: *Server) bool {
        if (!self.config.enable_session_tickets) return false;
        const key = self.config.ticket_key orelse return false;
        const ticket = self.presented_ticket orelse return false;
        // RFC 7627 §5.3: every resumable session used EMS, so the resuming
        // ClientHello must offer it again or the server falls back to a full
        // handshake (which itself enforces the require_extended_master_secret
        // policy before this point).
        if (!self.client_offered_ems) return false;

        const opened = tls_resumption.openTicketWithRotation(self.allocator, key, self.config.previous_ticket_key, ticket) catch return false;
        // opened.plain holds the cleartext session (incl. the 48-byte master_secret);
        // wipe it before returning the allocation.
        defer {
            std.crypto.secureZero(u8, opened.plain);
            self.allocator.free(opened.plain);
        }

        const suite = tls12.CipherSuite.fromWire(opened.opened.suite) catch return false;
        // The resumed suite must be one the client offered in this ClientHello,
        // and its certificate-auth must match our configured key.
        const auth = activeCertificateAuth(self.config) orelse return false;
        if (!suiteMatchesAuth(suite, auth)) return false;
        if (!clientOfferedSuite(self.offered_suites, suite)) return false;
        // The recovered PSK must be exactly the 48-byte master_secret.
        if (opened.opened.psk.len != tls12.master_secret_len) return false;
        // The AEAD-sealed EMS domain tag proves the original session used the
        // extended master secret (RFC 7627 §5.3); untagged tickets (older
        // builds, other legs) fall back to a full handshake.
        if (opened.opened.ticket_nonce.len < tls12_ems_ticket_tag.len or
            !std.mem.eql(u8, opened.opened.ticket_nonce[0..tls12_ems_ticket_tag.len], &tls12_ems_ticket_tag))
        {
            return false;
        }

        // Lifetime enforcement: a ticket's freshness can only be judged
        // against a real clock. Absent one (now_unix_seconds == 0, the
        // no-clock sentinel) we cannot validate a ticket's age at all —
        // refuse resumption fail-closed rather than silently accepting a
        // ticket of unknown/unbounded age. The caller always falls back to a
        // full handshake on a `false` return, so this never fails the
        // connection, only the resumption fast path.
        if (self.config.now_unix_seconds == 0) return false;
        const issued_s = @divTrunc(opened.opened.issued_unix_ms, 1000);
        // No issue time, or a ticket that does not carry the lifetime it was
        // minted with, cannot be shown to be inside that window.
        const sealed_lifetime = opened.opened.ticket_lifetime orelse return false;
        if (issued_s == 0) return false;
        if (self.config.now_unix_seconds < issued_s) return false;
        if (self.config.now_unix_seconds - issued_s > @as(i64, sealed_lifetime)) return false;

        // Replay defence: a ticket presented twice must NOT take the abbreviated
        // path again. The replay guard caps binders at SHA-384 size (48 bytes),
        // so we bind on the ticket's 16-byte ChaCha20-Poly1305 AEAD tag (the
        // trailing bytes of the sealed blob), which uniquely identifies it. A
        // repeat falls through to a fresh full handshake (new ECDHE, replay-safe)
        // rather than failing. This mirrors the TLS 1.3 path's intent — a replay
        // still connects, it just loses the resumption fast path. (TLS 1.2 has no
        // 0-RTT, so there is no early-data window to refuse separately.)
        if (self.config.replay_guard) |g| {
            const tag = ticket[ticket.len - ChaCha20Poly1305.tag_length ..];
            if (!g.checkAndRecord(tag)) return false;
        }

        self.selected_suite = suite;
        @memcpy(&self.master_secret, opened.opened.psk[0..tls12.master_secret_len]);
        self.keys = tls12.deriveKeyMaterial(suite, &self.master_secret, &self.client_random, &self.server_random) catch return false;
        return true;
    }

    /// Abbreviated (resumed) server flight (RFC 5077):
    ///   ServerHello(+empty SessionTicket ext), [NewSessionTicket], CCS, Finished.
    /// No Certificate / ServerKeyExchange. The server Finished is computed over
    /// the abbreviated transcript (ClientHello, ServerHello[, NewSessionTicket]).
    fn buildResumedServerFlight(self: *Server) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;

        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);

        var sh_body: std.ArrayList(u8) = .empty;
        defer sh_body.deinit(self.allocator);
        try appendU16(self.allocator, &sh_body, tls12.tls_version);
        try sh_body.appendSlice(self.allocator, &self.server_random);
        try sh_body.append(self.allocator, @intCast(self.session_id_len));
        try sh_body.appendSlice(self.allocator, self.session_id[0..self.session_id_len]);
        try appendU16(self.allocator, &sh_body, @intFromEnum(suite));
        try sh_body.append(self.allocator, 0);
        var exts: std.ArrayList(u8) = .empty;
        defer exts.deinit(self.allocator);
        try writeExtension(self.allocator, &exts, 0xff01, &.{0x00});
        // RFC 7627 §5.3: the resumed session was established with EMS (tickets
        // are only ever issued for EMS sessions, and tryResume required the
        // resuming ClientHello to offer it again), so the abbreviated
        // ServerHello MUST echo the extension.
        if (self.ems_negotiated) try writeExtension(self.allocator, &exts, ext_extended_master_secret, "");
        if (self.selected_alpn) |proto| {
            var alpn_body: [3 + 255]u8 = undefined;
            std.mem.writeInt(u16, alpn_body[0..2], @intCast(1 + proto.len), .big);
            alpn_body[2] = @intCast(proto.len);
            @memcpy(alpn_body[3 .. 3 + proto.len], proto);
            try writeExtension(self.allocator, &exts, 0x0010, alpn_body[0 .. 3 + proto.len]);
        }
        // RFC 5077: the resumed ServerHello carries an empty SessionTicket ext
        // when the server will issue a (new) NewSessionTicket.
        const reissue = self.config.ticket_key != null;
        if (reissue) try writeExtension(self.allocator, &exts, ext_session_ticket, "");
        // RFC 8449: echo the record_size_limit only when the client offered it,
        // exactly as the full-handshake ServerHello does.
        if (self.client_offered_record_size_limit) {
            var rsl_buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &rsl_buf, tls_record.record_size_limit_max, .big);
            try writeExtension(self.allocator, &exts, 0x001c, &rsl_buf);
        }
        try appendU16(self.allocator, &sh_body, @intCast(exts.items.len));
        try sh_body.appendSlice(self.allocator, exts.items);
        try writeHandshake(self.allocator, &hs, .server_hello, sh_body.items);
        try self.transcript.appendSlice(self.allocator, hs.items);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        // ServerHello goes out as one plaintext record; then optionally the
        // NewSessionTicket (also plaintext, hashed into the transcript), then
        // CCS, then the encrypted server Finished.
        const sh_rec = try writeFragmentedHandshakeFlight(self.allocator, hs.items);
        defer self.allocator.free(sh_rec);
        try out.appendSlice(self.allocator, sh_rec);

        if (reissue) {
            const nst = try self.buildNewSessionTicket();
            defer self.allocator.free(nst);
            try self.transcript.appendSlice(self.allocator, nst);
            const nst_rec = try writeFragmentedHandshakeFlight(self.allocator, nst);
            defer self.allocator.free(nst_rec);
            try out.appendSlice(self.allocator, nst_rec);
        }

        const verify = try tls12.finishedVerifyData(suite, &self.master_secret, "server finished", self.transcript.items);
        var fin: std.ArrayList(u8) = .empty;
        defer fin.deinit(self.allocator);
        try writeHandshake(self.allocator, &fin, .finished, &verify);
        try self.transcript.appendSlice(self.allocator, fin.items);

        const ccs = try tls12.writePlainRecord(self.allocator, .change_cipher_spec, &.{1});
        defer self.allocator.free(ccs);
        try out.appendSlice(self.allocator, ccs);
        const fin_rec = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.server_write, self.hs_write_seq, .handshake, fin.items);
        self.hs_write_seq += 1;
        defer self.allocator.free(fin_rec);
        try out.appendSlice(self.allocator, fin_rec);
        return out.toOwnedSlice(self.allocator);
    }
};

fn activeCertificateAuth(config: Config) ?CertificateAuth {
    if (config.rsa_signing_key != null) return .rsa;
    if (config.ecdsa_p256_signing_key != null) return .ecdsa_p256;
    return null;
}

/// Extract the client leaf's public key for the CertificateVerify possession
/// proof. Only RSA and ECDSA P-256 are accepted — the cert types and signature
/// algorithms the CertificateRequest advertised; any other key fails the
/// handshake. For RSA the n/e slices borrow `der`, which the caller keeps owned
/// in `client_cert_der` for the connection's lifetime.
fn clientKeyFromCert(der: []const u8) Error!ClientLeafKey {
    const cert = x509.parse(der) catch return error.BadHandshake;
    const spk = x509.extractPublicKey(cert.spki_der) catch return error.BadHandshake;
    return switch (spk) {
        .rsa => |r| .{ .rsa = .{ .n = r.modulus, .e = r.exponent } },
        .ecdsa_p256 => |sec1| .{ .ecdsa_p256 = ecdsa_p256.parsePublicKeySec1(sec1) catch return error.BadHandshake },
        else => error.BadHandshake,
    };
}

fn suiteMatchesAuth(suite: tls12.CipherSuite, auth: CertificateAuth) bool {
    return switch (auth) {
        .ecdsa_p256 => suite.isEcdsa(),
        .rsa => !suite.isEcdsa(),
    };
}

fn writeExtension(allocator: Allocator, out: *std.ArrayList(u8), typ: u16, body: []const u8) Error!void {
    try appendU16(allocator, out, typ);
    try appendU16(allocator, out, @intCast(body.len));
    try out.appendSlice(allocator, body);
}

fn writeHandshake(allocator: Allocator, out: *std.ArrayList(u8), typ: tls12.HandshakeType, body: []const u8) Error!void {
    try out.append(allocator, @intFromEnum(typ));
    try appendU24(allocator, out, @intCast(body.len));
    try out.appendSlice(allocator, body);
}

/// Write `plaintext` (a concatenation of one or more handshake MESSAGES) as
/// one or more TLS 1.2 plaintext handshake RECORDS, each bounded by
/// `tls12.max_plaintext_len` (RFC 5246 §6.2.1) — `tls12.writePlainRecord`
/// alone rejects anything over that with `error.PlaintextTooLong`. A sizeable
/// certificate chain (several intermediates, or a chain plus a large OCSP
/// staple) easily exceeds the single-record 16 KiB limit. Record-layer
/// fragmentation is transparent to the handshake-message layer — a message
/// may span record boundaries however this splits it, and the peer
/// reassembles by message length regardless (see `tls12_client.zig`'s
/// `hs_plain` reassembly). The transcript hashes `plaintext` directly, never
/// the record framing, so fragmentation cannot change what gets hashed.
fn writeFragmentedHandshakeFlight(allocator: Allocator, plaintext: []const u8) Error![]u8 {
    if (plaintext.len <= tls12.max_plaintext_len) {
        return tls12.writePlainRecord(allocator, .handshake, plaintext);
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var off: usize = 0;
    while (off < plaintext.len) {
        const n = @min(tls12.max_plaintext_len, plaintext.len - off);
        const rec = try tls12.writePlainRecord(allocator, .handshake, plaintext[off .. off + n]);
        defer allocator.free(rec);
        try out.appendSlice(allocator, rec);
        off += n;
    }
    return out.toOwnedSlice(allocator);
}

fn parseHandshake(bytes: []const u8, off: *usize) Error!HandshakeMsg {
    if (bytes.len - off.* < 4) return error.BadHandshake;
    const start = off.*;
    const len = (@as(usize, bytes[start + 1]) << 16) | (@as(usize, bytes[start + 2]) << 8) | bytes[start + 3];
    if (bytes.len - start < 4 + len) return error.BadHandshake;
    off.* = start + 4 + len;
    return .{
        .typ = @enumFromInt(bytes[start]),
        .body = bytes[start + 4 .. start + 4 + len],
        .raw = bytes[start .. start + 4 + len],
    };
}

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn init(bytes: []const u8) Cursor {
        return .{ .bytes = bytes };
    }

    fn remaining(self: Cursor) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (n > self.remaining()) return error.BadHandshake;
        const out = self.bytes[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    fn readU8(self: *Cursor) Error!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Cursor) Error!u16 {
        const b = try self.take(2);
        return (@as(u16, b[0]) << 8) | b[1];
    }

    fn readU24(self: *Cursor) Error!u32 {
        const b = try self.take(3);
        return (@as(u32, b[0]) << 16) | (@as(u32, b[1]) << 8) | b[2];
    }

    fn expectEmpty(self: Cursor) Error!void {
        if (self.remaining() != 0) return error.BadHandshake;
    }
};

fn appendU16(allocator: Allocator, out: *std.ArrayList(u8), v: u16) Allocator.Error!void {
    try out.append(allocator, @intCast(v >> 8));
    try out.append(allocator, @intCast(v & 0xff));
}

fn appendU24(allocator: Allocator, out: *std.ArrayList(u8), v: u32) Allocator.Error!void {
    try out.append(allocator, @intCast((v >> 16) & 0xff));
    try out.append(allocator, @intCast((v >> 8) & 0xff));
    try out.append(allocator, @intCast(v & 0xff));
}

fn appendU32(allocator: Allocator, out: *std.ArrayList(u8), v: u32) Allocator.Error!void {
    try out.append(allocator, @intCast((v >> 24) & 0xff));
    try out.append(allocator, @intCast((v >> 16) & 0xff));
    try out.append(allocator, @intCast((v >> 8) & 0xff));
    try out.append(allocator, @intCast(v & 0xff));
}

/// True when the raw offered cipher-suite octets (u16 big-endian, back to back)
/// include `suite`.
fn clientOfferedSuite(offered: []const u8, suite: tls12.CipherSuite) bool {
    const want = @intFromEnum(suite);
    var i: usize = 0;
    while (i + 2 <= offered.len) : (i += 2) {
        const v = (@as(u16, offered[i]) << 8) | offered[i + 1];
        if (v == want) return true;
    }
    return false;
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    std.mem.copyForwards(u8, list.items[0 .. list.items.len - n], list.items[n..]);
    list.shrinkRetainingCapacity(list.items.len - n);
}

fn osEntropy(buf: []u8) Error!void {
    switch (builtin.os.tag) {
        .linux => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
                const signed: isize = @bitCast(rc);
                if (signed < 0 or rc == 0) return error.EntropyUnavailable;
                filled += rc;
            }
        },
        else => return error.EntropyUnavailable,
    }
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const rsa_test_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
const rsa_test_e = hexToBytes("010001");
const rsa_test_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
const rsa_test_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
const rsa_test_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
const rsa_test_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
const rsa_test_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
const rsa_test_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");

fn rsaTestPrivateKey() rsa_sign.PrivateKey {
    return .{
        .n = &rsa_test_n,
        .e = &rsa_test_e,
        .d = &rsa_test_d,
        .p = &rsa_test_p,
        .q = &rsa_test_q,
        .dp = &rsa_test_dp,
        .dq = &rsa_test_dq,
        .qinv = &rsa_test_qinv,
    };
}

const Fixture = struct {
    storage: []u8,
    cert: []const u8,
    key: ecdsa_p256.KeyPair,

    fn deinit(self: Fixture, allocator: Allocator) void {
        allocator.free(self.storage);
    }
};

fn makeFixture(allocator: Allocator) !Fixture {
    const key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var buf = try allocator.alloc(u8, 2048);
    errdefer allocator.free(buf);
    const cert = try x509_selfsign.buildSelfSignedEcdsaP256(buf, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 1, 2, 3, 4 },
        .key_pair = key,
        .dns_names = &.{"localhost"},
        .is_ca = true,
    });
    return .{ .storage = buf, .cert = buf[0..cert.len], .key = key };
}

const LoopbackSuite = enum { aes128, aes256, chacha };

fn runLoopback(comptime suite_kind: LoopbackSuite) !void {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .alpn_protocols = &.{"irc"},
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .alpn_protocols = &.{"irc"},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    switch (suite_kind) {
        .aes128 => client.offerOnlyAes128ForTest(),
        .aes256 => client.offerOnlyAes256ForTest(),
        .chacha => client.offerOnlyChaChaForTest(),
    }

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // RFC 5746: the ServerHello flight MUST carry an empty renegotiation_info
    // (ff 01 00 01 00); clients that enforce secure renegotiation abort without
    // it. Guard the wire so this can't silently regress.
    try std.testing.expect(std.mem.indexOf(u8, sf, &[_]u8{ 0xff, 0x01, 0x00, 0x01, 0x00 }) != null);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);

    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
    try std.testing.expectEqualSlices(u8, "irc", client.selectedAlpn().?);
    try std.testing.expectEqualSlices(u8, "irc", server.selectedAlpn().?);

    const c_app = try client.encrypt("client to server");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "client to server", s_plain);

    const s_app = try server.encrypt("server to client");
    defer allocator.free(s_app);
    const c_plain = try client.decrypt(s_app);
    defer allocator.free(c_plain);
    try std.testing.expectEqualSlices(u8, "server to client", c_plain);
}

test "GAP-K13 an application record after the last sequence fails closed" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());

    const last = std.math.maxInt(u64);
    const s2c = try server.encrypt("nonce-zero");
    defer allocator.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer allocator.free(got_c);
    try std.testing.expectEqualStrings("nonce-zero", got_c);

    server.app_write_seq = last;
    try std.testing.expectError(error.SequenceExhausted, server.encrypt("wrap"));
    try std.testing.expectEqual(last, server.app_write_seq);

    client.app_read_seq = last;
    try std.testing.expectError(error.SequenceExhausted, client.decrypt(s2c));
    try std.testing.expectEqual(last, client.app_read_seq);

    const c2s = try client.encrypt("nonce-zero-c");
    defer allocator.free(c2s);
    const got_s = try server.decrypt(c2s);
    defer allocator.free(got_s);
    try std.testing.expectEqualStrings("nonce-zero-c", got_s);

    client.app_write_seq = last;
    try std.testing.expectError(error.SequenceExhausted, client.encrypt("wrap"));
    try std.testing.expectEqual(last, client.app_write_seq);

    server.app_read_seq = last;
    try std.testing.expectError(error.SequenceExhausted, server.decrypt(c2s));
    try std.testing.expectEqual(last, server.app_read_seq);

    std.debug.print("GAP-K13 branch=an application record after the last sequence fails closed\n", .{});
}

// F6 regression: `buildServerFlight` used to wrap the WHOLE first flight
// (ServerHello + Certificate + ...) in a single `tls12.writePlainRecord`
// call, which rejects anything over 16 KiB with `error.PlaintextTooLong` — a
// realistic-sized certificate chain (several intermediates, or a chain plus a
// large OCSP staple) can easily exceed that. `writeFragmentedHandshakeFlight`
// now splits the flight across multiple `<= max_plaintext_len` records, which
// (paired with the TLS 1.2 client's F5 cross-record reassembly fix) the peer
// consumes exactly as if it had arrived in one record.
test "TLS 1.2 server fragments a flight larger than 16 KiB across multiple records (F6, large cert chain)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);

    // Repeat the (self-signed, CA) fixture certificate many times to build a
    // certificate_list comfortably past the 16 KiB single-record limit. Every
    // chain entry is the SAME self-signed CA certificate, so each adjacent
    // link still verifies (issuer DN == subject DN, self-signature checks)
    // and the chain tip anchors directly against `anchors` below.
    const repeat_count = 80;
    const chain: [repeat_count][]const u8 = @splat(fixture.cert);
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // Precondition: this genuinely exercises record fragmentation rather than
    // the pre-existing single-record path.
    try std.testing.expect(sf.len > tls12.max_plaintext_len);

    // Feed the (multi-record) flight in one shot; correct reassembly on the
    // client side consumes every record and completes ServerHello through
    // ServerHelloDone before producing the client flight.
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(client.handshakeDone());
}

test "TLS 1.2 ServerHello.random carries the RFC 8446 downgrade sentinel" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
    });
    defer server.deinit();

    // The sentinel is stamped at construction and reused for every ServerHello.
    try std.testing.expectEqualSlices(u8, &tls13_downgrade_sentinel, server.server_random[24..32]);

    // Drive the real first flight and confirm the sentinel lands on the wire in
    // the emitted ServerHello.random (not just the in-memory field).
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const client_hello = try client.start();
    defer allocator.free(client_hello);
    const result = try server.feed(client_hello);
    const flight = switch (result) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer allocator.free(flight);

    // The first record is the plaintext handshake flight; ServerHello is its
    // first message. Within the record fragment the 32-byte random begins after
    // the handshake header (4) and legacy_version (2); the downgrade sentinel is
    // the final 8 bytes of that random.
    const rec = (try tls12.completeRecord(flight)) orelse return error.TestUnexpectedResult;
    if (rec.content_type != .handshake) return error.TestUnexpectedResult;
    if (rec.fragment.len < 38 or rec.fragment[0] != @intFromEnum(tls12.HandshakeType.server_hello)) {
        return error.TestUnexpectedResult;
    }
    const sh_random = rec.fragment[6..38];
    try std.testing.expectEqualSlices(u8, &tls13_downgrade_sentinel, sh_random[24..32]);
}

test "TLS 1.2 CertificateRequest wire format (mTLS)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .request_client_cert = true,
    });
    defer server.deinit();
    const body = try server.buildCertificateRequest();
    defer allocator.free(body);
    // certificate_types<2>: 0x40 ecdsa_sign, 0x01 rsa_sign.
    // supported_signature_algorithms<4>: 0x0403, 0x0401. Empty CA list <0>.
    const expected = [_]u8{ 0x02, 0x40, 0x01, 0x00, 0x04, 0x04, 0x03, 0x04, 0x01, 0x00, 0x00 };
    try std.testing.expectEqualSlices(u8, &expected, body);
}

test "TLS 1.2 clientKeyFromCert parses RSA and ECDSA P-256 leaves" {
    const allocator = std.testing.allocator;
    const rsa_key = rsaTestPrivateKey();
    var rsa_buf: [2048]u8 = undefined;
    const rsa_der = try x509_selfsign.buildSelfSignedRsa(&rsa_buf, .{
        .common_name = "client.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x20, 0x01 },
        .public_modulus = rsa_key.n,
        .public_exponent = rsa_key.e,
        .private_key = rsa_key,
        .dns_names = &.{"client.test"},
        .is_ca = false,
    });
    const rk = try clientKeyFromCert(rsa_der);
    try std.testing.expect(rk == .rsa);
    try std.testing.expectEqualSlices(u8, rsa_key.n, rk.rsa.n);
    try std.testing.expectEqualSlices(u8, rsa_key.e, rk.rsa.e);

    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const ek = try clientKeyFromCert(fixture.cert);
    try std.testing.expect(ek == .ecdsa_p256);
}

/// Drive a full TLS 1.2 mTLS handshake between the in-repo server and client
/// (no external tools) and assert the server captured the presented leaf + its
/// certfp, then exchanges application data on the mutually-authed channel.
fn runMtlsLoopback(client_cert: enum { ecdsa, rsa }) !void {
    const certfp = @import("../proto/certfp.zig");
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const server_chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    const client_cert_buf = try allocator.alloc(u8, 2048);
    defer allocator.free(client_cert_buf);
    const client_ecdsa = ecdsa_p256.KeyPair.generate(std.testing.io);
    const client_rsa = rsaTestPrivateKey();
    const client_der = switch (client_cert) {
        .ecdsa => try x509_selfsign.buildSelfSignedEcdsaP256(client_cert_buf, .{
            .common_name = "client.test",
            .not_before = 1_704_067_200,
            .not_after = 1_893_456_000,
            .serial = &.{ 9, 9, 9, 1 },
            .key_pair = client_ecdsa,
        }),
        .rsa => try x509_selfsign.buildSelfSignedRsa(client_cert_buf, .{
            .common_name = "client.test",
            .not_before = 1_704_067_200,
            .not_after = 1_893_456_000,
            .serial = &.{ 9, 9, 9, 2 },
            .public_modulus = client_rsa.n,
            .public_exponent = client_rsa.e,
            .private_key = client_rsa,
            .dns_names = &.{"client.test"},
            .is_ca = false,
        }),
    };

    var server = try Server.init(allocator, .{
        .cert_chain = &server_chain,
        .ecdsa_p256_signing_key = fixture.key,
        .request_client_cert = true,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();
    switch (client_cert) {
        .ecdsa => client.setClientCertEcdsaP256ForTest(client_der, client_ecdsa),
        .rsa => client.setClientCertRsaForTest(client_der, client_rsa),
    }

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);

    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());

    const presented = server.clientCertDer() orelse return error.BadHandshake;
    try std.testing.expectEqualSlices(u8, client_der, presented);
    var fp: certfp.Fingerprint = undefined;
    certfp.computeHex(presented, &fp);
    var expected: certfp.Fingerprint = undefined;
    certfp.computeHex(client_der, &expected);
    try std.testing.expectEqualSlices(u8, &expected, &fp);

    const c_app = try client.encrypt("AUTHENTICATE EXTERNAL\r\n");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualStrings("AUTHENTICATE EXTERNAL\r\n", s_plain);
}

test "TLS 1.2 mTLS: ECDSA P-256 client cert completes and exposes leaf + CertFP" {
    try runMtlsLoopback(.ecdsa);
}

test "TLS 1.2 mTLS: RSA client cert completes and exposes leaf + CertFP" {
    try runMtlsLoopback(.rsa);
}

test "TLS 1.2 mTLS: client may decline (empty Certificate) and still connect" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const server_chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &server_chain,
        .ecdsa_p256_signing_key = fixture.key,
        .request_client_cert = true,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();
    // No client cert configured: the client declines with an empty Certificate.

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);

    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(server.clientCertDer() == null);
}

test "TLS 1.2 mTLS: tampered client CertificateVerify is rejected, no certfp exposed" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const server_chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    const client_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const client_cert_buf = try allocator.alloc(u8, 2048);
    defer allocator.free(client_cert_buf);
    const client_der = try x509_selfsign.buildSelfSignedEcdsaP256(client_cert_buf, .{
        .common_name = "client.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 9, 9, 9, 3 },
        .key_pair = client_kp,
    });

    var server = try Server.init(allocator, .{
        .cert_chain = &server_chain,
        .ecdsa_p256_signing_key = fixture.key,
        .request_client_cert = true,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();
    client.setClientCertEcdsaP256ForTest(client_der, client_kp);

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);

    // The client flight is [Certificate][ClientKeyExchange][CertificateVerify]
    // as plaintext handshake records, then CCS + encrypted Finished. Flip the
    // last byte of the 3rd record's payload — the tail of the CV signature.
    var idx: usize = 0;
    var rec_count: usize = 0;
    var cv_last: ?usize = null;
    while (idx + 5 <= cf.len) {
        const rec_len = (@as(usize, cf[idx + 3]) << 8) | cf[idx + 4];
        const payload_end = idx + 5 + rec_len;
        if (payload_end > cf.len) break;
        rec_count += 1;
        if (rec_count == 3) {
            cv_last = payload_end - 1;
            break;
        }
        idx = payload_end;
    }
    cf[cv_last orelse return error.BadHandshake] ^= 0xff;

    try std.testing.expectError(error.BadHandshake, server.feed(cf));
    try std.testing.expect(!server.handshakeDone());
    try std.testing.expect(server.clientCertDer() == null);
}

test "TLS 1.2 loopback ECDHE ECDSA AES-128-GCM" {
    try runLoopback(.aes128);
}

test "TLS 1.2 loopback ECDHE ECDSA AES-256-GCM-SHA384" {
    // Real clients (OpenSSL, browsers) list AES-256-GCM-SHA384 first, so this is
    // the suite the server actually negotiates in the wild — exercise it.
    try runLoopback(.aes256);
}

test "TLS 1.2 loopback: record_size_limit negotiated + fragments outbound records (RFC 8449)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // The client offered record_size_limit, so the ServerHello flight must echo
    // it (28 = 0x001c, 2-byte body = 2^14+1 = 0x4001).
    try std.testing.expect(std.mem.indexOf(u8, sf, &[_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01 }) != null);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(client.handshakeDone() and server.handshakeDone());

    // Both advertised the maximum, so each stored the "no restriction" default.
    try std.testing.expectEqual(@as(usize, tls_record.max_plaintext_len + 1), server.peer_record_size_limit);
    try std.testing.expectEqual(@as(usize, tls_record.max_plaintext_len + 1), client.peer_record_size_limit);
    try std.testing.expect(server.client_offered_record_size_limit);

    // Simulate a peer that advertised a small limit (100). Unlike TLS 1.3 there is
    // no inner content-type byte, so the fragment content limit is the full 100. A
    // 250-byte payload must fragment into ceil(250/100) = 3 records, and the client
    // must decrypt each (seq incrementing) and reassemble the original bytes.
    server.peer_record_size_limit = 100;
    var payload: [250]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    const wire = try server.encrypt(&payload);
    defer allocator.free(wire);

    var reassembled: std.ArrayList(u8) = .empty;
    defer reassembled.deinit(allocator);
    var records: usize = 0;
    var off: usize = 0;
    while (off < wire.len) {
        try std.testing.expect(wire.len - off >= tls12.record_header_len);
        const rec_len = std.mem.readInt(u16, wire[off + 3 ..][0..2], .big);
        const rec = wire[off .. off + tls12.record_header_len + rec_len];
        const pt = try client.decrypt(rec);
        defer allocator.free(pt);
        // Each fragment's plaintext content stays within the negotiated 100 limit.
        try std.testing.expect(pt.len <= 100);
        try reassembled.appendSlice(allocator, pt);
        records += 1;
        off += tls12.record_header_len + rec_len;
    }
    try std.testing.expectEqual(off, wire.len);
    try std.testing.expectEqual(@as(usize, 3), records);
    try std.testing.expectEqualSlices(u8, &payload, reassembled.items);
}

test "TLS 1.2 server rejects an out-of-range record_size_limit (RFC 8449)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();

    // record_size_limit (0x001c) carrying 63 (0x003f) — one below the legal
    // minimum of 64. The range check fires inside the extension loop, before the
    // trailing supported-group check, so BadHandshake is the result.
    const too_small = [_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x00, 0x3f };
    try std.testing.expectError(error.BadHandshake, server.parseClientExtensions(&too_small));

    // 0x4002 = 16386 — one above the legal maximum (2^14+1 = 16385).
    const too_large = [_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x40, 0x02 };
    try std.testing.expectError(error.BadHandshake, server.parseClientExtensions(&too_large));

    // A wrong-length body (1 byte instead of 2) is also rejected.
    const bad_len = [_]u8{ 0x00, 0x1c, 0x00, 0x01, 0x40 };
    try std.testing.expectError(error.BadHandshake, server.parseClientExtensions(&bad_len));

    // A valid value at the minimum boundary, paired with the required
    // supported_groups(secp256r1), is accepted and remembered.
    const ok = [_]u8{
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17, // supported_groups: [secp256r1]
        0x00, 0x1c, 0x00, 0x02, 0x00, 0x40, // record_size_limit = 64
    };
    try server.parseClientExtensions(&ok);
    try std.testing.expect(server.client_offered_record_size_limit);
    try std.testing.expectEqual(@as(usize, 64), server.peer_record_size_limit);
}

test "TLS 1.2 exportResume/resumeConnected carries a live session across Server instances" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(server.handshakeDone());

    // Advance both directions so the carried seqs are non-zero.
    const pre_c = try client.encrypt("pre c2s");
    defer allocator.free(pre_c);
    const pre_cp = try server.decrypt(pre_c);
    defer allocator.free(pre_cp);
    const pre_s = try server.encrypt("pre s2c");
    defer allocator.free(pre_s);
    const pre_sp = try client.decrypt(pre_s);
    defer allocator.free(pre_sp);

    // Export is rejected mid-handshake and works once connected.
    var fresh = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer fresh.deinit();
    try std.testing.expectError(error.BadState, fresh.exportResume());
    const st = try server.exportResume();
    // One app record each way after the handshake. App sequences continue past
    // the encrypted Finished (which was seq 0), so each is now at 2: 1 (carried
    // from the handshake) + 1 (the single app record exchanged above).
    try std.testing.expectEqual(@as(u64, 2), st.app_read_seq);
    try std.testing.expectEqual(@as(u64, 2), st.app_write_seq);

    var successor = try Server.resumeConnected(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key }, st);
    defer successor.deinit();
    try std.testing.expect(successor.handshakeDone());

    const c2s = try client.encrypt("post c2s");
    defer allocator.free(c2s);
    const got_s = try successor.decrypt(c2s);
    defer allocator.free(got_s);
    try std.testing.expectEqualSlices(u8, "post c2s", got_s);

    const s2c = try successor.encrypt("post s2c");
    defer allocator.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer allocator.free(got_c);
    try std.testing.expectEqualSlices(u8, "post s2c", got_c);
}

test "TLS 1.2 loopback ECDHE ECDSA ChaCha20-Poly1305" {
    try runLoopback(.chacha);
}

test "TLS 1.2 loopback ECDHE RSA AES-128-GCM" {
    const allocator = std.testing.allocator;
    const rsa_key = rsaTestPrivateKey();
    const cert_buf = try allocator.alloc(u8, 2048);
    defer allocator.free(cert_buf);
    const cert = try x509_selfsign.buildSelfSignedRsa(cert_buf, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 5, 2, 0, 1 },
        .public_modulus = rsa_key.n,
        .public_exponent = rsa_key.e,
        .private_key = rsa_key,
        .dns_names = &.{"localhost"},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    const anchors = [_][]const u8{cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .rsa_signing_key = rsa_key,
        .alpn_protocols = &.{"irc"},
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .alpn_protocols = &.{"irc"},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    // Clean end-to-end flow: the in-repo client verifies the RSA ServerKeyExchange
    // directly (the leaf RSA key no longer dangles after the Certificate message).
    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);

    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
    try std.testing.expectEqualSlices(u8, "irc", client.selectedAlpn().?);
    try std.testing.expectEqualSlices(u8, "irc", server.selectedAlpn().?);

    const c_app = try client.encrypt("rsa client to server");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "rsa client to server", s_plain);

    const s_app = try server.encrypt("rsa server to client");
    defer allocator.free(s_app);
    const c_plain = try client.decrypt(s_app);
    defer allocator.free(c_plain);
    try std.testing.expectEqualSlices(u8, "rsa server to client", c_plain);
}

test "TLS 1.2 tampered encrypted Finished is rejected" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    var cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    cf[cf.len - 1] ^= 0x01;
    try std.testing.expectError(error.AeadAuthFailed, server.feed(cf));
}

// ---- RFC 5077 session-ticket resumption tests ----

const test_ticket_key = @as([@sizeOf(tls_resumption.TicketKey)]u8, @splat(0x5c));

/// Drive one full TLS 1.2 handshake with tickets enabled, asserting the server
/// issued a NewSessionTicket, and return the serialized resumable session the
/// client captured. The caller owns the returned bytes.
fn fullHandshakeIssuingTicket(
    allocator: Allocator,
    chain: []const []const u8,
    anchors: []const []const u8,
    key: ecdsa_p256.KeyPair,
    guard: *tls_resumption.ReplayGuard,
    now_unix_seconds: i64,
) ![]u8 {
    var server = try Server.init(allocator, .{
        .cert_chain = chain,
        .ecdsa_p256_signing_key = key,
        .enable_session_tickets = true,
        .ticket_key = test_ticket_key,
        .replay_guard = guard,
        .now_unix_seconds = now_unix_seconds,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    try client.requestSessionTicket();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // The ServerHello flight echoes an empty SessionTicket extension (00 23 00 00).
    try std.testing.expect(std.mem.indexOf(u8, sf, &[_]u8{ 0x00, 0x23, 0x00, 0x00 }) != null);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());

    const stored = client.takeSessionTicket() orelse return error.BadHandshake;
    return stored;
}

test "TLS 1.2 full handshake with tickets enabled issues a NewSessionTicket" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);
    // The captured ticket decodes as a stored session carrying the 48-byte
    // master_secret and the negotiated suite.
    const decoded = try tls_resumption.decodeStoredSession(stored);
    try std.testing.expectEqual(@as(usize, tls12.master_secret_len), decoded.psk.len);
    _ = try tls12.CipherSuite.fromWire(decoded.suite);
}

test "TLS 1.2 presenting a ticket performs the abbreviated handshake and exchanges app data" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);

    // Second connection presents the ticket and resumes.
    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .enable_session_tickets = true,
        .ticket_key = test_ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_001,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    try client.setSessionTicket(stored);

    const ch = try client.start();
    defer allocator.free(ch);
    // Abbreviated server flight: ServerHello[, NewSessionTicket], CCS, Finished.
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // The server must NOT send a Certificate on resume (abbreviated handshake).
    try std.testing.expect(!serverHelloFlightHasCertificate(sf));
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    // The client's resumed flight (CCS + Finished) completes the server.
    const after = try server.feed(cf);
    try std.testing.expect(after == .need_more or after == .bytes_to_send);
    switch (after) {
        .bytes_to_send => |b| allocator.free(b),
        .need_more => {},
    }

    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(client.handshakeDone());

    // Both peers derived identical traffic keys: app data round-trips.
    const c_app = try client.encrypt("resumed client to server");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "resumed client to server", s_plain);

    const s_app = try server.encrypt("resumed server to client");
    defer allocator.free(s_app);
    const c_plain = try client.decrypt(s_app);
    defer allocator.free(c_plain);
    try std.testing.expectEqualSlices(u8, "resumed server to client", c_plain);
}

test "TLS 1.2 takeAlert emits a PLAINTEXT fatal alert before the server ChangeCipherSpec" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    // Case A: a fresh server (wait_client_hello) — nothing sent, plaintext.
    {
        var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
        defer server.deinit();
        const rec = server.takeAlert(error.ProtocolVersion) orelse return error.BadHandshake;
        defer allocator.free(rec);
        // [content_type=21][03 03][len=0x0002][level=fatal(2)][desc=protocol_version(70)]
        try std.testing.expectEqual(@as(usize, 7), rec.len);
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls12.ContentType.alert)), rec[0]);
        try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, rec[3..5], .big));
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls_server.AlertLevel.fatal)), rec[5]);
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls_server.AlertDescription.protocol_version)), rec[6]);

        // OutOfMemory maps to no description ⇒ no alert.
        try std.testing.expect(server.takeAlert(error.OutOfMemory) == null);
    }

    // Case B: mid full handshake (wait_client_key_exchange) — the server has sent
    // only its plaintext flight (SH/Cert/SKE/SHD), not its CCS ⇒ still plaintext.
    {
        var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
        defer server.deinit();
        var client = try tls12_client.Client.init(allocator, .{
            .server_name = "localhost",
            .trust_anchors = &anchors,
            .now_unix_seconds = 1_735_689_600,
        });
        defer client.deinit();

        const ch = try client.start();
        defer allocator.free(ch);
        const sf = switch (try server.feed(ch)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        allocator.free(sf);
        try std.testing.expectEqual(State.wait_client_key_exchange, server.state);
        try std.testing.expectEqual(@as(u64, 0), server.hs_write_seq);

        const rec = server.takeAlert(error.BadHandshake) orelse return error.BadHandshake;
        defer allocator.free(rec);
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls12.ContentType.alert)), rec[0]);
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls_server.AlertLevel.fatal)), rec[5]);
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls_server.AlertDescription.decode_error)), rec[6]);
        // No write seq consumed on the plaintext path.
        try std.testing.expectEqual(@as(u64, 0), server.hs_write_seq);
    }
}

test "TLS 1.2 takeAlert seals an ENCRYPTED fatal alert after the resumed server ChangeCipherSpec" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);

    // Resume: the abbreviated server flight sends ServerHello, CCS, and an
    // encrypted Finished up front, so once it is emitted the server's write
    // cipher is active and it waits in `wait_resumed_client_ccs`.
    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .enable_session_tickets = true,
        .ticket_key = test_ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_001,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    try client.setSessionTicket(stored);

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    allocator.free(sf);
    try std.testing.expectEqual(State.wait_resumed_client_ccs, server.state);
    // The abbreviated flight sealed its Finished at seq 0, so the next unused
    // server write seq is 1.
    try std.testing.expectEqual(@as(u64, 1), server.hs_write_seq);

    const suite = server.selected_suite orelse return error.BadHandshake;
    const rec = server.takeAlert(error.FinishedMismatch) orelse return error.BadHandshake;
    defer allocator.free(rec);
    // The nonce/seq is consumed so it can never be reused.
    try std.testing.expectEqual(@as(u64, 2), server.hs_write_seq);
    // TLS 1.2 does not hide the content type: the OUTER record is alert (21).
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls12.ContentType.alert)), rec[0]);
    // It decrypts under the server write keys at the seq used (1), to
    // [fatal(2)][decrypt_error(51)].
    const opened = try tls12.openRecordAlloc(allocator, suite, &server.keys.server_write, 1, rec);
    defer allocator.free(opened.plaintext);
    try std.testing.expectEqual(tls12.ContentType.alert, opened.content_type);
    try std.testing.expectEqualSlices(u8, &.{
        @intFromEnum(tls_server.AlertLevel.fatal),
        @intFromEnum(tls_server.AlertDescription.decrypt_error),
    }, opened.plaintext);
}

test "TLS 1.2 tampered ticket falls back to a full handshake and still connects" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);

    // Flip a byte inside the opaque ticket so its AEAD tag fails to open. The
    // stored session format is OTS1 magic(4) | suite(2) | lifetime(4) |
    // age_add(4) | ticket_len(2) | ticket | ... — corrupt the LAST byte of the
    // ticket field (its ChaCha20-Poly1305 tag), which guarantees openTicket
    // fails while leaving the client's recovered master_secret intact.
    const tampered = try allocator.dupe(u8, stored);
    defer allocator.free(tampered);
    const decoded_for_offset = try tls_resumption.decodeStoredSession(stored);
    const ticket_offset = 4 + 2 + 4 + 4 + 2; // magic + suite + lifetime + age_add + ticket_len
    tampered[ticket_offset + decoded_for_offset.ticket.len - 1] ^= 0x01;

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .enable_session_tickets = true,
        .ticket_key = test_ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_001,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    try client.setSessionTicket(tampered);

    const ch = try client.start();
    defer allocator.free(ch);
    // The server cannot open the ticket → full handshake: the flight carries a
    // Certificate, so a ClientKeyExchange round-trip is required.
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);

    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(client.handshakeDone());

    const c_app = try client.encrypt("fallback works");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "fallback works", s_plain);
}

test "TLS 1.2 expired ticket falls back to a full handshake" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    // Issue at t=1_700_000_000 with the default 7200s lifetime.
    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);

    // Present it well past issued + lifetime; the server must NOT resume.
    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .enable_session_tickets = true,
        .ticket_key = test_ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_000 + 7200 + 60,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    try client.setSessionTicket(stored);

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // A full handshake flight carries a Certificate message; resume would not.
    try std.testing.expect(serverHelloFlightHasCertificate(sf));
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(client.handshakeDone());
}

// F7 regression: `tryResume`'s lifetime check used to be gated on
// `now_unix_seconds != 0`, so a server with NO configured clock (the
// `now_unix_seconds == 0` default/sentinel) skipped freshness enforcement
// entirely and would resume a ticket of ANY age. Absent a clock, freshness
// cannot be judged at all — the fix refuses resumption outright rather than
// silently accepting an unbounded-age ticket.
test "TLS 1.2 ticket resumption is refused when the server has no clock (now_unix_seconds == 0)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    // Issue with a real clock so the ticket carries a genuine issue time.
    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);

    // The resuming server has NO clock configured at all (now_unix_seconds
    // defaults to 0) — it must refuse the fast path, not silently accept it.
    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .enable_session_tickets = true,
        .ticket_key = test_ticket_key,
        .replay_guard = &guard,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    try client.setSessionTicket(stored);

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // A full handshake flight carries a Certificate message; resume would not.
    try std.testing.expect(serverHelloFlightHasCertificate(sf));
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(client.handshakeDone());
}

test "TLS 1.2 replayed ticket falls back to a full handshake (replay guard refuses fast path)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);

    // First resume records the ticket in the replay guard and takes the
    // abbreviated path (no Certificate in the flight).
    {
        var server = try Server.init(allocator, .{
            .cert_chain = &chain,
            .ecdsa_p256_signing_key = fixture.key,
            .enable_session_tickets = true,
            .ticket_key = test_ticket_key,
            .replay_guard = &guard,
            .now_unix_seconds = 1_700_000_001,
        });
        defer server.deinit();
        var client = try tls12_client.Client.init(allocator, .{
            .server_name = "localhost",
            .trust_anchors = &anchors,
            .now_unix_seconds = 1_735_689_600,
        });
        defer client.deinit();
        try client.setSessionTicket(stored);
        const ch = try client.start();
        defer allocator.free(ch);
        const sf = switch (try server.feed(ch)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(sf);
        try std.testing.expect(!serverHelloFlightHasCertificate(sf)); // abbreviated
    }

    // Second presentation of the SAME ticket: the replay guard refuses the fast
    // path, so the server falls back to a full handshake (Certificate present).
    {
        var server = try Server.init(allocator, .{
            .cert_chain = &chain,
            .ecdsa_p256_signing_key = fixture.key,
            .enable_session_tickets = true,
            .ticket_key = test_ticket_key,
            .replay_guard = &guard,
            .now_unix_seconds = 1_700_000_002,
        });
        defer server.deinit();
        var client = try tls12_client.Client.init(allocator, .{
            .server_name = "localhost",
            .trust_anchors = &anchors,
            .now_unix_seconds = 1_735_689_600,
        });
        defer client.deinit();
        try client.setSessionTicket(stored);
        const ch = try client.start();
        defer allocator.free(ch);
        const sf = switch (try server.feed(ch)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(sf);
        try std.testing.expect(serverHelloFlightHasCertificate(sf)); // full fallback

        // The full handshake still completes end to end.
        const cf = switch (try client.feed(sf)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(cf);
        const sfin = switch (try server.feed(cf)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(sfin);
        _ = try client.feed(sfin);
        try std.testing.expect(server.handshakeDone());
        try std.testing.expect(client.handshakeDone());
    }
}

test "TLS 1.2 tickets disabled issues no ticket and leaves the transcript unchanged" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    // Default config: enable_session_tickets = false.
    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    // Even though the client asks for a ticket, a tickets-disabled server must
    // not echo a SessionTicket extension nor emit a NewSessionTicket.
    try client.requestSessionTicket();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // No empty SessionTicket extension in the ServerHello flight.
    try std.testing.expect(std.mem.indexOf(u8, sf, &[_]u8{ 0x00, 0x23, 0x00, 0x00 }) == null);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    // No NewSessionTicket (handshake type 4) in the server's final flight.
    try std.testing.expect(!finalFlightHasNewSessionTicket(sfin));
    _ = try client.feed(sfin);
    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(client.takeSessionTicket() == null);
}

// ---- Hardened-profile enforcement tests (EMS, weak suites, SCSV, reneg,
// compression, malformed bytes) ----

/// Synthetic ClientHello body for driving parseClientHello directly with
/// attacker-chosen suites / compression / extension bytes.
fn synthClientHelloBody(
    allocator: Allocator,
    suites: []const u16,
    compression: []const u8,
    exts: []const u8,
) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    try appendU16(allocator, &body, tls12.tls_version);
    const rnd: [32]u8 = @splat(0x11);
    try body.appendSlice(allocator, &rnd);
    try body.append(allocator, 0); // empty session_id
    try appendU16(allocator, &body, @intCast(suites.len * 2));
    for (suites) |s| try appendU16(allocator, &body, s);
    try body.append(allocator, @intCast(compression.len));
    try body.appendSlice(allocator, compression);
    try appendU16(allocator, &body, @intCast(exts.len));
    try body.appendSlice(allocator, exts);
    return body.toOwnedSlice(allocator);
}

/// supported_groups=[secp256r1] + extended_master_secret — the minimum a
/// well-behaved hardened client sends.
const synth_ok_exts = [_]u8{
    0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17, // supported_groups: [secp256r1]
    0x00, 0x17, 0x00, 0x00, // extended_master_secret (empty)
};

test "tls12 EMS: default loopback negotiates extended master secret on the wire" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer allocator.free(ch);
    // The ClientHello offers the empty extended_master_secret extension
    // (00 17 00 00) and the empty renegotiation_info (ff 01 00 01 00).
    try std.testing.expect(std.mem.indexOf(u8, ch, &[_]u8{ 0x00, 0x17, 0x00, 0x00 }) != null);
    try std.testing.expect(std.mem.indexOf(u8, ch, &[_]u8{ 0xff, 0x01, 0x00, 0x01, 0x00 }) != null);

    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // The ServerHello echoes the empty extension.
    try std.testing.expect(std.mem.indexOf(u8, sf, &[_]u8{ 0x00, 0x17, 0x00, 0x00 }) != null);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(server.handshakeDone() and client.handshakeDone());
    try std.testing.expect(server.ems_negotiated and client.ems_negotiated);

    // Both sides derived the SAME session-hash-bound master secret: app data
    // round-trips (a derivation mismatch would fail the Finished long before).
    const c_app = try client.encrypt("ems bound");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "ems bound", s_plain);
}

test "tls12 EMS required: a legacy ClientHello without the extension is rejected, alert = handshake_failure" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .require_extended_master_secret = false,
    });
    defer client.deinit();
    client.omit_ems_for_test = true;

    const ch = try client.start();
    defer allocator.free(ch);
    try std.testing.expect(std.mem.indexOf(u8, ch, &[_]u8{ 0x00, 0x17, 0x00, 0x00 }) == null);
    try std.testing.expectError(error.EmsRequired, server.feed(ch));
    try std.testing.expect(!server.handshakeDone());

    // The refusal maps to a fatal handshake_failure(40) plaintext alert.
    const rec = server.takeAlert(error.EmsRequired) orelse return error.BadHandshake;
    defer allocator.free(rec);
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls12.ContentType.alert)), rec[0]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls_server.AlertLevel.fatal)), rec[5]);
    try std.testing.expectEqual(@as(u8, 40), rec[6]);
}

test "tls12 EMS optional: with the requirement loosened a non-EMS client completes via classic derivation" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .require_extended_master_secret = false,
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
        .require_extended_master_secret = false,
    });
    defer client.deinit();
    client.omit_ems_for_test = true;

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    // No EMS on the wire in either direction: the legacy path is byte-compatible.
    try std.testing.expect(std.mem.indexOf(u8, sf, &[_]u8{ 0x00, 0x17, 0x00, 0x00 }) == null);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);
    try std.testing.expect(server.handshakeDone() and client.handshakeDone());
    try std.testing.expect(!server.ems_negotiated and !client.ems_negotiated);

    const c_app = try client.encrypt("classic prf");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "classic prf", s_plain);
}

test "tls12 weak cipher suites offered alone are rejected (no RSA-kx / CBC / 3DES / RC4 / NULL)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();

    const weak = [_]u16{
        0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256 (static-RSA key transport)
        0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (MAC-then-encrypt)
        0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x0005, // TLS_RSA_WITH_RC4_128_SHA
        0x0001, // TLS_RSA_WITH_NULL_MD5
        0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA (finite-field DHE)
    };
    const body = try synthClientHelloBody(allocator, &weak, &.{0}, &synth_ok_exts);
    defer allocator.free(body);
    try std.testing.expectError(error.UnsupportedCipherSuite, server.parseClientHello(body));
}

test "tls12 FALLBACK_SCSV in a 1.2 ClientHello aborts with inappropriate_fallback (RFC 7507)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();

    // Even alongside a perfectly good suite, the SCSV means the client fell
    // back from a higher offer — and this daemon supports TLS 1.3.
    const suites = [_]u16{ 0xc02b, suite_fallback_scsv };
    const body = try synthClientHelloBody(allocator, &suites, &.{0}, &synth_ok_exts);
    defer allocator.free(body);
    try std.testing.expectError(error.InappropriateFallback, server.parseClientHello(body));
    // ...and it maps to the RFC 7507 inappropriate_fallback(86) alert.
    try std.testing.expectEqual(
        tls_server.AlertDescription.inappropriate_fallback,
        tls_server.alertDescriptionForError(error.InappropriateFallback).?,
    );
}

test "tls12 renegotiation_info: a non-empty renegotiated_connection in the initial ClientHello is rejected" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();

    // renegotiated_connection = 1 byte of "previous verify data" — a splice
    // attempt on an initial handshake (RFC 5746 §3.6 MUST abort).
    const hostile = [_]u8{ 0xff, 0x01, 0x00, 0x02, 0x01, 0xaa };
    try std.testing.expectError(error.BadHandshake, server.parseClientExtensions(&hostile));

    // The well-formed empty marker is accepted (alongside the required group).
    const ok = [_]u8{
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17, // supported_groups
        0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info: empty
    };
    try server.parseClientExtensions(&ok);
}

test "tls12 compression: a ClientHello without null compression is rejected (CRIME closed)" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();

    const suites = [_]u16{0xc02b};
    // DEFLATE(1) only — and even DEFLATE+null is refused (list must be exactly [null]).
    const deflate_only = try synthClientHelloBody(allocator, &suites, &.{1}, &synth_ok_exts);
    defer allocator.free(deflate_only);
    try std.testing.expectError(error.BadHandshake, server.parseClientHello(deflate_only));

    const deflate_and_null = try synthClientHelloBody(allocator, &suites, &.{ 1, 0 }, &synth_ok_exts);
    defer allocator.free(deflate_and_null);
    try std.testing.expectError(error.BadHandshake, server.parseClientHello(deflate_and_null));
}

test "tls12 malformed handshake bytes yield typed errors, never a crash" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};

    // An unknown record content type fails record parsing.
    {
        var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
        defer server.deinit();
        const bad_ct = [_]u8{ 99, 0x03, 0x03, 0x00, 0x01, 0x00 };
        try std.testing.expectError(error.BadRecord, server.feed(&bad_ct));
    }
    // A handshake header whose declared length overruns the record is refused.
    {
        var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
        defer server.deinit();
        const overrun = [_]u8{ 22, 0x03, 0x03, 0x00, 0x05, 1, 0x00, 0x00, 0xff, 0x00 };
        try std.testing.expectError(error.BadHandshake, server.feed(&overrun));
    }
    // A wrong first message type (Finished where ClientHello belongs) is refused.
    {
        var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
        defer server.deinit();
        const wrong_type = [_]u8{ 22, 0x03, 0x03, 0x00, 0x04, 20, 0x00, 0x00, 0x00 };
        try std.testing.expectError(error.BadHandshake, server.feed(&wrong_type));
    }
    // A truncated ClientHello body (random cut short) is refused, not crashed on.
    {
        var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
        defer server.deinit();
        const truncated = [_]u8{ 22, 0x03, 0x03, 0x00, 0x08, 1, 0x00, 0x00, 0x04, 0x03, 0x03, 0x11, 0x22 };
        try std.testing.expectError(error.BadHandshake, server.feed(&truncated));
    }
}

test "tls12 EMS ticket binding: non-EMS sessions get no ticket and a non-EMS resume falls back to a full handshake" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var guard = tls_resumption.ReplayGuard{};

    // (a) A non-EMS session (requirement loosened both sides) must NOT be
    // issued a NewSessionTicket even when the client asks for one.
    {
        var server = try Server.init(allocator, .{
            .cert_chain = &chain,
            .ecdsa_p256_signing_key = fixture.key,
            .require_extended_master_secret = false,
            .enable_session_tickets = true,
            .ticket_key = test_ticket_key,
            .replay_guard = &guard,
            .now_unix_seconds = 1_700_000_000,
        });
        defer server.deinit();
        var client = try tls12_client.Client.init(allocator, .{
            .server_name = "localhost",
            .trust_anchors = &anchors,
            .now_unix_seconds = 1_735_689_600,
            .require_extended_master_secret = false,
        });
        defer client.deinit();
        client.omit_ems_for_test = true;
        try client.requestSessionTicket();

        const ch = try client.start();
        defer allocator.free(ch);
        const sf = switch (try server.feed(ch)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(sf);
        // No SessionTicket extension echo for a session that can never resume.
        try std.testing.expect(std.mem.indexOf(u8, sf, &[_]u8{ 0x00, 0x23, 0x00, 0x00 }) == null);
        const cf = switch (try client.feed(sf)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(cf);
        const sfin = switch (try server.feed(cf)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(sfin);
        try std.testing.expect(!finalFlightHasNewSessionTicket(sfin));
        _ = try client.feed(sfin);
        try std.testing.expect(server.handshakeDone() and client.handshakeDone());
        try std.testing.expect(client.takeSessionTicket() == null);
    }

    // (b) A valid EMS-issued ticket presented by a ClientHello that does NOT
    // offer EMS must not take the abbreviated path (RFC 7627 §5.3): the server
    // (requirement loosened) falls back to a FULL handshake.
    const stored = try fullHandshakeIssuingTicket(allocator, &chain, &anchors, fixture.key, &guard, 1_700_000_000);
    defer allocator.free(stored);
    {
        var server = try Server.init(allocator, .{
            .cert_chain = &chain,
            .ecdsa_p256_signing_key = fixture.key,
            .require_extended_master_secret = false,
            .enable_session_tickets = true,
            .ticket_key = test_ticket_key,
            .replay_guard = &guard,
            .now_unix_seconds = 1_700_000_001,
        });
        defer server.deinit();
        var client = try tls12_client.Client.init(allocator, .{
            .server_name = "localhost",
            .trust_anchors = &anchors,
            .now_unix_seconds = 1_735_689_600,
            .require_extended_master_secret = false,
        });
        defer client.deinit();
        try client.setSessionTicket(stored);
        client.omit_ems_for_test = true;

        const ch = try client.start();
        defer allocator.free(ch);
        const sf = switch (try server.feed(ch)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(sf);
        // Full handshake (Certificate present) — the fast path was refused.
        try std.testing.expect(serverHelloFlightHasCertificate(sf));
        const cf = switch (try client.feed(sf)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(cf);
        const sfin = switch (try server.feed(cf)) {
            .bytes_to_send => |b| b,
            .need_more => return error.BadHandshake,
        };
        defer allocator.free(sfin);
        _ = try client.feed(sfin);
        try std.testing.expect(server.handshakeDone() and client.handshakeDone());
    }
}

// NOTE (RFC 7627 session-hash coverage): the derivation-input ordering — the
// CKE joining the transcript BEFORE the master secret derives — is pinned by
// every default (EMS) loopback above: client and server compute their session
// hashes from independently-assembled transcripts, so a server deriving before
// its CKE append would disagree with the client and fail the Finished/AEAD.

/// True when a plaintext ServerHello flight contains a Certificate handshake
/// message (type 11). Used to distinguish full (Certificate present) from
/// abbreviated (no Certificate) handshakes by inspecting the wire.
fn serverHelloFlightHasCertificate(flight: []const u8) bool {
    return handshakeFlightContainsType(flight, @intFromEnum(tls12.HandshakeType.certificate));
}

/// True when the server's final plaintext flight contains a NewSessionTicket
/// handshake message (type 4) before the CCS.
fn finalFlightHasNewSessionTicket(flight: []const u8) bool {
    return handshakeFlightContainsType(flight, @intFromEnum(tls12.HandshakeType.new_session_ticket));
}

/// Walk the TLS records in a plaintext flight and report whether any PLAINTEXT
/// handshake record (those preceding the ChangeCipherSpec) carries a handshake
/// message of `want_type`. We stop at the first CCS because everything after it
/// (the encrypted Finished) is opaque ciphertext that must not be misparsed.
fn handshakeFlightContainsType(flight: []const u8, want_type: u8) bool {
    var i: usize = 0;
    while (i + 5 <= flight.len) {
        const ct = flight[i];
        const len = (@as(usize, flight[i + 3]) << 8) | flight[i + 4];
        const body_start = i + 5;
        if (body_start + len > flight.len) return false;
        if (ct == @intFromEnum(tls12.ContentType.change_cipher_spec)) return false;
        if (ct == @intFromEnum(tls12.ContentType.handshake)) {
            var off = body_start;
            while (off + 4 <= body_start + len) {
                const mt = flight[off];
                const mlen = (@as(usize, flight[off + 1]) << 16) | (@as(usize, flight[off + 2]) << 8) | flight[off + 3];
                if (mt == want_type) return true;
                if (body_start + len - off < 4 + mlen) break;
                off += 4 + mlen;
            }
        }
        i = body_start + len;
    }
    return false;
}
