// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socketless TLS 1.2 client handshake state machine.
//!
//! The caller owns transport I/O: call `start()` to obtain ClientHello bytes,
//! feed peer bytes through `feed()`, write any returned flight, and use
//! `encrypt()` / `decrypt()` once `handshakeDone()` is true. Policy is
//! intentionally narrow: TLS 1.2, ECDHE over secp256r1, null compression, and
//! the AEAD suites exposed by `tls12.zig`.

const std = @import("std");
const builtin = @import("builtin");

const tls12 = @import("tls12.zig");
const tls_record = @import("tls_record.zig");
const tls_resumption = @import("tls_resumption.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_verify = @import("rsa_verify.zig");
const rsa_sign = @import("rsa_sign.zig");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const ocsp = @import("ocsp.zig");
const crl = @import("crl.zig");

const Allocator = std.mem.Allocator;

const named_group_secp256r1: u16 = 0x0017;
const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;
const sig_rsa_pkcs1_sha256: u16 = 0x0401;
const sig_rsa_pkcs1_sha384: u16 = 0x0501;

/// RFC 5077 SessionTicket extension type.
const ext_session_ticket: u16 = 0x0023;

/// RFC 6066 status_request (OCSP stapling).
const ext_status_request: u16 = 0x0005;

/// RFC 7627 extended_master_secret extension type (always empty).
const ext_extended_master_secret: u16 = 0x0017;

/// RFC 8446 §4.1.3 downgrade-protection sentinels ("DOWNGRD" + a version tag). A
/// TLS-1.3-capable server that is forced to negotiate a lower version stamps the
/// last 8 bytes of ServerHello.random with one of these, letting a client that
/// *offered* TLS 1.3 detect an active version-downgrade attack:
///   * `downgrade_sentinel_tls12` — server fell back from 1.3 to 1.2.
///   * `downgrade_sentinel_tls11` — server fell back from 1.3 to 1.1 or below.
/// This project's own 1.2 server stamps `downgrade_sentinel_tls12` on every
/// ServerHello (see tls12_server.tls13_downgrade_sentinel).
const downgrade_sentinel_tls12 = [8]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };
const downgrade_sentinel_tls11 = [8]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 };

/// Whether this engine ever offers a TLS version higher than the 1.2 it
/// negotiates. It does NOT: `writeClientHelloBody` sets legacy_version to 1.2 and
/// `writeSupportedVersionsExtension` offers ONLY 1.2. Per RFC 8446 §4.1.3 the
/// downgrade sentinel is therefore not a downgrade signal *for us*, so
/// `checkDowngradeSentinel` is inert by construction — it MUST be, or the client
/// could never complete a handshake with a 1.3-capable server that stamps the
/// sentinel unconditionally (as this project's own 1.2 server does). Kept as a
/// named flag so that teaching this client to also offer 1.3 (making 1.2 a
/// genuine fallback) activates a conformant check by flipping one value.
const client_offered_tls13 = false;

/// Bound on plaintext handshake bytes reassembled across TLS records for any
/// message OTHER than Certificate (ServerHello, ServerKeyExchange,
/// CertificateRequest, ServerHelloDone, CertificateStatus, NewSessionTicket) —
/// real messages of these types are at most a few KB. A hostile peer claiming
/// more is rejected fail-closed rather than growing `hs_plain` without bound.
const max_reassembled_handshake_bytes: usize = 64 * 1024;
/// Bound on a reassembled Certificate message specifically: a realistic chain
/// (leaf + several intermediates, RSA-4096 or several EC certs) comfortably
/// fits well under this.
const max_reassembled_certificate_bytes: usize = 512 * 1024;

pub const Error = tls12.Error || ecdh_p256.EcdhError || ecdsa_p256.DerError ||
    ecdsa_p256.Sec1Error || rsa_verify.Error || x509.Error || x509_verify.Error ||
    tls_resumption.Error || Allocator.Error || error{
    BadCertificate,
    BadHandshake,
    BadSignature,
    BadState,
    CertificateNameMismatch,
    CertificateRevoked,
    DowngradeDetected,
    EmptyCertificateChain,
    EmsRequired,
    FinishedMismatch,
    /// A handshake message (or the still-incomplete head of one) reassembled
    /// across TLS records exceeded `max_reassembled_handshake_bytes` /
    /// `max_reassembled_certificate_bytes`. See `foldHandshakeFragment`.
    HandshakeMessageTooLarge,
    NeedMore,
    NoServerCertificate,
    ProtocolVersion,
    TlsAlert,
    UnknownCa,
    UnsupportedCipherSuite,
    UnsupportedGroup,
    UnsupportedPublicKey,
    UnsupportedSignatureScheme,
    EntropyUnavailable,
};

pub const Options = struct {
    server_name: []const u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8 = &.{},
    now_unix_seconds: ?i64 = null,
    /// RFC 7627 Extended Master Secret policy. REQUIRED by default in this
    /// hardened profile: the ClientHello always offers the extension, and a
    /// ServerHello that fails to echo it aborts with `EmsRequired` — no silent
    /// fallback to the classic (Triple-Handshake-exposed) derivation. Set false
    /// only for legacy interop; EMS is still used whenever the server echoes it.
    require_extended_master_secret: bool = true,
    /// Optional caller-supplied CRL (DER) for leaf revocation, matching the
    /// TLS 1.3 client. A listed serial always revokes. Other CRL defects are
    /// ignored unless `require_crl` is set.
    crl: ?[]const u8 = null,
    /// When true AND `crl` is set, a missing clock, unparseable CRL,
    /// wrong-issuer signature, or stale window fails closed (`BadCertificate`).
    require_crl: bool = false,
};

pub const FeedResult = union(enum) {
    need_more,
    bytes_to_send: []u8,
};

const State = enum {
    idle,
    // Full handshake: server flight, then client sends its flight, then server
    // CCS + Finished.
    wait_server_flight,
    wait_server_ccs,
    wait_server_finished,
    // Abbreviated (RFC 5077 resumed) handshake: the server sends its whole
    // flight first (ServerHello[, NewSessionTicket], CCS, Finished); the client
    // verifies it and only then sends its own CCS + Finished.
    wait_resumed_server_ccs,
    wait_resumed_server_finished,
    connected,
};

const HandshakeMsg = struct {
    typ: tls12.HandshakeType,
    body: []const u8,
    raw: []const u8,
};

const LeafPublicKey = union(enum) {
    ecdsa_p256: ecdsa_p256.PublicKey,
    rsa: rsa_verify.PublicKey,
};

/// A private key for signing the client CertificateVerify (mTLS). ECDSA P-256
/// signs with ecdsa_secp256r1_sha256; RSA with rsa_pkcs1_sha256 (the schemes
/// the CertificateRequest advertises, RFC 5246 §7.4.8).
const ClientCertKey = union(enum) {
    ecdsa_p256: ecdsa_p256.KeyPair,
    rsa: rsa_sign.PrivateKey,
};

pub const Client = struct {
    allocator: Allocator,
    server_name: []u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8,
    now_unix_seconds: ?i64,

    state: State = .idle,
    recv_buf: std.ArrayList(u8) = .empty,
    transcript: std.ArrayList(u8) = .empty,
    /// Plaintext handshake bytes reassembled across TLS records: a handshake
    /// MESSAGE (e.g. a large Certificate chain) can span multiple records, but
    /// `wait_server_flight`/`wait_server_ccs`/`wait_resumed_server_ccs` only
    /// ever see one record's fragment at a time. Each record's fragment is
    /// folded in here (see `foldHandshakeFragment`) and messages are parsed
    /// off the accumulated stream, not off a single record — fixing a hang
    /// where an unconsumed record (a message still incomplete) was re-parsed
    /// from `recv_buf` forever without ever advancing.
    hs_plain: std.ArrayList(u8) = .empty,

    key_pair: ecdh_p256.KeyPair,
    client_random: [32]u8,
    server_random: [32]u8 = @splat(0),
    selected_suite: ?tls12.CipherSuite = null,
    selected_alpn: ?[]u8 = null,
    leaf_key: ?LeafPublicKey = null,
    /// Owned storage for the leaf RSA key's modulus/exponent. The parsed key
    /// borrows the certificate chain DER, which is freed right after the
    /// Certificate message — so an RSA leaf key would dangle by the time the
    /// ServerKeyExchange signature is verified. Copy n/e here and re-point.
    /// (ECDSA keys are value types and need no copy.)
    leaf_rsa_n: [rsa_verify.max_bytes]u8 = undefined,
    leaf_rsa_e: [16]u8 = undefined,

    /// RFC 7627 policy copied from `Options.require_extended_master_secret`.
    require_ems: bool = true,
    /// The ServerHello echoed the extended_master_secret extension; the master
    /// secret derives from the session hash (RFC 7627) instead of the randoms.
    ems_negotiated: bool = false,
    /// ECDHE pre-master secret held between ServerKeyExchange and the client
    /// flight: EMS needs the session hash to include ClientKeyExchange, so the
    /// master-secret derivation is deferred until the CKE joins the transcript
    /// (see `buildClientFlight`). Wiped immediately after derivation.
    pre_master_secret: [32]u8 = @splat(0),
    has_pre_master_secret: bool = false,

    master_secret: [tls12.master_secret_len]u8 = @splat(0),
    keys: tls12.KeyMaterial = .{},
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,
    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,
    /// RFC 8449 record_size_limit advertised by the server (max
    /// TLSPlaintext.fragment it accepts). Default 2^14+1 = unrestricted; outbound
    /// records are fragmented to honor a smaller value (see `encrypt`).
    peer_record_size_limit: usize = tls_record.max_plaintext_len + 1,

    // ---- RFC 5077 stateless session resumption (opt-in) ----
    /// When true the ClientHello advertises an (empty) SessionTicket extension so
    /// the server may issue one. Enabled by `requestSessionTicket` or implied by
    /// `setSessionTicket` (presenting a ticket to resume).
    request_session_ticket: bool = false,
    /// A ticket loaded via `setSessionTicket` to present in the ClientHello.
    /// Owned; freed on deinit / replacement.
    resume_ticket: ?[]u8 = null,
    /// master_secret + suite recovered from the loaded session, used to derive
    /// key material on the abbreviated handshake instead of a fresh ECDHE run.
    resume_master_secret: [tls12.master_secret_len]u8 = @splat(0),
    resume_suite: ?tls12.CipherSuite = null,
    /// True once the ServerHello echoed an empty SessionTicket extension. This
    /// is sent on both resumed and fresh-issue full handshakes, so it only means
    /// "a NewSessionTicket will follow" — not "abbreviated handshake".
    server_signaled_ticket: bool = false,
    /// True once we have committed to the abbreviated (resumed) path: we
    /// presented a ticket and the ServerHello was the lone handshake message in
    /// its record (no Certificate follows).
    resuming: bool = false,
    /// The server promised/sent a NewSessionTicket: capture the latest serialized
    /// session for the caller. Owned; freed on deinit / replacement.
    captured_session_ticket: ?[]u8 = null,

    force_chacha_only_for_test: bool = false,
    force_aes128_only_for_test: bool = false,
    force_aes256_only_for_test: bool = false,
    skip_cert_verify_for_test: bool = false,
    /// Test-only: omit the extended_master_secret extension from the
    /// ClientHello, emulating a legacy non-EMS client.
    omit_ems_for_test: bool = false,

    // ---- mTLS client auth ----
    /// True once the server's CertificateRequest is seen; the full-handshake
    /// client flight then leads with a Certificate (empty if we have none).
    cert_requested: bool = false,
    /// Configured client leaf DER + matching key, or null to decline (send an
    /// empty Certificate). Borrowed.
    client_cert_der: ?[]const u8 = null,
    client_key: ?ClientCertKey = null,

    /// RFC 6066: the ServerHello echoed an empty status_request, so a
    /// CertificateStatus MUST follow Certificate.
    server_signaled_ocsp: bool = false,
    leaf_must_staple: bool = false,
    leaf_serial: ?[]u8 = null,
    issuer_spki: ?[]u8 = null,
    ocsp_staple: ?[]u8 = null,
    crl: ?[]u8 = null,
    require_crl: bool = false,

    pub fn init(allocator: Allocator, options: Options) Error!Client {
        var random: [32]u8 = undefined;
        try osEntropy(&random);
        const name = try allocator.dupe(u8, options.server_name);
        errdefer allocator.free(name);
        const crl_copy: ?[]u8 = if (options.crl) |der| try allocator.dupe(u8, der) else null;
        errdefer if (crl_copy) |d| allocator.free(d);
        return .{
            .allocator = allocator,
            .server_name = name,
            .trust_anchors = options.trust_anchors,
            .alpn_protocols = options.alpn_protocols,
            .now_unix_seconds = options.now_unix_seconds,
            .require_ems = options.require_extended_master_secret,
            .key_pair = try ecdh_p256.generate(),
            .client_random = random,
            .crl = crl_copy,
            .require_crl = options.require_crl,
        };
    }

    pub fn deinit(self: *Client) void {
        self.allocator.free(self.server_name);
        if (self.selected_alpn) |p| self.allocator.free(p);
        if (self.resume_ticket) |t| self.allocator.free(t);
        if (self.captured_session_ticket) |t| self.allocator.free(t);
        if (self.leaf_serial) |s| self.allocator.free(s);
        if (self.issuer_spki) |s| self.allocator.free(s);
        if (self.ocsp_staple) |s| self.allocator.free(s);
        if (self.crl) |d| self.allocator.free(d);
        self.recv_buf.deinit(self.allocator);
        self.transcript.deinit(self.allocator);
        self.hs_plain.deinit(self.allocator);
        std.crypto.secureZero(u8, &self.key_pair.secret);
        std.crypto.secureZero(u8, &self.pre_master_secret);
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, &self.resume_master_secret);
        self.keys.wipe();
    }

    pub fn start(self: *Client) Error![]u8 {
        if (self.state != .idle) return error.BadState;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try self.writeClientHelloBody(&body);

        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .client_hello, body.items);
        try self.transcript.appendSlice(self.allocator, hs.items);
        self.state = .wait_server_flight;
        return tls12.writePlainRecord(self.allocator, .handshake, hs.items);
    }

    /// Fold one TLS record's handshake fragment into the plaintext-handshake
    /// reassembly buffer (`hs_plain`) and cap its size. Record-layer parsing
    /// is complete the moment `tls12.completeRecord` returns a `Record` — the
    /// record's wire bytes are consumed from `recv_buf` unconditionally here.
    /// What may still be incomplete is a handshake MESSAGE spanning further
    /// records, which `hs_plain` carries forward across `feed` calls (fixing a
    /// hang where an unconsumed record was re-parsed from `recv_buf` forever;
    /// see the F5 comment on `hs_plain`'s declaration). The cap is keyed off
    /// the type byte of the oldest not-yet-fully-parsed message (index 0):
    /// Certificate gets the larger allowance, everything else the smaller one.
    fn foldHandshakeFragment(self: *Client, rec: tls12.Record) Error!void {
        try self.hs_plain.appendSlice(self.allocator, rec.fragment);
        consumePrefix(&self.recv_buf, rec.wire_len);
        if (self.hs_plain.items.len == 0) return;
        const head_typ: tls12.HandshakeType = @enumFromInt(self.hs_plain.items[0]);
        const cap: usize = if (head_typ == .certificate) max_reassembled_certificate_bytes else max_reassembled_handshake_bytes;
        if (self.hs_plain.items.len > cap) return error.HandshakeMessageTooLarge;
    }

    pub fn feed(self: *Client, received: []const u8) Error!FeedResult {
        if (self.state == .idle or self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);

        while (true) {
            const rec = (try tls12.completeRecord(self.recv_buf.items)) orelse return .need_more;
            switch (self.state) {
                .wait_server_flight => {
                    if (rec.content_type == .alert) return error.TlsAlert;
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    try self.foldHandshakeFragment(rec);

                    var off: usize = 0;
                    while (parseHandshakeMaybe(self.hs_plain.items, &off)) |msg| {
                        try self.handleServerHandshake(msg);
                        if (self.state == .wait_server_ccs) {
                            // ServerHelloDone ends this flight; discard
                            // whatever's buffered (matches the pre-fix
                            // behavior of dropping the whole record here).
                            self.hs_plain.clearRetainingCapacity();
                            const reply = try self.buildClientFlight();
                            return .{ .bytes_to_send = reply };
                        }
                        // After ServerHello, decide abbreviated vs full. Our
                        // server frames a full first flight (ServerHello +
                        // Certificate + ...) across one or more records but a
                        // resumed ServerHello ALONE; so if we presented a
                        // ticket, the server signaled one, and ServerHello is
                        // the only thing reassembled so far, take the
                        // abbreviated path.
                        if (msg.typ == .server_hello and self.resume_ticket != null and
                            self.server_signaled_ticket and off == self.hs_plain.items.len)
                        {
                            self.resuming = true;
                            try self.beginResumedHandshake();
                            self.hs_plain.clearRetainingCapacity();
                            break;
                        }
                    }
                    if (!self.resuming) consumePrefix(&self.hs_plain, off);
                },
                .wait_server_ccs => {
                    // RFC 5077 (full handshake + issue): the server's final
                    // flight is NewSessionTicket, CCS, Finished — the ticket is a
                    // plaintext handshake record that precedes the CCS.
                    if (rec.content_type == .handshake) {
                        try self.foldHandshakeFragment(rec);
                        var off: usize = 0;
                        while (parseHandshakeMaybe(self.hs_plain.items, &off)) |msg| {
                            if (msg.typ != .new_session_ticket) return error.BadHandshake;
                            try self.handleServerHandshake(msg);
                        }
                        consumePrefix(&self.hs_plain, off);
                        continue;
                    }
                    // A change_cipher_spec record while a handshake message is
                    // still mid-reassembly is out of order — reject fail-closed.
                    if (self.hs_plain.items.len != 0) return error.BadHandshake;
                    if (rec.content_type != .change_cipher_spec or rec.fragment.len != 1 or rec.fragment[0] != 1) return error.BadHandshake;
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_server_finished;
                },
                .wait_resumed_server_ccs => {
                    // A NewSessionTicket may still arrive as a plaintext
                    // handshake record before the server CCS.
                    if (rec.content_type == .handshake) {
                        try self.foldHandshakeFragment(rec);
                        var off: usize = 0;
                        while (parseHandshakeMaybe(self.hs_plain.items, &off)) |msg| {
                            try self.handleServerHandshake(msg);
                        }
                        consumePrefix(&self.hs_plain, off);
                        continue;
                    }
                    if (self.hs_plain.items.len != 0) return error.BadHandshake;
                    if (rec.content_type != .change_cipher_spec or rec.fragment.len != 1 or rec.fragment[0] != 1) return error.BadHandshake;
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_resumed_server_finished;
                },
                .wait_resumed_server_finished => {
                    // Verify the server Finished over the abbreviated transcript,
                    // then send our CCS + Finished as the final flight.
                    const suite = self.selected_suite orelse return error.BadState;
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.server_write, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
                    self.hs_read_seq += 1;
                    defer self.allocator.free(opened.plaintext);
                    if (opened.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(opened.plaintext, &off);
                    if (off != opened.plaintext.len or msg.typ != .finished) return error.BadHandshake;
                    const expected = try tls12.finishedVerifyData(suite, &self.master_secret, "server finished", self.transcript.items);
                    if (!tls12.constantTimeEq(&expected, msg.body)) return error.FinishedMismatch;
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    const reply = try self.buildResumedClientFlight();
                    self.app_read_seq = self.hs_read_seq;
                    self.app_write_seq = self.hs_write_seq;
                    self.state = .connected;
                    return .{ .bytes_to_send = reply };
                },
                .wait_server_finished => {
                    const suite = self.selected_suite orelse return error.BadState;
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.server_write, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
                    self.hs_read_seq += 1;
                    defer self.allocator.free(opened.plaintext);
                    if (opened.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(opened.plaintext, &off);
                    if (off != opened.plaintext.len or msg.typ != .finished) return error.BadHandshake;
                    const expected = try tls12.finishedVerifyData(suite, &self.master_secret, "server finished", self.transcript.items);
                    if (!tls12.constantTimeEq(&expected, msg.body)) return error.FinishedMismatch;
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    // TLS 1.2 uses ONE record sequence per direction per epoch:
                    // application data continues the counter past the encrypted
                    // Finished (it does not reset to 0). Carry the handshake
                    // counters into the app counters so we agree with the peer.
                    self.app_read_seq = self.hs_read_seq;
                    self.app_write_seq = self.hs_write_seq;
                    self.state = .connected;
                    return .need_more;
                },
                else => return error.BadState,
            }
        }
    }

    pub fn handshakeDone(self: *const Client) bool {
        return self.state == .connected;
    }

    pub fn pendingBytes(self: *const Client) []const u8 {
        return self.recv_buf.items;
    }

    pub fn selectedAlpn(self: *const Client) ?[]const u8 {
        return if (self.selected_alpn) |p| p else null;
    }

    /// Advertise RFC 5077 SessionTicket support in the next `start()` so the
    /// server may issue a NewSessionTicket. Valid only before the handshake.
    pub fn requestSessionTicket(self: *Client) Error!void {
        if (self.state != .idle) return error.BadState;
        self.request_session_ticket = true;
    }

    /// Load a serialized session (from a prior `takeSessionTicket`) to present in
    /// the next `start()` for an abbreviated handshake. Valid only before the
    /// handshake. Falls back to a full handshake if the server declines.
    pub fn setSessionTicket(self: *Client, serialized: []const u8) Error!void {
        if (self.state != .idle) return error.BadState;
        const decoded = try tls_resumption.decodeStoredSession(serialized);
        const suite = try tls12.CipherSuite.fromWire(decoded.suite);
        if (decoded.psk.len != tls12.master_secret_len) return error.BadHandshake;
        const ticket = try self.allocator.dupe(u8, decoded.ticket);
        errdefer self.allocator.free(ticket);
        if (self.resume_ticket) |old| self.allocator.free(old);
        self.resume_ticket = ticket;
        @memcpy(&self.resume_master_secret, decoded.psk[0..tls12.master_secret_len]);
        self.resume_suite = suite;
        self.request_session_ticket = true;
    }

    /// Take ownership of the newest serialized resumable session captured from a
    /// server NewSessionTicket, or null if none was received. The returned bytes
    /// are suitable for a later `setSessionTicket`.
    pub fn takeSessionTicket(self: *Client) ?[]u8 {
        const t = self.captured_session_ticket orelse return null;
        self.captured_session_ticket = null;
        return t;
    }

    pub fn offerOnlyChaChaForTest(self: *Client) void {
        self.force_chacha_only_for_test = true;
        self.force_aes128_only_for_test = false;
    }

    pub fn offerOnlyAes128ForTest(self: *Client) void {
        self.force_aes128_only_for_test = true;
        self.force_chacha_only_for_test = false;
        self.force_aes256_only_for_test = false;
    }

    pub fn offerOnlyAes256ForTest(self: *Client) void {
        self.force_aes256_only_for_test = true;
        self.force_aes128_only_for_test = false;
        self.force_chacha_only_for_test = false;
    }

    pub fn skipServerCertVerifyForTest(self: *Client) void {
        self.skip_cert_verify_for_test = true;
    }

    /// Test-only: present an ECDSA P-256 client certificate in response to the
    /// server's CertificateRequest. `der` and `key_pair` are borrowed.
    pub fn setClientCertEcdsaP256ForTest(self: *Client, der: []const u8, key_pair: ecdsa_p256.KeyPair) void {
        self.client_cert_der = der;
        self.client_key = .{ .ecdsa_p256 = key_pair };
    }

    /// Test-only: present an RSA client certificate; CertificateVerify is signed
    /// with rsa_pkcs1_sha256. `der` and `key` are borrowed.
    pub fn setClientCertRsaForTest(self: *Client, der: []const u8, key: rsa_sign.PrivateKey) void {
        self.client_cert_der = der;
        self.client_key = .{ .rsa = key };
    }

    pub fn encrypt(self: *Client, appdata: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const limit = tls_record.recordContentLimit12(self.peer_record_size_limit);
        if (appdata.len <= limit) {
            const out = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.client_write, self.app_write_seq, .application_data, appdata);
            self.app_write_seq += 1;
            return out;
        }
        // RFC 8449: fragment application data to the server's smaller record limit,
        // one record per fragment, concatenated (seq bumped per record).
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        var off: usize = 0;
        while (off < appdata.len) {
            const n = @min(limit, appdata.len - off);
            const rec = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.client_write, self.app_write_seq, .application_data, appdata[off .. off + n]);
            defer self.allocator.free(rec);
            try buf.appendSlice(self.allocator, rec);
            self.app_write_seq += 1;
            off += n;
        }
        return buf.toOwnedSlice(self.allocator);
    }

    pub fn decrypt(self: *Client, record: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.server_write, self.app_read_seq, record);
        self.app_read_seq += 1;
        errdefer self.allocator.free(opened.plaintext);
        if (opened.content_type == .alert) return error.TlsAlert;
        if (opened.content_type != .application_data) return error.BadHandshake;
        return opened.plaintext;
    }

    fn writeClientHelloBody(self: *Client, out: *std.ArrayList(u8)) Error!void {
        try appendU16(self.allocator, out, tls12.tls_version);
        try out.appendSlice(self.allocator, &self.client_random);
        try out.append(self.allocator, 0); // session_id

        var suites: std.ArrayList(u8) = .empty;
        defer suites.deinit(self.allocator);
        if (self.force_chacha_only_for_test) {
            try appendU16(self.allocator, &suites, @intFromEnum(tls12.CipherSuite.tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256));
        } else if (self.force_aes128_only_for_test) {
            try appendU16(self.allocator, &suites, @intFromEnum(tls12.CipherSuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256));
        } else if (self.force_aes256_only_for_test) {
            try appendU16(self.allocator, &suites, @intFromEnum(tls12.CipherSuite.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384));
        } else {
            for (tls12.allowed_suites) |suite| try appendU16(self.allocator, &suites, @intFromEnum(suite));
        }
        try appendU16(self.allocator, out, @intCast(suites.items.len));
        try out.appendSlice(self.allocator, suites.items);
        try out.appendSlice(self.allocator, &.{ 1, 0 }); // null compression only

        var exts: std.ArrayList(u8) = .empty;
        defer exts.deinit(self.allocator);
        try self.writeSniExtension(&exts);
        try writeSupportedGroupsExtension(self.allocator, &exts);
        try writeEcPointFormatsExtension(self.allocator, &exts);
        try writeSignatureAlgorithmsExtension(self.allocator, &exts);
        try writeSupportedVersionsExtension(self.allocator, &exts);
        // RFC 7627: always offer the (empty) extended_master_secret extension;
        // whether a non-echoing server aborts is governed by `require_ems`.
        if (!self.omit_ems_for_test) {
            try writeExtension(self.allocator, &exts, ext_extended_master_secret, "");
        }
        // RFC 5746: signal secure-renegotiation support with an EMPTY
        // renegotiated_connection (one zero length byte) on the initial
        // handshake. This engine never renegotiates; the signal lets strict
        // servers bind the session and lets us validate the server's echo.
        try writeExtension(self.allocator, &exts, 0xff01, &.{0x00});
        try self.writeAlpnExtension(&exts);
        try writeRecordSizeLimitExtension(self.allocator, &exts);
        try self.writeSessionTicketExtension(&exts);
        // RFC 6066 status_request: status_type=ocsp, empty responder_id_list,
        // empty request_extensions. Always offered so a must-staple leaf can
        // be satisfied and a present staple can be authenticated.
        try writeExtension(self.allocator, &exts, ext_status_request, &[_]u8{ 1, 0, 0, 0, 0 });
        try appendU16(self.allocator, out, @intCast(exts.items.len));
        try out.appendSlice(self.allocator, exts.items);
    }

    /// RFC 5077 SessionTicket extension: an empty body asks the server for a
    /// ticket; a non-empty body is the ticket we wish to resume.
    fn writeSessionTicketExtension(self: *Client, out: *std.ArrayList(u8)) Error!void {
        if (!self.request_session_ticket) return;
        const ticket: []const u8 = if (self.resume_ticket) |t| t else "";
        try writeExtension(self.allocator, out, ext_session_ticket, ticket);
    }

    fn writeSniExtension(self: *Client, out: *std.ArrayList(u8)) Error!void {
        if (self.server_name.len == 0) return;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU16(self.allocator, &body, @intCast(1 + 2 + self.server_name.len));
        try body.append(self.allocator, 0);
        try appendU16(self.allocator, &body, @intCast(self.server_name.len));
        try body.appendSlice(self.allocator, self.server_name);
        try writeExtension(self.allocator, out, 0x0000, body.items);
    }

    fn writeAlpnExtension(self: *Client, out: *std.ArrayList(u8)) Error!void {
        if (self.alpn_protocols.len == 0) return;
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.allocator);
        for (self.alpn_protocols) |proto| {
            if (proto.len == 0 or proto.len > 255) return error.BadHandshake;
            try list.append(self.allocator, @intCast(proto.len));
            try list.appendSlice(self.allocator, proto);
        }
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU16(self.allocator, &body, @intCast(list.items.len));
        try body.appendSlice(self.allocator, list.items);
        try writeExtension(self.allocator, out, 0x0010, body.items);
    }

    fn handleServerHandshake(self: *Client, msg: HandshakeMsg) Error!void {
        switch (msg.typ) {
            .server_hello => {
                try self.parseServerHello(msg.body);
                try self.transcript.appendSlice(self.allocator, msg.raw);
                // The resume-vs-full decision is made by the feed loop after
                // ServerHello (abbreviated iff we presented a ticket and no
                // Certificate follows in the record).
            },
            .new_session_ticket => {
                try self.captureNewSessionTicket(msg.body);
                try self.transcript.appendSlice(self.allocator, msg.raw);
            },
            .certificate => {
                if (self.resuming) return error.BadHandshake;
                try self.parseCertificate(msg.body);
                try self.transcript.appendSlice(self.allocator, msg.raw);
            },
            .certificate_status => {
                if (self.resuming) return error.BadHandshake;
                if (self.leaf_key == null) return error.BadHandshake;
                if (self.ocsp_staple != null) return error.BadHandshake;
                try self.parseCertificateStatus(msg.body);
                try self.transcript.appendSlice(self.allocator, msg.raw);
            },
            .server_key_exchange => {
                if (self.resuming) return error.BadHandshake;
                try self.verifyServerKeyExchange(msg.body);
                try self.transcript.appendSlice(self.allocator, msg.raw);
            },
            .certificate_request => {
                // mTLS: the server asks for a client cert. We don't need the body
                // (our cert/scheme is fixed); record that a Certificate +
                // CertificateVerify must lead the client flight.
                if (self.resuming) return error.BadHandshake;
                self.cert_requested = true;
                try self.transcript.appendSlice(self.allocator, msg.raw);
            },
            .server_hello_done => {
                if (self.resuming) return error.BadHandshake;
                if (msg.body.len != 0) return error.BadHandshake;
                if (self.server_signaled_ocsp and self.ocsp_staple == null)
                    return error.BadCertificate;
                if (self.leaf_must_staple and self.ocsp_staple == null)
                    return error.BadCertificate;
                try self.transcript.appendSlice(self.allocator, msg.raw);
                self.state = .wait_server_ccs;
            },
            else => return error.BadHandshake,
        }
    }

    /// Abbreviated-path setup once the ServerHello confirmed resumption: adopt
    /// the recovered suite/master_secret and derive directional keys from the
    /// fresh server_random the server just sent.
    fn beginResumedHandshake(self: *Client) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        // RFC 7627 §5.3: this client only stores sessions that negotiated EMS
        // (see captureNewSessionTicket), so the abbreviated ServerHello MUST
        // echo the extension; a server resuming our EMS session without it is
        // a downgrade splice and the handshake aborts.
        if (!self.ems_negotiated) return error.EmsRequired;
        // The server must resume the same suite the ticket was issued under.
        if (self.resume_suite) |rs| {
            if (rs != suite) return error.UnsupportedCipherSuite;
        }
        @memcpy(&self.master_secret, &self.resume_master_secret);
        self.keys = try tls12.deriveKeyMaterial(suite, &self.master_secret, &self.client_random, &self.server_random);
        self.state = .wait_resumed_server_ccs;
    }

    /// Parse a NewSessionTicket and serialize the resumable session (opaque
    /// ticket + current master_secret + suite) for `takeSessionTicket`.
    fn captureNewSessionTicket(self: *Client, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const lifetime = try c.readU32();
        const ticket = try c.take(try c.readU16());
        try c.expectEmpty();
        if (ticket.len == 0) return; // a server may send an empty placeholder.
        // RFC 7627 §5.3: only EMS sessions are resumable — never store a ticket
        // from a non-EMS session (possible only with require_ems loosened), so a
        // later resume can insist on the EMS echo (see beginResumedHandshake).
        if (!self.ems_negotiated) return;
        const suite = self.selected_suite orelse return error.BadState;
        const serialized = try tls_resumption.encodeStoredSession(self.allocator, .{
            .suite = @intFromEnum(suite),
            .ticket_lifetime = lifetime,
            .ticket_age_add = 0,
            .ticket = ticket,
            .psk = &self.master_secret,
            .max_early_data_size = 0,
        });
        errdefer self.allocator.free(serialized);
        if (self.captured_session_ticket) |old| self.allocator.free(old);
        self.captured_session_ticket = serialized;
    }

    fn parseServerHello(self: *Client, body: []const u8) Error!void {
        var c = Cursor.init(body);
        if (try c.readU16() != tls12.tls_version) return error.ProtocolVersion;
        @memcpy(&self.server_random, try c.take(32));
        // RFC 8446 §4.1.3 downgrade protection, wired at the natural parse point.
        // Inert for this 1.2-only engine (see checkDowngradeSentinel), so it goes
        // live the moment the client is taught to offer TLS 1.3.
        try checkDowngradeSentinel(client_offered_tls13, &self.server_random);
        const sid_len = try c.readU8();
        _ = try c.take(sid_len);
        const suite = try tls12.CipherSuite.fromWire(try c.readU16());
        self.selected_suite = suite;
        if (try c.readU8() != 0) return error.BadHandshake;
        if (c.remaining() != 0) {
            const ext_len = try c.readU16();
            const ext_bytes = try c.take(ext_len);
            try self.parseServerExtensions(ext_bytes);
        }
        try c.expectEmpty();

        // RFC 7627: we offered EMS unconditionally (test hook aside); a hardened
        // client refuses a server that will not commit to the session-hash
        // derivation. Fires whether the echo was absent or there were no
        // extensions at all.
        if (self.require_ems and !self.omit_ems_for_test and !self.ems_negotiated) {
            return error.EmsRequired;
        }
    }

    fn parseServerExtensions(self: *Client, bytes: []const u8) Error!void {
        var c = Cursor.init(bytes);
        while (c.remaining() != 0) {
            const typ = try c.readU16();
            const len = try c.readU16();
            const body = try c.take(len);
            switch (typ) {
                0x0010 => {
                    var a = Cursor.init(body);
                    const list = try a.take(try a.readU16());
                    var l = Cursor.init(list);
                    const proto = try l.take(try l.readU8());
                    try l.expectEmpty();
                    try a.expectEmpty();
                    const copy = try self.allocator.dupe(u8, proto);
                    errdefer self.allocator.free(copy);
                    if (self.selected_alpn) |old| self.allocator.free(old);
                    self.selected_alpn = copy;
                },
                ext_session_ticket => {
                    // RFC 5077: an (empty) SessionTicket extension in ServerHello
                    // means the server will issue a NewSessionTicket. It is sent BOTH
                    // when resuming AND when issuing a fresh ticket on a full
                    // handshake, so it does NOT by itself imply the abbreviated path
                    // — that is decided by whether a Certificate follows.
                    if (body.len != 0) return error.BadHandshake;
                    self.server_signaled_ticket = true;
                },
                ext_extended_master_secret => {
                    // RFC 7627: always empty; the echo commits both sides to the
                    // session-hash master-secret derivation.
                    if (body.len != 0) return error.BadHandshake;
                    self.ems_negotiated = true;
                },
                ext_status_request => {
                    // RFC 6066: empty echo announces CertificateStatus.
                    if (body.len != 0) return error.BadHandshake;
                    self.server_signaled_ocsp = true;
                },
                0xff01 => {
                    // RFC 5746 §3.4: on the initial handshake the server's
                    // renegotiated_connection MUST be empty; anything else means
                    // a renegotiation splice and the client must abort.
                    if (body.len != 1 or body[0] != 0) return error.BadHandshake;
                },
                0x001c => {
                    // RFC 8449 record_size_limit: a 2-byte value in [64, 2^14+1];
                    // anything else is illegal_parameter. Store it so our outbound
                    // records honor the server's limit.
                    if (body.len != 2) return error.BadHandshake;
                    const limit = std.mem.readInt(u16, body[0..2], .big);
                    if (limit < tls_record.record_size_limit_min or limit > tls_record.record_size_limit_max) return error.BadHandshake;
                    self.peer_record_size_limit = limit;
                },
                0x002b => return error.ProtocolVersion, // supported_versions would select TLS 1.3.
                // Harmless acknowledgements of extensions we offered: an empty
                // server_name ack (RFC 6066 §3) and ec_point_formats (RFC 8422 —
                // servers commonly echo it; the list must be well-formed and
                // include uncompressed(0), the only format we ever emit/parse).
                0x0000 => if (body.len != 0) return error.BadHandshake,
                0x000b => {
                    if (body.len < 2 or body[0] != body.len - 1) return error.BadHandshake;
                    if (std.mem.indexOfScalar(u8, body[1..], 0) == null) return error.BadHandshake;
                },
                // RFC 5246 §7.4.1.4: a server MUST NOT send an extension the
                // client did not offer — fail closed on anything unsolicited.
                else => return error.BadHandshake,
            }
        }
    }

    fn parseCertificate(self: *Client, body: []const u8) Error!void {
        const chain = try parseCertificateChain(self.allocator, body);
        defer freeChain(self.allocator, chain);
        if (chain.len == 0) return error.EmptyCertificateChain;
        if (!self.skip_cert_verify_for_test) {
            try verifyChainToTrustAnchors(chain, self.trust_anchors, self.server_name, self.now_unix_seconds);
            try self.captureLeafRevocationInputs(chain);
        }
        const leaf = try x509_verify.linkInfo(chain[0]);
        self.leaf_key = try parsePublicKeyFromSpki(leaf.spki_der);
        // The RSA variant borrows the SPKI bytes (in the chain freed above); copy
        // n/e into owned storage so the key survives until ServerKeyExchange.
        if (self.leaf_key) |lk| {
            if (lk == .rsa) {
                const n = lk.rsa.n;
                const e = lk.rsa.e;
                if (n.len > self.leaf_rsa_n.len or e.len > self.leaf_rsa_e.len) return error.BadCertificate;
                @memcpy(self.leaf_rsa_n[0..n.len], n);
                @memcpy(self.leaf_rsa_e[0..e.len], e);
                self.leaf_key = .{ .rsa = .{ .n = self.leaf_rsa_n[0..n.len], .e = self.leaf_rsa_e[0..e.len] } };
            }
        }
    }

    fn captureLeafRevocationInputs(self: *Client, chain: []const []u8) Error!void {
        const leaf = try x509.parse(chain[0]);
        self.leaf_must_staple = leaf.must_staple;
        if (self.leaf_serial) |old| self.allocator.free(old);
        self.leaf_serial = try self.allocator.dupe(u8, leaf.serial_der);
        const issuer_der = if (chain.len >= 2) chain[1] else chain[0];
        const issuer = try x509.parse(issuer_der);
        if (self.issuer_spki) |old| self.allocator.free(old);
        self.issuer_spki = try self.allocator.dupe(u8, issuer.spki_der);
        if (self.crl) |der| {
            try checkCrlRevocation(der, issuer.spki_der, leaf.serial_der, self.now_unix_seconds, self.require_crl);
        }
    }

    fn parseCertificateStatus(self: *Client, body: []const u8) Error!void {
        const staple = try parseCertificateStatusOcsp(body);
        const copy = try self.allocator.dupe(u8, staple);
        errdefer self.allocator.free(copy);
        if (self.skip_cert_verify_for_test) {
            self.ocsp_staple = copy;
            return;
        }
        const issuer_spki = self.issuer_spki orelse return error.BadCertificate;
        const serial = self.leaf_serial orelse return error.BadCertificate;
        try verifyOcspStapleForLeaf(staple, issuer_spki, serial, self.now_unix_seconds);
        self.ocsp_staple = copy;
    }

    fn verifyServerKeyExchange(self: *Client, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const params_start: usize = 0;
        const curve_type = try c.readU8();
        if (curve_type != 3) return error.UnsupportedGroup;
        if (try c.readU16() != named_group_secp256r1) return error.UnsupportedGroup;
        const point_len = try c.readU8();
        const point = try c.take(point_len);
        if (point.len != ecdh_p256.public_length) return error.UnsupportedGroup;
        const params_end = c.pos;
        const scheme = try c.readU16();
        const sig = try c.take(try c.readU16());
        try c.expectEmpty();

        var server_pub: [ecdh_p256.public_length]u8 = undefined;
        @memcpy(&server_pub, point);
        // RFC 7627: the (extended) master secret needs the session hash, which
        // covers the transcript THROUGH ClientKeyExchange — a message not built
        // yet. Hold only the pre-master secret here; `buildClientFlight` derives
        // the master secret and traffic keys right after the CKE joins the
        // transcript, then wipes this copy.
        self.pre_master_secret = try ecdh_p256.sharedSecret(self.key_pair.secret, server_pub);
        self.has_pre_master_secret = true;

        var signed: std.ArrayList(u8) = .empty;
        defer signed.deinit(self.allocator);
        try signed.appendSlice(self.allocator, &self.client_random);
        try signed.appendSlice(self.allocator, &self.server_random);
        try signed.appendSlice(self.allocator, body[params_start..params_end]);
        try verifySignature(self.leaf_key orelse return error.NoServerCertificate, scheme, signed.items, sig);
    }

    fn buildClientFlight(self: *Client) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);

        // mTLS: a CertificateRequest makes the client flight lead with a
        // Certificate (empty when declining), and a presented cert is proven
        // with a CertificateVerify after ClientKeyExchange.
        if (self.cert_requested) {
            const cert_msg = try self.buildClientCertificate();
            defer self.allocator.free(cert_msg);
            try self.transcript.appendSlice(self.allocator, cert_msg);
            const rec = try tls12.writePlainRecord(self.allocator, .handshake, cert_msg);
            defer self.allocator.free(rec);
            try out.appendSlice(self.allocator, rec);
        }

        var point_body: [1 + ecdh_p256.public_length]u8 = undefined;
        point_body[0] = ecdh_p256.public_length;
        @memcpy(point_body[1..], &self.key_pair.public_sec1);
        var cke: std.ArrayList(u8) = .empty;
        defer cke.deinit(self.allocator);
        try writeHandshake(self.allocator, &cke, .client_key_exchange, &point_body);
        try self.transcript.appendSlice(self.allocator, cke.items);
        const cke_rec = try tls12.writePlainRecord(self.allocator, .handshake, cke.items);
        defer self.allocator.free(cke_rec);
        try out.appendSlice(self.allocator, cke_rec);

        // Derive the master secret now that the transcript ends at the
        // ClientKeyExchange (the exact RFC 7627 session-hash coverage; the
        // CertificateVerify below is correctly excluded), then wipe the
        // pre-master secret.
        if (!self.has_pre_master_secret) return error.BadState;
        if (self.ems_negotiated) {
            var hash_buf: [tls12.max_hash_len]u8 = undefined;
            const session_hash = tls12.transcriptHash(suite.hashAlg(), self.transcript.items, &hash_buf);
            self.master_secret = try tls12.deriveExtendedMasterSecret(suite, &self.pre_master_secret, session_hash);
        } else {
            self.master_secret = try tls12.deriveMasterSecret(suite, &self.pre_master_secret, &self.client_random, &self.server_random);
        }
        self.keys = try tls12.deriveKeyMaterial(suite, &self.master_secret, &self.client_random, &self.server_random);
        std.crypto.secureZero(u8, &self.pre_master_secret);
        self.has_pre_master_secret = false;

        if (self.cert_requested and self.client_cert_der != null) {
            const cv_msg = try self.buildClientCertificateVerify();
            defer self.allocator.free(cv_msg);
            try self.transcript.appendSlice(self.allocator, cv_msg);
            const rec = try tls12.writePlainRecord(self.allocator, .handshake, cv_msg);
            defer self.allocator.free(rec);
            try out.appendSlice(self.allocator, rec);
        }

        const verify = try tls12.finishedVerifyData(suite, &self.master_secret, "client finished", self.transcript.items);
        var fin: std.ArrayList(u8) = .empty;
        defer fin.deinit(self.allocator);
        try writeHandshake(self.allocator, &fin, .finished, &verify);
        try self.transcript.appendSlice(self.allocator, fin.items);

        const ccs = try tls12.writePlainRecord(self.allocator, .change_cipher_spec, &.{1});
        defer self.allocator.free(ccs);
        try out.appendSlice(self.allocator, ccs);
        const fin_rec = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.client_write, self.hs_write_seq, .handshake, fin.items);
        self.hs_write_seq += 1;
        defer self.allocator.free(fin_rec);
        try out.appendSlice(self.allocator, fin_rec);
        return out.toOwnedSlice(self.allocator);
    }

    /// Client Certificate (RFC 5246 §7.4.6): certificate_list<0..2^24-1>, each
    /// cert a 3-byte-length-prefixed DER. An empty list declines client auth.
    fn buildClientCertificate(self: *Client) Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.allocator);
        if (self.client_cert_der) |der| {
            try appendU24(self.allocator, &list, @intCast(der.len));
            try list.appendSlice(self.allocator, der);
        }
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU24(self.allocator, &body, @intCast(list.items.len));
        try body.appendSlice(self.allocator, list.items);
        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);
        try writeHandshake(self.allocator, &msg, .certificate, body.items);
        return msg.toOwnedSlice(self.allocator);
    }

    /// Client CertificateVerify (RFC 5246 §7.4.8): a SignatureAndHashAlgorithm +
    /// signature over all handshake messages so far (ClientHello through
    /// ClientKeyExchange — exactly `self.transcript` at this point).
    fn buildClientCertificateVerify(self: *Client) Error![]u8 {
        const key = self.client_key orelse return error.BadState;
        const signed = self.transcript.items;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        switch (key) {
            .ecdsa_p256 => |kp| {
                const sig = ecdsa_p256.sign(signed, kp) catch return error.BadSignature;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = ecdsa_p256.signatureToDer(sig, &der_buf) catch return error.BadSignature;
                try appendU16(self.allocator, &body, sig_ecdsa_secp256r1_sha256);
                try appendU16(self.allocator, &body, @intCast(der.len));
                try body.appendSlice(self.allocator, der);
            },
            .rsa => |k| {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(signed, &digest, .{});
                var sig_buf: [rsa_verify.max_bytes]u8 = undefined;
                const sig = rsa_sign.signPkcs1v15(k, .sha256, &digest, &sig_buf) catch return error.BadSignature;
                try appendU16(self.allocator, &body, sig_rsa_pkcs1_sha256);
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, sig);
            },
        }
        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);
        try writeHandshake(self.allocator, &msg, .certificate_verify, body.items);
        return msg.toOwnedSlice(self.allocator);
    }

    /// Abbreviated-path client flight (RFC 5077): CCS + Finished only. There is
    /// no ClientKeyExchange — keys came from the recovered master_secret. The
    /// client Finished is computed over the abbreviated transcript (ClientHello,
    /// ServerHello[, NewSessionTicket], server Finished).
    fn buildResumedClientFlight(self: *Client) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;
        const verify = try tls12.finishedVerifyData(suite, &self.master_secret, "client finished", self.transcript.items);
        var fin: std.ArrayList(u8) = .empty;
        defer fin.deinit(self.allocator);
        try writeHandshake(self.allocator, &fin, .finished, &verify);
        try self.transcript.appendSlice(self.allocator, fin.items);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const ccs = try tls12.writePlainRecord(self.allocator, .change_cipher_spec, &.{1});
        defer self.allocator.free(ccs);
        try out.appendSlice(self.allocator, ccs);
        const fin_rec = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.client_write, self.hs_write_seq, .handshake, fin.items);
        self.hs_write_seq += 1;
        defer self.allocator.free(fin_rec);
        try out.appendSlice(self.allocator, fin_rec);
        return out.toOwnedSlice(self.allocator);
    }
};

fn writeSupportedGroupsExtension(allocator: Allocator, out: *std.ArrayList(u8)) Error!void {
    var body: [4]u8 = undefined;
    std.mem.writeInt(u16, body[0..2], 2, .big);
    std.mem.writeInt(u16, body[2..4], named_group_secp256r1, .big);
    try writeExtension(allocator, out, 0x000a, &body);
}

fn writeEcPointFormatsExtension(allocator: Allocator, out: *std.ArrayList(u8)) Error!void {
    try writeExtension(allocator, out, 0x000b, &.{ 1, 0 });
}

/// supported_versions offering ONLY TLS 1.2 (0x0303). Standards-compliant 1.2
/// clients send this even though they could omit it, so we include it for wire
/// realism — and it exercises the server's acceptance of the extension (a 1.2
/// server must accept a 1.2-only supported_versions, not reject the extension
/// wholesale).
fn writeSupportedVersionsExtension(allocator: Allocator, out: *std.ArrayList(u8)) Error!void {
    // body = list_len(u8) + ProtocolVersion(2).
    var body: [3]u8 = undefined;
    body[0] = 2;
    std.mem.writeInt(u16, body[1..3], tls12.tls_version, .big);
    try writeExtension(allocator, out, 0x002b, &body);
}

/// RFC 8449 record_size_limit: advertise the largest TLSPlaintext.fragment we
/// accept (the protocol max — our recv path handles full-size records). The
/// server, if it supports the extension, echoes its own limit and we fragment
/// outbound records to honor it.
fn writeRecordSizeLimitExtension(allocator: Allocator, out: *std.ArrayList(u8)) Error!void {
    var body: [2]u8 = undefined;
    std.mem.writeInt(u16, &body, tls_record.record_size_limit_max, .big);
    try writeExtension(allocator, out, 0x001c, &body);
}

fn writeSignatureAlgorithmsExtension(allocator: Allocator, out: *std.ArrayList(u8)) Error!void {
    var body: [10]u8 = undefined;
    std.mem.writeInt(u16, body[0..2], 8, .big);
    std.mem.writeInt(u16, body[2..4], sig_ecdsa_secp256r1_sha256, .big);
    std.mem.writeInt(u16, body[4..6], sig_rsa_pkcs1_sha256, .big);
    std.mem.writeInt(u16, body[6..8], sig_rsa_pkcs1_sha384, .big);
    std.mem.writeInt(u16, body[8..10], 0x0503, .big);
    try writeExtension(allocator, out, 0x000d, &body);
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

fn parseHandshake(bytes: []const u8, off: *usize) Error!HandshakeMsg {
    return parseHandshakeMaybe(bytes, off) orelse error.NeedMore;
}

fn parseHandshakeMaybe(bytes: []const u8, off: *usize) ?HandshakeMsg {
    if (bytes.len - off.* < 4) return null;
    const start = off.*;
    const typ: tls12.HandshakeType = @enumFromInt(bytes[start]);
    const len = (@as(usize, bytes[start + 1]) << 16) | (@as(usize, bytes[start + 2]) << 8) | bytes[start + 3];
    if (bytes.len - start < 4 + len) return null;
    off.* = start + 4 + len;
    return .{ .typ = typ, .body = bytes[start + 4 .. start + 4 + len], .raw = bytes[start .. start + 4 + len] };
}

/// RFC 8446 §4.1.3 downgrade detection. A client that OFFERED a version higher
/// than the one it negotiated MUST abort if the last 8 bytes of
/// ServerHello.random equal a downgrade sentinel — a 1.3-capable server signals a
/// forced downgrade that way. `offered_higher` gates the check: this engine
/// offers only 1.2 (`client_offered_tls13 == false`), so the caller passes a
/// false guard and the check is a no-op. That inertness is required, not
/// incidental — a 1.2-only client must accept the sentinel, otherwise it could
/// never handshake with a 1.3-capable server that stamps it unconditionally (as
/// this project's own 1.2 server does). Passing `true` (once the client offers
/// 1.3) activates the conformant abort with no other edits.
fn parseCertificateStatusOcsp(data: []const u8) Error![]const u8 {
    if (data.len < 4) return error.BadCertificate;
    if (data[0] != 1) return error.BadCertificate;
    const len = (@as(usize, data[1]) << 16) | (@as(usize, data[2]) << 8) | data[3];
    if (data.len != 4 + len or len == 0) return error.BadCertificate;
    return data[4..];
}

fn checkCrlRevocation(
    crl_der: []const u8,
    issuer_spki_der: []const u8,
    leaf_serial_der: []const u8,
    now_unix: ?i64,
    require: bool,
) Error!void {
    const now = now_unix orelse {
        if (require) return error.BadCertificate;
        return;
    };
    const parsed = crl.parse(crl_der) catch {
        if (require) return error.BadCertificate;
        return;
    };
    crl.verifyParsedCrlSignature(parsed, issuer_spki_der) catch {
        if (require) return error.BadCertificate;
        return;
    };
    if (!crl.crlIsCurrent(parsed, now)) {
        if (require) return error.BadCertificate;
        return;
    }
    if (crl.isSerialRevoked(parsed, leaf_serial_der)) return error.CertificateRevoked;
}

fn verifyOcspStapleForLeaf(staple_der: []const u8, issuer_spki_der: []const u8, leaf_serial: []const u8, now_unix: ?i64) Error!void {
    const parsed = ocsp.parse(staple_der) catch return error.BadCertificate;
    const authenticated = if (now_unix) |now|
        ocsp.verifyResponseSignatureWithChain(parsed, issuer_spki_der, now)
    else
        ocsp.verifyResponseSignature(parsed, issuer_spki_der);
    if (!authenticated) return error.BadCertificate;
    try enforceOcspStatusForSerial(parsed, leaf_serial);
    if (now_unix) |now| {
        if (!ocsp.isStapleServable(staple_der, issuer_spki_der, leaf_serial, now, 60))
            return error.BadCertificate;
    }
}

fn enforceOcspStatusForSerial(parsed: anytype, leaf_serial: []const u8) Error!void {
    const status = ocsp.statusForSerial(parsed, leaf_serial) orelse return error.BadCertificate;
    switch (status) {
        .revoked => return error.CertificateRevoked,
        .unknown => return error.BadCertificate,
        .good => return,
    }
}

fn checkDowngradeSentinel(offered_higher: bool, server_random: *const [32]u8) Error!void {
    if (!offered_higher) return;
    const tail = server_random[24..32];
    if (std.mem.eql(u8, tail, &downgrade_sentinel_tls12) or
        std.mem.eql(u8, tail, &downgrade_sentinel_tls11))
    {
        return error.DowngradeDetected;
    }
}

fn parseCertificateChain(allocator: Allocator, body: []const u8) Error![][]u8 {
    var c = Cursor.init(body);
    const list = try c.take(try c.readU24());
    try c.expectEmpty();
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |cert| allocator.free(cert);
        out.deinit(allocator);
    }
    var certs = Cursor.init(list);
    while (certs.remaining() != 0) {
        const der = try certs.take(try certs.readU24());
        try out.append(allocator, try allocator.dupe(u8, der));
    }
    return out.toOwnedSlice(allocator);
}

fn freeChain(allocator: Allocator, chain: [][]u8) void {
    for (chain) |cert| allocator.free(cert);
    allocator.free(chain);
}

fn verifySignature(key: LeafPublicKey, scheme: u16, msg: []const u8, sig: []const u8) Error!void {
    switch (scheme) {
        sig_ecdsa_secp256r1_sha256 => {
            const pk = switch (key) {
                .ecdsa_p256 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            const decoded = try ecdsa_p256.signatureFromDer(sig);
            if (!ecdsa_p256.verify(decoded, msg, pk)) return error.BadSignature;
        },
        sig_rsa_pkcs1_sha256 => {
            const pk = switch (key) {
                .rsa => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, sig)) return error.BadSignature;
        },
        sig_rsa_pkcs1_sha384 => {
            const pk = switch (key) {
                .rsa => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            var digest: [48]u8 = undefined;
            std.crypto.hash.sha2.Sha384.hash(msg, &digest, .{});
            if (!rsa_verify.verifyPkcs1v15(pk, .sha384, &digest, sig)) return error.BadSignature;
        },
        else => return error.UnsupportedSignatureScheme,
    }
}

fn verifyChainToTrustAnchors(chain: []const []const u8, anchors: []const []const u8, server_name: []const u8, now: ?i64) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    if (anchors.len == 0) return error.UnknownCa;
    const leaf = try x509.parse(chain[0]);
    if (!dnsNameMatchesCert(server_name, leaf)) return error.CertificateNameMismatch;
    if (now) |t| try x509_verify.validateParsedAt(leaf, t);
    if (leaf.eku_present and !leaf.eku_server_auth) return error.BadCertificate;

    var i: usize = 0;
    while (i + 1 < chain.len) : (i += 1) {
        try verifyIssuedBy(chain[i], chain[i + 1]);
        const issuer = try x509.parse(chain[i + 1]);
        if (!issuer.basic_constraints_ca) return error.BadCertificate;
        if (issuer.key_usage_present and !issuer.key_usage_cert_sign) return error.BadCertificate;
        if (now) |t| try x509_verify.validateParsedAt(issuer, t);
        // RFC 5280 §4.2.1.10: a CA's NameConstraints bind the leaf's SAN
        // dNSNames. Shared with the TLS 1.3 client (x509_verify.zig) so the
        // two engines cannot silently diverge — this hardened 1.2 client
        // previously omitted the check entirely.
        try x509_verify.enforceNameConstraints(issuer, leaf);
    }

    // RFC 5280 §4.2.1.10 / §6.1.4(m): pathLenConstraint enforcement, shared
    // with the TLS 1.3 client. Reduce the chain to per-cert facts (path limit
    // + self-issued) then check with the pure `enforcePathLen` helper.
    var facts_buf: [16]x509_verify.CaPathFact = undefined;
    const fn_count = x509_verify.buildPathFacts(chain, &facts_buf);
    try x509_verify.enforcePathLen(facts_buf[0..fn_count]);

    // Anchor the chain tip: its issuer DN (or, for a self-issued tip, its own
    // subject DN) must match a configured anchor's subject, and its signature
    // must verify under that anchor's public key. A malformed anchor or a failed
    // match falls through to the next anchor — the search never aborts on one.
    // The signature primitive delegates to x509_verify.verifySignedBy, which
    // covers the full sig-alg set (RSA PKCS#1 SHA-256/384/512, RSASSA-PSS, ECDSA
    // P-256, Ed25519), so real CA links signed with sha384WithRSA or RSASSA-PSS
    // now anchor correctly.
    const last = chain[chain.len - 1];
    const last_info = try x509_verify.linkInfo(last);
    for (anchors) |anchor_der| {
        const anchor_info = x509_verify.linkInfo(anchor_der) catch continue;
        if (!std.mem.eql(u8, last_info.issuer_der, anchor_info.subject_der) and
            !std.mem.eql(u8, last_info.subject_der, anchor_info.subject_der)) continue;
        x509_verify.verifySignedBy(last_info, anchor_info) catch continue;
        return;
    }
    return error.UnknownCa;
}

fn verifyIssuedBy(child_der: []const u8, issuer_der: []const u8) Error!void {
    const child = try x509_verify.linkInfo(child_der);
    const issuer = try x509_verify.linkInfo(issuer_der);
    if (!std.mem.eql(u8, child.issuer_der, issuer.subject_der)) return error.BadCertificate;
    // Full sig-alg set via x509_verify (see verifyChainToTrustAnchors).
    try x509_verify.verifySignedBy(child, issuer);
}

fn dnsNameMatchesCert(server_name: []const u8, cert: x509.Certificate) bool {
    var i: usize = 0;
    while (i < cert.san_dns_count) : (i += 1) {
        if (asciiEqlIgnoreCase(cert.san_dns[i], server_name)) return true;
        if (wildcardMatches(cert.san_dns[i], server_name)) return true;
    }
    return false;
}

fn wildcardMatches(pattern: []const u8, name: []const u8) bool {
    if (pattern.len < 3 or pattern[0] != '*' or pattern[1] != '.') return false;
    const suffix = pattern[1..];
    if (name.len <= suffix.len) return false;
    if (!asciiEqlIgnoreCase(name[name.len - suffix.len ..], suffix)) return false;
    return std.mem.indexOfScalar(u8, name[0 .. name.len - suffix.len], '.') == null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    return true;
}

fn parsePublicKeyFromSpki(spki_der: []const u8) Error!LeafPublicKey {
    var top = x509.DerReader.init(spki_der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(x509.Tag.sequence);
    const key_bits = try spki.readExpected(x509.Tag.bit_string);
    try spki.expectEmpty();
    const alg = try parseSpkiAlgorithm(spki, alg_seq);
    const key_bytes = try bitStringBytes(key_bits);
    if (oidEq(alg.oid, &oid_ec_public_key)) {
        const params = alg.params orelse return error.UnsupportedPublicKey;
        if (!oidEq(params, &oid_prime256v1)) return error.UnsupportedPublicKey;
        return .{ .ecdsa_p256 = try ecdsa_p256.parsePublicKeySec1(key_bytes) };
    }
    if (oidEq(alg.oid, &oid_rsa_encryption)) {
        var r = x509.DerReader.init(key_bytes);
        const rsa_seq = try r.readExpected(x509.Tag.sequence);
        try r.expectEmpty();
        var body = try r.child(rsa_seq);
        const n = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        const e = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        try body.expectEmpty();
        return .{ .rsa = .{ .n = n, .e = e } };
    }
    return error.UnsupportedPublicKey;
}

const SpkiAlgorithm = struct { oid: []const u8, params: ?[]const u8 };

fn parseSpkiAlgorithm(parent: x509.DerReader, seq_tlv: x509.Tlv) Error!SpkiAlgorithm {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) {
        const p = try r.readTlv();
        if (p.tag == x509.Tag.oid) params = p.value;
    }
    try r.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

fn bitStringBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.value.len == 0 or tlv.value[0] != 0) return error.BadCertificate;
    return tlv.value[1..];
}

fn positiveIntegerBytes(tlv: x509.Tlv) Error![]const u8 {
    var bytes = tlv.value;
    if (bytes.len == 0) return error.BadCertificate;
    if (bytes.len > 1 and bytes[0] == 0) bytes = bytes[1..];
    return bytes;
}

fn oidEq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

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

    fn readU24(self: *Cursor) Error!usize {
        const b = try self.take(3);
        return (@as(usize, b[0]) << 16) | (@as(usize, b[1]) << 8) | b[2];
    }

    fn readU32(self: *Cursor) Error!u32 {
        const b = try self.take(4);
        return (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) | (@as(u32, b[2]) << 8) | b[3];
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

const testing = std.testing;

test "tls12 client downgrade sentinel (RFC 8446 4.1.3): inert for a 1.2-only client, aborts when a higher version was offered" {
    // Arrange: a server_random carrying the 1.3->1.2 sentinel, one carrying the
    // 1.3->1.1-or-below sentinel, and an ordinary random.
    var with_tls12_sentinel = @as([32]u8, @splat(0xAB));
    @memcpy(with_tls12_sentinel[24..32], &downgrade_sentinel_tls12);
    var with_tls11_sentinel = @as([32]u8, @splat(0xCD));
    @memcpy(with_tls11_sentinel[24..32], &downgrade_sentinel_tls11);
    const normal_random = @as([32]u8, @splat(0x5A));

    // This engine's real configuration is 1.2-only, so the sentinel is NOT a
    // downgrade signal for it: the check must accept EVERY random, including one a
    // 1.3-capable server (such as this project's own 1.2 server) stamped.
    try testing.expect(!client_offered_tls13);
    try checkDowngradeSentinel(client_offered_tls13, &with_tls12_sentinel);
    try checkDowngradeSentinel(client_offered_tls13, &with_tls11_sentinel);
    try checkDowngradeSentinel(client_offered_tls13, &normal_random);

    // Had the client offered a higher version, RFC 8446 §4.1.3 requires aborting
    // on either sentinel while still accepting an ordinary random.
    try testing.expectError(error.DowngradeDetected, checkDowngradeSentinel(true, &with_tls12_sentinel));
    try testing.expectError(error.DowngradeDetected, checkDowngradeSentinel(true, &with_tls11_sentinel));
    try checkDowngradeSentinel(true, &normal_random);
}

test "tls12 EMS required: client aborts when the ServerHello does not echo the extension" {
    const allocator = std.testing.allocator;
    const anchors = [_][]const u8{};
    var client = try Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();

    // Synthetic ServerHello body: 1.2, random, empty session_id, ECDHE-ECDSA
    // AES-128-GCM, null compression, and ONLY a renegotiation_info extension —
    // no extended_master_secret echo.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, tls12.tls_version);
    const rnd: [32]u8 = @splat(0x42);
    try body.appendSlice(allocator, &rnd);
    try body.append(allocator, 0);
    try appendU16(allocator, &body, 0xc02b);
    try body.append(allocator, 0);
    try appendU16(allocator, &body, 5); // extensions length
    try body.appendSlice(allocator, &.{ 0xff, 0x01, 0x00, 0x01, 0x00 });
    try std.testing.expectError(error.EmsRequired, client.parseServerHello(body.items));

    // A ServerHello with NO extensions block at all is refused the same way.
    var bare: std.ArrayList(u8) = .empty;
    defer bare.deinit(allocator);
    try appendU16(allocator, &bare, tls12.tls_version);
    try bare.appendSlice(allocator, &rnd);
    try bare.append(allocator, 0);
    try appendU16(allocator, &bare, 0xc02b);
    try bare.append(allocator, 0);
    var client2 = try Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client2.deinit();
    try std.testing.expectError(error.EmsRequired, client2.parseServerHello(bare.items));
}

test "tls12 client fails closed on hostile ServerHello extensions" {
    const allocator = std.testing.allocator;
    const anchors = [_][]const u8{};
    var client = try Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();

    // A non-empty extended_master_secret body is malformed (RFC 7627: always empty).
    const bad_ems = [_]u8{ 0x00, 0x17, 0x00, 0x01, 0x00 };
    try std.testing.expectError(error.BadHandshake, client.parseServerExtensions(&bad_ems));

    // A non-empty renegotiated_connection on the initial handshake is a splice
    // (RFC 5746 §3.4) and must abort.
    const bad_reneg = [_]u8{ 0xff, 0x01, 0x00, 0x02, 0x01, 0xaa };
    try std.testing.expectError(error.BadHandshake, client.parseServerExtensions(&bad_reneg));

    // An unsolicited extension (heartbeat, 0x000f) is refused outright
    // (RFC 5246 §7.4.1.4: servers may only echo what was offered).
    const unsolicited = [_]u8{ 0x00, 0x0f, 0x00, 0x01, 0x01 };
    try std.testing.expectError(error.BadHandshake, client.parseServerExtensions(&unsolicited));

    // The well-formed hardened echo set is accepted.
    const ok = [_]u8{
        0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info: empty marker
        0x00, 0x17, 0x00, 0x00, // extended_master_secret
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats (echo)
    };
    try client.parseServerExtensions(&ok);
    try std.testing.expect(client.ems_negotiated);
}

test "TLS 1.2 client rejects an out-of-range server record_size_limit (RFC 8449)" {
    const allocator = std.testing.allocator;
    const anchors = [_][]const u8{};
    var client = try Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();

    // ServerHello extension bytes carrying record_size_limit (0x001c). 63 is one
    // below the legal minimum of 64; anything out of [64, 2^14+1] is rejected.
    const too_small = [_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x00, 0x3f };
    try std.testing.expectError(error.BadHandshake, client.parseServerExtensions(&too_small));

    // 0x4002 = 16386 — one above the maximum (2^14+1 = 16385).
    const too_large = [_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x40, 0x02 };
    try std.testing.expectError(error.BadHandshake, client.parseServerExtensions(&too_large));

    // A wrong-length body (1 byte) is rejected too.
    const bad_len = [_]u8{ 0x00, 0x1c, 0x00, 0x01, 0x40 };
    try std.testing.expectError(error.BadHandshake, client.parseServerExtensions(&bad_len));

    // A valid value is accepted and drives outbound fragmentation.
    const ok = [_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x00, 0x40 }; // 64
    try client.parseServerExtensions(&ok);
    try std.testing.expectEqual(@as(usize, 64), client.peer_record_size_limit);
}

// ===========================================================================
// Certificate-chain signature-algorithm coverage (roadmap 1.3/#46).
//
// verifyChainToTrustAnchors delegates its signature primitive to
// x509_verify.verifySignedBy, so the TLS 1.2 client now anchors CA links across
// the FULL sig-alg set (RSA PKCS#1 SHA-256/384/512, RSASSA-PSS, ECDSA P-256,
// Ed25519), not just RSA-SHA256 + ECDSA-SHA256. Each cert below is minted
// self-signed with a SAN and used as its OWN trust anchor: the anchor loop
// matches the tip's subject DN, then verifies the tip's signature under the
// anchor's public key — precisely the code path a real intermediate->root link
// drives, exercised once per algorithm. `now = null` skips the validity window.
// ===========================================================================

const x509_selfsign = @import("../proto/x509_selfsign.zig");
const StdEd25519 = std.crypto.sign.Ed25519;

const chain_test_san = "leaf.tls12.onyx.test";

fn hexConst(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn verifySelfAnchored(der: []const u8) Error!void {
    const chain = [_][]const u8{der};
    const anchors = [_][]const u8{der};
    return verifyChainToTrustAnchors(&chain, &anchors, chain_test_san, null);
}

// A real RSA-2048 private key (the same vector x509_selfsign's own tests use) for
// minting RSA-signed test certs.
const chain_test_rsa_n = hexConst("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
const chain_test_rsa_e = hexConst("010001");
const chain_test_rsa_d = hexConst("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
const chain_test_rsa_p = hexConst("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
const chain_test_rsa_q = hexConst("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
const chain_test_rsa_dp = hexConst("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
const chain_test_rsa_dq = hexConst("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
const chain_test_rsa_qinv = hexConst("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");

fn chainTestRsaKey() rsa_sign.PrivateKey {
    return .{
        .n = &chain_test_rsa_n,
        .e = &chain_test_rsa_e,
        .d = &chain_test_rsa_d,
        .p = &chain_test_rsa_p,
        .q = &chain_test_rsa_q,
        .dp = &chain_test_rsa_dp,
        .dq = &chain_test_rsa_dq,
        .qinv = &chain_test_rsa_qinv,
    };
}

const RsaSigVariant = struct { sig_sha384: bool = false, sig_pss: bool = false };

fn buildRsaChainCert(out: []u8, serial: u8, variant: RsaSigVariant) ![]const u8 {
    return x509_selfsign.buildSelfSignedRsa(out, .{
        .common_name = "onyx tls12 rsa test",
        .not_before = 1_704_067_200, // 2024-01-01
        .not_after = 1_924_991_999, // 2030-12-31
        .serial = &.{ 0x52, serial },
        .public_modulus = &chain_test_rsa_n,
        .public_exponent = &chain_test_rsa_e,
        .private_key = chainTestRsaKey(),
        .dns_names = &.{chain_test_san},
        .sig_sha384 = variant.sig_sha384,
        .sig_pss = variant.sig_pss,
    });
}

test "TLS 1.2 client anchors an RSA PKCS#1 SHA-256 self-signed chain (regression)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x01, .{});
    try verifySelfAnchored(der);
}

test "TLS 1.2 client anchors an RSA PKCS#1 SHA-384 self-signed chain (new: sha384WithRSA)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x02, .{ .sig_sha384 = true });
    try verifySelfAnchored(der);
}

test "TLS 1.2 client anchors an RSASSA-PSS self-signed chain (new: params threaded through)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x03, .{ .sig_pss = true });
    try verifySelfAnchored(der);
}

test "TLS 1.2 client anchors an ECDSA P-256 SHA-256 self-signed chain (regression)" {
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(@as([ecdsa_p256.KeyPair.seed_length]u8, @splat(0x2c)));
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(&buf, .{
        .common_name = "onyx tls12 ecdsa test",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x52, 0x04 },
        .key_pair = kp,
        .dns_names = &.{chain_test_san},
    });
    try verifySelfAnchored(der);
}

test "TLS 1.2 client anchors an Ed25519 self-signed chain (new)" {
    const kp = try StdEd25519.KeyPair.generateDeterministic(@as([StdEd25519.KeyPair.seed_length]u8, @splat(0x2d)));
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&buf, .{
        .common_name = "onyx tls12 ed25519 test",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x52, 0x05 },
        .key_pair = kp,
        .dns_names = &.{chain_test_san},
    });
    try verifySelfAnchored(der);
}

test "TLS 1.2 client rejects a self-signed chain whose signature byte was flipped (isolates the sig check)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x0a, .{ .sig_pss = true });
    // Baseline: the untampered RSASSA-PSS self-signature anchors.
    try verifySelfAnchored(der);

    // Flip one bit in the trailing signature BIT STRING; every other byte — name,
    // validity, SPKI, DN linkage — is byte-identical, so only the signature check
    // can be what now rejects. The anchor loop's `catch continue` turns the failed
    // verify into UnknownCa (no other anchor to try).
    var tampered: [2048]u8 = undefined;
    @memcpy(tampered[0..der.len], der);
    tampered[der.len - 1] ^= 0x01;
    try std.testing.expectError(error.UnknownCa, verifySelfAnchored(tampered[0..der.len]));
}

// ===========================================================================
// F1 regression: this hardened TLS 1.2 client previously enforced neither a
// CA's NameConstraints nor pathLenConstraint at all (only CA:TRUE and
// keyCertSign), while the TLS 1.3 client already enforced both — letting a
// name-constrained sub-CA in the anchor set mint an out-of-scope leaf that
// TLS 1.3 correctly rejected but TLS 1.2 silently accepted. Both checks now
// live once in `x509_verify.zig` and are called from both clients, so they
// cannot diverge again. See `tls_client.zig`'s mirror test for the TLS 1.3
// control proving the two engines agree.
// ===========================================================================

test "TLS 1.2 client rejects a name-constrained CA's cross-domain leaf (F1)" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const ca_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xc1)));
    const leaf_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xc2)));

    // The CA is constrained to `.corp.example` (permittedSubtrees, dNSName).
    var ca_buf: [1024]u8 = undefined;
    const ca_der = try x509_verify.mintEd25519CertExt(
        &ca_buf,
        "Onyx Name-Constrained CA",
        "Onyx Name-Constrained CA",
        ca_kp.public_key.toBytes(),
        ca_kp,
        1_704_067_200,
        1_924_991_999,
        .{ .is_ca = true, .permitted_dns = &.{".corp.example"} },
    );

    // The CA (mis)issues a leaf entirely outside its permitted subtree.
    var leaf_buf: [1024]u8 = undefined;
    const leaf_der = try x509_verify.mintEd25519CertExt(
        &leaf_buf,
        "Onyx Name-Constrained CA",
        "login.victim-bank.com",
        leaf_kp.public_key.toBytes(),
        ca_kp,
        1_704_067_200,
        1_924_991_999,
        .{ .dns_names = &.{"login.victim-bank.com"} },
    );

    const chain = [_][]const u8{ leaf_der, ca_der };
    const anchors = [_][]const u8{ca_der};
    try std.testing.expectError(
        error.BadCertificate,
        verifyChainToTrustAnchors(&chain, &anchors, "login.victim-bank.com", null),
    );
}

test "TLS 1.2 client rejects a pathLen:0 CA with a spliced intermediate (F1)" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const root_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xd1)));
    const mid_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xd2)));
    const leaf_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xd3)));

    // Root asserts pathLenConstraint:0 — no intermediates permitted below it.
    var root_buf: [1024]u8 = undefined;
    const root_der = try x509_verify.mintEd25519CertExt(
        &root_buf,
        "Onyx PathLen0 Root",
        "Onyx PathLen0 Root",
        root_kp.public_key.toBytes(),
        root_kp,
        1_704_067_200,
        1_924_991_999,
        .{ .is_ca = true, .path_len = 0 },
    );

    // A non-self-issued intermediate spliced in anyway (a misissuance/attack
    // scenario the root's pathLen:0 exists to forbid).
    var mid_buf: [1024]u8 = undefined;
    const mid_der = try x509_verify.mintEd25519CertExt(
        &mid_buf,
        "Onyx PathLen0 Root",
        "Onyx Spliced Intermediate",
        mid_kp.public_key.toBytes(),
        root_kp,
        1_704_067_200,
        1_924_991_999,
        .{ .is_ca = true },
    );

    var leaf_buf: [1024]u8 = undefined;
    const leaf_der = try x509_verify.mintEd25519CertExt(
        &leaf_buf,
        "Onyx Spliced Intermediate",
        "leaf.pathlen0.test",
        leaf_kp.public_key.toBytes(),
        mid_kp,
        1_704_067_200,
        1_924_991_999,
        .{ .dns_names = &.{"leaf.pathlen0.test"} },
    );

    const chain = [_][]const u8{ leaf_der, mid_der, root_der };
    const anchors = [_][]const u8{root_der};
    try std.testing.expectError(
        error.BadCertificate,
        verifyChainToTrustAnchors(&chain, &anchors, "leaf.pathlen0.test", null),
    );
}

// ===========================================================================
// F5 regression: `wait_server_flight` (and its `wait_server_ccs` /
// `wait_resumed_server_ccs` siblings) used to parse handshake messages only
// from the CURRENT TLS record's fragment. When a message spanned multiple
// records (e.g. a large Certificate chain), the incomplete record was
// returned as `.need_more` WITHOUT being consumed from `recv_buf` — so the
// NEXT `feed()` call re-parsed the exact same still-head-of-buffer record
// forever: `completeRecord` always finds the same first record, ServerHello
// gets re-handled every time (corrupting the transcript), and the
// newly-arrived bytes after it are never reached. `hs_plain` (see its field
// doc above) now reassembles across records and is capped so a message that
// never completes cannot grow the client's memory without bound.
// ===========================================================================

const tls12_server = @import("tls12_server.zig");

/// Locate the Certificate handshake message within one record's fragment and
/// return an offset strictly inside its declared body — the split point used
/// to re-frame a single-record test flight as two records for the reassembly
/// regression below.
fn splitOffsetInsideCertificate(fragment: []const u8) usize {
    var off: usize = 0;
    while (off + 4 <= fragment.len) {
        const typ = fragment[off];
        const len = (@as(usize, fragment[off + 1]) << 16) | (@as(usize, fragment[off + 2]) << 8) | fragment[off + 3];
        if (typ == @intFromEnum(tls12.HandshakeType.certificate)) return off + 4 + len / 2;
        off += 4 + len;
    }
    unreachable; // test-only: the fixture flight always carries a Certificate.
}

/// Re-frame a single TLS record's fragment as two records, split at `split`
/// (a fragment-relative offset). Returns both owned record buffers.
fn reframeAsTwoRecords(allocator: Allocator, sf: []const u8, split: usize) !struct { a: []u8, b: []u8 } {
    const content_type = sf[0];
    const version = sf[1..3];
    const fragment = sf[tls12.record_header_len..];

    var a: std.ArrayList(u8) = .empty;
    errdefer a.deinit(allocator);
    try a.append(allocator, content_type);
    try a.appendSlice(allocator, version);
    var len_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_buf, @intCast(split), .big);
    try a.appendSlice(allocator, &len_buf);
    try a.appendSlice(allocator, fragment[0..split]);

    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(allocator);
    try b.append(allocator, content_type);
    try b.appendSlice(allocator, version);
    std.mem.writeInt(u16, &len_buf, @intCast(fragment.len - split), .big);
    try b.appendSlice(allocator, &len_buf);
    try b.appendSlice(allocator, fragment[split..]);

    return .{ .a = try a.toOwnedSlice(allocator), .b = try b.toOwnedSlice(allocator) };
}

test "TLS 1.2 client reassembles a Certificate message split across two TLS records (F5)" {
    const allocator = std.testing.allocator;
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(@as([ecdsa_p256.KeyPair.seed_length]u8, @splat(0x5a)));
    var cert_buf: [1024]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "onyx tls12 split test",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x5a, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"localhost"},
    });
    const chain = [_][]const u8{cert};
    const anchors = [_][]const u8{cert};

    var server = try tls12_server.Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = kp,
    });
    defer server.deinit();
    var client = try Client.init(allocator, .{
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

    // Split the server's ONE flight record into two records at a point
    // strictly inside the Certificate handshake message — the exact class of
    // split this client previously hung (or corrupted its transcript) on.
    const fragment = sf[tls12.record_header_len..];
    const split = splitOffsetInsideCertificate(fragment);
    try std.testing.expect(split > 0 and split < fragment.len);
    const parts = try reframeAsTwoRecords(allocator, sf, split);
    defer allocator.free(parts.a);
    defer allocator.free(parts.b);

    // First record alone: the Certificate message is incomplete — must be
    // `.need_more`, not an error and not a completed flight.
    switch (try client.feed(parts.a)) {
        .need_more => {},
        .bytes_to_send => |b| {
            allocator.free(b);
            return error.TestUnexpectedResult;
        },
    }

    // Second record completes Certificate + ServerKeyExchange +
    // ServerHelloDone; the client must reassemble across the split and
    // produce its own flight rather than re-looping on the first record.
    const cf = switch (try client.feed(parts.b)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    try std.testing.expectEqual(State.wait_server_ccs, client.state);
}

test "TLS 1.2 client rejects a handshake message whose reassembled size exceeds the cap (F5, fail-closed)" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &[_][]const u8{},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    const ch = try client.start();
    defer allocator.free(ch);

    // A bogus handshake message (type=2/server_hello — any non-Certificate
    // type exercises the smaller 64 KiB cap) claims a declared body length
    // far larger than the cap; the filler records below never complete it.
    const header = [_]u8{ 2, 0xff, 0xff, 0xff };
    switch (try feedOneHandshakeRecord(&client, allocator, &header)) {
        .need_more => {},
        .bytes_to_send => |b| {
            allocator.free(b);
            return error.TestUnexpectedResult;
        },
    }

    var filler: [tls12.max_plaintext_len]u8 = @splat(0xAA);
    var saw_too_large = false;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const result = feedOneHandshakeRecord(&client, allocator, &filler) catch |err| {
            try std.testing.expectEqual(error.HandshakeMessageTooLarge, err);
            saw_too_large = true;
            break;
        };
        switch (result) {
            .need_more => {},
            .bytes_to_send => |b| {
                allocator.free(b);
                return error.TestUnexpectedResult;
            },
        }
    }
    try std.testing.expect(saw_too_large);
}

fn feedOneHandshakeRecord(client: *Client, allocator: Allocator, fragment: []const u8) Error!FeedResult {
    var rec: std.ArrayList(u8) = .empty;
    defer rec.deinit(allocator);
    try rec.append(allocator, @intFromEnum(tls12.ContentType.handshake));
    var ver: [2]u8 = undefined;
    std.mem.writeInt(u16, &ver, tls12.tls_version, .big);
    try rec.appendSlice(allocator, &ver);
    var len_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_buf, @intCast(fragment.len), .big);
    try rec.appendSlice(allocator, &len_buf);
    try rec.appendSlice(allocator, fragment);
    return client.feed(rec.items);
}

fn clientHelloHasExtension(hello_record: []const u8, ext_type: u16) bool {
    if (hello_record.len < 9) return false;
    const rec_len = (@as(usize, hello_record[3]) << 8) | hello_record[4];
    if (hello_record.len < 5 + rec_len) return false;
    const hs = hello_record[5 .. 5 + rec_len];
    if (hs.len < 4) return false;
    const body = hs[4..];
    if (body.len < 2 + 32 + 1) return false;
    var off: usize = 2 + 32;
    const sid_len = body[off];
    off += 1 + sid_len;
    if (off + 2 > body.len) return false;
    const suites_len = (@as(usize, body[off]) << 8) | body[off + 1];
    off += 2 + suites_len;
    if (off + 1 > body.len) return false;
    const comp_len = body[off];
    off += 1 + comp_len;
    if (off + 2 > body.len) return false;
    const ext_len = (@as(usize, body[off]) << 8) | body[off + 1];
    off += 2;
    if (off + ext_len > body.len) return false;
    const exts = body[off .. off + ext_len];
    var i: usize = 0;
    while (i + 4 <= exts.len) {
        const typ = (@as(u16, exts[i]) << 8) | exts[i + 1];
        const len = (@as(usize, exts[i + 2]) << 8) | exts[i + 3];
        i += 4;
        if (i + len > exts.len) return false;
        if (typ == ext_type) return true;
        i += len;
    }
    return false;
}

test "exploit: TLS 1.2 ClientHello offers OCSP status_request" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{
        .server_name = "staple.test",
        .trust_anchors = &[_][]const u8{},
    });
    defer client.deinit();
    const hello = try client.start();
    defer allocator.free(hello);
    try std.testing.expect(clientHelloHasExtension(hello, ext_status_request));
}

test "exploit: TLS 1.2 require_crl fails closed on an unusable CRL" {
    try std.testing.expectError(
        error.BadCertificate,
        checkCrlRevocation(&[_]u8{ 0x30, 0x00 }, &[_]u8{}, &[_]u8{0x2A}, null, true),
    );
    try std.testing.expectError(
        error.BadCertificate,
        checkCrlRevocation(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, &[_]u8{}, &[_]u8{0x2A}, 1_767_225_601, true),
    );
}

test "exploit: TLS 1.2 CertificateStatus for the wrong serial fails closed" {
    var parsed = ocsp.Parsed{
        .der = &.{},
        .response_status = .successful,
        .basic_response_der = null,
        .tbs_response_data_der = &.{},
        .signature_algorithm_oid = &.{},
        .signature_value = &.{},
        .responses = undefined,
        .response_count = 1,
    };
    parsed.responses[0] = .{
        .hash_algorithm_oid = &.{},
        .issuer_name_hash = &.{},
        .issuer_key_hash = &.{},
        .serial = &[_]u8{0xAA},
        .cert_status = .good,
        .this_update = "20260102030405Z",
        .next_update = "20270102030405Z",
    };
    try std.testing.expectError(error.BadCertificate, enforceOcspStatusForSerial(parsed, &[_]u8{0x10}));
    parsed.responses[0].cert_status = .unknown;
    try std.testing.expectError(error.BadCertificate, enforceOcspStatusForSerial(parsed, &[_]u8{0xAA}));
    parsed.responses[0].cert_status = .revoked;
    try std.testing.expectError(error.CertificateRevoked, enforceOcspStatusForSerial(parsed, &[_]u8{0xAA}));
}

test "exploit: TLS 1.2 CertificateStatus body must be status_type=ocsp" {
    try std.testing.expectError(error.BadCertificate, parseCertificateStatusOcsp(&[_]u8{ 2, 0, 0, 1, 0x00 }));
    try std.testing.expectError(error.BadCertificate, parseCertificateStatusOcsp(&[_]u8{ 1, 0, 0, 0 }));
    const ok = [_]u8{ 1, 0, 0, 0x03, 0x30, 0x01, 0x00 };
    try std.testing.expectEqualSlices(u8, ok[4..], try parseCertificateStatusOcsp(&ok));
}
