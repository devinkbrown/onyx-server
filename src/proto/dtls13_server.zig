// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.3 server-side handshake flight state machine (RFC 9147) for the
//! WebRTC DTLS-SRTP media leg (RFC 5764 / RFC 8827). Onyx Server is always the DTLS
//! *server* (`setup:passive`); the browser/mobile peer initiates.
//!
//! Drives the TLS 1.3 handshake (TLS_AES_128_GCM_SHA256 over secp256r1) on top
//! of the record layers (`dtls12_record.zig` for epoch-0 DTLSPlaintext,
//! `dtls_record.zig` for the epoch-2 DTLSCiphertext unified header + AEAD) and
//! the message codecs in `dtls13_messages.zig`:
//!
//!   client → ClientHello (no cookie)
//!   server → HelloRetryRequest(cookie)                 [stateless, no state kept]
//!   client → ClientHello (cookie extension)
//!   server → ServerHello, {EncryptedExtensions, Certificate, CertificateVerify,
//!            Finished}                                  [epoch 0 then epoch 2]
//!   client → {Finished}                                [epoch 2]
//!   server → [ACK]                                     [handshake established]
//!
//! DoS resistance: the HelloRetryRequest cookie is a keyed MAC binding the
//! peer's transport address to the ClientHello transcript hash. No per-peer state
//! is allocated until a returned cookie proves return-routability, so half-open
//! handshakes are bounded and fail-closed. The cookie carries `Hash(ClientHello1)`
//! so the RFC 8446 §4.4.1 synthetic `message_hash` transcript can be
//! reconstructed statelessly on the second ClientHello.
//!
//! The TLS 1.3 key schedule reuses `crypto/hkdf_tls13.zig`; the handshake
//! *message framing* is DTLS-form (12-byte handshake headers, DTLS transcript)
//! because the TLS-over-TCP builders in `tls_server.zig` are private and hard-
//! wired to 5-byte TLS framing. On completion the RFC 9147 exporter derives SRTP
//! keying material (`dtls_srtp.exportSrtpKeysTls13`) stored on the session,
//! exposed via the same accessor API the 1.2 terminator uses.
//!
//! AEAD nonce discipline: each epoch-2 record uses a distinct sequence number →
//! a distinct GCM nonce. The on-wire sequence number is record-number-encrypted
//! (RFC 9147 §4.2.3). Every parse is fail-closed and constant-time where secret
//! (cookie, verify_data); hostile UDP input never traps.
//!
//! INTEROP CAVEAT — this engine is OPT-IN and DEFAULT-OFF (`[media].dtls13`).
//! Two RFC 9147 transcript details are underspecified vs. real stacks and are
//! validated here only by the same-library loopback, NOT against a browser:
//!   1. Handshake-message transcript header form: this engine uses the DTLS
//!      12-byte header (message_seq, fragment_offset=0, fragment_length=length),
//!      matching the DTLS 1.2 sibling. A stack that normalises to the TLS 1.3
//!      4-byte header would compute a different transcript.
//!   2. The RFC 8446 §4.4.1 synthetic `message_hash` uses the same DTLS 12-byte
//!      header form here.
//! Both are self-consistent (client + server from this lib interoperate) and
//! MUST be validated against a real DTLS 1.3 client before the flag is enabled
//! in production.

/// GAP-V1 hold. The RFC 9147 transcript caveats above are not browser-proven.
/// `[media].dtls13` stays default-off until an unmodified browser completes
/// DTLS 1.3 and media flows. DTLS 1.2 is a separate engine and is not weakened
/// by this hold. Do not clear this while the caveat stands.
pub const browser_interop_caveat_held = true;

const std = @import("std");

const p_record = @import("dtls12_record.zig"); // epoch-0 DTLSPlaintext framing
const record13 = @import("dtls_record.zig"); // epoch-2 unified header + AEAD + RNE
const dhs = @import("dtls_handshake.zig");
const msg13 = @import("dtls13_messages.zig");
const kx = @import("dtls_keyexchange.zig");
const dtls_srtp = @import("dtls_srtp.zig");
const fingerprint = @import("dtls_fingerprint.zig");
const peer_verify = @import("dtls_peer_verify.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const hkdf_tls13 = @import("../crypto/hkdf_tls13.zig");
const x509 = @import("../crypto/x509.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const TransportAddress = @import("ice.zig").TransportAddress;
const KS = hkdf_tls13.KeySchedule(.sha256);

/// Cookie = flags(1) || Hash(CH1)(32) || HMAC(cookie_secret, addr||port||flags||Hash(CH1))(32).
/// The flags byte records whether the HRR selected a key_share group, so the
/// exact HRR bytes are reconstructable on CH2 for the transcript.
pub const cookie_len: usize = 1 + 32 + 32;
pub const hash_len: usize = 32;
/// Cookie flag bit: the HRR that issued this cookie carried a key_share group
/// selection (RFC 8446 §4.1.4) because CH1 didn't lead with a secp256r1 share.
const cookie_flag_group_selection: u8 = 0x01;
pub const cert_der_cap: usize = 1024;
/// Reassembly / parse bound for an inbound plaintext ClientHello.
pub const ch_reasm_cap: usize = 2048;
/// Cached server flight (ServerHello + the four epoch-2 messages).
pub const flight_cap: usize = 2048;
pub const ack_cap: usize = 64;
/// Max plaintext of an epoch-2 handshake record (12-byte hdr + body + inner-type).
const enc_scratch_cap: usize = dhs.handshake_header_len + cert_der_cap + 64 + 1;

/// DTLSInnerPlaintext content types (RFC 9147 §4).
const inner_handshake: u8 = 22;
const inner_ack: u8 = 26;

/// Handshake epochs (RFC 9147 §6.1): 0 = cleartext, 2 = handshake traffic.
const epoch_handshake: u16 = 2;

/// Default bound on concurrent (post-cookie) handshakes.
pub const default_max_sessions: usize = 256;

pub const Error = error{
    CertTooLarge,
} || record13.EncodeError;

const State = enum {
    /// Cookie validated, server flight sent, awaiting the client Finished.
    expect_client_finish,
    established,
};

pub const Session = struct {
    active: bool = false,
    addr: TransportAddress = .{},
    state: State = .expect_client_finish,
    last_activity_ms: i64 = 0,

    client_random: [32]u8 = @splat(0),
    srtp_profile: u16 = 0,

    /// Post-flight secrets (everything needed once the server flight is out).
    server_hs_keys: record13.Aes128GcmKeys = undefined,
    client_hs_keys: record13.Aes128GcmKeys = undefined,
    client_finished_key: [hash_len]u8 = @splat(0),
    transcript_through_server_finished: [hash_len]u8 = @splat(0),
    exporter_master: [hash_len]u8 = @splat(0),
    have_secrets: bool = false,

    srtp_keys: dtls_srtp.ExportedKeys = undefined,

    /// RFC 8122 peer verification. Mirrors the 1.2 terminator: `fp_verified` is
    /// set true once a presented certificate matched the expected fingerprint AND
    /// possession of its key was proven (client CertificateVerify validated).
    fp_verified: bool = false,

    /// Mutual auth (client-certificate capture, #64). Set at server-flight
    /// emission when the terminator requests client certs AND a fingerprint is
    /// bound. Once set, `peerVerifiedSession` requires `fp_verified` for THIS
    /// session independent of the live binding table.
    mutual_auth: bool = false,
    /// Running handshake transcript. Stored through the server Finished; when
    /// mutual, extended with the client Certificate + CertificateVerify so the
    /// client Finished is checked against the post-client-auth transcript.
    transcript: Sha256 = undefined,
    /// Processed-once latches (retransmit-safe transcript feeding).
    got_client_cert: bool = false,
    got_client_cv: bool = false,
    client_cert_verified: bool = false,
    client_pubkey: ecdsa_p256.PublicKey = undefined,
    have_client_pubkey: bool = false,
    client_cert_digest: [peer_verify.digest_len]u8 = @splat(0),

    /// Epoch-0 (plaintext) server record sequence; starts at 1 (HRR used 0).
    epoch0_write_seq: u48 = 1,
    /// Next epoch-2 server write sequence number.
    server_epoch2_seq: u64 = 0,
    /// Highest epoch-2 client sequence number accepted (for reconstruction).
    client_epoch2_top: u64 = 0,
    client_epoch2_seen: bool = false,

    /// Cached server flights for retransmit on a duplicated client flight.
    flight: [flight_cap]u8 = undefined,
    flight_len: usize = 0,
    ack: [ack_cap]u8 = undefined,
    ack_len: usize = 0,

    fn reset(self: *Session) void {
        self.server_hs_keys.wipe();
        self.client_hs_keys.wipe();
        std.crypto.secureZero(u8, &self.client_finished_key);
        std.crypto.secureZero(u8, &self.exporter_master);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.srtp_keys));
        self.* = .{};
    }
};

/// Per-address DTLS 1.3 terminator. Shares its self-signed certificate + key
/// with the 1.2 terminator (so both advertise ONE `a=fingerprint`). Owns the
/// cookie secret + the bounded session table. Pump-thread-owned: NOT internally
/// synchronised.
pub const Terminator = struct {
    cert_der: [cert_der_cap]u8 = undefined,
    cert_len: usize = 0,
    cert_key: ecdsa_p256.KeyPair = undefined,
    cookie_secret: [32]u8 = @splat(0),
    csprng: std.Random.DefaultCsprng = undefined,
    sessions: []Session,
    /// RFC 8122 expected peer fingerprints keyed by remote transport address
    /// (see `dtls12_server.Terminator`). Fixed-capacity, no alloc.
    verify_bindings: peer_verify.Bindings(default_max_sessions) = .{},
    /// Client-certificate capture (#64). When true, a session with a bound
    /// expected fingerprint requests + possession-verifies the peer's client
    /// certificate (mutual DTLS). Default OFF ⇒ server-authenticated only, wire
    /// byte-identical. The media plane sets this when DTLS-SRTP is enabled.
    request_client_cert: bool = false,

    /// Initialise from a 32-byte entropy seed plus the SHARED cert DER + key
    /// (typically the 1.2 terminator's, so both engines present one fingerprint).
    /// `sessions` is a caller-owned, caller-freed backing array.
    pub fn init(
        seed: [32]u8,
        sessions: []Session,
        cert_der: []const u8,
        cert_key: ecdsa_p256.KeyPair,
    ) Error!Terminator {
        if (cert_der.len > cert_der_cap) return error.CertTooLarge;
        var self: Terminator = .{ .sessions = sessions };
        @memcpy(self.cert_der[0..cert_der.len], cert_der);
        self.cert_len = cert_der.len;
        self.cert_key = cert_key;
        self.csprng = std.Random.DefaultCsprng.init(seed);
        self.csprng.random().bytes(&self.cookie_secret);
        for (self.sessions) |*s| s.* = .{};
        return self;
    }

    /// Secure-zero all key material on teardown.
    pub fn deinit(self: *Terminator) void {
        std.crypto.secureZero(u8, &self.cookie_secret);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.cert_key));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.csprng));
        for (self.sessions) |*s| s.reset();
    }

    pub fn certDer(self: *const Terminator) []const u8 {
        return self.cert_der[0..self.cert_len];
    }

    pub fn certPublicKey(self: *const Terminator) ecdsa_p256.PublicKey {
        return self.cert_key.public_key;
    }

    pub fn fingerprintLine(self: *const Terminator, out: []u8) fingerprint.Error![]const u8 {
        return fingerprint.format(.sha256, self.certDer(), out);
    }

    /// Whether this engine currently owns a session for `addr` (for version
    /// dispatch: an in-flight/established 1.3 peer routes here regardless of the
    /// packet shape).
    pub fn owns(self: *const Terminator, addr: TransportAddress) bool {
        return self.find(addr) != null;
    }

    pub fn established(self: *const Terminator, addr: TransportAddress) bool {
        const s = self.find(addr) orelse return false;
        return s.state == .established;
    }

    /// Exported SRTP keying material for `addr`, else null. FAILS CLOSED on an
    /// unverified expected fingerprint (RFC 8122), mirroring the 1.2 terminator.
    pub fn exportedKeys(self: *const Terminator, addr: TransportAddress) ?dtls_srtp.ExportedKeys {
        const s = self.find(addr) orelse return null;
        if (s.state != .established) return null;
        if (!self.peerVerifiedSession(addr, s)) return null;
        return s.srtp_keys;
    }

    pub fn srtpProfile(self: *const Terminator, addr: TransportAddress) ?u16 {
        const s = self.find(addr) orelse return null;
        if (s.state != .established) return null;
        if (!self.peerVerifiedSession(addr, s)) return null;
        return s.srtp_profile;
    }

    fn peerVerifiedSession(self: *const Terminator, addr: TransportAddress, s: *const Session) bool {
        if (s.mutual_auth) return s.fp_verified;
        return self.verify_bindings.expectedFor(addr) == null or s.fp_verified;
    }

    /// Bind the RFC 8122 fingerprint the peer signaled for `addr`. Idempotent.
    pub fn bindExpectedFingerprint(self: *Terminator, addr: TransportAddress, digest: [peer_verify.digest_len]u8) void {
        _ = self.verify_bindings.bind(addr, digest);
    }

    /// Record the peer's presented certificate and verify it against the bound
    /// expected fingerprint (seam for client-certificate capture). No-op when no
    /// session exists for `addr`.
    pub fn recordPeerCertificate(self: *Terminator, addr: TransportAddress, cert_der: []const u8) void {
        const s = self.find(addr) orelse return;
        if (self.verify_bindings.expectedFor(addr)) |exp| {
            s.fp_verified = peer_verify.digestEql(exp, peer_verify.certDigest(cert_der));
        } else {
            s.fp_verified = false;
        }
    }

    /// Whether the peer at `addr` is RFC 8122 verified (no expectation ⇒ true).
    pub fn peerVerified(self: *const Terminator, addr: TransportAddress) bool {
        const s = self.find(addr) orelse return false;
        return self.peerVerifiedSession(addr, s);
    }

    // -- session table -----------------------------------------------------

    fn find(self: *const Terminator, addr: TransportAddress) ?*Session {
        for (self.sessions) |*s| {
            if (s.active and s.addr.eql(addr)) return @constCast(s);
        }
        return null;
    }

    /// Find-or-allocate a session slot for `addr`, evicting the stalest on a
    /// full table (bounds half-open handshakes).
    fn acquire(self: *Terminator, addr: TransportAddress, now_ms: i64) *Session {
        if (self.find(addr)) |s| return s;
        var free: ?*Session = null;
        var stalest: *Session = &self.sessions[0];
        for (self.sessions) |*s| {
            if (!s.active) {
                free = s;
                break;
            }
            if (s.last_activity_ms < stalest.last_activity_ms) stalest = s;
        }
        const slot = free orelse stalest;
        // Evicting a live slot for a different peer: drop that peer's stale
        // fingerprint binding so a reused address never inherits it.
        if (slot.active and !slot.addr.eql(addr)) self.verify_bindings.clear(slot.addr);
        slot.reset();
        slot.active = true;
        slot.addr = addr;
        slot.last_activity_ms = now_ms;
        return slot;
    }

    // -- cookie ------------------------------------------------------------

    fn cookieMac(self: *const Terminator, addr: TransportAddress, flags: u8, ch1_hash: [hash_len]u8) [32]u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        var h = HmacSha256.init(&self.cookie_secret);
        h.update(&[_]u8{addr.ip_len}); // length-delimit v4/v6 addresses
        h.update(addr.bytes());
        var port_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &port_be, addr.port, .big);
        h.update(&port_be);
        h.update(&[_]u8{flags});
        h.update(&ch1_hash);
        h.final(&mac);
        return mac;
    }

    // -- main entry --------------------------------------------------------

    /// Process one inbound DTLS datagram from `addr`. Returns a response
    /// datagram written into `out` (borrows `out`), or null. Never traps.
    ///
    /// Plaintext (epoch-0) handshake fragments are reassembled with the shared
    /// `dhs.Reassembler` before dispatch (bounded by `ch_reasm_cap`, fail-closed).
    pub fn handleDatagram(
        self: *Terminator,
        addr: TransportAddress,
        datagram: []const u8,
        now_ms: i64,
        out: []u8,
    ) ?[]const u8 {
        var reasm = dhs.Reassembler{};
        var reasm_buf: [ch_reasm_cap]u8 = undefined;
        var resp_len: usize = 0;
        var off: usize = 0;
        while (off < datagram.len) {
            const b0 = datagram[off];
            if ((b0 & 0b1110_0000) == 0b0010_0000) {
                // Unified-header (epoch ≥ 1) DTLSCiphertext record. A length-less
                // record (RFC 9147 §4) is the LAST record and runs to end-of-
                // datagram; a length-bearing record is bounded by its length.
                const dech = record13.Header.decode(datagram[off..]) catch break;
                const rec_bytes = if (dech.hdr.length_present) blk: {
                    const rec_total = dech.consumed + @as(usize, dech.hdr.record_len);
                    if (off + rec_total > datagram.len) break;
                    const rb = datagram[off .. off + rec_total];
                    off += rec_total;
                    break :blk rb;
                } else blk: {
                    const rb = datagram[off..];
                    off = datagram.len;
                    break :blk rb;
                };
                if (self.handleEncryptedRecord(addr, rec_bytes, now_ms, out)) |n| {
                    resp_len = n;
                    break;
                }
                continue;
            }

            const dec = p_record.RecordHeader.decode(datagram[off..]) catch break;
            off += dec.consumed;
            switch (dec.hdr.content_type) {
                .handshake => {
                    const hh = dhs.Header.decode(dec.fragment) catch break;
                    const flen: usize = hh.hdr.fragment_length;
                    if (dec.fragment.len < dhs.handshake_header_len + flen) break;
                    const frag = dec.fragment[dhs.handshake_header_len..][0..flen];
                    const complete = reasm.offer(hh.hdr, frag, &reasm_buf) catch break;
                    if (complete) |body| {
                        if (reasm.msg_type == .client_hello) {
                            if (self.onClientHello(addr, reasm.message_seq, body, now_ms, out)) |n| {
                                resp_len = n;
                                break;
                            }
                        }
                        // A fresh reassembler for any subsequent message in the datagram.
                        reasm = dhs.Reassembler{};
                    }
                },
                else => {}, // ccs / alert / plaintext-ack: ignore
            }
        }
        if (resp_len == 0) return null;
        return out[0..resp_len];
    }

    // -- ClientHello -------------------------------------------------------

    fn onClientHello(
        self: *Terminator,
        addr: TransportAddress,
        message_seq: u16,
        body: []const u8,
        now_ms: i64,
        out: []u8,
    ) ?usize {
        const ch = msg13.parseClientHello13(body) catch return null;
        if (!ch.offers_dtls13 or !ch.offers_target_cipher) return null;
        if (selectSrtpProfile(ch.use_srtp_body) == null) return null; // must offer our profile

        if (ch.cookie.len == 0) {
            // Flight 1: stateless HelloRetryRequest carrying the cookie. If CH1
            // didn't lead with a secp256r1 key_share, the HRR ALSO selects the
            // secp256r1 group (RFC 8446 §4.1.4) — provided the client at least
            // advertised it in supported_groups (else we cannot serve it).
            const need_group_selection = ch.key_share_point == null;
            if (need_group_selection and !ch.offers_secp256r1_group) return null;
            return self.emitHelloRetryRequest(addr, message_seq, body, ch.legacy_session_id, need_group_selection, out);
        }

        // CH2 with a cookie: verify it (return-routability + transcript binding).
        if (ch.has_early_data) return null; // early_data forbidden after HRR
        if (ch.cookie.len != cookie_len) return null;
        const flags: u8 = ch.cookie[0];
        const ch1_hash: [hash_len]u8 = ch.cookie[1 .. 1 + hash_len].*;
        const expected = self.cookieMac(addr, flags, ch1_hash);
        if (!std.crypto.timing_safe.eql([32]u8, expected, ch.cookie[1 + hash_len .. cookie_len].*)) return null;
        // After an HRR the client MUST present a secp256r1 key_share.
        const key_point = ch.key_share_point orelse return null;

        // Retransmitted CH2 for an in-flight session: resend the cached flight.
        if (self.find(addr)) |existing| {
            if (existing.flight_len != 0 and std.mem.eql(u8, &existing.client_random, &ch.random)) {
                existing.last_activity_ms = now_ms;
                if (out.len < existing.flight_len) return null;
                @memcpy(out[0..existing.flight_len], existing.flight[0..existing.flight_len]);
                return existing.flight_len;
            }
        }

        return self.emitServerFlight(addr, message_seq, body, ch, key_point, ch1_hash, flags, now_ms, out);
    }

    fn emitHelloRetryRequest(
        self: *Terminator,
        addr: TransportAddress,
        message_seq: u16,
        ch_body: []const u8,
        legacy_session_id: []const u8,
        need_group_selection: bool,
        out: []u8,
    ) ?usize {
        // Hash(ClientHello1) over the DTLS-form single-fragment message.
        var ts = Sha256.init(.{});
        feedTranscript13(&ts, .client_hello, message_seq, ch_body);
        const ch1_hash = ts.peek();

        const flags: u8 = if (need_group_selection) cookie_flag_group_selection else 0;
        var cookie: [cookie_len]u8 = undefined;
        cookie[0] = flags;
        @memcpy(cookie[1 .. 1 + hash_len], &ch1_hash);
        const mac = self.cookieMac(addr, flags, ch1_hash);
        @memcpy(cookie[1 + hash_len .. cookie_len], &mac);

        var hrr_buf: [256]u8 = undefined;
        const hrr = msg13.buildHelloRetryRequest(&hrr_buf, legacy_session_id, &cookie, need_group_selection) catch return null;
        // HRR is message_seq 0, epoch 0, record seq 0 (stateless).
        return framePlaintext13(out, .server_hello, 0, 0, hrr) catch return null;
    }

    fn emitServerFlight(
        self: *Terminator,
        addr: TransportAddress,
        ch2_message_seq: u16,
        ch2_body: []const u8,
        ch: msg13.ClientHello13View,
        client_point: [msg13.p256_point_len]u8,
        ch1_hash: [hash_len]u8,
        cookie_flags: u8,
        now_ms: i64,
        out: []u8,
    ) ?usize {
        // Ephemeral server ECDHE + the ECDHE shared secret. The private scalar is
        // wiped off the stack after deriving the shared secret.
        const rng = self.csprng.random();
        var ecdhe_seed: [32]u8 = undefined;
        rng.bytes(&ecdhe_seed);
        defer std.crypto.secureZero(u8, &ecdhe_seed);
        var ecdhe = kx.generateKeyPair(ecdhe_seed);
        defer std.crypto.secureZero(u8, &ecdhe.secret);
        var shared = kx.computeSharedSecret(ecdhe.secret, client_point) catch return null;
        defer std.crypto.secureZero(u8, &shared);

        var server_random: [32]u8 = undefined;
        rng.bytes(&server_random);

        // --- transcript: synthetic message_hash(CH1), HRR, CH2 ---
        // The HRR is reconstructed exactly (its group-selection form is recorded
        // in the cookie flags), so the transcript matches what the client hashed.
        const include_group_selection = (cookie_flags & cookie_flag_group_selection) != 0;
        var ts = Sha256.init(.{});
        feedSynthetic(&ts, ch1_hash);
        {
            var hrr_buf: [256]u8 = undefined;
            const hrr = msg13.buildHelloRetryRequest(&hrr_buf, ch.legacy_session_id, ch.cookie, include_group_selection) catch return null;
            feedTranscript13(&ts, .server_hello, 0, hrr);
        }
        feedTranscript13(&ts, .client_hello, ch2_message_seq, ch2_body);

        // --- key schedule: early + handshake secrets ---
        var early = KS.earlySecret("");
        defer early.wipe();
        var handshake = KS.handshakeSecret(&early, &shared) catch return null;
        defer handshake.wipe();

        var total: usize = 0;
        var epoch0_seq: u48 = 1; // HRR consumed record seq 0

        // --- ServerHello (epoch 0, message_seq 1) ---
        {
            var sh_buf: [256]u8 = undefined;
            const sh = msg13.buildServerHello13(&sh_buf, server_random, ch.legacy_session_id, ecdhe.public) catch return null;
            feedTranscript13(&ts, .server_hello, 1, sh);
            total += framePlaintext13(out[total..], .server_hello, 1, epoch0_seq, sh) catch return null;
            epoch0_seq += 1;
        }

        // Handshake traffic secrets are derived at the post-ServerHello transcript.
        const transcript_sh = ts.peek();
        var c_hs = KS.deriveSecret(&handshake, "c hs traffic", &transcript_sh) catch return null;
        defer c_hs.wipe();
        var s_hs = KS.deriveSecret(&handshake, "s hs traffic", &transcript_sh) catch return null;
        defer s_hs.wipe();
        // Derived into locals, copied into the session below, then wiped off the
        // stack (the session holds the live copies, zeroed in `reset`).
        var server_keys = record13.deriveAes128GcmKeys(s_hs.declassify());
        defer server_keys.wipe();
        var client_keys = record13.deriveAes128GcmKeys(c_hs.declassify());
        defer client_keys.wipe();

        var epoch2_seq: u64 = 0;

        // Mutual auth (#64): request + possession-verify the peer's client cert
        // when configured AND a fingerprint is bound. Off ⇒ no CertificateRequest
        // is ever sent and the flight is byte-identical to the server-auth path.
        const mutual = self.request_client_cert and self.verify_bindings.expectedFor(addr) != null;

        // --- EncryptedExtensions (epoch 2, message_seq 2) ---
        {
            var ee_buf: [64]u8 = undefined;
            const ee = msg13.buildEncryptedExtensions(&ee_buf, profileOf(ch)) catch return null;
            feedTranscript13(&ts, .encrypted_extensions, 2, ee);
            total += frameEncHandshake(out[total..], server_keys, epoch2_seq, .encrypted_extensions, 2, ee) catch return null;
            epoch2_seq += 1;
        }
        // Handshake-message sequence for the server-auth (or mutual) sub-flight.
        // When mutual, CertificateRequest is message_seq 3 and everything after
        // shifts up by one.
        var hs_seq: u16 = 3;
        // --- CertificateRequest (epoch 2, message_seq 3) — mutual auth only ---
        if (mutual) {
            var cr_buf: [64]u8 = undefined;
            const cr = msg13.buildCertificateRequest13(&cr_buf) catch return null;
            feedTranscript13(&ts, .certificate_request, hs_seq, cr);
            total += frameEncHandshake(out[total..], server_keys, epoch2_seq, .certificate_request, hs_seq, cr) catch return null;
            epoch2_seq += 1;
            hs_seq += 1;
        }
        // --- Certificate (epoch 2) ---
        {
            var cert_buf: [cert_der_cap + 16]u8 = undefined;
            const cert = msg13.buildCertificate13(&cert_buf, self.certDer()) catch return null;
            feedTranscript13(&ts, .certificate, hs_seq, cert);
            total += frameEncHandshake(out[total..], server_keys, epoch2_seq, .certificate, hs_seq, cert) catch return null;
            epoch2_seq += 1;
            hs_seq += 1;
        }
        // --- CertificateVerify (epoch 2) ---
        {
            const transcript_cert = ts.peek();
            var content_buf: [160]u8 = undefined;
            const content = msg13.certificateVerifyContent(&content_buf, &transcript_cert) catch return null;
            const sig = ecdsa_p256.sign(content, self.cert_key) catch return null;
            var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
            const sig_der = ecdsa_p256.signatureToDer(sig, &sig_der_buf) catch return null;
            var cv_buf: [160]u8 = undefined;
            const cv = msg13.buildCertificateVerify(&cv_buf, sig_der) catch return null;
            feedTranscript13(&ts, .certificate_verify, hs_seq, cv);
            total += frameEncHandshake(out[total..], server_keys, epoch2_seq, .certificate_verify, hs_seq, cv) catch return null;
            epoch2_seq += 1;
            hs_seq += 1;
        }
        // --- Finished (epoch 2) ---
        {
            const transcript_cv = ts.peek();
            var s_fin_key = KS.finishedKey(&s_hs) catch return null;
            defer s_fin_key.wipe();
            const verify_data = KS.finishedVerifyData(&s_fin_key, &transcript_cv) catch return null;
            feedTranscript13(&ts, .finished, hs_seq, &verify_data);
            total += frameEncHandshake(out[total..], server_keys, epoch2_seq, .finished, hs_seq, &verify_data) catch return null;
            epoch2_seq += 1;
        }

        // --- post-flight secrets: exporter + client Finished key ---
        const transcript_sf = ts.peek();
        var master = KS.masterSecret(&handshake) catch return null;
        defer master.wipe();
        var exporter = KS.exporterMasterSecret(&master, &transcript_sf) catch return null;
        defer exporter.wipe();
        var c_fin_key = KS.finishedKey(&c_hs) catch return null;
        defer c_fin_key.wipe();

        // --- commit to a session slot (fail-fast BEFORE this point) ---
        const s = self.acquire(addr, now_ms);
        s.reset();
        s.active = true;
        s.addr = addr;
        s.last_activity_ms = now_ms;
        s.state = .expect_client_finish;
        s.client_random = ch.random;
        s.srtp_profile = profileOf(ch);
        s.epoch0_write_seq = epoch0_seq;
        s.server_epoch2_seq = epoch2_seq;
        s.client_epoch2_top = 0;
        s.client_epoch2_seen = false;
        s.server_hs_keys = server_keys;
        s.client_hs_keys = client_keys;
        s.client_finished_key = c_fin_key.declassify();
        s.transcript_through_server_finished = transcript_sf;
        s.exporter_master = exporter.declassify();
        s.have_secrets = true;
        s.mutual_auth = mutual;
        // Keep the running transcript state (through the server Finished); when
        // mutual, the client Certificate + CertificateVerify extend it so the
        // client Finished is checked against the post-client-auth transcript.
        s.transcript = ts;

        if (total <= s.flight.len) {
            @memcpy(s.flight[0..total], out[0..total]);
            s.flight_len = total;
        }
        return total;
    }

    // -- encrypted (epoch-2) records ---------------------------------------

    fn handleEncryptedRecord(
        self: *Terminator,
        addr: TransportAddress,
        rec_bytes: []const u8,
        now_ms: i64,
        out: []u8,
    ) ?usize {
        const s = self.find(addr) orelse return null;
        if (!s.have_secrets) return null;

        var plain_buf: [ch_reasm_cap]u8 = undefined;
        const opened = openEncRecord(s.client_hs_keys, rec_bytes, s.client_epoch2_top, &plain_buf) catch return null;
        s.last_activity_ms = now_ms;
        if (opened.seq > s.client_epoch2_top or !s.client_epoch2_seen) {
            s.client_epoch2_top = opened.seq;
            s.client_epoch2_seen = true;
        }

        switch (opened.inner_type) {
            inner_handshake => return self.onClientHandshakeEnc(s, opened.content, opened.seq, out),
            inner_ack => return null, // the client acknowledged our flight — nothing to send
            else => return null,
        }
    }

    fn onClientHandshakeEnc(
        self: *Terminator,
        s: *Session,
        content: []const u8,
        record_seq: u64,
        out: []u8,
    ) ?usize {
        const hh = dhs.Header.decode(content) catch return null;
        if (hh.hdr.fragment_offset != 0 or hh.hdr.fragment_length != hh.hdr.length) return null;
        const blen: usize = hh.hdr.length;
        if (content.len < dhs.handshake_header_len + blen) return null;
        const body = content[dhs.handshake_header_len..][0..blen];

        switch (hh.hdr.msg_type) {
            // Mutual auth (#64): the client's Certificate + CertificateVerify
            // precede its Finished. Each is its own epoch-2 record; neither
            // produces a response. Ignored (dropped) when mutual auth is off.
            .certificate => {
                if (s.mutual_auth and s.state != .established) self.onClientCertificate13(s, hh.hdr.message_seq, body);
                return null;
            },
            .certificate_verify => {
                if (s.mutual_auth and s.state != .established) self.onClientCertificateVerify13(s, hh.hdr.message_seq, body);
                return null;
            },
            .finished => {},
            else => return null,
        }
        const fin_body = body;

        // Established retransmit: resend the cached ACK.
        if (s.state == .established) {
            if (s.ack_len != 0 and out.len >= s.ack_len) {
                @memcpy(out[0..s.ack_len], s.ack[0..s.ack_len]);
                return s.ack_len;
            }
            return null;
        }
        if (fin_body.len != hash_len) return null;
        // Mutual auth: the client cert MUST have been presented + possession-
        // verified before the Finished is accepted, else fail closed.
        if (s.mutual_auth and !s.client_cert_verified) return null;

        // Verify the client Finished. When mutual, the transcript runs through the
        // client CertificateVerify (fed by the handlers above); otherwise it is
        // the transcript through the server Finished.
        const finished_transcript: [hash_len]u8 = if (s.mutual_auth) s.transcript.peek() else s.transcript_through_server_finished;
        var c_fin_key = KS.SecretBytes.init(s.client_finished_key);
        defer c_fin_key.wipe();
        const expected = KS.finishedVerifyData(&c_fin_key, &finished_transcript) catch return null;
        if (!std.crypto.timing_safe.eql([hash_len]u8, expected, fin_body[0..hash_len].*)) return null;

        // Handshake complete: derive + store the SRTP keying material.
        s.srtp_keys = dtls_srtp.exportSrtpKeysTls13(s.exporter_master) catch return null;
        s.state = .established;

        // Acknowledge the client's Finished record (RFC 9147 §7).
        const rns = [_]msg13.RecordNumber{.{ .epoch = epoch_handshake, .sequence_number = record_seq }};
        var ack_body_buf: [32]u8 = undefined;
        const ack_body = msg13.encodeAck(&rns, &ack_body_buf) catch return null;
        const n = frameEncAck(out, s.server_hs_keys, s.server_epoch2_seq, ack_body) catch return null;
        s.server_epoch2_seq += 1;
        if (n <= s.ack.len) {
            @memcpy(s.ack[0..n], out[0..n]);
            s.ack_len = n;
        }
        return n;
    }

    /// Handle the client Certificate (mutual auth). Captures the leaf cert's
    /// public key + fingerprint for the CertificateVerify possession check, and
    /// extends the transcript FIRST (so an unparseable/empty cert stays
    /// transcript-consistent and simply fails closed at CertificateVerify).
    fn onClientCertificate13(self: *Terminator, s: *Session, message_seq: u16, body: []const u8) void {
        _ = self;
        if (s.got_client_cert) return; // processed-once (retransmit-safe)
        s.got_client_cert = true;
        feedTranscript13(&s.transcript, .certificate, message_seq, body);
        const leaf = msg13.parseCertificate13(body) catch return;
        if (leaf.len == 0) return;
        s.client_cert_digest = peer_verify.certDigest(leaf);
        const parsed = x509.parse(leaf) catch return;
        const spk = x509.extractPublicKey(parsed.spki_der) catch return;
        const point = switch (spk) {
            .ecdsa_p256 => |pt| pt,
            else => return, // wrong key family ⇒ fail closed
        };
        s.client_pubkey = ecdsa_p256.parsePublicKeySec1(point) catch return;
        s.have_client_pubkey = true;
    }

    /// Handle the client CertificateVerify (mutual auth). Verifies possession —
    /// the ECDSA signature over the RFC 8446 §4.4.3 client-context content bound
    /// to the transcript THROUGH the client Certificate — then binds RFC 8122
    /// identity. Extends the transcript with the CertificateVerify afterward so
    /// the client Finished covers it. Fail-closed on any deviation.
    fn onClientCertificateVerify13(self: *Terminator, s: *Session, message_seq: u16, body: []const u8) void {
        if (s.got_client_cv) return; // processed-once (retransmit-safe)
        s.got_client_cv = true;
        // The transcript at this point runs through the client Certificate.
        const transcript_hash = s.transcript.peek();
        self.verifyClientPossession13(s, transcript_hash, body);
        feedTranscript13(&s.transcript, .certificate_verify, message_seq, body);
    }

    /// Possession verify + RFC 8122 fingerprint bind for a presented DTLS 1.3
    /// client cert. Sets `client_cert_verified`/`fp_verified` only on full
    /// success; silent on any failure (the session then stays fail-closed).
    fn verifyClientPossession13(self: *Terminator, s: *Session, transcript_hash: [hash_len]u8, cv_body: []const u8) void {
        if (!s.have_client_pubkey) return;
        const view = msg13.parseCertificateVerify(cv_body) catch return;
        if (view.scheme != msg13.sig_scheme_ecdsa_secp256r1_sha256) return;
        var content_buf: [200]u8 = undefined;
        const content = msg13.certificateVerifyContentCtx(&content_buf, msg13.cert_verify_context_client, &transcript_hash) catch return;
        const sig = ecdsa_p256.signatureFromDer(view.sig_der) catch return;
        if (!ecdsa_p256.verify(sig, content, s.client_pubkey)) return;
        // Possession proven. Now bind RFC 8122 identity: the presented cert's
        // fingerprint must match the one the peer signaled (if any expectation).
        s.client_cert_verified = true;
        if (self.verify_bindings.expectedFor(s.addr)) |exp| {
            s.fp_verified = peer_verify.digestEql(exp, s.client_cert_digest);
        } else {
            s.fp_verified = false;
        }
    }
};

// Small view helper: the negotiated SRTP profile from a validated ClientHello.
fn profileOf(ch: msg13.ClientHello13View) u16 {
    return selectSrtpProfile(ch.use_srtp_body) orelse 0;
}

/// Choose the best SRTP profile we support (AES-128-CM-HMAC-SHA1-80).
pub fn selectSrtpProfile(use_srtp_body: []const u8) ?u16 {
    if (use_srtp_body.len == 0) return null;
    if (dtls_srtp.offersProfile(use_srtp_body, dtls_srtp.profile_aes128_cm_sha1_80))
        return dtls_srtp.profile_aes128_cm_sha1_80;
    return null;
}

/// Whether a datagram is a plaintext ClientHello offering DTLS 1.3 that THIS
/// engine can actually serve — the media plane's version-dispatch predicate.
/// Requires DTLS 1.3 *and* secp256r1 support (a P-256-less 1.3 client must fall
/// through to the 1.2 path rather than be black-holed here, since secp256r1 is
/// our only key-exchange group). Fail-closed (false on any parse issue).
pub fn offersDtls13(datagram: []const u8) bool {
    if (datagram.len == 0) return false;
    if ((datagram[0] & 0b1110_0000) == 0b0010_0000) return false; // encrypted record
    const dec = p_record.RecordHeader.decode(datagram) catch return false;
    if (dec.hdr.content_type != .handshake) return false;
    const hh = dhs.Header.decode(dec.fragment) catch return false;
    if (hh.hdr.msg_type != .client_hello) return false;
    const blen: usize = hh.hdr.length;
    if (hh.hdr.fragment_offset != 0 or hh.hdr.fragment_length != hh.hdr.length) return false;
    if (dec.fragment.len < dhs.handshake_header_len + blen) return false;
    const body = dec.fragment[dhs.handshake_header_len..][0..blen];
    const ch = msg13.parseClientHello13(body) catch return false;
    if (!ch.offers_dtls13) return false;
    return ch.key_share_point != null or ch.offers_secp256r1_group;
}

// ---------------------------------------------------------------------------
// Transcript + framing helpers (shared by the server and the test client)
// ---------------------------------------------------------------------------

/// Feed one handshake message into a transcript hash using its DTLS-form
/// single-fragment 12-byte header (fragment_offset=0, fragment_length=length),
/// preserving message_seq (RFC 9147 §5.2).
pub fn feedTranscript13(t: *Sha256, msg_type: dhs.HandshakeType, message_seq: u16, body: []const u8) void {
    var hdr_buf: [dhs.handshake_header_len]u8 = undefined;
    const hdr = dhs.Header{
        .msg_type = msg_type,
        .length = @intCast(body.len),
        .message_seq = message_seq,
        .fragment_offset = 0,
        .fragment_length = @intCast(body.len),
    };
    const enc = hdr.encode(&hdr_buf) catch return; // 12-byte buf always fits
    t.update(enc);
    t.update(body);
}

/// Feed the RFC 8446 §4.4.1 synthetic `message_hash` (type 254) replacing the
/// first ClientHello, using the DTLS-form header (message_seq 0). Both endpoints
/// use this identical convention.
pub fn feedSynthetic(t: *Sha256, ch1_hash: [hash_len]u8) void {
    var hdr_buf: [dhs.handshake_header_len]u8 = undefined;
    const hdr = dhs.Header{
        .msg_type = @enumFromInt(254), // message_hash
        .length = hash_len,
        .message_seq = 0,
        .fragment_offset = 0,
        .fragment_length = hash_len,
    };
    const enc = hdr.encode(&hdr_buf) catch return;
    t.update(enc);
    t.update(&ch1_hash);
}

/// Frame a plaintext (epoch-0) handshake message: DTLSPlaintext record header +
/// 12-byte handshake header + body. Returns bytes written to `out`.
pub fn framePlaintext13(
    out: []u8,
    msg_type: dhs.HandshakeType,
    message_seq: u16,
    rec_seq: u48,
    body: []const u8,
) p_record.EncodeError!usize {
    const frag_len = dhs.handshake_header_len + body.len;
    const total = p_record.record_header_len + frag_len;
    if (out.len < total) return error.BufferTooSmall;
    if (frag_len > std.math.maxInt(u16)) return error.BufferTooSmall;

    const rh = p_record.RecordHeader{ .content_type = .handshake, .epoch = 0, .seq = rec_seq, .length = @intCast(frag_len) };
    _ = try rh.encode(out[0..p_record.record_header_len]);
    const hh = dhs.Header{
        .msg_type = msg_type,
        .length = @intCast(body.len),
        .message_seq = message_seq,
        .fragment_offset = 0,
        .fragment_length = @intCast(body.len),
    };
    _ = hh.encode(out[p_record.record_header_len..][0..dhs.handshake_header_len]) catch return error.BufferTooSmall;
    @memcpy(out[p_record.record_header_len + dhs.handshake_header_len ..][0..body.len], body);
    return total;
}

/// Frame an epoch-2 (encrypted) handshake message: the DTLSInnerPlaintext is the
/// 12-byte handshake header + body + inner content-type (22), sealed with
/// AES-128-GCM and framed under a record-number-encrypted unified header.
pub fn frameEncHandshake(
    out: []u8,
    keys: record13.Aes128GcmKeys,
    rec_seq: u64,
    msg_type: dhs.HandshakeType,
    message_seq: u16,
    body: []const u8,
) record13.EncodeError!usize {
    var scratch: [enc_scratch_cap]u8 = undefined;
    const hs_len = dhs.handshake_header_len + body.len;
    if (hs_len + 1 > scratch.len) return error.BufferTooSmall;
    const hh = dhs.Header{
        .msg_type = msg_type,
        .length = @intCast(body.len),
        .message_seq = message_seq,
        .fragment_offset = 0,
        .fragment_length = @intCast(body.len),
    };
    _ = hh.encode(scratch[0..dhs.handshake_header_len]) catch return error.BufferTooSmall;
    @memcpy(scratch[dhs.handshake_header_len..][0..body.len], body);
    scratch[hs_len] = inner_handshake;
    return sealAndFrame(out, keys, epoch_handshake, rec_seq, scratch[0 .. hs_len + 1]);
}

/// Frame an epoch-2 (encrypted) ACK record.
pub fn frameEncAck(out: []u8, keys: record13.Aes128GcmKeys, rec_seq: u64, ack_body: []const u8) record13.EncodeError!usize {
    var scratch: [ack_cap + 1]u8 = undefined;
    if (ack_body.len + 1 > scratch.len) return error.BufferTooSmall;
    @memcpy(scratch[0..ack_body.len], ack_body);
    scratch[ack_body.len] = inner_ack;
    return sealAndFrame(out, keys, epoch_handshake, rec_seq, scratch[0 .. ack_body.len + 1]);
}

fn sealAndFrame(
    out: []u8,
    keys: record13.Aes128GcmKeys,
    epoch: u16,
    rec_seq: u64,
    plain: []const u8,
) record13.EncodeError!usize {
    const sealed_len = plain.len + record13.tag_len;
    if (sealed_len > std.math.maxInt(u16)) return error.BufferTooSmall;
    if (sealed_len < 16) return error.BufferTooSmall; // need a 16-byte RNE sample
    const hdr = record13.Header{
        .epoch_low = @truncate(epoch),
        .seq = rec_seq,
        .seq_len = .long,
        .length_present = true,
        .record_len = @intCast(sealed_len),
    };
    const hdr_len = hdr.wireLen(); // 5 (B0 + 2 seq + 2 len)
    const total = hdr_len + sealed_len;
    if (out.len < total) return error.BufferTooSmall;

    _ = try hdr.encode(out[0..hdr_len]);
    // AAD = the unified header with the sequence number in the clear.
    _ = try record13.sealRecordAes128Gcm(keys.key, keys.iv, rec_seq, out[0..hdr_len], plain, out[hdr_len..][0..sealed_len]);
    // RFC 9147 §4.2.3 record-number encryption over the 2 sequence-number bytes.
    const sample: [16]u8 = out[hdr_len..][0..16].*;
    const mask = record13.recordNumberMaskAes128(keys.sn_key, sample);
    record13.applyRecordNumberMask(out[1..3], mask[0..2]);
    return total;
}

pub const OpenedRecord = struct {
    content: []const u8,
    inner_type: u8,
    seq: u64,
};

/// Open an epoch-2 unified-header record: remove the record-number mask, recover
/// the cleartext sequence number, AEAD-open, and strip padding to the inner
/// content type. `read_top` anchors sequence-number reconstruction.
pub fn openEncRecord(
    keys: record13.Aes128GcmKeys,
    rec_bytes: []const u8,
    read_top: u64,
    plaintext: []u8,
) record13.DecodeError!OpenedRecord {
    const dec = try record13.Header.decode(rec_bytes);
    const hdr_len = dec.consumed;
    // A length-bearing record is bounded by its length; a length-less record
    // (RFC 9147 §4, last-in-datagram) runs to the end of `rec_bytes`.
    const sealed = if (dec.hdr.length_present) blk: {
        const rlen: usize = dec.hdr.record_len;
        if (rec_bytes.len < hdr_len + rlen) return error.BufferTooShort;
        break :blk rec_bytes[hdr_len .. hdr_len + rlen];
    } else rec_bytes[hdr_len..];
    if (sealed.len < 16) return error.PlaintextTooShort; // no RNE sample

    const sample: [16]u8 = sealed[0..16].*;
    const mask = record13.recordNumberMaskAes128(keys.sn_key, sample);

    // Recover the cleartext header (unmask the sequence-number bytes).
    var hbuf: [record13.max_header_len]u8 = undefined;
    @memcpy(hbuf[0..hdr_len], rec_bytes[0..hdr_len]);
    const seq_bytes: usize = if (dec.hdr.seq_len == .long) 2 else 1;
    record13.applyRecordNumberMask(hbuf[1 .. 1 + seq_bytes], mask[0..seq_bytes]);
    const rehdr = try record13.Header.decode(hbuf[0..hdr_len]);
    const bits: u6 = if (dec.hdr.seq_len == .long) 16 else 8;
    const full_seq = record13.reconstructSeq(rehdr.hdr.seq, bits, read_top);

    const opened = try record13.openRecordAes128Gcm(keys.key, keys.iv, full_seq, hbuf[0..hdr_len], sealed, plaintext);

    // Strip zero padding; the last non-zero byte is the inner content type.
    var end = opened.len;
    while (end > 0 and opened[end - 1] == 0) end -= 1;
    if (end == 0) return error.PlaintextTooShort;
    return .{ .content = opened[0 .. end - 1], .inner_type = opened[end - 1], .seq = full_seq };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const x509_selfsign = @import("x509_selfsign.zig");

fn testAddr(last_octet: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last_octet }, port) catch unreachable;
}

const TestTerminator = struct {
    term: Terminator,
    sessions: []Session,

    fn deinit(self: *TestTerminator) void {
        self.term.deinit();
        testing.allocator.free(self.sessions);
    }
};

fn makeTerminator(seed_byte: u8) !TestTerminator {
    const key_seed: [ecdsa_p256.KeyPair.seed_length]u8 = @splat(seed_byte);
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(key_seed);
    var cert_buf: [cert_der_cap]u8 = undefined;
    const serial = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "onyx-dtls",
        .not_before = 1_700_000_000,
        .not_after = 1_900_000_000,
        .serial = &serial,
        .key_pair = kp,
    });
    const sessions = try testing.allocator.alloc(Session, 8);
    errdefer testing.allocator.free(sessions);
    const term = try Terminator.init(@splat(seed_byte ^ 0x5a), sessions, der, kp);
    return .{ .term = term, .sessions = sessions };
}

test "shares one cert/fingerprint and derives a well-formed SHA-256 fingerprint" {
    var setup = try makeTerminator(0x11);
    defer setup.deinit();
    var buf: [128]u8 = undefined;
    const fp = try setup.term.fingerprintLine(&buf);
    try testing.expect(std.mem.startsWith(u8, fp, "sha-256 "));
    try testing.expectEqual(@as(usize, "sha-256 ".len + 95), fp.len);
}

test "bare ClientHello elicits a stateless HelloRetryRequest with a cookie" {
    var setup = try makeTerminator(0x22);
    defer setup.deinit();
    const addr = testAddr(2, 5000);

    var ch1_body: [512]u8 = undefined;
    const chb = try msg13.buildClientHello13(&ch1_body, .{
        .random = @splat(7),
        .key_share_point = kx.generateKeyPair(@splat(0x5c)).public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var dgram: [700]u8 = undefined;
    const dlen = try framePlaintext13(&dgram, .client_hello, 0, 0, chb);

    var out: [2048]u8 = undefined;
    const resp = setup.term.handleDatagram(addr, dgram[0..dlen], 1000, &out) orelse return error.TestUnexpectedResult;

    const rdec = try p_record.RecordHeader.decode(resp);
    try testing.expectEqual(p_record.ContentType.handshake, rdec.hdr.content_type);
    const hh = try dhs.Header.decode(rdec.fragment);
    const shv = try msg13.parseServerHello13(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]);
    try testing.expect(shv.isHelloRetryRequest());
    try testing.expectEqual(@as(usize, cookie_len), shv.cookie.len);
    // Stateless: no session was allocated.
    try testing.expect(!setup.term.owns(addr));
}

test "ClientHello with a forged cookie is dropped and never allocates a session" {
    var setup = try makeTerminator(0x23);
    defer setup.deinit();
    const addr = testAddr(3, 5001);
    const bad_cookie: [cookie_len]u8 = @splat(0xAA);
    var ch_body: [512]u8 = undefined;
    const chb = try msg13.buildClientHello13(&ch_body, .{
        .random = @splat(9),
        .key_share_point = kx.generateKeyPair(@splat(0x22)).public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .cookie = &bad_cookie,
    });
    var dgram: [700]u8 = undefined;
    const n = try framePlaintext13(&dgram, .client_hello, 1, 1, chb);
    var out: [2048]u8 = undefined;
    try testing.expect(setup.term.handleDatagram(addr, dgram[0..n], 1001, &out) == null);
    try testing.expect(!setup.term.owns(addr));
}

test "frameEncHandshake/openEncRecord round-trip (record-number encryption)" {
    var keys = record13.deriveAes128GcmKeys(@splat(0x33));
    defer keys.wipe();
    const body = "verify_data-and-friends-0123456789";
    var rec: [256]u8 = undefined;
    const n = try frameEncHandshake(&rec, keys, 0, .finished, 5, body);
    // The on-wire header's sequence-number bytes are encrypted (not raw 0x0000).
    try testing.expect(!(rec[1] == 0 and rec[2] == 0));

    var plain: [256]u8 = undefined;
    const opened = try openEncRecord(keys, rec[0..n], 0, &plain);
    try testing.expectEqual(inner_handshake, opened.inner_type);
    try testing.expectEqual(@as(u64, 0), opened.seq);
    const hh = try dhs.Header.decode(opened.content);
    try testing.expectEqual(dhs.HandshakeType.finished, hh.hdr.msg_type);
    try testing.expectEqualStrings(body, opened.content[dhs.handshake_header_len..][0..hh.hdr.length]);
}

test "malformed DTLS 1.3 datagrams are dropped without a trap or spurious session" {
    var setup = try makeTerminator(0x44);
    defer setup.deinit();
    const addr = testAddr(9, 6000);
    var out: [2048]u8 = undefined;

    var prng = std.Random.DefaultPrng.init(0xD7135_1234);
    const rng = prng.random();
    for (0..3000) |_| {
        var junk: [300]u8 = undefined;
        const nlen = 1 + rng.uintLessThan(usize, junk.len);
        rng.bytes(junk[0..nlen]);
        // Force the first byte across the RFC 7983 DTLS range (20..63).
        junk[0] = 20 + rng.uintLessThan(u8, 44);
        _ = setup.term.handleDatagram(addr, junk[0..nlen], 1, &out);
    }
    // Well-formed record + handshake header wrapping hostile bodies.
    for (0..3000) |_| {
        var body: [200]u8 = undefined;
        const blen = rng.uintLessThan(usize, body.len);
        rng.bytes(body[0..blen]);
        var dgram: [300]u8 = undefined;
        const framed = framePlaintext13(&dgram, .client_hello, rng.int(u16), rng.int(u48), body[0..blen]) catch continue;
        _ = setup.term.handleDatagram(addr, dgram[0..framed], 1, &out);
    }
    try testing.expect(!setup.term.owns(addr));
}

// -- Full loopback DTLS 1.3 handshake: a client built from the same lib
//    completes the handshake and both sides derive identical SRTP keys. -----

const Client13 = struct {
    ecdhe: kx.KeyPair,
    client_random: [32]u8,
    ch1_body: [512]u8 = undefined,
    ch1_len: usize = 0,
    ts: Sha256 = undefined,
    server_random: [32]u8 = @splat(0),
    server_point: [msg13.p256_point_len]u8 = @splat(0),

    fn init() Client13 {
        var cr: [32]u8 = undefined;
        for (&cr, 0..) |*b, i| b.* = @intCast((i *% 7) +% 1);
        return .{ .ecdhe = kx.generateKeyPair(@splat(0xC1)), .client_random = cr };
    }
};

/// Client-authentication material for the mutual-auth loopback (a self-signed
/// ECDSA-P256 cert + its key, mirroring a WebRTC browser peer).
const ClientAuth13 = struct {
    key_pair: ecdsa_p256.KeyPair,
    cert_der: []const u8,
};

/// Client-side flight behaviour, for exercising the mutual-auth fail-closed paths.
///   normal      — valid client cert; handshake completes and keys export.
///   omit_cert   — client ignores the CertificateRequest; must NOT complete.
///   tamper_cv   — corrupted CertificateVerify; possession fails, must NOT complete.
///   fp_mismatch — valid cert (possession proven) but its fingerprint ≠ the bound
///                 one; the DTLS handshake completes but NO keys export.
const Flight13Mode = enum { normal, omit_cert, tamper_cv, fp_mismatch };

/// Build a self-signed ECDSA-P256 client cert into `cert_buf`, returning auth
/// material (DER borrows `cert_buf`, which must outlive the handshake).
fn makeClientAuth13(seed_byte: u8, cert_buf: []u8) !ClientAuth13 {
    const key_seed: [ecdsa_p256.KeyPair.seed_length]u8 = @splat(seed_byte);
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(key_seed);
    const serial = [_]u8{ 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(cert_buf, .{
        .common_name = "webrtc-client-13",
        .not_before = 1_700_000_000,
        .not_after = 1_900_000_000,
        .serial = &serial,
        .key_pair = kp,
    });
    return .{ .key_pair = kp, .cert_der = der };
}

test "full DTLS 1.3 loopback handshake: both sides derive identical SRTP keys, then ACK" {
    var setup = try makeTerminator(0x77);
    defer setup.deinit();
    try driveFullHandshake(&setup.term, testAddr(5, 7000), false);
}

test "full DTLS 1.3 handshake when the client leads with a non-P-256 key_share (HRR group selection)" {
    var setup = try makeTerminator(0x79);
    defer setup.deinit();
    // The browser case the reviewer flagged: CH1 carries only a non-secp256r1
    // key_share; the server must send an HRR SELECTING secp256r1, not drop it.
    try driveFullHandshake(&setup.term, testAddr(7, 7020), true);
}

test "RFC 8122 (1.3): matching fingerprint unlocks keys; mismatch stays fail-closed" {
    var setup = try makeTerminator(0x7A);
    defer setup.deinit();
    var term = &setup.term;

    // Peer A: complete the handshake first (driveFullHandshake asserts keys with
    // no expectation bound), then bind + present a matching cert. The binding is
    // evaluated live, so it gates even though it lands after completion.
    const addr_a = testAddr(5, 7600);
    const peer_cert = "simulated browser client cert (1.3)";
    try driveFullHandshake(term, addr_a, false);
    term.bindExpectedFingerprint(addr_a, peer_verify.certDigest(peer_cert));
    // Bound but not yet verified ⇒ fail closed.
    try testing.expect(term.established(addr_a));
    try testing.expect(!term.peerVerified(addr_a));
    try testing.expect(term.exportedKeys(addr_a) == null);
    try testing.expect(term.srtpProfile(addr_a) == null);
    // Present the matching cert ⇒ verified ⇒ keys unlocked.
    term.recordPeerCertificate(addr_a, peer_cert);
    try testing.expect(term.peerVerified(addr_a));
    try testing.expect(term.exportedKeys(addr_a) != null);
    try testing.expect(term.srtpProfile(addr_a) != null);

    // Peer B: a mismatched presented cert stays fail-closed.
    const addr_b = testAddr(6, 7601);
    try driveFullHandshake(term, addr_b, false);
    term.bindExpectedFingerprint(addr_b, peer_verify.certDigest("the promised cert"));
    term.recordPeerCertificate(addr_b, "a completely different cert");
    try testing.expect(!term.peerVerified(addr_b));
    try testing.expect(term.exportedKeys(addr_b) == null);
    try testing.expect(term.srtpProfile(addr_b) == null);
}

const CapturedFlight13 = struct { bytes: [2048]u8, len: usize };

/// Drive CH1→HRR→CH2 and capture the server's flight bytes (ServerHello + the
/// epoch-2 records) for byte-identity assertions. Uses the deterministic
/// `Client13` so two same-seed terminators emit the same flight.
fn captureServerFlight13(term: *Terminator, addr: TransportAddress) !CapturedFlight13 {
    var client = Client13.init();
    var out: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    const ch1 = try msg13.buildClientHello13(&client.ch1_body, .{
        .random = client.client_random,
        .key_share_point = client.ecdhe.public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var cookie_store: [cookie_len]u8 = undefined;
    {
        const dlen = try framePlaintext13(&scratch, .client_hello, 0, 0, ch1);
        const hrr = term.handleDatagram(addr, scratch[0..dlen], 100, &out) orelse return error.TestUnexpectedResult;
        const rdec = try p_record.RecordHeader.decode(hrr);
        const hh = try dhs.Header.decode(rdec.fragment);
        const shv = try msg13.parseServerHello13(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]);
        @memcpy(&cookie_store, shv.cookie[0..cookie_len]);
    }
    var ch2_store: [600]u8 = undefined;
    const ch2 = try msg13.buildClientHello13(&ch2_store, .{
        .random = client.client_random,
        .key_share_point = client.ecdhe.public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .cookie = &cookie_store,
    });
    const dlen = try framePlaintext13(&scratch, .client_hello, 1, 1, ch2);
    const flight = term.handleDatagram(addr, scratch[0..dlen], 101, &out) orelse return error.TestUnexpectedResult;
    var cap: CapturedFlight13 = .{ .bytes = undefined, .len = flight.len };
    @memcpy(cap.bytes[0..flight.len], flight);
    return cap;
}

test "mutual auth off (1.3): server flight is byte-identical to the pre-#64 flight" {
    // Same seed ⇒ same cert, cookie secret, and CSPRNG stream ⇒ deterministic
    // flight. One terminator engages mutual auth but binds NO fingerprint (so
    // mutual is not activated), the other is untouched: the flights must match.
    var a = try makeTerminator(0x8F);
    defer a.deinit();
    var b = try makeTerminator(0x8F);
    defer b.deinit();
    a.term.request_client_cert = true; // engaged, but no fingerprint bound below

    const addr = testAddr(9, 7810);
    const f4a = try captureServerFlight13(&a.term, addr);
    const f4b = try captureServerFlight13(&b.term, addr);
    // No CertificateRequest emitted (no fingerprint bound ⇒ server-auth only).
    try testing.expectEqualSlices(u8, f4a.bytes[0..f4a.len], f4b.bytes[0..f4b.len]);
}

test "mutual auth (1.3): a matching client cert completes the handshake and unlocks SRTP keys" {
    var setup = try makeTerminator(0x81);
    defer setup.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(5, 7800);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth13(0x41, &cert_buf);
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(auth.cert_der));

    // driveFullHandshakeAuth asserts established + identical SRTP keys internally.
    try driveFullHandshakeAuth(term, addr, false, auth, .normal);
    try testing.expect(term.peerVerified(addr));
    try testing.expect(term.exportedKeys(addr) != null);
}

test "mutual auth (1.3): the HRR group-selection path also captures the client cert" {
    var setup = try makeTerminator(0x82);
    defer setup.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(7, 7801);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth13(0x42, &cert_buf);
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(auth.cert_der));

    // CH1 leads with X25519 (HRR selects secp256r1) AND client-cert capture.
    try driveFullHandshakeAuth(term, addr, true, auth, .normal);
    try testing.expect(term.peerVerified(addr));
    try testing.expect(term.exportedKeys(addr) != null);
}

test "mutual auth (1.3): a client cert whose fingerprint mismatches yields NO keys" {
    var setup = try makeTerminator(0x83);
    defer setup.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(5, 7802);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth13(0x43, &cert_buf);
    term.bindExpectedFingerprint(addr, peer_verify.certDigest("a cert the peer will NOT present"));
    // .fp_mismatch asserts the DTLS layer completes but exports no keys.
    try driveFullHandshakeAuth(term, addr, false, auth, .fp_mismatch);
}

test "mutual auth (1.3): a client that omits its Certificate is rejected (no keys)" {
    var setup = try makeTerminator(0x84);
    defer setup.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(5, 7803);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth13(0x44, &cert_buf);
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(auth.cert_der));
    try driveFullHandshakeAuth(term, addr, false, auth, .omit_cert);
}

test "mutual auth (1.3): a tampered CertificateVerify signature is rejected (no keys)" {
    var setup = try makeTerminator(0x85);
    defer setup.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(5, 7804);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth13(0x45, &cert_buf);
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(auth.cert_der));
    try driveFullHandshakeAuth(term, addr, false, auth, .tamper_cv);
}

/// Drive a complete DTLS 1.3 handshake with a same-library client. When
/// `lead_non_p256` is set, CH1 leads with an X25519-only key_share (so the
/// server must negotiate secp256r1 via an HRR group selection); otherwise CH1
/// already carries the secp256r1 share (cookie-only HRR).
fn driveFullHandshake(term: *Terminator, addr: TransportAddress, lead_non_p256: bool) !void {
    return driveFullHandshakeAuth(term, addr, lead_non_p256, null, .normal);
}

fn driveFullHandshakeAuth(
    term: *Terminator,
    addr: TransportAddress,
    lead_non_p256: bool,
    client_auth: ?ClientAuth13,
    mode: Flight13Mode,
) !void {
    var client = Client13.init();
    var out: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    const x25519_dummy: [32]u8 = @splat(0x42);

    // 1) ClientHello1 (no cookie) → HelloRetryRequest.
    const ch1 = try msg13.buildClientHello13(&client.ch1_body, .{
        .random = client.client_random,
        .key_share_point = client.ecdhe.public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .key_share_override = if (lead_non_p256) .{ .group = .x25519, .key_exchange = &x25519_dummy } else null,
    });
    client.ch1_len = ch1.len;
    var cookie_store: [cookie_len]u8 = undefined;
    {
        const dlen = try framePlaintext13(&scratch, .client_hello, 0, 0, ch1);
        const hrr_dg = term.handleDatagram(addr, scratch[0..dlen], 100, &out) orelse return error.TestUnexpectedResult;
        const rdec = try p_record.RecordHeader.decode(hrr_dg);
        const hh = try dhs.Header.decode(rdec.fragment);
        const shv = try msg13.parseServerHello13(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]);
        try testing.expect(shv.isHelloRetryRequest());
        // A non-P-256-leading CH1 elicits an HRR that SELECTS secp256r1.
        if (lead_non_p256) {
            try testing.expectEqual(@as(?u16, msg13.named_group_secp256r1), shv.selected_group);
        } else {
            try testing.expectEqual(@as(?u16, null), shv.selected_group);
        }
        @memcpy(&cookie_store, shv.cookie[0..cookie_len]);
    }

    // 2) ClientHello2 (cookie). Begin the client transcript: synthetic
    //    message_hash(CH1), HRR, CH2. After an HRR the client presents secp256r1.
    client.ts = Sha256.init(.{});
    feedSynthetic(&client.ts, blk: {
        var t = Sha256.init(.{});
        feedTranscript13(&t, .client_hello, 0, client.ch1_body[0..client.ch1_len]);
        break :blk t.peek();
    });
    var ch2_store: [600]u8 = undefined;
    const ch2 = try msg13.buildClientHello13(&ch2_store, .{
        .random = client.client_random,
        .key_share_point = client.ecdhe.public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .cookie = &cookie_store,
    });
    // Feed the received HRR into the client transcript (message_seq 0). The HRR's
    // group-selection form matches whether CH1 led with a non-P-256 share.
    {
        var hrr_buf: [256]u8 = undefined;
        const hrr = try msg13.buildHelloRetryRequest(&hrr_buf, &.{}, &cookie_store, lead_non_p256);
        feedTranscript13(&client.ts, .server_hello, 0, hrr);
        feedTranscript13(&client.ts, .client_hello, 1, ch2);
    }
    const flight = blk: {
        const dlen = try framePlaintext13(&scratch, .client_hello, 1, 1, ch2);
        break :blk term.handleDatagram(addr, scratch[0..dlen], 101, &out) orelse return error.TestUnexpectedResult;
    };

    // 3) Parse the server flight: ServerHello (epoch 0) + encrypted EE, Cert,
    //    CertVerify, Finished (epoch 2). Derive keys and verify along the way.
    var off: usize = 0;
    const shdec = try p_record.RecordHeader.decode(flight[off..]);
    off += shdec.consumed;
    {
        const hh = try dhs.Header.decode(shdec.fragment);
        const sh_body = shdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length];
        const shv = try msg13.parseServerHello13(sh_body);
        try testing.expectEqual(@as(?u16, msg13.dtls_version_13), shv.selected_version);
        client.server_random = shv.random;
        client.server_point = shv.key_share_point orelse return error.TestUnexpectedResult;
        feedTranscript13(&client.ts, .server_hello, 1, sh_body);
    }

    // Key schedule.
    var shared = try kx.computeSharedSecret(client.ecdhe.secret, client.server_point);
    defer std.crypto.secureZero(u8, &shared);
    var early = KS.earlySecret("");
    defer early.wipe();
    var handshake = try KS.handshakeSecret(&early, &shared);
    defer handshake.wipe();
    const transcript_sh = client.ts.peek();
    var c_hs = try KS.deriveSecret(&handshake, "c hs traffic", &transcript_sh);
    defer c_hs.wipe();
    var s_hs = try KS.deriveSecret(&handshake, "s hs traffic", &transcript_sh);
    defer s_hs.wipe();
    var server_keys = record13.deriveAes128GcmKeys(s_hs.declassify());
    defer server_keys.wipe();
    var client_keys = record13.deriveAes128GcmKeys(c_hs.declassify());
    defer client_keys.wipe();

    var read_top: u64 = 0;
    var plain: [2048]u8 = undefined;
    // EncryptedExtensions (record seq 0)
    {
        const rec = try nextEncRecord(flight, &off);
        const opened = try openEncRecord(server_keys, rec, read_top, &plain);
        read_top = opened.seq;
        const hh = try dhs.Header.decode(opened.content);
        try testing.expectEqual(dhs.HandshakeType.encrypted_extensions, hh.hdr.msg_type);
        const ee_body = opened.content[dhs.handshake_header_len..][0..hh.hdr.length];
        try testing.expectEqual(@as(?u16, dtls_srtp.profile_aes128_cm_sha1_80), try msg13.parseEncryptedExtensions(ee_body));
        feedTranscript13(&client.ts, .encrypted_extensions, hh.hdr.message_seq, ee_body);
    }
    // CertificateRequest — mutual auth only (must appear before Certificate).
    if (client_auth != null) {
        const rec = try nextEncRecord(flight, &off);
        const opened = try openEncRecord(server_keys, rec, read_top, &plain);
        read_top = opened.seq;
        const hh = try dhs.Header.decode(opened.content);
        try testing.expectEqual(dhs.HandshakeType.certificate_request, hh.hdr.msg_type);
        const cr_body = opened.content[dhs.handshake_header_len..][0..hh.hdr.length];
        const cr = try msg13.parseCertificateRequest13(cr_body);
        try testing.expect(cr.offers_ecdsa_secp256r1_sha256);
        feedTranscript13(&client.ts, .certificate_request, hh.hdr.message_seq, cr_body);
    }
    // Certificate
    {
        const rec = try nextEncRecord(flight, &off);
        const opened = try openEncRecord(server_keys, rec, read_top, &plain);
        read_top = opened.seq;
        const hh = try dhs.Header.decode(opened.content);
        const cert_body = opened.content[dhs.handshake_header_len..][0..hh.hdr.length];
        try testing.expectEqualSlices(u8, term.certDer(), try msg13.parseCertificate13(cert_body));
        feedTranscript13(&client.ts, .certificate, hh.hdr.message_seq, cert_body);
    }
    // CertificateVerify — verify the signature over the transcript.
    {
        const transcript_cert = client.ts.peek();
        const rec = try nextEncRecord(flight, &off);
        const opened = try openEncRecord(server_keys, rec, read_top, &plain);
        read_top = opened.seq;
        const hh = try dhs.Header.decode(opened.content);
        const cv_body = opened.content[dhs.handshake_header_len..][0..hh.hdr.length];
        const cv = try msg13.parseCertificateVerify(cv_body);
        try testing.expectEqual(msg13.sig_scheme_ecdsa_secp256r1_sha256, cv.scheme);
        var content_buf: [160]u8 = undefined;
        const content = try msg13.certificateVerifyContent(&content_buf, &transcript_cert);
        const sig = try ecdsa_p256.signatureFromDer(cv.sig_der);
        try testing.expect(ecdsa_p256.verify(sig, content, term.certPublicKey()));
        feedTranscript13(&client.ts, .certificate_verify, hh.hdr.message_seq, cv_body);
    }
    // server Finished — verify verify_data over the transcript.
    {
        const transcript_cv = client.ts.peek();
        const rec = try nextEncRecord(flight, &off);
        const opened = try openEncRecord(server_keys, rec, read_top, &plain);
        read_top = opened.seq;
        const hh = try dhs.Header.decode(opened.content);
        const fin_body = opened.content[dhs.handshake_header_len..][0..hh.hdr.length];
        var s_fin_key = try KS.finishedKey(&s_hs);
        defer s_fin_key.wipe();
        const expected = try KS.finishedVerifyData(&s_fin_key, &transcript_cv);
        try testing.expectEqualSlices(u8, &expected, fin_body);
        feedTranscript13(&client.ts, .finished, hh.hdr.message_seq, fin_body);
    }

    // 4) Post-flight secrets on the client side. The exporter is bound to the
    //    transcript THROUGH the server Finished (independent of client auth).
    const transcript_sf = client.ts.peek();
    var master = try KS.masterSecret(&handshake);
    defer master.wipe();
    var exporter = try KS.exporterMasterSecret(&master, &transcript_sf);
    defer exporter.wipe();
    var c_fin_key = try KS.finishedKey(&c_hs);
    defer c_fin_key.wipe();

    // 5) Build the client flight. Mutual auth: Certificate (seq 0), then
    //    CertificateVerify (seq 1), then Finished (seq 2). Server-auth or
    //    `omit_cert`: just Finished (seq 0).
    const send_client_cert = client_auth != null and mode != .omit_cert;
    var client_flight: [2048]u8 = undefined;
    var cf_len: usize = 0;
    var client_epoch2: u64 = 0;

    if (send_client_cert) {
        const auth = client_auth.?;
        // client Certificate (message_seq 2).
        var cert_buf: [cert_der_cap + 16]u8 = undefined;
        const cert = try msg13.buildCertificate13(&cert_buf, auth.cert_der);
        feedTranscript13(&client.ts, .certificate, 2, cert);
        cf_len += try frameEncHandshake(client_flight[cf_len..], client_keys, client_epoch2, .certificate, 2, cert);
        client_epoch2 += 1;
        // client CertificateVerify (message_seq 3), signed over the client-context
        // content bound to the transcript THROUGH the client Certificate.
        const th_cert = client.ts.peek();
        var cvc_buf: [200]u8 = undefined;
        const cvc = try msg13.certificateVerifyContentCtx(&cvc_buf, msg13.cert_verify_context_client, &th_cert);
        const cv_sig = try ecdsa_p256.sign(cvc, auth.key_pair);
        var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
        const sig_der = try ecdsa_p256.signatureToDer(cv_sig, &sig_der_buf);
        var cv_buf: [128]u8 = undefined;
        const cv = try msg13.buildCertificateVerify(&cv_buf, sig_der);
        if (mode == .tamper_cv) cv_buf[cv.len - 1] ^= 0x40; // corrupt the signature
        feedTranscript13(&client.ts, .certificate_verify, 3, cv);
        cf_len += try frameEncHandshake(client_flight[cf_len..], client_keys, client_epoch2, .certificate_verify, 3, cv);
        client_epoch2 += 1;
    }

    // client Finished. verify_data covers the transcript through the client
    // CertificateVerify (mutual) or the server Finished (server-auth / omit_cert).
    const finished_transcript = if (send_client_cert) client.ts.peek() else transcript_sf;
    const client_verify = try KS.finishedVerifyData(&c_fin_key, &finished_transcript);
    const client_fin_seq = client_epoch2;
    const fin_msg_seq: u16 = if (send_client_cert) 4 else 2;
    cf_len += try frameEncHandshake(client_flight[cf_len..], client_keys, client_epoch2, .finished, fin_msg_seq, &client_verify);
    client_epoch2 += 1;

    const resp_opt = term.handleDatagram(addr, client_flight[0..cf_len], 102, &out);

    switch (mode) {
        // Fail-closed mutual auth: no possession ⇒ the server never completes.
        .omit_cert, .tamper_cv => {
            try testing.expect(resp_opt == null);
            try testing.expect(!term.established(addr));
            try testing.expect(term.exportedKeys(addr) == null);
            try testing.expect(term.srtpProfile(addr) == null);
            return;
        },
        // Possession proven but the fingerprint does not match: the DTLS layer
        // completes (ACK) but identity is unverified ⇒ NO keys, no media.
        .fp_mismatch => {
            try testing.expect(resp_opt != null);
            try testing.expect(term.established(addr));
            try testing.expect(!term.peerVerified(addr));
            try testing.expect(term.exportedKeys(addr) == null);
            try testing.expect(term.srtpProfile(addr) == null);
            return;
        },
        .normal => {},
    }
    const ack_dg = resp_opt orelse return error.TestUnexpectedResult;

    // 6) The handshake is established and both sides export identical SRTP keys.
    try testing.expect(term.established(addr));
    const server_srtp = term.exportedKeys(addr) orelse return error.TestUnexpectedResult;
    const client_srtp = try dtls_srtp.exportSrtpKeysTls13(exporter.declassify());
    try testing.expectEqualSlices(u8, &client_srtp.client, &server_srtp.client);
    try testing.expectEqualSlices(u8, &client_srtp.server, &server_srtp.server);
    try testing.expectEqual(@as(?u16, dtls_srtp.profile_aes128_cm_sha1_80), term.srtpProfile(addr));

    // 7) The response is an ACK acknowledging the client's Finished record.
    {
        var ackoff: usize = 0;
        const rec = try nextEncRecord(ack_dg, &ackoff);
        const opened = try openEncRecord(server_keys, rec, read_top, &plain);
        try testing.expectEqual(inner_ack, opened.inner_type);
        try testing.expectEqual(@as(usize, 1), try msg13.parseAckCount(opened.content));
        const rn = try msg13.ackRecordNumber(opened.content, 0);
        try testing.expectEqual(@as(u64, epoch_handshake), rn.epoch);
        try testing.expectEqual(client_fin_seq, rn.sequence_number); // client Finished seq
    }

    // 8) The exported material actually feeds an SRTP session.
    const srtp = @import("srtp.zig");
    const sk = srtp.deriveSessionKeys(client_srtp.clientMaster(), client_srtp.clientSalt());
    const rtp = [_]u8{ 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0xCA, 0xFE, 0xBA, 0xBE } ++ "voice".*;
    var prot: [rtp.len + srtp.auth_tag_len]u8 = undefined;
    const wire = try srtp.protect(sk, 0, &rtp, &prot);
    var back: [rtp.len]u8 = undefined;
    try testing.expectEqualSlices(u8, &rtp, try srtp.unprotect(sk, 0, wire, &back));

    // 9) Reliability: a retransmitted client flight resends the cached ACK.
    var out2: [2048]u8 = undefined;
    const ack2 = term.handleDatagram(addr, client_flight[0..cf_len], 103, &out2) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, ack_dg, ack2);
}

test "openEncRecord accepts a length-elided last record (RFC 9147 §4)" {
    var keys = record13.deriveAes128GcmKeys(@splat(0x5a));
    defer keys.wipe();

    const body = "client-finished-32-byte-verifydat";
    var inner: [dhs.handshake_header_len + body.len + 1]u8 = undefined;
    const hh = dhs.Header{ .msg_type = .finished, .length = body.len, .message_seq = 2, .fragment_offset = 0, .fragment_length = body.len };
    _ = try hh.encode(inner[0..dhs.handshake_header_len]);
    @memcpy(inner[dhs.handshake_header_len..][0..body.len], body);
    inner[dhs.handshake_header_len + body.len] = inner_handshake;

    // Seal under a LENGTH-LESS unified header (runs to end-of-datagram).
    const hdr = record13.Header{ .epoch_low = @truncate(epoch_handshake), .seq = 0, .seq_len = .long, .length_present = false, .record_len = 0 };
    const hdr_len = hdr.wireLen(); // 3: B0 + 2 seq, no length field
    const sealed_len = inner.len + record13.tag_len;
    var rec: [3 + inner.len + record13.tag_len]u8 = undefined;
    _ = try hdr.encode(rec[0..hdr_len]);
    _ = try record13.sealRecordAes128Gcm(keys.key, keys.iv, 0, rec[0..hdr_len], &inner, rec[hdr_len..][0..sealed_len]);
    const sample: [16]u8 = rec[hdr_len..][0..16].*;
    const mask = record13.recordNumberMaskAes128(keys.sn_key, sample);
    record13.applyRecordNumberMask(rec[1..3], mask[0..2]);

    var plain: [256]u8 = undefined;
    const opened = try openEncRecord(keys, rec[0 .. hdr_len + sealed_len], 0, &plain);
    try testing.expectEqual(inner_handshake, opened.inner_type);
    const dhh = try dhs.Header.decode(opened.content);
    try testing.expectEqual(dhs.HandshakeType.finished, dhh.hdr.msg_type);
    try testing.expectEqualStrings(body, opened.content[dhs.handshake_header_len..][0..dhh.hdr.length]);
}

test "offersDtls13 requires secp256r1 support so a P-256-less 1.3 client falls through to 1.2" {
    var buf: [1024]u8 = undefined;
    var dg: [1200]u8 = undefined;
    const x25519: [32]u8 = @splat(0x09);

    // Normal 1.3 CH (secp256r1 key_share) → routes to 1.3.
    {
        const ch = try msg13.buildClientHello13(&buf, .{
            .random = @splat(1),
            .key_share_point = kx.generateKeyPair(@splat(0x02)).public,
            .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        });
        const n = try framePlaintext13(&dg, .client_hello, 0, 0, ch);
        try testing.expect(offersDtls13(dg[0..n]));
    }
    // 1.3 CH leading with X25519 but supporting secp256r1 in groups → still ours
    // (we negotiate secp256r1 via HRR).
    {
        const ch = try msg13.buildClientHello13(&buf, .{
            .random = @splat(3),
            .key_share_point = undefined,
            .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
            .key_share_override = .{ .group = .x25519, .key_exchange = &x25519 },
        });
        const n = try framePlaintext13(&dg, .client_hello, 0, 0, ch);
        try testing.expect(offersDtls13(dg[0..n]));
    }
    // 1.3 CH with NO secp256r1 support at all → NOT ours (falls through to 1.2).
    {
        const ch = try msg13.buildClientHello13(&buf, .{
            .random = @splat(5),
            .key_share_point = undefined,
            .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
            .key_share_override = .{ .group = .x25519, .key_exchange = &x25519 },
            .advertise_secp256r1_group = false,
        });
        const n = try framePlaintext13(&dg, .client_hello, 0, 0, ch);
        try testing.expect(!offersDtls13(dg[0..n]));
    }
    // Garbage / non-ClientHello → false.
    try testing.expect(!offersDtls13(&.{ 22, 0xfe, 0xfd, 0, 0 }));
    try testing.expect(!offersDtls13(&.{}));
}

test "a P-256-less-group 1.3 ClientHello is dropped by the 1.3 engine (cannot serve)" {
    var setup = try makeTerminator(0x91);
    defer setup.deinit();
    const addr = testAddr(11, 7300);
    const x25519: [32]u8 = @splat(0x09);
    var buf: [1024]u8 = undefined;
    const ch = try msg13.buildClientHello13(&buf, .{
        .random = @splat(2),
        .key_share_point = undefined,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .key_share_override = .{ .group = .x25519, .key_exchange = &x25519 },
        .advertise_secp256r1_group = false,
    });
    var dg: [1100]u8 = undefined;
    const n = try framePlaintext13(&dg, .client_hello, 0, 0, ch);
    var out: [2048]u8 = undefined;
    // No HRR (we can't offer P-256), no session — fail-closed.
    try testing.expect(setup.term.handleDatagram(addr, dg[0..n], 1, &out) == null);
    try testing.expect(!setup.term.owns(addr));
}

/// Advance `off` over one epoch-2 unified record and return its bytes.
fn nextEncRecord(datagram: []const u8, off: *usize) !([]const u8) {
    if (off.* >= datagram.len) return error.TestUnexpectedResult;
    try testing.expect((datagram[off.*] & 0b1110_0000) == 0b0010_0000);
    const dech = try record13.Header.decode(datagram[off.*..]);
    const rec_total = dech.consumed + @as(usize, dech.hdr.record_len);
    if (off.* + rec_total > datagram.len) return error.TestUnexpectedResult;
    const rec = datagram[off.* .. off.* + rec_total];
    off.* += rec_total;
    return rec;
}

test "retransmitted second ClientHello resends the cached server flight verbatim" {
    var setup = try makeTerminator(0x88);
    defer setup.deinit();
    var term = &setup.term;
    const addr = testAddr(6, 7100);

    const ecdhe = kx.generateKeyPair(@splat(0xC1));
    var out: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;

    // CH1 → HRR (grab the cookie).
    var ch1_body: [512]u8 = undefined;
    const ch1 = try msg13.buildClientHello13(&ch1_body, .{
        .random = @splat(4),
        .key_share_point = ecdhe.public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var cookie_store: [cookie_len]u8 = undefined;
    {
        const dlen = try framePlaintext13(&scratch, .client_hello, 0, 0, ch1);
        const hrr = term.handleDatagram(addr, scratch[0..dlen], 100, &out) orelse return error.TestUnexpectedResult;
        const rdec = try p_record.RecordHeader.decode(hrr);
        const hh = try dhs.Header.decode(rdec.fragment);
        const shv = try msg13.parseServerHello13(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]);
        @memcpy(&cookie_store, shv.cookie[0..cookie_len]);
    }

    // CH2 → server flight.
    var ch2_body: [600]u8 = undefined;
    const ch2 = try msg13.buildClientHello13(&ch2_body, .{
        .random = @splat(4),
        .key_share_point = ecdhe.public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .cookie = &cookie_store,
    });
    const ch2_dlen = try framePlaintext13(&scratch, .client_hello, 1, 1, ch2);

    var first_out: [2048]u8 = undefined;
    const f1 = term.handleDatagram(addr, scratch[0..ch2_dlen], 101, &first_out) orelse return error.TestUnexpectedResult;
    var first_copy: [2048]u8 = undefined;
    @memcpy(first_copy[0..f1.len], f1);

    // Retransmit the identical CH2 → identical flight, no new session slot.
    const f2 = term.handleDatagram(addr, scratch[0..ch2_dlen], 102, &out) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, first_copy[0..f1.len], f2);
}
