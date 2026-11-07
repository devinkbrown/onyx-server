// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection TLS 1.3 adapter that drives `crypto/tls_server.Server` from the
//! daemon's socket loop. The loop never touches the handshake state machine
//! directly: it hands raw socket bytes to `onInbound()`, writes back the returned
//! ciphertext, and once `handshakeDone()` is true reads decrypted application
//! data from the same `Outcome`. Outbound application data goes through `write()`.
//!
//! This wrapper owns the record-layer framing: a TLS record is a 5-byte header
//! (content type, 2-byte legacy version, 2-byte length) followed by `length`
//! body bytes. `onInbound()` buffers the inbound stream, processes only complete
//! records, and retains any trailing partial record for the next call. The inner
//! `Server` already buffers internally too, but we frame before feeding so we can
//! cleanly switch from "feed the handshake" to "decrypt application_data" the
//! instant the handshake completes (a connected `Server.feed` rejects records).
//!
//! Scope mirrors `tls_server`: TLS 1.3, X25519, an Ed25519 leaf. This module does
//! no syscalls — it is a pure byte transform over the `Server` it wraps.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const tls_server = @import("../crypto/tls_server.zig");
const tls12_server = @import("../crypto/tls12_server.zig");
const tls_record = @import("../crypto/tls_record.zig");
const tls_handshake_reassembly = @import("../crypto/tls_handshake_reassembly.zig");
const tls_resumption = @import("../crypto/tls_resumption.zig");
const ktls = @import("ktls.zig");
const acme_runner = @import("acme_runner.zig");
const acme_challenge = @import("../proto/acme_challenge.zig");
const kernel_other = @import("kernel_other.zig");
const linux = std.os.linux;
const posix = std.posix;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_conn requires a 64-bit target");
}

/// Errors surfaced by the adapter: the inner 1.3 + 1.2 handshake/record errors
/// plus the allocator errors from growing the internal buffers.
pub const Error = tls_server.Error || tls12_server.Error || Allocator.Error || error{ KtlsTxOffloaded, ControlBlocked, InvalidDeferred };

/// What a single `onInbound()` produced. Both slices point into internal buffers
/// and stay valid only until the next `onInbound()` / `write()` call; the caller
/// must consume or copy them before driving the connection again.
///
///   * `handshake_bytes` — ciphertext to write straight back to the socket. This
///     includes server flights and queued post-handshake control output.
///   * `plaintext` — decrypted application data accumulated from any
///     application_data records in this batch. Empty until the handshake is done
///     and whenever a batch carried no complete application records.
pub const Outcome = struct {
    handshake_bytes: []const u8 = &.{},
    plaintext: []const u8 = &.{},
    /// Exactly one fixed software KU response, preallocated before admission.
    control_reply: bool = false,
};

/// Inner engine selected from the first ClientHello. `undecided` holds until a
/// version is detected; afterwards exactly one engine drives the connection.
const Engine = union(enum) {
    undecided,
    tls13: tls_server.Server,
    tls12: tls12_server.Server,
};

pub const Version = enum { tls12, tls13 };

/// Caller-owned old plaintext prefix for a kernel TX held-control turn.
/// This relation is shared by non-destructive capture and strict hot decode.
pub fn validateKernelTxPrefix(tx: bool, phase: ControlBarrierPhase, reply_pending: bool, credit: u32, prefix: u64, wire_len: u64) Error!void {
    const holding = phase == .userspace_requested_ku_held or phase == .kernel_control_read_held;
    if (!tx or !holding) {
        if (prefix != 0) return error.BadState;
        return;
    }
    if (reply_pending or prefix > wire_len or (credit != 0 and credit != 5) or
        (credit == 0 and prefix != wire_len)) return error.BadState;
}

/// Incomplete kernel RX control remains under the caller's pre-read barrier.
/// A software RX prefix is independent and may be retained in the ordinary phase.
pub fn validateKernelRxControlPhase(rx: bool, phase: ControlBarrierPhase, ku_prefix_len: u8, open_type: u8, alert_prefix_len: u8) Error!void {
    if (open_type != 0 and open_type != 21 and open_type != 22) return error.BadState;
    if ((alert_prefix_len != 0 and open_type != 21) or
        (open_type == 21 and ku_prefix_len != 0) or
        (open_type == 22 and (ku_prefix_len == 0 or alert_prefix_len != 0))) return error.BadState;
    if (!rx) {
        if (open_type != 0 or alert_prefix_len != 0) return error.BadState;
    } else if ((ku_prefix_len != 0 or open_type != 0 or alert_prefix_len != 0) and
        phase != .kernel_control_read_held) return error.BadState;
}

pub const ControlBarrierPhase = enum(u8) {
    none = 0,
    userspace_requested_ku_held = 1,
    kernel_control_read_held = 2,
    software_tail_ready = 3,
};

/// Exact nonmutating geometry used by producer reservations and hot validation.
/// Empty deferred inputs are omitted. Preserve adapter max-record chunk splits.
pub fn chunkWireCharge(engine: TlsConn.ResumeState.EngineState, bytes_len: usize) Error!u64 {
    if (bytes_len == 0) return 0;
    const peer: usize = switch (engine) {
        inline else => |rs| rs.peer_record_size_limit_raw,
    };
    const limit: usize = switch (engine) {
        .tls13 => tls_record.recordContentLimit(peer),
        .tls12 => tls_record.recordContentLimit12(peer),
    };
    const overhead: u64 = switch (engine) {
        .tls13 => 22,
        .tls12 => |rs| blk: {
            const suite = @import("../crypto/tls12.zig").CipherSuite.fromWire(rs.suite) catch return error.BadState;
            break :blk if (suite.aead() == .chacha20_poly1305) 21 else 29;
        },
    };
    var remaining = bytes_len;
    var charge: u64 = 0;
    while (remaining != 0) {
        const n = @min(remaining, tls_record.max_plaintext_len);
        const records = (n - 1) / limit + 1;
        charge = std.math.add(u64, charge, std.math.add(u64, n, std.math.mul(u64, records, overhead) catch return error.PlaintextTooLong) catch return error.PlaintextTooLong) catch return error.PlaintextTooLong;
        remaining -= n;
    }
    return charge;
}

pub fn deferredCiphertextCharge(engine: TlsConn.ResumeState.EngineState, bytes: []const u8) Error!u64 {
    var offset: usize = 0;
    var charge: u64 = 0;
    while (offset != bytes.len) {
        if (bytes.len - offset < 4) return error.InvalidDeferred;
        const len = std.mem.readInt(u32, bytes[offset..][0..4], .little);
        offset += 4;
        if (len == 0 or len > bytes.len - offset) return error.InvalidDeferred;
        charge = std.math.add(u64, charge, try chunkWireCharge(engine, len)) catch return error.PlaintextTooLong;
        offset += len;
    }
    return charge;
}

pub const TlsConn = struct {
    allocator: Allocator,
    engine: Engine,
    /// TLS 1.3 server config (always present; the default/preferred protocol).
    cfg13: tls_server.Config,
    /// Optional hardened TLS 1.2 config. When null the listener is 1.3-only and
    /// a non-1.3 ClientHello is rejected with `error.ProtocolVersion`.
    cfg12: ?tls12_server.Config,
    /// Pins the live OCSP generation while a handshake can still reference it.
    ocsp_owned13: ?[]u8 = null,
    ocsp_owned12: ?[]u8 = null,

    /// Inbound socket bytes not yet split into a complete record.
    recv_buf: std.ArrayList(u8) = .empty,
    /// Bounded first ClientHello accumulation used only for dual-version
    /// dispatch. The selected engine still consumes the original wire records.
    version_detection: tls_handshake_reassembly.Reassembly = .{},
    version_detection_scanned: usize = 0,
    /// Already exposed ciphertext scratch, rebuilt per successful owner turn.
    send_buf: std.ArrayList(u8) = .empty,
    /// Owned engine flights whose bytes have not appeared in an Outcome. Slot
    /// capacity is reserved before consuming the engine, so TX publication
    /// never depends on a subsequent allocation to retain its exact bytes.
    unpublished: std.ArrayList([]u8) = .empty,
    /// An inbound failure closes application/capture admission. Retained output
    /// remains owned until terminal disposition; retries keep the first cause.
    terminal_error: ?anyerror = null,
    terminal_alert_attempted: bool = false,
    terminal_output_taken: bool = false,
    /// Decrypted application data, rebuilt per `onInbound()` call.
    plain_buf: std.ArrayList(u8) = .empty,
    /// Scratch for outbound ciphertext, rebuilt per `write()` call.
    write_buf: std.ArrayList(u8) = .empty,
    /// Set after a successful `enableKtlsTx`. `write()` must not userspace-AEAD
    /// the same bytes the kernel will encrypt.
    ktls_tx_offloaded: bool = false,
    ktls_rx_offloaded: bool = false,
    /// One graceful close_notify attempt per connection (`sendCloseNotify`).
    close_notify_attempted: bool = false,
    rx_open_control_type: u8 = 0,
    alert_prefix_len: u1 = 0,
    alert_prefix_byte: u8 = 0,
    tx_ku_reply_pending: bool = false,
    tx_ku_reply_sent: u3 = 0,
    control_phase: ControlBarrierPhase = .none,
    /// Deterministic test scheduling at the irreversible syscall/install seam.
    /// The callback changes the real descriptor; accepted bytes are never faked.
    test_after_kernel_reply: if (builtin.is_test) ?struct {
        ctx: *anyopaque,
        call: *const fn (*anyopaque, i32) void,
    } else void = if (builtin.is_test) null else {},
    held_record_len: u32 = 0,
    control_turn_active: bool = false,
    /// RFC 8737 tls-alpn-01: the ACME challenge store this listener consults
    /// for an `acme-tls/1` ClientHello. Borrowed (the ACME Service outlives
    /// every connection); null when tls-alpn-01 is not configured.
    acme_store: ?*acme_runner.TlsAlpn01Store = null,
    /// Set when this connection was selected as a tls-alpn-01 validation: the
    /// engine presents the challenge certificate from this heap copy, and the
    /// daemon closes the connection once the handshake completes.
    acme_validation: ?*AcmeValidation = null,
    /// The first complete record was already offered to `acme_store`.
    acme_checked: bool = false,

    const AcmeValidation = struct {
        lease: acme_runner.TlsAlpn01Store.Lease,
        chain: [1][]const u8,
    };

    /// TLS 1.3-only adapter (back-compatible): the engine is fixed to the TLS 1.3
    /// server and a 1.2 ClientHello is rejected.
    pub fn init(allocator: Allocator, config: tls_server.Config) Error!TlsConn {
        var owned: ?[]u8 = null;
        if (config.ocsp_staple.len != 0) owned = try allocator.dupe(u8, config.ocsp_staple);
        errdefer if (owned) |bytes| allocator.free(bytes);
        var pinned = config;
        if (owned) |bytes| pinned.ocsp_staple = bytes;
        return .{
            .allocator = allocator,
            .engine = .{ .tls13 = try tls_server.Server.init(allocator, pinned) },
            .cfg13 = pinned,
            .cfg12 = null,
            .ocsp_owned13 = owned,
        };
    }

    /// TLS 1.3-only accept path with a borrowed OCSP staple. The caller must
    /// keep the staple alive until the handshake finishes or this adapter is
    /// deinitialized, including across certificate and staple reloads.
    pub fn initBorrowed(allocator: Allocator, config: tls_server.Config) Error!TlsConn {
        return .{
            .allocator = allocator,
            .engine = .{ .tls13 = try tls_server.Server.init(allocator, config) },
            .cfg13 = config,
            .cfg12 = null,
        };
    }

    /// Version-dispatching adapter: the first ClientHello is routed to the TLS
    /// 1.3 server when it offers supported_versions=0x0304, otherwise to the
    /// hardened TLS 1.2 server. Both configs are borrowed.
    pub fn initDual(allocator: Allocator, cfg13: tls_server.Config, cfg12: tls12_server.Config) TlsConn {
        return .{ .allocator = allocator, .engine = .undecided, .cfg13 = cfg13, .cfg12 = cfg12 };
    }

    /// Production dual-version accept path. Each live staple is detached from
    /// the Server generation before the engine can borrow it.
    pub fn initDualOwnedStaple(allocator: Allocator, cfg13: tls_server.Config, cfg12: tls12_server.Config) Error!TlsConn {
        var pinned13 = cfg13;
        var pinned12 = cfg12;
        var owned13: ?[]u8 = null;
        var owned12: ?[]u8 = null;
        errdefer {
            if (owned12) |bytes| allocator.free(bytes);
            if (owned13) |bytes| allocator.free(bytes);
        }
        if (cfg13.ocsp_staple.len != 0) {
            owned13 = try allocator.dupe(u8, cfg13.ocsp_staple);
            pinned13.ocsp_staple = owned13.?;
        }
        if (cfg12.ocsp_staple.len != 0) {
            if (owned13 != null and cfg12.ocsp_staple.ptr == cfg13.ocsp_staple.ptr and
                cfg12.ocsp_staple.len == cfg13.ocsp_staple.len)
            {
                pinned12.ocsp_staple = owned13.?;
            } else {
                owned12 = try allocator.dupe(u8, cfg12.ocsp_staple);
                pinned12.ocsp_staple = owned12.?;
            }
        }
        return .{ .allocator = allocator, .engine = .undecided, .cfg13 = pinned13, .cfg12 = pinned12, .ocsp_owned13 = owned13, .ocsp_owned12 = owned12 };
    }

    pub fn deinit(self: *TlsConn) void {
        switch (self.engine) {
            .undecided => {},
            .tls13 => |*s| s.deinit(),
            .tls12 => |*s| s.deinit(),
        }
        self.recv_buf.deinit(self.allocator);
        self.version_detection.deinit(self.allocator);
        self.send_buf.deinit(self.allocator);
        self.discardUnpublished();
        self.unpublished.deinit(self.allocator);
        self.plain_buf.deinit(self.allocator);
        self.write_buf.deinit(self.allocator);
        if (self.ocsp_owned12) |bytes| self.allocator.free(bytes);
        if (self.ocsp_owned13) |bytes| self.allocator.free(bytes);
        if (self.acme_validation) |validation| {
            validation.lease.wipe();
            std.crypto.secureZero(u8, std.mem.asBytes(validation));
            self.allocator.destroy(validation);
        }
        self.* = undefined;
    }

    /// True for a connection answering an RFC 8737 tls-alpn-01 validation.
    /// RFC 8737 §3: such a connection carries no application data; the daemon
    /// must close it once the handshake completes and never hand it to IRC.
    pub fn isAcmeTlsAlpn01(self: *const TlsConn) bool {
        return self.acme_validation != null;
    }

    /// Engine configs for an `acme-tls/1` validation (RFC 8737 §3): only the
    /// challenge certificate and its key, only the `acme-tls/1` protocol, and
    /// no tickets, early data, client certificates, OCSP or delegated
    /// credentials. The acmeIdentifier extension is critical and unknown to
    /// the X.509 parser, so the certificate signature-algorithm policy check
    /// (which parses the chain) is off for this leaf.
    fn acmeConfig13(base: tls_server.Config, validation: *const AcmeValidation) tls_server.Config {
        var cfg = base;
        cfg.cert_chain = &validation.chain;
        cfg.ecdsa_p256_signing_key = validation.lease.key_pair;
        cfg.signing_key = null;
        cfg.rsa_signing_key = null;
        cfg.alpn_protocols = &acme_alpn_protocols;
        cfg.sni_certs = &.{};
        cfg.ocsp_staple = &.{};
        cfg.enable_session_tickets = false;
        cfg.max_early_data_size = 0;
        cfg.delegated_credential = null;
        cfg.enable_raw_public_key = false;
        cfg.request_client_cert = false;
        cfg.enforce_cert_signature_algorithms = false;
        cfg.enable_cert_compression = false;
        return cfg;
    }

    fn acmeConfig12(base: tls12_server.Config, validation: *const AcmeValidation) tls12_server.Config {
        var cfg = base;
        cfg.cert_chain = &validation.chain;
        cfg.ecdsa_p256_signing_key = validation.lease.key_pair;
        cfg.rsa_signing_key = null;
        cfg.alpn_protocols = &acme_alpn_protocols;
        cfg.ocsp_staple = &.{};
        cfg.enable_session_tickets = false;
        cfg.request_client_cert = false;
        return cfg;
    }

    const acme_alpn_protocols = [_][]const u8{acme_challenge.acme_tls_alpn_protocol};

    /// Consult the tls-alpn-01 store with the complete first record. A hit
    /// copies the lease into connection-owned storage; a miss (or a
    /// fragmented hello) handles the connection normally.
    fn selectAcmeValidation(self: *TlsConn) Error!void {
        if (self.acme_checked) return;
        self.acme_checked = true;
        const store = self.acme_store orelse return;
        var lease = store.selectForClientHello(self.recv_buf.items) orelse return;
        errdefer lease.wipe();
        const validation = try self.allocator.create(AcmeValidation);
        validation.* = .{ .lease = lease, .chain = undefined };
        validation.chain = .{validation.lease.certDer()};
        lease.wipe();
        self.acme_validation = validation;
    }

    /// Outcome of `sendCloseNotify`.
    pub const CloseNotifyOutcome = enum {
        /// Not eligible: handshake incomplete, a fatal alert/terminal failure
        /// already ended this TLS stream, an output/control turn is open, or a
        /// close_notify was already attempted.
        not_applicable,
        /// The whole alert record was accepted by the socket.
        sent,
        /// Eligible, but the socket refused or only partially accepted it.
        /// Best-effort: the caller closes the transport regardless.
        dropped,
    };

    /// True when no fatal alert, terminal failure, open control obligation or
    /// unpublished/prepared output precludes a graceful closure alert. Callers
    /// must additionally guarantee that every earlier TX byte reached the
    /// socket (no queued ciphertext or kernel plaintext tail).
    pub fn closeNotifyEligible(self: *const TlsConn) bool {
        // The only terminal input that still permits our alert is the peer's
        // own close_notify, which RFC 5246 §7.2.1 requires us to answer and
        // RFC 8446 §6.1 permits (each side closes its own write direction).
        if (self.terminal_error) |failure| {
            if (failure != error.TlsAlert or !self.peerSentCloseNotify()) return false;
        }
        // The engines report `read_failed` after any terminal input (including
        // that close_notify); the write direction remains connected.
        const connected = switch (self.engine) {
            .undecided => false,
            .tls13 => |*s| s.state == .connected,
            .tls12 => |*s| s.state == .connected,
        };
        return !self.close_notify_attempted and connected and
            !self.terminal_alert_attempted and !self.terminal_output_taken and
            self.unpublished.items.len == 0 and self.control_phase == .none and
            !self.tx_ku_reply_pending and !self.control_turn_active and !self.hasPreparedWrite();
    }

    /// Graceful closure (RFC 8446 §6.1, RFC 5246 §7.2.1): emit one
    /// close_notify warning alert on `fd` before the caller closes it.
    /// Best-effort and non-blocking (MSG_DONTWAIT): it never waits for socket
    /// space and never retries, so shutdown is never delayed. At most one
    /// attempt is made per connection and never after a fatal alert.
    ///
    ///   * userspace TX: the engine seals the alert at the next write sequence
    ///     (`closeNotify`) and the record is written directly;
    ///   * kTLS TX: the kernel owns the write sequence, so the alert is sent as
    ///     a kernel control record (`sendmsg` + `SOL_TLS`/`TLS_SET_RECORD_TYPE`
    ///     = 21, payload {warning(1), close_notify(0)}).
    ///
    /// The caller must have drained every earlier TX byte to the socket and
    /// must own the only send path at this moment (no armed SEND).
    pub fn sendCloseNotify(self: *TlsConn, fd: linux.fd_t) CloseNotifyOutcome {
        if (!self.closeNotifyEligible()) return .not_applicable;
        self.close_notify_attempted = true;
        if (comptime builtin.os.tag != .linux) return .dropped;
        const body = [_]u8{ 1, 0 }; // warning(1), close_notify(0)
        if (self.ktls_tx_offloaded) {
            const accepted = ktls.sendControl(fd, .alert, &body) catch return .dropped;
            return if (accepted == body.len) .sent else .dropped;
        }
        const record = switch (self.engine) {
            .tls13 => |*s| s.closeNotify(),
            .tls12 => |*s| s.closeNotify(),
            .undecided => return .dropped,
        } catch return .dropped;
        defer self.allocator.free(record);
        while (true) {
            const rc = linux.sendto(fd, record.ptr, record.len, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => return if (rc == record.len) .sent else .dropped,
                .INTR => continue,
                else => return .dropped,
            }
        }
    }

    /// True when the TLS stream ended because the peer sent close_notify
    /// (RFC 8446 §6.1 / RFC 5246 §7.2.1): a graceful end of input, not a fault.
    /// Valid after the engine reported `error.TlsAlert`.
    pub fn peerSentCloseNotify(self: *const TlsConn) bool {
        const alert = switch (self.engine) {
            .undecided => return false,
            .tls13 => |*s| s.peer_alert,
            .tls12 => |*s| s.peer_alert,
        } orelse return false;
        return alert.description == .close_notify;
    }

    /// True once the chosen engine's handshake has completed.
    pub fn handshakeDone(self: *const TlsConn) bool {
        if (self.terminal_error != null) return false;
        return switch (self.engine) {
            .undecided => false,
            .tls13 => |*s| s.handshakeDone(),
            .tls12 => |*s| s.handshakeDone(),
        };
    }

    pub const KtlsError = error{
        /// The engine isn't a connected TLS 1.3 or TLS 1.2 AEAD session whose
        /// state the kernel can take over exactly (see `ktlsTxParams`).
        KtlsUnsupportedEngine,
        /// Inbound userspace buffer holds a partial TLS record — attaching kTLS RX
        /// mid-record would desync `app_read_seq` from the kernel.
        KtlsDirtyInbound,
    } || ktls.Error || ktls.AttachError;

    /// Map a `tls_server` kTLS param bundle to an encoded kernel `crypto_info`.
    fn encodeKtlsCryptoInfo(params: tls_server.Server.KtlsTxParams, out: []u8) KtlsError![]const u8 {
        const cipher: ktls.Cipher = switch (params.cipher) {
            .aes_128_gcm => .aes_gcm_128,
            .aes_256_gcm => .aes_gcm_256,
            .chacha20_poly1305 => .chacha20_poly1305,
        };
        const info = try ktls.tls13CryptoInfo(cipher, &params.iv, params.key, params.seq);
        return info.encode(out);
    }

    fn ktls12Cipher(cipher: tls12_server.Server.KtlsCipher) ktls.Cipher {
        return switch (cipher) {
            .aes_128_gcm => .aes_gcm_128,
            .aes_256_gcm => .aes_gcm_256,
            .chacha20_poly1305 => .chacha20_poly1305,
        };
    }

    /// Map a `tls12_server` kTLS bundle to an encoded TLS 1.2 kernel
    /// `crypto_info`. `explicit` backs the AES-GCM explicit-nonce field
    /// (= `seq`, the 1.2 engine's nonce discipline) until `encode` returns.
    fn encodeKtls12CryptoInfo(params: tls12_server.Server.KtlsParams, explicit: *[ktls.rec_seq_len]u8, out: []u8) KtlsError![]const u8 {
        const info = try ktls.tls12CryptoInfo(ktls12Cipher(params.cipher), params.fixed_iv, params.key, params.seq, explicit);
        return info.encode(out);
    }

    fn buildKtlsCryptoInfo(self: *const TlsConn, direction: ktls.Direction, out: []u8) KtlsError![]const u8 {
        if (!self.outputBoundaryClean() or self.control_phase != .none or self.tx_ku_reply_pending or self.control_turn_active or
            self.acme_validation != null) return error.KtlsUnsupportedEngine;
        switch (self.engine) {
            .tls13 => |*s| {
                const params = (if (direction == .tx) s.ktlsTxParams() else s.ktlsRxParams()) orelse return error.KtlsUnsupportedEngine;
                return encodeKtlsCryptoInfo(params, out);
            },
            .tls12 => |*s| {
                const params = (if (direction == .tx) s.ktlsTxParams() else s.ktlsRxParams()) orelse return error.KtlsUnsupportedEngine;
                var explicit: [ktls.rec_seq_len]u8 = undefined;
                defer std.crypto.secureZero(u8, &explicit);
                return encodeKtls12CryptoInfo(params, &explicit, out);
            },
            .undecided => return error.KtlsUnsupportedEngine,
        }
    }

    /// Encode this session's server→client TX `crypto_info` into `out` (see
    /// `ktls.CryptoInfo.encode`), ready for `setsockopt(TLS_TX)`. TLS 1.3 and
    /// hardened TLS 1.2 AEAD sessions are supported; returns
    /// `KtlsUnsupportedEngine` before the handshake completes or when the
    /// engine cannot hand the direction over exactly.
    /// Pure (no syscalls): the byte transform half of `enableKtlsTx`.
    pub fn buildKtlsTxCryptoInfo(self: *const TlsConn, out: []u8) KtlsError![]const u8 {
        return self.buildKtlsCryptoInfo(.tx, out);
    }

    /// The client→server RX `crypto_info` (for `setsockopt(TLS_RX)`). Same
    /// constraints as `buildKtlsTxCryptoInfo`.
    pub fn buildKtlsRxCryptoInfo(self: *const TlsConn, out: []u8) KtlsError![]const u8 {
        return self.buildKtlsCryptoInfo(.rx, out);
    }

    /// Attach Linux kTLS TX offload to `fd` for the completed TLS 1.3 session, so
    /// the kernel encrypts subsequent server→client writes. The caller MUST have
    /// drained all userspace-sealed bytes (handshake flight + NewSessionTicket)
    /// from the socket first and the socket must be ESTABLISHED, or the kernel
    /// would encrypt the already-ciphertext tail. Only TLS 1.3 is supported.
    pub fn enableKtlsTx(self: *TlsConn, fd: linux.fd_t) KtlsError!void {
        if (!self.outputBoundaryClean() or self.control_phase != .none or self.tx_ku_reply_pending or self.control_turn_active) return error.KtlsUnsupportedEngine;
        if (comptime builtin.os.tag == .freebsd) {
            if (self.engine == .tls12) {
                const p12 = self.engine.tls12.ktlsTxParams() orelse return error.KtlsUnsupportedEngine;
                kernel_other.enableKernelTls12(
                    @intCast(fd),
                    .tx,
                    freebsdKtlsCipher(p12.cipher),
                    p12.key,
                    p12.fixed_iv,
                    ktls.seqToBytes(p12.seq),
                ) catch return error.KtlsTxUnsupported;
                self.markTxOffloaded();
                return;
            }
            const params = switch (self.engine) {
                .tls13 => |*s| s.ktlsTxParams() orelse return error.KtlsUnsupportedEngine,
                .undecided, .tls12 => return error.KtlsUnsupportedEngine,
            };
            kernel_other.enableKernelTls(
                @intCast(fd),
                .tx,
                freebsdKtlsCipher(params.cipher),
                params.key,
                &params.iv,
                ktls.seqToBytes(params.seq),
            ) catch return error.KtlsTxUnsupported;
            self.markTxOffloaded();
            return;
        }
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const encoded = try self.buildKtlsTxCryptoInfo(&buf);
        try ktls.attachUlp(fd);
        try ktls.attachTx(fd, encoded);
        self.markTxOffloaded();
    }

    /// The kernel now owns the server->client write sequence. Tell the engine
    /// too, so its userspace sealing entry points (`closeNotify`,
    /// `prepareAppWrite`, `encrypt`) fail closed (BadState) instead of reusing
    /// a (key, nonce) pair the kernel already consumed.
    fn markTxOffloaded(self: *TlsConn) void {
        self.ktls_tx_offloaded = true;
        switch (self.engine) {
            .tls13 => |*s| s.markTxOffloaded(),
            .tls12 => |*s| s.markTxOffloaded(),
            .undecided => {},
        }
    }

    /// Attach Linux kTLS RX offload to `fd`, so the kernel decrypts inbound
    /// records and `recv()` returns plaintext. The caller MUST first ensure the
    /// inbound stream is at a clean record boundary (`hasBufferedInbound()` false)
    /// so the kernel takes over from `app_read_seq` with no partial record left in
    /// userspace. Only TLS 1.3 is supported.
    pub fn enableKtlsRx(self: *TlsConn, fd: linux.fd_t) KtlsError!void {
        if (!self.outputBoundaryClean() or self.control_phase != .none or self.tx_ku_reply_pending or self.control_turn_active) return error.KtlsUnsupportedEngine;
        if (self.hasBufferedInbound()) return error.KtlsDirtyInbound;
        if (comptime builtin.os.tag == .freebsd) {
            if (self.engine == .tls12) {
                const p12 = self.engine.tls12.ktlsRxParams() orelse return error.KtlsUnsupportedEngine;
                kernel_other.enableKernelTls12(
                    @intCast(fd),
                    .rx,
                    freebsdKtlsCipher(p12.cipher),
                    p12.key,
                    p12.fixed_iv,
                    ktls.seqToBytes(p12.seq),
                ) catch return error.KtlsRxUnsupported;
                self.ktls_rx_offloaded = true;
                return;
            }
            const params = switch (self.engine) {
                .tls13 => |*s| s.ktlsRxParams() orelse return error.KtlsUnsupportedEngine,
                .undecided, .tls12 => return error.KtlsUnsupportedEngine,
            };
            kernel_other.enableKernelTls(
                @intCast(fd),
                .rx,
                freebsdKtlsCipher(params.cipher),
                params.key,
                &params.iv,
                ktls.seqToBytes(params.seq),
            ) catch return error.KtlsRxUnsupported;
            self.ktls_rx_offloaded = true;
            return;
        }
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const encoded = try self.buildKtlsRxCryptoInfo(&buf);
        try ktls.attachUlp(fd);
        try ktls.attachRx(fd, encoded);
        self.ktls_rx_offloaded = true;
    }

    /// Continuity after a peer KeyUpdate on an RX-offloaded TLS 1.3 conn: advance
    /// the client→server (RX) key in the engine and RE-INSTALL it on the kernel via
    /// a second `setsockopt(TLS_RX)` at record seq 0, so the kernel can decrypt the
    /// client's post-KeyUpdate records (which are under the client's rotated send
    /// key). The engine's TX secret/state is untouched; only the RX direction moves.
    ///
    /// Fail-safe: the kernel TLS_RX swap is atomic — on any error the previous RX
    /// key stays installed (never a half-installed state) and the caller falls back
    /// to a clean close. The engine's `client_app_secret` is advanced BEFORE the
    /// syscall so that a subsequent Helix `exportResume` carries the correct
    /// (advanced) secret; on a failed re-install the conn is closed anyway, so the
    /// engine⇄kernel divergence is moot (the conn never survives to be carried).
    /// Only TLS 1.3 is supported. The error set widens to include the engine's
    /// `Error` because advancing the traffic secret runs the HKDF derivation; the
    /// sole caller closes the conn on any error, so every failure is fail-safe.
    pub fn rekeyKtlsRx(self: *TlsConn, fd: linux.fd_t) (KtlsError || Error)!void {
        if (!self.outputBoundaryClean() or self.hasPreparedWrite()) return error.BadState;
        const engine = switch (self.engine) {
            .tls13 => |*value| value,
            else => return error.KtlsUnsupportedEngine,
        };
        var prepared = try engine.prepareKernelKeyUpdate(.rx);
        defer prepared.deinit();
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const encoded = try encodeKtlsCryptoInfo(prepared.params(), &buf);
        try ktls.attachRx(fd, encoded);
        prepared.commit();
    }

    pub const KernelReadResult = union(enum) {
        progress,
        application: []u8,
        key_update: struct { requested: bool, software_reply: ?[]u8 },
    };

    fn engine13(self: *TlsConn) Error!*tls_server.Server {
        return switch (self.engine) {
            .tls13 => |*engine| engine,
            else => error.BadState,
        };
    }

    /// Preserve actual next sequence while releasing the kernel's KU pause.
    /// This is identical-key continuation, never semantic HKDF/rekey.
    fn continueKernelRx(self: *TlsConn, fd: i32) (KtlsError || Error || ktls.ControlError)!void {
        const engine = try self.engine13();
        const params = engine.ktlsRxParams() orelse return error.KtlsUnsupportedEngine;
        var expected: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected);
        const encoded = try encodeKtlsCryptoInfo(params, &expected);
        const cipher: ktls.Cipher = switch (params.cipher) {
            .aes_128_gcm => .aes_gcm_128,
            .aes_256_gcm => .aes_gcm_256,
            .chacha20_poly1305 => .chacha20_poly1305,
        };
        var actual = try ktls.getTuple(fd, .rx, cipher);
        defer actual.wipe();
        try actual.validateEpoch(encoded);
        try ktls.attachRx(fd, actual.encoded());
        engine.app_read_seq = actual.sequence();
    }

    pub fn kernelApplicationAllowed(self: *const TlsConn) bool {
        if (self.terminal_error != null or self.rx_open_control_type != 0 or self.alert_prefix_len != 0 or self.control_phase == .kernel_control_read_held) return false;
        return switch (self.engine) {
            .tls13 => |engine| engine.post_handshake_recv_len == 0,
            // TLS 1.2 has no post-handshake messages in this profile.
            .tls12 => true,
            .undecided => false,
        };
    }

    /// All fallible reply/epoch preparation precedes recvmsg. A consumed final
    /// control is followed only by kernel install and allocation-free custody.
    /// The caller has reserved27 software or5 kernel reply bytes BEFORE entry.
    pub fn readKernelControl(self: *TlsConn, fd: i32, buf: []u8) (Error || KtlsError || ktls.ControlError || ktls.RecvError)!KernelReadResult {
        var consumed = false;
        return self.readKernelControlCandidate(fd, buf, &consumed) catch |err| {
            if (consumed) {
                self.terminal_error = err;
                switch (self.engine) {
                    .tls13 => |*engine| engine.read_failed = true,
                    .tls12 => |*engine| engine.read_failed = true,
                    .undecided => {},
                }
                if (err == error.TlsAlert) self.discardTerminalOutput();
            }
            return err;
        };
    }

    fn readKernelControlCandidate(self: *TlsConn, fd: i32, buf: []u8, consumed: *bool) (Error || KtlsError || ktls.ControlError || ktls.RecvError)!KernelReadResult {
        if (!self.ktls_rx_offloaded or self.terminal_error != null or self.control_turn_active or
            self.hasPreparedWrite() or self.tx_ku_reply_pending) return error.BadState;
        if (self.engine == .tls12) return self.readKernelControl12(fd, buf, consumed);
        const engine = try self.engine13();
        var rx_key = try engine.prepareKernelKeyUpdate(.rx);
        defer rx_key.deinit();
        var reply: ?tls_server.Server.PreparedKeyUpdateReply = null;
        if (!self.ktls_tx_offloaded) reply = try engine.prepareKeyUpdateReply();
        defer if (reply) |*prepared| prepared.deinit();
        self.control_turn_active = true;
        defer self.control_turn_active = false;
        const rr = ktls.recvmsgRecordType(fd, buf, linux.MSG.DONTWAIT) catch |err| {
            if (err == error.NeedsRekey and engine.post_handshake_recv_len != 0 and self.rx_open_control_type == 0) {
                consumed.* = true;
                try self.continueKernelRx(fd);
                return .progress;
            }
            return err;
        };
        consumed.* = true;
        if (self.rx_open_control_type != 0 and self.rx_open_control_type != rr.record_type) return error.BadHandshake;
        switch (rr.record_type) {
            23 => {
                if (engine.post_handshake_recv_len != 0 or self.rx_open_control_type != 0 or self.alert_prefix_len != 0) return error.BadHandshake;
                return .{ .application = rr.plaintext };
            },
            21 => {
                const total = @as(usize, self.alert_prefix_len) + rr.plaintext.len;
                if (total > 2 or (rr.end_of_record and total != 2) or (!rr.end_of_record and total >= 2)) return error.BadRecord;
                var bytes: [2]u8 = @splat(0);
                if (self.alert_prefix_len != 0) bytes[0] = self.alert_prefix_byte;
                @memcpy(bytes[self.alert_prefix_len..][0..rr.plaintext.len], rr.plaintext);
                if (!rr.end_of_record) {
                    self.rx_open_control_type = 21;
                    self.alert_prefix_len = @intCast(total);
                    self.alert_prefix_byte = if (total != 0) bytes[0] else 0;
                    return .progress;
                }
                // Record the kernel-delivered alert like the userspace path, so
                // a peer close_notify is classified as a clean end of input.
                engine.peer_alert = @import("../proto/tls_alert.zig").parse(&bytes) catch return error.BadRecord;
                self.terminal_error = error.TlsAlert;
                engine.read_failed = true;
                self.discardTerminalOutput();
                return error.TlsAlert;
            },
            22 => {
                if (!rr.metadata_present or rr.plaintext.len == 0) return error.BadHandshake;
                const total = @as(usize, engine.post_handshake_recv_len) + rr.plaintext.len;
                if (total > 5 or (total == 5 and !rr.end_of_record)) return error.BadHandshake;
                var candidate: [5]u8 = @splat(0);
                @memcpy(candidate[0..engine.post_handshake_recv_len], engine.post_handshake_recv[0..engine.post_handshake_recv_len]);
                @memcpy(candidate[engine.post_handshake_recv_len..][0..rr.plaintext.len], rr.plaintext);
                const header = [_]u8{ 24, 0, 0, 1 };
                if (!std.mem.eql(u8, candidate[0..@min(total, 4)], header[0..@min(total, 4)])) return error.BadHandshake;
                if (total < 5) {
                    engine.post_handshake_recv = candidate;
                    engine.post_handshake_recv_len = @intCast(total);
                    self.rx_open_control_type = if (rr.end_of_record) 0 else 22;
                    if (rr.end_of_record) try self.continueKernelRx(fd);
                    return .progress;
                }
                if (candidate[4] > 1) return error.BadHandshake;
                var encoded_buf: [ktls.max_crypto_info_len]u8 = undefined;
                defer std.crypto.secureZero(u8, &encoded_buf);
                const encoded = try encodeKtlsCryptoInfo(rx_key.params(), &encoded_buf);
                try ktls.attachRx(fd, encoded);
                rx_key.commit();
                self.rx_open_control_type = 0;
                const requested = candidate[4] == 1;
                var software: ?[]u8 = null;
                if (requested) {
                    if (self.ktls_tx_offloaded) {
                        self.tx_ku_reply_pending = true;
                        self.tx_ku_reply_sent = 0;
                    } else {
                        reply.?.commit();
                        software = reply.?.takeBytes();
                    }
                }
                return .{ .key_update = .{ .requested = requested, .software_reply = software } };
            },
            else => return error.BadRecord,
        }
    }

    /// Kernel RX demux for an offloaded TLS 1.2 session. The kernel already
    /// authenticated the record (and accepts only record version 0x0303).
    /// application_data is data; an alert (possibly split across records) is
    /// terminal; any handshake record is a renegotiation attempt, which this
    /// profile refuses (RFC 5746 §4.4 permits refusing; the hardened 1.2
    /// engine never renegotiates), so the connection closes fatally. TLS 1.2
    /// never enters the TLS 1.3 KeyUpdate paths.
    fn readKernelControl12(self: *TlsConn, fd: i32, buf: []u8, consumed: *bool) (Error || KtlsError || ktls.ControlError || ktls.RecvError)!KernelReadResult {
        const engine = &self.engine.tls12;
        self.control_turn_active = true;
        defer self.control_turn_active = false;
        const rr = try ktls.recvmsgRecordType(fd, buf, linux.MSG.DONTWAIT);
        consumed.* = true;
        if (self.rx_open_control_type != 0 and self.rx_open_control_type != rr.record_type) return error.BadRecord;
        switch (rr.record_type) {
            23 => {
                if (self.rx_open_control_type != 0 or self.alert_prefix_len != 0) return error.BadRecord;
                return .{ .application = rr.plaintext };
            },
            21 => {
                const total = @as(usize, self.alert_prefix_len) + rr.plaintext.len;
                if (total > 2 or (rr.end_of_record and total != 2) or (!rr.end_of_record and total >= 2)) return error.BadRecord;
                var bytes: [2]u8 = @splat(0);
                if (self.alert_prefix_len != 0) bytes[0] = self.alert_prefix_byte;
                @memcpy(bytes[self.alert_prefix_len..][0..rr.plaintext.len], rr.plaintext);
                if (!rr.end_of_record) {
                    self.rx_open_control_type = 21;
                    self.alert_prefix_len = @intCast(total);
                    self.alert_prefix_byte = if (total != 0) bytes[0] else 0;
                    return .progress;
                }
                // Record the kernel-delivered alert like the userspace path, so
                // a peer close_notify is classified as a clean end of input.
                engine.peer_alert = @import("../proto/tls_alert.zig").parse(&bytes) catch return error.BadRecord;
                self.terminal_error = error.TlsAlert;
                engine.read_failed = true;
                self.discardTerminalOutput();
                return error.TlsAlert;
            },
            22 => return error.BadHandshake,
            else => return error.BadRecord,
        }
    }

    pub const KernelReplyProgress = struct { accepted: usize, completed: bool };

    /// Each accepted typed fragment advances the carried offset exactly once.
    /// New TX keys are installed only after the complete old-key KU reached EOR.
    pub fn progressKernelReply(self: *TlsConn, fd: i32, fragment_budget: usize) (Error || KtlsError || ktls.ControlError)!KernelReplyProgress {
        if (!self.ktls_tx_offloaded or !self.tx_ku_reply_pending or self.tx_ku_reply_sent > 4 or
            self.terminal_error != null or self.hasPreparedWrite() or self.control_turn_active or fragment_budget == 0) return error.BadState;
        const engine = try self.engine13();
        const current = self.kernelSequence(fd, .tx) catch |err| {
            // An admitted reply obligation cannot recover by guessing the
            // kernel epoch after its full getter fails, even before byte one.
            self.terminal_error = err;
            return err;
        };
        engine.app_write_seq = current;
        var prepared = try engine.prepareKernelKeyUpdate(.tx);
        defer prepared.deinit();
        self.control_turn_active = true;
        defer self.control_turn_active = false;
        const body = [_]u8{ 24, 0, 0, 1, 0 };
        const len = @min(fragment_budget, 5 - @as(usize, self.tx_ku_reply_sent));
        const accepted = ktls.sendControl(fd, .handshake, body[self.tx_ku_reply_sent..][0..len]) catch |err| {
            if (err == error.WouldBlock) return .{ .accepted = 0, .completed = false };
            self.terminal_error = err;
            return err;
        };
        const sent = @as(usize, self.tx_ku_reply_sent) + accepted;
        if (sent != 5) {
            self.tx_ku_reply_sent = @intCast(sent);
            engine.app_write_seq = self.kernelSequence(fd, .tx) catch |err| {
                self.terminal_error = err;
                return err;
            };
            return .{ .accepted = accepted, .completed = false };
        }
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const encoded = try encodeKtlsCryptoInfo(prepared.params(), &buf);
        if (comptime builtin.is_test) if (self.test_after_kernel_reply) |hook| hook.call(hook.ctx, fd);
        ktls.attachTx(fd, encoded) catch |err| {
            self.terminal_error = err;
            return err;
        };
        prepared.commit();
        self.tx_ku_reply_pending = false;
        self.tx_ku_reply_sent = 0;
        return .{ .accepted = accepted, .completed = true };
    }

    /// Server-initiated KeyUpdate on a TX-offloaded connection. The daemon
    /// never initiates one today (only peer-requested replies rotate TX), but
    /// the adapter supports it with the same custody as `progressKernelReply`:
    /// the 5-byte KeyUpdate is sent under the OLD kernel epoch, the rotated
    /// epoch is installed at sequence 0, and only then is the engine secret
    /// committed. The caller must invoke this only with the send queue drained
    /// (the same precondition as TX attach), so no earlier plaintext record can
    /// overtake or follow the KeyUpdate under the wrong epoch. If the socket
    /// would block before byte one, nothing is sent and no state changes; the
    /// caller may retry after draining.
    pub fn initiateKernelKeyUpdate(self: *TlsConn, fd: i32, request_peer: bool) (Error || KtlsError || ktls.ControlError)!void {
        if (!self.ktls_tx_offloaded or self.tx_ku_reply_pending or self.terminal_error != null or
            self.hasPreparedWrite() or self.control_turn_active) return error.BadState;
        const engine = try self.engine13();
        engine.app_write_seq = self.kernelSequence(fd, .tx) catch |err| {
            self.terminal_error = err;
            return err;
        };
        var prepared = try engine.prepareKernelKeyUpdate(.tx);
        defer prepared.deinit();
        self.control_turn_active = true;
        defer self.control_turn_active = false;
        const body = [_]u8{ 24, 0, 0, 1, if (request_peer) 1 else 0 };
        var sent: usize = 0;
        var blocked_retries: usize = 0;
        while (sent < body.len) {
            const accepted = ktls.sendControl(fd, .handshake, body[sent..]) catch |err| {
                if (err == error.WouldBlock and sent == 0) return error.WouldBlock;
                if (err == error.WouldBlock) {
                    // A partial KeyUpdate already reached the peer, so the new
                    // epoch must be installed or the connection is terminal.
                    blocked_retries += 1;
                    if (blocked_retries > 1024) {
                        self.terminal_error = error.WouldBlock;
                        return error.WouldBlock;
                    }
                    continue;
                }
                self.terminal_error = err;
                return err;
            };
            if (accepted == 0) return error.WouldBlock;
            sent += accepted;
        }
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        const encoded = try encodeKtlsCryptoInfo(prepared.params(), &buf);
        ktls.attachTx(fd, encoded) catch |err| {
            self.terminal_error = err;
            return err;
        };
        prepared.commit();
    }

    fn freebsdKtlsCipher(cipher: tls_server.Server.KtlsCipher) i32 {
        return switch (cipher) {
            .aes_128_gcm, .aes_256_gcm => kernel_other.crypto_aes_nist_gcm_16,
            .chacha20_poly1305 => kernel_other.crypto_chacha20_poly1305,
        };
    }

    /// True when a partial inbound TLS record is buffered (an incomplete record
    /// awaiting more socket bytes). kTLS RX offload must NOT attach while this is
    /// true — the kernel would resume mid-record and desync.
    pub fn hasBufferedInbound(self: *const TlsConn) bool {
        return self.recv_buf.items.len != 0;
    }

    pub fn hasCompleteBufferedInbound(self: *const TlsConn) bool {
        if (self.ktls_rx_offloaded or !self.handshakeDone() or self.terminal_error != null) return false;
        return (completeRecordLen(self.recv_buf.items) catch return true) != null;
    }

    /// The negotiated protocol version, or null before the engine is chosen.
    pub fn negotiatedVersion(self: *const TlsConn) ?Version {
        return switch (self.engine) {
            .undecided => null,
            .tls13 => .tls13,
            .tls12 => .tls12,
        };
    }

    pub fn selectedAlpn(self: *const TlsConn) ?[]const u8 {
        return switch (self.engine) {
            .undecided => null,
            .tls13 => |*s| s.selectedAlpn(),
            .tls12 => |*s| s.selectedAlpn(),
        };
    }

    /// IANA name of the negotiated cipher suite (e.g. "TLS_AES_128_GCM_SHA256"),
    /// or null until the chosen engine has selected one. The returned string is
    /// static — safe to hold for the connection's lifetime (WHOIS 671).
    pub fn cipherName(self: *const TlsConn) ?[]const u8 {
        return switch (self.engine) {
            .undecided => null,
            .tls13 => |*s| s.cipherName(),
            .tls12 => |*s| s.cipherName(),
        };
    }

    /// The verified client leaf DER (mTLS), or null. Both the TLS 1.3 and the
    /// hardened TLS 1.2 engines capture the client leaf once its CertificateVerify
    /// possession proof verifies; resumed handshakes never carry a client cert.
    pub fn clientCertDer(self: *const TlsConn) ?[]const u8 {
        return switch (self.engine) {
            .tls13 => |*s| s.clientCertDer(),
            .tls12 => |*s| s.clientCertDer(),
            .undecided => null,
        };
    }

    /// RFC 9266 tls-exporter channel-binding value for TLS 1.3 connections.
    /// TLS 1.2 does not implement this clean-room exporter path, so callers
    /// treat error.BadState as "not available" and keep PLUS mechanisms gated.
    pub fn channelBindingTlsExporter(self: *const TlsConn, out: *[32]u8) Error!void {
        if (!self.outputBoundaryClean()) return error.BadState;
        return switch (self.engine) {
            .tls13 => |*s| s.channelBindingTlsExporter(out),
            // RFC 9266 §2: tls-exporter is defined for TLS 1.2 only when the
            // master secret is unique, i.e. with the RFC 7627 extended master
            // secret; the 1.2 engine's exporter refuses (BadState) otherwise.
            .tls12 => |*s| s.channelBindingTlsExporter(out),
            .undecided => error.BadState,
        };
    }

    /// Drive the connection with a chunk of bytes read from the socket. On the
    /// first call it selects the protocol version from the buffered ClientHello,
    /// then drives the chosen engine.
    pub fn onInbound(self: *TlsConn, socket_bytes: []const u8) Error!Outcome {
        if (self.hasPreparedWrite()) return error.BadState;
        if (self.terminal_error != null) return error.BadState;
        return self.onInboundWithControlCustody(socket_bytes, true);
    }

    pub fn onInboundWithControlCustody(self: *TlsConn, socket_bytes: []const u8, allow_requested: bool) Error!Outcome {
        if (self.hasPreparedWrite() or self.control_turn_active or self.ktls_rx_offloaded or self.terminal_error != null) return error.BadState;
        const outcome = self.onInboundCandidate(socket_bytes, allow_requested) catch |err| {
            self.terminal_error = err;
            self.plain_buf.clearRetainingCapacity();
            if (err == error.TlsAlert) self.discardTerminalOutput();
            return err;
        };
        self.releaseCompletedOcsp();
        return outcome;
    }

    fn releaseCompletedOcsp(self: *TlsConn) void {
        if (!self.handshakeDone()) return;
        const borrowed12 = if (self.cfg12) |cfg| cfg.ocsp_staple.len != 0 else false;
        if (self.cfg13.ocsp_staple.len == 0 and !borrowed12 and
            self.ocsp_owned13 == null and self.ocsp_owned12 == null) return;
        // Certificate and CertificateStatus have already been encoded into
        // owned handshake output. TLS renegotiation is disabled; connected
        // engines never read these config slices again.
        self.cfg13.ocsp_staple = &.{};
        if (self.cfg12) |*cfg| cfg.ocsp_staple = &.{};
        switch (self.engine) {
            .undecided => unreachable,
            .tls13 => |*engine| engine.config.ocsp_staple = &.{},
            .tls12 => |*engine| engine.config.ocsp_staple = &.{},
        }
        if (self.ocsp_owned12) |bytes| self.allocator.free(bytes);
        if (self.ocsp_owned13) |bytes| self.allocator.free(bytes);
        self.ocsp_owned12 = null;
        self.ocsp_owned13 = null;
    }

    fn onInboundCandidate(self: *TlsConn, socket_bytes: []const u8, allow_requested: bool) Error!Outcome {
        self.send_buf.clearRetainingCapacity();
        self.plain_buf.clearRetainingCapacity();
        try self.recv_buf.appendSlice(self.allocator, socket_bytes);

        // A TLS 1.3-only adapter builds its engine before any input; it has
        // consumed nothing yet, so a tls-alpn-01 hit on the first complete
        // record can still swap in the challenge-certificate engine.
        if (!self.acme_checked and self.acme_store != null and self.engine == .tls13 and
            try completeRecordLen(self.recv_buf.items) != null)
        {
            try self.selectAcmeValidation();
            if (self.acme_validation) |validation| {
                const replacement = try tls_server.Server.init(self.allocator, acmeConfig13(self.cfg13, validation));
                self.engine.tls13.deinit();
                self.engine = .{ .tls13 = replacement };
            }
        }
        if (std.meta.activeTag(self.engine) == .undecided) {
            const detected = try self.detectVersion();
            if (detected != .need_more) try self.selectAcmeValidation();
            switch (detected) {
                .need_more => return .{ .handshake_bytes = &.{}, .plaintext = &.{} },
                .tls13 => {
                    const cfg = if (self.acme_validation) |validation| acmeConfig13(self.cfg13, validation) else self.cfg13;
                    const s13 = try tls_server.Server.init(self.allocator, cfg);
                    self.engine = .{ .tls13 = s13 };
                },
                .tls12 => {
                    const c12 = self.cfg12 orelse return error.ProtocolVersion;
                    const cfg = if (self.acme_validation) |validation| acmeConfig12(c12, validation) else c12;
                    const s12 = try tls12_server.Server.init(self.allocator, cfg);
                    self.engine = .{ .tls12 = s12 };
                },
            }
        }

        // Previously sealed engine output has its own epoch and custody. Publish
        // it before admitting another record; the just-buffered input remains
        // owned for the next turn. In particular, an NST is not a newly admitted
        // requested-KU reply, and an already retained reply must not be replaced.
        try self.collectPendingOutput();
        if (self.unpublished.items.len != 0) {
            try self.publishOutput();
            return .{ .handshake_bytes = self.send_buf.items, .plaintext = &.{} };
        }

        // Requested software replies have a fixed owned publication slot before
        // authentication/admission. No transfer/flatten allocation follows the
        // RX/TX epoch cut. The caller reserves exact physical queue custody too.
        var control_reply = false;
        // Walk records with a cursor and compact once. Shifting the remaining
        // stream after every record turns an attacker-controlled flight of tiny
        // records into quadratic copying.
        var consumed_len: usize = 0;
        defer if (consumed_len != 0) consumePrefix(&self.recv_buf, consumed_len);
        while (try completeRecordLen(self.recv_buf.items[consumed_len..])) |wire_len| {
            const record = self.recv_buf.items[consumed_len .. consumed_len + wire_len];
            const connected = self.handshakeDone();
            // A flight accumulated earlier in this call must reach the caller
            // before a requested reply can advance the TX epoch. Retain the
            // exact authenticated request when that earlier output is pending.
            const admit_requested = allow_requested and self.unpublished.items.len == 0;
            const reserve_software_reply = connected and admit_requested and !self.ktls_tx_offloaded and self.engine == .tls13;
            if (reserve_software_reply) try self.send_buf.ensureTotalCapacity(self.allocator, 27);
            if (connected) {
                if (!try self.decryptRecord(record, admit_requested)) {
                    self.control_phase = .userspace_requested_ku_held;
                    self.held_record_len = @intCast(wire_len);
                    break;
                }
                if (self.control_phase == .userspace_requested_ku_held) {
                    self.control_phase = .none;
                    self.held_record_len = 0;
                }
            } else {
                try self.feedRecord(record);
            }
            consumed_len += wire_len;
            if (reserve_software_reply and self.engine.tls13.post_handshake_send.items.len != 0) {
                const pending = self.engine.tls13.post_handshake_send.items;
                std.debug.assert(pending.len == 27 and self.unpublished.items.len == 0);
                self.send_buf.items.len = pending.len;
                @memcpy(self.send_buf.items, pending);
                self.engine.tls13.post_handshake_send.clearRetainingCapacity();
                control_reply = true;
                break;
            }
            try self.collectPendingOutput();
            if (self.tx_ku_reply_pending) break;
        }

        // A post-handshake KeyUpdate (TLS 1.3 only) makes the inner server queue
        // a reply; send it back alongside any handshake flight.
        if (!control_reply) {
            try self.collectPendingOutput();
            try self.publishOutput();
        }
        return .{ .handshake_bytes = self.send_buf.items, .plaintext = self.plain_buf.items, .control_reply = control_reply };
    }

    /// Retained unpublished output and a fatal TLS alert for the error `err` before
    /// closing (RFC 8446 §6). Each engine picks the correct encoding for its
    /// state: the TLS 1.3 engine emits a plaintext alert before its ServerHello
    /// and an encrypted one (under the active write keys) afterward; the TLS 1.2
    /// engine emits plaintext before it sends its ChangeCipherSpec and encrypted
    /// after. An `undecided` engine (version-detect / init failure) has sent
    /// nothing, so a plaintext alert is correct. Either engine returns null for a
    /// state where no alert is warranted (bare close). Caller owns the buffer.
    pub fn takeAlert(self: *TlsConn, err: anyerror) ?[]u8 {
        if (self.hasPreparedWrite() or self.terminal_output_taken) return null;
        if (self.terminal_error == null) self.terminal_error = err;
        const failure = self.terminal_error.?;
        if (failure == error.TlsAlert) {
            self.discardTerminalOutput();
            self.terminal_output_taken = true;
            return null;
        }
        // A raw software ciphertext alert would be encrypted a second time by
        // TX kTLS. Kernel control-record emission requires its own caller path.
        if (self.ktls_tx_offloaded) return null;
        // Drain old-key control bytes before sealing a terminal suffix. Both
        // transfers have a reserved owned slot before the engine can mutate.
        if (!self.terminal_alert_attempted) {
            self.collectPendingOutput() catch return null;
            self.unpublished.ensureUnusedCapacity(self.allocator, 1) catch return null;
            const alert = switch (self.engine) {
                .tls13 => |*s| s.takeAlert(failure),
                .undecided => tls_server.alertRecordForError(self.allocator, failure),
                .tls12 => |*s| s.takeAlert(failure),
            };
            if (alert) |owned| self.unpublished.appendAssumeCapacity(owned);
            self.terminal_alert_attempted = true;
        }
        const total = self.unpublishedByteLen() catch return null;
        if (total == 0) {
            self.discardUnpublished();
            self.terminal_output_taken = true;
            return null;
        }
        const owned = self.allocator.alloc(u8, total) catch return null;
        self.copyUnpublished(owned);
        self.discardUnpublished();
        self.terminal_output_taken = true;
        return owned;
    }

    fn outputBoundaryClean(self: *const TlsConn) bool {
        return self.terminal_error == null and self.unpublished.items.len == 0;
    }

    fn discardUnpublished(self: *TlsConn) void {
        for (self.unpublished.items) |owned| self.allocator.free(owned);
        self.unpublished.clearRetainingCapacity();
    }

    fn discardTerminalOutput(self: *TlsConn) void {
        self.discardUnpublished();
        switch (self.engine) {
            .tls13 => |*s| {
                if (s.failed_flight) |flight| self.allocator.free(flight);
                s.failed_flight = null;
                s.post_handshake_send.clearRetainingCapacity();
            },
            else => {},
        }
    }

    fn unpublishedByteLen(self: *const TlsConn) Error!usize {
        var total: usize = 0;
        for (self.unpublished.items) |owned| total = std.math.add(usize, total, owned.len) catch return error.InputTooLarge;
        return total;
    }

    fn copyUnpublished(self: *const TlsConn, out: []u8) void {
        var at: usize = 0;
        for (self.unpublished.items) |owned| {
            @memcpy(out[at..][0..owned.len], owned);
            at += owned.len;
        }
        std.debug.assert(at == out.len);
    }

    fn publishOutput(self: *TlsConn) Error!void {
        // The checked sum is bounded by the exact owned output of accepted
        // records, not an additional cap on valid caller input batches.
        const total = try self.unpublishedByteLen();
        try self.send_buf.ensureTotalCapacity(self.allocator, total);
        self.send_buf.items.len = total;
        self.copyUnpublished(self.send_buf.items);
        self.discardUnpublished();
    }

    fn collectPendingOutput(self: *TlsConn) Error!void {
        switch (self.engine) {
            .tls13 => |*s| {
                if (s.post_handshake_send.items.len == 0 and s.failed_flight == null) return;
                try self.unpublished.ensureUnusedCapacity(self.allocator, 1);
                if (try s.takePendingSend()) |owned| self.unpublished.appendAssumeCapacity(owned);
            },
            else => {},
        }
    }

    /// Adapter-level resume state for a Helix live upgrade: the chosen engine's
    /// connected-state snapshot plus any buffered partial inbound record. The
    /// `pending_recv` slice borrows this TlsConn's internal buffer — serialize it
    /// before driving the connection again.
    pub const ResumeState = struct {
        engine: EngineState,
        /// Bytes of a partially received TLS record buffered at export time.
        pending_recv: []const u8 = &.{},
        rx_open_control_type: u8 = 0,
        alert_prefix_len: u1 = 0,
        alert_prefix_byte: u8 = 0,
        tx_ku_reply_pending: bool = false,
        tx_ku_reply_sent: u3 = 0,
        barrier_phase: ControlBarrierPhase,
        held_record_len: u32,

        pub const EngineState = union(Version) {
            tls12: tls12_server.Server.ResumeState,
            tls13: tls_server.Server.ResumeState,
        };
    };

    /// Capture this connection's live TLS state for a Helix upgrade handoff.
    /// Only valid once the handshake completed (`error.BadState` otherwise —
    /// mid-handshake connections are not resumable and must reconnect).
    fn resumeState(self: *const TlsConn, engine: ResumeState.EngineState) ResumeState {
        return .{ .engine = engine, .pending_recv = self.recv_buf.items, .rx_open_control_type = self.rx_open_control_type, .alert_prefix_len = self.alert_prefix_len, .alert_prefix_byte = self.alert_prefix_byte, .tx_ku_reply_pending = self.tx_ku_reply_pending, .tx_ku_reply_sent = self.tx_ku_reply_sent, .barrier_phase = self.control_phase, .held_record_len = self.held_record_len };
    }

    pub fn exportResume(self: *const TlsConn) Error!ResumeState {
        if (!self.outputBoundaryClean() or self.control_turn_active or self.ktls_tx_offloaded or self.ktls_rx_offloaded) return error.BadState;
        if (!self.handshakeDone()) return error.BadState;
        return self.resumeState(switch (self.engine) {
            .tls13 => |*s| .{ .tls13 = try s.exportResume() },
            .tls12 => |*s| .{ .tls12 = try s.exportResume() },
            .undecided => return error.BadState,
        });
    }

    pub const CaptureInput = struct {
        fd: i32,
        tx_offloaded: bool,
        rx_offloaded: bool,
        wire_chunks: []const []const u8,
        deferred_plain: []const u8,
        deferred_ciphertext_charge: u64,
        control_charge: u32,
        queue_cap: usize,
        kernel_tx_prefix_remaining: u64,
    };

    pub const PreparedCapture = struct {
        allocator: Allocator,
        state: ResumeState,
        pending_out: []u8,
        kernel_tx_prefix_remaining: u64,

        pub fn deinit(self: *PreparedCapture) void {
            std.crypto.secureZero(u8, self.pending_out);
            self.allocator.free(self.pending_out);
            switch (self.state.engine) {
                .tls13 => |*rs| {
                    std.crypto.secureZero(u8, &rs.client_app_secret);
                    std.crypto.secureZero(u8, &rs.server_app_secret);
                    std.crypto.secureZero(u8, &rs.exporter_master_secret);
                },
                .tls12 => |*rs| rs.keys.wipe(),
            }
        }
    };

    /// Freeze caller FIFO plus ONLY unexposed engine/ledger bytes. No output
    /// transfer, offset movement or counter mutation occurs during preparation.
    pub fn prepareCapture(self: *const TlsConn, allocator: Allocator, input: CaptureInput) (Error || KtlsError || ktls.ControlError)!PreparedCapture {
        if (self.terminal_error != null or self.hasPreparedWrite() or self.control_turn_active or !self.handshakeDone() or
            input.tx_offloaded != self.ktls_tx_offloaded or input.rx_offloaded != self.ktls_rx_offloaded) return error.BadState;
        var engine_pending: []const u8 = &.{};
        var state = self.resumeState(switch (self.engine) {
            .tls13 => |*engine| blk: {
                const view = try engine.captureWithPending();
                engine_pending = view.pending_send;
                break :blk .{ .tls13 = view.state };
            },
            .tls12 => |*engine| .{ .tls12 = try engine.exportResume() },
            .undecided => return error.BadState,
        });
        // The returned candidate owns its copied secrets. The temporary view
        // is wiped on every exit, including getter/validation/allocation faults.
        defer switch (state.engine) {
            .tls13 => |*rs| {
                std.crypto.secureZero(u8, &rs.client_app_secret);
                std.crypto.secureZero(u8, &rs.server_app_secret);
                std.crypto.secureZero(u8, &rs.exporter_master_secret);
            },
            .tls12 => |*rs| rs.keys.wipe(),
        };
        if ((input.tx_offloaded and (engine_pending.len != 0 or self.unpublished.items.len != 0)) or
            (input.rx_offloaded and state.pending_recv.len != 0)) return error.BadState;
        try validateKernelRxControlPhase(input.rx_offloaded, state.barrier_phase, if (state.engine == .tls13) state.engine.tls13.ku_prefix_len else 0, state.rx_open_control_type, state.alert_prefix_len);
        // Once the kernel owns a direction the engine's sequence is stale: the
        // successor must continue from the kernel's next record sequence.
        switch (state.engine) {
            .tls13 => |*rs| {
                if (input.tx_offloaded) rs.app_write_seq = try self.kernelSequence(input.fd, .tx);
                if (input.rx_offloaded) rs.app_read_seq = try self.kernelSequence(input.fd, .rx);
            },
            .tls12 => |*rs| {
                if (state.tx_ku_reply_pending or state.barrier_phase == .userspace_requested_ku_held) return error.BadState;
                if (input.tx_offloaded) rs.app_write_seq = try self.kernelSequence(input.fd, .tx);
                if (input.rx_offloaded) rs.app_read_seq = try self.kernelSequence(input.fd, .rx);
            },
        }
        if (try deferredCiphertextCharge(state.engine, input.deferred_plain) != input.deferred_ciphertext_charge) return error.InvalidDeferred;
        var total: usize = engine_pending.len;
        for (input.wire_chunks) |piece| total = std.math.add(usize, total, piece.len) catch return error.PlaintextTooLong;
        for (self.unpublished.items) |piece| total = std.math.add(usize, total, piece.len) catch return error.PlaintextTooLong;
        try validateKernelTxPrefix(input.tx_offloaded, state.barrier_phase, state.tx_ku_reply_pending, input.control_charge, input.kernel_tx_prefix_remaining, total);
        const charged = std.math.add(u64, std.math.add(u64, total, input.deferred_ciphertext_charge) catch return error.PlaintextTooLong, input.control_charge) catch return error.PlaintextTooLong;
        if (charged > input.queue_cap) return error.PlaintextTooLong;
        const owned = try allocator.alloc(u8, total);
        var offset: usize = 0;
        for (input.wire_chunks) |piece| {
            @memcpy(owned[offset..][0..piece.len], piece);
            offset += piece.len;
        }
        for (self.unpublished.items) |piece| {
            @memcpy(owned[offset..][0..piece.len], piece);
            offset += piece.len;
        }
        @memcpy(owned[offset..][0..engine_pending.len], engine_pending);
        return .{ .allocator = allocator, .state = state, .pending_out = owned, .kernel_tx_prefix_remaining = input.kernel_tx_prefix_remaining };
    }

    fn kernelSequence(self: *const TlsConn, fd: i32, direction: ktls.Direction) (KtlsError || ktls.ControlError)!u64 {
        if (comptime builtin.os.tag != .linux) return error.Unsupported;
        const engine = switch (self.engine) {
            .tls13 => |*value| value,
            .tls12 => |*value| return kernelSequence12(value, fd, direction),
            .undecided => return error.KtlsUnsupportedEngine,
        };
        const params = (if (direction == .tx) engine.ktlsTxParams() else engine.ktlsRxParams()) orelse return error.KtlsUnsupportedEngine;
        var expected: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected);
        const encoded = try encodeKtlsCryptoInfo(params, &expected);
        const cipher: ktls.Cipher = switch (params.cipher) {
            .aes_128_gcm => .aes_gcm_128,
            .aes_256_gcm => .aes_gcm_256,
            .chacha20_poly1305 => .chacha20_poly1305,
        };
        var actual = try ktls.getTuple(fd, direction, cipher);
        defer actual.wipe();
        try actual.validateEpoch(encoded);
        return actual.sequence();
    }

    /// TLS 1.2: read the live tuple with the 1.2 version and check its key,
    /// salt and the `iv == rec_seq` nonce invariant (`validateTls12Epoch`);
    /// the engine's own sequence may be stale once the kernel owns the
    /// direction, so only the key material is compared.
    fn kernelSequence12(engine: *const tls12_server.Server, fd: i32, direction: ktls.Direction) (KtlsError || ktls.ControlError)!u64 {
        const params = (if (direction == .tx) engine.ktlsTxParams() else engine.ktlsRxParams()) orelse return error.KtlsUnsupportedEngine;
        var expected: [ktls.max_crypto_info_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected);
        var explicit: [ktls.rec_seq_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &explicit);
        const encoded = try encodeKtls12CryptoInfo(params, &explicit, &expected);
        const cipher = ktls12Cipher(params.cipher);
        var actual = try ktls.getTupleVersion(fd, direction, cipher, ktls.TLS_1_2_VERSION);
        defer actual.wipe();
        try actual.validateTls12Epoch(cipher, encoded);
        return actual.sequence();
    }

    /// Read the current TX tuple on this exact fd and compare its key epoch.
    /// The kernel owns its advancing sequence. Held controls and partial typed
    /// replies remain untouched; this alone grants no caller/output authority.
    pub fn validateKernelTxEpoch(self: *const TlsConn, fd: i32) (KtlsError || Error || ktls.ControlError)!void {
        if (comptime builtin.os.tag != .linux) return error.Unsupported;
        if (!self.ktls_tx_offloaded or !self.handshakeDone() or self.terminal_error != null or
            self.control_turn_active or self.hasPreparedWrite()) return error.BadState;
        _ = try self.kernelSequence(fd, .tx);
    }

    /// Validate inherited live tuples; never attach/reset a speculative fd.
    pub fn restoreInheritedOffload(self: *TlsConn, fd: i32, tx: bool, rx: bool) (KtlsError || Error || ktls.ControlError)!void {
        if (self.control_turn_active or self.hasPreparedWrite() or self.terminal_error != null) return error.BadState;
        try validateKernelRxControlPhase(rx, self.control_phase, if (self.engine == .tls13) self.engine.tls13.post_handshake_recv_len else 0, self.rx_open_control_type, self.alert_prefix_len);
        if ((tx or rx) and (comptime builtin.os.tag != .linux)) return error.KtlsUnsupportedEngine;
        switch (self.engine) {
            .tls13 => |*engine| {
                if (tx and try self.kernelSequence(fd, .tx) != engine.app_write_seq) return error.TupleMismatch;
                if (rx and try self.kernelSequence(fd, .rx) != engine.app_read_seq) return error.TupleMismatch;
            },
            .tls12 => |*engine| {
                // No KeyUpdate exists in TLS 1.2: only an open alert may be
                // pending under the kernel-control hold.
                if (self.tx_ku_reply_pending or self.rx_open_control_type == 22 or
                    self.control_phase == .userspace_requested_ku_held) return error.BadState;
                if (tx and try self.kernelSequence(fd, .tx) != engine.app_write_seq) return error.TupleMismatch;
                if (rx and try self.kernelSequence(fd, .rx) != engine.app_read_seq) return error.TupleMismatch;
            },
            .undecided => return error.BadState,
        }
        if (!rx and (self.rx_open_control_type != 0 or self.alert_prefix_len != 0)) return error.BadState;
        if (rx and self.recv_buf.items.len != 0) return error.KtlsDirtyInbound;
        if (!tx and self.tx_ku_reply_pending) return error.BadState;
        if (tx) self.markTxOffloaded() else self.ktls_tx_offloaded = false;
        self.ktls_rx_offloaded = rx;
    }

    /// Successor side of a Helix upgrade: rebuild a CONNECTED adapter from an
    /// exported `ResumeState`. The matching engine config must be supplied (a
    /// 1.2-engine state with no `cfg12` fails with `error.ProtocolVersion`).
    /// Any carried partial inbound record is re-buffered so the byte stream
    /// continues exactly where the predecessor stopped.
    pub fn resumeFrom(allocator: Allocator, cfg13: tls_server.Config, cfg12: ?tls12_server.Config, st: ResumeState) Error!TlsConn {
        // Inherited TLS states are connected and never renegotiate, so they
        // have no reason to borrow the candidate's mutable staple generation.
        var connected13 = cfg13;
        connected13.ocsp_staple = &.{};
        var connected12 = cfg12;
        if (connected12) |*cfg| cfg.ocsp_staple = &.{};
        var self = TlsConn{
            .allocator = allocator,
            .engine = .undecided,
            .cfg13 = connected13,
            .cfg12 = connected12,
        };
        errdefer self.deinit();
        switch (st.engine) {
            .tls13 => |s13| self.engine = .{ .tls13 = try tls_server.Server.resumeConnected(allocator, connected13, s13) },
            .tls12 => |s12| {
                const c12 = connected12 orelse return error.ProtocolVersion;
                self.engine = .{ .tls12 = try tls12_server.Server.resumeConnected(allocator, c12, s12) };
            },
        }
        try self.recv_buf.appendSlice(allocator, st.pending_recv);
        self.rx_open_control_type = st.rx_open_control_type;
        self.alert_prefix_len = st.alert_prefix_len;
        self.alert_prefix_byte = st.alert_prefix_byte;
        self.tx_ku_reply_pending = st.tx_ku_reply_pending;
        self.tx_ku_reply_sent = st.tx_ku_reply_sent;
        self.control_phase = st.barrier_phase;
        self.held_record_len = st.held_record_len;
        if (st.barrier_phase == .userspace_requested_ku_held) {
            if (st.held_record_len == 0 or st.held_record_len > st.pending_recv.len or
                (try completeRecordLen(st.pending_recv) orelse return error.BadState) != st.held_record_len) return error.BadState;
            switch (self.engine) {
                .tls13 => |*engine| if (!try engine.requestedKeyUpdate(st.pending_recv[0..st.held_record_len])) return error.BadState,
                else => return error.BadState,
            }
        }
        return self;
    }

    /// Owns one exclusive application TX preparation. The TlsConn must stay in
    /// place; do not copy this handle or retain it across an owner turn/Helix.
    /// Reserve the complete bytes() in the physical SendQ before commit().
    pub const PreparedWrite = struct {
        inner: union(Version) {
            tls12: tls12_server.Server.PreparedAppWrite,
            tls13: tls_server.Server.PreparedAppWrite,
        },

        pub fn bytes(self: *const PreparedWrite) []const u8 {
            return switch (self.inner) {
                inline else => |*p| p.bytes(),
            };
        }

        pub fn canCommit(self: *const PreparedWrite) bool {
            return switch (self.inner) {
                inline else => |*p| p.canCommit(),
            };
        }

        pub fn commit(self: *PreparedWrite) void {
            switch (self.inner) {
                inline else => |*p| p.commit(),
            }
        }

        pub fn takeBytes(self: *PreparedWrite) []u8 {
            return switch (self.inner) {
                inline else => |*p| p.takeBytes(),
            };
        }

        pub fn abort(self: *PreparedWrite) void {
            switch (self.inner) {
                inline else => |*p| p.abort(),
            }
        }

        pub fn deinit(self: *PreparedWrite) void {
            self.abort();
        }
    };

    pub fn hasPreparedWrite(self: *const TlsConn) bool {
        return switch (self.engine) {
            inline .tls12, .tls13 => |*s| s.app_write_active != null,
            .undecided => false,
        };
    }

    /// Stage a whole application batch while preserving the legacy adapter's
    /// 16KiB input boundaries and each engine's negotiated smaller record limit.
    /// No live output buffer, TX counter, or key changes before commit.
    pub fn applicationOutputDeferred(self: *const TlsConn) bool {
        return !self.ktls_tx_offloaded and self.control_phase != .none;
    }

    pub fn applicationWireCharge(self: *const TlsConn, inputs: []const []const u8) Error!usize {
        const state: ResumeState.EngineState = switch (self.engine) {
            .tls13 => |*engine| .{ .tls13 = (try engine.captureWithPending()).state },
            .tls12 => |*engine| .{ .tls12 = try engine.exportResume() },
            .undecided => return error.BadState,
        };
        var charge: u64 = 0;
        for (inputs) |input| charge = std.math.add(u64, charge, try chunkWireCharge(state, input.len)) catch return error.PlaintextTooLong;
        return std.math.cast(usize, charge) orelse error.PlaintextTooLong;
    }

    pub fn prepareWriteBatch(self: *TlsConn, inputs: []const []const u8) Error!PreparedWrite {
        if (self.control_phase != .none or self.tx_ku_reply_pending or self.control_turn_active) return error.ControlBlocked;
        return self.prepareApplicationBatch(inputs);
    }

    /// Only the physical owner may drain the complete typed FIFO after control
    /// reply custody. This preparation never changes the stable ready phase.
    pub fn prepareDeferredWriteBatch(self: *TlsConn, inputs: []const []const u8) Error!PreparedWrite {
        if (self.control_phase != .software_tail_ready or self.tx_ku_reply_pending or self.control_turn_active) return error.ControlBlocked;
        return self.prepareApplicationBatch(inputs);
    }

    fn prepareApplicationBatch(self: *TlsConn, inputs: []const []const u8) Error!PreparedWrite {
        if (self.ktls_tx_offloaded) return error.KtlsTxOffloaded;
        if (!self.outputBoundaryClean() or !self.handshakeDone() or self.hasPreparedWrite()) return error.BadState;
        var split: std.ArrayList([]const u8) = .empty;
        defer split.deinit(self.allocator);
        var needs_split = false;
        for (inputs) |input| {
            if (input.len > tls_record.max_plaintext_len) needs_split = true;
        }
        const chunks = if (needs_split) blk: {
            for (inputs) |input| {
                var off: usize = 0;
                while (true) {
                    const n = @min(tls_record.max_plaintext_len, input.len - off);
                    try split.append(self.allocator, input[off..][0..n]);
                    off += n;
                    if (off == input.len) break;
                }
            }
            break :blk split.items;
        } else inputs;
        return switch (self.engine) {
            .tls13 => |*engine| .{ .inner = .{ .tls13 = try engine.prepareAppWrite(chunks) } },
            .tls12 => |*engine| .{ .inner = .{ .tls12 = try engine.prepareAppWrite(chunks) } },
            .undecided => error.BadState,
        };
    }

    /// Encrypt into adapter-owned scratch. Replace the previous scratch only
    /// after preparation has succeeded; publishing the new buffer cannot fail.
    pub fn write(self: *TlsConn, plaintext: []const u8) Error![]const u8 {
        var prepared = try self.prepareWriteBatch(&.{plaintext});
        defer prepared.deinit();
        prepared.commit();
        const owned = prepared.takeBytes();
        self.write_buf.deinit(self.allocator);
        self.write_buf = .empty;
        self.write_buf.items = owned;
        self.write_buf.capacity = owned.len;
        return self.write_buf.items;
    }

    /// Feed one complete handshake-phase record to the chosen engine.
    fn feedRecord(self: *TlsConn, record: []const u8) Error!void {
        try self.unpublished.ensureUnusedCapacity(self.allocator, 1);
        switch (self.engine) {
            .tls13 => |*s| {
                switch (try s.feed(record)) {
                    .need_more => {},
                    .bytes_to_send => |flight| {
                        self.unpublished.appendAssumeCapacity(flight);
                    },
                }
                if (s.handshakeDone()) {
                    if (try s.takeEarlyData()) |early| {
                        defer self.allocator.free(early);
                        try self.plain_buf.appendSlice(self.allocator, early);
                    }
                }
            },
            .tls12 => |*s| switch (try s.feed(record)) {
                .need_more => {},
                .bytes_to_send => |flight| {
                    self.unpublished.appendAssumeCapacity(flight);
                },
            },
            .undecided => return error.BadState,
        }
    }

    /// Decrypt one complete application_data record into `plain_buf`.
    fn decryptRecord(self: *TlsConn, record: []const u8, allow_requested: bool) Error!bool {
        const opened = switch (self.engine) {
            .tls13 => |*s| blk: {
                const policy: tls_server.Server.ControlPolicy = if (!allow_requested) .hold_requested else if (self.ktls_tx_offloaded) .kernel_reply else .software_reply;
                switch (try s.decryptWithControlPolicy(record, policy)) {
                    .held_request => return false,
                    .kernel_reply => {
                        self.tx_ku_reply_pending = true;
                        self.tx_ku_reply_sent = 0;
                        return true;
                    },
                    .plaintext => |owned| break :blk owned,
                }
            },
            .tls12 => |*s| try s.decrypt(record),
            .undecided => return error.BadState,
        };
        defer self.allocator.free(opened);
        try self.plain_buf.appendSlice(self.allocator, opened);
        return true;
    }

    const Detected = enum { need_more, tls12, tls13 };

    /// Inspect the buffered first ClientHello and decide the protocol version: a
    /// supported_versions extension listing 0x0304 selects TLS 1.3, otherwise
    /// TLS 1.2. Reassembles the ClientHello across handshake records if needed.
    fn detectVersion(self: *TlsConn) Error!Detected {
        var pos = self.version_detection_scanned;
        const buf = self.recv_buf.items;
        while (true) {
            const wire = try completeRecordLen(buf[pos..]) orelse return .need_more;
            const rec = buf[pos .. pos + wire];
            if (rec[0] != @backingInt(tls_record.ContentType.handshake)) return error.BadRecord;
            const frag = rec[tls_record.record_header_len..];
            if (frag.len > tls_record.max_plaintext_len) return error.RecordOverflow;
            try self.version_detection.append(self.allocator, frag);
            pos += wire;
            self.version_detection_scanned = pos;
            const message_len = self.version_detection.completeLen() orelse continue;
            // RFC 8446 §5.1 / RFC 5246 §7.4: the first flight is exactly one
            // ClientHello. Trailing handshake bytes coalesced after it, or any
            // other first handshake type, are an out-of-order message, i.e.
            // unexpected_message (RFC 8446 §6.2), not a decode failure. This
            // matches the engines' own first-flight checks
            // (tls12_server: client_hello_reassembly).
            if (message_len != self.version_detection.bytes.items.len) return error.UnexpectedMessage;
            const message = self.version_detection.bytes.items;
            if (message[0] != 1) return error.UnexpectedMessage; // must be client_hello
            const detected = classifyClientHello(message[4..message_len]);
            self.version_detection.deinit(self.allocator);
            self.version_detection = .{};
            self.version_detection_scanned = 0;
            return detected;
        }
    }
};

/// Classify a ClientHello body: returns `.tls13` when a supported_versions
/// extension lists 0x0304, else `.tls12`. Strict bounds checks throughout.
fn classifyClientHello(body: []const u8) TlsConn.Detected {
    var i: usize = 0;
    // client_version(2) + random(32)
    i += 2 + 32;
    if (i > body.len) return .tls12;
    // session_id
    if (i >= body.len) return .tls12;
    i += 1 + body[i];
    if (i + 2 > body.len) return .tls12;
    // cipher_suites
    const cs_len = (@as(usize, body[i]) << 8) | body[i + 1];
    i += 2 + cs_len;
    if (i >= body.len) return .tls12;
    // compression_methods
    i += 1 + body[i];
    // extensions are optional; a TLS 1.2 ClientHello may omit them entirely.
    if (i + 2 > body.len) return .tls12;
    const ext_total = (@as(usize, body[i]) << 8) | body[i + 1];
    i += 2;
    const ext_end = @min(i + ext_total, body.len);
    while (i + 4 <= ext_end) {
        const etype = (@as(usize, body[i]) << 8) | body[i + 1];
        const elen = (@as(usize, body[i + 2]) << 8) | body[i + 3];
        i += 4;
        if (i + elen > ext_end) break;
        if (etype == 43) { // supported_versions
            const list = body[i .. i + elen];
            if (list.len >= 1) {
                const ll = list[0];
                var j: usize = 1;
                while (j + 1 < list.len and j + 1 <= ll) : (j += 2) {
                    if (((@as(usize, list[j]) << 8) | list[j + 1]) == 0x0304) return .tls13;
                }
            }
        }
        i += elen;
    }
    return .tls12;
}

/// Length on the wire of the first complete TLS record in `buf`.
///
/// Returns null ONLY when more bytes are genuinely needed. A structurally
/// invalid header is an error, never a null: this framer runs in FRONT of both
/// inner engines, so anything it reports as merely "incomplete" is retained in
/// `recv_buf` and waited on indefinitely. A peer that declares a body it never
/// sends parks that many bytes per connection until the idle timeout, and the
/// inner engine's own header checks never get to run because the record never
/// completes.
///
///   * RFC 8446 §5 / RFC 5246 §6.2.1: the content type set is {20,21,22,23} for
///     both engines, so a byte outside it can only come from a peer inventing
///     one — terminate rather than wait for the body.
///   * RFC 8446 §5.2 / RFC 5246 §6.2.3: TLSCiphertext.length is capped at
///     2^14+256 on both arms, but the wire field is a u16, so a peer can declare
///     0xFFFF and make us hold ~64 KiB for a record we are guaranteed to reject.
///
/// The legacy version byte is deliberately NOT checked here — it differs between
/// the two arms (TLS 1.2 accepts 0x0301–0x0303) and is the inner engine's call.
fn completeRecordLen(buf: []const u8) Error!?usize {
    if (buf.len < tls_record.record_header_len) return null;
    if (tls_record.ContentType.fromWire(buf[0]) == null) return error.BadRecord;
    const body_len = std.mem.readInt(u16, buf[3..5], .big);
    if (body_len > tls_record.max_ciphertext_len) return error.RecordOverflow;
    const wire_len = tls_record.record_header_len + @as(usize, body_len);
    if (buf.len < wire_len) return null;
    return wire_len;
}

/// Drop the first `n` bytes of `list`, shifting the remainder down in place.
fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const remain = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..remain], list.items[n..]);
    list.shrinkRetainingCapacity(remain);
}

// ── kTLS RX control-record demux ─────────────────────────────────────────────
//
// Once a conn is kTLS-RX-offloaded the kernel returns application_data plaintext
// from a plain `recv`, but a kernel-decrypted *control* record (KeyUpdate /
// close_notify) can only be conveyed via `recvmsg` + a `TLS_GET_RECORD_TYPE`
// cmsg — a plain `recv` rejects it with `EIO`. The daemon's recv loop, on that
// error, calls `drainKtlsRxControl` to read the record's content type out of band
// and act on it WITHOUT dropping the connection for a benign KeyUpdate.

/// The typed outcome of demuxing one record off a kTLS-RX-offloaded socket. The
/// daemon maps each variant to a recv-loop action (feed / consume+continue /
/// close) so a control record never reaches the IRC parser and a KeyUpdate never
/// triggers a spurious drop.
pub const KtlsRxRecord = union(enum) {
    /// Kernel-decrypted application bytes (a prefix of the passed buffer) — feed to
    /// the IRC/WS layer exactly as the plain-recv fast path does.
    app_data: []u8,
    /// A TLS 1.3 post-handshake handshake record — a client KeyUpdate. The kernel
    /// consumed it; the conn continues, no drop. The KeyUpdate rotates the peer's
    /// send key, so the caller re-installs the advanced RX `crypto_info` on the
    /// kernel (a second `setsockopt(TLS_RX)` at seq 0 — `TlsConn.rekeyKtlsRx`) to
    /// keep decrypting *subsequent* app data. `request_peer` carries the RFC 8446
    /// §4.6.3 `update_requested` flag: when true the client obliges the server to
    /// send its OWN KeyUpdate(update_not_requested) and rotate TX before its next
    /// application record (the daemon's spec-safe handling of that reply obligation
    /// lives in the recv loop — see `handleKtlsRxControl`).
    key_update: struct { request_peer: bool },
    /// A close_notify (or any) alert record — close the conn gracefully.
    close_notify,
    /// TCP EOF — the peer closed the socket.
    eof,
    /// Nothing more is queued right now (EAGAIN) — re-arm recv and wait.
    would_block,
    /// The kernel needs a fresh RX key before it can decrypt the next record
    /// (post-KeyUpdate app data; EKEYEXPIRED). A distinct, non-fault close reason.
    needs_rekey,
    /// An unexpected record type or a genuine recv fault — close fail-safe.
    fault,
};

/// TLS 1.3 `HandshakeType.key_update` (RFC 8446 §4.6.3). The only post-handshake
/// handshake message a compliant peer sends on an established application-data
/// stream; anything else demuxed as a handshake record is a protocol violation.
const tls_handshake_key_update: u8 = 24;

/// Pure classifier: map a demuxed TLS content type to the recv-loop action. Split
/// out from `drainKtlsRxControl` so the policy (handshake ⇒ KeyUpdate, alert ⇒
/// close, unexpected ⇒ fail-safe close) is unit-testable without a live socket.
///
/// A handshake record on a kTLS-offloaded conn is parsed as a KeyUpdate and the
/// `update_requested` flag is read from the kernel-delivered plaintext (verified
/// on this kernel: the 5-byte KeyUpdate message is returned in `plaintext`). Fail
/// closed: a handshake record that is NOT exactly one well-formed KeyUpdate
/// (`{key_update(24), uint24 len 1, one-byte request ∈ {0,1}}`) is a protocol
/// violation ⇒ `.fault` (close), never a silent continue.
fn classifyKtlsRecord(record_type: u8, plaintext: []u8) KtlsRxRecord {
    return switch (record_type) {
        @backingInt(ktls.RecordType.application_data) => .{ .app_data = plaintext },
        @backingInt(ktls.RecordType.handshake) => parseKeyUpdate(plaintext),
        @backingInt(ktls.RecordType.alert) => .close_notify,
        // change_cipher_spec (a legal no-op mid-handshake) has no business after
        // the handshake on a kTLS conn, and any other type is unknown — fail-safe.
        else => .fault,
    };
}

/// Strictly parse the plaintext of a demuxed post-handshake handshake record as a
/// single TLS 1.3 KeyUpdate and extract its `update_requested` flag. Fail closed
/// on any deviation (wrong type/length, coalesced messages, out-of-range request
/// value) so a malformed control record can never masquerade as a benign rekey.
fn parseKeyUpdate(plaintext: []const u8) KtlsRxRecord {
    // KeyUpdate wire form: type(1)=24, length(uint24)=1, body(1)=request. Exactly.
    if (plaintext.len != 5) return .fault;
    if (plaintext[0] != tls_handshake_key_update) return .fault;
    if (plaintext[1] != 0 or plaintext[2] != 0 or plaintext[3] != 1) return .fault;
    return switch (plaintext[4]) {
        0 => .{ .key_update = .{ .request_peer = false } }, // update_not_requested
        1 => .{ .key_update = .{ .request_peer = true } }, // update_requested
        else => .fault,
    };
}

/// Demux ONE record from a kTLS-RX-offloaded socket `fd` via `recvmsg` + the
/// `TLS_GET_RECORD_TYPE` cmsg, returning the typed action for the daemon's recv
/// loop. `buf` receives kernel-decrypted plaintext for an application-data
/// record. `flags` is forwarded to `recvmsg` (the reactor passes `MSG.DONTWAIT`
/// so a spurious wakeup never blocks the loop). This is the offloaded-conn recv
/// path that replaces "a control record ⇒ drop the conn".
pub fn drainKtlsRxControl(fd: linux.fd_t, buf: []u8, flags: u32) KtlsRxRecord {
    const rr = ktls.recvmsgRecordType(fd, buf, flags) catch |err| return switch (err) {
        error.WouldBlock => .would_block,
        error.Eof => .eof,
        error.NeedsRekey => .needs_rekey,
        error.RecvFailed, error.MalformedControl => .fault,
    };
    return classifyKtlsRecord(rr.record_type, rr.plaintext);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Ed25519 = std.crypto.sign.Ed25519;
const tls_client = @import("../crypto/tls_client.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");

/// Build the self-signed Ed25519 leaf the loopback tests share: a CA-flagged
/// cert carrying the `irc.test` dNSName, matching the tls_server loopback test.
fn makeLeaf(out: []u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x34 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
}

test "onInbound drives a full handshake against tls_client and streams app data both ways" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    // ClientHello -> TlsConn returns the server flight, no plaintext yet.
    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    try std.testing.expect(sh_out.handshake_bytes.len != 0);
    try std.testing.expectEqual(@as(usize, 0), sh_out.plaintext.len);
    try std.testing.expect(!conn.handshakeDone());

    // Client consumes the flight and produces its Finished.
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());

    // Finished -> TlsConn completes the handshake with nothing to send back.
    const fin_out = try conn.onInbound(cfin);
    try std.testing.expectEqual(@as(usize, 0), fin_out.handshake_bytes.len);
    try std.testing.expectEqual(@as(usize, 0), fin_out.plaintext.len);
    try std.testing.expect(conn.handshakeDone());

    // Client -> server application data surfaces as Outcome.plaintext.
    const c2s = try client.encrypt("hello server");
    defer alloc.free(c2s);
    const app_out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("hello server", app_out.plaintext);
    try std.testing.expectEqual(@as(usize, 0), app_out.handshake_bytes.len);

    // Server -> client application data round-trips through write().
    const cipher = try conn.write("hello client");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("hello client", got);
}

/// Drive an in-memory TLS 1.3 handshake to completion (server = `conn`).
fn perfHandshake(conn: *TlsConn, client: *tls_client.Client, alloc: Allocator) !void {
    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
}

/// Count the TLS records framed in `buf` (each: 5-byte header + u16 length body).
fn countAppRecords(buf: []const u8) usize {
    var off: usize = 0;
    var n: usize = 0;
    while (off + tls_record.record_header_len <= buf.len) {
        const len = std.mem.readInt(u16, buf[off + 3 ..][0..2], .big);
        off += tls_record.record_header_len + len;
        n += 1;
    }
    return n;
}

// Measurement for the server.zig deliverTagged/deliverTimed local-TLS coalescing
// (prefersJoinedAppend): a tagged channel message to a userspace-TLS recipient
// used to append the @-tag prefix and the line as TWO separate writes, sealing
// TWO discrete TLS records; joining them into ONE append seals ONE record. This
// pins the halving and reports the per-message record + wire-byte overhead the
// change removes for every tagged fan-out recipient on a userspace-TLS conn.
test "perf: joining a tag prefix + line halves TLS records vs two appends" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    const prefix = "@time=2026-07-12T00:00:00.000Z;msgid=abcd1234ef;account=alice ";
    const line = ":alice!alice@host PRIVMSG #chan :hello everyone in this channel\r\n";

    // OLD: two appends -> two records. write() reuses write_buf, so measure the
    // first record blob before issuing the second write.
    var records_two: usize = 0;
    var wire_two: usize = 0;
    {
        var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
        defer conn.deinit();
        var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
        defer client.deinit();
        try perfHandshake(&conn, &client, alloc);

        const c1 = try conn.write(prefix);
        records_two += countAppRecords(c1);
        wire_two += c1.len;
        const c2 = try conn.write(line);
        records_two += countAppRecords(c2);
        wire_two += c2.len;
    }

    // NEW: one joined append -> one record.
    var records_one: usize = 0;
    var wire_one: usize = 0;
    {
        var joined_buf: [512]u8 = undefined;
        @memcpy(joined_buf[0..prefix.len], prefix);
        @memcpy(joined_buf[prefix.len..][0..line.len], line);
        const joined = joined_buf[0 .. prefix.len + line.len];

        var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
        defer conn.deinit();
        var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
        defer client.deinit();
        try perfHandshake(&conn, &client, alloc);

        const c1 = try conn.write(joined);
        records_one += countAppRecords(c1);
        wire_one += c1.len;
    }

    // The win: 2 records (2 AEAD seals + 2 headers + 2 GCM tags) collapse to 1.
    try std.testing.expectEqual(@as(usize, 2), records_two);
    try std.testing.expectEqual(@as(usize, 1), records_one);
    try std.testing.expect(wire_one < wire_two);
    std.debug.print(
        "\n[perf] tagged TLS delivery: records {d} -> {d}, wire bytes {d} -> {d} (saved {d}/msg)\n",
        .{ records_two, records_one, wire_two, wire_one, wire_two - wire_one },
    );
}

test "buildKtlsTxCryptoInfo produces a kernel-shaped TLS 1.3 crypto_info post-handshake" {
    const alloc = std.testing.allocator;
    const native = @import("builtin").cpu.arch.endian();

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    var buf: [ktls.max_crypto_info_len]u8 = undefined;
    // No offload material before the handshake completes.
    try std.testing.expectError(error.KtlsUnsupportedEngine, conn.buildKtlsTxCryptoInfo(&buf));

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // Check the actual negotiated suite's kernel ABI and exact TX material.
    const engine = &conn.engine.tls13;
    const suite = @backingInt(engine.selected_suite.?);
    const shape: struct { len: usize, cipher: ktls.CipherType, key_len: usize, iv_len: usize, salt_len: usize } = switch (suite) {
        0x1301 => .{ .len = 40, .cipher = .aes_gcm_128, .key_len = 16, .iv_len = 8, .salt_len = 4 },
        0x1302 => .{ .len = 56, .cipher = .aes_gcm_256, .key_len = 32, .iv_len = 8, .salt_len = 4 },
        0x1303 => .{ .len = 56, .cipher = .chacha20_poly1305, .key_len = 32, .iv_len = 12, .salt_len = 0 },
        else => return error.TestUnexpectedResult,
    };
    const encoded = try conn.buildKtlsTxCryptoInfo(&buf);
    try std.testing.expectEqual(shape.len, encoded.len);
    try std.testing.expectEqual(ktls.TLS_1_3_VERSION, std.mem.readInt(u16, encoded[0..2], native));
    try std.testing.expectEqual(shape.cipher.toInt(), std.mem.readInt(u16, encoded[2..4], native));
    var at: usize = 4;
    try std.testing.expectEqualSlices(u8, engine.server_app_keys.iv[shape.salt_len..], encoded[at..][0..shape.iv_len]);
    at += shape.iv_len;
    try std.testing.expectEqualSlices(u8, engine.server_app_keys.key[0..shape.key_len], encoded[at..][0..shape.key_len]);
    at += shape.key_len;
    try std.testing.expectEqualSlices(u8, engine.server_app_keys.iv[0..shape.salt_len], encoded[at..][0..shape.salt_len]);
    at += shape.salt_len;
    try std.testing.expectEqual(engine.app_write_seq, std.mem.readInt(u64, encoded[at..][0..8], .big));
    try std.testing.expectEqual(encoded.len, at + 8);
}

fn testTcpSocketOrSkip() !linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SkipZigTest;
    return @intCast(rc);
}

test "kTLS TX offload: the kernel encrypts server writes and tls_client decrypts them" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    // In-memory TLS 1.3 handshake → a connected TlsConn whose keys the client
    // shares (so the client can decrypt whatever the kernel produces from them).
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // A real ESTABLISHED loopback pair for the kernel to encrypt over.
    const listen_fd = try testTcpSocketOrSkip();
    defer _ = linux.close(listen_fd);
    var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    if (posix.errno(linux.bind(listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(listen_fd, 1)) != .SUCCESS) return error.SkipZigTest;
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SkipZigTest;
    addr.port = (@as(*const linux.sockaddr.in, @ptrCast(@alignCast(&storage)))).port;
    const client_fd = try testTcpSocketOrSkip();
    defer _ = linux.close(client_fd);
    if (posix.errno(linux.connect(client_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    const accept_rc = linux.accept4(listen_fd, null, null, 0);
    if (posix.errno(accept_rc) != .SUCCESS) return error.SkipZigTest;
    const server_fd: linux.fd_t = @intCast(accept_rc);
    defer _ = linux.close(server_fd);

    // Offload TX to the kernel using the live handshake keys; skip if no CONFIG_TLS.
    // (`TlsConn.init` leaves session tickets off, so no NST is emitted and
    // `app_write_seq` is 0 at attach — the kernel starts at seq 0, matching the
    // client's read seq 0. With tickets on, an undelivered NST would desync this.)
    conn.enableKtlsTx(server_fd) catch return error.SkipZigTest;

    // Plaintext written to the socket is TLS-record-encrypted BY THE KERNEL.
    const msg = "kernel-encrypted server->client hello";
    if (posix.errno(linux.write(server_fd, msg.ptr, msg.len)) != .SUCCESS) return error.SkipZigTest;

    // Read the record on the client end and decrypt it with the shared keys —
    // a green decrypt proves the kernel used our key/iv/salt/seq correctly.
    var rec: [512]u8 = undefined;
    const rr = linux.read(client_fd, &rec, rec.len);
    if (posix.errno(rr) != .SUCCESS) return error.SkipZigTest;
    const n: usize = @intCast(rr);
    try std.testing.expect(n != 0);
    try std.testing.expectEqual(@as(u8, 23), rec[0]); // TLS application_data record
    const got = try client.decrypt(rec[0..n]);
    defer alloc.free(got);
    try std.testing.expectEqualStrings(msg, got);
}

/// In-memory TLS 1.3 handshake between a fresh `TlsConn` and `tls_client`
/// (session tickets off, so `app_write_seq` is 0 when it returns).
fn closeNotifyHandshake(alloc: Allocator, conn: *TlsConn, client: *tls_client.Client) !void {
    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());
}

fn expectClientSeesCloseNotify(alloc: Allocator, client: *tls_client.Client, fd: i32) !void {
    const record = try Tls3TcpPair.record(fd, alloc);
    defer alloc.free(record);
    // TLS 1.3 protects the alert inside an application_data outer record.
    try std.testing.expectEqual(@as(u8, 23), record[0]);
    // RFC 8446 §6.1: the client engine reports close_notify as a clean EOF.
    try std.testing.expectError(error.EndOfStream, client.decrypt(record));
    try std.testing.expectEqual(tls_alert_mod.AlertDescription.close_notify, client.last_alert.?.description);
}

const tls_alert_mod = @import("../proto/tls_alert.zig");

test "close_notify: userspace TX sends exactly one authenticated close_notify" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x38)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    try closeNotifyHandshake(alloc, &conn, &client);
    const sockets = Tls3TcpPair.open() catch return error.SkipZigTest;
    defer sockets.deinit();
    try std.testing.expect(conn.closeNotifyEligible());
    try std.testing.expectEqual(TlsConn.CloseNotifyOutcome.sent, conn.sendCloseNotify(sockets.server));
    try expectClientSeesCloseNotify(alloc, &client, sockets.peer);
    // RFC 8446 §6.1: nothing (including a second alert) follows close_notify.
    try std.testing.expectEqual(TlsConn.CloseNotifyOutcome.not_applicable, conn.sendCloseNotify(sockets.server));
    try std.testing.expectError(error.BadState, conn.engine.tls13.encrypt("after close"));
}

test "close_notify: never sent before the handshake or after a fatal alert" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x39)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const sockets = Tls3TcpPair.open() catch return error.SkipZigTest;
    defer sockets.deinit();
    {
        var fresh = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
        defer fresh.deinit();
        try std.testing.expectEqual(TlsConn.CloseNotifyOutcome.not_applicable, fresh.sendCloseNotify(sockets.server));
    }
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    try closeNotifyHandshake(alloc, &conn, &client);
    // A tampered client record is a fatal record failure: the stream ends with
    // bad_record_mac, and no close_notify may follow (RFC 8446 §6.2).
    const app = try client.encrypt("tampered");
    defer alloc.free(app);
    app[app.len - 1] ^= 1;
    const failure = if (conn.onInbound(app)) |_| return error.TestUnexpectedResult else |err| err;
    const fatal = conn.takeAlert(failure) orelse return error.TestUnexpectedResult;
    alloc.free(fatal);
    try std.testing.expect(!conn.closeNotifyEligible());
    try std.testing.expectEqual(TlsConn.CloseNotifyOutcome.not_applicable, conn.sendCloseNotify(sockets.server));
}

test "close_notify: a peer close_notify is classified as a clean end of input" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3a)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    try closeNotifyHandshake(alloc, &conn, &client);
    try std.testing.expect(!conn.peerSentCloseNotify());
    const bye = try client.closeNotify();
    defer alloc.free(bye);
    try std.testing.expectError(error.TlsAlert, conn.onInbound(bye));
    try std.testing.expect(conn.peerSentCloseNotify());
    // RFC 5246 §7.2.1 / RFC 8446 §6.1: answer with our own close_notify.
    if (comptime builtin.os.tag != .linux) return;
    const sockets = Tls3TcpPair.open() catch return error.SkipZigTest;
    defer sockets.deinit();
    try std.testing.expect(conn.closeNotifyEligible());
    try std.testing.expectEqual(TlsConn.CloseNotifyOutcome.sent, conn.sendCloseNotify(sockets.server));
    try expectClientSeesCloseNotify(alloc, &client, sockets.peer);
}

test "close_notify: a peer fatal alert is not a clean end and gets no close_notify" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3c)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    try closeNotifyHandshake(alloc, &conn, &client);
    const fatal = client.takeAlert(error.BadHandshake) orelse return error.TestUnexpectedResult;
    defer alloc.free(fatal);
    try std.testing.expectError(error.TlsAlert, conn.onInbound(fatal));
    try std.testing.expect(!conn.peerSentCloseNotify());
    try std.testing.expect(!conn.closeNotifyEligible());
    const sockets = Tls3TcpPair.open() catch return error.SkipZigTest;
    defer sockets.deinit();
    try std.testing.expectEqual(TlsConn.CloseNotifyOutcome.not_applicable, conn.sendCloseNotify(sockets.server));
}

test "close_notify: kTLS TX marks the engine offloaded and sends a kernel control alert" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3b)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    try closeNotifyHandshake(alloc, &conn, &client);
    const sockets = Tls3TcpPair.open() catch return error.SkipZigTest;
    defer sockets.deinit();
    conn.enableKtlsTx(sockets.server) catch return error.SkipZigTest;
    // The engine must refuse every userspace seal under the kernel's sequence.
    try std.testing.expect(conn.engine.tls13.tx_offloaded);
    try std.testing.expectError(error.BadState, conn.engine.tls13.closeNotify());
    try std.testing.expectError(error.BadState, conn.engine.tls13.encrypt("userspace after offload"));
    // One kernel-encrypted application record precedes the alert so the
    // client proves the kernel sequence continues across the control record.
    try Tls3TcpPair.send(sockets.server, "last line");
    const first = try Tls3TcpPair.record(sockets.peer, alloc);
    defer alloc.free(first);
    const line = try client.decrypt(first);
    defer alloc.free(line);
    try std.testing.expectEqualStrings("last line", line);
    try std.testing.expectEqual(TlsConn.CloseNotifyOutcome.sent, conn.sendCloseNotify(sockets.server));
    try expectClientSeesCloseNotify(alloc, &client, sockets.peer);
}

test "enableKtlsRx fails closed when inbound is not at a record boundary" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x39)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    try conn.recv_buf.appendSlice(alloc, &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x10 });
    try std.testing.expect(conn.hasBufferedInbound());
    try std.testing.expectError(error.KtlsDirtyInbound, conn.enableKtlsRx(@as(linux.fd_t, -1)));
}

test "exploit: write after kTLS TX attach fails closed instead of double-encrypting" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3a)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    conn.ktls_tx_offloaded = true;
    try std.testing.expectError(error.KtlsTxOffloaded, conn.write("do-not-double-encrypt"));
}

test "kTLS RX offload: the kernel decrypts client records into recv() plaintext" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    // In-memory TLS 1.3 handshake → a connected TlsConn whose keys the client
    // shares (so records the client encrypts, the kernel — using our RX
    // crypto_info from the same keys — can decrypt).
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // Real ESTABLISHED loopback pair.
    const listen_fd = try testTcpSocketOrSkip();
    defer _ = linux.close(listen_fd);
    var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    if (posix.errno(linux.bind(listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(listen_fd, 1)) != .SUCCESS) return error.SkipZigTest;
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SkipZigTest;
    addr.port = (@as(*const linux.sockaddr.in, @ptrCast(@alignCast(&storage)))).port;
    const client_fd = try testTcpSocketOrSkip();
    defer _ = linux.close(client_fd);
    if (posix.errno(linux.connect(client_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    const accept_rc = linux.accept4(listen_fd, null, null, 0);
    if (posix.errno(accept_rc) != .SUCCESS) return error.SkipZigTest;
    const server_fd: linux.fd_t = @intCast(accept_rc);
    defer _ = linux.close(server_fd);

    // Offload RX (client→server decrypt) to the kernel. app_read_seq is 0 (no
    // inbound app data consumed yet), matching the client's write seq 0.
    conn.enableKtlsRx(server_fd) catch return error.SkipZigTest;

    // The client encrypts an app record; the KERNEL decrypts it on recv().
    const msg = "kernel-decrypted client->server hello";
    const rec = try client.encrypt(msg);
    defer alloc.free(rec);
    var off: usize = 0;
    while (off < rec.len) {
        const wr = linux.write(client_fd, rec[off..].ptr, rec.len - off);
        if (posix.errno(wr) != .SUCCESS) return error.SkipZigTest;
        off += @intCast(wr);
    }

    var buf: [256]u8 = undefined;
    const rr = linux.read(server_fd, &buf, buf.len);
    if (posix.errno(rr) != .SUCCESS) return error.SkipZigTest;
    const n: usize = @intCast(rr);
    // recv() returns the KERNEL-DECRYPTED plaintext (not a TLS record).
    try std.testing.expectEqualStrings(msg, buf[0..n]);

    // ── Control-record demux via recvmsg + TLS_GET_RECORD_TYPE cmsg ─────────
    // The client emits a KeyUpdate — a TLS 1.3 *control* record (inner
    // content_type = handshake(22)). A plain recv() cannot convey a record type,
    // so it rejects the control record with an error (EIO) — the pre-demux
    // behavior that forced a drop — while leaving the decrypted record queued for
    // a recvmsg that supplies a SOL_TLS control buffer.
    try client.sendKeyUpdateForTest();
    const ku = (try client.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(ku);
    {
        var ko: usize = 0;
        while (ko < ku.len) {
            const w = linux.write(client_fd, ku[ko..].ptr, ku.len - ko);
            if (posix.errno(w) != .SUCCESS) return error.SkipZigTest;
            ko += @intCast(w);
        }
    }

    // Pre-demux: a plain recv() still fails on the control record (kTLS surfaces
    // non-data records only via recvmsg + cmsg), leaving it queued.
    var throwaway: [256]u8 = undefined;
    try std.testing.expect(posix.errno(linux.read(server_fd, &throwaway, throwaway.len)) != .SUCCESS);

    // THE CRUX: recvmsg + the TLS_GET_RECORD_TYPE cmsg recover the record's content
    // type out of band — handshake(22), NOT application_data(23). So the daemon can
    // identify the KeyUpdate instead of feeding a control record to the IRC parser.
    var demux_buf: [256]u8 = undefined;
    const rr2 = try ktls.recvmsgRecordType(server_fd, &demux_buf, 0);
    // Observed on this kernel (7.0.3): record_type=22 (handshake), n=5 (the
    // KeyUpdate handshake message: 4-byte header + 1-byte update_request).
    try std.testing.expectEqual(@backingInt(ktls.RecordType.handshake), rr2.record_type);
    try std.testing.expect(rr2.record_type != @backingInt(ktls.RecordType.application_data));
    // The daemon-level classifier maps that to `.key_update` (consume + continue),
    // never `.app_data` and never a hard fault ⇒ no spurious drop.
    try std.testing.expect(classifyKtlsRecord(rr2.record_type, rr2.plaintext) == .key_update);

    // Continuation boundary (see enableKtlsRx / KtlsRxRecord.key_update): the
    // client rotated its send key with the KeyUpdate, so its next app record is
    // under the NEW key while the kernel's RX crypto_info is still the OLD key
    // (this test deliberately does NOT re-install it). The kernel therefore does
    // NOT decrypt that record and never delivers the new-key plaintext as
    // application_data — it signals the stream needs a rekey (EKEYEXPIRED ⇒
    // NeedsRekey) rather than corrupting the byte stream. This isolates the raw
    // kernel behavior; the FULL continuity path (advance RX key + a second
    // setsockopt(TLS_RX) at seq 0 ⇒ the post-rekey record decrypts) is proven in
    // "kTLS RX rekey continuity: a client KeyUpdate survives with zero dropped
    // bytes" below.
    const after = try client.encrypt("post-rekey app data");
    defer alloc.free(after);
    {
        var ao: usize = 0;
        while (ao < after.len) {
            const w = linux.write(client_fd, after[ao..].ptr, after.len - ao);
            if (posix.errno(w) != .SUCCESS) return error.SkipZigTest;
            ao += @intCast(w);
        }
    }
    var after_buf: [256]u8 = undefined;
    // Observed on this kernel (7.0.3): this returns error.NeedsRekey (EKEYEXPIRED).
    if (ktls.recvmsgRecordType(server_fd, &after_buf, linux.MSG.DONTWAIT)) |ok| {
        // Whatever came back, it must NOT be the new-key plaintext delivered as a
        // clean application_data record.
        try std.testing.expect(!(ok.record_type == @backingInt(ktls.RecordType.application_data) and
            std.mem.eql(u8, ok.plaintext, "post-rekey app data")));
    } else |err| {
        // The stale RX key cannot open the rotated record: a rekey signal or a
        // recv fault, never a successful app-data delivery.
        try std.testing.expect(err == error.NeedsRekey or err == error.RecvFailed or err == error.WouldBlock);
    }
}

test "advanceRxKeyForKtls advances only the RX key and resets its seq, TX untouched" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    const engine = switch (conn.engine) {
        .tls13 => |*s| s,
        else => return error.TestUnexpectedResult,
    };

    // Snapshot the pre-advance RX key/iv and the TX key by value (the engine
    // mutates the RX material in place).
    const rx0 = engine.ktlsRxParams() orelse return error.TestUnexpectedResult;
    var rx0_key: [32]u8 = @splat(0);
    @memcpy(rx0_key[0..rx0.key.len], rx0.key);
    const rx0_iv = rx0.iv;
    const rx0_key_len = rx0.key.len;
    const tx0 = engine.ktlsTxParams() orelse return error.TestUnexpectedResult;
    var tx0_key: [32]u8 = @splat(0);
    @memcpy(tx0_key[0..tx0.key.len], tx0.key);
    const tx0_iv = tx0.iv;

    // Advance the RX key (mirrors the RX half of applyKeyUpdate).
    const rx1 = try engine.advanceRxKeyForKtls();

    // The rekeyed RX params carry record seq 0 (RFC 8446 §5.3: the sequence resets
    // on a key change) and a genuinely rotated key/iv.
    try std.testing.expectEqual(@as(u64, 0), rx1.seq);
    try std.testing.expectEqual(rx0_key_len, rx1.key.len);
    try std.testing.expect(!std.mem.eql(u8, rx0_key[0..rx0_key_len], rx1.key));
    try std.testing.expect(!std.mem.eql(u8, &rx0_iv, &rx1.iv));

    // The TX (server→client) material is untouched — only the RX direction moved.
    const tx1 = engine.ktlsTxParams() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, tx0_key[0..tx0.key.len], tx1.key);
    try std.testing.expectEqualSlices(u8, &tx0_iv, &tx1.iv);
    try std.testing.expectEqual(tx0.seq, tx1.seq);

    // The engine's advanced RX secret matches the client's own rotated send key, so
    // a fresh derivation is mutually consistent: encrypt a record on the client
    // (whose send key we advance to match) and open it with the engine.
    try client.sendKeyUpdateForTest(); // client rotates its send (our RX) key
    const ku = (try client.takePendingSend()) orelse return error.TestUnexpectedResult;
    alloc.free(ku); // discard the KeyUpdate record; we only needed the key rotation
    const rec = try client.encrypt("after client keyupdate");
    defer alloc.free(rec);
    const opened = try engine.decrypt(rec);
    defer alloc.free(opened);
    try std.testing.expectEqualStrings("after client keyupdate", opened);
}

test "kTLS RX rekey continuity: a client KeyUpdate survives with zero dropped bytes" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    // In-memory TLS 1.3 handshake → a connected TlsConn whose keys the client
    // shares, so the kernel (using our RX crypto_info from the same keys) decrypts
    // what the client encrypts.
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // Real ESTABLISHED loopback pair.
    const listen_fd = try testTcpSocketOrSkip();
    defer _ = linux.close(listen_fd);
    var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    if (posix.errno(linux.bind(listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(listen_fd, 1)) != .SUCCESS) return error.SkipZigTest;
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SkipZigTest;
    addr.port = (@as(*const linux.sockaddr.in, @ptrCast(@alignCast(&storage)))).port;
    const client_fd = try testTcpSocketOrSkip();
    defer _ = linux.close(client_fd);
    if (posix.errno(linux.connect(client_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    const accept_rc = linux.accept4(listen_fd, null, null, 0);
    if (posix.errno(accept_rc) != .SUCCESS) return error.SkipZigTest;
    const server_fd: linux.fd_t = @intCast(accept_rc);
    defer _ = linux.close(server_fd);

    conn.enableKtlsRx(server_fd) catch return error.SkipZigTest; // no CONFIG_TLS ⇒ skip

    // Baseline: a pre-KeyUpdate app record decrypts via the kernel (proves the
    // offload is live before we rotate).
    {
        const rec = try client.encrypt("before keyupdate");
        defer alloc.free(rec);
        var off: usize = 0;
        while (off < rec.len) {
            const wr = linux.write(client_fd, rec[off..].ptr, rec.len - off);
            if (posix.errno(wr) != .SUCCESS) return error.SkipZigTest;
            off += @intCast(wr);
        }
        var buf: [256]u8 = undefined;
        switch (drainKtlsRxControl(server_fd, &buf, 0)) {
            .app_data => |pt| try std.testing.expectEqualStrings("before keyupdate", pt),
            else => return error.TestUnexpectedResult,
        }
    }

    // The client emits a KeyUpdate(update_not_requested), rotating its send (our RX)
    // key, then an app record under the NEW key. Write BOTH before draining so the
    // kernel must queue the control record ahead of the rotated app record — exactly
    // the ordering the reactor's drain loop sees.
    try client.sendKeyUpdateForTest();
    const ku = (try client.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(ku);
    {
        var ko: usize = 0;
        while (ko < ku.len) {
            const w = linux.write(client_fd, ku[ko..].ptr, ku.len - ko);
            if (posix.errno(w) != .SUCCESS) return error.SkipZigTest;
            ko += @intCast(w);
        }
    }
    const after = try client.encrypt("post-rekey app data");
    defer alloc.free(after);
    {
        var ao: usize = 0;
        while (ao < after.len) {
            const w = linux.write(client_fd, after[ao..].ptr, after.len - ao);
            if (posix.errno(w) != .SUCCESS) return error.SkipZigTest;
            ao += @intCast(w);
        }
    }

    // Drain #1: the kernel surfaces the KeyUpdate as a handshake control record,
    // classified as a benign key_update with update_requested=false.
    var buf1: [256]u8 = undefined;
    switch (drainKtlsRxControl(server_fd, &buf1, 0)) {
        .key_update => |k| try std.testing.expect(!k.request_peer),
        else => return error.TestUnexpectedResult,
    }

    // THE CRUX: advance the RX key and re-install it on the kernel (a second
    // setsockopt(TLS_RX) at seq 0). If this kernel rejected the re-install, the
    // continuity path is genuinely unsupported here — skip rather than fail.
    conn.rekeyKtlsRx(server_fd) catch |e| switch (e) {
        error.KtlsRxUnsupported => return error.SkipZigTest,
        else => return e,
    };

    // Drain #2: the post-KeyUpdate record now decrypts under the re-installed key —
    // the exact plaintext, intact, with the connection never dropped.
    var buf2: [256]u8 = undefined;
    switch (drainKtlsRxControl(server_fd, &buf2, 0)) {
        .app_data => |pt| try std.testing.expectEqualStrings("post-rekey app data", pt),
        else => return error.TestUnexpectedResult,
    }

    // And the stream keeps flowing under the rotated key: a second post-rekey record
    // decrypts too (no off-by-one in the kernel's re-based record sequence).
    {
        const more = try client.encrypt("still flowing");
        defer alloc.free(more);
        var mo: usize = 0;
        while (mo < more.len) {
            const w = linux.write(client_fd, more[mo..].ptr, more.len - mo);
            if (posix.errno(w) != .SUCCESS) return error.SkipZigTest;
            mo += @intCast(w);
        }
        var buf3: [256]u8 = undefined;
        switch (drainKtlsRxControl(server_fd, &buf3, 0)) {
            .app_data => |pt| try std.testing.expectEqualStrings("still flowing", pt),
            else => return error.TestUnexpectedResult,
        }
    }
}

test "classifyKtlsRecord maps TLS content types to recv-loop actions" {
    var pt = [_]u8{ 1, 2, 3 };
    // application_data ⇒ feed the plaintext buffer.
    switch (classifyKtlsRecord(@backingInt(ktls.RecordType.application_data), &pt)) {
        .app_data => |d| try std.testing.expectEqualSlices(u8, &pt, d),
        else => return error.TestUnexpectedResult,
    }
    // handshake ⇒ a KeyUpdate, with the update_requested flag read from the wire.
    // update_not_requested(0): continue (advance RX key, no reply owed).
    var ku_not = [_]u8{ 24, 0, 0, 1, 0 };
    switch (classifyKtlsRecord(@backingInt(ktls.RecordType.handshake), &ku_not)) {
        .key_update => |k| try std.testing.expect(!k.request_peer),
        else => return error.TestUnexpectedResult,
    }
    // update_requested(1): the flag is surfaced so the daemon can honor the reply
    // obligation (RFC 8446 §4.6.3) — spec-safe close in the offloaded-TX case.
    var ku_req = [_]u8{ 24, 0, 0, 1, 1 };
    switch (classifyKtlsRecord(@backingInt(ktls.RecordType.handshake), &ku_req)) {
        .key_update => |k| try std.testing.expect(k.request_peer),
        else => return error.TestUnexpectedResult,
    }
    // Fail-closed: a handshake record that is not exactly one well-formed KeyUpdate
    // ⇒ .fault (close), never a silent continue. Wrong length, wrong type, wrong
    // uint24 length prefix, and an out-of-range request value are each rejected.
    try std.testing.expect(classifyKtlsRecord(@backingInt(ktls.RecordType.handshake), &pt) == .fault);
    var bad_type = [_]u8{ 20, 0, 0, 1, 0 }; // finished(20), not key_update
    try std.testing.expect(classifyKtlsRecord(@backingInt(ktls.RecordType.handshake), &bad_type) == .fault);
    var bad_len = [_]u8{ 24, 0, 0, 2, 0 }; // uint24 length 2, not 1
    try std.testing.expect(classifyKtlsRecord(@backingInt(ktls.RecordType.handshake), &bad_len) == .fault);
    var bad_req = [_]u8{ 24, 0, 0, 1, 2 }; // request value 2 ∉ {0,1}
    try std.testing.expect(classifyKtlsRecord(@backingInt(ktls.RecordType.handshake), &bad_req) == .fault);
    var coalesced = [_]u8{ 24, 0, 0, 1, 0, 24, 0, 0, 1, 0 }; // two KeyUpdates
    try std.testing.expect(classifyKtlsRecord(@backingInt(ktls.RecordType.handshake), &coalesced) == .fault);
    // alert (close_notify) ⇒ graceful close.
    try std.testing.expect(classifyKtlsRecord(@backingInt(ktls.RecordType.alert), &pt) == .close_notify);
    // change_cipher_spec / any unknown type post-handshake ⇒ fail-safe close.
    try std.testing.expect(classifyKtlsRecord(@backingInt(ktls.RecordType.change_cipher_spec), &pt) == .fault);
    try std.testing.expect(classifyKtlsRecord(99, &pt) == .fault);
}

test "shared ticket key and replay guard resume across TlsConn instances" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x68)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const ticket_key = @as([@sizeOf(tls_resumption.TicketKey)]u8, @splat(0x24));
    var guard = tls_resumption.ReplayGuard{};

    var conn1 = try TlsConn.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .ticket_key = ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_000,
        .max_early_data_size = 4096,
    });
    defer conn1.deinit();
    var client1 = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client1.deinit();

    const ch1 = try client1.start();
    defer alloc.free(ch1);
    const sh1 = try conn1.onInbound(ch1);
    const cfin1 = switch (try client1.feed(sh1.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin1);
    const fin1 = try conn1.onInbound(cfin1);
    try std.testing.expect(conn1.handshakeDone());
    try std.testing.expect(fin1.handshake_bytes.len != 0);
    try std.testing.expectEqual(tls_client.AppRead.control, try client1.decryptApp(fin1.handshake_bytes));
    const stored = client1.takeSessionTicket() orelse return error.TestUnexpectedResult;
    defer alloc.free(stored);

    var conn2 = try TlsConn.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .ticket_key = ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_001,
        .max_early_data_size = 4096,
    });
    defer conn2.deinit();
    var client2 = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client2.deinit();
    try client2.setSessionTicket(stored, 1000);
    try client2.setEarlyData("EARLY hello");

    const rch = try client2.start();
    defer alloc.free(rch);
    const sh2 = try conn2.onInbound(rch);
    try std.testing.expect(switch (conn2.engine) {
        .tls13 => |*s| s.acceptedSessionTicket(),
        else => false,
    });
    try std.testing.expect(switch (conn2.engine) {
        .tls13 => |*s| s.earlyDataAccepted(),
        else => false,
    });
    const cfin2 = switch (try client2.feed(sh2.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin2);
    try std.testing.expectEqual(@as(?bool, true), client2.earlyDataAccepted());
    const fin2 = try conn2.onInbound(cfin2);
    try std.testing.expect(conn2.handshakeDone());
    try std.testing.expectEqualStrings("EARLY hello", fin2.plaintext);

    var conn3 = try TlsConn.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_001,
        .max_early_data_size = 4096,
    });
    defer conn3.deinit();
    const replay = try conn3.onInbound(rch);
    try std.testing.expect(replay.handshake_bytes.len != 0);
    try std.testing.expect(switch (conn3.engine) {
        .tls13 => |*s| s.acceptedSessionTicket(),
        else => false,
    });
    try std.testing.expect(!switch (conn3.engine) {
        .tls13 => |*s| s.earlyDataAccepted(),
        else => true,
    });
}

test "exportResume/resumeFrom carries a live TLS 1.3 conn, including a buffered partial record" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x71)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const cfg13 = tls_server.Config{ .cert_chain = &.{der}, .signing_key = kp };

    var conn = try TlsConn.init(alloc, cfg13);
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    // Export before the handshake completes is rejected (fail-safe: such a
    // connection is dropped from the upgrade carry set, never mis-carried).
    try std.testing.expectError(error.BadState, conn.exportResume());

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // Advance both directions, then leave HALF of a client record buffered so
    // the export carries a non-empty pending_recv.
    const pre = try client.encrypt("before upgrade");
    defer alloc.free(pre);
    const pre_out = try conn.onInbound(pre);
    try std.testing.expectEqualStrings("before upgrade", pre_out.plaintext);
    const ack = try conn.write("ack");
    const ack_plain = try client.decrypt(ack);
    defer alloc.free(ack_plain);
    try std.testing.expectEqualStrings("ack", ack_plain);

    const split_rec = try client.encrypt("split across upgrade");
    defer alloc.free(split_rec);
    const half = split_rec.len / 2;
    const part = try conn.onInbound(split_rec[0..half]);
    try std.testing.expectEqual(@as(usize, 0), part.plaintext.len);

    const st = try conn.exportResume();
    try std.testing.expectEqual(Version.tls13, std.meta.activeTag(st.engine));
    try std.testing.expect(st.pending_recv.len != 0);

    // Successor adapter: the second half of the record completes and decrypts.
    var conn2 = try TlsConn.resumeFrom(alloc, cfg13, null, st);
    defer conn2.deinit();
    try std.testing.expect(conn2.handshakeDone());
    const rest = try conn2.onInbound(split_rec[half..]);
    try std.testing.expectEqualStrings("split across upgrade", rest.plaintext);

    // Both directions keep flowing on the resumed adapter.
    const cipher = try conn2.write("hello from successor");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("hello from successor", got);
    const more = try client.encrypt("more after upgrade");
    defer alloc.free(more);
    const more_out = try conn2.onInbound(more);
    try std.testing.expectEqualStrings("more after upgrade", more_out.plaintext);
}

test "resumeFrom rejects a TLS 1.2 engine state when no 1.2 config is supplied" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x72)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const st = TlsConn.ResumeState{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls12 = .{
        .suite = 0xc02b,
        .keys = .{},
        .app_read_seq = 0,
        .app_write_seq = 0,
        .peer_record_size_limit_raw = 16384,
        .local_receive_policy = 16384,
        .record_size_limit_negotiated = false,
        .selected_alpn = &.{},
    } } };
    try std.testing.expectError(
        error.ProtocolVersion,
        TlsConn.resumeFrom(alloc, .{ .cert_chain = &.{der}, .signing_key = kp }, null, st),
    );
}

test "onInbound reassembles a handshake record split across two calls" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);

    // Feed the ClientHello in two chunks: the first half is an incomplete record,
    // so the partial bytes must be retained and no flight produced yet.
    const split = ch.len / 2;
    const part1 = try conn.onInbound(ch[0..split]);
    try std.testing.expectEqual(@as(usize, 0), part1.handshake_bytes.len);
    try std.testing.expect(!conn.handshakeDone());

    // The second chunk completes the record and yields the full server flight.
    const part2 = try conn.onInbound(ch[split..]);
    try std.testing.expect(part2.handshake_bytes.len != 0);

    // The flight still drives the standards client to a finished handshake.
    const cfin = switch (try client.feed(part2.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());

    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // End-to-end app data confirms the reassembled handshake derived live keys.
    const c2s = try client.encrypt("after split");
    defer alloc.free(c2s);
    const out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("after split", out.plaintext);
}

test "write splits plaintext larger than the record limit into multiple records" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // A payload just over one record's worth must produce two records: the client
    // decrypts each independently, and concatenated they reproduce the payload.
    const big = try alloc.alloc(u8, tls_record.max_plaintext_len + 100);
    defer alloc.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);

    const cipher = try conn.write(big);
    // Two records: 2 * 5-byte headers of overhead beyond the plaintext + tags.
    try std.testing.expect(cipher.len > big.len + 2 * tls_record.record_header_len);

    var reassembled: std.ArrayList(u8) = .empty;
    defer reassembled.deinit(alloc);
    var pos: usize = 0;
    while (try completeRecordLen(cipher[pos..])) |wire_len| {
        const rec = cipher[pos .. pos + wire_len];
        const pt = try client.decrypt(rec);
        defer alloc.free(pt);
        try reassembled.appendSlice(alloc, pt);
        pos += wire_len;
    }
    try std.testing.expectEqual(cipher.len, pos);
    try std.testing.expectEqualSlices(u8, big, reassembled.items);
}

test "write before handshakeDone is rejected" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    try std.testing.expectError(error.BadState, conn.write("too early"));
}

const PreparedOutputTestPair = struct {
    conn: TlsConn = undefined,
    client: union(Version) { tls12: tls12_client.Client, tls13: tls_client.Client } = undefined,
    cert13: [2048]u8 = undefined,
    cert12: [4096]u8 = undefined,
    chain13: [1][]const u8 = undefined,
    chain12: [1][]const u8 = undefined,

    fn createUnfinished(version: Version, chacha: bool) !*PreparedOutputTestPair {
        const limit: u16 = if (version == .tls13) 16385 else 16384;
        return createWithLimits(version, chacha, limit, limit);
    }

    fn createWithLimits(version: Version, chacha: bool, local_limit: u16, peer_limit: u16) !*PreparedOutputTestPair {
        const a = std.testing.allocator;
        const pair = try a.create(PreparedOutputTestPair);
        errdefer a.destroy(pair);
        const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x59)));
        pair.chain13[0] = try makeLeaf(&pair.cert13, kp);
        const cfg13 = tls_server.Config{ .cert_chain = &pair.chain13, .signing_key = kp, .receive_record_size_limit = local_limit };
        switch (version) {
            .tls13 => {
                pair.conn = try TlsConn.init(a, cfg13);
                errdefer pair.conn.deinit();
                pair.client = .{ .tls13 = try tls_client.Client.init(a, .{ .server_name = "irc.test", .trust_anchors = &pair.chain13, .receive_record_size_limit = peer_limit }) };
            },
            .tls12 => {
                const ec = ecdsa_p256.KeyPair.generate(std.testing.io);
                pair.chain12[0] = try x509_selfsign.buildSelfSignedEcdsaP256(&pair.cert12, .{
                    .common_name = "irc.test",
                    .not_before = 1_704_067_200,
                    .not_after = 1_893_456_000,
                    .serial = &.{1},
                    .key_pair = ec,
                    .dns_names = &.{"irc.test"},
                    .is_ca = true,
                });
                pair.conn = TlsConn.initDual(a, cfg13, .{ .cert_chain = &pair.chain12, .ecdsa_p256_signing_key = ec, .receive_record_size_limit = local_limit });
                errdefer pair.conn.deinit();
                pair.client = .{ .tls12 = try tls12_client.Client.init(a, .{ .server_name = "irc.test", .trust_anchors = &pair.chain12, .now_unix_seconds = 1_735_689_600, .receive_record_size_limit = peer_limit }) };
            },
        }
        errdefer {
            pair.conn.deinit();
            switch (pair.client) {
                inline else => |*c| c.deinit(),
            }
        }
        if (version == .tls12) pair.client.tls12.force_chacha_only_for_test = chacha;
        return pair;
    }

    fn create(version: Version) !*PreparedOutputTestPair {
        const a = std.testing.allocator;
        const pair = try createUnfinished(version, false);
        errdefer pair.destroy();
        const hello = switch (pair.client) {
            inline else => |*c| try c.start(),
        };
        defer a.free(hello);
        const flight = try pair.conn.onInbound(hello);
        const finished = switch (pair.client) {
            inline else => |*c| switch (try c.feed(flight.handshake_bytes)) {
                .bytes_to_send => |b| b,
                .need_more => return error.TestUnexpectedResult,
            },
        };
        defer a.free(finished);
        const final = try pair.conn.onInbound(finished);
        if (version == .tls12) _ = try pair.client.tls12.feed(final.handshake_bytes);
        try std.testing.expect(pair.conn.handshakeDone());
        return pair;
    }

    fn destroy(self: *PreparedOutputTestPair) void {
        self.conn.deinit();
        switch (self.client) {
            inline else => |*c| c.deinit(),
        }
        std.testing.allocator.destroy(self);
    }

    fn allocatorForWrite(self: *PreparedOutputTestPair, a: Allocator) void {
        self.conn.allocator = a;
        switch (self.conn.engine) {
            inline .tls13, .tls12 => |*s| s.allocator = a,
            .undecided => unreachable,
        }
    }

    fn sequence(self: *const PreparedOutputTestPair) u64 {
        return switch (self.conn.engine) {
            inline .tls13, .tls12 => |s| s.app_write_seq,
            .undecided => unreachable,
        };
    }

    fn consume(self: *PreparedOutputTestPair, wire: []const u8) ![]u8 {
        var plain: std.ArrayList(u8) = .empty;
        errdefer plain.deinit(std.testing.allocator);
        var at: usize = 0;
        while (try completeRecordLen(wire[at..])) |len| {
            const decoded = switch (self.client) {
                inline else => |*c| try c.decrypt(wire[at..][0..len]),
            };
            defer std.testing.allocator.free(decoded);
            try plain.appendSlice(std.testing.allocator, decoded);
            at += len;
        }
        try std.testing.expectEqual(wire.len, at);
        return plain.toOwnedSlice(std.testing.allocator);
    }
};

fn preparedOutputOomProof(version: Version) !void {
    const a = std.testing.allocator;
    var failures: usize = 0;
    for (0..32) |index| {
        const pair = try PreparedOutputTestPair.create(version);
        defer pair.destroy();
        const warm = try pair.conn.write("warm");
        const received = try pair.consume(warm);
        defer a.free(received);
        try std.testing.expectEqualStrings("warm", received);
        const previous = try a.dupe(u8, pair.conn.write_buf.items);
        defer a.free(previous);
        const before = pair.sequence();
        var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        pair.allocatorForWrite(fault.allocator());
        defer pair.allocatorForWrite(a);
        const payload: [tls_record.max_plaintext_len + 100]u8 = @splat(0x61);
        const encrypted = pair.conn.write(&payload) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
            try std.testing.expectEqual(before, pair.sequence());
            try std.testing.expectEqualSlices(u8, previous, pair.conn.write_buf.items);
            pair.allocatorForWrite(a);
            const retry = try pair.conn.write(&payload);
            const restored = try pair.consume(retry);
            defer a.free(restored);
            try std.testing.expectEqualSlices(u8, &payload, restored);
            continue;
        };
        const restored = try pair.consume(encrypted);
        defer a.free(restored);
        try std.testing.expectEqualSlices(u8, &payload, restored);
        try std.testing.expect(failures >= 3);
        return;
    }
    return error.TestUnexpectedResult;
}

test "prepared application output TLS1.3 write OOM preserves sequence scratch and retry stream" {
    try preparedOutputOomProof(.tls13);
}

test "prepared application output TLS1.2 write OOM preserves sequence scratch and retry stream" {
    try preparedOutputOomProof(.tls12);
}

fn preparedOutputEngineOomProof(version: Version) !void {
    const a = std.testing.allocator;
    var failures: usize = 0;
    for (0..32) |index| {
        const pair = try PreparedOutputTestPair.create(version);
        defer pair.destroy();
        const before = pair.sequence();
        var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        pair.allocatorForWrite(fault.allocator());
        defer pair.allocatorForWrite(a);
        const payload: [tls_record.max_plaintext_len + 100]u8 = @splat(0x62);
        const encrypted = switch (pair.conn.engine) {
            inline .tls12, .tls13 => |*s| s.encrypt(&payload),
            .undecided => unreachable,
        } catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
            try std.testing.expectEqual(before, pair.sequence());
            pair.allocatorForWrite(a);
            const retry = try pair.conn.write(&payload);
            const restored = try pair.consume(retry);
            defer a.free(restored);
            try std.testing.expectEqualSlices(u8, &payload, restored);
            continue;
        };
        defer a.free(encrypted);
        const restored = try pair.consume(encrypted);
        defer a.free(restored);
        try std.testing.expectEqualSlices(u8, &payload, restored);
        try std.testing.expect(failures >= 2);
        return;
    }
    return error.TestUnexpectedResult;
}

test "prepared application output TLS1.3 engine OOM never advances a partial batch" {
    try preparedOutputEngineOomProof(.tls13);
}

test "prepared application output TLS1.2 engine OOM never advances a partial batch" {
    try preparedOutputEngineOomProof(.tls12);
}

const PreparedOutputQueue = struct {
    send_buf: [8]u8 = undefined,
    send_len: usize = 0,
    send_offset: usize = 0,
    send_armed: bool = false,
    sendq_cap: usize = 1,
    send_overflow: std.ArrayList(u8) = .empty,
    overflow_allocator: Allocator,
};

fn preparedOutputCustodyProof(version: Version) !void {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.create(version);
    defer pair.destroy();
    const warm = try pair.conn.write("warm");
    const received = try pair.consume(warm);
    defer a.free(received);
    const previous = try a.dupe(u8, pair.conn.write_buf.items);
    defer a.free(previous);
    const before = pair.sequence();
    const inputs: []const []const u8 = &.{ "first\r\n", "second\r\n" };
    const sendq = @import("sendq.zig");
    var q: PreparedOutputQueue = .{ .overflow_allocator = a };
    defer q.send_overflow.deinit(a);

    var capped = try pair.conn.prepareWriteBatch(inputs);
    defer capped.deinit();
    const expected = try a.dupe(u8, capped.bytes());
    defer a.free(expected);
    try std.testing.expectError(error.OutputTooSmall, sendq.prepareAppend(&q, capped.bytes().len));
    capped.abort();
    try std.testing.expectEqual(before, pair.sequence());
    try std.testing.expectEqualSlices(u8, previous, pair.conn.write_buf.items);
    try std.testing.expectEqual(@as(u64, 0), sendq.backlog(&q));

    // Capacity is sufficient but allocating physical overflow fails. Neither
    // failure may leave a prefix owning TLS counters or public queue bytes.
    q.sendq_cap = expected.len;
    var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    q.overflow_allocator = fault.allocator();
    var oom = try pair.conn.prepareWriteBatch(inputs);
    defer oom.deinit();
    try std.testing.expectEqualSlices(u8, expected, oom.bytes());
    try std.testing.expectError(error.OutputTooSmall, sendq.prepareAppend(&q, oom.bytes().len));
    oom.abort();
    try std.testing.expectEqual(before, pair.sequence());
    try std.testing.expectEqualSlices(u8, previous, pair.conn.write_buf.items);
    try std.testing.expectEqual(@as(u64, 0), sendq.backlog(&q));

    q.overflow_allocator = a;
    var retry = try pair.conn.prepareWriteBatch(inputs);
    defer retry.deinit();
    try std.testing.expectEqualSlices(u8, expected, retry.bytes());
    var custody = try sendq.prepareAppend(&q, retry.bytes().len);
    custody.commit(retry.bytes());
    retry.commit();
    try std.testing.expectEqual(before + 2, pair.sequence());
    try std.testing.expectEqualSlices(u8, expected, q.send_overflow.items);
    // Prepared output never replaces the legacy borrowed write() scratch.
    try std.testing.expectEqualSlices(u8, previous, pair.conn.write_buf.items);
    const decoded = try pair.consume(q.send_overflow.items);
    defer a.free(decoded);
    try std.testing.expectEqualStrings("first\r\nsecond\r\n", decoded);
}

test "prepared application output TLS1.3 whole SendQ cap and OOM rejection retry exact ciphertext" {
    try preparedOutputCustodyProof(.tls13);
}

test "prepared application output TLS1.2 whole SendQ cap and OOM rejection retry exact ciphertext" {
    try preparedOutputCustodyProof(.tls12);
}

fn preparedOutputExclusiveProof(version: Version) !void {
    const pair = try PreparedOutputTestPair.create(version);
    defer pair.destroy();
    const before = pair.sequence();
    var held = try pair.conn.prepareWriteBatch(&.{"held"});
    defer held.deinit();
    try std.testing.expect(held.canCommit());
    try std.testing.expectError(error.BadState, pair.conn.prepareWriteBatch(&.{"other"}));
    try std.testing.expectError(error.BadState, pair.conn.write("other"));
    try std.testing.expectError(error.BadState, pair.conn.onInbound("partial record"));
    try std.testing.expectEqual(@as(usize, 0), pair.conn.recv_buf.items.len);
    try std.testing.expectError(error.BadState, pair.conn.exportResume());
    switch (pair.conn.engine) {
        inline .tls12, .tls13 => |*engine| {
            try std.testing.expectError(error.BadState, engine.encrypt("other"));
            try std.testing.expectError(error.BadState, engine.decrypt(&.{}));
            try std.testing.expectError(error.BadState, engine.feed(&.{}));
            try std.testing.expectError(error.BadState, engine.exportResume());
            try std.testing.expect(engine.takeAlert(error.BadRecord) == null);
        },
        .undecided => unreachable,
    }
    if (version == .tls13) {
        try std.testing.expectError(error.BadState, pair.conn.engine.tls13.initiateKeyUpdate(true));
        try std.testing.expect(pair.conn.engine.tls13.ktlsTxParams() == null);
    }
    try std.testing.expectEqual(before, pair.sequence());
    held.abort();
    try std.testing.expect(!held.canCommit());
    var next = try pair.conn.prepareWriteBatch(&.{"accepted"});
    defer next.deinit();
    // Reusing a completed handle cannot release the next generation's TX lease.
    held.abort();
    try std.testing.expect(next.canCommit());
    next.commit();
    try std.testing.expect(!next.canCommit());
    const decoded = try pair.consume(next.bytes());
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("accepted", decoded);
    _ = try pair.conn.exportResume();
}

test "prepared application output TLS1.3 exclusive abort reentry key update and Helix barrier" {
    try preparedOutputExclusiveProof(.tls13);
}

test "prepared application output TLS1.2 exclusive abort reentry and Helix barrier" {
    try preparedOutputExclusiveProof(.tls12);
}

fn preparedOutputExhaustionProof(version: Version) !void {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.create(version);
    defer pair.destroy();
    const last = std.math.maxInt(u64) - 1;
    switch (pair.conn.engine) {
        inline .tls12, .tls13 => |*engine| engine.app_write_seq = last,
        .undecided => unreachable,
    }
    switch (pair.client) {
        inline else => |*client| client.app_read_seq = last,
    }
    var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    pair.allocatorForWrite(fault.allocator());
    defer pair.allocatorForWrite(a);
    try std.testing.expectError(error.SequenceExhausted, pair.conn.prepareWriteBatch(&.{ "one", "two" }));
    try std.testing.expectEqual(last, pair.sequence());
    try std.testing.expect(!pair.conn.hasPreparedWrite());
    pair.allocatorForWrite(a);
    var final = try pair.conn.prepareWriteBatch(&.{"last"});
    defer final.deinit();
    try std.testing.expectEqual(last, pair.sequence());
    final.commit();
    try std.testing.expectEqual(std.math.maxInt(u64), pair.sequence());
    const decoded = try pair.consume(final.bytes());
    defer a.free(decoded);
    try std.testing.expectEqualStrings("last", decoded);
    try std.testing.expectError(error.SequenceExhausted, pair.conn.write("exhausted"));
    try std.testing.expectEqual(std.math.maxInt(u64), pair.sequence());
}

test "prepared application output TLS1.3 whole batch sequence exhaustion precedes allocation" {
    try preparedOutputExhaustionProof(.tls13);
}

test "prepared application output TLS1.2 whole batch sequence exhaustion precedes allocation" {
    try preparedOutputExhaustionProof(.tls12);
}

fn preparedOutputFragmentProof(version: Version) !void {
    const pair = try PreparedOutputTestPair.create(version);
    defer pair.destroy();
    // TLS1.3's inner content type consumes one byte of the peer's limit;
    // TLS1.2 limits plaintext directly. Include outer 16KiB boundaries and an
    // empty explicit input in one atomic batch.
    switch (pair.conn.engine) {
        inline .tls12, .tls13 => |*engine| engine.peer_record_size_limit = 100,
        .undecided => unreachable,
    }
    const payload: [tls_record.max_plaintext_len + 100]u8 = @splat(0x63);
    const limit: usize = if (version == .tls13) 99 else 100;
    const expected_records = 1 + (tls_record.max_plaintext_len + limit - 1) / limit + (100 + limit - 1) / limit;
    const before = pair.sequence();
    var prepared = try pair.conn.prepareWriteBatch(&.{ &.{}, &payload });
    defer prepared.deinit();
    try std.testing.expectEqual(before, pair.sequence());
    var count: usize = 0;
    var at: usize = 0;
    while (try completeRecordLen(prepared.bytes()[at..])) |len| {
        const overhead: usize = switch (pair.conn.engine) {
            .tls13 => 5 + 16, // All supported TLS1.3 suites use a 16-byte AEAD tag.
            .tls12 => |engine| 5 + engine.selected_suite.?.explicitNonceLen() + engine.selected_suite.?.tagLen(),
            .undecided => unreachable,
        };
        try std.testing.expect(len <= 100 + overhead);
        at += len;
        count += 1;
    }
    try std.testing.expectEqual(prepared.bytes().len, at);
    try std.testing.expectEqual(expected_records, count);
    prepared.commit();
    try std.testing.expectEqual(before + expected_records, pair.sequence());
    const decoded = try pair.consume(prepared.bytes());
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &payload, decoded);
    // No input is different from an explicit empty input: no nonce consumed.
    var empty = try pair.conn.prepareWriteBatch(&.{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.bytes().len);
    const after = pair.sequence();
    empty.commit();
    try std.testing.expectEqual(after, pair.sequence());
}

test "prepared application output TLS1.3 negotiated fragmentation and empty batch" {
    try preparedOutputFragmentProof(.tls13);
}

test "prepared application output TLS1.2 negotiated fragmentation and empty batch" {
    try preparedOutputFragmentProof(.tls12);
}

const tls12_client = @import("../crypto/tls12_client.zig");
const tls12 = @import("../crypto/tls12.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");

test "owned OCSP staples survive source publication and share only aliased generations" {
    const allocator = std.testing.allocator;
    var shared = [_]u8{ 1, 2, 3, 4 };
    var conn = try TlsConn.initDualOwnedStaple(
        allocator,
        .{ .cert_chain = &.{}, .ocsp_staple = &shared },
        .{ .cert_chain = &.{}, .ocsp_staple = &shared },
    );
    defer conn.deinit();
    shared[0] = 9;
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, conn.cfg13.ocsp_staple);
    try std.testing.expect(conn.cfg13.ocsp_staple.ptr == conn.cfg12.?.ocsp_staple.ptr);
    try std.testing.expect(conn.ocsp_owned13 != null and conn.ocsp_owned12 == null);

    var other = [_]u8{ 5, 6, 7 };
    var distinct = try TlsConn.initDualOwnedStaple(
        allocator,
        .{ .cert_chain = &.{}, .ocsp_staple = &shared },
        .{ .cert_chain = &.{}, .ocsp_staple = &other },
    );
    defer distinct.deinit();
    other[0] = 8;
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7 }, distinct.cfg12.?.ocsp_staple);
    try std.testing.expect(distinct.cfg13.ocsp_staple.ptr != distinct.cfg12.?.ocsp_staple.ptr);
}

test "borrowed OCSP staple stays live through incomplete handshake and clears on completion" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x6b)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const leaf = try @import("../crypto/x509.zig").parse(der);
    const staple = try @import("../crypto/ocsp.zig").testSignedOcspResponse(alloc, kp, leaf.serial_der, .good, null);
    defer alloc.free(staple);

    for (0..2) |variant| {
        const cfg13 = tls_server.Config{ .cert_chain = &.{der}, .signing_key = kp, .ocsp_staple = staple };
        var conn = if (variant == 0)
            try TlsConn.initBorrowed(alloc, cfg13)
        else
            TlsConn.initDual(alloc, cfg13, .{ .cert_chain = &.{}, .ocsp_staple = staple });
        defer conn.deinit();
        try std.testing.expect(conn.ocsp_owned13 == null and conn.ocsp_owned12 == null);
        try std.testing.expect(conn.cfg13.ocsp_staple.ptr == staple.ptr);
        if (conn.cfg12) |cfg| try std.testing.expect(cfg.ocsp_staple.ptr == staple.ptr);

        var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
        defer client.deinit();
        const ch = try client.start();
        defer alloc.free(ch);
        const split = ch.len / 2;
        const partial = try conn.onInbound(ch[0..split]);
        try std.testing.expectEqual(@as(usize, 0), partial.handshake_bytes.len);
        try std.testing.expect(!conn.handshakeDone());
        try std.testing.expect(conn.cfg13.ocsp_staple.ptr == staple.ptr);

        const flight = try conn.onInbound(ch[split..]);
        try std.testing.expect(flight.handshake_bytes.len != 0);
        try std.testing.expect(!conn.handshakeDone());
        try std.testing.expect(conn.cfg13.ocsp_staple.ptr == staple.ptr);
        const finished = switch (try client.feed(flight.handshake_bytes)) {
            .bytes_to_send => |bytes| bytes,
            .need_more => return error.TestUnexpectedResult,
        };
        defer alloc.free(finished);
        _ = try conn.onInbound(finished);
        try std.testing.expect(conn.handshakeDone());
        try std.testing.expectEqual(@as(usize, 0), conn.cfg13.ocsp_staple.len);
        if (conn.cfg12) |cfg| try std.testing.expectEqual(@as(usize, 0), cfg.ocsp_staple.len);
        try std.testing.expectEqual(@as(usize, 0), conn.engine.tls13.config.ocsp_staple.len);
    }
}

test "version-dispatch: a TLS 1.3 client completes through a dual TlsConn" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    // ECDSA cert/key for the (unused here) 1.2 leg.
    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ec_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x34 },
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var conn = TlsConn.initDual(
        alloc,
        .{ .cert_chain = &.{der}, .signing_key = kp },
        .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key },
    );
    defer conn.deinit();

    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh = try conn.onInbound(ch);
    try std.testing.expectEqual(Version.tls13, conn.negotiatedVersion().?);
    const cfin = switch (try client.feed(sh.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    const c2s = try client.encrypt("hello 1.3");
    defer alloc.free(c2s);
    const out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("hello 1.3", out.plaintext);
    const cipher = try conn.write("reply 1.3");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("reply 1.3", got);
}

test "version-dispatch: a fragmented TLS 1.2 ClientHello completes through a dual TlsConn" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x55)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp); // 1.3 leg (unused here)

    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ec_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 1, 2, 3, 4 },
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var conn = TlsConn.initDual(
        alloc,
        .{ .cert_chain = &.{der}, .signing_key = kp },
        .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key },
    );
    defer conn.deinit();

    var client = try tls12_client.Client.init(alloc, .{
        .server_name = "irc.test",
        .trust_anchors = &.{ec_der},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const ch_record = (try tls12.completeRecord(ch)) orelse return error.TestUnexpectedResult;
    const ch_first = try tls12.writePlainRecord(alloc, .handshake, ch_record.fragment[0..2]);
    defer alloc.free(ch_first);
    const ch_second = try tls12.writePlainRecord(alloc, .handshake, ch_record.fragment[2..]);
    defer alloc.free(ch_second);
    const fragmented_ch = try alloc.alloc(u8, ch_first.len + ch_second.len);
    defer alloc.free(fragmented_ch);
    @memcpy(fragmented_ch[0..ch_first.len], ch_first);
    @memcpy(fragmented_ch[ch_first.len..], ch_second);
    const sf = try conn.onInbound(fragmented_ch);
    try std.testing.expectEqual(Version.tls12, conn.negotiatedVersion().?);
    const cf = switch (try client.feed(sf.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cf);
    const sfin = try conn.onInbound(cf);
    _ = try client.feed(sfin.handshake_bytes);
    try std.testing.expect(conn.handshakeDone());
    try std.testing.expect(client.handshakeDone());

    const c2s = try client.encrypt("hello 1.2");
    defer alloc.free(c2s);
    const out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("hello 1.2", out.plaintext);
    const cipher = try conn.write("reply 1.2");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("reply 1.2", got);
}

test "version-dispatch: dual TlsConn accepts a padded 20KiB fragmented TLS 1.2 ClientHello" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x57)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ec_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 1, 2, 3, 5 },
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var conn = TlsConn.initDual(
        alloc,
        .{ .cert_chain = &.{der}, .signing_key = kp },
        .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key },
    );
    defer conn.deinit();

    var client = try tls12_client.Client.init(alloc, .{
        .server_name = "irc.test",
        .trust_anchors = &.{ec_der},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const original = try client.start();
    defer alloc.free(original);
    const original_record = (try tls12.completeRecord(original)) orelse return error.TestUnexpectedResult;
    const padded_hello = try padTls12ClientHello(alloc, original_record.fragment, 20 * 1024);
    defer alloc.free(padded_hello);
    // Keep the peer's transcript aligned with the exact wire ClientHello.
    client.transcript.clearRetainingCapacity();
    try client.transcript.appendSlice(alloc, padded_hello);

    // Split every handshake byte into a separate legal record. This exercises
    // the adapter's bounded cursor path with enough records to catch repeated
    // front-compaction while retaining the end-to-end handshake/app-data proof.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(alloc);
    try wire.ensureTotalCapacity(alloc, padded_hello.len * (tls_record.record_header_len + 1));
    for (padded_hello) |byte| {
        wire.appendSliceAssumeCapacity(&.{
            @backingInt(tls_record.ContentType.handshake),
            0x03,
            0x03,
            0x00,
            0x01,
            byte,
        });
    }

    const server_flight = try conn.onInbound(wire.items);
    try std.testing.expectEqual(Version.tls12, conn.negotiatedVersion().?);
    const client_flight = switch (try client.feed(server_flight.handshake_bytes)) {
        .bytes_to_send => |bytes| bytes,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(client_flight);
    const final_flight = try conn.onInbound(client_flight);
    _ = try client.feed(final_flight.handshake_bytes);
    try std.testing.expect(conn.handshakeDone());
    try std.testing.expect(client.handshakeDone());

    const app = try client.encrypt("padded client hello app data");
    defer alloc.free(app);
    const plaintext = try conn.onInbound(app);
    try std.testing.expectEqualStrings("padded client hello app data", plaintext.plaintext);
    const reply = try conn.write("padded reply");
    const opened = try client.decrypt(reply);
    defer alloc.free(opened);
    try std.testing.expectEqualStrings("padded reply", opened);
}

test "version-dispatch: dual TlsConn applies the shared total handshake bound" {
    const alloc = std.testing.allocator;
    var conn = TlsConn.initDual(alloc, .{ .cert_chain = &.{} }, .{ .cert_chain = &.{}, .ecdsa_p256_signing_key = null });
    defer conn.deinit();
    // Header declares one byte beyond the shared 1 MiB complete-message cap.
    const oversized = [_]u8{ 1, 0x0f, 0xff, 0xfd };
    const record = try tls12.writePlainRecord(alloc, .handshake, &oversized);
    defer alloc.free(record);
    try std.testing.expectError(error.BadHandshake, conn.onInbound(record));
}

test "version-dispatch: out-of-order first flight is unexpected_message, not decode_error" {
    // RFC 8446 §6.2 / RFC 5246 §7.2.2: a non-ClientHello first message, or a
    // ClientHello coalesced with a following handshake message in the same
    // flight before any ServerHello, is an unexpected message (alert 10).
    // BoGo: WrongMessageType-*ClientHello-TLS, PartialClientKeyExchangeWithClientHello.
    const alloc = std.testing.allocator;
    const minimal_hello = [_]u8{ 1, 0, 0, 0 };
    const cke_first = [_]u8{ 16, 0, 0, 0 };
    const hello_then_partial = minimal_hello ++ [_]u8{ 16, 0, 0 };
    for ([_][]const u8{ &cke_first, &hello_then_partial }) |flight| {
        var conn = TlsConn.initDual(alloc, .{ .cert_chain = &.{} }, .{ .cert_chain = &.{}, .ecdsa_p256_signing_key = null });
        defer conn.deinit();
        const record = try tls12.writePlainRecord(alloc, .handshake, flight);
        defer alloc.free(record);
        try std.testing.expectError(error.UnexpectedMessage, conn.onInbound(record));
        const alert = conn.takeAlert(error.UnexpectedMessage) orelse return error.TestUnexpectedResult;
        defer alloc.free(alert);
        // Plaintext alert record: type 21, fatal(2), unexpected_message(10).
        try std.testing.expectEqual(@as(u8, 21), alert[0]);
        try std.testing.expectEqualSlices(u8, &.{ 2, 10 }, alert[alert.len - 2 ..]);
    }
}

test "version-dispatch: dual TlsConn rejects oversized plaintext record payload" {
    const alloc = std.testing.allocator;
    var conn = TlsConn.initDual(alloc, .{ .cert_chain = &.{} }, .{ .cert_chain = &.{}, .ecdsa_p256_signing_key = null });
    defer conn.deinit();

    const payload_len = tls_record.max_plaintext_len + 1;
    const payload = try alloc.alloc(u8, payload_len);
    defer alloc.free(payload);
    try std.testing.expectError(error.PlaintextTooLong, tls12.writePlainRecord(alloc, .handshake, payload));

    const wire = try alloc.alloc(u8, tls_record.record_header_len + payload_len);
    defer alloc.free(wire);
    wire[0] = @backingInt(tls_record.ContentType.handshake);
    std.mem.writeInt(u16, wire[1..3], 0x0303, .big);
    std.mem.writeInt(u16, wire[3..5], @intCast(payload_len), .big);
    @memset(wire[tls_record.record_header_len..], 0);
    try std.testing.expectError(error.RecordOverflow, conn.onInbound(wire));
}

test "version-dispatch: dual TlsConn rejects malformed ClientHello at shared handshake cap" {
    const alloc = std.testing.allocator;
    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var cert_buf: [2048]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{1},
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
    var conn = TlsConn.initDual(alloc, .{ .cert_chain = &.{} }, .{ .cert_chain = &.{cert}, .ecdsa_p256_signing_key = ec_key });
    defer conn.deinit();

    const total_len = tls_handshake_reassembly.max_message_len;
    const handshake = try alloc.alloc(u8, total_len);
    defer alloc.free(handshake);
    handshake[0] = 1;
    std.mem.writeInt(u24, handshake[1..4], @intCast(total_len - 4), .big);
    // Invalid client_version makes this exact-cap message fail closed after
    // the adapter has reassembled and dispatched it to the TLS 1.2 parser.
    @memset(handshake[4..], 0);

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(alloc);
    const fragment_cap = 16;
    const record_count = (handshake.len + fragment_cap - 1) / fragment_cap;
    const wire_len = handshake.len + record_count * tls_record.record_header_len;
    try wire.ensureTotalCapacity(alloc, wire_len);
    var offset: usize = 0;
    while (offset < handshake.len) {
        const fragment_len = @min(fragment_cap, handshake.len - offset);
        const fragment_wire_len: u16 = @intCast(fragment_len);
        wire.appendSliceAssumeCapacity(&.{
            @backingInt(tls_record.ContentType.handshake),
            0x03,
            0x03,
            @intCast(fragment_wire_len >> 8),
            @truncate(fragment_wire_len),
        });
        wire.appendSliceAssumeCapacity(handshake[offset .. offset + fragment_len]);
        offset += fragment_len;
    }
    try std.testing.expectEqual(record_count, wire.items.len / (tls_record.record_header_len + fragment_cap));
    try std.testing.expectError(error.ProtocolVersion, conn.onInbound(wire.items));
}

fn padTls12ClientHello(allocator: Allocator, handshake: []const u8, padding_len: usize) Error![]u8 {
    if (handshake.len < 4 or handshake[0] != 1 or padding_len > std.math.maxInt(u16)) return error.BadHandshake;
    const body_len = (@as(usize, handshake[1]) << 16) | (@as(usize, handshake[2]) << 8) | handshake[3];
    if (body_len + 4 != handshake.len) return error.BadHandshake;
    const body = handshake[4..];
    var offset: usize = 34;
    if (offset >= body.len) return error.BadHandshake;
    offset += 1 + body[offset];
    if (offset + 2 > body.len) return error.BadHandshake;
    const suites_len = (@as(usize, body[offset]) << 8) | body[offset + 1];
    offset += 2 + suites_len;
    if (offset >= body.len) return error.BadHandshake;
    offset += 1 + body[offset];
    if (offset + 2 > body.len) return error.BadHandshake;
    const extensions_len = (@as(usize, body[offset]) << 8) | body[offset + 1];
    if (offset + 2 + extensions_len != body.len) return error.BadHandshake;
    const new_extensions_len = std.math.add(usize, extensions_len, 4 + padding_len) catch return error.BadHandshake;
    if (new_extensions_len > std.math.maxInt(u16)) return error.BadHandshake;
    const output = try allocator.alloc(u8, handshake.len + 4 + padding_len);
    errdefer allocator.free(output);
    const extension_bytes_start = 4 + offset + 2;
    @memcpy(output[0 .. extension_bytes_start + extensions_len], handshake[0 .. extension_bytes_start + extensions_len]);
    std.mem.writeInt(u16, output[4 + offset ..][0..2], @intCast(new_extensions_len), .big);
    const padding_header = extension_bytes_start + extensions_len;
    output[padding_header] = 0;
    output[padding_header + 1] = 21;
    std.mem.writeInt(u16, output[padding_header + 2 ..][0..2], @intCast(padding_len), .big);
    @memset(output[padding_header + 4 ..], 0);
    const new_body_len = body_len + 4 + padding_len;
    output[1] = @intCast((new_body_len >> 16) & 0xff);
    output[2] = @intCast((new_body_len >> 8) & 0xff);
    output[3] = @intCast(new_body_len & 0xff);
    return output;
}

test "version-dispatch: failed TLS 1.2 init leaves engine undecided" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x56)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp); // 1.3 leg (unused here)

    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ec_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 5, 6, 7, 8 },
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var conn = TlsConn.initDual(
        alloc,
        .{ .cert_chain = &.{der}, .signing_key = kp },
        .{ .cert_chain = &.{ec_der} },
    );
    defer conn.deinit();

    var client = try tls12_client.Client.init(alloc, .{
        .server_name = "irc.test",
        .trust_anchors = &.{ec_der},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    try std.testing.expectError(error.NoSigningKey, conn.onInbound(ch));
    try std.testing.expect(conn.negotiatedVersion() == null);
    const alert = conn.takeAlert(error.NoSigningKey) orelse return error.TestUnexpectedResult;
    defer alloc.free(alert);
    try std.testing.expect(alert.len != 0);
}

test "TLS 1.2 session ticket resumes across dual TlsConn instances (RFC 5077)" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x57)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp); // 1.3 leg (unused here)

    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ec_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 1, 2, 3, 4 },
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    const ticket_key = @as([@sizeOf(tls_resumption.TicketKey)]u8, @splat(0x42));
    var guard = tls_resumption.ReplayGuard{};
    const cfg13 = tls_server.Config{ .cert_chain = &.{der}, .signing_key = kp };
    const cfg12 = tls12_server.Config{
        .cert_chain = &.{ec_der},
        .ecdsa_p256_signing_key = ec_key,
        .enable_session_tickets = true,
        .ticket_key = ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_000,
    };

    // First connection: full handshake that issues a ticket.
    var stored: []u8 = undefined;
    {
        var conn = TlsConn.initDual(alloc, cfg13, cfg12);
        defer conn.deinit();
        var client = try tls12_client.Client.init(alloc, .{
            .server_name = "irc.test",
            .trust_anchors = &.{ec_der},
            .now_unix_seconds = 1_735_689_600,
        });
        defer client.deinit();
        try client.requestSessionTicket();

        const ch = try client.start();
        defer alloc.free(ch);
        const sf = try conn.onInbound(ch);
        try std.testing.expectEqual(Version.tls12, conn.negotiatedVersion().?);
        const cf = switch (try client.feed(sf.handshake_bytes)) {
            .bytes_to_send => |b| b,
            .need_more => return error.TestUnexpectedResult,
        };
        defer alloc.free(cf);
        const sfin = try conn.onInbound(cf);
        _ = try client.feed(sfin.handshake_bytes);
        try std.testing.expect(conn.handshakeDone());
        try std.testing.expect(client.handshakeDone());
        stored = client.takeSessionTicket() orelse return error.TestUnexpectedResult;
    }
    defer alloc.free(stored);

    // Second connection presents the ticket and resumes (abbreviated handshake).
    var conn2 = TlsConn.initDual(alloc, cfg13, cfg12);
    defer conn2.deinit();
    var client2 = try tls12_client.Client.init(alloc, .{
        .server_name = "irc.test",
        .trust_anchors = &.{ec_der},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client2.deinit();
    try client2.setSessionTicket(stored);

    const ch2 = try client2.start();
    defer alloc.free(ch2);
    const sf2 = try conn2.onInbound(ch2);
    try std.testing.expectEqual(Version.tls12, conn2.negotiatedVersion().?);
    const cf2 = switch (try client2.feed(sf2.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cf2);
    const fin2 = try conn2.onInbound(cf2);
    _ = fin2;
    try std.testing.expect(conn2.handshakeDone());
    try std.testing.expect(client2.handshakeDone());

    // Resumed peers share traffic keys: app data flows both ways.
    const c2s = try client2.encrypt("resumed 1.2");
    defer alloc.free(c2s);
    const out = try conn2.onInbound(c2s);
    try std.testing.expectEqualStrings("resumed 1.2", out.plaintext);
    const cipher = try conn2.write("reply resumed");
    const got = try client2.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("reply resumed", got);
}

test {
    std.testing.refAllDecls(@This());
}

// ---------------------------------------------------------------------------
// Adversarial corpus (`zig build test-exploit`).
//
// `TlsConn` is the daemon's real listener edge: it frames records BEFORE either
// inner engine sees them, so a header the framer mistakes for "incomplete" is
// held in `recv_buf` until the idle timeout rather than rejected.
// ---------------------------------------------------------------------------

test "exploit: an oversize record declaration cannot park 64 KiB in the daemon framer" {
    // The wire length field is a u16, so a peer can declare 0xFFFF while both
    // engines cap TLSCiphertext at 2^14+256. Uncapped, this header alone made the
    // daemon wait for ~64 KiB of a record guaranteed to be rejected, and the
    // inner engine's own cap never ran because the record never completed.
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x51)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();

    // Only the 5-byte header is ever sent; the declaration alone must fail.
    const header = [_]u8{ 22, 0x03, 0x03, 0xFF, 0xFF };
    try std.testing.expectError(error.RecordOverflow, conn.onInbound(&header));
}

test "exploit: the daemon framer rejects an unknown record content type" {
    // An unrecognized outer type must terminate, not be treated as "need more".
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x52)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    for ([_]u8{ 0, 19, 24, 25, 0xFF }) |bad_type| {
        var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
        defer conn.deinit();
        const rec = [_]u8{ bad_type, 0x03, 0x03, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };
        try std.testing.expectError(error.BadRecord, conn.onInbound(&rec));
    }
}

test "exploit: a hostile record after a valid ClientHello is rejected mid-handshake" {
    // The engine is selected and the server flight already emitted, so this
    // exercises the steady-state framing loop rather than `detectVersion`.
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x53)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const flight = try conn.onInbound(ch);
    try std.testing.expect(flight.handshake_bytes.len != 0);

    const oversize = [_]u8{ 23, 0x03, 0x03, 0xFF, 0xFF };
    try std.testing.expectError(error.RecordOverflow, conn.onInbound(&oversize));
}

test "exploit: a legitimate maximum-size record is still accepted (no regression)" {
    // The cap must sit exactly at 2^14+256, not below it: a full-size application
    // record is legal on both arms and must survive the new check.
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x54)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const flight = try conn.onInbound(ch);
    const cfin = switch (try client.feed(flight.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // A full plaintext record encrypts to just under the ciphertext cap.
    const payload = try alloc.alloc(u8, tls_record.max_plaintext_len);
    defer alloc.free(payload);
    @memset(payload, 'A');
    const sealed = try client.encrypt(payload);
    defer alloc.free(sealed);
    const body_len = std.mem.readInt(u16, sealed[3..5], .big);
    try std.testing.expect(body_len <= tls_record.max_ciphertext_len);

    const out = try conn.onInbound(sealed);
    try std.testing.expectEqual(payload.len, out.plaintext.len);
}

test "TLS record limit: adapter with TX offload never returns raw software fatal ciphertext" {
    const pair = try PreparedOutputTestPair.create(.tls13);
    defer pair.destroy();
    const before = pair.sequence();
    pair.conn.ktls_tx_offloaded = true;
    try std.testing.expect(pair.conn.takeAlert(error.RecordOverflow) == null);
    try std.testing.expectEqual(before, pair.sequence());
    pair.conn.ktls_tx_offloaded = false;
    const wire = pair.conn.takeAlert(error.RecordOverflow).?;
    defer std.testing.allocator.free(wire);
    switch (pair.client) {
        .tls13 => |*client| {
            try std.testing.expectError(error.TlsAlert, client.decryptApp(wire));
            try std.testing.expectEqual(@as(u8, 22), @backingInt(client.last_alert.?.description));
        },
        else => unreachable,
    }
}

test "TLS record limit: actual adapter peer fatal closes without response" {
    for ([_]Version{ .tls12, .tls13 }) |version| {
        const pair = try PreparedOutputTestPair.create(version);
        defer pair.destroy();
        const wire = switch (pair.client) {
            inline else => |*client| client.takeAlert(error.BadHandshake) orelse return error.TestUnexpectedResult,
        };
        defer std.testing.allocator.free(wire);
        const tx_before = pair.sequence();
        try std.testing.expectError(error.TlsAlert, pair.conn.onInbound(wire));
        try std.testing.expect(!pair.conn.handshakeDone());
        try std.testing.expect(pair.conn.takeAlert(error.TlsAlert) == null);
        try std.testing.expectEqual(tx_before, pair.sequence());
    }
}

fn recordLimitConnectedPair12(chacha: bool) !*PreparedOutputTestPair {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.createUnfinished(.tls12, chacha);
    errdefer pair.destroy();
    const hello = try pair.client.tls12.start();
    defer a.free(hello);
    const flight = try pair.conn.onInbound(hello);
    const finished = switch (try pair.client.tls12.feed(flight.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer a.free(finished);
    const final = try pair.conn.onInbound(finished);
    _ = try pair.client.tls12.feed(final.handshake_bytes);
    try std.testing.expect(pair.conn.handshakeDone());
    try std.testing.expect(pair.client.tls12.handshakeDone());
    return pair;
}

fn recordLimitMalformed12Proof(oversized: bool) !void {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |chacha| {
        for ([_]bool{ false, true }) |at_server| {
            for (0..@as(usize, if (oversized) 1 else 4)) |length_case| {
                const pair = try recordLimitConnectedPair12(chacha);
                defer pair.destroy();
                const suite = pair.client.tls12.selected_suite.?;
                const minimum = suite.explicitNonceLen() + suite.tagLen();
                const short_lengths = [_]usize{ 0, 1, suite.explicitNonceLen(), minimum - 1 };
                const length = if (oversized) minimum + 16385 else short_lengths[length_case];
                const wire = try a.alloc(u8, tls_record.record_header_len + length);
                defer a.free(wire);
                @memset(wire, 0);
                wire[0] = @backingInt(tls_record.ContentType.application_data);
                wire[1] = 3;
                wire[2] = 3;
                std.mem.writeInt(u16, wire[3..5], @intCast(wire.len - tls_record.record_header_len), .big);
                const sequence = if (at_server) pair.conn.engine.tls12.app_write_seq else pair.client.tls12.app_write_seq;
                const failure: anyerror = if (at_server) blk: {
                    _ = pair.conn.onInbound(wire) catch |err| break :blk err;
                    return error.TestUnexpectedResult;
                } else blk: {
                    const decoded = pair.client.tls12.decrypt(wire) catch |err| break :blk err;
                    a.free(decoded);
                    return error.TestUnexpectedResult;
                };
                const alert = if (at_server) pair.conn.takeAlert(failure).? else pair.client.tls12.takeAlert(@errorCast(failure)).?;
                defer a.free(alert);
                const keys = if (at_server) &pair.client.tls12.keys.server_write else &pair.conn.engine.tls12.keys.client_write;
                const opened = try tls12.openRecordAlloc(a, suite, keys, sequence, alert);
                defer a.free(opened.plaintext);
                try std.testing.expectEqual(tls12.ContentType.alert, opened.content_type);
                try std.testing.expectEqualSlices(u8, &.{ 2, if (oversized) 22 else 20 }, opened.plaintext);
                try std.testing.expectEqual(if (oversized) error.RecordOverflow else error.AeadAuthFailed, failure);
            }
        }
    }
}

test "TLS record limit: TLS12 actual pair short protected record emits fatal20" {
    try recordLimitMalformed12Proof(false);
}

test "TLS record limit: TLS12 actual pair protocol overflow emits fatal22" {
    try recordLimitMalformed12Proof(true);
}

test "TLS record limit: adapter retains TLS12 committed Finished before coalesced error alert" {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.createUnfinished(.tls12, false);
    defer pair.destroy();
    const hello = try pair.client.tls12.start();
    defer a.free(hello);
    const flight = try pair.conn.onInbound(hello);
    const finished = switch (try pair.client.tls12.feed(flight.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer a.free(finished);
    const bad = [_]u8{ 23, 3, 3, 0, 0 };
    const coalesced = try std.mem.concat(a, u8, &.{ finished, &bad });
    defer a.free(coalesced);
    const failure = blk: {
        _ = pair.conn.onInbound(coalesced) catch |err| break :blk err;
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u64, 1), pair.conn.engine.tls12.app_write_seq);
    const terminal = pair.conn.takeAlert(failure).?;
    defer a.free(terminal);
    // The peer must receive CCS and sequence-zero Finished before the fatal
    // sequence-one alert, even though the inbound call returned an error.
    try std.testing.expectEqual(@as(u8, 20), terminal[0]);
    var at: usize = 0;
    while (!pair.client.tls12.handshakeDone()) {
        const len = (try completeRecordLen(terminal[at..])).?;
        _ = try pair.client.tls12.feed(terminal[at..][0..len]);
        at += len;
    }
    const opened = try tls12.openRecordAlloc(a, pair.client.tls12.selected_suite.?, &pair.client.tls12.keys.server_write, 1, terminal[at..]);
    defer a.free(opened.plaintext);
    try std.testing.expectEqualSlices(u8, &.{ 2, 20 }, opened.plaintext);
    try std.testing.expectError(error.TlsAlert, pair.client.tls12.decrypt(terminal[at..]));
    try std.testing.expect(pair.conn.takeAlert(failure) == null);
}

test "TLS record limit: adapter output allocation failure retains committed actual TLS13 flight" {
    const a = std.testing.allocator;
    var before_consume: usize = 0;
    var after_consume: usize = 0;
    for (0..32) |index| {
        const pair = try PreparedOutputTestPair.createUnfinished(.tls13, false);
        defer pair.destroy();
        const hello = try pair.client.tls13.start();
        defer a.free(hello);
        // Target adapter output allocations, while the crypto engine uses its
        // ordinary allocator. The input storage is already owned.
        try pair.conn.recv_buf.ensureTotalCapacity(a, hello.len);
        var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        pair.conn.allocator = fault.allocator();
        defer pair.conn.allocator = a;
        const out = pair.conn.onInbound(hello) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            pair.conn.allocator = a;
            const engine = &pair.conn.engine.tls13;
            if (engine.state == .wait_client_hello) {
                before_consume += 1;
                try std.testing.expectEqual(@as(u64, 0), engine.hs_write_seq);
                try std.testing.expect(pair.conn.takeAlert(err) == null);
            } else {
                after_consume += 1;
                try std.testing.expectEqual(@as(@TypeOf(engine.state), .wait_client_finished), engine.state);
                const retained = pair.conn.takeAlert(err) orelse return error.TestUnexpectedResult;
                defer a.free(retained);
                const finished = switch (try pair.client.tls13.feed(retained)) {
                    .bytes_to_send => |b| b,
                    .need_more => return error.TestUnexpectedResult,
                };
                a.free(finished);
                try std.testing.expect(pair.conn.takeAlert(err) == null);
            }
            try std.testing.expectError(error.BadState, pair.conn.onInbound(&.{}));
            continue;
        };
        pair.conn.allocator = a;
        const finished = switch (try pair.client.tls13.feed(out.handshake_bytes)) {
            .bytes_to_send => |b| b,
            .need_more => return error.TestUnexpectedResult,
        };
        defer a.free(finished);
        _ = try pair.conn.onInbound(finished);
        try std.testing.expect(pair.conn.handshakeDone());
        try std.testing.expect(before_consume > 0);
        try std.testing.expect(after_consume > 0);
        return;
    }
    return error.TestUnexpectedResult;
}

test "TLS record limit: adapter terminal flatten OOM retains exact epoch prefix and fatal once" {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.createUnfinished(.tls12, false);
    defer pair.destroy();
    const hello = try pair.client.tls12.start();
    defer a.free(hello);
    const flight = try pair.conn.onInbound(hello);
    const finished = switch (try pair.client.tls12.feed(flight.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer a.free(finished);
    const coalesced = try std.mem.concat(a, u8, &.{ finished, &.{ 23, 3, 3, 0, 0 } });
    defer a.free(coalesced);
    try std.testing.expectError(error.AeadAuthFailed, pair.conn.onInbound(coalesced));
    const original_prefix = try a.dupe(u8, pair.conn.unpublished.items[0]);
    defer a.free(original_prefix);
    var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    pair.conn.allocator = fault.allocator();
    defer pair.conn.allocator = a;
    try std.testing.expect(pair.conn.takeAlert(error.RecordOverflow) == null);
    try std.testing.expectEqual(@as(u64, 2), pair.sequence());
    try std.testing.expectEqual(@as(usize, 2), pair.conn.unpublished.items.len);
    const original_alert = try a.dupe(u8, pair.conn.unpublished.items[1]);
    defer a.free(original_alert);
    const expected = try std.mem.concat(a, u8, &.{ original_prefix, original_alert });
    defer a.free(expected);
    pair.conn.allocator = a;
    try std.testing.expect(!pair.conn.handshakeDone());
    try std.testing.expectError(error.BadState, pair.conn.exportResume());
    try std.testing.expectError(error.BadState, pair.conn.write("late"));
    try std.testing.expectError(error.BadState, pair.conn.onInbound(&.{}));
    var crypto_info: [ktls.max_crypto_info_len]u8 = undefined;
    try std.testing.expectError(error.KtlsUnsupportedEngine, pair.conn.buildKtlsTxCryptoInfo(&crypto_info));
    try std.testing.expectError(error.KtlsUnsupportedEngine, pair.conn.buildKtlsRxCryptoInfo(&crypto_info));
    const retry = pair.conn.takeAlert(error.RecordOverflow).?;
    defer a.free(retry);
    try std.testing.expectEqualSlices(u8, expected, retry);
    try std.testing.expectEqual(@as(u64, 2), pair.sequence());
    try std.testing.expect(pair.conn.takeAlert(error.RecordOverflow) == null);
    const opened = try tls12.openRecordAlloc(a, pair.client.tls12.selected_suite.?, &pair.client.tls12.keys.server_write, 1, original_alert);
    defer a.free(opened.plaintext);
    // A changed caller argument cannot replace the original MAC failure.
    try std.testing.expectEqualSlices(u8, &.{ 2, 20 }, opened.plaintext);
}

test "TLS record limit: adapter pending KU transfer OOM retains exact engine custody" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |fail_engine_transfer| {
        const pair = try PreparedOutputTestPair.create(.tls13);
        defer pair.destroy();
        const engine = &pair.conn.engine.tls13;
        // The authenticated client seals a requested KU with its negotiated
        // suite and advances its own write epoch as a real peer would.
        try std.testing.expectEqual(engine.app_read_seq, pair.client.tls13.app_write_seq);
        try pair.client.tls13.sendKeyUpdateFragmentsForTest(true, &.{5});
        const request = (try pair.client.tls13.takePendingSend()) orelse return error.TestUnexpectedResult;
        defer a.free(request);
        const empty = try engine.decrypt(request);
        a.free(empty);
        try std.testing.expect(engine.post_handshake_send.items.len > 0);
        try std.testing.expectError(error.BadState, engine.exportResume());
        const expected = try a.dupe(u8, engine.post_handshake_send.items);
        defer a.free(expected);
        const rx_keys = engine.client_app_keys;
        const tx_keys = engine.server_app_keys;
        const rx_seq = engine.app_read_seq;
        const tx_seq = engine.app_write_seq;
        pair.conn.unpublished.clearAndFree(a);
        var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = 0, .resize_fail_index = 0 });
        if (fail_engine_transfer) {
            try pair.conn.unpublished.ensureUnusedCapacity(a, 1);
            // Force toOwnedSlice to need a shrink or owned replacement.
            try engine.post_handshake_send.ensureTotalCapacity(a, expected.len + 32);
            engine.allocator = fault.allocator();
        } else {
            pair.conn.allocator = fault.allocator();
        }
        defer pair.conn.allocator = a;
        defer engine.allocator = a;
        try std.testing.expectError(error.OutOfMemory, pair.conn.onInbound(&.{}));
        try std.testing.expect(fault.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), pair.conn.unpublished.items.len);
        try std.testing.expectEqualSlices(u8, expected, engine.post_handshake_send.items);
        try std.testing.expectEqualDeep(rx_keys, engine.client_app_keys);
        try std.testing.expectEqualDeep(tx_keys, engine.server_app_keys);
        try std.testing.expectEqual(rx_seq, engine.app_read_seq);
        try std.testing.expectEqual(tx_seq, engine.app_write_seq);
        pair.conn.allocator = a;
        engine.allocator = a;
        const retained = pair.conn.takeAlert(error.BadRecord) orelse return error.TestUnexpectedResult;
        defer a.free(retained);
        try std.testing.expectEqualSlices(u8, expected, retained);
        try std.testing.expectEqual(@as(usize, 0), engine.post_handshake_send.items.len);
        try std.testing.expectEqual(tx_seq, engine.app_write_seq);
        const control = try pair.client.tls13.decryptApp(retained);
        try std.testing.expectEqual(.control, std.meta.activeTag(control));
        try std.testing.expectEqualSlices(u8, &engine.server_app_keys.key, &pair.client.tls13.server_app_keys.key);
        try std.testing.expectEqualSlices(u8, &engine.server_app_keys.iv, &pair.client.tls13.server_app_keys.iv);
        try std.testing.expect(pair.conn.takeAlert(error.BadRecord) == null);
        try std.testing.expectError(error.BadState, pair.conn.exportResume());
    }
}

test "TLS record limit: adapter coalesced peer fatal disposes unpublished flight and locks cause" {
    const a = std.testing.allocator;
    for ([_]Version{ .tls12, .tls13 }) |version| {
        const pair = try PreparedOutputTestPair.createUnfinished(version, false);
        defer pair.destroy();
        const hello = switch (pair.client) {
            inline else => |*c| try c.start(),
        };
        defer a.free(hello);
        const flight = try pair.conn.onInbound(hello);
        const finished = switch (pair.client) {
            inline else => |*c| switch (try c.feed(flight.handshake_bytes)) {
                .bytes_to_send => |b| b,
                .need_more => return error.TestUnexpectedResult,
            },
        };
        defer a.free(finished);
        const fatal = switch (pair.client) {
            inline else => |*c| c.takeAlert(error.BadHandshake).?,
        };
        defer a.free(fatal);
        const coalesced = try std.mem.concat(a, u8, &.{ finished, fatal });
        defer a.free(coalesced);
        try std.testing.expectError(error.TlsAlert, pair.conn.onInbound(coalesced));
        try std.testing.expectEqual(@as(usize, 0), pair.conn.unpublished.items.len);
        const tx_before = pair.sequence();
        try std.testing.expect(pair.conn.takeAlert(error.BadHandshake) == null);
        try std.testing.expect(pair.conn.takeAlert(error.TlsAlert) == null);
        try std.testing.expectEqual(tx_before, pair.sequence());
        try std.testing.expectError(error.BadState, pair.conn.exportResume());
    }
}

test "TLS record limit: adapter terminal output never repeats previously exposed Outcome" {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.create(.tls12);
    defer pair.destroy();
    try std.testing.expect(pair.conn.send_buf.items.len != 0);
    const failure = blk: {
        _ = pair.conn.onInbound(&.{ 23, 3, 3, 0, 0 }) catch |err| break :blk err;
        return error.TestUnexpectedResult;
    };
    const terminal = pair.conn.takeAlert(failure).?;
    defer a.free(terminal);
    // The prior CCS+Finished was consumed by the client during pair creation.
    // It must not precede this sole sequence-one protected alert again.
    try std.testing.expectEqual(@as(u8, 21), terminal[0]);
    try std.testing.expectEqual(terminal.len, (try completeRecordLen(terminal)).?);
    try std.testing.expectError(error.TlsAlert, pair.client.tls12.decrypt(terminal));
    try std.testing.expect(pair.conn.takeAlert(failure) == null);
}

test "TLS record limit: actual adapter negotiated peer64 carries mandatory hot record limit" {
    const a = std.testing.allocator;
    for ([_]Version{ .tls12, .tls13 }) |version| {
        const pair = try PreparedOutputTestPair.createWithLimits(version, false, if (version == .tls13) 16385 else 16384, 64);
        defer pair.destroy();
        const hello = switch (pair.client) {
            inline else => |*c| try c.start(),
        };
        defer a.free(hello);
        const flight = try pair.conn.onInbound(hello);
        const finished = switch (pair.client) {
            inline else => |*c| switch (try c.feed(flight.handshake_bytes)) {
                .bytes_to_send => |b| b,
                .need_more => return error.TestUnexpectedResult,
            },
        };
        defer a.free(finished);
        const final = try pair.conn.onInbound(finished);
        if (version == .tls12) _ = try pair.client.tls12.feed(final.handshake_bytes);
        try std.testing.expect(pair.conn.handshakeDone());
        switch (pair.conn.engine) {
            inline .tls12, .tls13 => |*engine| {
                try std.testing.expectEqual(@as(usize, 64), engine.peer_record_size_limit);
                const state = try engine.exportResume();
                try std.testing.expectEqual(@as(u16, 64), state.peer_record_size_limit_raw);
            },
            else => unreachable,
        }
        const carried = try pair.conn.exportResume();
        switch (carried.engine) {
            inline else => |state| try std.testing.expectEqual(@as(u16, 64), state.peer_record_size_limit_raw),
        }
        const wire = try pair.conn.write("continued userspace application");
        const plain = try pair.consume(wire);
        defer a.free(plain);
        try std.testing.expectEqualStrings("continued userspace application", plain);
    }
}

fn tls3ConnectedPair(version: Version, local_limit: u16, peer_limit: u16) !*PreparedOutputTestPair {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.createWithLimits(version, false, local_limit, peer_limit);
    errdefer pair.destroy();
    const hello = switch (pair.client) {
        inline else => |*c| try c.start(),
    };
    defer a.free(hello);
    const flight = try pair.conn.onInbound(hello);
    const finished = switch (pair.client) {
        inline else => |*c| switch (try c.feed(flight.handshake_bytes)) {
            .bytes_to_send => |bytes| bytes,
            .need_more => return error.TestUnexpectedResult,
        },
    };
    defer a.free(finished);
    const final = try pair.conn.onInbound(finished);
    if (version == .tls12) _ = try pair.client.tls12.feed(final.handshake_bytes);
    try std.testing.expect(pair.conn.handshakeDone());
    return pair;
}

test "TLS3: actual negotiated64 capture keeps limits across changed successor config" {
    const a = std.testing.allocator;
    const tls_snapshot = @import("helix/tls_snapshot.zig");
    for ([_]Version{ .tls13, .tls12 }) |version| {
        const pair = try tls3ConnectedPair(version, 64, 64);
        defer pair.destroy();
        const state = try pair.conn.exportResume();
        const wire = try tls_snapshot.encode(a, .{ .kernel_tx_prefix_remaining = 0, .fd = 42, .state = state });
        defer a.free(wire);
        const decoded = try tls_snapshot.decodeCurrent(wire);
        var cfg13 = pair.conn.cfg13;
        cfg13.receive_record_size_limit = 16385;
        var cfg12 = pair.conn.cfg12;
        if (cfg12) |*config| config.receive_record_size_limit = 16384;
        var successor = try TlsConn.resumeFrom(a, cfg13, cfg12, decoded.state);
        defer successor.deinit();
        switch (successor.engine) {
            inline .tls13, .tls12 => |*engine| {
                try std.testing.expectEqual(@as(usize, 64), engine.peer_record_size_limit);
                try std.testing.expectEqual(@as(u16, 64), engine.receive_record_size_limit);
            },
            .undecided => return error.TestUnexpectedResult,
        }
        const payload: [300]u8 = @splat(0x71);
        const ciphertext = try successor.write(&payload);
        const plaintext = try pair.consume(ciphertext);
        defer a.free(plaintext);
        try std.testing.expectEqualSlices(u8, &payload, plaintext);
    }
}

test "TLS3: actual exporter survives two canonical capsule codec cycles" {
    const a = std.testing.allocator;
    const tls_snapshot = @import("helix/tls_snapshot.zig");
    const pair = try PreparedOutputTestPair.create(.tls13);
    defer pair.destroy();
    var binding: [32]u8 = undefined;
    try pair.conn.channelBindingTlsExporter(&binding);
    var current = &pair.conn;
    var first: ?TlsConn = null;
    defer if (first) |*conn| conn.deinit();
    var second: ?TlsConn = null;
    defer if (second) |*conn| conn.deinit();
    for (0..2) |cycle| {
        const state = try current.exportResume();
        const wire = try tls_snapshot.encode(a, .{ .kernel_tx_prefix_remaining = 0, .fd = 43, .state = state });
        defer a.free(wire);
        const decoded = try tls_snapshot.decodeCurrent(wire);
        const resumed = try TlsConn.resumeFrom(a, pair.conn.cfg13, null, decoded.state);
        if (cycle == 0) {
            first = resumed;
            current = &first.?;
        } else {
            second = resumed;
            current = &second.?;
        }
        var restored: [32]u8 = undefined;
        try current.channelBindingTlsExporter(&restored);
        try std.testing.expectEqualSlices(u8, &binding, &restored);
    }
    const ciphertext = try current.write("two codec cycles");
    const plaintext = try pair.consume(ciphertext);
    defer a.free(plaintext);
    try std.testing.expectEqualStrings("two codec cycles", plaintext);
}

fn tls3SuitePair(suite: u16) !*PreparedOutputTestPair {
    const a = std.testing.allocator;
    const pair = try PreparedOutputTestPair.createUnfinished(.tls13, false);
    errdefer pair.destroy();
    pair.client.tls13.force_aes256_only_for_test = suite == 0x1302;
    pair.client.tls13.force_chacha_only_for_test = suite == 0x1303;
    const hello = try pair.client.tls13.start();
    defer a.free(hello);
    const flight = try pair.conn.onInbound(hello);
    const finished = switch (try pair.client.tls13.feed(flight.handshake_bytes)) {
        .bytes_to_send => |wire| wire,
        .need_more => return error.TestUnexpectedResult,
    };
    defer a.free(finished);
    _ = try pair.conn.onInbound(finished);
    try std.testing.expect(pair.conn.handshakeDone());
    try std.testing.expect(pair.client.tls13.handshakeDone());
    try std.testing.expectEqual(suite, @backingInt(pair.conn.engine.tls13.selected_suite.?));
    try std.testing.expectEqual(suite, @backingInt(pair.client.tls13.selected_suite.?));
    return pair;
}

const Tls3TcpPair = struct {
    server: i32,
    peer: i32,
    fn open() !Tls3TcpPair {
        if (comptime builtin.os.tag != .linux) return error.Unsupported;
        const listener_rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
        if (posix.errno(listener_rc) != .SUCCESS) return error.TcpSetupFailed;
        const listener: i32 = @intCast(listener_rc);
        defer _ = linux.close(listener);
        var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        if (posix.errno(linux.bind(listener, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS or
            posix.errno(linux.listen(listener, 1)) != .SUCCESS) return error.TcpSetupFailed;
        var size: posix.socklen_t = @sizeOf(linux.sockaddr.in);
        if (posix.errno(linux.getsockname(listener, @ptrCast(&addr), &size)) != .SUCCESS) return error.TcpSetupFailed;
        const peer_rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
        if (posix.errno(peer_rc) != .SUCCESS) return error.TcpSetupFailed;
        const peer: i32 = @intCast(peer_rc);
        errdefer _ = linux.close(peer);
        if (posix.errno(linux.connect(peer, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.TcpSetupFailed;
        var ready = [_]posix.pollfd{.{ .fd = listener, .events = posix.POLL.IN, .revents = 0 }};
        if (try posix.poll(&ready, 2000) == 0) return error.TestTimeout;
        const accepted = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (posix.errno(accepted) != .SUCCESS) return error.TcpSetupFailed;
        return .{ .server = @intCast(accepted), .peer = peer };
    }
    fn deinit(self: Tls3TcpPair) void {
        if (comptime builtin.os.tag == .linux) {
            _ = linux.close(self.server);
            _ = linux.close(self.peer);
        }
    }
    fn send(fd: i32, bytes: []const u8) !void {
        if (comptime builtin.os.tag != .linux) return error.Unsupported;
        var offset: usize = 0;
        while (offset != bytes.len) {
            var ready = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
            if (try posix.poll(&ready, 2000) == 0) return error.TestTimeout;
            const rc = linux.sendto(fd, bytes[offset..].ptr, bytes.len - offset, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.TestUnexpectedResult;
                    offset += rc;
                },
                .AGAIN, .INTR => {},
                else => return error.SocketSendFailed,
            }
        }
    }
    fn receive(fd: i32, out: []u8) !usize {
        if (comptime builtin.os.tag != .linux) return error.Unsupported;
        var ready = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        if (try posix.poll(&ready, 2000) == 0) return error.TestTimeout;
        const rc = linux.recvfrom(fd, out.ptr, out.len, linux.MSG.DONTWAIT, null, null);
        if (posix.errno(rc) != .SUCCESS or rc == 0) return error.SocketReceiveFailed;
        return rc;
    }
    fn record(fd: i32, a: Allocator) ![]u8 {
        var record_bytes: std.ArrayList(u8) = .empty;
        errdefer record_bytes.deinit(a);
        var scratch: [4096]u8 = undefined;
        while ((try completeRecordLen(record_bytes.items)) == null) {
            const wanted = if (record_bytes.items.len < 5) 5 - record_bytes.items.len else 5 + @as(usize, std.mem.readInt(u16, record_bytes.items[3..5], .big)) - record_bytes.items.len;
            const n = try receive(fd, scratch[0..@min(wanted, scratch.len)]);
            try record_bytes.appendSlice(a, scratch[0..n]);
        }
        return record_bytes.toOwnedSlice(a);
    }
};

fn tls3KernelNext(t: *TlsConn, fd: i32, buf: []u8) !TlsConn.KernelReadResult {
    for (0..100) |_| {
        const result = t.readKernelControl(fd, buf) catch |err| {
            if (err != error.WouldBlock) return err;
            var ready = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
            _ = try posix.poll(&ready, 25);
            continue;
        };
        return result;
    }
    return error.TestTimeout;
}

// Derive the expected kernel key and IV from the authenticated peer's traffic
// secret, independently of the server engine's key cache and attach helpers.
fn tls3ExpectKernelTupleT(comptime KS: type, fd: i32, direction: ktls.Direction, cipher: ktls.Cipher, peer_secret: []const u8, sequence: u64) !void {
    var raw_secret: [KS.hash_len]u8 = undefined;
    @memcpy(&raw_secret, peer_secret[0..KS.hash_len]);
    defer std.crypto.secureZero(u8, &raw_secret);
    var secret = KS.SecretBytes.init(raw_secret);
    defer secret.wipe();
    var key: [32]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &key);
    var iv: [12]u8 = undefined;
    defer std.crypto.secureZero(u8, &iv);
    try KS.hkdfExpandLabel(&secret, "key", "", key[0..cipher.keyLen()]);
    try KS.hkdfExpandLabel(&secret, "iv", "", &iv);
    const info = try ktls.tls13CryptoInfo(cipher, &iv, key[0..cipher.keyLen()], sequence);
    var encoded: [ktls.max_crypto_info_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    const expected = try info.encode(&encoded);
    var actual = try ktls.getTuple(fd, direction, cipher);
    defer actual.wipe();
    try std.testing.expectEqualSlices(u8, expected, actual.encoded());
}

fn tls3ExpectKernelTuple(suite: u16, fd: i32, direction: ktls.Direction, cipher: ktls.Cipher, peer_secret: []const u8, sequence: u64) !void {
    const hkdf = @import("../crypto/hkdf_tls13.zig");
    if (suite == 0x1302) return tls3ExpectKernelTupleT(hkdf.Sha384, fd, direction, cipher, peer_secret, sequence);
    return tls3ExpectKernelTupleT(hkdf.Sha256, fd, direction, cipher, peer_secret, sequence);
}

fn tls3AuthenticatedKernelProof(suite: u16, rx: bool, tx: bool, first: usize, tiny: bool) !void {
    // This host's TCP ULP list has no `tls`. Attaching kTLS is KtlsUlpUnsupported.
    if (!ktls.probeUlpSupport()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const pair = try tls3SuitePair(suite);
    defer pair.destroy();
    const sockets = try Tls3TcpPair.open();
    defer sockets.deinit();
    if (tx) try pair.conn.enableKtlsTx(sockets.server);
    if (rx) try pair.conn.enableKtlsRx(sockets.server);
    const cipher: ktls.Cipher = switch (suite) {
        0x1301 => .aes_gcm_128,
        0x1302 => .aes_gcm_256,
        0x1303 => .chacha20_poly1305,
        else => unreachable,
    };
    var old_rx_secret = pair.client.tls13.client_app_secret;
    defer std.crypto.secureZero(u8, &old_rx_secret);
    var old_tx_secret = pair.client.tls13.server_app_secret;
    defer std.crypto.secureZero(u8, &old_tx_secret);
    const old_rx_seq = pair.conn.engine.tls13.app_read_seq;
    const old_tx_seq = pair.conn.engine.tls13.app_write_seq;
    if (rx) try tls3ExpectKernelTuple(suite, sockets.server, .rx, cipher, &old_rx_secret, old_rx_seq);
    if (tx) try tls3ExpectKernelTuple(suite, sockets.server, .tx, cipher, &old_tx_secret, old_tx_seq);
    try pair.client.tls13.sendKeyUpdateFragmentsForTest(true, &.{ first, 5 - first });
    const request = (try pair.client.tls13.takePendingSend()).?;
    defer a.free(request);
    const after = try pair.client.tls13.encrypt("authenticated new RX epoch");
    defer a.free(after);
    var software_reply: ?[]u8 = null;
    defer if (software_reply) |wire| a.free(wire);
    var control_buf: [32]u8 = undefined;
    if (rx) {
        try Tls3TcpPair.send(sockets.peer, request);
        var completed = false;
        for (0..32) |_| {
            switch (try tls3KernelNext(&pair.conn, sockets.server, control_buf[0..if (tiny) @as(usize, 1) else control_buf.len])) {
                .progress => {
                    try std.testing.expect(!pair.conn.kernelApplicationAllowed());
                    if (pair.conn.engine.tls13.post_handshake_recv_len != 0 and pair.conn.rx_open_control_type == 0) {
                        try std.testing.expectEqual(old_rx_seq + 1, pair.conn.engine.tls13.app_read_seq);
                        try tls3ExpectKernelTuple(suite, sockets.server, .rx, cipher, &old_rx_secret, old_rx_seq + 1);
                    }
                },
                .key_update => |ku| {
                    try std.testing.expect(ku.requested);
                    software_reply = ku.software_reply;
                    completed = true;
                    break;
                },
                .application => return error.TestUnexpectedResult,
            }
        }
        try std.testing.expect(completed);
        try tls3ExpectKernelTuple(suite, sockets.server, .rx, cipher, &pair.client.tls13.client_app_secret, 0);
        try std.testing.expectEqualSlices(u8, &pair.client.tls13.client_app_secret, &pair.conn.engine.tls13.client_app_secret);
    } else {
        const outcome = try pair.conn.onInbound(request);
        if (!tx) software_reply = try a.dupe(u8, outcome.handshake_bytes);
    }
    if (tx) {
        try std.testing.expect(pair.conn.tx_ku_reply_pending);
        for (0..5) |index| {
            const progress = try pair.conn.progressKernelReply(sockets.server, 1);
            try std.testing.expectEqual(@as(usize, 1), progress.accepted);
            try std.testing.expectEqual(index == 4, progress.completed);
            const wire = try Tls3TcpPair.record(sockets.peer, a);
            defer a.free(wire);
            const content = try pair.client.tls13.decrypt(wire);
            defer a.free(content);
            try std.testing.expectEqual(@as(usize, 0), content.len);
            if (index != 4) try tls3ExpectKernelTuple(suite, sockets.server, .tx, cipher, &old_tx_secret, old_tx_seq + index + 1);
        }
        try tls3ExpectKernelTuple(suite, sockets.server, .tx, cipher, &pair.client.tls13.server_app_secret, 0);
    } else {
        const content = try pair.client.tls13.decrypt(software_reply.?);
        defer a.free(content);
        try std.testing.expectEqual(@as(usize, 0), content.len);
    }
    try std.testing.expectEqualSlices(u8, &pair.client.tls13.server_app_secret, &pair.conn.engine.tls13.server_app_secret);
    if (rx) {
        try Tls3TcpPair.send(sockets.peer, after);
        switch (try tls3KernelNext(&pair.conn, sockets.server, &control_buf)) {
            .application => |plain| try std.testing.expectEqualStrings("authenticated new RX epoch", plain),
            else => return error.TestUnexpectedResult,
        }
        try tls3ExpectKernelTuple(suite, sockets.server, .rx, cipher, &pair.client.tls13.client_app_secret, 1);
    } else {
        const outcome = try pair.conn.onInbound(after);
        try std.testing.expectEqualStrings("authenticated new RX epoch", outcome.plaintext);
    }
    if (tx) {
        try Tls3TcpPair.send(sockets.server, "authenticated new TX epoch");
        const wire = try Tls3TcpPair.record(sockets.peer, a);
        defer a.free(wire);
        const content = try pair.client.tls13.decrypt(wire);
        defer a.free(content);
        try std.testing.expectEqualStrings("authenticated new TX epoch", content);
        try tls3ExpectKernelTuple(suite, sockets.server, .tx, cipher, &pair.client.tls13.server_app_secret, 1);
    } else {
        const wire = try pair.conn.write("authenticated new TX epoch");
        const content = try pair.client.tls13.decrypt(wire);
        defer a.free(content);
        try std.testing.expectEqualStrings("authenticated new TX epoch", content);
    }
}

test "TLS3: authenticated Linux kernel all suites four modes split KU EOR and typed reply" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]u16{ 0x1301, 0x1302, 0x1303 }) |suite| {
        for ([_]bool{ false, true }) |rx| {
            for ([_]bool{ false, true }) |tx| {
                for (1..5) |first| try tls3AuthenticatedKernelProof(suite, rx, tx, first, false);
            }
        }
        try tls3AuthenticatedKernelProof(suite, true, true, 1, true);
    }
}

fn tls3KernelCipher(suite: u16) ktls.Cipher {
    return switch (suite) {
        0x1301 => .aes_gcm_128,
        0x1302 => .aes_gcm_256,
        0x1303 => .chacha20_poly1305,
        else => unreachable,
    };
}

fn tls3KernelExpectKeyUpdate(pair: *PreparedOutputTestPair, sockets: Tls3TcpPair, requested: bool) !void {
    var control_buf: [64]u8 = undefined;
    for (0..32) |_| {
        switch (try tls3KernelNext(&pair.conn, sockets.server, &control_buf)) {
            .progress => continue,
            .key_update => |ku| {
                try std.testing.expectEqual(requested, ku.requested);
                try std.testing.expect(ku.software_reply == null);
                return;
            },
            .application => return error.TestUnexpectedResult,
        }
    }
    return error.TestTimeout;
}

fn tls3KernelReplyFragment(pair: *PreparedOutputTestPair, sockets: Tls3TcpPair) !bool {
    const a = std.testing.allocator;
    const progress = try pair.conn.progressKernelReply(sockets.server, 1);
    try std.testing.expectEqual(@as(usize, 1), progress.accepted);
    const wire = try Tls3TcpPair.record(sockets.peer, a);
    defer a.free(wire);
    const content = try pair.client.tls13.decrypt(wire);
    defer a.free(content);
    try std.testing.expectEqual(@as(usize, 0), content.len);
    return progress.completed;
}

fn tls3KernelSendAndExpect(pair: *PreparedOutputTestPair, sockets: Tls3TcpPair, text: []const u8) !void {
    const a = std.testing.allocator;
    const wire = try pair.client.tls13.encrypt(text);
    defer a.free(wire);
    try Tls3TcpPair.send(sockets.peer, wire);
    var control_buf: [128]u8 = undefined;
    switch (try tls3KernelNext(&pair.conn, sockets.server, &control_buf)) {
        .application => |plain| try std.testing.expectEqualStrings(text, plain),
        else => return error.TestUnexpectedResult,
    }
}

fn tls3KernelReceiveAndExpect(pair: *PreparedOutputTestPair, sockets: Tls3TcpPair, text: []const u8) !void {
    const a = std.testing.allocator;
    try Tls3TcpPair.send(sockets.server, text);
    const wire = try Tls3TcpPair.record(sockets.peer, a);
    defer a.free(wire);
    const content = try pair.client.tls13.decrypt(wire);
    defer a.free(content);
    try std.testing.expectEqualStrings(text, content);
}

test "TLS3 kernel txrx unrequested and consecutive peer KeyUpdates survive" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (!ktls.probeUlpSupport()) return error.SkipZigTest;
    const a = std.testing.allocator;
    for ([_]u16{ 0x1301, 0x1302, 0x1303 }) |suite| {
        const pair = try tls3SuitePair(suite);
        defer pair.destroy();
        const sockets = try Tls3TcpPair.open();
        defer sockets.deinit();
        try pair.conn.enableKtlsTx(sockets.server);
        try pair.conn.enableKtlsRx(sockets.server);
        const cipher = tls3KernelCipher(suite);

        // Epoch 1: update_not_requested rotates only the client's send key.
        const tx_secret_before = pair.client.tls13.server_app_secret;
        try pair.client.tls13.sendKeyUpdateFragmentsForTest(false, &.{ 2, 3 });
        const first_request = (try pair.client.tls13.takePendingSend()).?;
        defer a.free(first_request);
        try Tls3TcpPair.send(sockets.peer, first_request);
        try tls3KernelExpectKeyUpdate(pair, sockets, false);
        try std.testing.expect(!pair.conn.tx_ku_reply_pending);
        try std.testing.expectEqualSlices(u8, &tx_secret_before, &pair.client.tls13.server_app_secret);
        try std.testing.expectEqualSlices(u8, &pair.client.tls13.client_app_secret, &pair.conn.engine.tls13.client_app_secret);
        try tls3ExpectKernelTuple(suite, sockets.server, .rx, cipher, &pair.client.tls13.client_app_secret, 0);
        try pair.conn.validateKernelTxEpoch(sockets.server);
        try tls3KernelSendAndExpect(pair, sockets, "txrx epoch one client data");
        try tls3KernelReceiveAndExpect(pair, sockets, "txrx epoch one server data");

        // Epoch 2: update_requested starts a typed TX reply. Queue epoch 3
        // while that reply is only partly sent; the adapter must not consume
        // it until the old-epoch reply completes and installs epoch 2.
        try pair.client.tls13.sendKeyUpdateFragmentsForTest(true, &.{ 1, 4 });
        const second_request = (try pair.client.tls13.takePendingSend()).?;
        defer a.free(second_request);
        try Tls3TcpPair.send(sockets.peer, second_request);
        try tls3KernelExpectKeyUpdate(pair, sockets, true);
        try std.testing.expect(pair.conn.tx_ku_reply_pending);
        try std.testing.expect(!try tls3KernelReplyFragment(pair, sockets));
        try std.testing.expect(!try tls3KernelReplyFragment(pair, sockets));
        try std.testing.expectEqual(@as(u3, 2), pair.conn.tx_ku_reply_sent);
        const second_app = try pair.client.tls13.encrypt("txrx epoch two client data");
        defer a.free(second_app);
        try Tls3TcpPair.send(sockets.peer, second_app);

        try pair.client.tls13.sendKeyUpdateFragmentsForTest(false, &.{ 3, 2 });
        const third_request = (try pair.client.tls13.takePendingSend()).?;
        defer a.free(third_request);
        const third_app = try pair.client.tls13.encrypt("txrx epoch three client data");
        defer a.free(third_app);
        try Tls3TcpPair.send(sockets.peer, third_request);
        var control_buf: [64]u8 = undefined;
        try std.testing.expectError(error.BadState, pair.conn.readKernelControl(sockets.server, &control_buf));
        try std.testing.expectEqual(@as(u3, 2), pair.conn.tx_ku_reply_sent);

        try std.testing.expect(!try tls3KernelReplyFragment(pair, sockets));
        try std.testing.expect(!try tls3KernelReplyFragment(pair, sockets));
        try std.testing.expect(try tls3KernelReplyFragment(pair, sockets));
        try std.testing.expect(!pair.conn.tx_ku_reply_pending);
        try tls3ExpectKernelTuple(suite, sockets.server, .tx, cipher, &pair.client.tls13.server_app_secret, 0);
        switch (try tls3KernelNext(&pair.conn, sockets.server, &control_buf)) {
            .application => |plain| try std.testing.expectEqualStrings("txrx epoch two client data", plain),
            else => return error.TestUnexpectedResult,
        }
        try tls3KernelReceiveAndExpect(pair, sockets, "txrx epoch two server data");

        // Epoch 3 was queued, not consumed, during the partial reply.
        try tls3KernelExpectKeyUpdate(pair, sockets, false);
        try std.testing.expect(!pair.conn.tx_ku_reply_pending);
        try tls3ExpectKernelTuple(suite, sockets.server, .rx, cipher, &pair.client.tls13.client_app_secret, 0);
        try Tls3TcpPair.send(sockets.peer, third_app);
        switch (try tls3KernelNext(&pair.conn, sockets.server, &control_buf)) {
            .application => |plain| try std.testing.expectEqualStrings("txrx epoch three client data", plain),
            else => return error.TestUnexpectedResult,
        }
        try tls3KernelReceiveAndExpect(pair, sockets, "txrx epoch three server data");
    }
}

test "TLS3 kernel server-initiated KeyUpdate rotates TX epoch" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (!ktls.probeUlpSupport()) return error.SkipZigTest;
    const a = std.testing.allocator;
    for ([_]u16{ 0x1301, 0x1302, 0x1303 }) |suite| {
        for ([_]bool{ false, true }) |rx| {
            const pair = try tls3SuitePair(suite);
            defer pair.destroy();
            const sockets = try Tls3TcpPair.open();
            defer sockets.deinit();
            try pair.conn.enableKtlsTx(sockets.server);
            if (rx) try pair.conn.enableKtlsRx(sockets.server);
            const cipher = tls3KernelCipher(suite);

            // Unrequested initiation: only the server TX epoch rotates.
            try pair.conn.initiateKernelKeyUpdate(sockets.server, false);
            const ku_wire = try Tls3TcpPair.record(sockets.peer, a);
            defer a.free(ku_wire);
            const ku_content = try pair.client.tls13.decrypt(ku_wire);
            defer a.free(ku_content);
            try std.testing.expectEqual(@as(usize, 0), ku_content.len);
            try std.testing.expectEqualSlices(u8, &pair.client.tls13.server_app_secret, &pair.conn.engine.tls13.server_app_secret);
            try tls3ExpectKernelTuple(suite, sockets.server, .tx, cipher, &pair.client.tls13.server_app_secret, 0);
            try tls3KernelReceiveAndExpect(pair, sockets, "server initiated epoch one data");
            if (rx) try tls3KernelSendAndExpect(pair, sockets, "server initiated epoch one client data");

            // Requested initiation: the client answers with its own KeyUpdate,
            // which rotates the RX epoch when RX is offloaded.
            try pair.conn.initiateKernelKeyUpdate(sockets.server, true);
            const ku2_wire = try Tls3TcpPair.record(sockets.peer, a);
            defer a.free(ku2_wire);
            const ku2_content = try pair.client.tls13.decrypt(ku2_wire);
            defer a.free(ku2_content);
            try std.testing.expectEqual(@as(usize, 0), ku2_content.len);
            try std.testing.expectEqualSlices(u8, &pair.client.tls13.server_app_secret, &pair.conn.engine.tls13.server_app_secret);
            try tls3ExpectKernelTuple(suite, sockets.server, .tx, cipher, &pair.client.tls13.server_app_secret, 0);
            if (rx) {
                const response = (try pair.client.tls13.takePendingSend()) orelse return error.TestUnexpectedResult;
                defer a.free(response);
                try Tls3TcpPair.send(sockets.peer, response);
                try tls3KernelExpectKeyUpdate(pair, sockets, false);
                try tls3ExpectKernelTuple(suite, sockets.server, .rx, cipher, &pair.client.tls13.client_app_secret, 0);
                try tls3KernelSendAndExpect(pair, sockets, "server initiated epoch two client data");
            }
            try tls3KernelReceiveAndExpect(pair, sockets, "server initiated epoch two data");
        }
    }
}

test "TLS3 kernel txrx capture after completed rekey adopts on same fd" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (!ktls.probeUlpSupport()) return error.SkipZigTest;
    const a = std.testing.allocator;
    const tls_snapshot = @import("helix/tls_snapshot.zig");
    for ([_]u16{ 0x1301, 0x1303 }) |suite| {
        const pair = try tls3SuitePair(suite);
        defer pair.destroy();
        const sockets = try Tls3TcpPair.open();
        defer sockets.deinit();
        try pair.conn.enableKtlsTx(sockets.server);
        try pair.conn.enableKtlsRx(sockets.server);

        try pair.client.tls13.sendKeyUpdateFragmentsForTest(true, &.{ 2, 3 });
        const request = (try pair.client.tls13.takePendingSend()).?;
        defer a.free(request);
        try Tls3TcpPair.send(sockets.peer, request);
        try tls3KernelExpectKeyUpdate(pair, sockets, true);
        while (!try tls3KernelReplyFragment(pair, sockets)) {}
        try tls3KernelSendAndExpect(pair, sockets, "completed rekey client data");
        try tls3KernelReceiveAndExpect(pair, sockets, "completed rekey server data");

        var capture = try pair.conn.prepareCapture(a, .{
            .fd = sockets.server,
            .tx_offloaded = true,
            .rx_offloaded = true,
            .wire_chunks = &.{},
            .deferred_plain = &.{},
            .deferred_ciphertext_charge = 0,
            .control_charge = 0,
            .queue_cap = 4096,
            .kernel_tx_prefix_remaining = 0,
        });
        defer capture.deinit();
        const wire = try tls_snapshot.encode(a, .{
            .fd = sockets.server,
            .state = capture.state,
            .pending_out = capture.pending_out,
            .tx_offloaded = true,
            .rx_offloaded = true,
            .kernel_tx_prefix_remaining = capture.kernel_tx_prefix_remaining,
        });
        defer a.free(wire);
        const decoded = try tls_snapshot.decodeCurrent(wire);
        var successor = try TlsConn.resumeFrom(a, pair.conn.cfg13, null, decoded.state);
        defer successor.deinit();
        try successor.restoreInheritedOffload(sockets.server, true, true);

        const client_wire = try pair.client.tls13.encrypt("adopted rekey client data");
        defer a.free(client_wire);
        try Tls3TcpPair.send(sockets.peer, client_wire);
        var control_buf: [128]u8 = undefined;
        switch (try tls3KernelNext(&successor, sockets.server, &control_buf)) {
            .application => |plain| try std.testing.expectEqualStrings("adopted rekey client data", plain),
            else => return error.TestUnexpectedResult,
        }
        try Tls3TcpPair.send(sockets.server, "adopted rekey server data");
        const server_wire = try Tls3TcpPair.record(sockets.peer, a);
        defer a.free(server_wire);
        const server_plain = try pair.client.tls13.decrypt(server_wire);
        defer a.free(server_plain);
        try std.testing.expectEqualStrings("adopted rekey server data", server_plain);
    }
}

fn protectedSignalingEpochUnchanged(pair: *PreparedOutputTestPair, fd: i32, cipher: ktls.Cipher) !void {
    const a = std.testing.allocator;
    const before_pending = try a.dupe(u8, pair.conn.recv_buf.items);
    defer a.free(before_pending);
    const before_phase = pair.conn.control_phase;
    const before_held = pair.conn.held_record_len;
    const before_reply = pair.conn.tx_ku_reply_pending;
    const before_sent = pair.conn.tx_ku_reply_sent;
    const before_rx_sequence = pair.conn.engine.tls13.app_read_seq;
    const before_tx_sequence = pair.conn.engine.tls13.app_write_seq;
    const before_prefix_len = pair.conn.engine.tls13.post_handshake_recv_len;
    const before_prefix = pair.conn.engine.tls13.post_handshake_recv;
    var before = try ktls.getTuple(fd, .tx, cipher);
    defer before.wipe();
    try pair.conn.validateKernelTxEpoch(fd);
    var after = try ktls.getTuple(fd, .tx, cipher);
    defer after.wipe();
    try std.testing.expectEqualSlices(u8, before.encoded(), after.encoded());
    try std.testing.expectEqualSlices(u8, before_pending, pair.conn.recv_buf.items);
    try std.testing.expectEqual(before_phase, pair.conn.control_phase);
    try std.testing.expectEqual(before_held, pair.conn.held_record_len);
    try std.testing.expectEqual(before_reply, pair.conn.tx_ku_reply_pending);
    try std.testing.expectEqual(before_sent, pair.conn.tx_ku_reply_sent);
    try std.testing.expectEqual(before_rx_sequence, pair.conn.engine.tls13.app_read_seq);
    try std.testing.expectEqual(before_tx_sequence, pair.conn.engine.tls13.app_write_seq);
    try std.testing.expectEqual(before_prefix_len, pair.conn.engine.tls13.post_handshake_recv_len);
    try std.testing.expectEqualSlices(u8, &before_prefix, &pair.conn.engine.tls13.post_handshake_recv);
}

test "protected MEDIA signaling: actual kernel epoch getter keeps held KU and typed reply custody" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    if (!ktls.probeUlpSupport()) return error.SkipZigTest;
    const a = std.testing.allocator;
    for ([_]u16{ 0x1301, 0x1302, 0x1303 }) |suite| {
        const pair = try tls3SuitePair(suite);
        defer pair.destroy();
        const sockets = try Tls3TcpPair.open();
        defer sockets.deinit();
        try std.testing.expectError(error.BadState, pair.conn.validateKernelTxEpoch(sockets.server));
        try pair.conn.enableKtlsTx(sockets.server);
        const cipher: ktls.Cipher = switch (suite) {
            0x1301 => .aes_gcm_128,
            0x1302 => .aes_gcm_256,
            0x1303 => .chacha20_poly1305,
            else => unreachable,
        };
        try protectedSignalingEpochUnchanged(pair, sockets.server, cipher);
        const foreign = try tls3SuitePair(suite);
        defer foreign.destroy();
        const foreign_sockets = try Tls3TcpPair.open();
        defer foreign_sockets.deinit();
        try std.testing.expectError(error.GetFailed, pair.conn.validateKernelTxEpoch(foreign_sockets.server));
        try foreign.conn.enableKtlsTx(foreign_sockets.server);
        try std.testing.expectError(error.TupleMismatch, pair.conn.validateKernelTxEpoch(foreign_sockets.server));
        try protectedSignalingEpochUnchanged(pair, sockets.server, cipher);

        // An actual kernel send advances its own sequence without rewriting the
        // engine counter. Validation compares the epoch, not that stale counter.
        const engine_sequence = pair.conn.engine.tls13.app_write_seq;
        try Tls3TcpPair.send(sockets.server, "protected caller prefix");
        const prefix_wire = try Tls3TcpPair.record(sockets.peer, a);
        defer a.free(prefix_wire);
        const prefix_plain = try pair.client.tls13.decrypt(prefix_wire);
        defer a.free(prefix_plain);
        try std.testing.expectEqualStrings("protected caller prefix", prefix_plain);
        var advanced = try ktls.getTuple(sockets.server, .tx, cipher);
        defer advanced.wipe();
        try std.testing.expectEqual(engine_sequence + 1, advanced.sequence());
        try std.testing.expectEqual(engine_sequence, pair.conn.engine.tls13.app_write_seq);
        try protectedSignalingEpochUnchanged(pair, sockets.server, cipher);

        try pair.client.tls13.sendKeyUpdateFragmentsForTest(true, &.{ 1, 4 });
        const request = (try pair.client.tls13.takePendingSend()).?;
        defer a.free(request);
        _ = try pair.conn.onInboundWithControlCustody(request, false);
        try std.testing.expectEqual(ControlBarrierPhase.userspace_requested_ku_held, pair.conn.control_phase);
        try std.testing.expect(pair.conn.held_record_len != 0);
        try std.testing.expectEqual(@as(u8, 1), pair.conn.engine.tls13.post_handshake_recv_len);
        try protectedSignalingEpochUnchanged(pair, sockets.server, cipher);

        _ = try pair.conn.onInboundWithControlCustody(&.{}, true);
        try std.testing.expect(pair.conn.tx_ku_reply_pending);
        try protectedSignalingEpochUnchanged(pair, sockets.server, cipher);
        const partial = try pair.conn.progressKernelReply(sockets.server, 1);
        try std.testing.expectEqual(@as(usize, 1), partial.accepted);
        try std.testing.expect(!partial.completed);
        const first_wire = try Tls3TcpPair.record(sockets.peer, a);
        defer a.free(first_wire);
        const first_plain = try pair.client.tls13.decrypt(first_wire);
        defer a.free(first_plain);
        try std.testing.expectEqual(@as(usize, 0), first_plain.len);
        try std.testing.expectEqual(@as(u8, 1), pair.conn.tx_ku_reply_sent);
        try protectedSignalingEpochUnchanged(pair, sockets.server, cipher);
        const completed = try pair.conn.progressKernelReply(sockets.server, 4);
        try std.testing.expectEqual(@as(usize, 4), completed.accepted);
        try std.testing.expect(completed.completed);
        const last_wire = try Tls3TcpPair.record(sockets.peer, a);
        defer a.free(last_wire);
        const last_plain = try pair.client.tls13.decrypt(last_wire);
        defer a.free(last_plain);
        try std.testing.expectEqual(@as(usize, 0), last_plain.len);
        try protectedSignalingEpochUnchanged(pair, sockets.server, cipher);
    }
}

// ---------------------------------------------------------------------------
// Armor wave 3 (integrator): TLS 1.2 channel binding, TLS 1.2 kTLS, RFC 8737.
// ---------------------------------------------------------------------------

fn tls12Handshake(alloc: Allocator, conn: *TlsConn, client: *tls12_client.Client) !void {
    const ch = try client.start();
    defer alloc.free(ch);
    const sf = try conn.onInbound(ch);
    try std.testing.expectEqual(Version.tls12, conn.negotiatedVersion().?);
    const cf = switch (try client.feed(sf.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cf);
    const sfin = try conn.onInbound(cf);
    _ = try client.feed(sfin.handshake_bytes);
    try std.testing.expect(conn.handshakeDone());
    try std.testing.expect(client.handshakeDone());
}

fn ecdsaLeaf(buf: []u8, key: ecdsa_p256.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSignedEcdsaP256(buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 1, 2, 3, 4 },
        .key_pair = key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
}

test "RFC 9266: TLS 1.2 tls-exporter channel binding matches the client and is not re-derivable after resume" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x61)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try ecdsaLeaf(&ec_buf, ec_key);
    const cfg13: tls_server.Config = .{ .cert_chain = &.{der}, .signing_key = kp };
    const cfg12: tls12_server.Config = .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key };
    var conn = TlsConn.initDual(alloc, cfg13, cfg12);
    defer conn.deinit();
    var client = try tls12_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{ec_der}, .now_unix_seconds = 1_735_689_600 });
    defer client.deinit();
    try tls12Handshake(alloc, &conn, &client);

    var server_cb: [32]u8 = undefined;
    try conn.channelBindingTlsExporter(&server_cb);
    var client_cb: [32]u8 = undefined;
    try client.channelBindingTlsExporter(&client_cb);
    try std.testing.expectEqualSlices(u8, &client_cb, &server_cb);

    // A Helix-resumed TLS 1.2 engine carries no master secret, so the binding
    // can only reach the successor as the carried value (tls_snapshot v4).
    const st = try conn.exportResume();
    var resumed = try TlsConn.resumeFrom(alloc, cfg13, cfg12, st);
    defer resumed.deinit();
    var after: [32]u8 = undefined;
    try std.testing.expectError(error.BadState, resumed.channelBindingTlsExporter(&after));
}

test "kTLS TLS 1.2: crypto_info carries the 1.2 version, key, salt and explicit nonce = seq" {
    const alloc = std.testing.allocator;
    const native = @import("builtin").cpu.arch.endian();
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x62)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try ecdsaLeaf(&ec_buf, ec_key);
    var conn = TlsConn.initDual(alloc, .{ .cert_chain = &.{der}, .signing_key = kp }, .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key });
    defer conn.deinit();
    var client = try tls12_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{ec_der}, .now_unix_seconds = 1_735_689_600 });
    defer client.deinit();

    var buf: [ktls.max_crypto_info_len]u8 = undefined;
    try std.testing.expectError(error.KtlsUnsupportedEngine, conn.buildKtlsTxCryptoInfo(&buf));
    try tls12Handshake(alloc, &conn, &client);
    // Advance the server's write sequence so the nonce check is non-trivial
    // (the Finished record already used sequence 0).
    const seq_before = conn.engine.tls12.app_write_seq;
    const sealed = try conn.write("one");
    const opened = try client.decrypt(sealed);
    alloc.free(opened);

    const engine = &conn.engine.tls12;
    const suite = engine.selected_suite.?;
    const tx = try conn.buildKtlsTxCryptoInfo(&buf);
    try std.testing.expectEqual(ktls.TLS_1_2_VERSION, std.mem.readInt(u16, tx[0..2], native));
    const seq_bytes = ktls.seqToBytes(engine.app_write_seq);
    try std.testing.expectEqual(seq_before + 1, engine.app_write_seq);
    try std.testing.expectEqualSlices(u8, &seq_bytes, tx[tx.len - 8 ..]);
    switch (suite.aead()) {
        .aes_128_gcm, .aes_256_gcm => {
            // [hdr 4][iv 8 = seq][key][salt 4 = fixed iv][rec_seq 8]
            try std.testing.expectEqualSlices(u8, &seq_bytes, tx[4..12]);
            try std.testing.expectEqualSlices(u8, engine.keys.server_write.key[0..suite.keyLen()], tx[12..][0..suite.keyLen()]);
            try std.testing.expectEqualSlices(u8, engine.keys.server_write.iv[0..4], tx[12 + suite.keyLen() ..][0..4]);
        },
        .chacha20_poly1305 => {
            try std.testing.expectEqualSlices(u8, engine.keys.server_write.iv[0..12], tx[4..16]);
            try std.testing.expectEqualSlices(u8, engine.keys.server_write.key[0..32], tx[16..48]);
        },
    }
    const rx = try conn.buildKtlsRxCryptoInfo(&buf);
    try std.testing.expectEqual(ktls.TLS_1_2_VERSION, std.mem.readInt(u16, rx[0..2], native));
    try std.testing.expectEqualSlices(u8, &ktls.seqToBytes(engine.app_read_seq), rx[rx.len - 8 ..]);
}

fn loopbackPairOrSkip() !struct { client: linux.fd_t, server: linux.fd_t } {
    const listen_fd = try testTcpSocketOrSkip();
    defer _ = linux.close(listen_fd);
    var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    if (posix.errno(linux.bind(listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(listen_fd, 1)) != .SUCCESS) return error.SkipZigTest;
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SkipZigTest;
    addr.port = (@as(*const linux.sockaddr.in, @ptrCast(@alignCast(&storage)))).port;
    const client_fd = try testTcpSocketOrSkip();
    errdefer _ = linux.close(client_fd);
    if (posix.errno(linux.connect(client_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    const accept_rc = linux.accept4(listen_fd, null, null, 0);
    if (posix.errno(accept_rc) != .SUCCESS) return error.SkipZigTest;
    return .{ .client = client_fd, .server = @intCast(accept_rc) };
}

fn writeAllFd(fd: linux.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (posix.errno(rc) != .SUCCESS) return error.TestUnexpectedResult;
        off += @intCast(rc);
    }
}

test "kTLS TLS 1.2: kernel TX/RX interoperate with the 1.2 client, capture carries kernel seqs, control records fail closed" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x63)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try ecdsaLeaf(&ec_buf, ec_key);
    const cfg13: tls_server.Config = .{ .cert_chain = &.{der}, .signing_key = kp };
    const cfg12: tls12_server.Config = .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key };
    var conn = TlsConn.initDual(alloc, cfg13, cfg12);
    defer conn.deinit();
    var client = try tls12_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{ec_der}, .now_unix_seconds = 1_735_689_600 });
    defer client.deinit();
    try tls12Handshake(alloc, &conn, &client);
    const write_seq0 = conn.engine.tls12.app_write_seq;
    const read_seq0 = conn.engine.tls12.app_read_seq;

    const pair = try loopbackPairOrSkip();
    defer _ = linux.close(pair.client);
    defer _ = linux.close(pair.server);
    conn.enableKtlsTx(pair.server) catch return error.SkipZigTest;
    conn.enableKtlsRx(pair.server) catch return error.SkipZigTest;
    try std.testing.expect(conn.kernelApplicationAllowed());

    // Kernel TX: plaintext written to the socket arrives as a 1.2 record.
    const msg = "kernel tls12 tx";
    try writeAllFd(pair.server, msg);
    var rec: [512]u8 = undefined;
    const rn = linux.read(pair.client, &rec, rec.len);
    if (posix.errno(rn) != .SUCCESS) return error.TestUnexpectedResult;
    const got = try client.decrypt(rec[0..@intCast(rn)]);
    defer alloc.free(got);
    try std.testing.expectEqualStrings(msg, got);

    // Kernel RX: a client record is decrypted into recv() plaintext.
    const c2s = try client.encrypt("kernel tls12 rx");
    defer alloc.free(c2s);
    try writeAllFd(pair.client, c2s);
    var plain: [256]u8 = undefined;
    const pn = linux.read(pair.server, &plain, plain.len);
    if (posix.errno(pn) != .SUCCESS) return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("kernel tls12 rx", plain[0..@intCast(pn)]);

    // Helix capture writes the kernel's next sequences back into the state.
    {
        var capture = try conn.prepareCapture(alloc, .{
            .fd = pair.server,
            .tx_offloaded = true,
            .rx_offloaded = true,
            .wire_chunks = &.{},
            .deferred_plain = &.{},
            .deferred_ciphertext_charge = 0,
            .control_charge = 0,
            .queue_cap = 1 << 20,
            .kernel_tx_prefix_remaining = 0,
        });
        defer capture.deinit();
        try std.testing.expectEqual(write_seq0 + 1, capture.state.engine.tls12.app_write_seq);
        try std.testing.expectEqual(read_seq0 + 1, capture.state.engine.tls12.app_read_seq);
        // The successor validates the inherited kernel tuples on the same fd.
        var successor = try TlsConn.resumeFrom(alloc, cfg13, cfg12, capture.state);
        defer successor.deinit();
        try successor.restoreInheritedOffload(pair.server, true, true);
        try std.testing.expect(successor.ktls_tx_offloaded and successor.ktls_rx_offloaded);
        // A stale engine sequence is a tuple mismatch, never a silent adopt.
        var stale_state = capture.state;
        stale_state.engine.tls12.app_write_seq = write_seq0;
        var stale = try TlsConn.resumeFrom(alloc, cfg13, cfg12, stale_state);
        defer stale.deinit();
        try std.testing.expectError(error.TupleMismatch, stale.restoreInheritedOffload(pair.server, true, true));
    }

    // A handshake record (renegotiation) under kernel RX is fatal.
    const suite = client.selected_suite.?;
    const reneg = try tls12.sealRecordAlloc(alloc, suite, &client.keys.client_write, client.app_write_seq, .handshake, &.{ 0, 0, 0, 0 });
    defer alloc.free(reneg);
    client.app_write_seq += 1;
    try writeAllFd(pair.client, reneg);
    var control: [256]u8 = undefined;
    conn.control_phase = .kernel_control_read_held;
    try std.testing.expectError(error.BadHandshake, conn.readKernelControl(pair.server, &control));
    try std.testing.expect(conn.terminal_error != null);
    try std.testing.expect(conn.engine.tls12.read_failed);
}

test "kTLS TLS 1.2: an alert under kernel RX is terminal and application data passes" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x64)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try ecdsaLeaf(&ec_buf, ec_key);
    var conn = TlsConn.initDual(alloc, .{ .cert_chain = &.{der}, .signing_key = kp }, .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key });
    defer conn.deinit();
    var client = try tls12_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{ec_der}, .now_unix_seconds = 1_735_689_600 });
    defer client.deinit();
    try tls12Handshake(alloc, &conn, &client);
    const pair = try loopbackPairOrSkip();
    defer _ = linux.close(pair.client);
    defer _ = linux.close(pair.server);
    conn.enableKtlsRx(pair.server) catch return error.SkipZigTest;

    const suite = client.selected_suite.?;
    const data = try tls12.sealRecordAlloc(alloc, suite, &client.keys.client_write, client.app_write_seq, .application_data, "data");
    defer alloc.free(data);
    client.app_write_seq += 1;
    const alert = try tls12.sealRecordAlloc(alloc, suite, &client.keys.client_write, client.app_write_seq, .alert, &.{ 1, 0 });
    defer alloc.free(alert);
    client.app_write_seq += 1;
    try writeAllFd(pair.client, data);
    try writeAllFd(pair.client, alert);
    var control: [256]u8 = undefined;
    conn.control_phase = .kernel_control_read_held;
    switch (try conn.readKernelControl(pair.server, &control)) {
        .application => |plain| try std.testing.expectEqualStrings("data", plain),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(error.TlsAlert, conn.readKernelControl(pair.server, &control));
    try std.testing.expect(conn.engine.tls12.read_failed);
}

test "RFC 8737 tls-alpn-01: an acme-tls/1 hello gets the challenge certificate and ALPN; others are untouched" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x65)));
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const cfg13: tls_server.Config = .{ .cert_chain = &.{der}, .signing_key = kp, .alpn_protocols = &.{"irc"}, .enable_session_tickets = false };

    var store: acme_runner.TlsAlpn01Store = .{};
    var challenge_buf: [acme_challenge.max_tls_alpn01_cert_len]u8 = undefined;
    var minted = try acme_runner.mintTlsAlpn01(std.testing.io, &challenge_buf, "irc.example.test", "token.thumbprint", 1_735_689_600);
    defer ecdsa_p256.wipeKeyPair(&minted.key_pair);
    try store.put("irc.example.test", minted.der, minted.key_pair);

    // Validation handshake: SNI = the domain, ALPN exactly acme-tls/1.
    {
        var conn = try TlsConn.initBorrowed(alloc, cfg13);
        defer conn.deinit();
        conn.acme_store = &store;
        var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.example.test", .trust_anchors = &.{}, .alpn_protocols = &.{acme_challenge.acme_tls_alpn_protocol}, .grease = false });
        defer client.deinit();
        client.disableServerCertVerification();
        const ch = try client.start();
        defer alloc.free(ch);
        const flight = try conn.onInbound(ch);
        try std.testing.expect(flight.handshake_bytes.len != 0);
        try std.testing.expect(conn.isAcmeTlsAlpn01());
        // The engine presents the challenge certificate and its key, selects
        // acme-tls/1, and issues no ticket or early data (RFC 8737 §3).
        const engine_cfg = conn.engine.tls13.config;
        try std.testing.expectEqualSlices(u8, minted.der, engine_cfg.cert_chain[0]);
        try std.testing.expectEqual(@as(usize, 1), engine_cfg.cert_chain.len);
        try std.testing.expect(engine_cfg.ecdsa_p256_signing_key != null and engine_cfg.signing_key == null);
        try std.testing.expectEqualStrings(acme_challenge.acme_tls_alpn_protocol, engine_cfg.alpn_protocols[0]);
        try std.testing.expect(!engine_cfg.enable_session_tickets and engine_cfg.max_early_data_size == 0);
        try std.testing.expectEqualStrings(acme_challenge.acme_tls_alpn_protocol, conn.selectedAlpn().?);
        // Our own client refuses the critical acmeIdentifier extension, as an
        // ordinary client should; the CA validator accepts it.
        try std.testing.expectError(error.UnsupportedCriticalExtension, client.feed(flight.handshake_bytes));
        var info: [ktls.max_crypto_info_len]u8 = undefined;
        try std.testing.expectError(error.KtlsUnsupportedEngine, conn.buildKtlsTxCryptoInfo(&info));
    }
    // An ordinary IRC hello (ALPN irc) to the same SNI is not a validation.
    {
        var conn = try TlsConn.initBorrowed(alloc, cfg13);
        defer conn.deinit();
        conn.acme_store = &store;
        var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.example.test", .trust_anchors = &.{der}, .alpn_protocols = &.{"irc"} });
        defer client.deinit();
        client.disableServerCertVerification();
        const ch = try client.start();
        defer alloc.free(ch);
        _ = try conn.onInbound(ch);
        try std.testing.expect(!conn.isAcmeTlsAlpn01());
        try std.testing.expectEqualSlices(u8, der, conn.engine.tls13.config.cert_chain[0]);
    }
    // acme-tls/1 for a name with no live challenge is handled normally.
    {
        var conn = try TlsConn.initBorrowed(alloc, cfg13);
        defer conn.deinit();
        conn.acme_store = &store;
        var client = try tls_client.Client.init(alloc, .{ .server_name = "other.example.test", .trust_anchors = &.{}, .alpn_protocols = &.{acme_challenge.acme_tls_alpn_protocol}, .grease = false });
        defer client.deinit();
        const ch = try client.start();
        defer alloc.free(ch);
        _ = try conn.onInbound(ch);
        try std.testing.expect(!conn.isAcmeTlsAlpn01());
    }
}
