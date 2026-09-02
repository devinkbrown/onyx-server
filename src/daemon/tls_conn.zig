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
const Allocator = std.mem.Allocator;

const tls_server = @import("../crypto/tls_server.zig");
const tls12_server = @import("../crypto/tls12_server.zig");
const tls_record = @import("../crypto/tls_record.zig");
const tls_resumption = @import("../crypto/tls_resumption.zig");
const ktls = @import("ktls.zig");
const linux = std.os.linux;
const posix = std.posix;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_conn requires a 64-bit target");
}

/// Errors surfaced by the adapter: the inner 1.3 + 1.2 handshake/record errors
/// plus the allocator errors from growing the internal buffers.
pub const Error = tls_server.Error || tls12_server.Error || Allocator.Error;

/// What a single `onInbound()` produced. Both slices point into internal buffers
/// and stay valid only until the next `onInbound()` / `write()` call; the caller
/// must consume or copy them before driving the connection again.
///
///   * `handshake_bytes` — ciphertext to write straight back to the socket. This
///     is the server flight during the handshake and is empty afterwards.
///   * `plaintext` — decrypted application data accumulated from any
///     application_data records in this batch. Empty until the handshake is done
///     and whenever a batch carried no complete application records.
pub const Outcome = struct {
    handshake_bytes: []const u8 = &.{},
    plaintext: []const u8 = &.{},
};

/// Inner engine selected from the first ClientHello. `undecided` holds until a
/// version is detected; afterwards exactly one engine drives the connection.
const Engine = union(enum) {
    undecided,
    tls13: tls_server.Server,
    tls12: tls12_server.Server,
};

pub const Version = enum { tls12, tls13 };

pub const TlsConn = struct {
    allocator: Allocator,
    engine: Engine,
    /// TLS 1.3 server config (always present; the default/preferred protocol).
    cfg13: tls_server.Config,
    /// Optional hardened TLS 1.2 config. When null the listener is 1.3-only and
    /// a non-1.3 ClientHello is rejected with `error.ProtocolVersion`.
    cfg12: ?tls12_server.Config,

    /// Inbound socket bytes not yet split into a complete record.
    recv_buf: std.ArrayList(u8) = .empty,
    /// Ciphertext to send back, rebuilt per `onInbound()` call.
    send_buf: std.ArrayList(u8) = .empty,
    /// Decrypted application data, rebuilt per `onInbound()` call.
    plain_buf: std.ArrayList(u8) = .empty,
    /// Scratch for outbound ciphertext, rebuilt per `write()` call.
    write_buf: std.ArrayList(u8) = .empty,

    /// TLS 1.3-only adapter (back-compatible): the engine is fixed to the TLS 1.3
    /// server and a 1.2 ClientHello is rejected.
    pub fn init(allocator: Allocator, config: tls_server.Config) Error!TlsConn {
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

    pub fn deinit(self: *TlsConn) void {
        switch (self.engine) {
            .undecided => {},
            .tls13 => |*s| s.deinit(),
            .tls12 => |*s| s.deinit(),
        }
        self.recv_buf.deinit(self.allocator);
        self.send_buf.deinit(self.allocator);
        self.plain_buf.deinit(self.allocator);
        self.write_buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// True once the chosen engine's handshake has completed.
    pub fn handshakeDone(self: *const TlsConn) bool {
        return switch (self.engine) {
            .undecided => false,
            .tls13 => |*s| s.handshakeDone(),
            .tls12 => |*s| s.handshakeDone(),
        };
    }

    pub const KtlsError = error{
        /// The engine isn't a connected TLS 1.3 session (1.2 offload is deferred).
        KtlsUnsupportedEngine,
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

    /// Encode this session's server→client TX `crypto_info` into `out` (see
    /// `ktls.CryptoInfo.encode`), ready for `setsockopt(TLS_TX)`. Only the TLS 1.3
    /// engine is supported (1.2 kTLS derivation is deferred to a later phase);
    /// returns `KtlsUnsupportedEngine` otherwise or before the handshake completes.
    /// Pure (no syscalls): the byte transform half of `enableKtlsTx`.
    pub fn buildKtlsTxCryptoInfo(self: *const TlsConn, out: []u8) KtlsError![]const u8 {
        const params = switch (self.engine) {
            .tls13 => |*s| s.ktlsTxParams() orelse return error.KtlsUnsupportedEngine,
            .undecided, .tls12 => return error.KtlsUnsupportedEngine,
        };
        return encodeKtlsCryptoInfo(params, out);
    }

    /// The client→server RX `crypto_info` (for `setsockopt(TLS_RX)`). Same
    /// constraints as `buildKtlsTxCryptoInfo`.
    pub fn buildKtlsRxCryptoInfo(self: *const TlsConn, out: []u8) KtlsError![]const u8 {
        const params = switch (self.engine) {
            .tls13 => |*s| s.ktlsRxParams() orelse return error.KtlsUnsupportedEngine,
            .undecided, .tls12 => return error.KtlsUnsupportedEngine,
        };
        return encodeKtlsCryptoInfo(params, out);
    }

    /// Attach Linux kTLS TX offload to `fd` for the completed TLS 1.3 session, so
    /// the kernel encrypts subsequent server→client writes. The caller MUST have
    /// drained all userspace-sealed bytes (handshake flight + NewSessionTicket)
    /// from the socket first and the socket must be ESTABLISHED, or the kernel
    /// would encrypt the already-ciphertext tail. Only TLS 1.3 is supported.
    pub fn enableKtlsTx(self: *const TlsConn, fd: linux.fd_t) KtlsError!void {
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        const encoded = try self.buildKtlsTxCryptoInfo(&buf);
        try ktls.attachUlp(fd);
        try ktls.attachTx(fd, encoded);
    }

    /// Attach Linux kTLS RX offload to `fd`, so the kernel decrypts inbound
    /// records and `recv()` returns plaintext. The caller MUST first ensure the
    /// inbound stream is at a clean record boundary (`hasBufferedInbound()` false)
    /// so the kernel takes over from `app_read_seq` with no partial record left in
    /// userspace. Only TLS 1.3 is supported.
    pub fn enableKtlsRx(self: *const TlsConn, fd: linux.fd_t) KtlsError!void {
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        const encoded = try self.buildKtlsRxCryptoInfo(&buf);
        try ktls.attachUlp(fd);
        try ktls.attachRx(fd, encoded);
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
        const params = switch (self.engine) {
            .tls13 => |*s| try s.advanceRxKeyForKtls(),
            .undecided, .tls12 => return error.KtlsUnsupportedEngine,
        };
        var buf: [ktls.max_crypto_info_len]u8 = undefined;
        const encoded = try encodeKtlsCryptoInfo(params, &buf);
        // The ULP is already attached (RX offload is live); re-install the RX key.
        try ktls.attachRx(fd, encoded);
    }

    /// True when a partial inbound TLS record is buffered (an incomplete record
    /// awaiting more socket bytes). kTLS RX offload must NOT attach while this is
    /// true — the kernel would resume mid-record and desync.
    pub fn hasBufferedInbound(self: *const TlsConn) bool {
        return self.recv_buf.items.len != 0;
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
        return switch (self.engine) {
            .tls13 => |*s| s.channelBindingTlsExporter(out),
            else => error.BadState,
        };
    }

    /// Drive the connection with a chunk of bytes read from the socket. On the
    /// first call it selects the protocol version from the buffered ClientHello,
    /// then drives the chosen engine.
    pub fn onInbound(self: *TlsConn, socket_bytes: []const u8) Error!Outcome {
        self.send_buf.clearRetainingCapacity();
        self.plain_buf.clearRetainingCapacity();
        try self.recv_buf.appendSlice(self.allocator, socket_bytes);

        if (std.meta.activeTag(self.engine) == .undecided) {
            switch (try self.detectVersion()) {
                .need_more => return .{ .handshake_bytes = &.{}, .plaintext = &.{} },
                .tls13 => {
                    const s13 = try tls_server.Server.init(self.allocator, self.cfg13);
                    self.engine = .{ .tls13 = s13 };
                },
                .tls12 => {
                    const c12 = self.cfg12 orelse return error.ProtocolVersion;
                    const s12 = try tls12_server.Server.init(self.allocator, c12);
                    self.engine = .{ .tls12 = s12 };
                },
            }
        }

        // Process complete records front-to-back, consuming each from recv_buf.
        while (try completeRecordLen(self.recv_buf.items)) |wire_len| {
            if (self.handshakeDone()) {
                try self.decryptRecord(self.recv_buf.items[0..wire_len]);
            } else {
                try self.feedRecord(self.recv_buf.items[0..wire_len]);
            }
            consumePrefix(&self.recv_buf, wire_len);
        }

        // A post-handshake KeyUpdate (TLS 1.3 only) makes the inner server queue
        // a reply; send it back alongside any handshake flight.
        switch (self.engine) {
            .tls13 => |*s| {
                if (try s.takePendingSend()) |reply| {
                    defer self.allocator.free(reply);
                    try self.send_buf.appendSlice(self.allocator, reply);
                }
            },
            else => {},
        }

        return .{ .handshake_bytes = self.send_buf.items, .plaintext = self.plain_buf.items };
    }

    /// A fatal TLS alert record to send for the handshake error `err` before
    /// closing (RFC 8446 §6). Each engine picks the correct encoding for its
    /// state: the TLS 1.3 engine emits a plaintext alert before its ServerHello
    /// and an encrypted one (under the active write keys) afterward; the TLS 1.2
    /// engine emits plaintext before it sends its ChangeCipherSpec and encrypted
    /// after. An `undecided` engine (version-detect / init failure) has sent
    /// nothing, so a plaintext alert is correct. Either engine returns null for a
    /// state where no alert is warranted (bare close). Caller owns the buffer.
    pub fn takeAlert(self: *TlsConn, err: anyerror) ?[]u8 {
        return switch (self.engine) {
            .tls13 => |*s| s.takeAlert(err),
            .undecided => tls_server.alertRecordForError(self.allocator, err),
            .tls12 => |*s| s.takeAlert(err),
        };
    }

    /// Adapter-level resume state for a Helix live upgrade: the chosen engine's
    /// connected-state snapshot plus any buffered partial inbound record. The
    /// `pending_recv` slice borrows this TlsConn's internal buffer — serialize it
    /// before driving the connection again.
    pub const ResumeState = struct {
        engine: EngineState,
        /// Bytes of a partially received TLS record buffered at export time.
        pending_recv: []const u8 = &.{},

        pub const EngineState = union(Version) {
            tls12: tls12_server.Server.ResumeState,
            tls13: tls_server.Server.ResumeState,
        };
    };

    /// Capture this connection's live TLS state for a Helix upgrade handoff.
    /// Only valid once the handshake completed (`error.BadState` otherwise —
    /// mid-handshake connections are not resumable and must reconnect).
    pub fn exportResume(self: *const TlsConn) Error!ResumeState {
        if (!self.handshakeDone()) return error.BadState;
        return switch (self.engine) {
            .tls13 => |*s| .{ .engine = .{ .tls13 = try s.exportResume() }, .pending_recv = self.recv_buf.items },
            .tls12 => |*s| .{ .engine = .{ .tls12 = try s.exportResume() }, .pending_recv = self.recv_buf.items },
            .undecided => error.BadState,
        };
    }

    /// Successor side of a Helix upgrade: rebuild a CONNECTED adapter from an
    /// exported `ResumeState`. The matching engine config must be supplied (a
    /// 1.2-engine state with no `cfg12` fails with `error.ProtocolVersion`).
    /// Any carried partial inbound record is re-buffered so the byte stream
    /// continues exactly where the predecessor stopped.
    pub fn resumeFrom(allocator: Allocator, cfg13: tls_server.Config, cfg12: ?tls12_server.Config, st: ResumeState) Error!TlsConn {
        var self = TlsConn{
            .allocator = allocator,
            .engine = .undecided,
            .cfg13 = cfg13,
            .cfg12 = cfg12,
        };
        errdefer self.deinit();
        switch (st.engine) {
            .tls13 => |s13| self.engine = .{ .tls13 = try tls_server.Server.resumeConnected(allocator, cfg13, s13) },
            .tls12 => |s12| {
                const c12 = cfg12 orelse return error.ProtocolVersion;
                self.engine = .{ .tls12 = try tls12_server.Server.resumeConnected(allocator, c12, s12) };
            },
        }
        try self.recv_buf.appendSlice(allocator, st.pending_recv);
        return self;
    }

    /// Encrypt `plaintext` into one or more application_data records.
    pub fn write(self: *TlsConn, plaintext: []const u8) Error![]const u8 {
        if (!self.handshakeDone()) return error.BadState;
        self.write_buf.clearRetainingCapacity();

        var offset: usize = 0;
        while (true) {
            const end = @min(offset + tls_record.max_plaintext_len, plaintext.len);
            const chunk = plaintext[offset..end];
            const record = try self.encryptOne(chunk);
            defer self.allocator.free(record);
            try self.write_buf.appendSlice(self.allocator, record);
            offset = end;
            if (offset >= plaintext.len) break;
        }
        return self.write_buf.items;
    }

    fn encryptOne(self: *TlsConn, chunk: []const u8) Error![]u8 {
        return switch (self.engine) {
            .tls13 => |*s| try s.encrypt(chunk),
            .tls12 => |*s| try s.encrypt(chunk),
            .undecided => error.BadState,
        };
    }

    /// Feed one complete handshake-phase record to the chosen engine.
    fn feedRecord(self: *TlsConn, record: []const u8) Error!void {
        switch (self.engine) {
            .tls13 => |*s| {
                switch (try s.feed(record)) {
                    .need_more => {},
                    .bytes_to_send => |flight| {
                        defer self.allocator.free(flight);
                        try self.send_buf.appendSlice(self.allocator, flight);
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
                    defer self.allocator.free(flight);
                    try self.send_buf.appendSlice(self.allocator, flight);
                },
            },
            .undecided => return error.BadState,
        }
    }

    /// Decrypt one complete application_data record into `plain_buf`.
    fn decryptRecord(self: *TlsConn, record: []const u8) Error!void {
        const opened = switch (self.engine) {
            .tls13 => |*s| try s.decrypt(record),
            .tls12 => |*s| try s.decrypt(record),
            .undecided => return error.BadState,
        };
        defer self.allocator.free(opened);
        try self.plain_buf.appendSlice(self.allocator, opened);
    }

    const Detected = enum { need_more, tls12, tls13 };

    /// Inspect the buffered first ClientHello and decide the protocol version: a
    /// supported_versions extension listing 0x0304 selects TLS 1.3, otherwise
    /// TLS 1.2. Reassembles the ClientHello across handshake records if needed.
    fn detectVersion(self: *const TlsConn) Error!Detected {
        var hs: [tls_record.max_plaintext_len]u8 = undefined;
        var hs_len: usize = 0;
        var pos: usize = 0;
        const buf = self.recv_buf.items;
        while (true) {
            const wire = try completeRecordLen(buf[pos..]) orelse return .need_more;
            const rec = buf[pos .. pos + wire];
            if (rec[0] != @intFromEnum(tls_record.ContentType.handshake)) return error.BadRecord;
            const frag = rec[tls_record.record_header_len..];
            if (hs_len + frag.len > hs.len) return error.BadHandshake;
            @memcpy(hs[hs_len..][0..frag.len], frag);
            hs_len += frag.len;
            pos += wire;
            if (hs_len >= 4) {
                const msg_len = (@as(usize, hs[1]) << 16) | (@as(usize, hs[2]) << 8) | hs[3];
                if (hs_len >= 4 + msg_len) {
                    if (hs[0] != 1) return error.BadHandshake; // must be client_hello
                    return classifyClientHello(hs[4 .. 4 + msg_len]);
                }
            }
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
    if (body_len > tls_record.max_ciphertext_len) return error.BadRecord;
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
        @intFromEnum(ktls.RecordType.application_data) => .{ .app_data = plaintext },
        @intFromEnum(ktls.RecordType.handshake) => parseKeyUpdate(plaintext),
        @intFromEnum(ktls.RecordType.alert) => .close_notify,
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
        error.RecvFailed => .fault,
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

    // Real handshake keys → a well-formed AES-128-GCM crypto_info (40 bytes,
    // version 0x0304, cipher_type 51) — the same shape the kernel accepted in
    // ktls.zig's TLS_TX loopback test, now sourced from a live TlsConn session.
    const encoded = try conn.buildKtlsTxCryptoInfo(&buf);
    try std.testing.expectEqual(@as(usize, 40), encoded.len);
    try std.testing.expectEqual(ktls.TLS_1_3_VERSION, std.mem.readInt(u16, encoded[0..2], native));
    try std.testing.expectEqual(ktls.CipherType.aes_gcm_128.toInt(), std.mem.readInt(u16, encoded[2..4], native));
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
    try std.testing.expectEqual(@intFromEnum(ktls.RecordType.handshake), rr2.record_type);
    try std.testing.expect(rr2.record_type != @intFromEnum(ktls.RecordType.application_data));
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
        try std.testing.expect(!(ok.record_type == @intFromEnum(ktls.RecordType.application_data) and
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
    switch (classifyKtlsRecord(@intFromEnum(ktls.RecordType.application_data), &pt)) {
        .app_data => |d| try std.testing.expectEqualSlices(u8, &pt, d),
        else => return error.TestUnexpectedResult,
    }
    // handshake ⇒ a KeyUpdate, with the update_requested flag read from the wire.
    // update_not_requested(0): continue (advance RX key, no reply owed).
    var ku_not = [_]u8{ 24, 0, 0, 1, 0 };
    switch (classifyKtlsRecord(@intFromEnum(ktls.RecordType.handshake), &ku_not)) {
        .key_update => |k| try std.testing.expect(!k.request_peer),
        else => return error.TestUnexpectedResult,
    }
    // update_requested(1): the flag is surfaced so the daemon can honor the reply
    // obligation (RFC 8446 §4.6.3) — spec-safe close in the offloaded-TX case.
    var ku_req = [_]u8{ 24, 0, 0, 1, 1 };
    switch (classifyKtlsRecord(@intFromEnum(ktls.RecordType.handshake), &ku_req)) {
        .key_update => |k| try std.testing.expect(k.request_peer),
        else => return error.TestUnexpectedResult,
    }
    // Fail-closed: a handshake record that is not exactly one well-formed KeyUpdate
    // ⇒ .fault (close), never a silent continue. Wrong length, wrong type, wrong
    // uint24 length prefix, and an out-of-range request value are each rejected.
    try std.testing.expect(classifyKtlsRecord(@intFromEnum(ktls.RecordType.handshake), &pt) == .fault);
    var bad_type = [_]u8{ 20, 0, 0, 1, 0 }; // finished(20), not key_update
    try std.testing.expect(classifyKtlsRecord(@intFromEnum(ktls.RecordType.handshake), &bad_type) == .fault);
    var bad_len = [_]u8{ 24, 0, 0, 2, 0 }; // uint24 length 2, not 1
    try std.testing.expect(classifyKtlsRecord(@intFromEnum(ktls.RecordType.handshake), &bad_len) == .fault);
    var bad_req = [_]u8{ 24, 0, 0, 1, 2 }; // request value 2 ∉ {0,1}
    try std.testing.expect(classifyKtlsRecord(@intFromEnum(ktls.RecordType.handshake), &bad_req) == .fault);
    var coalesced = [_]u8{ 24, 0, 0, 1, 0, 24, 0, 0, 1, 0 }; // two KeyUpdates
    try std.testing.expect(classifyKtlsRecord(@intFromEnum(ktls.RecordType.handshake), &coalesced) == .fault);
    // alert (close_notify) ⇒ graceful close.
    try std.testing.expect(classifyKtlsRecord(@intFromEnum(ktls.RecordType.alert), &pt) == .close_notify);
    // change_cipher_spec / any unknown type post-handshake ⇒ fail-safe close.
    try std.testing.expect(classifyKtlsRecord(@intFromEnum(ktls.RecordType.change_cipher_spec), &pt) == .fault);
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
    const st = TlsConn.ResumeState{ .engine = .{ .tls12 = .{
        .suite = 0xc02b,
        .keys = .{},
        .app_read_seq = 0,
        .app_write_seq = 0,
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

const tls12_client = @import("../crypto/tls12_client.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");

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

test "version-dispatch: a TLS 1.2 client completes through a dual TlsConn" {
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

    const c2s = try client.encrypt("hello 1.2");
    defer alloc.free(c2s);
    const out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("hello 1.2", out.plaintext);
    const cipher = try conn.write("reply 1.2");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("reply 1.2", got);
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
    try std.testing.expectError(error.BadRecord, conn.onInbound(&header));
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
    try std.testing.expectError(error.BadRecord, conn.onInbound(&oversize));
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
