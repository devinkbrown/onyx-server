// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-owned WebTransport listener (layer 7): the live UDP endpoint that
//! turns the from-scratch QUIC (`quic_conn`) + HTTP/3 + WebTransport
//! (`http3_conn`) stack into a real running server, and bridges each
//! WebTransport session to the daemon's ordinary IRC listener over a loopback
//! TCP proxy.
//!
//! Threading model (mirrors `native_media_transport.zig` exactly): a single
//! pump thread blocks on a UDP socket with a short recv timeout so it can
//! observe the stop flag, and is torn down + joined on `shutdown`/`deinit`.
//! No reactor / dispatch changes: the daemon already serves IRC over TCP, so
//! the WT user is handed to it as an ordinary local client via a loopback TCP
//! connection — there is no cross-thread injection into the reactor.
//!
//! Data flow for one WebTransport session
//! --------------------------------------
//!   browser ──QUIC/H3/WT bidi stream──▶ this pump ──TCP 127.0.0.1:irc──▶ daemon
//!   daemon  ──TCP──▶ this pump ──writeWtStream──▶ browser
//! IRC is a CRLF line protocol; we proxy raw bytes and let the daemon do all
//! the IRC framing. The WT bidi data stream is the first bidi stream the client
//! opens after the session is established.
//!
//! Connection demux (per inbound datagram)
//! ---------------------------------------
//! QUIC carries the connection identity in the packet's Destination Connection
//! ID. We demux:
//!   * long-header (Initial / Handshake) packets by the *client-chosen* DCID
//!     (stable for the whole handshake, RFC 9001 §5.2); a previously-unseen
//!     Initial DCID mints a new connection with a server-chosen SCID.
//!   * short-header (1-RTT) packets by our server SCID (the DCID the client
//!     addresses once it has learned our SCID, RFC 9000 §7.2).
//! Both keys point at the same connection slot, so a connection is reachable by
//! either id across its lifetime.
//!
//! DoS resistance / bounds (documented simplifications)
//! ----------------------------------------------------
//!   * `max_connections` caps the live connection table; a flood of fresh
//!     Initials past the cap is dropped (no per-flood allocation).
//!   * Each `Conn`/`Http3Conn`/proxy is fixed-shape; the QUIC engine already
//!     bounds per-connection buffers (flow control, bounded datagram inbox).
//!   * Anti-amplification (RFC 9000 §8.1): every new server connection is
//!     amplification-limited to 3× the bytes received until the peer's address
//!     is validated (a decrypted Handshake packet, or a returned Retry token).
//!     This gate lives in the `quic_conn` layer; the listener feeds it.
//!   * Version Negotiation (RFC 9000 §17.2.1): an Initial with an unsupported
//!     QUIC version is answered with a VN packet (listing v1) and no connection
//!     is created. The VN reply is always ≤ the triggering Initial, never an
//!     amplifier.
//!   * Retry (RFC 9000 §8.1.2): OFF by default (fast path). When
//!     `retry_policy = .always` (or `.under_load` past `retry_load_threshold`
//!     live connections), a fresh Initial WITHOUT a valid address-validation
//!     token is answered with a Retry packet instead of proceeding; the client
//!     re-sends its Initial carrying the token and is validated immediately. A
//!     replayed/expired/wrong-IP token is rejected (falls back to a new Retry).
//!   * Stateless reset (RFC 9000 §10.3): a short-header (1-RTT) datagram whose
//!     DCID matches no live connection is answered with a Stateless Reset. The
//!     16-byte token is HMAC(reset_key, DCID) under the per-process key; the
//!     reset is shaped like a 1-RTT packet, never larger than the trigger
//!     (§10.3.3 never-amplify), only sent when the trigger is large enough, and
//!     token-bucket rate-limited (§21.11) so it cannot be used as a reflector.
//!   * One server SCID per connection. Connection migration + path validation
//!     (RFC 9000 §9) ARE supported: a 1-RTT packet from a new source address on
//!     an established connection triggers a PATH_CHALLENGE to the new address
//!     (3×-budget-limited), and only a matching PATH_RESPONSE migrates `conn.peer`
//!     to it — the QUIC core (`quic_conn`) owns the state machine; the listener
//!     feeds it the per-datagram source and routes probes to the candidate path.
//!   * One WebTransport session per QUIC connection, one IRC bridge per
//!     session (the common deployment shape; `http3_conn` rejects a 2nd CONNECT).
//!   * Dual-stack UDP (`DualStackUdpSocket`): Linux uses one mapped socket;
//!     OpenBSD uses native sockets per family at the same port. Both serve peers
//!     (Linux IPv4 sources arrive mapped, surfaced back as real
//!     ipv4 `TransportAddress` for PROXY-protocol + logging). The per-connection
//!     peer address + reply path are family-agnostic — they already use
//!     `TransportAddress`. The media plane keeps its own IPv4-only `MediaSocket`.
//!   * PROXY-protocol carry of the real client address is OPTIONAL and OFF by
//!     default: the daemon sees the bridge's loopback identity. When the daemon
//!     trusts loopback as a PROXY source, set `send_proxy_header = true` to
//!     prepend a PROXY v1 line carrying the QUIC peer's address.

const std = @import("std");
const dlog = @import("dlog.zig");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const os_runtime = @import("os_runtime.zig");
const native_network = @import("native_network.zig");
const posix = std.posix;

const quic_conn = @import("../proto/quic_conn.zig");
const quic_packet = @import("../proto/quic_packet.zig");
const quic_retry = @import("../proto/quic_retry.zig");
const http3_conn = @import("../proto/http3_conn.zig");
const quic_transport_params = @import("../proto/quic_transport_params.zig");
const quic_handshake = @import("../proto/quic_handshake.zig");
const proxy_protocol = @import("../proto/proxy_protocol.zig");
const media_socket = @import("../substrate/media_socket.zig");
const dualstack_udp = @import("dualstack_udp.zig");

pub const MediaSocket = media_socket.MediaSocket;
pub const DualStackUdpSocket = dualstack_udp.DualStackUdpSocket;
pub const TransportAddress = media_socket.TransportAddress;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;

/// Default cap on concurrent QUIC connections (DoS bound). A flood of fresh
/// handshakes past this is dropped without allocation.
pub const default_max_connections: usize = 256;

/// Default live-connection count at/above which the `.under_load` Retry policy
/// starts forcing a stateless Retry round trip (half the connection cap).
pub const default_retry_load_threshold: usize = 128;

/// Default stateless-reset rate (RFC 9000 §10.3 / §21.11): a steady cap on
/// resets per second once the burst is spent, and a burst allowance for short
/// spikes. Kept low — a reset is only ever owed for a genuinely-unknown 1-RTT
/// DCID (e.g. a peer talking to state we lost on restart), so legitimate demand
/// is small, while a spoofed flood is throttled to a non-amplifying trickle.
pub const default_reset_rate_per_s: f64 = 100.0;
pub const default_reset_burst: u32 = 20;

/// Retry address-validation policy (RFC 9000 §8.1.2). See the field docs on
/// `WebTransportListener.retry_policy`.
pub const RetryPolicy = enum {
    /// Never issue a Retry; mint connections directly (anti-amplification still
    /// applies). The default fast path.
    never,
    /// Issue a Retry for every tokenless new Initial.
    always,
    /// Issue a Retry only once the live connection count reaches the threshold.
    under_load,
};

/// Scratch read buffer size for a single UDP datagram (QUIC keeps datagrams
/// under ~1252 bytes; allow generous slack).
const recv_buf_len: usize = 2048;

/// Scratch buffer for one TCP↔WT pump pass.
const proxy_chunk_len: usize = 4096;

/// Periodic timer tick: how often (in pump iterations of `recv_timeout_ms`) we
/// run `onTimeout` on every live connection to drive idle/PTO timers.
const recv_timeout_ms: u32 = 100;

pub const Error = error{
    AlreadyStarted,
    BindFailed,
} || std.mem.Allocator.Error;

/// TLS material + transport identity the listener needs to stand up a QUIC
/// server connection. Mirrors what the daemon already loaded for its TLS
/// listener; `signing_key` is whichever key matches the leaf cert.
pub const TlsConfig = struct {
    cert_chain: []const []const u8,
    signing_key: quic_handshake.SigningKey,
};

/// One live QUIC connection and everything layered on it: the HTTP/3 +
/// WebTransport driver and (once a session is established) the loopback TCP
/// proxy carrying IRC bytes.
const Connection = struct {
    /// Server-chosen source connection id (the DCID short-header packets carry).
    scid: [quic_packet.max_connection_id_len]u8,
    scid_len: u8,
    /// Client-chosen Initial DCID (stable for the handshake); the other demux key.
    /// After a Retry this is the *post-Retry* DCID (= the server's Retry SCID),
    /// which the client now addresses; the ORIGINAL pre-Retry DCID lives in
    /// `orig_dcid` below and is what the `original_destination_connection_id`
    /// transport parameter must echo (RFC 9000 §7.3).
    init_dcid: [quic_packet.max_connection_id_len]u8,
    init_dcid_len: u8,
    /// The DCID of the client's FIRST Initial (RFC 9000 §7.3 ODCID). Without a
    /// Retry this equals `init_dcid`; after a Retry it is the pre-Retry DCID
    /// recovered from the token. Stable storage borrowed by the transport params.
    orig_dcid: [quic_packet.max_connection_id_len]u8,
    orig_dcid_len: u8,
    /// When this connection was minted after a Retry, the SCID the server placed
    /// in the Retry packet (= this connection's post-Retry `init_dcid`), which the
    /// `retry_source_connection_id` transport parameter MUST echo. Zero-length
    /// (`retry_scid_len == 0`) when no Retry occurred.
    retry_scid: [quic_packet.max_connection_id_len]u8,
    retry_scid_len: u8 = 0,
    /// The peer's UDP return address (learned from the first datagram; this layer
    /// does not support migration, so it is fixed for the connection's life).
    peer: TransportAddress,
    conn: *quic_conn.Conn,
    h3: *http3_conn.Http3Conn,
    /// Loopback TCP fd to the daemon's IRC listener, once a session establishes.
    irc_fd: ?sys.fd_t = null,
    /// Whether we already opened a server→client WT bidi stream for IRC output.
    /// We instead reuse the client's first WT bidi data stream; this records it.
    wt_stream_id: ?u64 = null,
    /// Whether the client's WT data stream has been observed yet.
    have_wt_stream: bool = false,

    fn scidSlice(self: *const Connection) []const u8 {
        return self.scid[0..self.scid_len];
    }
    fn initDcidSlice(self: *const Connection) []const u8 {
        return self.init_dcid[0..self.init_dcid_len];
    }
    fn origDcidSlice(self: *const Connection) []const u8 {
        return self.orig_dcid[0..self.orig_dcid_len];
    }
    /// The `retry_source_connection_id` to advertise, or null when no Retry
    /// occurred for this connection.
    fn retryScidSlice(self: *const Connection) ?[]const u8 {
        if (self.retry_scid_len == 0) return null;
        return self.retry_scid[0..self.retry_scid_len];
    }
};

pub const WebTransportListener = struct {
    allocator: std.mem.Allocator,
    tls: TlsConfig,
    /// Local TCP port of the daemon's IRC listener (loopback bridge target).
    irc_port: u16,
    /// Prepend a PROXY-protocol v1 header carrying the real QUIC peer address.
    /// Off by default (loopback identity); see module doc.
    send_proxy_header: bool = false,
    /// Interop / echo mode: when set, every WebTransport datagram received on a
    /// session is echoed straight back to the peer (RFC 9297/9220 datagram leg).
    /// Off in production (the IRC bridge carries stream bytes, not datagrams);
    /// the browser interop harness flips this on to validate the datagram path.
    echo_wt_datagrams: bool = false,
    max_connections: usize = default_max_connections,

    /// Retry policy (RFC 9000 §8.1.2). `.never` is the default fast path — a new
    /// Initial mints a connection directly (still anti-amplification-limited).
    /// `.always` issues a Retry for every tokenless Initial. `.under_load` issues
    /// a Retry only once the live connection count reaches `retry_load_threshold`
    /// (a cheap DoS valve: under attack, force every client through a stateless
    /// round trip before any per-connection state is allocated).
    retry_policy: RetryPolicy = .never,
    /// Live-connection count at/above which `.under_load` starts issuing Retries.
    retry_load_threshold: usize = default_retry_load_threshold,
    /// Per-process address-validation / stateless-reset key bundle (RFC 9000
    /// §8.1.2 / §10.3). Minted on first use from the OS CSPRNG.
    retry_secret: ?quic_retry.Secret = null,
    /// Bounded single-use cache for accepted Retry tokens (replay defense).
    token_replay: quic_retry.ReplayCache = .{},

    socket: ?DualStackUdpSocket = null,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Bound local UDP port (0 until started).
    port: u16 = 0,

    /// Demux table: connection-id (owned dupe) → connection index in `conns`.
    by_cid: std.StringHashMapUnmanaged(usize) = .empty,
    /// Live connections. A slot is null once torn down (compacted lazily).
    conns: std.ArrayListUnmanaged(?*Connection) = .empty,

    /// Monotonic counter feeding the server-chosen SCID so each connection gets
    /// a unique id (no migration / no rotation — one SCID per connection).
    scid_counter: u64 = 0,

    /// Stateless-reset rate limiter (RFC 9000 §10.3 / §21.11): an unbounded reset
    /// responder is itself a reflection/DoS amplifier, so we cap resets to a
    /// token-bucket rate. `reset_tokens` is the current allowance (refilled over
    /// time up to `reset_burst`); `reset_last_refill_ns` is the last refill tick.
    reset_tokens: f64 = @floatFromInt(default_reset_burst),
    reset_last_refill_ns: u64 = 0,
    /// Resets per second once the burst is exhausted.
    reset_rate_per_s: f64 = default_reset_rate_per_s,
    /// Maximum reset burst (token-bucket capacity).
    reset_burst: u32 = default_reset_burst,

    pub fn init(allocator: std.mem.Allocator, tls: TlsConfig, irc_port: u16) WebTransportListener {
        return .{ .allocator = allocator, .tls = tls, .irc_port = irc_port };
    }

    pub fn deinit(self: *WebTransportListener) void {
        self.shutdown();
        // Tear down any connections that survived (shutdown joins the pump first,
        // so nothing races us here).
        for (self.conns.items) |maybe| {
            if (maybe) |c| self.destroyConnection(c);
        }
        self.conns.deinit(self.allocator);
        var it = self.by_cid.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.by_cid.deinit(self.allocator);
        self.* = undefined;
    }

    /// Bind on `bind_be`:`port` (port 0 = ephemeral) and spawn the pump thread.
    ///
    /// `bind_be` is the legacy IPv4-in-network-byte-order bind selector kept for
    /// the existing `main.zig`/test call sites; it is mapped onto the dual-stack
    /// socket's `BindAddr` (so the socket itself is always `AF_INET6` with
    /// `IPV6_V6ONLY=0`, serving both families):
    ///   * `any_be` (0.0.0.0) → bind `[::]` (all interfaces, both families).
    ///   * `loopback_be` (127.0.0.1) → bind `::ffff:127.0.0.1` (v4-mapped loopback).
    ///   * any other configured v4 address → bind it v4-mapped.
    pub fn start(self: *WebTransportListener, bind_be: u32, port: u16) Error!void {
        return self.startAddress(bindAddrFromBe(bind_be), port);
    }

    fn startAddress(self: *WebTransportListener, address: DualStackUdpSocket.BindAddr, port: u16) Error!void {
        if (comptime builtin.os.tag == .windows) return error.BindFailed;
        if (self.socket != null) return error.AlreadyStarted;
        var sock = DualStackUdpSocket.bind(address, port) catch return error.BindFailed;
        self.port = sock.localPort() catch {
            sock.deinit();
            return error.BindFailed;
        };
        sock.setRecvTimeoutMs(recv_timeout_ms);
        self.socket = sock;

        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch {
            self.socket.?.deinit();
            self.socket = null;
            return error.BindFailed;
        };
    }

    /// Signal the pump to stop, join it, and close the UDP socket. Idempotent.
    pub fn shutdown(self: *WebTransportListener) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (self.socket) |*s| {
            s.deinit();
            self.socket = null;
        }
    }

    // -----------------------------------------------------------------------
    // Pump thread
    // -----------------------------------------------------------------------

    fn pumpLoop(self: *WebTransportListener) void {
        var buf: [recv_buf_len]u8 = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const sock = if (self.socket) |*s| s else return;
            if (sock.recvFrom(&buf)) |got| {
                self.handleDatagram(got.data, got.from);
            }
            // On every wake (datagram or timeout) advance per-connection timers
            // and pump the IRC bridges. This is the periodic tick.
            self.serviceAll();
        }
    }

    /// Process one inbound UDP datagram: demux to (or create) a connection, feed
    /// the QUIC engine, service H3/WT, and flush owed datagrams to the peer.
    ///
    /// A previously-unseen connection id triggers the address-validation policy
    /// (RFC 9000 §8): Version Negotiation for an unsupported version, an optional
    /// Retry to force an address round trip, and — once a connection is minted —
    /// the per-connection 3× anti-amplification limit in `quic_conn`.
    fn handleDatagram(self: *WebTransportListener, data: []const u8, from: TransportAddress) void {
        if (data.len == 0) return;
        const cid = peekDestCid(data) orelse return;

        if (self.lookup(cid)) |conn| {
            self.feedConnection(conn, data, from);
            return;
        }

        // Unknown connection id. Only a long-header (Initial) packet may create a
        // new connection; a short header (1-RTT) for an unknown cid gets a
        // Stateless Reset (RFC 9000 §10.3) so the peer learns its connection is
        // gone (e.g. our state was lost on restart) — subject to never-amplify +
        // rate-limit guards in `sendStatelessReset`.
        if ((data[0] & 0x80) == 0) {
            self.sendStatelessReset(cid, data, from);
            return;
        }

        const conn = self.admitNewInitial(data, from) orelse return;
        dbg("admitted new QUIC connection from {d}-byte Initial", .{data.len});
        self.feedConnection(conn, data, from);
    }

    /// Apply the RFC 9000 §8 admission policy to a long-header Initial from an
    /// unknown connection id and, if it passes, mint the connection. Returns null
    /// (after possibly emitting a VN or Retry packet) when no connection should
    /// be created for this datagram.
    fn admitNewInitial(self: *WebTransportListener, data: []const u8, from: TransportAddress) ?*Connection {
        const hdr = parseInitialHeader(data) orelse {
            // A long header we cannot parse as an Initial (e.g. a 0-RTT/Retry/
            // Handshake for an unknown cid): drop without state.
            return null;
        };

        // Version Negotiation (RFC 9000 §17.2.1): unsupported version → reply with
        // a VN packet listing v1 and create NO connection. The VN is ≤ the
        // triggering datagram, so it never amplifies.
        if (!quic_retry.supportsVersion(hdr.version)) {
            self.sendVersionNegotiation(hdr, from, data.len);
            return null;
        }

        // Retry / address-validation token policy (RFC 9000 §8.1.2).
        if (self.retryActive()) {
            if (hdr.token.len > 0) {
                // The client returned a token. Accept it only if it authenticates
                // for THIS source IP, is unexpired, and is not a replay; then the
                // new connection is address-validated immediately (no 3× limit).
                // The token carries the client's ORIGINAL (pre-Retry) DCID, which
                // we recover here to set the ODCID transport parameter; the
                // current `hdr.dcid` is the SCID we chose in the Retry packet, so
                // it becomes the `retry_source_connection_id` (RFC 9000 §7.3).
                var odcid_buf: [quic_packet.max_connection_id_len]u8 = undefined;
                if (self.acceptToken(hdr.token, from, &odcid_buf)) |odcid| {
                    const conn = self.createConnection(hdr.dcid, from, .{
                        .original_dcid = odcid,
                        .retry_scid = hdr.dcid,
                    }) orelse return null;
                    conn.conn.markAddressValidated();
                    return conn;
                }
                // A bad/expired/replayed token: fall through and issue a fresh
                // Retry rather than trusting it.
            }
            // No token (or a rejected one): issue a Retry and create no state.
            self.sendRetry(hdr, from);
            return null;
        }

        // Fast path: mint the connection directly. It is still subject to the
        // per-connection 3× anti-amplification limit until a Handshake packet
        // validates the address. No Retry → ODCID == the first-Initial DCID.
        return self.createConnection(hdr.dcid, from, .{ .original_dcid = hdr.dcid });
    }

    /// Whether the Retry policy is currently active for a new Initial.
    fn retryActive(self: *const WebTransportListener) bool {
        return switch (self.retry_policy) {
            .never => false,
            .always => true,
            .under_load => self.liveCount() >= self.retry_load_threshold,
        };
    }

    /// Lazily mint (once) and return the per-process address-validation secret.
    fn secret(self: *WebTransportListener) *const quic_retry.Secret {
        if (self.retry_secret == null) self.retry_secret = quic_retry.Secret.generate();
        return &self.retry_secret.?;
    }

    /// Verify a returned Retry token: authenticates under our key, was minted for
    /// `from`'s IP, is unexpired, and is not a replay. On success records it
    /// (single-use) and returns the client's ORIGINAL (pre-Retry) DCID recovered
    /// from the token, written into `out_dcid`. Returns null if invalid.
    fn acceptToken(
        self: *WebTransportListener,
        token: []const u8,
        from: TransportAddress,
        out_dcid: *[quic_packet.max_connection_id_len]u8,
    ) ?[]const u8 {
        const sec = self.secret();
        var addr = from;
        const v = quic_retry.Token.verify(
            token,
            sec,
            addr.bytes(),
            out_dcid,
            nowNs(),
            quic_retry.default_token_lifetime_ns,
        ) catch return null;
        // Authenticated + fresh; enforce single-use (replay defense).
        self.token_replay.checkAndRecord(token) catch return null;
        return v.original_dcid;
    }

    /// Emit a Retry packet (RFC 9000 §17.2.5): a fresh server SCID + an
    /// address-validation token binding the client IP and original DCID. Creates
    /// no per-connection state — the client must re-send its Initial with the
    /// token. Failure to build/send is silently dropped (the client will retry).
    fn sendRetry(self: *WebTransportListener, hdr: InitialHeader, from: TransportAddress) void {
        const sec = self.secret();
        // Mint the token (bind IP + the client's original DCID + issue time).
        var addr = from;
        var token_buf: [quic_retry.max_token_len]u8 = undefined;
        const token = quic_retry.Token.seal(&token_buf, sec, addr.bytes(), hdr.dcid, nowNs()) catch return;

        // A fresh server SCID (the connection-id the client will address next).
        var scid: [8]u8 = undefined;
        std.mem.writeInt(u64, scid[0..8], self.scid_counter, .big);
        self.scid_counter +%= 1;

        // Retry's DCID = the client's SCID (so the client recognises the reply).
        var out: [quic_retry.retry_packet_max]u8 = undefined;
        const n = quic_retry.encodeRetry(&out, hdr.scid, &scid, token_buf[0..token], hdr.dcid) catch return;
        const sock = if (self.socket) |*s| s else return;
        sock.sendTo(from, out[0..n]);
    }

    /// Emit a Version Negotiation packet (RFC 9000 §17.2.1) in response to an
    /// unsupported-version Initial. The VN swaps the connection ids and lists the
    /// versions we support (v1). It is sent only when it cannot exceed the
    /// triggering datagram's size (`trigger_len`), so it can never amplify.
    fn sendVersionNegotiation(self: *WebTransportListener, hdr: InitialHeader, from: TransportAddress, trigger_len: usize) void {
        var out: [256]u8 = undefined;
        // Our DCID = the client's SCID; our SCID = the client's DCID (§17.2.1).
        const n = quic_retry.encodeVersionNegotiation(&out, hdr.scid, hdr.dcid) catch return;
        if (n > trigger_len) return; // never amplify (defensive; always holds here)
        const sock = if (self.socket) |*s| s else return;
        sock.sendTo(from, out[0..n]);
    }

    /// Emit a Stateless Reset (RFC 9000 §10.3) in response to a short-header
    /// (1-RTT) datagram whose Destination Connection ID matches no live
    /// connection. The reset tells the peer its connection no longer exists (e.g.
    /// our state was lost across a restart) so it can fail fast instead of timing
    /// out.
    ///
    /// Security properties enforced here:
    ///   * Never amplify (§10.3.3): the reset is shaped like an ordinary 1-RTT
    ///     packet and MUST NOT be larger than the triggering datagram. We also
    ///     refuse to respond at all unless the incoming packet is large enough to
    ///     plausibly carry a reset (`min_stateless_reset_len`), so a tiny probe
    ///     gets nothing. The reset length is `min(incoming_len, sized cap)` and is
    ///     always ≤ the incoming size.
    ///   * Token derivation (§10.3): the 16-byte token is HMAC(reset_key, DCID)
    ///     under the per-process reset key. We derive it from the *incoming* DCID:
    ///     we cannot reset a CID we never chose (we have no record of it), so —
    ///     per standard server behaviour — we treat the DCID the peer addressed as
    ///     the connection id and key the token off it. A peer that genuinely holds
    ///     that connection recognises the token (it observed the same derivation
    ///     when we issued the id); a spoofer cannot forge or correlate it without
    ///     the key.
    ///   * Rate limit (§21.11): a token-bucket caps resets so an attacker cannot
    ///     turn the endpoint into a reflection amplifier by flooding unknown CIDs.
    fn sendStatelessReset(self: *WebTransportListener, dcid: []const u8, trigger: []const u8, from: TransportAddress) void {
        // Never-amplify floor (§10.3.3): if the triggering packet is too small to
        // carry a reset, send nothing (a smaller reply would still be an amplifier
        // risk and a too-small reset is invalid anyway).
        if (trigger.len < quic_retry.min_stateless_reset_len) return;

        // Rate limit before doing any work (§21.11).
        if (!self.takeResetToken()) return;

        // Size the reset like a plausible 1-RTT packet but never larger than the
        // triggering datagram (§10.3.3). Cap at a modest size so we never reflect a
        // large datagram back; the token lives in the trailing 16 bytes regardless.
        const max_reset_len: usize = 64;
        const reset_len = @min(@min(trigger.len, max_reset_len), @as(usize, quic_retry.retry_packet_max));
        if (reset_len < quic_retry.min_stateless_reset_len) return;

        const token = quic_retry.statelessResetToken(self.secret(), dcid);
        var out: [64]u8 = undefined;
        const n = quic_retry.encodeStatelessReset(out[0..reset_len], token) catch return;
        if (n > trigger.len) return; // defensive: never amplify
        const sock = if (self.socket) |*s| s else return;
        sock.sendTo(from, out[0..n]);
    }

    /// Token-bucket gate for stateless resets (RFC 9000 §21.11). Refills
    /// `reset_rate_per_s` tokens per second up to `reset_burst`, then consumes one
    /// per reset. Returns false (drop the reset) when the bucket is empty.
    fn takeResetToken(self: *WebTransportListener) bool {
        const now = nowNs();
        if (self.reset_last_refill_ns == 0) self.reset_last_refill_ns = now;
        if (now > self.reset_last_refill_ns) {
            const elapsed_s = @as(f64, @floatFromInt(now - self.reset_last_refill_ns)) /
                @as(f64, @floatFromInt(std.time.ns_per_s));
            self.reset_tokens = @min(
                @as(f64, @floatFromInt(self.reset_burst)),
                self.reset_tokens + elapsed_s * self.reset_rate_per_s,
            );
            self.reset_last_refill_ns = now;
        }
        if (self.reset_tokens < 1.0) return false;
        self.reset_tokens -= 1.0;
        return true;
    }

    /// Drive QUIC recv → H3 service → flush for one connection, then handle any
    /// session lifecycle events and pump its IRC bridge. `from` is the datagram's
    /// UDP source address, fed into the QUIC core so connection migration + path
    /// validation (RFC 9000 §9) can run; after recv we reconcile `conn.peer` with
    /// whatever path the core migrated to (so replies and the PROXY header follow
    /// a validated address change).
    fn feedConnection(self: *WebTransportListener, conn: *Connection, data: []const u8, from: TransportAddress) void {
        const now = nowNs();
        conn.conn.recvDatagramFrom(data, pathFromAddr(from), now) catch |err| {
            // A malformed/undecryptable datagram is dropped by the lower layer;
            // a hard error means the connection is unusable → tear it down.
            dbg("recvDatagramFrom error: {s} → teardown", .{@errorName(err)});
            self.teardownConnection(conn);
            return;
        };
        // Follow a validated migration: the core only changes its primary path on
        // a matching PATH_RESPONSE, so this address is already validated.
        conn.peer = addrFromPath(conn.conn.currentPath());
        self.serviceConnection(conn, now);
    }

    /// Run H3 service + event handling + bridge pump + flush for one connection.
    /// Any step that destroys the connection short-circuits the rest (the `conn`
    /// pointer is freed by `teardownConnection`, so nothing may touch it after).
    fn serviceConnection(self: *WebTransportListener, conn: *Connection, now: u64) void {
        conn.h3.service() catch |err| {
            dbg("serviceConnection: h3.service error {s} → teardown", .{@errorName(err)});
            self.teardownConnection(conn);
            return;
        };
        self.drainEvents(conn); // never tears down (only opens/closes the bridge)
        if (self.echo_wt_datagrams) self.pumpDatagramEcho(conn);
        if (!self.pumpBridge(conn)) return; // may tear down on a TCP/WT fault
        self.flush(conn);

        // Drive idle / PTO timers.
        if (conn.conn.onTimeout(now)) |owed| {
            if (owed) self.flush(conn);
        } else |err| {
            // Idle timeout (or fatal) → close the connection.
            dbg("serviceConnection: onTimeout error {s} → teardown", .{@errorName(err)});
            self.teardownConnection(conn);
            return;
        }
        if (conn.conn.isClosing()) {
            dbg("serviceConnection: conn.isClosing() → teardown", .{});
            self.teardownConnection(conn);
        }
    }

    /// Periodic per-iteration work: advance timers + pump bridges for every live
    /// connection (called on every pump wake so an idle connection still ticks).
    fn serviceAll(self: *WebTransportListener) void {
        const now = nowNs();
        var i: usize = 0;
        while (i < self.conns.items.len) : (i += 1) {
            const conn = self.conns.items[i] orelse continue;
            self.serviceConnection(conn, now);
        }
    }

    // -----------------------------------------------------------------------
    // WebTransport session events → IRC loopback bridge
    // -----------------------------------------------------------------------

    fn drainEvents(self: *WebTransportListener, conn: *Connection) void {
        while (conn.h3.nextEvent()) |ev| {
            switch (ev) {
                .session_established => {
                    self.openBridge(conn);
                },
                .session_closed => {
                    self.closeBridge(conn);
                },
                .connect_rejected => {},
                // A plain HTTP/3 GET/POST/… was answered directly by the H3
                // layer (curl/browser probe). It never opens the IRC bridge.
                .http_responded => {},
            }
        }
        // Discover the client's WT bidi data stream once established.
        if (conn.irc_fd != null and !conn.have_wt_stream) {
            if (firstClientWtBidiStream(conn.h3)) |sid| {
                conn.wt_stream_id = sid;
                conn.have_wt_stream = true;
            }
        }
    }

    /// On session establishment, open the loopback TCP connection to the IRC
    /// listener (the daemon will treat this as an ordinary local client).
    fn openBridge(self: *WebTransportListener, conn: *Connection) void {
        if (conn.irc_fd != null) return; // already bridged (one session per conn)
        const fd = connectLoopbackTcp(self.irc_port) orelse return;
        // Non-blocking so the single pump thread never stalls on a slow read.
        if (!setNonBlocking(fd) or (self.send_proxy_header and !self.writeProxyHeader(conn, fd))) {
            _ = sys.close(fd);
            return;
        }
        conn.irc_fd = fd;
    }

    fn closeBridge(self: *WebTransportListener, conn: *Connection) void {
        _ = self;
        if (conn.irc_fd) |fd| {
            _ = sys.close(fd);
            conn.irc_fd = null;
        }
        conn.have_wt_stream = false;
        conn.wt_stream_id = null;
    }

    /// Move bytes both directions between the WT data stream and the TCP socket.
    /// WT bidi stream → TCP, and TCP → `writeWtStream`. Non-blocking. Returns
    /// `false` if the connection was torn down (a TCP/WT fault); the caller must
    /// then NOT touch `conn` again (the pointer is freed). Returns `true` if the
    /// connection is still alive (including the no-bridge-yet and IRC-closed
    /// cases — the latter closes only the session, not the QUIC connection).
    fn pumpBridge(self: *WebTransportListener, conn: *Connection) bool {
        const fd = conn.irc_fd orelse return true;
        const sid = conn.wt_stream_id orelse return true;

        var buf: [proxy_chunk_len]u8 = undefined;

        // WT stream → TCP (browser → IRC daemon).
        while (true) {
            const n = conn.h3.readWtStream(sid, &buf);
            if (n == 0) break;
            if (!writeAllFd(fd, buf[0..n])) {
                self.teardownConnection(conn);
                return false;
            }
        }

        // TCP → WT stream (IRC daemon → browser).
        while (true) {
            const rc = sys.read(fd, &buf, buf.len);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) {
                        // Daemon closed the IRC connection → close the WT session
                        // (but keep the QUIC connection alive to deliver the FIN).
                        conn.h3.closeSession() catch {};
                        self.closeBridge(conn);
                        return true;
                    }
                    conn.h3.writeWtStream(sid, buf[0..n], false) catch {
                        self.teardownConnection(conn);
                        return false;
                    };
                },
                .AGAIN => break, // no more TCP data right now
                .INTR => continue,
                else => {
                    self.teardownConnection(conn);
                    return false;
                },
            }
        }
        return true;
    }

    /// Interop datagram-echo pump (only runs when `echo_wt_datagrams` is set).
    /// Drains every WebTransport datagram the session has received and re-queues
    /// each one back to the peer verbatim. The queued datagrams are flushed by
    /// the caller's subsequent `flush(conn)`. Bounded: `recvWtDatagram` yields at
    /// most the engine's bounded datagram inbox per service tick, so this loop
    /// cannot run unbounded. Echo failures are non-fatal (a full send queue just
    /// drops; the next tick retries the next datagram).
    fn pumpDatagramEcho(self: *WebTransportListener, conn: *Connection) void {
        _ = self;
        while (conn.h3.recvWtDatagram() catch null) |payload| {
            defer conn.h3.allocator.free(payload);
            conn.h3.sendWtDatagram(payload) catch {};
        }
    }

    /// Prepend a PROXY v1 line carrying the real QUIC peer address. Works for
    /// both families: an IPv4 peer (incl. an IPv4-mapped one, surfaced as a
    /// 4-byte address) → TCP4 with a 127.0.0.1 destination; a native IPv6 peer →
    /// TCP6 with a ::1 destination. The peer address is already a
    /// `TransportAddress`, so the family is just its `ip_len`.
    fn writeProxyHeader(self: *WebTransportListener, conn: *Connection, fd: sys.fd_t) bool {
        _ = self;
        var out: [proxy_protocol.v1_max_line_len]u8 = undefined;
        const peer = conn.peer;
        var dst_ip: [16]u8 = @splat(0);
        const family: proxy_protocol.Family = switch (peer.ip_len) {
            4 => blk: {
                dst_ip[0..4].* = [_]u8{ 127, 0, 0, 1 };
                break :blk .tcp4;
            },
            16 => blk: {
                dst_ip[15] = 1; // ::1
                break :blk .tcp6;
            },
            else => return false, // never publish a bridge without its mandatory header
        };
        const hdr = proxy_protocol.Header{
            .family = family,
            .src_ip = peer.ip,
            .dst_ip = dst_ip,
            .src_port = peer.port,
            .dst_port = 0,
        };
        const line = proxy_protocol.buildV1(&out, hdr) catch return false;
        return writeAllFd(fd, line);
    }

    /// Flush all datagrams the QUIC engine owes. Most go to the connection's
    /// current primary path (`conn.peer`); a datagram carrying a `dest` override
    /// is a path-validation probe (a PATH_CHALLENGE, RFC 9000 §8.2.1) bound for a
    /// candidate (not-yet-migrated) address, so it is routed there instead. App
    /// data thus keeps flowing to the old path while the new one is validated.
    fn flush(self: *WebTransportListener, conn: *Connection) void {
        var out: std.ArrayList(quic_conn.OutDatagram) = .empty;
        defer {
            for (out.items) |d| self.allocator.free(d.bytes);
            out.deinit(self.allocator);
        }
        _ = conn.conn.sendDatagrams(&out) catch |err| {
            dbg("sendDatagrams error: {s}", .{@errorName(err)});
            return;
        };
        const sock = if (self.socket) |*s| s else return;
        if (out.items.len > 0) {
            var total: usize = 0;
            for (out.items) |d| total += d.bytes.len;
            dbg("flush: sending {d} datagram(s), {d} bytes total", .{ out.items.len, total });
        }
        for (out.items) |d| {
            const dst = if (d.dest) |p| addrFromPath(p) else conn.peer;
            sock.sendTo(dst, d.bytes);
        }
    }

    // -----------------------------------------------------------------------
    // Connection table
    // -----------------------------------------------------------------------

    fn lookup(self: *WebTransportListener, cid: []const u8) ?*Connection {
        const idx = self.by_cid.get(cid) orelse return null;
        return self.conns.items[idx];
    }

    /// Address-validation provenance for a new connection. `original_dcid` is the
    /// DCID of the client's first Initial (RFC 9000 §7.3 ODCID); when the
    /// connection followed a Retry, `retry_scid` is the SCID the server chose in
    /// the Retry packet. Without a Retry, `original_dcid == init_dcid` and
    /// `retry_scid == null`.
    const RetryInfo = struct {
        original_dcid: []const u8,
        retry_scid: ?[]const u8 = null,
    };

    fn createConnection(
        self: *WebTransportListener,
        init_dcid: []const u8,
        from: TransportAddress,
        retry: RetryInfo,
    ) ?*Connection {
        if (self.liveCount() >= self.max_connections) return null;
        if (init_dcid.len > quic_packet.max_connection_id_len) return null;
        if (retry.original_dcid.len > quic_packet.max_connection_id_len) return null;
        if (retry.retry_scid) |rs| {
            if (rs.len > quic_packet.max_connection_id_len) return null;
        }

        // Mint a unique server SCID (8 bytes: counter || marker).
        var scid: [8]u8 = undefined;
        std.mem.writeInt(u64, scid[0..8], self.scid_counter, .big);
        self.scid_counter +%= 1;

        const conn = self.allocator.create(Connection) catch return null;
        errdefer self.allocator.destroy(conn);

        // Populate the connection's *stable* connection-id storage FIRST so the
        // QUIC transport parameters can borrow it (the handshake holds the param
        // slices by reference and encodes them lazily into EncryptedExtensions,
        // long after this function returns — a local `scid`/`init_dcid` would be a
        // dangling pointer by then).
        conn.scid = undefined;
        conn.scid_len = @intCast(scid.len);
        conn.init_dcid = undefined;
        conn.init_dcid_len = @intCast(init_dcid.len);
        @memcpy(conn.scid[0..scid.len], &scid);
        @memcpy(conn.init_dcid[0..init_dcid.len], init_dcid);
        // ODCID = the original (pre-Retry) DCID — equals init_dcid without a Retry.
        conn.orig_dcid = undefined;
        conn.orig_dcid_len = @intCast(retry.original_dcid.len);
        @memcpy(conn.orig_dcid[0..retry.original_dcid.len], retry.original_dcid);
        // retry_source_connection_id, only when a Retry happened.
        conn.retry_scid_len = 0;
        if (retry.retry_scid) |rs| {
            conn.retry_scid_len = @intCast(rs.len);
            @memcpy(conn.retry_scid[0..rs.len], rs);
        }

        const qconn = self.allocator.create(quic_conn.Conn) catch {
            self.allocator.destroy(conn);
            return null;
        };
        // RFC 9000 §7.3: the server MUST set `original_destination_connection_id`
        // to the client's first-Initial DCID (and `initial_source_connection_id`
        // to its own SCID). A real QUIC client (curl/ngtcp2) validates this and
        // closes with TRANSPORT_PARAMETER_ERROR (0x08) if it is missing/wrong —
        // both must point at the stable per-connection storage above.
        qconn.* = quic_conn.Conn.initServer(self.allocator, .{
            .cert_chain = self.tls.cert_chain,
            .signing_key = self.tls.signing_key,
            .alpn_protocols = &[_][]const u8{"h3"},
            .transport_params = serverTransportParams(conn.scidSlice(), conn.origDcidSlice(), conn.retryScidSlice()),
            .local_cid = conn.scidSlice(),
        }) catch {
            self.allocator.destroy(qconn);
            self.allocator.destroy(conn);
            return null;
        };

        const h3 = self.allocator.create(http3_conn.Http3Conn) catch {
            qconn.deinit();
            self.allocator.destroy(qconn);
            self.allocator.destroy(conn);
            return null;
        };
        h3.* = http3_conn.Http3Conn.init(self.allocator, qconn);

        conn.peer = from;
        conn.conn = qconn;
        conn.h3 = h3;
        conn.irc_fd = null;
        conn.wt_stream_id = null;
        conn.have_wt_stream = false;

        // Register the connection slot.
        const idx = self.appendSlot(conn) catch {
            self.destroyConnection(conn);
            return null;
        };

        // Index by both demux keys; failure to index → drop the connection.
        self.indexCid(conn.initDcidSlice(), idx) catch {
            self.removeSlot(idx);
            self.destroyConnection(conn);
            return null;
        };
        self.indexCid(conn.scidSlice(), idx) catch {
            _ = self.by_cid.remove(conn.initDcidSlice());
            self.removeSlot(idx);
            self.destroyConnection(conn);
            return null;
        };
        return conn;
    }

    fn indexCid(self: *WebTransportListener, cid: []const u8, idx: usize) !void {
        // Avoid a duplicate-key dupe leak if init_dcid == scid (never, but safe).
        if (self.by_cid.contains(cid)) {
            try self.by_cid.put(self.allocator, cid, idx);
            return;
        }
        const key = try self.allocator.dupe(u8, cid);
        errdefer self.allocator.free(key);
        try self.by_cid.put(self.allocator, key, idx);
    }

    fn appendSlot(self: *WebTransportListener, conn: *Connection) !usize {
        // Reuse a freed slot if one exists.
        for (self.conns.items, 0..) |slot, i| {
            if (slot == null) {
                self.conns.items[i] = conn;
                return i;
            }
        }
        try self.conns.append(self.allocator, conn);
        return self.conns.items.len - 1;
    }

    fn removeSlot(self: *WebTransportListener, idx: usize) void {
        if (idx < self.conns.items.len) self.conns.items[idx] = null;
    }

    /// Remove a connection from the table (freeing its cid keys) and destroy it.
    fn teardownConnection(self: *WebTransportListener, conn: *Connection) void {
        // Find + clear its slot.
        for (self.conns.items, 0..) |slot, i| {
            if (slot == conn) {
                self.conns.items[i] = null;
                break;
            }
        }
        // Remove both demux keys (free the owned key strings).
        self.unindexCid(conn.initDcidSlice());
        self.unindexCid(conn.scidSlice());
        self.destroyConnection(conn);
    }

    fn unindexCid(self: *WebTransportListener, cid: []const u8) void {
        if (self.by_cid.fetchRemove(cid)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    fn destroyConnection(self: *WebTransportListener, conn: *Connection) void {
        if (conn.irc_fd) |fd| _ = sys.close(fd);
        conn.h3.deinit();
        self.allocator.destroy(conn.h3);
        conn.conn.deinit();
        self.allocator.destroy(conn.conn);
        self.allocator.destroy(conn);
    }

    fn liveCount(self: *const WebTransportListener) usize {
        var n: usize = 0;
        for (self.conns.items) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }
};

// ===========================================================================
// Helpers
// ===========================================================================

/// Local transport parameters for a server connection. Generous stream/data
/// windows so a full IRC session streams without artificial flow-control stalls.
///
/// `scid` is this server's chosen Source Connection ID (→ `initial_source_
/// connection_id`). `original_dcid` is the Destination Connection ID the client
/// put in its very first Initial; RFC 9000 §7.3 requires the server to echo it
/// as `original_destination_connection_id` so the client can authenticate that
/// the transport parameters came from the endpoint it addressed. Both slices
/// must outlive the handshake (the encoder borrows them); callers pass the
/// connection's stable per-connection storage.
fn serverTransportParams(
    scid: []const u8,
    original_dcid: []const u8,
    retry_scid: ?[]const u8,
) quic_transport_params.TransportParameters {
    return .{
        .original_destination_connection_id = original_dcid,
        .initial_source_connection_id = scid,
        // RFC 9000 §7.3: present only when the connection followed a Retry; it is
        // the SCID the server chose in the Retry packet. ngtcp2/curl rejects the
        // handshake (TRANSPORT_PARAMETER_ERROR) if this is missing after a Retry
        // or present without one.
        .retry_source_connection_id = retry_scid,
        .max_idle_timeout = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_streams_bidi = 100,
        // RFC 9000 §18.2: advertise a non-trivial uni-stream window + ack delay
        // bits + active CID limit so an interop client's H3 control/QPACK uni
        // streams flow and its CID bookkeeping is satisfied.
        .initial_max_stream_data_uni = 256 * 1024,
        .initial_max_streams_uni = 8,
        .active_connection_id_limit = 2,
        // RFC 9221 §3: advertise a non-zero max DATAGRAM frame size so the peer
        // may send QUIC DATAGRAM frames. WebTransport datagrams (RFC 9297/9220)
        // ride these, so a browser (Chrome) only enables WT datagrams once it
        // sees this. 1200 comfortably covers a WT datagram (quarter-stream-id
        // varint + payload) inside the QUIC min-MTU envelope.
        .max_datagram_frame_size = 1200,
    };
}

/// Map the listener's `TransportAddress` onto the QUIC core's socketless
/// `PathAddress` (the core never imports the socket layer). They mirror each
/// other field-for-field (16-byte IP slot + len + port).
fn pathFromAddr(addr: TransportAddress) quic_conn.PathAddress {
    return quic_conn.PathAddress.fromParts(addr.ip[0..addr.ip_len], addr.port);
}

/// The inverse of `pathFromAddr`: turn a migrated `PathAddress` from the QUIC
/// core back into the listener's `TransportAddress` for sending.
fn addrFromPath(path: quic_conn.PathAddress) TransportAddress {
    return .{ .ip = path.ip, .ip_len = path.ip_len, .port = path.port };
}

/// Peek the Destination Connection ID out of a QUIC packet header without
/// decrypting. Long header: parse the dcid-len-prefixed field. Short header:
/// the dcid is a fixed 8 bytes (our server SCID length) — we issue 8-byte SCIDs.
fn peekDestCid(data: []const u8) ?[]const u8 {
    if (data.len < 1) return null;
    const is_long = (data[0] & 0x80) != 0;
    if (is_long) {
        // first(1) + version(4) + dcid_len(1) + dcid...
        if (data.len < 6) return null;
        const dcid_len = data[5];
        if (dcid_len > quic_packet.max_connection_id_len) return null;
        if (data.len < 6 + dcid_len) return null;
        return data[6 .. 6 + dcid_len];
    }
    // Short header: first(1) + dcid(8). We always issue 8-byte SCIDs.
    const dcid_len: usize = 8;
    if (data.len < 1 + dcid_len) return null;
    return data[1 .. 1 + dcid_len];
}

/// The fields of a long-header Initial the admission policy needs, parsed
/// without decrypting. Slices borrow from the input datagram.
const InitialHeader = struct {
    version: u32,
    /// The client-chosen Destination Connection ID (stable for the handshake;
    /// also the "original DCID" the Retry token binds, RFC 9000 §17.2.5.2).
    dcid: []const u8,
    /// The client's Source Connection ID (becomes the Retry/VN reply's DCID).
    scid: []const u8,
    /// The address-validation token the client echoed (empty on a first Initial).
    token: []const u8,
};

/// Parse a long-header Initial's version, connection ids, and token, bounds-
/// checked. Returns null for a non-Initial long header or any truncation, so a
/// malformed datagram is dropped without allocation (and never amplifies).
///
/// Layout (RFC 9000 §17.2.2): first(1) ‖ version(4) ‖ DCIDL(1) ‖ DCID ‖
/// SCIDL(1) ‖ SCID ‖ TokenLen(varint) ‖ Token ‖ Length(varint) ‖ ...
fn parseInitialHeader(data: []const u8) ?InitialHeader {
    if (data.len < 6) return null;
    if ((data[0] & 0x80) == 0) return null; // not a long header

    // Long packet type lives in bits 4–5 of the first byte. Only Initial (0b00)
    // may create a connection via this path; the type bits are NOT
    // header-protected on a long header, so we can read them in the clear.
    const ptype = (data[0] >> 4) & 0x03;
    if (ptype != @intFromEnum(quic_packet.LongPacketType.initial)) return null;

    const version = std.mem.readInt(u32, data[1..5], .big);

    var pos: usize = 5;
    if (pos >= data.len) return null;
    const dcid_len = data[pos];
    pos += 1;
    if (dcid_len > quic_packet.max_connection_id_len) return null;
    if (pos + dcid_len + 1 > data.len) return null;
    const dcid = data[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = data[pos];
    pos += 1;
    if (scid_len > quic_packet.max_connection_id_len) return null;
    if (pos + scid_len > data.len) return null;
    const scid = data[pos .. pos + scid_len];
    pos += scid_len;

    // Token length varint, then the token bytes.
    const tok_vi = decodeVarintAt(data, pos) orelse return null;
    pos += tok_vi.len;
    const tok_len = std.math.cast(usize, tok_vi.value) orelse return null;
    if (pos + tok_len > data.len) return null;
    const token = data[pos .. pos + tok_len];

    return .{ .version = version, .dcid = dcid, .scid = scid, .token = token };
}

/// A QUIC varint decoded from `data[off..]` (RFC 9000 §16). Returns null on
/// truncation. Tolerant of non-minimal encodings (the spec permits them).
const DecodedVarint = struct { value: u64, len: usize };
fn decodeVarintAt(data: []const u8, off: usize) ?DecodedVarint {
    if (off >= data.len) return null;
    const tag = data[off] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (off + len > data.len) return null;
    var value: u64 = data[off] & 0x3f;
    var i: usize = 1;
    while (i < len) : (i += 1) value = (value << 8) | data[off + i];
    return .{ .value = value, .len = len };
}

/// The QUIC stream id of the first *client-opened* WebTransport bidirectional
/// stream registered on the session, distinct from the CONNECT stream. This is
/// the WT data channel carrying the IRC byte stream.
fn firstClientWtBidiStream(h3: *http3_conn.Http3Conn) ?u64 {
    const s = if (h3.session) |*ss| ss else return null;
    for (s.streams.items) |wt| {
        if (wt.is_bidirectional and wt.stream_id != s.session_id.stream_id) {
            return wt.stream_id;
        }
    }
    return null;
}

/// Map the legacy IPv4-in-network-byte-order bind selector to the dual-stack
/// socket's `BindAddr`. `any_be` (0) → bind `[::]` (all interfaces, both
/// families). A configured v4 address → bind it v4-mapped (`::ffff:a.b.c.d`), so
/// a v4-only operator config still works over the single dual-stack socket.
fn bindAddrFromBe(bind_be: u32) DualStackUdpSocket.BindAddr {
    if (bind_be == any_be) return .any;
    // `bind_be` is already in network byte order; its bytes are the v4 octets.
    return .{ .v4_mapped = @bitCast(bind_be) };
}

fn nowNs() u64 {
    if (comptime builtin.os.tag == .windows) return @as(u64, @intCast(@max(@import("../substrate/platform.zig").monotonicMillis(), 0))) * std.time.ns_per_ms;
    var ts: sys.timespec = undefined;
    if (posix.errno(sys.clock_gettime(posix.CLOCK.MONOTONIC, &ts)) != .SUCCESS) @panic("WebTransport monotonic clock unavailable");
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Diagnostic tracing for QUIC/HTTP3 interop debugging, gated on the
/// `ONYX_QUIC_DEBUG` environment variable (any non-empty value enables it).
/// Off by default and zero-cost on the hot path beyond the env check; intended
/// for `tools/quic_interop.sh` runs and field interop triage, never normal
/// operation.
var dbg_enabled: ?bool = null;
fn dbg(comptime fmt: []const u8, args: anytype) void {
    const on = dbg_enabled orelse blk: {
        const enabled = envIsSet("ONYX_QUIC_DEBUG");
        dbg_enabled = enabled;
        break :blk enabled;
    };
    if (!on) return;
    dlog.log("[quic-dbg] " ++ fmt ++ "\n", args);
}

/// Whether environment variable `name` is present and non-empty. Reads
/// `/proc/self/environ` (NUL-separated `KEY=VALUE` records) via raw syscalls —
/// Zig 0.16 dropped `std.posix.getenv`/`std.os.environ` on a no-libc Linux
/// target, and this layer has no `std.process.Init.environ_map` handle.
fn envIsSet(name: []const u8) bool {
    if (comptime builtin.os.tag == .windows) return false;
    if (comptime builtin.os.tag != .linux) {
        var key: [128:0]u8 = undefined;
        if (name.len >= key.len or std.mem.indexOfScalar(u8, name, 0) != null) return false;
        @memcpy(key[0..name.len], name);
        key[name.len] = 0;
        const value = std.c.getenv(key[0..name.len :0]) orelse return false;
        return value[0] != 0;
    }
    const path = "/proc/self/environ";
    const O_RDONLY = 0;
    const rc = sys.open(path, .{ .ACCMODE = .RDONLY }, 0);
    _ = O_RDONLY;
    const signed_fd: isize = @bitCast(rc);
    if (signed_fd < 0) return false;
    const fd: sys.fd_t = @intCast(rc);
    defer _ = sys.close(fd);

    var buf: [16384]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = sys.read(fd, buf[total..].ptr, buf.len - total);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        total += n;
    }
    var it = std.mem.splitScalar(u8, buf[0..total], 0);
    while (it.next()) |record| {
        const eq = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (std.mem.eql(u8, record[0..eq], name)) return record.len > eq + 1;
    }
    return false;
}

fn sleepMs(ms: u32) void {
    if (comptime builtin.os.tag == .windows) return;
    if (comptime builtin.os.tag != .linux) return os_runtime.sleepMillis(ms);
    var req = sys.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = sys.nanosleep(&req, null);
}

fn connectLoopbackTcp(port: u16) ?sys.fd_t {
    if (comptime builtin.os.tag == .windows) return null;
    if (comptime builtin.os.tag != .linux) return native_network.connect(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } }, 1000) catch null;
    const rc = sys.socket(posix.AF.INET, sys.SOCK.STREAM | sys.SOCK.CLOEXEC, sys.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return null;
    const fd: sys.fd_t = @intCast(rc);
    var addr = sys.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    if (posix.errno(sys.connect(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS) {
        _ = sys.close(fd);
        return null;
    }
    return fd;
}

fn setNonBlocking(fd: sys.fd_t) bool {
    if (comptime builtin.os.tag == .windows) return false;
    os_runtime.setNonblocking(fd) catch return false;
    return true;
}

fn writeAllFd(fd: sys.fd_t, bytes: []const u8) bool {
    if (comptime builtin.os.tag == .windows) return false;
    if (comptime builtin.os.tag != .linux) {
        // A slow IRC peer cannot pin this single UDP pump indefinitely. Never
        // replay already-sent bytes: failure tears down this bridge.
        const deadline = nowNs() + std.time.ns_per_s;
        var sent: usize = 0;
        while (sent < bytes.len) {
            if (nowNs() >= deadline) return false;
            const rc = sys.send(fd, bytes[sent..].ptr, bytes.len - sent, posix.MSG.NOSIGNAL | posix.MSG.DONTWAIT);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    if (rc <= 0) return false;
                    sent += @intCast(rc);
                },
                .INTR => continue,
                .AGAIN => {
                    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                    const now = nowNs();
                    if (now >= deadline) return false;
                    const remaining = @min((deadline - now) / std.time.ns_per_ms, 50);
                    const ready = sys.poll(&fds, 1, @intCast(remaining));
                    if (ready < 0 and posix.errno(ready) != .INTR) return false;
                    if (fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) return false;
                },
                else => return false,
            }
        }
        return true;
    }
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = sys.write(fd, bytes[sent..].ptr, bytes.len - sent);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return false;
                sent += n;
            },
            .INTR, .AGAIN => continue,
            else => return false,
        }
    }
    return true;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const webtransport = @import("../proto/webtransport.zig");
const qpack = @import("../proto/http3_qpack.zig");

// ---- pure unit tests: demux header parsing --------------------------------

test "peekDestCid extracts the long-header DCID" {
    // first | version(4) | dcid_len=4 | dcid(4) | scid_len=0 | ...
    const pkt = [_]u8{
        0xc0, // long header, Initial
        0x00, 0x00, 0x00, 0x01, // version 1
        0x04, 0xde, 0xad, 0xbe, 0xef, // dcid_len + dcid
        0x00, // scid_len
    };
    const cid = peekDestCid(&pkt) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, cid);
}

test "peekDestCid extracts the short-header 8-byte DCID" {
    const pkt = [_]u8{ 0x40, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb };
    const cid = peekDestCid(&pkt) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, cid);
}

test "peekDestCid rejects a truncated header" {
    try testing.expect(peekDestCid(&[_]u8{0xc0}) == null);
    try testing.expect(peekDestCid(&[_]u8{ 0x40, 1, 2 }) == null);
}

// ---- listener lifecycle: bind / port / clean shutdown ---------------------

const TestServerKeys = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    cert: []const u8,
    cert_chain: [1][]const u8,

    fn init(self: *TestServerKeys) !void {
        self.kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
        self.cert = try x509_selfsign.buildSelfSigned(&self.cert_buf, .{
            .common_name = "wt.test",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{ 0x51, 0x99 },
            .key_pair = self.kp,
            .dns_names = &.{"wt.test"},
            .is_ca = true,
        });
        self.cert_chain = .{self.cert};
    }
};

test "WebTransportListener: bind, port, and clean re-startable shutdown" {
    // Live UDP sockets; no Windows datagram backend here.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var keys: TestServerKeys = undefined;
    try keys.init();
    var lst = WebTransportListener.init(testing.allocator, .{
        .cert_chain = &keys.cert_chain,
        .signing_key = .{ .ed25519 = keys.kp },
    }, 0);
    defer lst.deinit();

    try lst.start(loopback_be, 0);
    try testing.expect(lst.port != 0);
    const before_stop = nowNs();
    lst.shutdown();
    try testing.expect(nowNs() - before_stop < std.time.ns_per_s);
    // Re-start cleanly on a fresh ephemeral port.
    try lst.start(loopback_be, 0);
    try testing.expect(lst.port != 0);
}

// ---- REAL-UDP-SOCKET end-to-end: live QUIC/H3/WT handshake + bridge --------

/// A loopback "IRC server": a blocking TCP listener thread that accepts one
/// connection, reads the bytes the bridge forwards, echoes a fixed reply, and
/// records what it saw. Stands in for the daemon's IRC listener so the test can
/// assert the WT→TCP→WT loopback proxy round-trips real bytes.
const FakeIrcServer = struct {
    listen_fd: sys.fd_t,
    port: u16,
    thread: ?std.Thread = null,
    got: [256]u8 = undefined,
    got_len: std.atomic.Value(usize) = .init(0),
    reply: []const u8,

    fn start(reply: []const u8) !*FakeIrcServer {
        const self = try testing.allocator.create(FakeIrcServer);
        errdefer testing.allocator.destroy(self);
        const rc = sys.socket(posix.AF.INET, sys.SOCK.STREAM | sys.SOCK.CLOEXEC, sys.IPPROTO.TCP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
        self.listen_fd = @intCast(rc);
        errdefer _ = sys.close(self.listen_fd);
        var addr = sys.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
        if (posix.errno(sys.bind(self.listen_fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in))) != .SUCCESS)
            return error.BindFailed;
        if (posix.errno(sys.listen(self.listen_fd, 4)) != .SUCCESS) return error.ListenFailed;
        var sa: sys.sockaddr.in = undefined;
        var slen: posix.socklen_t = @sizeOf(sys.sockaddr.in);
        _ = sys.getsockname(self.listen_fd, @ptrCast(&sa), &slen);
        self.port = std.mem.bigToNative(u16, sa.port);
        self.got_len = .init(0);
        self.reply = reply;
        self.thread = try std.Thread.spawn(.{}, accept, .{self});
        return self;
    }

    fn accept(self: *FakeIrcServer) void {
        var polls = [_]posix.pollfd{.{ .fd = self.listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        if (sys.poll(&polls, 1, 5000) <= 0) return;
        const cfd_rc = sys.accept(self.listen_fd, null, null);
        if (posix.errno(cfd_rc) != .SUCCESS) return;
        const cfd: sys.fd_t = @intCast(cfd_rc);
        defer _ = sys.close(cfd);
        const timeout = sys.timeval{ .sec = 2, .usec = 0 };
        if (posix.errno(sys.setsockopt(cfd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout), @sizeOf(@TypeOf(timeout)))) != .SUCCESS) return;
        var total: usize = 0;
        while (total < self.got.len) {
            const rc = sys.read(cfd, self.got[total..].ptr, self.got.len - total);
            if (posix.errno(rc) != .SUCCESS or rc == 0) return;
            total += @intCast(rc);
            if (std.mem.endsWith(u8, self.got[0..total], "NICK wtuser\r\n")) break;
        }
        self.got_len.store(total, .release);
        _ = writeAllFd(cfd, self.reply);
        // Hold the connection open briefly so the reply is flushed.
        sleepMs(50);
    }

    fn join(self: *FakeIrcServer) void {
        if (self.thread) |t| t.join();
        _ = sys.close(self.listen_fd);
        testing.allocator.destroy(self);
    }
};

test "WebTransportListener: live UDP QUIC/H3/WT session bridges IRC bytes both ways" {
    try exerciseLiveBridge(false, false);
}

test "WebTransportListener: native IPv6 QUIC/H3/WT bridges IRC with mandatory PROXY header" {
    try exerciseLiveBridge(true, true);
}

fn exerciseLiveBridge(ipv6: bool, proxy: bool) !void {
    // Live UDP/QUIC bridge; no Windows datagram backend here.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    // End-to-end over the DUAL-STACK socket: `lst.start` now binds an AF_INET6
    // socket with IPV6_V6ONLY=0, and the client below is a plain IPv4 loopback
    // `MediaSocket`. So this also proves the full QUIC/H3/WT handshake + IRC
    // bridge still completes after the socket swap, with the v4 client reaching
    // the dual-stack server as an IPv4-mapped source surfaced back as ipv4.
    const alloc = testing.allocator;
    var keys: TestServerKeys = undefined;
    try keys.init();

    // Fake IRC server the bridge will dial on loopback.
    var irc = try FakeIrcServer.start(":server NOTICE * :hi from irc\r\n");
    defer irc.join();

    var lst = WebTransportListener.init(alloc, .{
        .cert_chain = &keys.cert_chain,
        .signing_key = .{ .ed25519 = keys.kp },
    }, irc.port);
    defer lst.deinit();
    lst.send_proxy_header = proxy;
    try lst.startAddress(if (ipv6) .loopback_v6 else .{ .v4_mapped = .{ 127, 0, 0, 1 } }, 0);
    const server_port = lst.port;

    // A real IPv4 UDP socket acting as the QUIC/WT client. It addresses the
    // dual-stack server at 127.0.0.1:server_port; the server sees it as a
    // v4-mapped source and replies via the same dual-stack socket.
    var cli_sock = try DualStackUdpSocket.bind(if (ipv6) .loopback_v6 else .{ .v4_mapped = .{ 127, 0, 0, 1 } }, 0);
    defer cli_sock.deinit();
    cli_sock.setRecvTimeoutMs(100);
    var loopback6: [16]u8 = @splat(0);
    loopback6[15] = 1;
    const server_addr = try TransportAddress.fromBytes(if (ipv6) &loopback6 else &[_]u8{ 127, 0, 0, 1 }, server_port);

    // Build the client QUIC connection. Its Initial DCID is what the server's
    // listener will demux + mint a connection for.
    const client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const initial_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    var client = try quic_conn.Conn.initClient(alloc, .{
        .alpn_protocols = &[_][]const u8{"h3"},
        .transport_params = .{
            .initial_source_connection_id = &client_cid,
            .initial_max_data = 1 << 20,
            .initial_max_stream_data_bidi_local = 256 * 1024,
            .initial_max_stream_data_bidi_remote = 256 * 1024,
            .initial_max_streams_bidi = 100,
        },
        .local_cid = &client_cid,
        .initial_dcid = &initial_dcid,
        .x25519_seed = @as([32]u8, @splat(0x42)),
        .client_random = @as([32]u8, @splat(0x11)),
    });
    defer client.deinit();

    // Drive the QUIC handshake over the REAL UDP socket pair.
    var established = false;
    var round: usize = 0;
    while (round < 40 and !established) : (round += 1) {
        try sendQuic(alloc, &client, &cli_sock, server_addr);
        // Receive whatever the server flushed back.
        try recvQuicAll(&client, &cli_sock);
        if (client.isEstablished()) established = true;
    }
    try testing.expect(established);

    // Now run the WT control + Extended CONNECT, then open a WT bidi data stream
    // and write an IRC line. We reuse the codecs directly (no WtClient struct).
    try sendControlAndConnect(alloc, &client, "irc.example", "/wt");
    // Drive until the CONNECT is answered 200.
    var ok = false;
    round = 0;
    var connect_stream: u64 = undefined;
    connect_stream = lastOpenedBidi(&client);
    while (round < 40 and !ok) : (round += 1) {
        try sendQuic(alloc, &client, &cli_sock, server_addr);
        try recvQuicAll(&client, &cli_sock);
        ok = connectAnswered200(alloc, &client, connect_stream) catch false;
    }
    try testing.expect(ok);

    // Open a WT bidi data stream and write an IRC registration line.
    const session_id = try webtransport.SessionId.initClientBidirectional(connect_stream);
    const data_stream = try client.openStream();
    const prefix = try webtransport.encodeStreamSignal(alloc, webtransport.StreamType.webtransport_bidirectional, session_id);
    defer alloc.free(prefix);
    try client.sendStream(data_stream, prefix, false);
    const irc_line = "NICK wtuser\r\n";
    try client.sendStream(data_stream, irc_line, false);

    // Pump until the fake IRC server has seen the forwarded bytes AND the client
    // has received the server's echoed reply over the WT data stream.
    var reply_buf: [256]u8 = undefined;
    var reply_total: usize = 0;
    round = 0;
    while (round < 60) : (round += 1) {
        try sendQuic(alloc, &client, &cli_sock, server_addr);
        try recvQuicAll(&client, &cli_sock);
        // Read any WT-stream bytes the server proxied from the IRC reply.
        reply_total += readWtBidi(&client, data_stream, reply_buf[reply_total..], session_id);
        if (irc.got_len.load(.acquire) > 0 and reply_total >= irc.reply.len) break;
        sleepMs(5);
    }

    // The fake IRC server received the IRC line forwarded by the bridge.
    const received = irc.got[0..irc.got_len.load(.acquire)];
    if (proxy) {
        const header = try proxy_protocol.parseV1(received);
        try testing.expectEqual(proxy_protocol.Family.tcp6, header.header.family);
        try testing.expectEqualSlices(u8, &loopback6, header.header.srcBytes());
        try testing.expectEqualSlices(u8, &loopback6, header.header.dstBytes());
        try testing.expectEqual(try cli_sock.localPort(), header.header.src_port);
        try testing.expectEqual(@as(u16, 0), header.header.dst_port);
        try testing.expectEqualStrings(irc_line, received[header.consumed..]);
    } else try testing.expectEqualStrings(irc_line, received);
    // The client received the IRC server's reply, proxied back over the WT stream.
    try testing.expectEqualStrings(irc.reply, reply_buf[0..reply_total]);
}

// -- test-only QUIC/WT client glue over a real UDP socket -------------------

fn sendQuic(alloc: std.mem.Allocator, conn: *quic_conn.Conn, sock: anytype, dst: TransportAddress) !void {
    var out: std.ArrayList(quic_conn.OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try conn.sendDatagrams(&out);
    for (out.items) |d| sock.sendTo(dst, d.bytes);
}

fn recvQuicAll(conn: *quic_conn.Conn, sock: anytype) !void {
    var buf: [recv_buf_len]u8 = undefined;
    var tries: usize = 0;
    while (tries < 8) : (tries += 1) {
        const got = sock.recvFrom(&buf) orelse return;
        conn.recvDatagram(got.data) catch {};
    }
}

fn sendControlAndConnect(alloc: std.mem.Allocator, conn: *quic_conn.Conn, authority: []const u8, path: []const u8) !void {
    const ctl = try conn.openUniStream();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    var vbuf: [8]u8 = undefined;
    try out.appendSlice(alloc, try webtransport.encodeVarint(http3_conn.UniStreamType.control, &vbuf));
    const body = try http3_conn.encodeSettingsBody(alloc, http3_conn.Settings.serverDefault());
    defer alloc.free(body);
    try http3_conn.encodeFrame(alloc, &out, http3_conn.FrameType.settings, body);
    try conn.sendStream(ctl, out.items, false);

    const cs = try conn.openStream();
    const block = try http3_conn.encodeConnectHeaders(alloc, authority, path);
    defer alloc.free(block);
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);
    try http3_conn.encodeFrame(alloc, &req, http3_conn.FrameType.headers, block);
    try conn.sendStream(cs, req.items, false);
}

/// The last bidi stream id this client opened (the CONNECT stream).
fn lastOpenedBidi(conn: *quic_conn.Conn) u64 {
    // Client bidi ids are 0,4,8,…; next_bidi_stream points past the last issued.
    return conn.next_bidi_stream - 4;
}

fn connectAnswered200(alloc: std.mem.Allocator, conn: *quic_conn.Conn, cs: u64) !bool {
    var scratch: [2048]u8 = undefined;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    while (true) {
        const n = conn.readStream(cs, &scratch);
        if (n == 0) break;
        try buf.appendSlice(alloc, scratch[0..n]);
    }
    var pos: usize = 0;
    const frame = (try http3_conn.findFrame(buf.items, &pos, http3_conn.FrameType.headers)) orelse return false;
    var section = try qpack.decodeFieldSectionAlloc(alloc, frame.payload);
    defer section.deinit(alloc);
    for (section.headers) |h| {
        if (std.mem.eql(u8, h.name, ":status") and std.mem.eql(u8, h.value, "200")) return true;
    }
    return false;
}

/// Read WT-bidi payload from a client-opened stream: the server never sends a
/// signal prefix back on this stream (it reuses the same stream id), so the
/// bytes are the raw proxied IRC reply.
fn readWtBidi(conn: *quic_conn.Conn, sid: u64, dst: []u8, session_id: webtransport.SessionId) usize {
    _ = session_id;
    if (dst.len == 0) return 0;
    return conn.readStream(sid, dst);
}

// ===========================================================================
// Address-validation policy tests (RFC 9000 §8 / §17.2.1 / §17.2.5)
// ===========================================================================

/// Build a synthetic long-header Initial header with the given fields and an
/// optional token, into `out`. Returns the slice. This is only the header (no
/// frames/padding) — enough to drive the listener's admission/parse path.
fn buildInitialHeader(out: []u8, version: u32, dcid: []const u8, scid: []const u8, token: []const u8) []const u8 {
    var pos: usize = 0;
    out[pos] = 0xc0; // long header, fixed bit, Initial type (0b00)
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], version, .big);
    pos += 4;
    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos..][0..scid.len], scid);
    pos += scid.len;
    // Token length varint (1-byte form for < 64).
    out[pos] = @intCast(token.len);
    pos += 1;
    @memcpy(out[pos..][0..token.len], token);
    pos += token.len;
    // A minimal Length varint + a byte so the packet looks structurally sane.
    out[pos] = 0x00;
    pos += 1;
    return out[0..pos];
}

test "parseInitialHeader extracts version, cids, and token; rejects truncation" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const scid = [_]u8{ 0x11, 0x22 };
    const token = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const pkt = buildInitialHeader(&buf, 0x0000_0001, &dcid, &scid, &token);

    const hdr = parseInitialHeader(pkt) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 0x0000_0001), hdr.version);
    try testing.expectEqualSlices(u8, &dcid, hdr.dcid);
    try testing.expectEqualSlices(u8, &scid, hdr.scid);
    try testing.expectEqualSlices(u8, &token, hdr.token);

    // A short-header (no long bit) is not an Initial.
    try testing.expect(parseInitialHeader(&[_]u8{ 0x40, 1, 2, 3, 4, 5, 6, 7, 8 }) == null);
    // Truncated mid-header → null (no panic).
    try testing.expect(parseInitialHeader(pkt[0..7]) == null);
}

/// A listener bound to a real UDP socket but NOT started (no pump thread), so we
/// can call `handleDatagram` directly and read what it sends from a peer socket.
const PolicyFixture = struct {
    keys: TestServerKeys,
    lst: WebTransportListener,
    peer: MediaSocket,
    server_addr: TransportAddress,
    peer_addr: TransportAddress,

    fn init(self: *PolicyFixture, policy: RetryPolicy) !void {
        try self.keys.init();
        self.lst = WebTransportListener.init(testing.allocator, .{
            .cert_chain = &self.keys.cert_chain,
            .signing_key = .{ .ed25519 = self.keys.kp },
        }, 0);
        self.lst.retry_policy = policy;
        // Bind the listener's DUAL-STACK UDP socket WITHOUT spawning the pump
        // thread (so we can call `handleDatagram` directly). It binds [::] but
        // serves the v4 peer below as an IPv4-mapped source.
        var sock = try DualStackUdpSocket.bind(.any, 0);
        self.lst.port = try sock.localPort();
        sock.setRecvTimeoutMs(200);
        self.lst.socket = sock;

        // A peer socket to send Initials from and read VN/Retry replies on.
        self.peer = try MediaSocket.bind(loopback_be, 0);
        self.peer.setRecvTimeoutMs(300);
        self.server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, self.lst.port);
        self.peer_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try self.peer.localPort());
    }

    fn deinit(self: *PolicyFixture) void {
        // The listener never started its pump, so deinit just frees state +
        // closes the socket we handed it.
        self.lst.deinit();
        self.peer.deinit();
    }

    /// Feed `data` to the listener as if it arrived from the peer, then read one
    /// reply datagram the listener sent back (or null on timeout).
    fn exchange(self: *PolicyFixture, data: []const u8, reply: []u8) ?usize {
        self.lst.handleDatagram(data, self.peer_addr);
        const got = self.peer.recvFrom(reply) orelse return null;
        return got.data.len;
    }
};

test "version negotiation — an Initial with version 0xff000099 yields a VN listing v1 and no connection" {
    var fx: PolicyFixture = undefined;
    try fx.init(.never);
    defer fx.deinit();

    // A real client Initial is padded to ≥1200 bytes (RFC 9000 §14.1), so the VN
    // reply (a few dozen bytes) never amplifies. We mimic that here: the parsed
    // header is the same, but the on-wire datagram is padded so the VN passes the
    // never-amplify guard.
    var buf: [1300]u8 = @splat(0);
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const hdr = buildInitialHeader(&buf, 0xff00_0099, &dcid, &scid, &.{});
    const pkt = buf[0..1200]; // header + trailing zero PADDING to 1200 bytes
    _ = hdr;

    var reply: [256]u8 = undefined;
    const n = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;

    // A VN packet: high bit set, version field == 0, lists v1 in the trailer.
    try testing.expect((reply[0] & 0x80) != 0);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, reply[1..5], .big));
    try testing.expectEqual(quic_retry.quic_version_1, std.mem.readInt(u32, reply[n - 4 ..][0..4], .big));
    // No connection was created for an unsupported version.
    try testing.expectEqual(@as(usize, 0), fx.lst.liveCount());
    // VN never amplifies relative to the trigger.
    try testing.expect(n <= pkt.len);
}

test "retry — a tokenless Initial under .always policy is answered with a Retry and no connection" {
    var fx: PolicyFixture = undefined;
    try fx.init(.always);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, &.{});

    var reply: [256]u8 = undefined;
    const n = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;

    // The reply is a Retry packet: long header, Retry type bits 0b11.
    try testing.expect((reply[0] & 0x80) != 0);
    try testing.expectEqual(@as(u8, @intFromEnum(quic_packet.LongPacketType.retry)), (reply[0] >> 4) & 0x03);
    // Retry's DCID = the client's SCID (so the client recognises the reply).
    try testing.expectEqual(@as(u8, scid.len), reply[5]);
    try testing.expectEqualSlices(u8, &scid, reply[6 .. 6 + scid.len]);
    // No connection state was allocated.
    try testing.expectEqual(@as(usize, 0), fx.lst.liveCount());
    // The Retry's integrity tag (last 16 bytes) verifies against the §5.8
    // construction over the pseudo-packet (binding the client's original DCID).
    const expected_tag = try quic_retry.retryIntegrityTag(&dcid, reply[0 .. n - quic_retry.tag_len]);
    try testing.expectEqualSlices(u8, &expected_tag, reply[n - quic_retry.tag_len .. n]);
}

test "retry — a client returning a valid token is address-validated immediately (no 3x cap)" {
    var fx: PolicyFixture = undefined;
    try fx.init(.always);
    defer fx.deinit();

    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };

    // Step 1: tokenless Initial → the listener issues a Retry carrying a token.
    var buf: [128]u8 = undefined;
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, &.{});
    var reply: [256]u8 = undefined;
    const rn = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;

    // Extract the token from the Retry: after first(1)+ver(4)+DCIDL(1)+DCID+
    // SCIDL(1)+SCID, the token runs to the 16-byte integrity tag.
    var pos: usize = 5;
    const r_dcidl = reply[pos];
    pos += 1 + r_dcidl;
    const r_scidl = reply[pos];
    pos += 1 + r_scidl;
    const token = reply[pos .. rn - quic_retry.tag_len];
    try testing.expect(token.len > 0);

    // Step 2: the client re-sends its Initial WITH the token. It must now be
    // accepted, the connection created, and the address validated (no 3× cap).
    // We call `admitNewInitial` directly (the admission decision under test);
    // feeding the synthetic header through the full recv path would tear the
    // connection down on the (intentionally undecryptable) body.
    var buf2: [256]u8 = undefined;
    const pkt2 = buildInitialHeader(&buf2, quic_retry.quic_version_1, &dcid, &scid, token);
    const conn = fx.lst.admitNewInitial(pkt2, fx.peer_addr) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), fx.lst.liveCount());
    try testing.expect(conn.conn.isAddressValidated());

    // Step 3: a REPLAY of the same token (new DCID, same IP) is rejected — the
    // listener issues a fresh Retry instead of a second validated connection.
    const dcid2 = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    var buf3: [256]u8 = undefined;
    const pkt3 = buildInitialHeader(&buf3, quic_retry.quic_version_1, &dcid2, &scid, token);
    try testing.expect(fx.lst.admitNewInitial(pkt3, fx.peer_addr) == null);
    // No new validated connection for the replayed token.
    try testing.expect(fx.lst.lookup(&dcid2) == null);
}

test "retry — a token from a different client IP is rejected" {
    var fx: PolicyFixture = undefined;
    try fx.init(.always);
    defer fx.deinit();

    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };

    // Seal a token bound to a DIFFERENT IP than the peer's loopback address.
    const sec = fx.lst.secret();
    var token_buf: [quic_retry.max_token_len]u8 = undefined;
    const tn = try quic_retry.Token.seal(&token_buf, sec, &[_]u8{ 203, 0, 113, 5 }, &dcid, nowNs());

    var buf: [256]u8 = undefined;
    const scid = [_]u8{ 0xb1, 0xb2 };
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, token_buf[0..tn]);
    // The Initial arrives from the peer's loopback IP, which the token does NOT
    // match → rejected → a fresh Retry, no connection.
    var reply: [256]u8 = undefined;
    _ = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;
    try testing.expect(fx.lst.lookup(&dcid) == null);
    try testing.expectEqual(@as(u8, @intFromEnum(quic_packet.LongPacketType.retry)), (reply[0] >> 4) & 0x03);
}

test "retry policy .never mints a connection directly (default fast path unaffected)" {
    var fx: PolicyFixture = undefined;
    try fx.init(.never);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, &.{});

    // No Retry/VN under .never: the connection is created directly (still
    // anti-amplification-limited until a Handshake validates the address). We
    // exercise the admission decision in isolation (admitNewInitial) since the
    // synthetic header has no valid encrypted body to feed through recv.
    const conn = fx.lst.admitNewInitial(pkt, fx.peer_addr) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), fx.lst.liveCount());
    try testing.expect(!conn.conn.isAddressValidated());
}

// ===========================================================================
// Stateless-reset emit (RFC 9000 §10.3) tests
// ===========================================================================

/// Build a synthetic short-header (1-RTT) datagram with an 8-byte DCID followed
/// by `body_len` padding bytes (so the whole datagram is `1 + 8 + body_len`).
/// The first byte has the high bit CLEAR (short header) and the fixed bit set.
fn buildShortHeaderDatagram(out: []u8, dcid: [8]u8, body_len: usize) []const u8 {
    out[0] = 0x40; // short header form (high bit 0), fixed bit 1
    @memcpy(out[1..9], &dcid);
    var i: usize = 0;
    while (i < body_len) : (i += 1) out[9 + i] = @intCast(i & 0xff);
    return out[0 .. 9 + body_len];
}

test "stateless reset — an unknown short-header DCID yields a reset carrying the HMAC-derived token" {
    var fx: PolicyFixture = undefined;
    try fx.init(.never);
    defer fx.deinit();

    // A 1-RTT packet for a DCID no live connection owns, large enough to carry a
    // reset (≥ min_stateless_reset_len). No connection exists, so the listener
    // must answer with a Stateless Reset.
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    var buf: [128]u8 = undefined;
    const pkt = buildShortHeaderDatagram(&buf, dcid, 40); // 49-byte datagram

    var reply: [256]u8 = undefined;
    const n = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;

    // Shaped like a 1-RTT packet: high bit clear, fixed bit set.
    try testing.expectEqual(@as(u8, 0x00), reply[0] & 0x80);
    try testing.expectEqual(@as(u8, 0x40), reply[0] & 0x40);
    // Never amplifies: the reset is no larger than the triggering datagram.
    try testing.expect(n <= pkt.len);
    try testing.expect(n >= quic_retry.min_stateless_reset_len);

    // The trailing 16 bytes are the stateless-reset token = HMAC(reset_key, DCID).
    const expected = quic_retry.statelessResetToken(fx.lst.secret(), &dcid);
    try testing.expectEqualSlices(u8, &expected, reply[n - quic_retry.stateless_reset_token_len .. n]);

    // No connection was created for the unknown short-header packet.
    try testing.expectEqual(@as(usize, 0), fx.lst.liveCount());
}

test "stateless reset — a too-small datagram yields nothing (never amplify)" {
    var fx: PolicyFixture = undefined;
    try fx.init(.never);
    defer fx.deinit();

    // A short-header packet smaller than min_stateless_reset_len (21 bytes): the
    // listener must NOT reply (no amplification, and a reset that small is
    // invalid anyway). 1 + 8 + 5 = 14 bytes < 21.
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    var buf: [64]u8 = undefined;
    const pkt = buildShortHeaderDatagram(&buf, dcid, 5);
    try testing.expect(pkt.len < quic_retry.min_stateless_reset_len);

    var reply: [256]u8 = undefined;
    // No reply (timeout → null).
    try testing.expect(fx.exchange(pkt, &reply) == null);
}

test "stateless reset — the emit is rate-limited (token bucket)" {
    var fx: PolicyFixture = undefined;
    try fx.init(.never);
    defer fx.deinit();

    // Drain the burst to a tiny allowance so the limiter is exercised quickly.
    fx.lst.reset_burst = 3;
    fx.lst.reset_tokens = 3.0;
    fx.lst.reset_rate_per_s = 0.0; // no refill within the test window
    fx.lst.reset_last_refill_ns = nowNs();

    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
    var buf: [128]u8 = undefined;
    const pkt = buildShortHeaderDatagram(&buf, dcid, 40);

    // The first 3 unknown short-header packets each get a reset; the bucket then
    // empties and further ones are dropped (no reply).
    var reply: [256]u8 = undefined;
    var got: usize = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (fx.exchange(pkt, &reply) != null) got += 1;
    }
    try testing.expectEqual(@as(usize, 3), got);
}

// ===========================================================================
// Path-address mapping (listener ↔ QUIC core) tests
// ===========================================================================

test "path mapping — TransportAddress round-trips through the QUIC-core PathAddress" {
    const ta = try TransportAddress.fromBytes(&[_]u8{ 198, 51, 100, 7 }, 4433);
    const path = pathFromAddr(ta);
    try testing.expectEqual(@as(u8, 4), path.ip_len);
    try testing.expectEqual(@as(u16, 4433), path.port);
    const back = addrFromPath(path);
    try testing.expect(back.eql(ta));

    // IPv6 (16-byte) addresses map losslessly too.
    const ta6 = try TransportAddress.fromBytes(&[_]u8{ 0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 5060);
    const back6 = addrFromPath(pathFromAddr(ta6));
    try testing.expect(back6.eql(ta6));
}

// ===========================================================================
// Real third-party interop: curl --http3 → our QUIC/HTTP3 stack
// ===========================================================================

/// Whether the system `curl` supports HTTP/3 (so the interop test is meaningful).
/// Runs `curl --version` and scans for the http3 feature; returns false on any
/// error (curl missing / unspawnable) so the caller skips rather than fails.
fn curlHasHttp3(allocator: std.mem.Allocator) bool {
    const io = std.testing.io;
    const res = std.process.run(allocator, io, .{
        .argv = &.{ "curl", "--version" },
    }) catch return false;
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);
    switch (res.term) {
        .exited => |code| if (code != 0) return false,
        else => return false,
    }
    // The Features line lists "HTTP3"; the Protocols/banner also contain
    // "http3"/"HTTP3". A case-insensitive substring scan is robust.
    return asciiContainsIgnoreCase(res.stdout, "http3");
}

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return needle.len == 0;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |c, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(c)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

test "interop: curl --http3 GET / gets 200 from the live QUIC/HTTP3 listener" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    // Skip on a box whose curl lacks HTTP/3 (CI without an h3 curl still passes).
    if (!curlHasHttp3(allocator)) return error.SkipZigTest;

    // Stand up the real listener on an ephemeral UDP loopback port with a fresh
    // self-signed cert (the same stack `main.zig` runs). irc_port = 0: a plain
    // GET is answered by the H3 layer and never touches the IRC bridge.
    var keys: TestServerKeys = undefined;
    try keys.init();
    var lst = WebTransportListener.init(allocator, .{
        .cert_chain = &keys.cert_chain,
        .signing_key = .{ .ed25519 = keys.kp },
    }, 0);
    defer lst.deinit();
    lst.start(loopback_be, 0) catch |err| {
        // A sandbox that forbids binding a UDP socket cannot run this test.
        dlog.log("interop: bind failed ({s}); skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const port = lst.port;
    try testing.expect(port != 0);

    // Drive curl --http3 against it. Force h3 (no Alt-Svc upgrade dance), accept
    // the self-signed cert (-k), bound the time so a hang fails fast.
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{port});
    // curl's own --max-time 8 bounds the request; no separate spawn timeout.
    const res = std.process.run(allocator, io, .{
        .argv = &.{ "curl", "--http3-only", "-k", "-sS", "--max-time", "8", url },
    }) catch |err| {
        dlog.log("interop: failed to spawn curl ({s})\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    // curl must exit 0 and the body must be the GET / response.
    switch (res.term) {
        .exited => |code| {
            if (code != 0) {
                dlog.log("interop: curl exited {d}; stderr: {s}\n", .{ code, res.stderr });
                return error.CurlFailed;
            }
        },
        else => {
            dlog.log("interop: curl terminated abnormally; stderr: {s}\n", .{res.stderr});
            return error.CurlFailed;
        },
    }
    try testing.expect(asciiContainsIgnoreCase(res.stdout, "onyx quic ok"));
}

/// The deterministic `/big` body byte at absolute offset `i` — mirrors
/// `http3_conn.bigBodyByteAt` so the test can recompute the expected body and
/// assert the curl download is byte-exact. Kept in lockstep with that function.
fn expectedBigByte(i: usize) u8 {
    const col: u8 = @intCast(i % 64);
    const row: u8 = @intCast((i / 64) % 26);
    if (col == 63) return '\n';
    return 0x21 + ((col + row) % 0x5e);
}

test "interop: curl --http3 large transfer + multi-request + Retry round-trip (deep)" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    // Skip on a box whose curl lacks HTTP/3 (mirrors tools/quic_interop_deep.sh).
    if (!curlHasHttp3(allocator)) return error.SkipZigTest;

    var keys: TestServerKeys = undefined;
    try keys.init();

    // ---- variant A: large transfer + multi-request (retry off) -------------
    {
        var lst = WebTransportListener.init(allocator, .{
            .cert_chain = &keys.cert_chain,
            .signing_key = .{ .ed25519 = keys.kp },
        }, 0);
        defer lst.deinit();
        lst.start(loopback_be, 0) catch |err| {
            dlog.log("interop-deep: bind failed ({s}); skipping\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        const port = lst.port;
        try testing.expect(port != 0);

        // Large transfer: download a 256 KiB /big body to a temp file and verify
        // its exact length and byte-exact content (the deterministic pattern that
        // flows through the real flow-control + congestion + ACK paths).
        const big_n: usize = 256 * 1024;
        var url_buf: [96]u8 = undefined;
        const big_url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/big?n={d}", .{ port, big_n });
        const big = std.process.run(allocator, io, .{
            .argv = &.{ "curl", "--http3-only", "-k", "-sS", "--max-time", "30", big_url },
        }) catch |err| {
            dlog.log("interop-deep: curl spawn failed ({s})\n", .{@errorName(err)});
            return error.SkipZigTest;
        };
        defer allocator.free(big.stdout);
        defer allocator.free(big.stderr);
        switch (big.term) {
            .exited => |c| if (c != 0) {
                dlog.log("interop-deep: curl /big exited {d}; stderr: {s}\n", .{ c, big.stderr });
                return error.CurlFailed;
            },
            else => return error.CurlFailed,
        }
        // Exact length …
        try testing.expectEqual(big_n, big.stdout.len);
        // … and byte-exact content (spot-check a spread of offsets incl. the
        // boundaries — a full compare would also be correct but this is cheap and
        // catches reordering/duplication/truncation just as well).
        const probes = [_]usize{ 0, 1, 63, 64, 1000, 65535, 65536, 131072, big_n - 2, big_n - 1 };
        for (probes) |off| {
            try testing.expectEqual(expectedBigByte(off), big.stdout[off]);
        }

        // Multiple requests on ONE connection: one curl invocation, several URLs.
        // Each `-o`/url pair writes to /dev/null; `-w` prints a per-request line.
        var u_root: [64]u8 = undefined;
        var u_big: [80]u8 = undefined;
        var u_404: [80]u8 = undefined;
        const root_url = try std.fmt.bufPrint(&u_root, "https://127.0.0.1:{d}/", .{port});
        const small_big_url = try std.fmt.bufPrint(&u_big, "https://127.0.0.1:{d}/big?n=65536", .{port});
        const nf_url = try std.fmt.bufPrint(&u_404, "https://127.0.0.1:{d}/nonexistent", .{port});
        const multi = std.process.run(allocator, io, .{
            .argv = &.{
                "curl",      "--http3-only",                    "-k", "-sS",       "--max-time", "30",
                "-w",        "%{http_code} %{size_download}\n", "-o", "/dev/null", root_url,     "-o",
                "/dev/null", small_big_url,                     "-o", "/dev/null", nf_url,
            },
        }) catch return error.SkipZigTest;
        defer allocator.free(multi.stdout);
        defer allocator.free(multi.stderr);
        switch (multi.term) {
            .exited => |c| if (c != 0) {
                dlog.log("interop-deep: curl multi exited {d}; stderr: {s}\n", .{ c, multi.stderr });
                return error.CurlFailed;
            },
            else => return error.CurlFailed,
        }
        // Each request returned its correct status + body size, over one conn.
        try testing.expect(asciiContainsIgnoreCase(multi.stdout, "200 13"));
        try testing.expect(asciiContainsIgnoreCase(multi.stdout, "200 65536"));
        try testing.expect(asciiContainsIgnoreCase(multi.stdout, "404 10"));

        lst.shutdown();
    }

    // ---- variant B: Retry round-trip (address validation on) ---------------
    {
        var lst = WebTransportListener.init(allocator, .{
            .cert_chain = &keys.cert_chain,
            .signing_key = .{ .ed25519 = keys.kp },
        }, 0);
        defer lst.deinit();
        lst.start(loopback_be, 0) catch return error.SkipZigTest;
        lst.retry_policy = .always; // force a Retry for every tokenless Initial.
        const port = lst.port;
        try testing.expect(port != 0);

        var url_buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{port});
        // curl must transparently handle the Retry packet (re-send its Initial
        // with the token) and still complete the handshake + GET → 200.
        const res = std.process.run(allocator, io, .{
            .argv = &.{ "curl", "--http3-only", "-k", "-sS", "--max-time", "15", url },
        }) catch return error.SkipZigTest;
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        switch (res.term) {
            .exited => |c| if (c != 0) {
                dlog.log("interop-deep: Retry curl exited {d}; stderr: {s}\n", .{ c, res.stderr });
                return error.CurlFailed;
            },
            else => return error.CurlFailed,
        }
        try testing.expect(asciiContainsIgnoreCase(res.stdout, "onyx quic ok"));

        lst.shutdown();
    }
}

test "WebTransportListener: native bridge write failure retires a broken peer without SIGPIPE" {
    if (comptime builtin.os.tag != .openbsd) return;
    var pair: [2]sys.fd_t = undefined;
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0, &pair)));
    defer _ = sys.close(pair[0]);
    _ = sys.close(pair[1]);
    try testing.expect(!writeAllFd(pair[0], "retired-peer"));
    try testing.expect(!setNonBlocking(-1));
    try testing.expect(!writeAllFd(-1, "invalid-peer"));
}
