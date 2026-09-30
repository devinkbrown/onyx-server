// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-owned media transport plane: ties the SFU endpoint registry
//! (MediaTransport) to a live UDP MediaSocket and a background pump thread.
//!
//! The pump thread blocks on the media socket (with a short recv timeout so it
//! can observe the stop flag), demultiplexes each datagram, and answers STUN
//! connectivity checks under a mutex. The daemon's main thread allocates and
//! removes endpoints (on MEDIA OFFER / LEAVE) through the same mutex, so the two
//! threads share the registry safely. Media STUN traffic is low-rate (a call
//! handshake), so a single coarse mutex is more than adequate.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const media_transport = @import("../substrate/media_transport.zig");
const media_socket = @import("../substrate/media_socket.zig");
const rtp_profile = @import("../proto/rtp_profile.zig");
const rtp_nack = @import("../substrate/rtp_nack.zig");
const rtcp_translate = @import("../proto/rtcp_translate.zig");
const media_bridge = @import("media_bridge.zig");
const dtls_server = @import("../proto/dtls12_server.zig");
const dtls13_server = @import("../proto/dtls13_server.zig");
const peer_verify = @import("../proto/dtls_peer_verify.zig");
const platform = @import("../substrate/platform.zig");
const sfu_srtp = @import("sfu_srtp.zig");

pub const MediaTransport = media_transport.MediaTransport;
pub const MediaSocket = media_socket.MediaSocket;
pub const TransportAddress = media_transport.TransportAddress;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;
pub const max_datagram = media_socket.max_datagram;
const rtcp_egress_queue_cap: usize = 64;
const rtcp_egress_max_bytes: usize = 2048;

const QueuedRtcp = struct {
    dest: TransportAddress = .{},
    len: usize = 0,
    bytes: [rtcp_egress_max_bytes]u8 = undefined,
};

/// Blocking acquire on the tryLock-only `std.atomic.Mutex`. Contention is
/// near-zero (rare allocate/remove vs. low-rate STUN handshakes), so yielding.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

/// Whether byte 1 of a version-2 packet marks it as RTCP rather than RTP.
/// RFC 5761 reserves RTP payload types 64–95 so RTCP packet types (200–204,
/// i.e. byte 1 in 192–223) are unambiguous on a muxed RTP/RTCP socket.
fn isRtcp(b1: u8) bool {
    return b1 >= 192 and b1 <= 223;
}

/// Fill `buf` with OS entropy (getrandom).
fn osEntropy(buf: []u8) !void {
    if (comptime @import("builtin").os.tag != .linux) {
        return platform.fillOsEntropy(buf) catch return error.EntropyUnavailable;
    }
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.EntropyUnavailable,
        }
        if (rc == 0) return error.EntropyUnavailable;
        filled += @intCast(rc);
    }
}

/// ICE credentials handed back to the signaling layer to advertise to a client.
pub const Creds = struct {
    ufrag: [media_transport.ufrag_len]u8,
    pwd: [media_transport.pwd_len]u8,

    pub fn ufragSlice(self: *const Creds) []const u8 {
        return self.ufrag[0..];
    }
    pub fn pwdSlice(self: *const Creds) []const u8 {
        return self.pwd[0..];
    }
};

pub const MediaPlane = struct {
    allocator: std.mem.Allocator,
    transport: MediaTransport,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// The bound local UDP port (0 until started); advertised to clients.
    port: u16 = 0,
    /// Optional STUN server to query at boot for the reflexive candidate. Set
    /// before `start`.
    stun_server: ?TransportAddress = null,
    /// The discovered server-reflexive address (null if discovery is off/failed).
    discovered: ?TransportAddress = null,
    /// Runtime cap for accepted RTP/RTCP datagrams.
    max_frame_bytes: usize = media_socket.max_datagram,
    /// Runtime cap reserved for upload-bearing media operations.
    max_upload_bytes: u64 = 16 * 1024 * 1024,
    /// CSPRNG for ICE credential generation, seeded from the OS at init.
    /// Accessed only under `mutex` (in allocate).
    csprng: std.Random.DefaultCsprng,
    /// Optional cross-leg sink: after relaying an RTP frame to WebRTC peers, the
    /// pump hands it here to also reach the channel's native members (rewrapped to
    /// cadence). Null = no native members / no bridging.
    cross: ?media_bridge.RtpCrossSink = null,
    /// Opt-in DTLS-SRTP termination (RFC 5764). Set before `start`; when false
    /// the pump has no DTLS demux branch and is byte-identical to today.
    dtls_enabled: bool = false,
    /// Per-peer DTLS server terminator, allocated in `start` when `dtls_enabled`
    /// and freed in `shutdown`. Pump-thread-owned (not internally synchronised).
    dtls: ?*dtls_server.Terminator = null,
    /// Backing session table for `dtls` (owned; freed alongside it).
    dtls_sessions: []dtls_server.Session = &.{},
    /// Inline snapshot of the DTLS `a=fingerprint` line, taken once at `start`
    /// from the immutable cert. Read by the signaling layer from any thread
    /// WITHOUT dereferencing the mutable terminator pointer (never a UAF, and
    /// the buffer is inline so it is never freed). `len` 0 = DTLS off/down.
    dtls_fingerprint_buf: [128]u8 = undefined,
    dtls_fingerprint_len: usize = 0,
    /// Independent opt-in for the DTLS 1.3 engine (default OFF). Set before
    /// `start`. When false, enabling `dtls_enabled` gives exactly Increment 1's
    /// DTLS 1.2-only behavior — the 1.3 engine is never stood up and 1.3-offering
    /// peers fall through to the 1.2 path. Kept separate because the RFC 9147
    /// transcript interop points are not yet browser-validated (see
    /// `dtls13_server.zig`).
    dtls13_enabled: bool = false,
    /// Opt-in DTLS 1.3 engine (RFC 9147), sharing the 1.2 terminator's cert +
    /// `a=fingerprint`. A peer offering DTLS 1.3 (supported_versions) routes here;
    /// 1.2 stays on `dtls`. Pump-thread-owned; null when 1.3 is off/unavailable.
    dtls13: ?*dtls13_server.Terminator = null,
    /// Backing session table for `dtls13` (owned; freed alongside it).
    dtls13_sessions: []dtls13_server.Session = &.{},
    /// Per-peer SRTP/SRTCP crypto contexts for the DTLS-SRTP SFU leg. Built
    /// lazily from the terminator's exported keys, keyed by transport address.
    /// Pump-thread-owned (the sole thread that drives DTLS + relays media); never
    /// touched from another thread, so no synchronisation is needed. Set in
    /// `init` (its peer table is allocated lazily on the first established peer).
    srtp_hub: sfu_srtp.SfuSrtp,
    /// RFC 8122 offered peer fingerprints, keyed by the transport's composite
    /// "channel\x00participant" key. Written by the signaling layer (MEDIA OFFER /
    /// ANSWER, reactor threads) and read by the pump thread, so guarded by
    /// `fp_mutex`. The pump binds an entry into the DTLS terminator (by resolved
    /// peer address) when that peer's DTLS records arrive.
    offered_fps: std.StringHashMapUnmanaged([peer_verify.digest_len]u8) = .empty,
    fp_mutex: std.atomic.Mutex = .unlocked,
    /// Canonical RTCP packets produced off the media pump thread, usually by the
    /// native-media bridge. The pump drains this queue so DTLS-SRTP recipients
    /// receive SRTCP protected under the pump-owned crypto hub.
    rtcp_out: [rtcp_egress_queue_cap]QueuedRtcp = undefined,
    rtcp_out_head: usize = 0,
    rtcp_out_len: usize = 0,
    rtcp_out_mutex: std.atomic.Mutex = .unlocked,

    pub fn init(allocator: std.mem.Allocator) MediaPlane {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        osEntropy(&seed) catch @panic("media CSPRNG entropy unavailable");
        return .{
            .allocator = allocator,
            .transport = MediaTransport.init(allocator),
            .csprng = std.Random.DefaultCsprng.init(seed),
            .srtp_hub = sfu_srtp.SfuSrtp.init(allocator),
        };
    }

    pub fn deinit(self: *MediaPlane) void {
        self.shutdown();
        self.transport.deinit();
        var it = self.offered_fps.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.offered_fps.deinit(self.allocator);
        self.* = undefined;
    }

    /// Whether no live WebRTC transport state would be lost by an in-place
    /// exec. This is an allocation-free, cross-thread-safe snapshot: take the
    /// three registry/egress locks together so an endpoint, fingerprint, or
    /// queued control packet cannot move between independently observed states.
    ///
    /// Merely having a bound socket, a configured cross-leg sink, or allocated
    /// but idle DTLS engines is not active continuity state. Legitimate DTLS/SRTP
    /// peers are admitted through an endpoint, so the endpoint/index gate covers
    /// their continuity without racing the pump-owned crypto tables.
    pub fn upgradeContinuityReady(self: *MediaPlane) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        lockSpin(&self.rtcp_out_mutex);
        defer self.rtcp_out_mutex.unlock();

        return self.transport.endpoints.count() == 0 and
            self.transport.by_ufrag.count() == 0 and
            self.transport.by_addr.count() == 0 and
            self.transport.by_ssrc.count() == 0 and
            self.transport.group_keys.count() == 0 and
            self.offered_fps.count() == 0 and
            self.rtcp_out_len == 0;
    }

    /// Install the cross-leg sink (call before `start`, or while stopped).
    pub fn setCrossLegSink(self: *MediaPlane, sink: media_bridge.RtpCrossSink) void {
        self.cross = sink;
    }

    /// Bind the media socket on `bind_be`:`port` (port 0 = ephemeral) and spawn
    /// the pump thread. No-op if already started.
    pub fn start(self: *MediaPlane, bind_be: u32, port: u16) !void {
        if (self.socket != null) return;
        var sock = try MediaSocket.bind(bind_be, port);
        errdefer sock.deinit();
        self.port = try sock.localPort();
        self.socket = sock;

        // Discover the server-reflexive candidate before the pump owns the socket.
        if (self.stun_server) |srv| {
            self.socket.?.setRecvTimeoutMs(1500); // allow for STUN RTT
            var txid: [12]u8 = undefined;
            self.csprng.random().bytes(&txid);
            self.discovered = self.socket.?.queryReflexive(srv, txid, self.allocator);
        }
        self.socket.?.setRecvTimeoutMs(250); // pump: wake to observe the stop flag

        // Stand up the DTLS-SRTP terminator before the pump owns it (the pump is
        // the sole thread that drives handshakes). A failure disables DTLS but
        // keeps the media plane serving.
        if (self.dtls_enabled) self.startDtls() catch |e| {
            self.dtls_enabled = false;
            std.log.warn("onyx-server: DTLS-SRTP terminator disabled ({s})", .{@errorName(e)});
        };

        lockSpin(&self.rtcp_out_mutex);
        self.rtcp_out_head = 0;
        self.rtcp_out_len = 0;
        self.rtcp_out_mutex.unlock();

        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch |e| {
            self.stopDtls();
            self.socket.?.deinit();
            self.socket = null;
            return e;
        };
    }

    /// Allocate + initialise the DTLS terminator and its session table.
    fn startDtls(self: *MediaPlane) !void {
        var seed: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed); // don't leave the seed on the stack
        try platform.fillOsEntropy(&seed);
        const sessions = try self.allocator.alloc(dtls_server.Session, dtls_server.default_max_sessions);
        errdefer self.allocator.free(sessions);
        const now_s = @divTrunc(platform.realtimeMillis(), 1000);
        const term = try self.allocator.create(dtls_server.Terminator);
        errdefer self.allocator.destroy(term);
        term.* = try dtls_server.Terminator.init(seed, sessions, now_s - 86_400, now_s + 10 * 365 * 86_400);
        // Mutual DTLS auth (#64): with DTLS-SRTP enabled, request + possession-
        // verify the browser's client certificate for any peer that signaled an
        // RFC 8122 fingerprint. Peers without a bound fingerprint stay
        // server-authenticated (byte-identical).
        term.request_client_cert = true;
        // Snapshot the immutable fingerprint for lock-free cross-thread reads.
        if (term.fingerprintLine(&self.dtls_fingerprint_buf)) |fp| {
            self.dtls_fingerprint_len = fp.len;
        } else |_| {
            self.dtls_fingerprint_len = 0;
        }
        self.dtls_sessions = sessions;
        self.dtls = term;

        // Stand up the DTLS 1.3 engine (opt-in, sharing the same certificate +
        // fingerprint). Best-effort: a 1.3 failure leaves the 1.2 path serving.
        if (self.dtls13_enabled) self.startDtls13(term) catch |e| {
            self.stopDtls13();
            std.log.warn("onyx-server: DTLS 1.3 engine disabled ({s})", .{@errorName(e)});
        };
    }

    /// Allocate + initialise the DTLS 1.3 terminator, sharing the 1.2
    /// terminator's certificate + key so both version engines present ONE
    /// `a=fingerprint`. The DER is copied into the 1.3 terminator (no borrow).
    fn startDtls13(self: *MediaPlane, term12: *const dtls_server.Terminator) !void {
        var seed: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try platform.fillOsEntropy(&seed);
        const sessions = try self.allocator.alloc(dtls13_server.Session, dtls13_server.default_max_sessions);
        errdefer self.allocator.free(sessions);
        const term = try self.allocator.create(dtls13_server.Terminator);
        errdefer self.allocator.destroy(term);
        term.* = try dtls13_server.Terminator.init(seed, sessions, term12.certDer(), term12.certKeyPair());
        term.request_client_cert = true; // mutual DTLS auth (#64), mirrors the 1.2 engine
        self.dtls13_sessions = sessions;
        self.dtls13 = term;
    }

    /// Tear down the DTLS 1.3 terminator (secure-zeroing key material) and free it.
    fn stopDtls13(self: *MediaPlane) void {
        if (self.dtls13) |term| {
            term.deinit();
            self.allocator.destroy(term);
            self.dtls13 = null;
        }
        if (self.dtls13_sessions.len != 0) {
            self.allocator.free(self.dtls13_sessions);
            self.dtls13_sessions = &.{};
        }
    }

    /// Tear down the DTLS terminators (secure-zeroing key material) and free them.
    fn stopDtls(self: *MediaPlane) void {
        self.dtls_fingerprint_len = 0;
        self.srtp_hub.wipe(); // secure-zero any cached per-peer SRTP session keys
        self.stopDtls13(); // LIFO: 1.3 was stood up after 1.2
        if (self.dtls) |term| {
            term.deinit();
            self.allocator.destroy(term);
            self.dtls = null;
        }
        if (self.dtls_sessions.len != 0) {
            self.allocator.free(self.dtls_sessions);
            self.dtls_sessions = &.{};
        }
    }

    /// Signal the pump thread to stop, join it, and close the socket.
    pub fn shutdown(self: *MediaPlane) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        // Only safe to free after the pump (sole DTLS driver) has joined.
        self.stopDtls();
        if (self.socket) |*s| {
            s.deinit();
            self.socket = null;
        }
    }

    fn pumpLoop(self: *MediaPlane) void {
        var buf: [media_socket.max_datagram]u8 = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const sock = &(self.socket orelse return);
            self.drainQueuedRtcp(sock);
            const got = sock.recvFrom(&buf) orelse {
                self.drainQueuedRtcp(sock);
                continue;
            }; // timeout/idle
            if (got.data.len == 0) continue;
            if (got.data.len > self.max_frame_bytes) continue;
            // RFC 7983 demultiplexing: DTLS records carry a content-type byte in
            // 20..=63. Only taken when DTLS-SRTP is enabled, so the STUN/RTP
            // paths below are byte-identical when off.
            if (self.dtls_enabled and got.data[0] >= 20 and got.data[0] <= 63) {
                self.handleDtls(sock, got.from, got.data);
                continue;
            }
            if (MediaSocket.isStun(got.data[0])) {
                lockSpin(&self.mutex);
                const resp = self.transport.handleStunBinding(self.allocator, got.data, got.from) catch null;
                self.mutex.unlock();
                if (resp) |r| {
                    defer self.allocator.free(r);
                    sock.sendTo(got.from, r);
                }
            } else {
                // Media: require RTP/RTCP framing (version 2 in the top two bits,
                // min header) so the port is not an open UDP reflector.
                if (got.data.len < rtp_profile.header_len or (got.data[0] & 0xC0) != 0x80) continue;
                const b1 = got.data[1];
                if (isRtcp(b1)) {
                    // RTCP: decrypt from a DTLS peer FIRST, then terminate a NACK
                    // or relay. The Generic-NACK media SSRC + FCI live past the
                    // clear SRTCP header (byte 8+), so they are ciphertext until
                    // decrypted — reading them raw only works for a plaintext peer.
                    self.handleRtcp(sock, got.from, got.data);
                } else {
                    var ssrc: u32 = 0;
                    var seq: ?u16 = null;
                    if (rtp_profile.decodeHeader(got.data)) |dh| {
                        ssrc = dh.header.ssrc;
                        seq = dh.header.sequence;
                    } else |_| {}
                    self.relay(&sock.*, got.from, got.data, ssrc, seq);
                }
            }
        }
    }

    /// Drain off-thread RTCP egress on the pump thread. This is the only place
    /// queued RTCP may touch the DTLS-SRTP crypto hub.
    fn drainQueuedRtcp(self: *MediaPlane, sock: *MediaSocket) void {
        while (true) {
            var item: QueuedRtcp = undefined;
            lockSpin(&self.rtcp_out_mutex);
            if (self.rtcp_out_len == 0) {
                self.rtcp_out_mutex.unlock();
                return;
            }
            item = self.rtcp_out[self.rtcp_out_head];
            self.rtcp_out_head = (self.rtcp_out_head + 1) % rtcp_egress_queue_cap;
            self.rtcp_out_len -= 1;
            self.rtcp_out_mutex.unlock();

            self.sendCanonicalRtcpTo(sock, item.dest, item.bytes[0..item.len]);
        }
    }

    /// Pump-thread-only send of canonical RTCP to one destination. DTLS peers are
    /// protected as SRTCP; group-key/plain peers receive the canonical packet.
    fn sendCanonicalRtcpTo(self: *MediaPlane, sock: *MediaSocket, dest: TransportAddress, canonical: []const u8) void {
        var enc_buf: [media_socket.max_datagram + sfu_srtp.rtcp_overhead]u8 = undefined;
        switch (self.dtlsState(dest)) {
            .not_dtls => sock.sendTo(dest, canonical),
            .unavailable => {},
            .ready => if (self.srtp_hub.protectRtcp(dest, canonical, &enc_buf)) |wire| {
                sock.sendTo(dest, wire);
            },
        }
    }

    /// Drive one DTLS record datagram through the per-peer terminator and send
    /// any response flight back to `from`. Terminator state is touched only by
    /// this (pump) thread. The response is a small handshake flight (< 2 KiB).
    fn handleDtls(self: *MediaPlane, sock: *MediaSocket, from: TransportAddress, data: []const u8) void {
        var out: [2048]u8 = undefined;
        const now = platform.monotonicMillis();
        // RFC 8122: bind this peer's signaled fingerprint (if any) into the
        // terminator before the handshake can complete, so an unverified
        // certificate fails closed. Idempotent; no-op until ICE binds the peer.
        self.bindDtlsFingerprintFor(from);
        // Version dispatch: a peer the 1.3 engine already owns, or a fresh
        // ClientHello offering DTLS 1.3 (supported_versions), routes to the 1.3
        // engine; everything else stays on Increment 1's DTLS 1.2 path.
        if (self.dtls13) |t13| {
            if (t13.owns(from) or dtls13_server.offersDtls13(data)) {
                if (t13.handleDatagram(from, data, now, &out)) |resp| sock.sendTo(from, resp);
                return;
            }
        }
        const term = self.dtls orelse return;
        if (term.handleDatagram(from, data, now, &out)) |resp| {
            sock.sendTo(from, resp);
        }
    }

    /// The daemon's DTLS `a=fingerprint` line (SHA-256), copied into `out`, for
    /// the signaling layer to advertise (Increment 3). Null when DTLS-SRTP is
    /// disabled/down. Reads the inline snapshot taken at `start` — never
    /// dereferences the mutable terminator pointer, so it is UAF-safe from any
    /// thread even racing teardown (worst case: a stale-but-valid line or null).
    pub fn dtlsFingerprint(self: *const MediaPlane, out: []u8) ?[]const u8 {
        const n = self.dtls_fingerprint_len;
        if (n == 0 or out.len < n) return null;
        @memcpy(out[0..n], self.dtls_fingerprint_buf[0..n]);
        return out[0..n];
    }

    /// A transport address's DTLS-SRTP status for the SFU crypto path.
    const DtlsState = enum {
        /// Not a DTLS-SRTP peer (DTLS off, or not an established DTLS session):
        /// the group-key/native plaintext path applies (byte-identical off).
        not_dtls,
        /// An established DTLS-SRTP peer with a live crypto context.
        ready,
        /// A DTLS-SRTP peer whose context could not be installed (table full):
        /// its media must be DROPPED, never forwarded in the clear.
        unavailable,
    };

    /// Resolve `addr`'s DTLS-SRTP crypto status, reconciling the hub against the
    /// terminator each call (pump-thread-only): a departed/rekeyed session is
    /// evicted, a live one is (re)installed. Always re-reading the terminator is
    /// what re-keys a re-handshake at the same address and keeps a stale key from
    /// silently blackholing a peer.
    fn dtlsState(self: *MediaPlane, addr: TransportAddress) DtlsState {
        if (!self.dtls_enabled) return .not_dtls;
        const term = self.dtls orelse return .not_dtls;
        const keys = term.exportedKeys(addr) orelse {
            // Session gone (or handshake not complete) ⇒ drop any stale context.
            self.srtp_hub.evict(addr);
            return .not_dtls;
        };
        if (self.srtp_hub.noteEstablished(addr, keys)) return .ready;
        // Table full: reclaim slots held by peers whose DTLS session is gone
        // (departed via MEDIA LEAVE/disconnect — `remove` cannot touch the
        // pump-owned hub), then retry. Because the hub is sized to the
        // terminator's session cap, a genuinely new peer always frees a slot.
        self.reconcileHub(term);
        return if (self.srtp_hub.noteEstablished(addr, keys)) .ready else .unavailable;
    }

    /// Evict any hub peer whose DTLS session no longer exists in the terminator
    /// (secure-zeroing its keys). Pump-thread-only; bounded by the hub size.
    fn reconcileHub(self: *MediaPlane, term: *dtls_server.Terminator) void {
        var addrs: [sfu_srtp.max_peers]TransportAddress = undefined;
        const n = self.srtp_hub.activePeerAddrs(&addrs);
        for (addrs[0..n]) |a| {
            if (term.exportedKeys(a) == null) self.srtp_hub.evict(a);
        }
    }

    /// Composite "channel\x00participant" key for the offered-fingerprint map,
    /// written into `buf`. Returns null when it overflows `buf`.
    fn fpKey(buf: []u8, channel: []const u8, participant: []const u8) ?[]const u8 {
        if (channel.len + 1 + participant.len > buf.len) return null;
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = 0;
        @memcpy(buf[channel.len + 1 ..][0..participant.len], participant);
        return buf[0 .. channel.len + 1 + participant.len];
    }

    /// Store the RFC 8122 fingerprint a participant signaled in its MEDIA OFFER /
    /// ANSWER (SHA-256 of the certificate it will present). The pump binds this
    /// into the DTLS terminator by resolved peer address once the peer's DTLS
    /// records arrive, so the handshake fails closed on a mismatch. Idempotent.
    pub fn bindOfferedFingerprint(self: *MediaPlane, channel: []const u8, participant: []const u8, digest: [peer_verify.digest_len]u8) !void {
        var kb: [256]u8 = undefined;
        const k = fpKey(&kb, channel, participant) orelse return error.NameTooLong;
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        const gop = try self.offered_fps.getOrPut(self.allocator, k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.offered_fps.remove(k);
                return e;
            };
        }
        gop.value_ptr.* = digest;
    }

    /// Drop a participant's offered fingerprint (MEDIA LEAVE / disconnect).
    pub fn dropOfferedFingerprint(self: *MediaPlane, channel: []const u8, participant: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = fpKey(&kb, channel, participant) orelse return;
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        if (self.offered_fps.fetchRemove(k)) |kv| self.allocator.free(kv.key);
    }

    /// Test/introspection: whether a fingerprint is currently bound for a
    /// participant (does not touch the terminator).
    pub fn hasOfferedFingerprint(self: *MediaPlane, channel: []const u8, participant: []const u8) bool {
        var kb: [256]u8 = undefined;
        const k = fpKey(&kb, channel, participant) orelse return false;
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        return self.offered_fps.contains(k);
    }

    /// Bind the offered fingerprint for the peer at `from` (if any) into the DTLS
    /// terminator(s) by address, so the handshake-completion path can fail closed
    /// on a certificate mismatch. Runs on the pump thread (sole terminator owner)
    /// and resolves `from`→participant via the ICE-bound transport index, so it is
    /// a no-op until the peer's ICE check has bound its address. Idempotent.
    fn bindDtlsFingerprintFor(self: *MediaPlane, from: TransportAddress) void {
        // Resolve the composite key under the transport lock, copying it out
        // before unlocking (it borrows transport-owned memory).
        var kb: [256]u8 = undefined;
        var klen: usize = 0;
        lockSpin(&self.mutex);
        if (self.transport.compositeForSource(from)) |c| {
            if (c.len <= kb.len) {
                @memcpy(kb[0..c.len], c);
                klen = c.len;
            }
        }
        self.mutex.unlock();
        if (klen == 0) return;

        lockSpin(&self.fp_mutex);
        const digest = self.offered_fps.get(kb[0..klen]);
        self.fp_mutex.unlock();
        if (digest) |d| {
            if (self.dtls13) |t13| t13.bindExpectedFingerprint(from, d);
            if (self.dtls) |t12| t12.bindExpectedFingerprint(from, d);
        }
    }

    /// Selectively forward an RTP `packet` (from `source`) to the other call
    /// participants; meter + cache it for NACK; bridge to native members.
    ///
    /// DTLS-SRTP is layered on top: a packet from a DTLS peer is decrypted once
    /// under that peer's inbound key (auth-fail/replay ⇒ dropped, never
    /// forwarded), and the plaintext "canonical" packet is what feeds the forward
    /// decision, the NACK cache, the native bridge, and each group-key recipient.
    /// A recipient that is itself a DTLS peer gets the canonical packet
    /// re-encrypted under its OWN outbound key. When DTLS-SRTP is off (or no
    /// address on the call is a DTLS peer) the canonical packet IS the input, so
    /// this path is byte-identical to the pre-DTLS relay.
    fn relay(self: *MediaPlane, sock: *MediaSocket, source: TransportAddress, packet: []const u8, ssrc: u32, seq: ?u16) void {
        var plain_buf: [media_socket.max_datagram]u8 = undefined;
        var canonical: []const u8 = packet;
        switch (self.dtlsState(source)) {
            .not_dtls => {}, // plaintext source: canonical IS the input packet
            .unavailable => return, // DTLS source with no context ⇒ drop (fail-closed)
            // Inbound is SRTP under the source's key (the hub reads ssrc/seq from
            // the packet's own header). Drop on auth/replay/ownership failure.
            .ready => canonical = self.srtp_hub.unprotectRtp(source, packet, &plain_buf) orelse return,
        }
        var targets: [media_transport.max_forward]TransportAddress = undefined;
        var chanbuf: [256]u8 = undefined;
        var chanlen: usize = 0;
        lockSpin(&self.mutex);
        const n = self.transport.forwardFromSource(source, canonical, ssrc, seq, &targets);
        // Copy the source's channel out under the lock so the cross-leg sink can
        // use it after we unlock (the composite key may be freed).
        if (self.transport.channelForSource(source)) |chan| {
            if (chan.len <= chanbuf.len) {
                @memcpy(chanbuf[0..chan.len], chan);
                chanlen = chan.len;
            }
        }
        self.mutex.unlock();

        var enc_buf: [media_socket.max_datagram + sfu_srtp.rtp_overhead]u8 = undefined;
        for (targets[0..n]) |dst| {
            switch (self.dtlsState(dst)) {
                .not_dtls => sock.sendTo(dst, canonical), // group-key/plaintext leg
                .unavailable => {}, // DTLS peer with no context ⇒ skip (never send it plaintext)
                // DTLS recipient: re-encrypt under ITS OWN outbound key. The
                // per-recipient replay window (keyed by the packet's own SSRC)
                // makes a nonce repeat impossible.
                .ready => if (self.srtp_hub.protectRtp(dst, canonical, &enc_buf)) |wire| {
                    sock.sendTo(dst, wire);
                },
            }
        }

        // Bridge the same (plaintext) RTP frame to any native members.
        if (chanlen != 0) {
            if (self.cross) |sink| sink.onRtpFrame(chanbuf[0..chanlen], canonical, false);
        }
    }

    /// Handle one inbound RTCP `packet` (from `source`): decrypt it if the source
    /// is a DTLS-SRTP peer (drop on auth failure), then either terminate a
    /// Generic NACK locally from the retransmit cache or relay it to the other
    /// participants, or translate it to native feedback for a native publisher.
    /// Decrypting FIRST is what makes feedback work for DTLS peers (the media
    /// SSRC + FCI are SRTCP-encrypted on the wire).
    fn handleRtcp(self: *MediaPlane, sock: *MediaSocket, source: TransportAddress, packet: []const u8) void {
        var plain_buf: [media_socket.max_datagram]u8 = undefined;
        var canonical: []const u8 = packet;
        switch (self.dtlsState(source)) {
            .not_dtls => {},
            .unavailable => return, // DTLS source with no context ⇒ drop
            .ready => canonical = self.srtp_hub.unprotectRtcp(source, packet, &plain_buf) orelse return,
        }

        var chanbuf: [256]u8 = undefined;
        var chanlen: usize = 0;
        lockSpin(&self.mutex);
        if (self.transport.channelForSource(source)) |chan| {
            if (chan.len <= chanbuf.len) {
                @memcpy(chanbuf[0..chan.len], chan);
                chanlen = chan.len;
            }
        }
        self.mutex.unlock();
        if (chanlen != 0) {
            if (self.cross) |sink| {
                if (sink.onRtcpFeedback(chanbuf[0..chanlen], canonical)) return;
            }
        }

        // Terminate a Generic NACK (RTPFB PT=205, FMT=1) from the retransmit
        // cache using the DECRYPTED media SSRC + FCI. Not relayed onward.
        if (canonical.len >= 12 and (canonical[0] & 0xC0) == 0x80 and
            canonical[1] == 205 and (canonical[0] & 0x1f) == 1)
        {
            const media_ssrc = std.mem.readInt(u32, canonical[8..12], .big);
            self.handleNack(sock, source, media_ssrc, canonical[12..]);
            return;
        }
        self.forwardRtcp(sock, source, canonical);
    }

    /// Relay an already-decrypted (canonical) RTCP `packet` to the other call
    /// participants: re-encrypt per DTLS recipient (SRTCP), plain-forward to
    /// group-key peers. Not cached for NACK.
    fn forwardRtcp(self: *MediaPlane, sock: *MediaSocket, source: TransportAddress, canonical: []const u8) void {
        var targets: [media_transport.max_forward]TransportAddress = undefined;
        lockSpin(&self.mutex);
        const n = self.transport.forwardFromSource(source, canonical, 0, null, &targets);
        self.mutex.unlock();

        for (targets[0..n]) |dst| {
            self.sendCanonicalRtcpTo(sock, dst, canonical);
        }
    }

    /// Answer a Generic NACK from `requester` for `media_ssrc`: resend each
    /// requested-and-still-cached packet from the publisher's retransmit buffer.
    fn handleNack(self: *MediaPlane, sock: *MediaSocket, requester: TransportAddress, media_ssrc: u32, fci: []const u8) void {
        const missing = rtp_nack.parseNackFci(self.allocator, fci) catch return;
        defer self.allocator.free(missing);
        var scratch: [media_socket.max_datagram]u8 = undefined;
        var enc_buf: [media_socket.max_datagram + sfu_srtp.rtp_overhead]u8 = undefined;
        // The retransmit cache holds the canonical (plaintext, for a DTLS source)
        // packet. The requester's leg decides the on-wire form: a group-key peer
        // gets the cached bytes verbatim (byte-identical when DTLS-SRTP is off); a
        // DTLS peer gets it re-protected under ITS OWN outbound key.
        //
        // DTLS caveat (by design): `protectRtp`'s per-recipient replay window
        // refuses to re-encrypt an index it already sent to this recipient — so a
        // retransmit of a packet the recipient RECEIVED-then-lost is fail-closed
        // (returns null, nothing sent), since re-using an SRTP nonce is forbidden.
        // A packet never forwarded to the recipient (e.g. a mid-join gap) still
        // retransmits. The product recovery path is that cache
        // (`media_transport.rtx_capacity` packets per publisher). A distinct
        // RFC 4588 RTX SSRC is not the product: re-protecting an index already
        // sent to this recipient would reuse an SRTP nonce.
        const req_state = self.dtlsState(requester);
        if (req_state == .unavailable) return; // DTLS peer with no context ⇒ nothing to send
        for (missing) |seq| {
            lockSpin(&self.mutex);
            const got = self.transport.copyRetransmit(media_ssrc, seq, &scratch);
            self.mutex.unlock();
            if (got) |len| {
                const canonical = scratch[0..len];
                switch (req_state) {
                    // Re-protect under the requester's own key. The hub derives
                    // the SRTP nonce from `canonical`'s header, and copyRetransmit
                    // guarantees that header carries `media_ssrc` — so the replay
                    // window and the nonce can never diverge on the NACK path.
                    .ready => if (self.srtp_hub.protectRtp(requester, canonical, &enc_buf)) |wire| {
                        sock.sendTo(requester, wire);
                    },
                    else => sock.sendTo(requester, canonical),
                }
            }
        }
    }

    /// Highest spatial layer this RTP receiver accepts, or null when the
    /// endpoint has not been allocated.
    pub fn receiverSpatial(self: *MediaPlane, channel: []const u8, participant: []const u8) ?u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.get(channel, participant) orelse return null;
        return ep.max_spatial;
    }

    /// Record a receiver's spatial ceiling on its RTP endpoint. False when
    /// that endpoint does not exist yet.
    pub fn setReceiverSpatial(self: *MediaPlane, channel: []const u8, participant: []const u8, max_spatial: u8) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.transport.setReceiverSpatial(channel, participant, max_spatial);
    }

    /// Allocate (or rotate) the ICE credentials for a call participant and return
    /// them for the signaling layer to advertise. Null on allocation failure.
    pub fn allocate(self: *MediaPlane, channel: []const u8, participant: []const u8) ?Creds {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.allocate(channel, participant, self.csprng.random()) catch return null;
        return .{ .ufrag = ep.ufrag, .pwd = ep.pwd };
    }

    /// Format the discovered server-reflexive IPv4 into `buf` for advertising as
    /// the media candidate, or null when discovery is off/failed (caller uses
    /// its configured fallback host).
    pub fn candidateIp(self: *const MediaPlane, buf: []u8) ?[]const u8 {
        const a = self.discovered orelse return null;
        if (a.ip_len != 4) return null;
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a.ip[0], a.ip[1], a.ip[2], a.ip[3] }) catch null;
    }

    /// The per-call SRTP group key (SDES) for `channel`, generated on first use.
    pub fn groupKey(self: *MediaPlane, channel: []const u8) [media_transport.group_key_len]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.transport.ensureGroupKey(channel, self.csprng.random());
    }

    /// Drop a participant's endpoint (MEDIA LEAVE / disconnect), including any
    /// stored RFC 8122 offered fingerprint.
    pub fn remove(self: *MediaPlane, channel: []const u8, participant: []const u8) void {
        {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            self.transport.remove(channel, participant);
        }
        self.dropOfferedFingerprint(channel, participant);
    }

    /// Snapshot per-participant transport stats for `channel` into `out`.
    pub fn statsForChannel(self: *MediaPlane, channel: []const u8, out: []MediaTransport.ParticipantStat) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.transport.statsForChannel(channel, out);
    }

    /// Send `bytes` to `dest` on the media socket. Used by the native pump's
    /// cross-leg sink to deliver RTP-rewrapped frames to WebRTC peers. UDP
    /// sendto on a shared fd is safe to call from another thread.
    pub fn sendTo(self: *MediaPlane, dest: TransportAddress, bytes: []const u8) void {
        if (self.socket) |*s| s.sendTo(dest, bytes);
    }

    /// Send canonical RTCP to a WebRTC peer from outside the media pump. When
    /// DTLS-SRTP is enabled, this enqueues the packet for pump-thread egress so
    /// the pump-owned SRTCP crypto hub can protect DTLS recipients.
    pub fn sendRtcpTo(self: *MediaPlane, dest: TransportAddress, bytes: []const u8) void {
        if (!self.dtls_enabled) {
            if (self.socket) |*s| s.sendTo(dest, bytes);
            return;
        }
        if (self.socket == null or bytes.len > rtcp_egress_max_bytes) return;
        lockSpin(&self.rtcp_out_mutex);
        defer self.rtcp_out_mutex.unlock();
        if (self.rtcp_out_len >= rtcp_egress_queue_cap) return;
        const idx = (self.rtcp_out_head + self.rtcp_out_len) % rtcp_egress_queue_cap;
        self.rtcp_out[idx].dest = dest;
        self.rtcp_out[idx].len = bytes.len;
        @memcpy(self.rtcp_out[idx].bytes[0..bytes.len], bytes);
        self.rtcp_out_len += 1;
    }

    /// The bound remote address of a WebRTC participant (learned via STUN), or
    /// null if unknown/unbound. Lets the cross-leg sink resolve a live target
    /// address rather than a stale one.
    pub fn remoteFor(self: *MediaPlane, channel: []const u8, participant: []const u8) ?TransportAddress {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.get(channel, participant) orelse return null;
        if (!ep.connected()) return null;
        return ep.remote;
    }

    /// Whether a participant's ICE check has bound a peer address (test/introspection).
    pub fn isConnected(self: *MediaPlane, channel: []const u8, participant: []const u8) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.get(channel, participant) orelse return false;
        return ep.connected();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const stun = @import("../proto/stun.zig");
const dtls_messages = @import("../proto/dtls12_messages.zig");
const dtls_record = @import("../proto/dtls12_record.zig");
const dtls_handshake = @import("../proto/dtls_handshake.zig");
const dtls_srtp = @import("../proto/dtls_srtp.zig");
const dtls13_messages = @import("../proto/dtls13_messages.zig");
const dtls_kx = @import("../proto/dtls_keyexchange.zig");
const srtp = @import("../proto/srtp.zig");
const srtcp = @import("../proto/srtcp.zig");

test "MediaPlane: threaded pump answers a STUN check and binds the peer" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);

    const creds = plane.allocate("#c", "alice") orelse return error.TestUnexpectedResult;

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    var user_buf: [media_transport.ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{creds.ufragSlice()}) catch unreachable;
    const tx: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = creds.pwdSlice(),
        .fingerprint = true,
    });
    defer testing.allocator.free(req);

    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, req);

    // The pump thread answers; receiving the response proves it was processed.
    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    var decoded = try stun.decode(testing.allocator, got.data);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    try testing.expect(plane.isConnected("#c", "alice"));
}

test "upgrade continuity: MediaPlane ignores idle socket and gates live transport state" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();

    try testing.expect(plane.upgradeContinuityReady());
    try plane.start(loopback_be, 0);
    try testing.expect(plane.upgradeContinuityReady());

    _ = plane.allocate("#c", "alice") orelse return error.TestUnexpectedResult;
    try testing.expect(!plane.upgradeContinuityReady());
    plane.remove("#c", "alice");
    try testing.expect(plane.upgradeContinuityReady());

    const digest: [peer_verify.digest_len]u8 = @splat(0xA5);
    try plane.bindOfferedFingerprint("#c", "alice", digest);
    try testing.expect(!plane.upgradeContinuityReady());
    plane.dropOfferedFingerprint("#c", "alice");
    try testing.expect(plane.upgradeContinuityReady());

    _ = plane.groupKey("#orphan");
    try testing.expect(!plane.upgradeContinuityReady());
    plane.remove("#orphan", "nobody");
    try testing.expect(plane.upgradeContinuityReady());
}

test "MediaPlane: start/shutdown is clean and re-startable port is reported" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    try testing.expect(plane.port != 0);
    plane.shutdown();
    // After shutdown the socket is closed; re-start binds a fresh ephemeral port.
    try plane.start(loopback_be, 0);
    try testing.expect(plane.port != 0);
}

test "MediaPlane: offered-fingerprint registry stores, reports, and drops (no leak)" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();

    const d1 = peer_verify.certDigest("alice presented cert");
    const d2 = peer_verify.certDigest("bob presented cert");

    try testing.expect(!plane.hasOfferedFingerprint("#c", "alice"));
    try plane.bindOfferedFingerprint("#c", "alice", d1);
    try plane.bindOfferedFingerprint("#c", "bob", d2);
    try testing.expect(plane.hasOfferedFingerprint("#c", "alice"));
    try testing.expect(plane.hasOfferedFingerprint("#c", "bob"));

    // Re-binding the same participant updates in place (no duplicate key leak).
    try plane.bindOfferedFingerprint("#c", "alice", d2);
    try testing.expect(plane.hasOfferedFingerprint("#c", "alice"));

    // remove() drops the participant's endpoint AND its fingerprint.
    plane.remove("#c", "alice");
    try testing.expect(!plane.hasOfferedFingerprint("#c", "alice"));
    try testing.expect(plane.hasOfferedFingerprint("#c", "bob"));

    plane.dropOfferedFingerprint("#c", "bob");
    try testing.expect(!plane.hasOfferedFingerprint("#c", "bob"));
    // deinit frees any remainder (testing allocator would flag a leak).
}

test "MediaPlane: DTLS off leaves the pump with no terminator and no fingerprint" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    try testing.expect(plane.dtls == null);
    var fp_buf: [128]u8 = undefined;
    try testing.expect(plane.dtlsFingerprint(&fp_buf) == null);
}

test "MediaPlane: DTLS-enabled pump demultiplexes a ClientHello into a HelloVerifyRequest" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    try plane.start(loopback_be, 0);
    // Terminator stood up and exposes a well-formed SHA-256 fingerprint.
    try testing.expect(plane.dtls != null);
    var fp_buf: [128]u8 = undefined;
    const fp = plane.dtlsFingerprint(&fp_buf) orelse return error.TestUnexpectedResult;
    try testing.expect(std.mem.startsWith(u8, fp, "sha-256 "));

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    // Send a bare ClientHello (RFC 7983 DTLS range → content-type byte 22).
    var rnd: [32]u8 = undefined;
    for (&rnd, 0..) |*b, i| b.* = @intCast(i +% 1);
    var ch_body: [512]u8 = undefined;
    const chb = try dtls_messages.buildClientHello(&ch_body, .{
        .random = rnd,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var dgram: [700]u8 = undefined;
    const dlen = try dtls_server.framePlaintextHandshake(&dgram, .client_hello, 0, 0, 0, chb);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, dgram[0..dlen]);

    // The pump demuxes to DTLS and replies with a HelloVerifyRequest.
    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    const rdec = try dtls_record.RecordHeader.decode(got.data);
    try testing.expectEqual(dtls_record.ContentType.handshake, rdec.hdr.content_type);
    const hh = try dtls_handshake.Header.decode(rdec.fragment);
    try testing.expectEqual(dtls_handshake.HandshakeType.hello_verify_request, hh.hdr.msg_type);
}

test "MediaPlane: DTLS-SRTP on but dtls13 off leaves the 1.3 engine down (1.2-only)" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true; // dtls13_enabled defaults false
    try plane.start(loopback_be, 0);
    try testing.expect(plane.dtls != null); // 1.2 up
    try testing.expect(plane.dtls13 == null); // 1.3 stays down by default
}

test "DTLS-SRTP GAP-V1 hold-off: dtls13 off still answers a DTLS 1.2 ClientHello" {
    try testing.expect(dtls13_server.browser_interop_caveat_held);
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    try testing.expect(!plane.dtls13_enabled);
    try plane.start(loopback_be, 0);
    try testing.expect(plane.dtls != null);
    try testing.expect(plane.dtls13 == null);

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    var rnd: [32]u8 = undefined;
    for (&rnd, 0..) |*b, i| b.* = @intCast(i +% 1);
    var ch_body: [512]u8 = undefined;
    const chb = try dtls_messages.buildClientHello(&ch_body, .{
        .random = rnd,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var dgram: [700]u8 = undefined;
    const dlen = try dtls_server.framePlaintextHandshake(&dgram, .client_hello, 0, 0, 0, chb);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, dgram[0..dlen]);

    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    const rdec = try dtls_record.RecordHeader.decode(got.data);
    try testing.expectEqual(dtls_record.ContentType.handshake, rdec.hdr.content_type);
    const hh = try dtls_handshake.Header.decode(rdec.fragment);
    try testing.expectEqual(dtls_handshake.HandshakeType.hello_verify_request, hh.hdr.msg_type);
    std.debug.print("GAP-V1 branch=hold-off dtls13=off caveat=kept dtls12=HelloVerifyRequest\n", .{});
}

test "MediaPlane: version seam routes a DTLS 1.3 ClientHello to the 1.3 engine (HRR)" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    plane.dtls13_enabled = true;
    try plane.start(loopback_be, 0);
    // Both engines stood up sharing one certificate → one fingerprint.
    try testing.expect(plane.dtls != null);
    try testing.expect(plane.dtls13 != null);

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    // A DTLS 1.3 ClientHello (supported_versions offers 0xfefc) → the pump routes
    // to the 1.3 engine, which replies with a HelloRetryRequest.
    var ch_body: [512]u8 = undefined;
    const chb = try dtls13_messages.buildClientHello13(&ch_body, .{
        .random = @splat(0x33),
        .key_share_point = dtls_kx.generateKeyPair(@splat(0x5c)).public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var dgram: [700]u8 = undefined;
    const dlen = try dtls13_server.framePlaintext13(&dgram, .client_hello, 0, 0, chb);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, dgram[0..dlen]);

    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    const rdec = try dtls_record.RecordHeader.decode(got.data);
    try testing.expectEqual(dtls_record.ContentType.handshake, rdec.hdr.content_type);
    const hh = try dtls_handshake.Header.decode(rdec.fragment);
    const shv = try dtls13_messages.parseServerHello13(rdec.fragment[dtls_handshake.handshake_header_len..][0..hh.hdr.length]);
    try testing.expect(shv.isHelloRetryRequest());
    try testing.expectEqual(@as(usize, dtls13_server.cookie_len), shv.cookie.len);
}

// ---------------------------------------------------------------------------
// End-to-end: two DTLS-SRTP peers handshake through the LIVE pump, then a
// forwarded SRTP frame from A is decrypted under A's key, re-encrypted under
// B's OWN key, and recovered by B — proving the decrypt -> forward -> per-peer
// re-encrypt path over real UDP.
// ---------------------------------------------------------------------------

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Complete a short-term-credential STUN binding so the SFU learns the peer's
/// media address (required before it will forward the peer's RTP).
fn stunBindPeer(client: *MediaSocket, server_addr: TransportAddress, creds: Creds) !void {
    var user_buf: [media_transport.ufrag_len + 6]u8 = undefined;
    const user = try std.fmt.bufPrint(&user_buf, "{s}:peer", .{creds.ufragSlice()});
    const tx: stun.TransactionId = .{ 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = creds.pwdSlice(),
        .fingerprint = true,
    });
    defer testing.allocator.free(req);
    client.sendTo(server_addr, req);
    var buf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    var decoded = try stun.decode(testing.allocator, got.data);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
}

const RtcpCaptureSink = struct {
    sock: *MediaSocket,
    dest: TransportAddress,

    fn onRtp(_: *anyopaque, _: []const u8, _: []const u8, _: bool) void {}

    fn onRtcp(ctx: *anyopaque, channel: []const u8, rtcp: []const u8) bool {
        if (!std.mem.eql(u8, channel, "#call")) return false;
        const self: *RtcpCaptureSink = @ptrCast(@alignCast(ctx));
        self.sock.sendTo(self.dest, rtcp);
        return true;
    }
};

test "MediaPlane: RTCP feedback sink receives canonical feedback for a bound WebRTC peer" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);

    const creds = plane.allocate("#call", "mob") orelse return error.TestUnexpectedResult;
    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);
    try stunBindPeer(&client, server_addr, creds);

    var capture = try MediaSocket.bind(loopback_be, 0);
    defer capture.deinit();
    capture.setRecvTimeoutMs(2000);
    const capture_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try capture.localPort());
    var sink = RtcpCaptureSink{ .sock = &client, .dest = capture_addr };
    plane.setCrossLegSink(.{ .ctx = &sink, .on_rtp_frame = RtcpCaptureSink.onRtp, .on_rtcp_feedback = RtcpCaptureSink.onRtcp });

    var rtcp_buf: [64]u8 = undefined;
    const pli = try rtcp_translate.buildKeyframeRequest(0xABCD, 0xA100, &rtcp_buf);
    client.sendTo(server_addr, pli);

    var got_buf: [media_socket.max_datagram]u8 = undefined;
    const got = capture.recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, pli, got.data);
}

test "MediaPlane: cross-thread RTCP egress is direct when DTLS is off and queued when on" {
    var capture = try MediaSocket.bind(loopback_be, 0);
    defer capture.deinit();
    capture.setRecvTimeoutMs(2000);
    const capture_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try capture.localPort());
    const rtcp = [_]u8{ 0x81, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2 };

    {
        var plane = MediaPlane.init(testing.allocator);
        defer plane.deinit();
        try plane.start(loopback_be, 0);
        plane.sendRtcpTo(capture_addr, &rtcp);
        var got_buf: [media_socket.max_datagram]u8 = undefined;
        const got = capture.recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, &rtcp, got.data);
    }

    {
        var plane = MediaPlane.init(testing.allocator);
        defer plane.deinit();
        plane.dtls_enabled = true;
        try plane.start(loopback_be, 0);
        plane.sendRtcpTo(capture_addr, &rtcp);
        var got_buf: [media_socket.max_datagram]u8 = undefined;
        const got = capture.recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, &rtcp, got.data);
    }
}

/// Drive a DTLS 1.2 client handshake to completion against the live pump and
/// return the exported SRTP keying material for the leg.
fn dtlsHandshakeClient(client: *MediaSocket, server_addr: TransportAddress, seed: u8, client_random: [32]u8) !dtls_srtp.ExportedKeys {
    const ecdhe_seed: [32]u8 = @splat(seed);
    const ecdhe = dtls_kx.generateKeyPair(ecdhe_seed);
    var out: [2048]u8 = undefined;
    var rbuf: [media_socket.max_datagram]u8 = undefined;

    // 1) ClientHello (no cookie) -> HelloVerifyRequest(cookie).
    var ch1_body: [512]u8 = undefined;
    const ch1b = try dtls_messages.buildClientHello(&ch1_body, .{ .random = client_random, .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80} });
    const ch1_len = try dtls_server.framePlaintextHandshake(&out, .client_hello, 0, 0, 0, ch1b);
    client.sendTo(server_addr, out[0..ch1_len]);
    var cookie: [64]u8 = undefined;
    var cookie_len: usize = 0;
    {
        const got = client.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
        const rdec = try dtls_record.RecordHeader.decode(got.data);
        const hh = try dtls_handshake.Header.decode(rdec.fragment);
        if (hh.hdr.msg_type != .hello_verify_request) return error.TestUnexpectedResult;
        const c = try dtls_handshake.parseHelloVerifyRequest(rdec.fragment[dtls_handshake.handshake_header_len..][0..hh.hdr.length]);
        @memcpy(cookie[0..c.len], c);
        cookie_len = c.len;
    }

    // 2) ClientHello (cookie) -> flight 4. Begin the client transcript with CH2.
    var transcript = Sha256.init(.{});
    var ch2_body: [600]u8 = undefined;
    const ch2b = try dtls_messages.buildClientHello(&ch2_body, .{ .random = client_random, .cookie = cookie[0..cookie_len], .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80} });
    dtls_server.feedTranscript(&transcript, .client_hello, 1, ch2b);
    const ch2_len = try dtls_server.framePlaintextHandshake(&out, .client_hello, 1, 0, 1, ch2b);
    client.sendTo(server_addr, out[0..ch2_len]);

    var server_random: [32]u8 = @splat(0);
    var server_point: [dtls_messages.p256_point_len]u8 = @splat(0);
    {
        const got = client.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
        var off: usize = 0;
        while (off < got.data.len) {
            const rdec = try dtls_record.RecordHeader.decode(got.data[off..]);
            off += rdec.consumed;
            const hh = try dtls_handshake.Header.decode(rdec.fragment);
            const mbody = rdec.fragment[dtls_handshake.handshake_header_len..][0..hh.hdr.length];
            switch (hh.hdr.msg_type) {
                .server_hello => {
                    const sh = try dtls_messages.parseServerHello(mbody);
                    server_random = sh.random;
                },
                .server_key_exchange => {
                    const ske = try dtls_messages.parseServerKeyExchange(mbody);
                    server_point = ske.point;
                },
                else => {},
            }
            dtls_server.feedTranscript(&transcript, hh.hdr.msg_type, hh.hdr.message_seq, mbody);
        }
    }

    // 3) Derive the shared secret, master secret, and key block.
    const pre_master = try dtls_kx.computeSharedSecret(ecdhe.secret, server_point);
    const master_secret = dtls_kx.masterSecret(&pre_master, client_random, server_random);
    const key_block = dtls_messages.deriveKeyBlock(&master_secret, client_random, server_random);

    // 4) flight 5: ClientKeyExchange + ChangeCipherSpec + Finished (all in one).
    var flight5: [512]u8 = undefined;
    var f5: usize = 0;
    var cke_body: [80]u8 = undefined;
    const cke = try dtls_messages.buildClientKeyExchange(&cke_body, ecdhe.public);
    dtls_server.feedTranscript(&transcript, .client_key_exchange, 2, cke);
    f5 += try dtls_server.framePlaintextHandshake(flight5[f5..], .client_key_exchange, 2, 0, 2, cke);
    f5 += (try dtls_record.writePlaintext(.change_cipher_spec, 0, 3, &.{0x01}, flight5[f5..])).len;
    const client_hash = transcript.peek();
    const client_vd = dtls_kx.verifyData(&master_secret, "client finished", client_hash);
    f5 += try dtls_server.frameEncryptedHandshake(flight5[f5..], key_block.client_write_key, key_block.client_write_iv, 1, 0, .finished, 3, &client_vd);
    client.sendTo(server_addr, flight5[0..f5]);
    // Drain flight 6 (server ChangeCipherSpec + Finished): the session is now
    // established and the SFU can key the leg on the peer's first media packet.
    _ = client.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;

    return dtls_srtp.exportSrtpKeys(&master_secret, client_random, server_random);
}

test "MediaPlane e2e: DTLS-SRTP media forwards A->B, decrypted then re-encrypted per peer" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    try plane.start(loopback_be, 0);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);

    const credsA = plane.allocate("#call", "alice") orelse return error.TestUnexpectedResult;
    const credsB = plane.allocate("#call", "bob") orelse return error.TestUnexpectedResult;

    var a = try MediaSocket.bind(loopback_be, 0);
    defer a.deinit();
    a.setRecvTimeoutMs(3000);
    var b = try MediaSocket.bind(loopback_be, 0);
    defer b.deinit();
    b.setRecvTimeoutMs(3000);

    var ar: [32]u8 = undefined;
    for (&ar, 0..) |*x, i| x.* = @intCast((i *% 3) +% 1);
    var br: [32]u8 = undefined;
    for (&br, 0..) |*x, i| x.* = @intCast((i *% 5) +% 2);

    // Both peers bind (STUN) and complete a DTLS-SRTP handshake with the SFU.
    try stunBindPeer(&a, server_addr, credsA);
    try stunBindPeer(&b, server_addr, credsB);
    const keysA = try dtlsHandshakeClient(&a, server_addr, 0xA5, ar);
    const keysB = try dtlsHandshakeClient(&b, server_addr, 0x5A, br);
    // Distinct handshakes ⇒ distinct SRTP keying material per leg.
    try testing.expect(!std.mem.eql(u8, &keysA.client, &keysB.server));

    // A publishes an SRTP frame protected with A's client-write context.
    const a_out = srtp.deriveSessionKeys(keysA.clientMaster(), keysA.clientSalt());
    const rtp = [_]u8{ 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0xA1, 0xA1, 0xA1, 0xA1 } ++ "cadencevox-voice".*;
    var wire_buf: [rtp.len + srtp.auth_tag_len]u8 = undefined;
    const wireA = try srtp.protect(a_out, 0, &rtp, &wire_buf);
    a.sendTo(server_addr, wireA);

    // B receives the frame re-encrypted under ITS OWN server-write context.
    var rcv: [media_socket.max_datagram]u8 = undefined;
    const got = b.recvFrom(&rcv) orelse return error.TestUnexpectedResult;
    // Per-recipient key ⇒ the bytes B sees are NOT the bytes A sent.
    try testing.expect(!std.mem.eql(u8, got.data, wireA));
    const b_in = srtp.deriveSessionKeys(keysB.serverMaster(), keysB.serverSalt());
    var plain: [rtp.len]u8 = undefined;
    const recovered = try srtp.unprotect(b_in, 0, got.data, &plain);
    try testing.expectEqualSlices(u8, &rtp, recovered);
}

test "MediaPlane e2e: queued RTCP egress is SRTCP protected for DTLS recipient" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    try plane.start(loopback_be, 0);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);

    const creds = plane.allocate("#call", "bob") orelse return error.TestUnexpectedResult;
    var b = try MediaSocket.bind(loopback_be, 0);
    defer b.deinit();
    b.setRecvTimeoutMs(3000);

    var br: [32]u8 = undefined;
    for (&br, 0..) |*x, i| x.* = @intCast((i *% 7) +% 3);

    try stunBindPeer(&b, server_addr, creds);
    const keys = try dtlsHandshakeClient(&b, server_addr, 0x6B, br);
    const dest = plane.remoteFor("#call", "bob") orelse return error.TestUnexpectedResult;

    var rtcp_buf: [64]u8 = undefined;
    const pli = try rtcp_translate.buildKeyframeRequest(0xABCD0001, 0xA1000001, &rtcp_buf);
    plane.sendRtcpTo(dest, pli);

    var got_buf: [media_socket.max_datagram]u8 = undefined;
    const got = b.recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
    try testing.expect(!std.mem.eql(u8, got.data, pli));
    const inbound = srtp.deriveSessionKeys(keys.serverMaster(), keys.serverSalt());
    var recovered_buf: [64]u8 = undefined;
    const recovered = try srtcp.unprotect(inbound, got.data, &recovered_buf);
    try testing.expectEqualSlices(u8, pli, recovered);
}
