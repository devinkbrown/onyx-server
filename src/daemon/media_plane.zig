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
const stun = @import("../proto/stun.zig");
const sdp = @import("../proto/sdp.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const routing = @import("../substrate/media_routing.zig");
const media_rooms = @import("media_room.zig");
const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const ecdsa = @import("../crypto/ecdsa_p256.zig");
const x509 = @import("../crypto/x509.zig");
const x509_verify = @import("../crypto/x509_verify.zig");
const linux = std.os.linux;
const posix = std.posix;
const media_transport = @import("../substrate/media_transport.zig");
const media_socket = @import("../substrate/media_socket.zig");
const rtp_profile = @import("../proto/rtp_profile.zig");
const rtp_nack = @import("../substrate/rtp_nack.zig");
const native_feedback = @import("../substrate/native_feedback.zig");
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

pub const RoutingDisposition = enum { sent, stale, denied, unbound, would_block, socket_error, source_error };
fn routingSendDisposition(result: media_socket.SendDisposition) RoutingDisposition {
    return switch (result) {
        .sent => .sent,
        .would_block => .would_block,
        .socket_error, .invalid_destination => .socket_error,
    };
}
fn routingPayloadDigest(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}
fn profileHasCodec(profile: media_rooms.CallProfile, tag: sdp.CodecTag) bool {
    if (profile.codec_count == 0 or profile.codec_count > media_rooms.max_profile_codecs) return false;
    for (profile.slice()) |codec| if (codec.tag == tag) return true;
    return false;
}
fn validRoutingRemote(addr: TransportAddress) bool {
    return (addr.ip_len == 4 or addr.ip_len == 16) and addr.port != 0;
}
fn routingAddressEqual(a: TransportAddress, b: TransportAddress) bool {
    return (a.ip_len == 4 or a.ip_len == 16) and a.ip_len == b.ip_len and a.port == b.port and std.mem.eql(u8, a.ip[0..a.ip_len], b.ip[0..b.ip_len]);
}
const RoutingCryptoAssociation = struct { live: bool = false, endpoint: routing.EndpointId = undefined, binding_revision: u64 = 0, addr: TransportAddress = .{} };
const RoutingInboundKind = enum { stun, dtls, media };
const RoutingInbound = struct { ordinal: u64, source: routing.EndpointStamp, key: routing.EndpointKey, from: TransportAddress, bytes: [media_socket.max_datagram]u8, len: usize, digest: [32]u8, kind: RoutingInboundKind, canonical: [media_socket.max_datagram]u8 = undefined, canonical_len: usize = 0, canonical_kind: routing.PacketKind = .rtp, canonical_digest: [32]u8 = @splat(0), authenticated: bool = false };
const RoutingStunCapture = struct {
    key: routing.EndpointKey,
    identity: routing.EndpointObservation,
    ufrag: [media_transport.ufrag_len]u8,
    pwd: [media_transport.pwd_len]u8,
    revision: u64,
    fn wipe(self: *@This()) void {
        std.crypto.secureZero(u8, &self.pwd);
    }
};
pub const AuthenticatedWebrtcFrame = struct { source: routing.EndpointStamp, stream_id: u32, profile: media_rooms.CallProfile, kind_bits: u8, bytes: []const u8, kind: routing.PacketKind };
const PhysicalSsrc = struct { live: bool = false, ssrc: u32 = 0, key: routing.EndpointKey = undefined, endpoint: routing.EndpointId = undefined };
pub const RoutingAccepted = struct { ordinal: u64 };
pub const RoutingProducerFence = enum(u128) { _ };
pub const RoutingEgressState = struct { queued: usize, inflight: bool, fenced: bool, capacity: usize, payload_limit: usize, next_ordinal: u64 };
pub const RoutingAttemptObservation = struct { source: routing.EndpointStamp, target: routing.EndpointStamp };
const RoutingWireKind = enum { canonical, native_frame, native_feedback };
const RoutingEgressRow = struct { wire: RoutingWireKind = .canonical, source: routing.EndpointStamp, target: routing.EndpointStamp, kind: routing.PacketKind, source_stream: u32, ordinal: u64, len: usize, digest: [32]u8 };
const RoutingEgressQueue = struct {
    rows: []RoutingEgressRow,
    payloads: []u8,
    payload_limit: usize,
    mutex: std.atomic.Mutex = .unlocked,
    head: usize = 0,
    len: usize = 0,
    next_ordinal: u64 = 1,
    pump_id: ?std.Thread.Id = null,
    completed: u64 = 0,
    last_disposition: ?RoutingDisposition = null,
    inflight: ?u64 = null,
    poisoned: bool = false,
    next_fence: u64 = 1,
    fence: ?RoutingProducerFence = null,
};

pub const MediaPlane = struct {
    allocator: std.mem.Allocator,
    routing_domain: ?*routing.Domain = null,
    routing_closed: bool = false,
    routing_binding: ?*routing.WebrtcBinding = null,
    physical_revision: u64 = 1,
    routing_egress: ?*RoutingEgressQueue = null,
    retired_routing_egress: ?*RoutingEgressQueue = null,
    physical_ssrcs: [sfu_srtp.max_owners]PhysicalSsrc = @splat(.{}),
    routing_inbound: ?RoutingInbound = null,
    next_routing_inbound: u64 = 1,
    routing_ingress_refused: u64 = 0,
    routing_ingress_completed: u64 = 0,
    routing_last_ingress_error: ?anyerror = null,
    routing_crypto: [sfu_srtp.max_peers]RoutingCryptoAssociation = @splat(.{}),
    physical_pending: usize = 0,
    physical_rows: PhysicalRtcMap = .empty,
    physical_ufrags: PhysicalUfragMap = .empty,
    physical_groups: PhysicalGroupMap = .empty,
    transport: MediaTransport,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    legacy_joining: bool = false,
    worker_id: ?std.Thread.Id = null,
    runtime: runtime_pause.WorkerState = .{},
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
    dtls_requested: bool = false,
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
    dtls13_requested: bool = false,
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
        return initFallible(allocator) catch @panic("media CSPRNG entropy unavailable");
    }

    pub fn initFallible(allocator: std.mem.Allocator) !MediaPlane {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try osEntropy(&seed);
        return .{
            .allocator = allocator,
            .transport = MediaTransport.init(allocator),
            .csprng = std.Random.DefaultCsprng.init(seed),
            .srtp_hub = sfu_srtp.SfuSrtp.init(allocator),
        };
    }

    /// Private worker registration: only the actual pump body enters it. An
    /// empty FIFO, a passed boolean or an arbitrary thread is not this owner.
    fn enterRoutingPump(self: *MediaPlane) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        if (queue.pump_id != null) return error.Busy;
        queue.pump_id = std.Thread.getCurrentId();
    }
    fn leaveRoutingPump(self: *MediaPlane) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const queue = self.routing_egress.?;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        std.debug.assert(queue.pump_id == std.Thread.getCurrentId() and (queue.inflight == null or queue.poisoned));
        queue.pump_id = null;
    }

    /// Current-pump-only terminal attempt, with owned payload held until the
    /// actual disposition. Would-block/socket failure consume this attempt;
    /// there is no re-protect/retry that could reset nonce or replay authority.
    fn drainOneRoutingEgress(self: *MediaPlane, sock: *MediaSocket) !?RoutingDisposition {
        const domain = self.routing_domain orelse return error.NotRoutingBound;
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        if (queue.pump_id != std.Thread.getCurrentId() or queue.inflight != null or queue.poisoned) {
            queue.mutex.unlock();
            return error.NotRoutingPump;
        }
        if (queue.len == 0) {
            queue.mutex.unlock();
            return null;
        }
        const row = queue.rows[queue.head];
        const canonical = queue.payloads[queue.head * queue.payload_limit ..][0..row.len];
        queue.inflight = row.ordinal;
        queue.mutex.unlock();
        const Process = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            row: RoutingEgressRow,
            bytes: []const u8,
            const Prepared = union(enum) { held, disposed: RoutingDisposition };
            fn run(scope: *routing.Locked, ctx: @This()) !Prepared {
                _ = ctx.domain.requireCurrentLocked(scope, ctx.row.source) catch return .{ .disposed = .stale };
                const target = ctx.domain.requireCurrentLocked(scope, ctx.row.target) catch return .{ .disposed = .stale };
                try ctx.domain.requireWebrtcBindingLocked(scope, ctx.owner.routing_binding orelse return error.NotRoutingBound, ctx.owner);
                if (target.stamp.endpoint.leg == .native) {
                    const bytes = try ctx.owner.borrowNativeRoutingAttempt(ctx.row.ordinal);
                    switch (bytes.kind) {
                        .frame => ctx.domain.requireNativeTargetLocked(scope, target.stamp, bytes.bytes) catch return .{ .disposed = .denied },
                        .feedback => ctx.domain.requireNativeFeedbackTargetLocked(scope, target.stamp, bytes.bytes) catch return .{ .disposed = .denied },
                    }
                    try ctx.domain.holdWebrtcEgressLocked(scope, ctx.owner, ctx.row.ordinal);
                    return .held;
                }
                lockSpin(&ctx.owner.mutex);
                defer ctx.owner.mutex.unlock();
                if (ctx.owner.routing_closed or ctx.owner.stop_flag.load(.acquire)) return .{ .disposed = .denied };
                const key: routing.EndpointKey = .{ .call = target.stamp.endpoint.call, .client = target.stamp.offering_client, .leg = .webrtc };
                const actual = ctx.owner.physical_rows.get(key) orelse return .{ .disposed = .stale };
                if (!std.meta.eql(actual.identity, target) or !std.meta.eql(ctx.row.source.endpoint.call, target.stamp.endpoint.call)) return .{ .disposed = .stale };
                if (actual.endpoint.remote == null) return .{ .disposed = .unbound };
                try ctx.domain.requireBridgeNegotiationLocked(scope, actual.identity.reference, actual.profile, actual.kind_bits);
                if (ctx.row.kind == .rtp) requirePhysicalRtpPacketPolicy(actual, ctx.bytes) catch return .{ .disposed = .denied };
                try ctx.domain.holdWebrtcEgressLocked(scope, ctx.owner, ctx.row.ordinal);
                return .held;
            }
        };
        const preparation = domain.withLocked(Process{ .owner = self, .domain = domain, .row = row, .bytes = canonical }, Process.run) catch |err| {
            self.finishRoutingEgressAttempt(queue, row.ordinal, .source_error);
            return err;
        };
        switch (preparation) {
            .held => {},
            .disposed => |disposition| {
                self.finishRoutingEgressAttempt(queue, row.ordinal, disposition);
                return disposition;
            },
        }
        // The genuine Domain pin now retains all source/target authority and
        // blocks publication/retirement. Actual pump crypto/syscalls run here,
        // outside Domain, Plane and FIFO gates. No source callback/backend is
        // invoked by the authority cut above.
        const disposition = self.sendPinnedRoutingAttempt(sock, row, canonical);
        // Canonical source-issued completion uses the scope serial retained
        // by the actual pin, not a fresh ordinary admission at next_scope.
        // A finish refusal retains pin+inflight bytes, fails closed and stops.
        domain.completeWebrtcEgress(self, row.ordinal) catch |err| {
            lockSpin(&queue.mutex);
            queue.poisoned = true;
            queue.last_disposition = .source_error;
            queue.mutex.unlock();
            self.stop_flag.store(true, .release);
            return err;
        };
        self.finishRoutingEgressAttempt(queue, row.ordinal, disposition);
        return disposition;
    }

    pub fn inspectRoutingEgressAttemptLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64) !RoutingAttemptObservation {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        if (queue.pump_id != std.Thread.getCurrentId() or queue.inflight != ordinal or queue.len == 0) return error.NotRoutingPump;
        const row = queue.rows[queue.head];
        if (row.ordinal != ordinal or row.len > queue.payload_limit) return error.InvalidAttempt;
        const bytes = queue.payloads[queue.head * queue.payload_limit ..][0..row.len];
        const digest = routingPayloadDigest(bytes);
        if (!std.mem.eql(u8, &digest, &row.digest)) return error.InvalidAttempt;
        return .{ .source = row.source, .target = row.target };
    }

    pub const NativeAttemptKind = enum { frame, feedback };
    pub const NativeRoutingAttempt = struct { kind: NativeAttemptKind, bytes: []const u8, source_stream: u32 };
    /// Borrow expires on actual private queue finish. Copied ordinal alone
    /// cannot access it from a producer, foreign worker or later queue reuse.
    pub fn borrowNativeRoutingAttempt(self: *MediaPlane, ordinal: u64) !NativeRoutingAttempt {
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        if (queue.pump_id != std.Thread.getCurrentId() or queue.inflight != ordinal or queue.len == 0) return error.NotRoutingPump;
        const row = queue.rows[queue.head];
        if (row.ordinal != ordinal or row.target.endpoint.leg != .native or row.wire == .canonical or row.len > queue.payload_limit) return error.InvalidAttempt;
        const bytes = queue.payloads[queue.head * queue.payload_limit ..][0..row.len];
        if (!std.mem.eql(u8, &row.digest, &routingPayloadDigest(bytes))) return error.InvalidAttempt;
        return .{ .kind = if (row.wire == .native_frame) .frame else .feedback, .bytes = bytes, .source_stream = row.source_stream };
    }

    fn sendPinnedRoutingAttempt(self: *MediaPlane, socket: *MediaSocket, row: RoutingEgressRow, canonical: []const u8) RoutingDisposition {
        if (row.target.endpoint.leg == .native) {
            if (row.wire == .canonical) return .denied;
            const outcome = self.routing_domain.?.sendNativeRoutingEgress(self, row.ordinal) catch return .denied;
            return routingSendDisposition(outcome);
        }
        if (row.wire != .canonical) return .denied;
        const key: routing.EndpointKey = .{ .call = row.target.endpoint.call, .client = row.target.offering_client, .leg = .webrtc };
        // Current source rows are immutable under the issued Domain attempt pin.
        const actual = self.physical_rows.get(key) orelse return .stale;
        const addr = actual.endpoint.remote orelse return .unbound;
        if (actual.identity.mode == .dtls_required) {
            var association: ?RoutingCryptoAssociation = null;
            for (self.routing_crypto) |candidate| if (candidate.live and routingAddressEqual(candidate.addr, addr)) {
                association = candidate;
                break;
            };
            const joined = association orelse return .denied;
            if (!std.meta.eql(joined.endpoint, row.target.endpoint) or joined.binding_revision != row.target.binding_revision) return .denied;
            if (actual.expected_fp) |expected| {
                if (self.dtls) |term| term.bindExpectedFingerprint(addr, expected);
                if (self.dtls13) |term| term.bindExpectedFingerprint(addr, expected);
            }
            if (self.srtp_hub.peers.len == 0) return .denied;
            var keys: ?sfu_srtp.ExportedKeys = null;
            if (self.dtls13) |term| if (term.owns(addr)) {
                if (term.srtpProfile(addr) != @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) return .denied;
                keys = term.exportedKeys(addr) orelse return .denied;
            };
            if (keys == null) if (self.dtls) |term| if (term.owns(addr)) {
                if (term.srtpProfile(addr) != @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) return .denied;
                keys = term.exportedKeys(addr) orelse return .denied;
            };
            if (keys == null or !self.srtp_hub.peerMaterialMatches(addr, keys.?)) return .denied;
            var protected: [media_socket.max_datagram + sfu_srtp.rtcp_overhead]u8 = undefined;
            const wire = switch (row.kind) {
                .rtp => self.srtp_hub.protectRtp(addr, canonical, &protected),
                .rtcp => self.srtp_hub.protectRtcp(addr, canonical, &protected),
            } orelse return .denied;
            return routingSendDisposition(socket.trySendTo(addr, wire));
        }
        return routingSendDisposition(socket.trySendTo(addr, canonical));
    }

    fn finishRoutingEgressAttempt(self: *MediaPlane, queue: *RoutingEgressQueue, ordinal: u64, disposition: RoutingDisposition) void {
        _ = self;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        std.debug.assert(queue.pump_id == std.Thread.getCurrentId() and queue.inflight == ordinal and queue.len != 0 and queue.rows[queue.head].ordinal == ordinal);
        std.crypto.secureZero(u8, queue.payloads[queue.head * queue.payload_limit ..][0..queue.payload_limit]);
        queue.head = (queue.head + 1) % queue.rows.len;
        queue.len -= 1;
        queue.inflight = null;
        queue.completed += 1; // Each completion consumes one checked ordinal.
        queue.last_disposition = disposition;
    }

    /// Preallocate bounded owned egress storage outside the routing cut. This is
    /// source construction, not readiness or admission of a transport graph.
    pub fn prepareRoutingEgress(self: *MediaPlane, domain: *routing.Domain, capacity: usize, payload_limit: usize) !void {
        if (capacity == 0 or capacity > std.math.maxInt(u16) or payload_limit < 12 or payload_limit > media_socket.max_datagram) return error.InvalidRequest;
        const bytes = std.math.mul(usize, capacity, payload_limit) catch return error.InvalidRequest;
        const Capture = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            fn run(scope: *routing.Locked, ctx: @This()) !u64 {
                try ctx.domain.requireWebrtcBindingLocked(scope, ctx.owner.routing_binding orelse return error.NotRoutingBound, ctx.owner);
                lockSpin(&ctx.owner.mutex);
                defer ctx.owner.mutex.unlock();
                if (ctx.owner.routing_closed or ctx.owner.routing_egress != null or ctx.owner.physical_pending != 0 or ctx.owner.legacy_joining or ctx.owner.thread != null or ctx.owner.runtime.view != null) return error.Busy;
                ctx.owner.physical_pending = 1;
                return ctx.owner.physical_revision;
            }
        };
        const revision = try domain.withLocked(Capture{ .owner = self, .domain = domain }, Capture.run);
        defer self.finishPhysicalPlan();
        const queue = try self.allocator.create(RoutingEgressQueue);
        errdefer self.allocator.destroy(queue);
        const rows = try self.allocator.alloc(RoutingEgressRow, capacity);
        errdefer self.allocator.free(rows);
        const payloads = try self.allocator.alloc(u8, bytes);
        errdefer self.allocator.free(payloads);
        @memset(payloads, 0);
        queue.* = .{ .rows = rows, .payloads = payloads, .payload_limit = payload_limit };
        const Install = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            queue: *RoutingEgressQueue,
            revision: u64,
            fn run(scope: *routing.Locked, ctx: @This()) !void {
                try ctx.domain.requireWebrtcBindingLocked(scope, ctx.owner.routing_binding orelse return error.NotRoutingBound, ctx.owner);
                lockSpin(&ctx.owner.mutex);
                defer ctx.owner.mutex.unlock();
                if (ctx.owner.routing_closed or ctx.owner.routing_egress != null or ctx.owner.physical_pending != 1 or ctx.owner.physical_revision != ctx.revision or ctx.owner.legacy_joining or ctx.owner.thread != null or ctx.owner.runtime.view != null) return error.StaleCandidate;
                ctx.owner.routing_egress = ctx.queue;
            }
        };
        try domain.withLocked(Install{ .owner = self, .domain = domain, .queue = queue, .revision = revision }, Install.run);
    }

    /// Authenticated source bytes are obtained from the canonical native owner.
    /// The caller supplies only the exact current target stamp. Rewrap and copy
    /// finish before publishing the ordinal; no borrowed producer buffer escapes.
    pub fn requirePhysicalSelectionLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, expected: routing.EndpointObservation) !void {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_closed or self.physical_revision == std.math.maxInt(u64)) return error.Busy;
        const row = self.physical_rows.get(.{ .call = expected.stamp.endpoint.call, .client = expected.stamp.offering_client, .leg = .webrtc }) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, expected)) return error.StaleCandidate;
    }
    pub fn commitPhysicalSelectionLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, next: routing.EndpointObservation, selection: @import("native_media_transport.zig").Selection) void {
        domain.requireWebrtcBindingLocked(scope, self.routing_binding.?, self) catch @panic("foreign selection publication");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const row = self.physical_rows.getPtr(.{ .call = next.stamp.endpoint.call, .client = next.stamp.offering_client, .leg = .webrtc }).?;
        row.identity = next;
        row.endpoint.max_spatial = selection.max_spatial;
        row.max_temporal = selection.max_temporal;
        self.physical_revision += 1;
    }

    pub fn enqueueNativeFrameLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, handle: routing.IngressHandle, target: routing.EndpointStamp) !RoutingAccepted {
        const frame = try domain.resolveNativeIngressLocked(scope, handle);
        if (frame.content != .frame) return error.InvalidIngress;
        const destination = try domain.requireCurrentLocked(scope, target);
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        if (!std.meta.eql(target.endpoint.call, frame.source.endpoint.call) or std.meta.eql(target.offering_client, frame.source.offering_client)) return error.RouteDenied;
        if (target.endpoint.leg == .native) {
            try domain.requireNativeTargetLocked(scope, target, frame.bytes);
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            return self.enqueueWireBytesLocked(frame.source, target, .rtp, frame.stream_id, frame.bytes, .native_frame);
        }
        const decoded = try cadence_frame.decode(frame.bytes);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_closed or self.stop_flag.load(.acquire)) return error.Closing;
        const key: routing.EndpointKey = .{ .call = target.endpoint.call, .client = target.offering_client, .leg = .webrtc };
        const row = self.physical_rows.get(key) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, destination)) return error.StaleCandidate;
        try domain.requireBridgeNegotiationLocked(scope, destination.reference, row.profile, row.kind_bits);
        var accepted_codec = false;
        const codec_tag: @TypeOf(row.profile.codecs[0].tag) = switch (decoded.codec) {
            .cadencevox_audio => .cadencevox,
            .cadencevis_video => .cadencevis,
            .raw => .raw,
        };
        for (row.profile.slice()) |codec| if (codec.tag == codec_tag) {
            accepted_codec = true;
            break;
        };
        if (decoded.band_id - cadence_frame.MEDIA_BAND_FLOOR > row.endpoint.max_spatial or (row.max_temporal == 0 and !decoded.keyframe)) return error.LayerDenied;
        if (!accepted_codec or (decoded.codec == .cadencevox_audio and row.kind_bits & 1 == 0) or (decoded.codec == .cadencevis_video and row.kind_bits & 6 == 0)) return error.ProfileDenied;
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        if (queue.fence != null) return error.ProducerFenced;
        if (queue.len == queue.rows.len) return error.QueueFull;
        if (queue.next_ordinal == 0 or queue.next_ordinal == std.math.maxInt(u64)) return error.SequenceExhausted;
        const index = (queue.head + queue.len) % queue.rows.len;
        const storage = queue.payloads[index * queue.payload_limit ..][0..queue.payload_limit];
        var map = media_bridge.defaultPtMap();
        // Publisher stream is source-issued and unique, never inferred from a
        // nickname, address, recipient stream or an absent bridge mapping.
        const canonical = media_bridge.nativeDatagramToRtp(frame.bytes, &map, frame.stream_id, storage) catch |err| {
            std.crypto.secureZero(u8, storage);
            return err;
        };
        const ordinal = queue.next_ordinal;
        queue.rows[index] = .{ .source = frame.source, .target = target, .kind = .rtp, .source_stream = frame.stream_id, .ordinal = ordinal, .len = canonical.len, .digest = routingPayloadDigest(canonical) };
        queue.len += 1;
        queue.next_ordinal += 1;
        return .{ .ordinal = ordinal };
    }

    pub fn enqueueNativeFeedbackLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, handle: routing.IngressHandle, target: routing.EndpointStamp) !RoutingAccepted {
        const source = try domain.resolveNativeIngressLocked(scope, handle);
        if (source.content != .feedback) return error.InvalidIngress;
        const destination = try domain.requireCurrentLocked(scope, target);
        if (!std.meta.eql(source.source.endpoint.call, target.endpoint.call) or source.source.offering_client.eql(target.offering_client) or try @import("native_media_transport.zig").NativeMediaTransport.feedbackTargetStream(source.bytes) != destination.stream_id) return error.RouteDenied;
        if (target.endpoint.leg == .native) {
            try domain.requireNativeFeedbackTargetLocked(scope, target, source.bytes);
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            return self.enqueueWireBytesLocked(source.source, target, .rtcp, source.stream_id, source.bytes, .native_feedback);
        }
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const row = self.physical_rows.get(.{ .call = target.endpoint.call, .client = target.offering_client, .leg = .webrtc }) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, destination) or row.endpoint.ssrc == 0) return error.RouteDenied;
        try domain.requireBridgeNegotiationLocked(scope, row.identity.reference, row.profile, row.kind_bits);
        var seqs32: [64]u32 = undefined;
        const request = try native_feedback.parse(source.bytes, &seqs32);
        var storage: [12 + 64 * 4]u8 = undefined;
        const rtcp = switch (request) {
            .keyframe_request => try rtcp_translate.buildKeyframeRequest(source.stream_id, row.endpoint.ssrc, &storage),
            .nack => |nack| nack: {
                var seqs16: [64]u16 = undefined;
                for (nack.seqs, 0..) |seq, i| {
                    if (seq > std.math.maxInt(u16)) return error.InvalidIngress;
                    seqs16[i] = @intCast(seq);
                }
                break :nack try rtcp_translate.buildNack(source.stream_id, row.endpoint.ssrc, seqs16[0..nack.seqs.len], &storage);
            },
            .receiver_report => return error.FeedbackUnavailable,
        };
        return self.enqueueCanonicalBytesLocked(source.source, target, .rtcp, source.stream_id, rtcp);
    }

    pub fn requireRoutingProducerAdmissionLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked) routing.Error!void {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.InvalidIdentity, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_closed or self.stop_flag.load(.acquire)) return error.Closing;
        const queue = self.routing_egress orelse return error.Busy;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        if (queue.fence != null or queue.poisoned) return error.Busy;
    }

    /// The fence is source-issued under the same routing/producer gate. It
    /// closes admission without asserting that accepted jobs are settled.
    pub fn fenceRoutingProducersLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked) !RoutingProducerFence {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        if (queue.fence != null) return error.Busy;
        if (queue.next_fence == 0 or queue.next_fence == std.math.maxInt(u64)) return error.SequenceExhausted;
        const context = try domain.webrtcSourceContextLocked(scope, self.routing_binding.?, self);
        const fence: RoutingProducerFence = @enumFromInt(@as(u128, context.registration) | (@as(u128, queue.next_fence) << 64));
        queue.next_fence += 1;
        queue.fence = fence;
        return fence;
    }

    pub fn resumeRoutingProducersLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, fence: RoutingProducerFence) !void {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        try self.requireRoutingFence(domain, scope, queue, fence);
        queue.fence = null;
    }

    pub fn requireRoutingEgressSettledLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, fence: RoutingProducerFence) !void {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        try self.requireRoutingFence(domain, scope, queue, fence);
        if (queue.len != 0 or queue.inflight != null) return error.Busy;
    }

    fn requireRoutingFence(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, queue: *RoutingEgressQueue, fence: RoutingProducerFence) !void {
        const context = try domain.webrtcSourceContextLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        if (queue.fence != fence or @as(u64, @truncate(@intFromEnum(fence))) != context.registration) return error.InvalidFence;
    }

    pub fn routingEgressStateLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked) !RoutingEgressState {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        return .{ .queued = queue.len, .inflight = queue.inflight != null, .fenced = queue.fence != null, .capacity = queue.rows.len, .payload_limit = queue.payload_limit, .next_ordinal = queue.next_ordinal };
    }

    /// Source teardown refuses accepted custody. Actual worker join and detach
    /// are mandatory before storage retirement; an empty queue is not a join.
    pub fn disposeRoutingEgress(self: *MediaPlane, domain: *routing.Domain) !void {
        const Take = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            fn run(scope: *routing.Locked, ctx: @This()) !*RoutingEgressQueue {
                try ctx.domain.requireWebrtcBindingLocked(scope, ctx.owner.routing_binding orelse return error.NotRoutingBound, ctx.owner);
                lockSpin(&ctx.owner.mutex);
                defer ctx.owner.mutex.unlock();
                if (ctx.owner.legacy_joining or ctx.owner.thread != null or ctx.owner.runtime.view != null or ctx.owner.physical_pending != 0) return error.Busy;
                const queue = ctx.owner.routing_egress orelse return error.QueueUnavailable;
                lockSpin(&queue.mutex);
                defer queue.mutex.unlock();
                if (queue.len != 0 or queue.inflight != null or queue.pump_id != null or queue.poisoned) return error.Busy;
                ctx.owner.routing_egress = null;
                return queue;
            }
        };
        const queue = try domain.withLocked(Take{ .owner = self, .domain = domain }, Take.run);
        std.crypto.secureZero(u8, queue.payloads);
        self.allocator.free(queue.payloads);
        self.allocator.free(queue.rows);
        self.allocator.destroy(queue);
    }

    pub fn requireRoutingAttachable(self: *MediaPlane) routing.Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        lockSpin(&self.rtcp_out_mutex);
        defer self.rtcp_out_mutex.unlock();
        if (self.retired_routing_egress != null or self.routing_egress != null or self.legacy_joining or self.physical_pending != 0 or self.physical_rows.count() != 0 or self.physical_ufrags.count() != 0 or self.physical_groups.count() != 0 or self.routing_domain != null or self.routing_binding != null or self.thread != null or self.runtime.view != null or self.transport.endpoints.count() != 0 or self.transport.by_ufrag.count() != 0 or self.transport.by_addr.count() != 0 or self.transport.by_ssrc.count() != 0 or self.transport.group_keys.count() != 0 or self.offered_fps.count() != 0 or self.rtcp_out_len != 0) return error.Busy;
    }
    pub fn attachRoutingLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, binding: *routing.WebrtcBinding) routing.Error!void {
        try domain.requireWebrtcBindingLocked(scope, binding, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        lockSpin(&self.rtcp_out_mutex);
        defer self.rtcp_out_mutex.unlock();
        if (self.retired_routing_egress != null or self.routing_egress != null or self.legacy_joining or self.physical_pending != 0 or self.physical_rows.count() != 0 or self.physical_ufrags.count() != 0 or self.physical_groups.count() != 0 or self.routing_domain != null or self.routing_binding != null or self.thread != null or self.runtime.view != null or self.transport.endpoints.count() != 0 or self.transport.by_ufrag.count() != 0 or self.transport.by_addr.count() != 0 or self.transport.by_ssrc.count() != 0 or self.transport.group_keys.count() != 0 or self.offered_fps.count() != 0 or self.rtcp_out_len != 0) return error.Busy;
        self.routing_domain = domain;
        self.routing_binding = binding;
    }
    pub fn requireRoutingTerminal(self: *MediaPlane) routing.Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        lockSpin(&self.rtcp_out_mutex);
        defer self.rtcp_out_mutex.unlock();
        if (self.routing_inbound != null or self.worker_id != null or self.legacy_joining or self.thread != null or self.runtime.view != null or self.physical_pending != 0 or self.rtcp_out_len != 0 or self.retired_routing_egress != null) return error.Busy;
        if (self.routing_egress) |queue| {
            lockSpin(&queue.mutex);
            defer queue.mutex.unlock();
            if (queue.len != 0 or queue.inflight != null or queue.pump_id != null or queue.poisoned) return error.Busy;
        }
    }
    pub fn latchRoutingTerminal(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, binding: *routing.WebrtcBinding) void {
        domain.requireTerminalLocked(scope) catch @panic("terminal routing source is not closed");
        domain.requireWebrtcBindingLocked(scope, binding, self) catch @panic("unissued terminal source binding");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.thread == null and self.runtime.view == null);
        // Domain has already refused every active operation/candidate and
        // checked actual worker join/View detach for BOTH bound source owners.
        // Its irreversible closed admission now prevents new queue producers.
        if (self.routing_egress) |queue| {
            lockSpin(&queue.mutex);
            defer queue.mutex.unlock();
            std.debug.assert(queue.len == 0 and queue.inflight == null and queue.pump_id == null and !queue.poisoned and self.retired_routing_egress == null);
            self.retired_routing_egress = queue;
            self.routing_egress = null;
        }
        self.routing_closed = true;
    }

    /// Counter-free AFTER the genuine irreversible Domain terminal cut. The
    /// actual source queue was detached by latchRoutingTerminal, never by a
    /// caller quiescence bit, exhausted ordinary issuer or epoch reset.
    /// All original allocator callbacks execute after terminal exclusion ends.
    pub fn finishRoutingTerminalCleanup(self: *MediaPlane, domain: *routing.Domain) !void {
        const Take = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            fn run(scope: *routing.Locked, ctx: @This()) !?*RoutingEgressQueue {
                try ctx.domain.requireTerminalLocked(scope);
                try ctx.domain.requireWebrtcBindingLocked(scope, ctx.owner.routing_binding orelse return error.NotRoutingBound, ctx.owner);
                lockSpin(&ctx.owner.mutex);
                defer ctx.owner.mutex.unlock();
                if (!ctx.owner.routing_closed or ctx.owner.legacy_joining or ctx.owner.thread != null or ctx.owner.worker_id != null or ctx.owner.runtime.view != null or ctx.owner.physical_pending != 0 or ctx.owner.routing_egress != null) return error.Busy;
                const queue = ctx.owner.retired_routing_egress orelse return null;
                lockSpin(&queue.mutex);
                defer queue.mutex.unlock();
                if (queue.len != 0 or queue.inflight != null or queue.pump_id != null or queue.poisoned) return error.Busy;
                ctx.owner.retired_routing_egress = null;
                return queue;
            }
        };
        const queue = (try domain.withTerminalLocked(Take{ .owner = self, .domain = domain }, Take.run)) orelse return;
        std.crypto.secureZero(u8, queue.payloads);
        self.allocator.free(queue.payloads);
        self.allocator.free(queue.rows);
        self.allocator.destroy(queue);
    }
    pub fn requireRoutingReleasable(self: *MediaPlane) routing.Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        lockSpin(&self.rtcp_out_mutex);
        defer self.rtcp_out_mutex.unlock();
        if (self.routing_inbound != null or self.routing_egress != null or self.retired_routing_egress != null or self.physical_pending != 0 or self.physical_rows.count() != 0 or self.physical_ufrags.count() != 0 or self.physical_groups.count() != 0 or self.thread != null or self.runtime.view != null or self.transport.endpoints.count() != 0 or self.transport.by_ufrag.count() != 0 or self.transport.by_addr.count() != 0 or self.transport.by_ssrc.count() != 0 or self.transport.group_keys.count() != 0 or self.offered_fps.count() != 0 or self.rtcp_out_len != 0) return error.Busy;
        for (self.srtp_hub.peers) |peer| if (peer.active) return error.Busy;
        for (self.srtp_hub.owners) |owner| if (owner.active) return error.Busy;
    }
    pub fn detachRoutingLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, binding: *routing.WebrtcBinding) void {
        domain.requireWebrtcBindingLocked(scope, binding, self) catch @panic("unissued WebRTC routing release");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.routing_domain == domain and self.routing_binding == binding);
        self.routing_domain = null;
        self.routing_binding = null;
    }

    pub fn deinit(self: *MediaPlane) void {
        if (self.routing_binding != null or self.routing_egress != null) @panic("routing owner must quiesce and release before deinit");
        self.runtime.requireDetached() catch @panic("managed worker must join and detach before deinit");
        self.shutdown();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.csprng));
        std.debug.assert(self.physical_pending == 0);
        var physical = self.physical_rows.valueIterator();
        while (physical.next()) |row| {
            row.endpoint.rtx.deinit();
            row.physical_cache.deinit();
            row.wipe();
        }
        self.physical_rows.deinit(self.allocator);
        self.physical_ufrags.deinit(self.allocator);
        var groups = self.physical_groups.valueIterator();
        while (groups.next()) |group| std.crypto.secureZero(u8, &group.key);
        self.physical_groups.deinit(self.allocator);
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

        return self.routing_binding == null and self.transport.endpoints.count() == 0 and
            self.transport.by_ufrag.count() == 0 and
            self.transport.by_addr.count() == 0 and
            self.transport.by_ssrc.count() == 0 and
            self.transport.group_keys.count() == 0 and
            self.offered_fps.count() == 0 and
            self.rtcp_out_len == 0;
    }

    /// Prepare physical ICE/fingerprint/profile custody outside Domain. Current
    /// mode is captured, not guessed from failed export. Actual activation waits
    /// for the physical pump/index/crypto integration and its strict DTO joins.
    pub fn prepareOffer(self: *MediaPlane, domain: *routing.Domain, offers: *routing.PreparedOffers, channel: []const u8, profile: media_rooms.CallProfile, kind_bits: u8, expected_fp: ?[peer_verify.digest_len]u8) !*PreparedWebrtcOffer {
        if (channel.len == 0 or channel.len > 128 or kind_bits == 0 or kind_bits & ~@as(u8, 7) != 0 or profile.codec_count == 0 or profile.codec_count > media_rooms.max_profile_codecs) return error.InvalidProfile;
        const preview = offers.preview();
        var proposed: ?routing.EndpointObservation = null;
        for (preview.endpoints[0..preview.count]) |row| if (row.reference.endpoint.leg == .webrtc) {
            proposed = row;
            break;
        };
        const identity = proposed orelse return error.EndpointUnavailable;
        const key = routing.EndpointKey{ .call = identity.reference.endpoint.call, .client = identity.reference.offering_client, .leg = .webrtc };
        lockSpin(&self.mutex);
        if (self.routing_closed or self.routing_domain != domain or self.routing_binding == null) {
            self.mutex.unlock();
            return error.NotRoutingBound;
        }
        if (self.physical_revision == std.math.maxInt(u64)) {
            self.mutex.unlock();
            return error.SequenceExhausted;
        }
        if (identity.mode == .dtls_required and (expected_fp == null or (!self.dtls_enabled and !self.dtls13_enabled) or (self.dtls == null and self.dtls13 == null))) {
            self.mutex.unlock();
            return error.DtlsUnavailable;
        }
        var old = self.physical_rows.get(key);
        defer if (old) |*row| row.wipe();
        const old_digest = if (old) |row| rtcDigest(row) else @as(?[32]u8, null);
        var old_group = self.physical_groups.get(key.call);
        defer if (old_group) |*row| std.crypto.secureZero(u8, &row.key);
        const next_group = identity.mode == .legacy_group;
        const prior_group = if (old) |row| row.identity.mode == .legacy_group else false;
        var group = old_group;
        defer if (group) |*row| std.crypto.secureZero(u8, &row.key);
        if ((prior_group and old_group == null) or (old_group != null and old_group.?.count == 0)) {
            self.mutex.unlock();
            return error.InvalidSnapshot;
        }
        if (next_group and group == null) group = .{ .key = @splat(0), .count = 0 };
        if (next_group and !prior_group) group.?.count = std.math.add(u32, group.?.count, 1) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        if (prior_group and !next_group) {
            if (group == null or group.?.count == 0) {
                self.mutex.unlock();
                return error.InvalidSnapshot;
            }
            group.?.count -= 1;
            if (group.?.count == 0) {
                std.crypto.secureZero(u8, &group.?.key);
                group = null;
            }
        }
        const rows_state = rtcMapState(self.physical_rows);
        const ufrags_state = rtcMapState(self.physical_ufrags);
        const groups_state = rtcMapState(self.physical_groups);
        const rows_required = std.math.add(u32, self.physical_rows.count(), if (old == null) 1 else 0) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        const ufrags_required = std.math.add(u32, self.physical_ufrags.count(), 1) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        const groups_required = std.math.add(u32, self.physical_groups.count(), if (group != null and old_group == null) 1 else 0) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        const grow_rows = rows_required - self.physical_rows.count() > self.physical_rows.available;
        const grow_ufrags = self.physical_ufrags.available == 0;
        const grow_groups = groups_required - self.physical_groups.count() > self.physical_groups.available;
        const revision = self.physical_revision;
        const dtls_mode = self.dtls_enabled;
        const dtls13_mode = self.dtls13_enabled;
        self.physical_pending = std.math.add(usize, self.physical_pending, 1) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        self.mutex.unlock();
        errdefer self.finishPhysicalPlan();
        const plan = try self.allocator.create(WebrtcOfferPlan);
        plan.* = .{ .owner = self, .domain = domain, .revision = revision, .key = key, .old = old, .old_digest = old_digest, .old_group = old_group, .group = group, .rows_state = rows_state, .ufrags_state = ufrags_state, .groups_state = groups_state, .dtls_enabled = dtls_mode, .dtls13_enabled = dtls13_mode, .next = .{ .identity = identity, .profile = profile, .kind_bits = kind_bits, .expected_fp = expected_fp, .physical_cache = rtp_nack.PerSsrcRetransmitBuffer.init(self.allocator, media_transport.rtx_capacity, sfu_srtp.max_owners), .endpoint = .{ .ufrag = @splat(0), .pwd = @splat(0), .rtx = rtp_nack.RetransmitBuffer.init(self.allocator, media_transport.rtx_capacity) } } };
        errdefer {
            if (plan.rows) |*map| map.deinit(self.allocator);
            if (plan.ufrags) |*map| map.deinit(self.allocator);
            if (plan.groups) |*map| map.deinit(self.allocator);
            plan.wipe();
            self.allocator.destroy(plan);
        }
        plan.channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(plan.channel);
        var entropy: [media_transport.ufrag_len + media_transport.pwd_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        try osEntropy(&entropy);
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (plan.next.endpoint.ufrag, 0..) |_, n| plan.next.endpoint.ufrag[n] = alphabet[entropy[n] & 63];
        for (plan.next.endpoint.pwd, 0..) |_, n| plan.next.endpoint.pwd[n] = alphabet[entropy[media_transport.ufrag_len + n] & 63];
        if (next_group and old_group == null) try osEntropy(&plan.group.?.key);
        if (grow_rows) {
            plan.rows = .empty;
            try plan.rows.?.ensureTotalCapacity(self.allocator, rows_required);
        }
        if (grow_ufrags) {
            plan.ufrags = .empty;
            try plan.ufrags.?.ensureTotalCapacity(self.allocator, ufrags_required);
        }
        if (grow_groups) {
            plan.groups = .empty;
            try plan.groups.?.ensureTotalCapacity(self.allocator, groups_required);
        }
        return @ptrCast(plan);
    }
    /// Exact physical retirement. The old retransmission graph stays owned by
    /// this source until joined void publication transfers it into the plan.
    pub fn prepareDeparture(self: *MediaPlane, domain: *routing.Domain, departure: *routing.PreparedDeparture) !*PreparedWebrtcDeparture {
        const key = departure.ownerKey(.webrtc);
        lockSpin(&self.mutex);
        if (self.routing_domain != domain or self.routing_binding == null or self.routing_closed != departure.isTerminal()) {
            self.mutex.unlock();
            return error.NotRoutingBound;
        }
        var old = self.physical_rows.get(key);
        defer if (old) |*row| row.wipe();
        if (old != null and !self.routing_closed and self.physical_revision == std.math.maxInt(u64)) {
            self.mutex.unlock();
            return error.SequenceExhausted;
        }
        if (!std.meta.eql(if (old) |row| @as(?routing.EndpointObservation, row.identity) else null, departure.expectedOffer(.webrtc))) {
            self.mutex.unlock();
            return error.StaleCandidate;
        }
        const old_digest = if (old) |row| rtcDigest(row) else @as(?[32]u8, null);
        var old_group = self.physical_groups.get(key.call);
        defer if (old_group) |*group| std.crypto.secureZero(u8, &group.key);
        var group = old_group;
        defer if (group) |*row| std.crypto.secureZero(u8, &row.key);
        if (old) |row| {
            if (!std.meta.eql(self.physical_ufrags.get(row.endpoint.ufrag), @as(?routing.EndpointKey, key))) {
                self.mutex.unlock();
                return error.StaleCandidate;
            }
            if (row.identity.mode == .legacy_group) {
                if (group == null or group.?.count == 0) {
                    self.mutex.unlock();
                    return error.InvalidSnapshot;
                }
                group.?.count -= 1;
                if (group.?.count == 0) {
                    std.crypto.secureZero(u8, &group.?.key);
                    group = null;
                }
            }
        }
        const revision = self.physical_revision;
        const terminal = self.routing_closed;
        self.physical_pending = std.math.add(usize, self.physical_pending, 1) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        self.mutex.unlock();
        errdefer self.finishPhysicalPlan();
        const plan = try self.allocator.create(WebrtcDeparturePlan);
        plan.* = .{ .owner = self, .domain = domain, .key = key, .old = old, .old_digest = old_digest, .old_group = old_group, .group = group, .revision = revision, .terminal = terminal, .batch_part = departure.isBatchPart() };
        return @ptrCast(plan);
    }

    pub fn prepareClientDeparture(self: *MediaPlane, domain: *routing.Domain, departure: *routing.PreparedClientDeparture) !*PreparedWebrtcClientDeparture {
        lockSpin(&self.mutex);
        if (self.routing_domain != domain or self.routing_binding == null or self.routing_closed != departure.isTerminal()) {
            self.mutex.unlock();
            return error.NotRoutingBound;
        }
        const revision = self.physical_revision;
        self.physical_pending = std.math.add(usize, self.physical_pending, 1) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        self.mutex.unlock();
        errdefer self.finishPhysicalPlan();
        const plan = try self.allocator.create(WebrtcClientDeparturePlan);
        errdefer self.allocator.destroy(plan);
        const parts = try self.allocator.alloc(*PreparedWebrtcDeparture, departure.count());
        errdefer self.allocator.free(parts);
        var initialized: usize = 0;
        errdefer for (parts[0..initialized]) |part| part.deinit();
        for (parts, 0..) |*part, n| {
            part.* = try self.prepareDeparture(domain, departure.part(n));
            initialized += 1;
        }
        plan.* = .{ .owner = self, .domain = domain, .departure = departure, .parts = parts, .revision = revision };
        return @ptrCast(plan);
    }
    /// Captures signaling host provenance even when only a native leg is offered.
    /// It creates no RTC credentials or readiness authority. The frozen fallback
    /// comes from the caller's independently retained configured policy.
    pub fn prepareAdvertisementHost(self: *MediaPlane, domain: *routing.Domain, offers: *routing.PreparedOffers, channel: []const u8, fallback_host: []const u8) !*PreparedAdvertisementHost {
        try validateAdvertisementHost(fallback_host);
        const offered = offers.preview();
        var native: ?routing.EndpointObservation = null;
        for (offered.endpoints[0..offered.count]) |endpoint| if (endpoint.reference.endpoint.leg == .native) {
            native = endpoint;
        };
        const actual_native = native orelse return error.InvalidProfile;
        lockSpin(&self.mutex);
        if (self.routing_domain != domain or self.routing_binding == null or self.routing_closed or self.stop_flag.load(.acquire)) {
            self.mutex.unlock();
            return error.NotRoutingBound;
        }
        self.physical_pending = std.math.add(usize, self.physical_pending, 1) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        self.mutex.unlock();
        errdefer self.finishPhysicalPlan();
        const plan = try self.allocator.create(AdvertisementHostPlan);
        errdefer self.allocator.destroy(plan);
        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_domain != domain or self.routing_closed or self.stop_flag.load(.acquire)) return error.StaleCandidate;
        const preview = try selectAdvertisementHost(self.discovered, fallback_host);
        var fallback: HostAdvertisement = .{};
        @memcpy(fallback.host[0..fallback_host.len], fallback_host);
        fallback.host_len = @intCast(fallback_host.len);
        const socket: ?HostSocketObservation = if (self.socket) |*held| .{ .fd = held.fd, .snapshot = try held.capture() } else null;
        // Discovery derives from a real prepared socket, never a copied host scalar.
        if (self.discovered != null and socket == null) return error.NotPrepared;
        plan.* = .{ .owner = self, .domain = domain, .channel = owned_channel, .native = actual_native, .revision = self.physical_revision, .preview = preview, .fallback = fallback, .discovered = self.discovered, .stun_server = self.stun_server, .socket = socket, .port = self.port };
        return @ptrCast(plan);
    }

    fn finishPhysicalPlan(self: *MediaPlane) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.physical_pending != 0);
        self.physical_pending -= 1;
    }

    /// Install the cross-leg sink (call before `start`, or while stopped).
    pub fn setCrossLegSink(self: *MediaPlane, sink: media_bridge.RtpCrossSink) void {
        self.cross = sink;
    }

    /// Bind the media socket on `bind_be`:`port` (port 0 = ephemeral) and spawn
    /// the pump thread. No-op if already started.
    pub fn start(self: *MediaPlane, bind_be: u32, port: u16) !void {
        if (self.routing_closed) return error.Closing;
        if (self.runtime.view != null) return error.SharedGateOwned;
        if (self.socket != null) return;
        try self.prepareBoundResources(bind_be, port);
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch |err| {
            self.stopDtls();
            self.socket.?.deinit();
            self.socket = null;
            self.port = 0;
            return err;
        };
    }

    fn prepareBoundResources(self: *MediaPlane, bind_be: u32, port: u16) !void {
        if (self.physical_pending != 0 or self.routing_binding != null) return error.Busy;
        if (self.socket != null or self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        if (self.max_frame_bytes == 0 or self.max_frame_bytes > max_datagram or self.max_upload_bytes == 0) return error.InvalidConfig;
        var sock = try MediaSocket.bind(bind_be, port);
        errdefer sock.deinit();
        const actual_port = try sock.localPort();
        // STUN discovery is explicit cold preparation, never inherited restore.
        if (self.stun_server) |srv| {
            sock.setRecvTimeoutMs(1500);
            var txid: [12]u8 = undefined;
            self.csprng.random().bytes(&txid);
            self.discovered = sock.queryReflexive(srv, txid, self.allocator);
        }
        sock.setRecvTimeoutMs(250);
        _ = try sock.capture();
        self.dtls_requested = self.dtls_enabled;
        self.dtls13_requested = self.dtls13_enabled;
        // Preserve the existing explicit optional cold DTLS policy. Failure to
        // spawn a required worker never changes configuration to disabled.
        if (self.dtls_enabled) self.startDtls() catch |err| {
            self.dtls_enabled = false;
            std.log.warn("onyx-server: DTLS-SRTP terminator disabled ({s})", .{@errorName(err)});
        };
        self.socket = sock;
        self.port = actual_port;
    }

    pub fn prepareColdResources(self: *MediaPlane, io: std.Io, bind_be: u32, port: u16) !void {
        if (self.routing_closed) return error.Closing;
        try self.runtime.pause.bindIo(io);
        try self.prepareBoundResources(bind_be, port);
    }
    pub fn prepareInheritedResources(self: *MediaPlane, io: std.Io) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        const socket = if (self.socket) |*sock| sock else return error.NotPrepared;
        _ = try socket.capture();
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *MediaPlane, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .media_plane, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *MediaPlane, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        if (self.routing_closed) return error.Closing;
        try self.runtime.validatePreparation(control, view, slot, .media_plane, 0, self, dormant_spawn_options);
        if (self.legacy_joining or self.thread != null) return error.AlreadyStarted;
        const socket = if (self.socket) |*sock| sock else return error.NotPrepared;
        _ = try socket.capture();
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .media_plane, 0, MediaPlane, self, pumpLoop, dormant_spawn_options);
    }
    /// Signals this owner only. Runtime Control owns all actual joins.
    /// Move the actual legacy handle once, then join outside the metadata gate.
    /// Resources remain owned; terminal release cannot race the joining latch.
    /// Configured View ownership is exclusively joined by its private Control.
    /// Start only the actual already-prepared owner resource. A temporary
    /// source latch pins it through spawn; failure retains the socket/engine
    /// for the caller's complete source-owned unwind. No Control/View join.
    pub fn startPreparedLegacyWorker(self: *MediaPlane) !void {
        lockSpin(&self.mutex);
        if (self.routing_closed or self.runtime.view != null or self.legacy_joining or self.thread != null or self.worker_id != null or self.physical_pending != 0) {
            self.mutex.unlock();
            return error.Busy;
        }
        if (self.socket == null or (self.routing_binding != null and self.routing_egress == null)) {
            self.mutex.unlock();
            return error.NotPrepared;
        }
        self.legacy_joining = true;
        self.stop_flag.store(false, .release);
        self.mutex.unlock();
        const thread = std.Thread.spawn(dormant_spawn_options, pumpLoop, .{self}) catch |err| {
            lockSpin(&self.mutex);
            self.stop_flag.store(true, .release);
            self.legacy_joining = false;
            self.mutex.unlock();
            return err;
        };
        lockSpin(&self.mutex);
        std.debug.assert(self.legacy_joining and self.thread == null);
        self.thread = thread;
        self.legacy_joining = false;
        self.mutex.unlock();
    }

    pub fn joinLegacyAfterStop(self: *MediaPlane) !void {
        lockSpin(&self.mutex);
        if (self.runtime.view != null or self.legacy_joining or !self.stop_flag.load(.acquire) or self.worker_id == std.Thread.getCurrentId()) {
            self.mutex.unlock();
            return error.Busy;
        }
        const thread = self.thread orelse {
            self.mutex.unlock();
            return;
        };
        self.thread = null;
        self.legacy_joining = true;
        self.mutex.unlock();
        thread.join();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.legacy_joining and self.thread == null and self.worker_id == null);
        self.legacy_joining = false;
    }

    pub fn requestStopAndWake(self: *MediaPlane) void {
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
    }
    pub fn detachAfterJoined(self: *MediaPlane) !void {
        try self.runtime.detachAfterJoined();
    }
    pub fn requireParked(self: *MediaPlane) !void {
        try self.runtime.requireParked();
    }
    pub fn requireActivated(self: *MediaPlane) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime.requireActivated();
    }
    pub fn requestPause(self: *MediaPlane, epoch: u64) !runtime_pause.Token {
        return self.runtime.pause.request(epoch);
    }
    pub fn awaitPaused(self: *MediaPlane, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *MediaPlane, token: runtime_pause.Token) !void {
        try self.runtime.pause.resumePaused(token);
    }
    pub fn capturePaused(self: *MediaPlane, token: runtime_pause.Token) !Snapshot {
        if (self.thread == null and self.runtime.view == null) return error.NotRunning;
        try self.runtime.pause.requirePaused(token);
        return self.captureIdle(.paused);
    }
    pub fn captureUnstarted(self: *MediaPlane) !Snapshot {
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return self.captureIdle(.unstarted);
    }
    // Caller freezes all signaling/bridge producers across this complete cut.
    // Pump-owned crypto is read only after actual source arrival or before spawn.
    fn captureIdle(self: *MediaPlane, execution: Execution) !Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_binding != null) return error.RoutingContinuityUnsupported;
        lockSpin(&self.fp_mutex);
        defer self.fp_mutex.unlock();
        lockSpin(&self.rtcp_out_mutex);
        defer self.rtcp_out_mutex.unlock();
        if (self.transport.endpoints.count() != 0 or self.transport.by_ufrag.count() != 0 or self.transport.by_addr.count() != 0 or self.transport.by_ssrc.count() != 0 or self.transport.group_keys.count() != 0 or self.offered_fps.count() != 0 or self.rtcp_out_len != 0) return error.ActiveMediaContinuityUnsupported;
        for (self.srtp_hub.peers) |peer| if (peer.active) return error.ActiveMediaContinuityUnsupported;
        for (self.srtp_hub.owners) |owner| if (owner.active) return error.ActiveMediaContinuityUnsupported;
        const socket = if (self.socket) |*sock| sock else return error.NotPrepared;
        var carry: Snapshot = .{ .socket = try socket.capture(), .csprng = RngState.capture(&self.csprng), .stun_server = self.stun_server, .discovered = self.discovered, .max_frame_bytes = self.max_frame_bytes, .max_upload_bytes = self.max_upload_bytes, .dtls_enabled = self.dtls_enabled, .dtls_requested = self.dtls_requested, .dtls13_enabled = self.dtls13_enabled, .dtls13_requested = self.dtls13_requested, .dtls12 = null, .dtls13 = null, .srtp_clock = self.srtp_hub.clock, .cross_configured = self.cross != null, .execution = execution };
        errdefer carry.deinit();
        if (self.dtls) |term| carry.dtls12 = try IdleDtls.capture(term);
        if (self.dtls13) |term| carry.dtls13 = try IdleDtls.capture(term);
        try carry.validate();
        return carry;
    }

    /// Owns only the received UDP reference; restoring idle identity does not
    /// mint certificates/cookies or consume OS entropy/STUN/network traffic.
    pub fn initInherited(allocator: std.mem.Allocator, fd: std.posix.fd_t, carry: *const Snapshot, cross: ?media_bridge.RtpCrossSink) !MediaPlane {
        carry.validate() catch |err| {
            _ = std.posix.system.close(fd);
            return err;
        };
        var socket = try MediaSocket.initInherited(fd, &carry.socket);
        errdefer socket.deinit();
        if (carry.cross_configured != (cross != null)) return error.ConfigMismatch;
        var owner: MediaPlane = .{ .allocator = allocator, .transport = MediaTransport.init(allocator), .csprng = carry.csprng.restore(), .srtp_hub = sfu_srtp.SfuSrtp.init(allocator) };
        errdefer owner.deinit();
        owner.max_frame_bytes = carry.max_frame_bytes;
        owner.max_upload_bytes = carry.max_upload_bytes;
        owner.stun_server = carry.stun_server;
        owner.discovered = carry.discovered;
        owner.dtls_enabled = carry.dtls_enabled;
        owner.dtls_requested = carry.dtls_requested;
        owner.dtls13_enabled = carry.dtls13_enabled;
        owner.dtls13_requested = carry.dtls13_requested;
        owner.cross = cross;
        owner.srtp_hub.clock = carry.srtp_clock;
        if (carry.dtls12) |*idle| {
            const sessions = try allocator.alloc(dtls_server.Session, dtls_server.default_max_sessions);
            errdefer allocator.free(sessions);
            const term = try allocator.create(dtls_server.Terminator);
            idle.restore(term, sessions);
            owner.dtls_sessions = sessions;
            owner.dtls = term;
            const fp = term.fingerprintLine(&owner.dtls_fingerprint_buf) catch unreachable;
            owner.dtls_fingerprint_len = fp.len;
        }
        if (carry.dtls13) |*idle| {
            const sessions = try allocator.alloc(dtls13_server.Session, dtls13_server.default_max_sessions);
            errdefer allocator.free(sessions);
            const term = try allocator.create(dtls13_server.Terminator);
            idle.restore(term, sessions);
            owner.dtls13_sessions = sessions;
            owner.dtls13 = term;
        }
        owner.socket = socket;
        owner.port = carry.socket.port;
        return owner;
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
        lockSpin(&self.mutex);
        const held = self.legacy_joining or self.physical_pending != 0 or self.routing_binding != null;
        self.mutex.unlock();
        if (held) @panic("WebRTC resource retirement requires actual candidate disposal");
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
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

    pub fn inspectRoutingInboundLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64) !routing.EndpointStamp {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const actual = if (self.routing_inbound) |*value| value else return error.InvalidIngress;
        if (self.worker_id != std.Thread.getCurrentId() or actual.ordinal != ordinal or self.routing_domain != domain) return error.NotRoutingPump;
        if (!std.mem.eql(u8, &actual.digest, &routingPayloadDigest(actual.bytes[0..actual.len]))) return error.InvalidIngress;
        const row = self.physical_rows.get(actual.key) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity.stamp, actual.source)) return error.StaleCandidate;
        if (actual.kind == .stun and !(stun.verifyMessageIntegrity(actual.bytes[0..actual.len], row.endpoint.pwdSlice()) catch false)) return error.InvalidIngress;
        return actual.source;
    }

    fn installRoutingInboundLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, expected: routing.EndpointObservation, from: TransportAddress, bytes: []const u8, kind: RoutingInboundKind) !u64 {
        _ = try domain.requireCurrentLocked(scope, expected.stamp);
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        if (self.routing_closed or self.routing_inbound != null or self.stop_flag.load(.acquire) or self.worker_id != std.Thread.getCurrentId()) {
            self.mutex.unlock();
            return error.NotRoutingPump;
        }
        if (self.next_routing_inbound == 0 or self.next_routing_inbound == std.math.maxInt(u64)) {
            self.mutex.unlock();
            return error.SequenceExhausted;
        }
        const queue = self.routing_egress orelse {
            self.mutex.unlock();
            return error.QueueUnavailable;
        };
        lockSpin(&queue.mutex);
        const accepting = queue.pump_id == std.Thread.getCurrentId() and queue.fence == null and !queue.poisoned;
        queue.mutex.unlock();
        if (!accepting) {
            self.mutex.unlock();
            return error.ProducerFenced;
        }
        const key = routing.EndpointKey{ .call = expected.stamp.endpoint.call, .client = expected.stamp.offering_client, .leg = .webrtc };
        const row = self.physical_rows.get(key) orelse {
            self.mutex.unlock();
            return error.EndpointUnavailable;
        };
        if (!std.meta.eql(row.identity, expected)) {
            self.mutex.unlock();
            return error.StaleCandidate;
        }
        const ordinal = self.next_routing_inbound;
        if (bytes.len > media_socket.max_datagram) {
            self.mutex.unlock();
            return error.InvalidIngress;
        }
        self.routing_inbound = .{ .ordinal = ordinal, .source = expected.stamp, .key = key, .from = from, .bytes = undefined, .len = bytes.len, .digest = routingPayloadDigest(bytes), .kind = kind };
        @memcpy(self.routing_inbound.?.bytes[0..bytes.len], bytes);
        self.mutex.unlock();
        domain.holdWebrtcInboundLocked(scope, self, ordinal) catch |err| {
            lockSpin(&self.mutex);
            std.crypto.secureZero(u8, &self.routing_inbound.?.bytes);
            self.routing_inbound = null;
            self.mutex.unlock();
            return err;
        };
        lockSpin(&self.mutex);
        self.next_routing_inbound += 1;
        self.mutex.unlock();
        return ordinal;
    }

    fn finishRoutingInbound(self: *MediaPlane, domain: *routing.Domain, ordinal: u64) !void {
        domain.completeWebrtcInbound(self, ordinal) catch |err| {
            self.stop_flag.store(true, .release);
            return err; // retain actual pin+original buffer custody, fail closed
        };
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.routing_inbound.?.ordinal == ordinal and self.worker_id == std.Thread.getCurrentId());
        std.crypto.secureZero(u8, &self.routing_inbound.?.bytes);
        std.crypto.secureZero(u8, &self.routing_inbound.?.canonical);
        self.routing_inbound = null;
    }

    pub fn validateRoutingStunBindingLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64) !bool {
        _ = try self.inspectRoutingInboundLocked(domain, scope, ordinal);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const actual = &self.routing_inbound.?;
        if (actual.kind != .stun or !validRoutingRemote(actual.from)) return error.InvalidIngress;
        const row = self.physical_rows.get(actual.key).?;
        if (row.endpoint.remote) |remote| {
            if (!routingAddressEqual(remote, actual.from)) return error.AddressDenied;
            return false; // authenticated repeated request never migrates a binding
        }
        if (self.physical_revision == std.math.maxInt(u64)) return error.SequenceExhausted;
        var rows = self.physical_rows.iterator();
        while (rows.next()) |entry| if (!std.meta.eql(entry.key_ptr.*, actual.key)) {
            if (entry.value_ptr.endpoint.remote) |remote| if (routingAddressEqual(remote, actual.from)) return error.AddressOwned;
        };
        return true;
    }
    pub fn commitRoutingStunBindingLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64, next: routing.EndpointObservation) void {
        domain.requireWebrtcBindingLocked(scope, self.routing_binding.?, self) catch @panic("foreign ICE publication");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const actual = &self.routing_inbound.?;
        std.debug.assert(actual.ordinal == ordinal and actual.kind == .stun);
        const row = self.physical_rows.getPtr(actual.key).?;
        std.debug.assert(row.endpoint.remote == null);
        row.endpoint.remote = actual.from;
        row.identity = next;
        actual.source = next.stamp;
        self.physical_revision += 1;
    }

    fn handleRoutingStun(self: *MediaPlane, socket: *MediaSocket, from: TransportAddress, bytes: []const u8) !void {
        if (!validRoutingRemote(from)) return error.AddressDenied;
        var msg = try stun.decode(self.allocator, bytes);
        defer msg.deinit(self.allocator);
        if (msg.typ != .binding_request) return error.InvalidIngress;
        var username: ?[]const u8 = null;
        var integrity = false;
        for (msg.attributes) |attribute| switch (attribute) {
            .username => |value| {
                if (username != null or integrity) return error.InvalidIngress;
                username = value;
            },
            .message_integrity => {
                if (integrity) return error.InvalidIngress;
                integrity = true;
            },
            .fingerprint => {
                if (!(try stun.verifyFingerprint(bytes))) return error.InvalidIngress;
            },
            else => {
                if (integrity) return error.InvalidIngress;
            },
        };
        if (!integrity) return error.InvalidIngress;
        const user = username orelse return error.InvalidIngress;
        const colon = std.mem.indexOfScalar(u8, user, ':') orelse user.len;
        if (colon != media_transport.ufrag_len) return error.InvalidIngress;
        var ufrag: [media_transport.ufrag_len]u8 = undefined;
        @memcpy(&ufrag, user[0..colon]);
        const domain = self.routing_domain orelse return error.NotRoutingBound;
        const Capture = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            ufrag: [media_transport.ufrag_len]u8,
            fn run(scope: *routing.Locked, ctx: @This()) !RoutingStunCapture {
                try ctx.domain.requireWebrtcBindingLocked(scope, ctx.owner.routing_binding.?, ctx.owner);
                lockSpin(&ctx.owner.mutex);
                defer ctx.owner.mutex.unlock();
                const key = ctx.owner.physical_ufrags.get(ctx.ufrag) orelse return error.EndpointUnavailable;
                const row = ctx.owner.physical_rows.get(key) orelse return error.EndpointUnavailable;
                _ = try ctx.domain.requireCurrentLocked(scope, row.identity.stamp);
                return .{ .key = key, .identity = row.identity, .ufrag = row.endpoint.ufrag, .pwd = row.endpoint.pwd, .revision = ctx.owner.physical_revision };
            }
        };
        var captured = try domain.withLocked(Capture{ .owner = self, .domain = domain, .ufrag = ufrag }, Capture.run);
        defer captured.wipe();
        if (!(try stun.verifyMessageIntegrity(bytes, &captured.pwd))) return error.InvalidIngress;
        const mapped: stun.Address = switch (from.ip_len) {
            4 => .{ .ipv4 = .{ .ip = from.ip[0..4].*, .port = from.port } },
            16 => .{ .ipv6 = .{ .ip = from.ip, .port = from.port } },
            else => return error.AddressDenied,
        };
        const response = try stun.buildBindingSuccessResponse(self.allocator, msg.transaction_id, .{ .xor_mapped_address = mapped, .integrity_key = &captured.pwd, .fingerprint = true });
        defer {
            std.crypto.secureZero(u8, response);
            self.allocator.free(response);
        }
        const Admit = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            captured: RoutingStunCapture,
            from: TransportAddress,
            bytes: []const u8,
            fn run(scope: *routing.Locked, ctx: @This()) !u64 {
                lockSpin(&ctx.owner.mutex);
                const current = ctx.owner.physical_rows.get(ctx.captured.key);
                const valid = current != null and ctx.owner.physical_revision == ctx.captured.revision and std.meta.eql(current.?.identity, ctx.captured.identity) and std.mem.eql(u8, &current.?.endpoint.pwd, &ctx.captured.pwd) and std.mem.eql(u8, &current.?.endpoint.ufrag, &ctx.captured.ufrag);
                ctx.owner.mutex.unlock();
                if (!valid) return error.StaleCandidate;
                const ordinal = try ctx.owner.installRoutingInboundLocked(ctx.domain, scope, ctx.captured.identity, ctx.from, ctx.bytes, .stun);
                ctx.domain.publishWebrtcBindingLocked(scope, ctx.owner, ordinal) catch |err| {
                    // Failed final admission still owns an actual attempt. Its
                    // reserved finish executes after leaving this Domain cut.
                    return err;
                };
                return ordinal;
            }
        };
        const ordinal = domain.withLocked(Admit{ .owner = self, .domain = domain, .captured = captured, .from = from, .bytes = bytes }, Admit.run) catch |err| {
            if (self.routing_inbound) |active| try self.finishRoutingInbound(domain, active.ordinal);
            return err;
        };
        _ = socket.trySendTo(from, response); // actual I/O outside all source gates
        try self.finishRoutingInbound(domain, ordinal);
    }

    fn handleRoutingDtls(self: *MediaPlane, socket: *MediaSocket, from: TransportAddress, bytes: []const u8) !void {
        const domain = self.routing_domain orelse return error.NotRoutingBound;
        const Admit = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            from: TransportAddress,
            bytes: []const u8,
            const Result = struct { ordinal: u64, row: PhysicalRtcEndpoint, association: usize };
            fn run(scope: *routing.Locked, ctx: @This()) !Result {
                lockSpin(&ctx.owner.mutex);
                var found: ?PhysicalRtcEndpoint = null;
                var rows = ctx.owner.physical_rows.valueIterator();
                while (rows.next()) |row| if (row.endpoint.remote) |remote| if (routingAddressEqual(remote, ctx.from)) {
                    found = row.*;
                    break;
                };
                const row = found orelse {
                    ctx.owner.mutex.unlock();
                    return error.EndpointUnavailable;
                };
                if (row.identity.mode != .dtls_required or row.expected_fp == null) {
                    ctx.owner.mutex.unlock();
                    return error.ProfileDenied;
                }
                var association: ?usize = null;
                for (ctx.owner.routing_crypto, 0..) |entry, i| if (entry.live and std.meta.eql(entry.endpoint, row.identity.stamp.endpoint)) {
                    association = i;
                    break;
                };
                if (association == null) for (ctx.owner.routing_crypto, 0..) |entry, i| if (!entry.live) {
                    association = i;
                    break;
                };
                ctx.owner.mutex.unlock();
                const index = association orelse return error.CryptoCapacity;
                const ordinal = try ctx.owner.installRoutingInboundLocked(ctx.domain, scope, row.identity, ctx.from, ctx.bytes, .dtls);
                return .{ .ordinal = ordinal, .row = row, .association = index };
            }
        };
        const actual = try domain.withLocked(Admit{ .owner = self, .domain = domain, .from = from, .bytes = bytes }, Admit.run);
        // The canonical operation pin retains this endpoint/session lineage;
        // neither publication nor retirement can reset it while crypto runs.
        var out: [2048]u8 = undefined;
        const now = platform.monotonicMillis();
        if (self.dtls) |term| term.bindExpectedFingerprint(from, actual.row.expected_fp.?);
        if (self.dtls13) |term| term.bindExpectedFingerprint(from, actual.row.expected_fp.?);
        if (self.dtls13) |term| {
            if (term.owns(from) or dtls13_server.offersDtls13(bytes)) {
                if (term.handleDatagram(from, bytes, now, &out)) |response| _ = socket.trySendTo(from, response);
                if (term.srtpProfile(from) == @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) if (term.exportedKeys(from)) |keys| {
                    if (self.srtp_hub.noteEstablished(from, keys)) self.routing_crypto[actual.association] = .{ .live = true, .endpoint = actual.row.identity.stamp.endpoint, .binding_revision = actual.row.identity.stamp.binding_revision, .addr = from };
                };
                try self.finishRoutingInbound(domain, actual.ordinal);
                return;
            }
        }
        if (self.dtls) |term| {
            if (term.handleDatagram(from, bytes, now, &out)) |response| _ = socket.trySendTo(from, response);
            if (term.srtpProfile(from) == @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) if (term.exportedKeys(from)) |keys| {
                if (self.srtp_hub.noteEstablished(from, keys)) self.routing_crypto[actual.association] = .{ .live = true, .endpoint = actual.row.identity.stamp.endpoint, .binding_revision = actual.row.identity.stamp.binding_revision, .addr = from };
            };
        }
        try self.finishRoutingInbound(domain, actual.ordinal);
    }

    fn retireRoutingCryptoLocked(self: *MediaPlane, endpoint: routing.EndpointId, remote: ?TransportAddress) void {
        if (remote) |addr| {
            if (self.dtls) |term| term.retirePeer(addr);
            if (self.dtls13) |term| term.retirePeer(addr);
            self.srtp_hub.evict(addr);
        }
        for (&self.physical_ssrcs) |*entry| if (entry.live and std.meta.eql(entry.endpoint, endpoint)) {
            entry.* = .{};
        };
        for (&self.routing_crypto) |*entry| if (entry.live and std.meta.eql(entry.endpoint, endpoint)) {
            if (self.dtls) |term| term.retirePeer(entry.addr);
            if (self.dtls13) |term| term.retirePeer(entry.addr);
            self.srtp_hub.evict(entry.addr);
            entry.* = .{};
        };
    }

    fn routingMediaKeys(self: *MediaPlane, row: PhysicalRtcEndpoint, addr: TransportAddress) ?sfu_srtp.ExportedKeys {
        if (row.identity.mode != .dtls_required or row.expected_fp == null) return null;
        var associated = false;
        for (self.routing_crypto) |entry| if (entry.live and std.meta.eql(entry.endpoint, row.identity.stamp.endpoint) and entry.binding_revision == row.identity.stamp.binding_revision and routingAddressEqual(entry.addr, addr)) {
            associated = true;
            break;
        };
        if (!associated) return null;
        if (self.dtls) |term| term.bindExpectedFingerprint(addr, row.expected_fp.?);
        if (self.dtls13) |term| term.bindExpectedFingerprint(addr, row.expected_fp.?);
        if (self.dtls13) |term| if (term.owns(addr)) {
            if (term.srtpProfile(addr) != @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) return null;
            const material = term.exportedKeys(addr) orelse return null;
            return if (self.srtp_hub.peerMaterialMatches(addr, material)) material else null;
        };
        if (self.dtls) |term| if (term.owns(addr)) {
            if (term.srtpProfile(addr) != @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) return null;
            const material = term.exportedKeys(addr) orelse return null;
            return if (self.srtp_hub.peerMaterialMatches(addr, material)) material else null;
        };
        return null;
    }

    fn handleRoutingMedia(self: *MediaPlane, from: TransportAddress, bytes: []const u8) !routing.FanoutResult {
        if (bytes.len < rtp_profile.header_len or bytes[0] & 0xc0 != 0x80) return error.InvalidIngress;
        const kind: routing.PacketKind = if (isRtcp(bytes[1])) .rtcp else .rtp;
        const domain = self.routing_domain orelse return error.NotRoutingBound;
        const Admit = struct {
            owner: *MediaPlane,
            domain: *routing.Domain,
            from: TransportAddress,
            bytes: []const u8,
            kind: routing.PacketKind,
            const Result = struct { ordinal: u64, row: PhysicalRtcEndpoint, ssrc_slot: ?usize };
            fn run(scope: *routing.Locked, ctx: @This()) !Result {
                lockSpin(&ctx.owner.mutex);
                var found: ?PhysicalRtcEndpoint = null;
                var rows = ctx.owner.physical_rows.valueIterator();
                while (rows.next()) |row| if (row.endpoint.remote) |remote| if (routingAddressEqual(remote, ctx.from)) {
                    found = row.*;
                    break;
                };
                const row = found orelse {
                    ctx.owner.mutex.unlock();
                    return error.EndpointUnavailable;
                };
                var slot: ?usize = null;
                if (ctx.kind == .rtp) {
                    const header = rtp_profile.decodeHeader(ctx.bytes) catch |err| {
                        ctx.owner.mutex.unlock();
                        return err;
                    };
                    const tag: sdp.CodecTag = switch (header.header.payload_type) {
                        111 => .cadencevox,
                        96 => .cadencevis,
                        else => {
                            ctx.owner.mutex.unlock();
                            return error.ProfileDenied;
                        },
                    };
                    if (!profileHasCodec(row.profile, tag) or (tag == .cadencevox and row.kind_bits & 1 == 0) or (tag == .cadencevis and row.kind_bits & 6 == 0)) {
                        ctx.owner.mutex.unlock();
                        return error.ProfileDenied;
                    }
                    ctx.domain.requireWebrtcSsrcAvailableLocked(scope, header.header.ssrc) catch |err| {
                        ctx.owner.mutex.unlock();
                        return err;
                    };
                    for (ctx.owner.physical_ssrcs, 0..) |entry, i| if (entry.live and entry.ssrc == header.header.ssrc) {
                        if (!std.meta.eql(entry.endpoint, row.identity.stamp.endpoint)) {
                            ctx.owner.mutex.unlock();
                            return error.ForeignSsrc;
                        }
                        slot = i;
                        break;
                    };
                    if (slot == null) for (ctx.owner.physical_ssrcs, 0..) |entry, i| if (!entry.live) {
                        slot = i;
                        break;
                    };
                    if (slot == null) {
                        ctx.owner.mutex.unlock();
                        return error.SsrcCapacity;
                    }
                }
                ctx.owner.mutex.unlock();
                const ordinal = try ctx.owner.installRoutingInboundLocked(ctx.domain, scope, row.identity, ctx.from, ctx.bytes, .media);
                return .{ .ordinal = ordinal, .row = row, .ssrc_slot = slot };
            }
        };
        const actual = try domain.withLocked(Admit{ .owner = self, .domain = domain, .from = from, .bytes = bytes, .kind = kind }, Admit.run);
        const result = self.routeHeldMedia(domain, actual.ordinal, actual.row, actual.ssrc_slot, kind) catch |err| {
            try self.finishRoutingInbound(domain, actual.ordinal);
            return err;
        };
        try self.finishRoutingInbound(domain, actual.ordinal);
        return result;
    }

    fn routeHeldMedia(self: *MediaPlane, domain: *routing.Domain, ordinal: u64, row: PhysicalRtcEndpoint, ssrc_slot: ?usize, kind: routing.PacketKind) !routing.FanoutResult {
        const active = &self.routing_inbound.?;
        std.debug.assert(active.ordinal == ordinal and active.kind == .media and self.worker_id == std.Thread.getCurrentId());
        const original = active.bytes[0..active.len];
        var canonical: []const u8 = undefined;
        var crypto: ?sfu_srtp.PreparedIngress = null;
        defer if (crypto) |prepared| self.srtp_hub.abortIngress(prepared.receipt) catch @panic("lost actual tentative ingress");
        if (row.identity.mode == .dtls_required) {
            _ = self.routingMediaKeys(row, active.from) orelse return error.DtlsUnavailable;
            crypto = switch (kind) {
                .rtp => self.srtp_hub.prepareIngressRtp(active.from, original, &active.canonical),
                .rtcp => self.srtp_hub.prepareIngressRtcp(active.from, original, &active.canonical),
            } orelse return error.AuthenticationDenied;
            canonical = crypto.?.plain;
        } else {
            @memcpy(active.canonical[0..original.len], original);
            canonical = active.canonical[0..original.len];
        }
        var header: ?rtp_profile.DecodedHeader = null;
        if (kind == .rtcp) {
            var sequences: [64]u16 = undefined;
            _ = try parseRoutingFeedback(canonical, &sequences);
        } else {
            _ = try validatePhysicalRtpPacket(row, canonical);
            header = try rtp_profile.decodeHeader(canonical);
        }
        const key = routing.EndpointKey{ .call = row.identity.stamp.endpoint.call, .client = row.identity.stamp.offering_client, .leg = .webrtc };
        var cache: ?*rtp_nack.PreparedPerSsrcSent = null;
        defer if (cache) |candidate| candidate.deinit();
        if (kind == .rtp) {
            const actual_header = header.?;
            // Root's actual inbound pin retains this source row while NEW
            // per-SSRC storage is prepared outside every exclusion gate.
            cache = try self.physical_rows.getPtr(key).?.physical_cache.prepareSent(actual_header.header.ssrc, actual_header.header.sequence, canonical);
        }
        lockSpin(&self.mutex);
        var locked = true;
        defer if (locked) self.mutex.unlock();
        if (cache) |candidate| try candidate.validate();
        if (crypto) |prepared| try self.srtp_hub.validateIngress(prepared.receipt);
        // Every fallible cache/decode/current-key check has finished. No
        // allocator, crypto transform, syscall or callback runs in this cut.
        if (crypto) |prepared| {
            self.srtp_hub.commitIngress(prepared.receipt);
            crypto = null;
        }
        if (cache) |candidate| {
            const actual_header = header.?;
            candidate.commitRetainingMetadata();
            self.physical_ssrcs[ssrc_slot.?] = .{ .live = true, .ssrc = actual_header.header.ssrc, .key = key, .endpoint = row.identity.stamp.endpoint };
            self.physical_rows.getPtr(key).?.endpoint.ssrc = actual_header.header.ssrc;
        }
        self.mutex.unlock();
        locked = false;
        lockSpin(&self.mutex);
        active.canonical_len = canonical.len;
        active.canonical_kind = kind;
        active.canonical_digest = routingPayloadDigest(canonical);
        active.authenticated = true; // issued only after actual source processing
        self.mutex.unlock();
        return domain.publishWebrtcMedia(self, ordinal);
    }

    pub fn inspectRoutingCanonicalLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64) !AuthenticatedWebrtcFrame {
        _ = try self.inspectRoutingInboundLocked(domain, scope, ordinal);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const active = &self.routing_inbound.?;
        if (active.kind != .media or !active.authenticated or active.canonical_len == 0 or !std.mem.eql(u8, &active.canonical_digest, &routingPayloadDigest(active.canonical[0..active.canonical_len]))) return error.InvalidIngress;
        const row = self.physical_rows.get(active.key).?;
        return .{ .source = active.source, .stream_id = row.identity.stream_id, .profile = row.profile, .kind_bits = row.kind_bits, .bytes = active.canonical[0..active.canonical_len], .kind = active.canonical_kind };
    }

    pub fn enqueueWebrtcCanonicalLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64, target: routing.EndpointStamp) !RoutingAccepted {
        const source = try domain.resolveWebrtcCanonicalLocked(scope, self, ordinal);
        const destination = try domain.requireCurrentLocked(scope, target);
        if (!std.meta.eql(source.source.endpoint.call, target.endpoint.call) or source.source.offering_client.eql(target.offering_client)) return error.RouteDenied;
        if (target.endpoint.leg == .native) {
            if (source.kind != .rtp) return error.FeedbackUnavailable;
            var storage: [media_socket.max_datagram]u8 = undefined;
            var map = media_bridge.defaultPtMap();
            const length = try media_bridge.rtpToNativeDatagram(source.bytes, &map, cadence_frame.MEDIA_BAND_FLOOR, source.stream_id, false, &storage);
            const bytes = storage[0..length];
            try domain.requireNativeTargetLocked(scope, target, bytes);
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            return self.enqueueWireBytesLocked(source.source, target, .rtp, source.stream_id, bytes, .native_frame);
        }
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const row = self.physical_rows.get(.{ .call = target.endpoint.call, .client = target.offering_client, .leg = .webrtc }) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, destination)) return error.StaleCandidate;
        try domain.requireBridgeNegotiationLocked(scope, row.identity.reference, row.profile, row.kind_bits);
        if (source.kind == .rtp) try requirePhysicalRtpPacketPolicy(row, source.bytes);
        return self.enqueueCanonicalBytesLocked(source.source, target, source.kind, source.stream_id, source.bytes);
    }

    fn enqueueCanonicalBytesLocked(self: *MediaPlane, source: routing.EndpointStamp, target: routing.EndpointStamp, kind: routing.PacketKind, stream_id: u32, bytes: []const u8) !RoutingAccepted {
        return self.enqueueWireBytesLocked(source, target, kind, stream_id, bytes, .canonical);
    }
    fn enqueueWireBytesLocked(self: *MediaPlane, source: routing.EndpointStamp, target: routing.EndpointStamp, kind: routing.PacketKind, stream_id: u32, bytes: []const u8, wire: RoutingWireKind) !RoutingAccepted {
        const queue = self.routing_egress orelse return error.QueueUnavailable;
        lockSpin(&queue.mutex);
        defer queue.mutex.unlock();
        if (self.routing_closed or queue.fence != null) return error.ProducerFenced;
        if (queue.len == queue.rows.len) return error.QueueFull;
        if (queue.next_ordinal == 0 or queue.next_ordinal == std.math.maxInt(u64)) return error.SequenceExhausted;
        if (bytes.len > queue.payload_limit) return error.PayloadTooLarge;
        const index = (queue.head + queue.len) % queue.rows.len;
        @memcpy(queue.payloads[index * queue.payload_limit ..][0..bytes.len], bytes);
        const ordinal = queue.next_ordinal;
        queue.rows[index] = .{ .wire = wire, .source = source, .target = target, .kind = kind, .source_stream = stream_id, .ordinal = ordinal, .len = bytes.len, .digest = routingPayloadDigest(bytes) };
        queue.len += 1;
        queue.next_ordinal += 1;
        return .{ .ordinal = ordinal };
    }

    pub fn requireUnclaimedRoutingSsrcLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, stream: u32) routing.Error!void {
        try domain.requireWebrtcBindingLocked(scope, self.routing_binding orelse return error.InvalidIdentity, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.physical_ssrcs) |entry| if (entry.live and entry.ssrc == stream) return error.PublisherCollision;
    }

    /// Traverse and validate EVERY compound member before selecting feedback.
    /// Padding can occur only on the final member; supported feedback bodies
    /// must match their complete canonical shape, not just the common header.
    pub fn parseRoutingFeedback(bytes: []const u8, sequences: []u16) !rtcp_translate.Feedback {
        if (bytes.len < 4 or bytes.len % 4 != 0) return error.InvalidIngress;
        var compound = @import("../proto/rtcp_compound.zig").parse(bytes);
        while (try compound.next()) |_| {}
        var selected: ?rtcp_translate.Feedback = null;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const length = (@as(usize, std.mem.readInt(u16, bytes[offset + 2 ..][0..2], .big)) + 1) * 4;
            const packet = bytes[offset..][0..length]; // full iterator checked bounds
            var effective = length;
            if (packet[0] & 0x20 != 0) {
                if (offset + length != bytes.len) return error.InvalidIngress;
                const padding = packet[length - 1];
                if (padding == 0 or padding > length - 4) return error.InvalidIngress;
                effective -= padding;
            }
            const body = packet[0..effective];
            const fmt = packet[0] & 0x1f;
            switch (packet[1]) {
                205, 206 => {
                    if (effective < 12 or effective % 4 != 0) return error.InvalidIngress;
                    if (packet[1] == 206 and fmt == 1 and effective != 12) return error.InvalidIngress;
                    if (packet[1] == 206 and fmt == 4) {
                        if (effective < 20 or (effective - 12) % 8 != 0 or (effective - 12) / 8 > 16 or std.mem.readInt(u32, body[8..12], .big) != 0) return error.InvalidIngress;
                        var entry: usize = 12;
                        while (entry < effective) : (entry += 8) for (body[entry + 5 ..][0..3]) |reserved| if (reserved != 0) return error.InvalidIngress;
                    }
                    if (packet[1] == 205 and fmt == 1 and (effective < 16 or (effective - 12) % 4 != 0)) return error.InvalidIngress;
                    var scratch: [64]u16 = undefined;
                    const feedback = try rtcp_translate.parse(body, &scratch);
                    if (selected == null) switch (feedback) {
                        .nack => |nack| {
                            if (nack.seqs.len > sequences.len) return error.InvalidIngress;
                            @memcpy(sequences[0..nack.seqs.len], nack.seqs);
                            selected = .{ .nack = .{ .media_ssrc = nack.media_ssrc, .seqs = sequences[0..nack.seqs.len] } };
                        },
                        .keyframe_request => |request| selected = .{ .keyframe_request = request },
                        .other => {},
                    };
                },
                204 => if (effective < 12) return error.InvalidIngress,
                207 => {
                    if (effective < 8) return error.InvalidIngress;
                    var blocks: @import("../proto/rtcp_xr.zig").BlockIterator = .{ .bytes = body[8..] };
                    while (try blocks.next()) |_| {}
                },
                else => {}, // compound iterator validates SR/RR/SDES/BYE
            }
            offset += length;
        }
        return selected orelse .other;
    }

    pub fn routingPublisherForFeedbackLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64, ssrc: u32) !routing.EndpointStamp {
        const requester = try domain.resolveWebrtcCanonicalLocked(scope, self, ordinal);
        if (requester.kind != .rtcp) return error.InvalidIngress;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.physical_ssrcs) |entry| if (entry.live and entry.ssrc == ssrc) {
            const row = self.physical_rows.get(entry.key) orelse return error.RouteDenied;
            _ = try domain.requireCurrentLocked(scope, row.identity.stamp);
            if (!std.meta.eql(entry.endpoint, row.identity.stamp.endpoint) or !std.meta.eql(row.identity.stamp.endpoint.call, requester.source.endpoint.call) or row.identity.stamp.offering_client.eql(requester.source.offering_client)) return error.RouteDenied;
            try domain.requireBridgeNegotiationLocked(scope, row.identity.reference, row.profile, row.kind_bits);
            return row.identity.stamp;
        };
        return error.RouteDenied;
    }

    pub fn enqueueWebrtcFeedbackLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64, target: routing.EndpointStamp) !RoutingAccepted {
        const source = try domain.resolveWebrtcCanonicalLocked(scope, self, ordinal);
        if (source.kind != .rtcp) return error.InvalidIngress;
        const destination = try domain.requireCurrentLocked(scope, target);
        if (!std.meta.eql(target.endpoint.call, source.source.endpoint.call) or target.offering_client.eql(source.source.offering_client)) return error.RouteDenied;
        var seqs: [64]u16 = undefined;
        const request = try parseRoutingFeedback(source.bytes, &seqs);
        if (target.endpoint.leg == .native) {
            var storage: [7 + 64 * 4]u8 = undefined;
            const feedback = switch (request) {
                .keyframe_request => try native_feedback.encodeKeyframeRequest(destination.stream_id, &storage),
                .nack => |nack| nack: {
                    var seqs32: [64]u32 = undefined;
                    for (nack.seqs, 0..) |seq, i| seqs32[i] = seq;
                    break :nack try native_feedback.encodeNack(destination.stream_id, seqs32[0..nack.seqs.len], &storage);
                },
                .other => return error.FeedbackUnavailable,
            };
            try domain.requireNativeFeedbackTargetLocked(scope, target, feedback);
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            return self.enqueueWireBytesLocked(source.source, target, .rtcp, source.stream_id, feedback, .native_feedback);
        }
        const publisher_ssrc: u32 = switch (request) {
            .keyframe_request => |value| value.media_ssrc,
            .nack => |value| value.media_ssrc,
            .other => return error.FeedbackUnavailable,
        };
        const actual = try self.routingPublisherForFeedbackLocked(domain, scope, ordinal, publisher_ssrc);
        if (!std.meta.eql(actual, target)) return error.RouteDenied;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.enqueueCanonicalBytesLocked(source.source, target, .rtcp, source.stream_id, source.bytes);
    }

    pub fn enqueueRoutingNackLocked(self: *MediaPlane, domain: *routing.Domain, scope: *const routing.Locked, ordinal: u64) !routing.FanoutResult {
        const requester = try domain.resolveWebrtcCanonicalLocked(scope, self, ordinal);
        if (requester.kind != .rtcp) return error.InvalidIngress;
        var seqs: [64]u16 = undefined;
        const feedback = try parseRoutingFeedback(requester.bytes, &seqs);
        const nack = switch (feedback) {
            .nack => |value| value,
            else => return error.InvalidIngress,
        };
        const publisher = try self.routingPublisherForFeedbackLocked(domain, scope, ordinal, nack.media_ssrc);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const row = self.physical_rows.get(.{ .call = publisher.endpoint.call, .client = publisher.offering_client, .leg = .webrtc }).?;
        var result = routing.FanoutResult{ .recognized = true };
        for (nack.seqs) |seq| {
            const packet = row.physical_cache.lookup(nack.media_ssrc, seq) orelse {
                result.refused += 1;
                continue;
            };
            const target = self.physical_rows.get(.{ .call = requester.source.endpoint.call, .client = requester.source.offering_client, .leg = .webrtc }) orelse return error.EndpointUnavailable;
            _ = try domain.requireCurrentLocked(scope, target.identity.stamp);
            try domain.requireBridgeNegotiationLocked(scope, target.identity.reference, target.profile, target.kind_bits);
            requirePhysicalRtpPacketPolicy(target, packet) catch |err| {
                result.refused += 1;
                result.last_refusal = err;
                continue;
            };
            _ = self.enqueueCanonicalBytesLocked(row.identity.stamp, requester.source, .rtp, row.identity.stream_id, packet) catch |err| {
                result.refused += 1;
                result.last_refusal = err;
                continue;
            };
            result.accepted += 1;
        }
        return result;
    }

    fn noteRoutingIngressError(self: *MediaPlane, err: anyerror) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.routing_ingress_refused +|= 1;
        self.routing_last_ingress_error = err; // local diagnostic; never wire ordinal
    }
    fn noteRoutingIngressComplete(self: *MediaPlane) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.routing_ingress_completed +|= 1;
    }

    fn pumpLoop(self: *MediaPlane) void {
        lockSpin(&self.mutex);
        self.worker_id = std.Thread.getCurrentId();
        self.mutex.unlock();
        defer {
            lockSpin(&self.mutex);
            self.worker_id = null;
            self.mutex.unlock();
        }
        const physically_routed = self.routing_domain != null;
        if (physically_routed) self.enterRoutingPump() catch return;
        defer if (physically_routed) self.leaveRoutingPump();
        self.runtime.markEntered();
        defer self.runtime.markExited();
        var buf: [media_socket.max_datagram]u8 = undefined;
        while (!self.stop_flag.load(.acquire)) {
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            const sock = &(self.socket orelse return);
            if (physically_routed) {
                while (self.drainOneRoutingEgress(sock) catch break) |_| {}
            } else self.drainQueuedRtcp(sock);
            const got = sock.recvFrom(&buf) orelse {
                if (!physically_routed) self.drainQueuedRtcp(sock);
                continue;
            }; // timeout/idle
            if (physically_routed) {
                if (got.data.len == 0 or got.data.len > self.max_frame_bytes) continue;
                if (MediaSocket.isStun(got.data[0])) {
                    self.handleRoutingStun(sock, got.from, got.data) catch |err| {
                        self.noteRoutingIngressError(err);
                        continue;
                    };
                    self.noteRoutingIngressComplete();
                } else if (got.data[0] >= 20 and got.data[0] <= 63) {
                    self.handleRoutingDtls(sock, got.from, got.data) catch |err| {
                        self.noteRoutingIngressError(err);
                        continue;
                    };
                    self.noteRoutingIngressComplete();
                } else {
                    _ = self.handleRoutingMedia(got.from, got.data) catch |err| {
                        self.noteRoutingIngressError(err);
                        continue;
                    };
                    self.noteRoutingIngressComplete();
                }
                continue;
            }
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
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.sendCanonicalRtcpToLocked(sock, dest, canonical);
    }

    fn sendCanonicalRtcpToLocked(self: *MediaPlane, sock: *MediaSocket, dest: TransportAddress, canonical: []const u8) void {
        var enc_buf: [media_socket.max_datagram + sfu_srtp.rtcp_overhead]u8 = undefined;
        switch (self.dtlsStateLocked(dest)) {
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
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.dtlsStateLocked(addr);
    }

    /// Registry lock precedes fingerprint lock. A denied export never destroys
    /// accepted replay authority: reapproval with the same key must retain it.
    fn dtlsStateLocked(self: *MediaPlane, addr: TransportAddress) DtlsState {
        const expected = self.bindDtlsFingerprintForLocked(addr);
        if (self.dtls13) |term| {
            if (term.owns(addr)) {
                const profile = term.srtpProfile(addr) orelse return .unavailable;
                if (profile != @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) return .unavailable;
                const keys = term.exportedKeys(addr) orelse return .unavailable;
                return if (self.srtp_hub.noteEstablished(addr, keys)) .ready else .unavailable;
            }
        }
        if (self.dtls) |term| {
            if (term.owns(addr)) {
                const profile = term.srtpProfile(addr) orelse return .unavailable;
                if (profile != @import("../proto/dtls_srtp.zig").profile_aes128_cm_sha1_80) return .unavailable;
                const keys = term.exportedKeys(addr) orelse return .unavailable;
                return if (self.srtp_hub.noteEstablished(addr, keys)) .ready else .unavailable;
            }
            if (term.verify_bindings.exhausted or term.verify_bindings.expectedFor(addr) != null) return .unavailable;
        }
        if (self.dtls13) |term| if (term.verify_bindings.exhausted or term.verify_bindings.expectedFor(addr) != null) return .unavailable;
        return if (expected) .unavailable else .not_dtls;
    }

    /// Actual routing selector exposed ONLY to in-module crypto fixture callers.
    /// Production cannot manufacture a routing verdict through this test seam.
    pub fn testOnlyDtlsDisposition(self: *MediaPlane, addr: TransportAddress) DtlsState {
        if (!@import("builtin").is_test) @compileError("test-only media dispatch fixture");
        return self.dtlsState(addr);
    }

    /// Fixture invokes the actual relay/feedback paths; it cannot set a
    /// production verdict. The supplied material only constructs/authenticates
    /// packet bytes; the independently owned terminator still decides routing.
    /// A genuine mutual-DTLS test driver lends its already-established actual
    /// terminator for this lexical worker lifetime. The real clientFinished
    /// datagram must install the association through handleRoutingDtls; neither
    /// the supplied material nor this fixture can set a verification verdict.
    pub fn testOnlyPhysicalCacheOom(term: *dtls_server.Terminator, peer: *MediaSocket, expected_fp: [peer_verify.digest_len]u8, client_finished: []const u8, material: sfu_srtp.ExportedKeys) !void {
        return testOnlyPhysicalCacheOomIndex(term, peer, expected_fp, client_finished, material, 0);
    }
    pub fn testOnlyPhysicalCacheOomIndex(term: *dtls_server.Terminator, peer: *MediaSocket, expected_fp: [peer_verify.digest_len]u8, client_finished: []const u8, material: sfu_srtp.ExportedKeys, fault_index: usize) !void {
        if (!@import("builtin").is_test) @compileError("test-only authentic physical SRTP cache OOM fixture");
        const address = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, try peer.localPort());
        const authentic = term.exportedKeys(address) orelse return error.TestUnexpectedResult;
        try testing.expectEqualDeep(material, authentic);
        try testing.expect(term.peerVerified(address));
        var fail = testing.FailingAllocator.init(testing.allocator, .{});
        var fixture = try PhysicalIceFixture.init(&fail);
        fixture.owner.dtls_enabled = true;
        fixture.owner.dtls = term;
        defer {
            // The borrowed terminator remains alive until actual thread join.
            fixture.owner.requestStopAndWake();
            fixture.owner.joinLegacyAfterStop() catch unreachable;
            fixture.owner.dtls = null;
            fixture.deinit();
        }
        const channel = "#cache-oom-proof";
        var source: PhysicalOfferedPeerTest = undefined;
        {
            const offers = try fixture.domain.prepareOffers(channel, .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .webrtc, .mode = .dtls_required }});
            defer offers.deinit();
            const candidate = try fixture.owner.prepareOffer(fixture.domain, offers, channel, webrtcCandidateTestProfile(), 1, expected_fp);
            defer candidate.deinit();
            const bridge = try fixture.domain.preparePhysicalBridge(offers, channel, null, candidate);
            defer bridge.deinit();
            const preview = candidate.preview();
            source = .{ .key = .{ .call = preview.identity.stamp.endpoint.call, .client = preview.identity.stamp.offering_client, .leg = .webrtc }, .creds = .{ .ufrag = preview.ufrag.*, .pwd = preview.pwd.* } };
            const Publish = struct {
                fixture: *PhysicalIceFixture,
                offers: *routing.PreparedOffers,
                candidate: *PreparedWebrtcOffer,
                bridge: *routing.PreparedPhysicalBridge,
                fn run(scope: *routing.Locked, ctx: @This()) !void {
                    try ctx.offers.validateLocked(ctx.fixture.domain, scope);
                    try ctx.candidate.validateLocked(ctx.fixture.domain, scope, ctx.offers);
                    try ctx.bridge.validateLocked(ctx.fixture.domain, scope, ctx.offers, null, ctx.candidate);
                    ctx.candidate.commitLocked(ctx.fixture.domain, scope);
                    ctx.bridge.commitLocked(ctx.fixture.domain, scope);
                    ctx.offers.commitLocked(ctx.fixture.domain, scope);
                }
            };
            try fixture.domain.withLocked(Publish{ .fixture = &fixture, .offers = offers, .candidate = candidate, .bridge = bridge }, Publish.run);
        }
        defer std.crypto.secureZero(u8, &source.creds.pwd);
        var target = try offerPhysicalGroupBridgeTest(&fixture, channel, .{ .shard = 0, .slot = 1, .gen = 0 });
        defer std.crypto.secureZero(u8, &target.creds.pwd);
        var receiver = try MediaSocket.bind(loopback_be, 0);
        defer receiver.deinit();
        receiver.setRecvTimeoutMs(900);
        peer.setRecvTimeoutMs(900);
        const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.owner.port);
        try fixture.owner.startPreparedLegacyWorker();
        try bindPhysicalGroupPeerTest(peer, destination, &source.creds, 0xa1);
        try bindPhysicalGroupPeerTest(&receiver, destination, &target.creds, 0xa2);
        peer.sendTo(destination, client_finished);
        var response_buf: [2048]u8 = undefined;
        _ = peer.recvFrom(&response_buf) orelse return error.TestUnexpectedResult;
        const first_pause = try fixture.paused(1);
        var first_paused = true;
        defer if (first_paused) fixture.owner.resumePaused(first_pause) catch unreachable;
        try testing.expect(fixture.owner.srtp_hub.peerMaterialMatches(address, material));
        const clock_before = fixture.owner.srtp_hub.clock;
        var clear_storage: [128]u8 = undefined;
        const canonical = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 59, .timestamp = 480, .ssrc = 10001 }, .payload = "actual-mutual-SRTP-cache-retry" }, &clear_storage);
        var encrypted_storage: [256]u8 = undefined;
        const keys = @import("../proto/srtp.zig").deriveSessionKeys(material.clientMaster(), material.clientSalt());
        const encrypted = try @import("../proto/srtp.zig").protect(keys, 0, canonical, &encrypted_storage);
        fail.fail_index = fail.alloc_index + fault_index; // exact NEW cache allocation boundary
        peer.sendTo(destination, encrypted);
        try fixture.owner.resumePaused(first_pause);
        first_paused = false;
        try testing.expect(receiver.recvFrom(&response_buf) == null);
        const second_pause = try fixture.paused(2);
        var second_paused = true;
        defer if (second_paused) fixture.owner.resumePaused(second_pause) catch unreachable;
        fail.fail_index = std.math.maxInt(usize);
        // Independent grounding precedes the intended replay/custody oracle.
        try testing.expect(fail.has_induced_failure);
        try testing.expectEqual(error.OutOfMemory, fixture.owner.routing_last_ingress_error.?);
        try testing.expect(fixture.owner.routing_inbound == null);
        try testing.expectEqual(@as(usize, 0), fixture.owner.routing_egress.?.len);
        const clock_after_failed_cache = fixture.owner.srtp_hub.clock;
        try fixture.owner.resumePaused(second_pause);
        second_paused = false;
        peer.sendTo(destination, encrypted); // identical authentic packet, no reset
        const retried = receiver.recvFrom(&response_buf) orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, canonical, retried.data);
        try testing.expectEqual(clock_before, clock_after_failed_cache);
        peer.sendTo(destination, encrypted);
        try testing.expect(receiver.recvFrom(&response_buf) == null); // accepted retry now consumes replay once
    }
    pub fn testOnlyPacketPath(self: *MediaPlane, addr: TransportAddress, material: sfu_srtp.ExportedKeys, rtcp: bool, sequence: u16, expect_delivery: bool) !void {
        if (!@import("builtin").is_test) @compileError("test-only actual media packet fixture");
        var socket = try MediaSocket.bind(loopback_be, 0);
        defer socket.deinit();
        var receiver = try MediaSocket.bind(loopback_be, 0);
        defer receiver.deinit();
        receiver.setRecvTimeoutMs(1000);
        const dest = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, try receiver.localPort());
        var prng = std.Random.DefaultPrng.init(0xACE);
        _ = try self.transport.allocate("#packet-proof", "source", prng.random());
        defer self.transport.remove("#packet-proof", "source");
        _ = try self.transport.allocate("#packet-proof", "recipient", prng.random());
        defer self.transport.remove("#packet-proof", "recipient");
        try testing.expect(self.transport.bindRemote("#packet-proof", "source", addr));
        try testing.expect(self.transport.bindRemote("#packet-proof", "recipient", dest));
        const Probe = struct {
            calls: usize = 0,
            fn rtp(ctx: *anyopaque, _: []const u8, _: []const u8, _: bool) void {
                const p: *@This() = @ptrCast(@alignCast(ctx));
                p.calls += 1;
            }
            fn feedback(ctx: *anyopaque, _: []const u8, _: []const u8) bool {
                const p: *@This() = @ptrCast(@alignCast(ctx));
                p.calls += 1;
                return false;
            }
        };
        var probe: Probe = .{};
        const prior_cross = self.cross;
        self.cross = .{ .ctx = &probe, .on_rtp_frame = Probe.rtp, .on_rtcp_feedback = Probe.feedback };
        defer self.cross = prior_cross;
        var packet: [28]u8 = @splat(0);
        packet[0] = 0x80;
        packet[1] = if (rtcp) 200 else 96;
        std.mem.writeInt(u16, packet[2..4], if (rtcp) 6 else sequence, .big);
        if (rtcp) std.mem.writeInt(u32, packet[4..8], 991, .big) else std.mem.writeInt(u32, packet[8..12], 991, .big);
        const canonical: []const u8 = if (rtcp) &packet else packet[0..16];
        const inbound = srtp.deriveSessionKeys(material.clientMaster(), material.clientSalt());
        var protected: [128]u8 = undefined;
        const wire = if (rtcp) try srtcp.protect(inbound, sequence, canonical, &protected) else try srtp.protect(inbound, 0, canonical, &protected);
        if (rtcp) self.handleRtcp(&socket, addr, wire) else self.relay(&socket, addr, wire, 991, sequence);
        var received: [128]u8 = undefined;
        if (expect_delivery) {
            const got = receiver.recvFrom(&received) orelse return error.TestUnexpectedResult;
            try testing.expectEqualSlices(u8, canonical, got.data);
            try testing.expectEqual(@as(usize, 1), probe.calls);
        } else {
            var polls = [_]posix.pollfd{.{ .fd = receiver.fd, .events = posix.POLL.IN, .revents = 0 }};
            try testing.expect(posix.system.poll(&polls, polls.len, 0) == 0);
            try testing.expectEqual(@as(usize, 0), probe.calls);
            // Also exercise attempted cleartext ingress after the same denial.
            if (rtcp) self.handleRtcp(&socket, addr, canonical) else self.relay(&socket, addr, canonical, 991, sequence);
            try testing.expect(posix.system.poll(&polls, polls.len, 0) == 0);
            try testing.expectEqual(@as(usize, 0), probe.calls);
        }
    }

    pub fn testOnlyEncryptedEgressPaths(self: *MediaPlane, peer: *MediaSocket, material: sfu_srtp.ExportedKeys, sequence: u16, expect_delivery: bool) !void {
        if (!@import("builtin").is_test) @compileError("test-only actual media egress fixture");
        var socket = try MediaSocket.bind(loopback_be, 0);
        defer socket.deinit();
        const addr = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, try peer.localPort());
        const source = try TransportAddress.fromBytes(&.{ 127, 0, 0, 2 }, 9911);
        var prng = std.Random.DefaultPrng.init(0xEC);
        _ = try self.transport.allocate("#egress-proof", "source", prng.random());
        defer self.transport.remove("#egress-proof", "source");
        _ = try self.transport.allocate("#egress-proof", "recipient", prng.random());
        defer self.transport.remove("#egress-proof", "recipient");
        try testing.expect(self.transport.bindRemote("#egress-proof", "source", source));
        try testing.expect(self.transport.bindRemote("#egress-proof", "recipient", addr));
        var rtp: [16]u8 = @splat(0);
        rtp[0] = 0x80;
        rtp[1] = 96;
        std.mem.writeInt(u16, rtp[2..4], sequence, .big);
        std.mem.writeInt(u32, rtp[8..12], 991, .big);
        var report: [28]u8 = @splat(0);
        report[0] = 0x80;
        report[1] = 200;
        std.mem.writeInt(u16, report[2..4], 6, .big);
        std.mem.writeInt(u32, report[4..8], 991, .big);
        const outbound = srtp.deriveSessionKeys(material.serverMaster(), material.serverSalt());
        const Oracle = struct {
            fn receive(client: *MediaSocket, keys: @import("../proto/srtp.zig").SessionKeys, canonical: []const u8, rtcp: bool, delivery: bool) !void {
                if (!delivery) {
                    var polls = [_]posix.pollfd{.{ .fd = client.fd, .events = posix.POLL.IN, .revents = 0 }};
                    try testing.expect(posix.system.poll(&polls, polls.len, 0) == 0);
                    return;
                }
                var wire: [128]u8 = undefined;
                var plain: [128]u8 = undefined;
                const got = client.recvFrom(&wire) orelse return error.TestUnexpectedResult;
                try testing.expect(got.data.len > canonical.len);
                const recovered = if (rtcp) try @import("../proto/srtcp.zig").unprotect(keys, got.data, &plain) else try @import("../proto/srtp.zig").unprotect(keys, 0, got.data, &plain);
                try testing.expectEqualSlices(u8, canonical, recovered);
            }
        };
        peer.setRecvTimeoutMs(1000);
        self.relay(&socket, source, &rtp, 991, sequence);
        try Oracle.receive(peer, outbound, &rtp, false, expect_delivery);
        self.forwardRtcp(&socket, source, &report);
        try Oracle.receive(peer, outbound, &report, true, expect_delivery);
        // A not-yet-forwarded packet in the actual source cache is requested by
        // canonical NACK. A previously emitted nonce must not be reused.
        const nack_sequence = try std.math.add(u16, sequence, 1);
        std.mem.writeInt(u16, rtp[2..4], nack_sequence, .big);
        var ignored: [0]TransportAddress = .{};
        _ = self.transport.forwardFromSource(source, &rtp, 991, nack_sequence, &ignored);
        var fci: [4]u8 = @splat(0);
        std.mem.writeInt(u16, fci[0..2], nack_sequence, .big);
        self.handleNack(&socket, addr, 991, &fci);
        try Oracle.receive(peer, outbound, &rtp, false, expect_delivery);
        if (expect_delivery) {
            self.handleNack(&socket, addr, 991, &fci);
            try Oracle.receive(peer, outbound, &rtp, false, false);
        }
        // Queue through the real off-pump interface, then drain on this sole
        // fixture pump owner; the shared queue lock is dropped before registry.
        const old_socket = self.socket;
        self.socket = socket;
        defer self.socket = old_socket;
        self.sendRtcpTo(addr, &report);
        try testing.expectEqual(@as(usize, 1), self.rtcp_out_len);
        self.drainQueuedRtcp(&socket);
        try Oracle.receive(peer, outbound, &report, true, expect_delivery);
        try testing.expectEqual(@as(usize, 0), self.rtcp_out_len);
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
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        _ = self.bindDtlsFingerprintForLocked(from);
    }

    fn bindDtlsFingerprintForLocked(self: *MediaPlane, from: TransportAddress) bool {
        const key = self.transport.compositeForSource(from) orelse return false;
        lockSpin(&self.fp_mutex);
        const digest = self.offered_fps.get(key);
        self.fp_mutex.unlock();
        if (digest) |d| {
            if (self.dtls13) |term| term.bindExpectedFingerprint(from, d);
            if (self.dtls) |term| term.bindExpectedFingerprint(from, d);
            return true;
        }
        return false;
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
        var cursor = self.transport.beginForwardFromSource(source, canonical, ssrc, seq);
        // Copy the source's channel out under the lock so the cross-leg sink can
        // use it after we unlock (the composite key may be freed).
        if (self.transport.channelForSource(source)) |chan| {
            if (chan.len <= chanbuf.len) {
                @memcpy(chanbuf[0..chan.len], chan);
                chanlen = chan.len;
            }
        }
        var enc_buf: [media_socket.max_datagram + sfu_srtp.rtp_overhead]u8 = undefined;
        if (cursor) |*traversal| {
            while (true) {
                const n = traversal.nextChunk(&targets);
                if (n == 0) break;
                for (targets[0..n]) |dst| {
                    switch (self.dtlsStateLocked(dst)) {
                        .not_dtls => sock.sendTo(dst, canonical),
                        .unavailable => {},
                        .ready => if (self.srtp_hub.protectRtp(dst, canonical, &enc_buf)) |wire| sock.sendTo(dst, wire),
                    }
                }
            }
        }
        self.mutex.unlock();

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
        defer self.mutex.unlock();
        var cursor = self.transport.beginForwardFromSource(source, canonical, 0, null) orelse return;
        while (true) {
            const n = cursor.nextChunk(&targets);
            if (n == 0) break;
            for (targets[0..n]) |dst| self.sendCanonicalRtcpToLocked(sock, dst, canonical);
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
const dtls_messages = @import("../proto/dtls12_messages.zig");
const dtls_record = @import("../proto/dtls12_record.zig");
const dtls_handshake = @import("../proto/dtls_handshake.zig");
const dtls_srtp = @import("../proto/dtls_srtp.zig");
const dtls13_messages = @import("../proto/dtls13_messages.zig");
const dtls_kx = @import("../proto/dtls_keyexchange.zig");
const srtp = @import("../proto/srtp.zig");
const srtcp = @import("../proto/srtcp.zig");

test "MediaPlane: threaded pump answers a STUN check and binds the peer" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    try testing.expect(plane.dtls == null);
    var fp_buf: [128]u8 = undefined;
    try testing.expect(plane.dtlsFingerprint(&fp_buf) == null);
}

test "MediaPlane: DTLS-enabled pump demultiplexes a ClientHello into a HelloVerifyRequest" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true; // dtls13_enabled defaults false
    try plane.start(loopback_be, 0);
    try testing.expect(plane.dtls != null); // 1.2 up
    try testing.expect(plane.dtls13 == null); // 1.3 stays down by default
}

test "DTLS-SRTP GAP-V1 hold-off: dtls13 off still answers a DTLS 1.2 ClientHello" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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

/// Real loopback endpoints authenticate their ICE bindings before one media
/// packet enters the actual pump. The deadline bounds missing datagrams; it is
/// not a sleep used to infer that the worker reached an operation boundary.
fn completeFanoutCausal(rtcp: bool) !void {
    // FD-budget fixture via `getrlimit`; unavailable on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const previous_limit = try posix.getrlimit(.NOFILE);
    if (previous_limit.max < 512) return error.FdBudgetPrecondition;
    var selected_limit = previous_limit;
    selected_limit.cur = @max(previous_limit.cur, 512);
    try posix.setrlimit(.NOFILE, selected_limit);
    defer {
        posix.setrlimit(.NOFILE, previous_limit) catch @panic("media fanout fixture FD limit restore");
        const restored = posix.getrlimit(.NOFILE) catch @panic("media fanout fixture FD limit observation");
        if (!std.meta.eql(previous_limit, restored)) @panic("media fanout fixture FD limit mismatch");
    }
    const observed_limit = try posix.getrlimit(.NOFILE);
    try testing.expectEqualDeep(selected_limit, observed_limit);
    std.debug.print("complete fanout fixture NOFILE old={d}/{d} selected={d}/{d}\n", .{ previous_limit.cur, previous_limit.max, observed_limit.cur, observed_limit.max });
    const receivers = 130;
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    const server_addr = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, plane.port);
    var sender = try MediaSocket.bind(loopback_be, 0);
    defer sender.deinit();
    sender.setRecvTimeoutMs(2000);
    const source_creds = plane.allocate("#complete", "source") orelse return error.TestUnexpectedResult;
    try stunBindPeer(&sender, server_addr, source_creds);
    try testing.expect(plane.isConnected("#complete", "source"));

    var clients: [receivers]MediaSocket = undefined;
    var initialized: usize = 0;
    defer for (clients[0..initialized]) |*client| client.deinit();
    for (&clients, 0..) |*client, i| {
        client.* = try MediaSocket.bind(loopback_be, 0);
        initialized += 1;
        client.setRecvTimeoutMs(2000);
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "peer-{d}", .{i});
        const creds = plane.allocate("#complete", name) orelse return error.TestUnexpectedResult;
        try stunBindPeer(client, server_addr, creds);
        try testing.expect(plane.isConnected("#complete", name));
        client.setRecvTimeoutMs(1);
    }
    // Bound foreign and unbound same-channel endpoints are real exclusion
    // controls, not guessed limits on the eligible endpoint population.
    var foreign = try MediaSocket.bind(loopback_be, 0);
    defer foreign.deinit();
    foreign.setRecvTimeoutMs(2000);
    const foreign_creds = plane.allocate("#foreign", "foreign") orelse return error.TestUnexpectedResult;
    try stunBindPeer(&foreign, server_addr, foreign_creds);
    _ = plane.allocate("#complete", "unbound") orelse return error.TestUnexpectedResult;

    const rtp_packet = [_]u8{ 0x80, 96, 0, 7, 0, 0, 0, 1, 0xFA, 0x70, 0, 1, 0xA5, 0x5A };
    // A complete RFC 3550 sender report (no report blocks), rather than a
    // short packet rejected by the pump's common media framing admission.
    const rtcp_packet = [_]u8{ 0x80, 200, 0, 6, 0xFA, 0x70, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2 };
    const packet: []const u8 = if (rtcp) &rtcp_packet else &rtp_packet;
    sender.sendTo(server_addr, packet);
    var polls: [receivers]posix.pollfd = undefined;
    var received: [receivers]bool = @splat(false);
    for (&polls, &clients) |*pfd, *client| pfd.* = .{ .fd = client.fd, .events = posix.POLL.IN, .revents = 0 };
    const deadline = platform.monotonicMillis() + 2000;
    var count: usize = 0;
    var buf: [2048]u8 = undefined;
    while (count < receivers) {
        const now = platform.monotonicMillis();
        if (now >= deadline) break;
        const ready = posix.system.poll(&polls, polls.len, @intCast(deadline - now));
        switch (posix.errno(ready)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.TestUnexpectedResult,
        }
        if (ready == 0) break;
        for (&polls, &clients, 0..) |*pfd, *client, i| {
            if (pfd.revents & posix.POLL.IN == 0) continue;
            const got = client.recvFrom(&buf) orelse return error.TestUnexpectedResult;
            try testing.expectEqualSlices(u8, packet, got.data);
            try testing.expect(!received[i]);
            received[i] = true;
            count += 1;
            pfd.events = 0;
        }
    }
    // Probe all eligible sockets again: one source packet may produce at most
    // one datagram at each recipient, including across a chunk boundary.
    for (&polls) |*pfd| pfd.events = posix.POLL.IN;
    try testing.expect(posix.system.poll(&polls, polls.len, 0) == 0);
    var excluded = [_]posix.pollfd{
        .{ .fd = sender.fd, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = foreign.fd, .events = posix.POLL.IN, .revents = 0 },
    };
    try testing.expect(posix.system.poll(&excluded, excluded.len, 0) == 0);
    std.debug.print("complete fanout causal rtcp={any} authenticated_receivers={d} actual_datagrams={d}\n", .{ rtcp, receivers, count });
    try testing.expectEqual(@as(usize, receivers), count);
}

test "active media dispatch causal complete RTP fanout reaches all 130 authenticated endpoints" {
    try completeFanoutCausal(false);
}

test "active media dispatch causal complete RTCP fanout reaches all 130 authenticated endpoints" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try completeFanoutCausal(true);
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
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

pub const Execution = enum(u8) { unstarted = 0, paused = 1 };
/// Typed ChaCha8 state; bytes consumed from the current block are canonically
/// zero. No std.Random callback/pointer or structure padding crosses the cut.
pub const RngState = struct {
    state: [512]u8,
    offset: u16,
    pub fn capture(rng: *const std.Random.DefaultCsprng) RngState {
        return .{ .state = rng.state, .offset = @intCast(rng.offset) };
    }
    pub fn validate(self: *const RngState) !void {
        if (self.offset > self.state.len - std.Random.DefaultCsprng.secret_seed_length) return error.InvalidSnapshot;
        for (self.state[std.Random.DefaultCsprng.secret_seed_length..][0..self.offset]) |byte| if (byte != 0) return error.InvalidSnapshot;
    }
    fn restore(self: *const RngState) std.Random.DefaultCsprng {
        return .{ .state = self.state, .offset = self.offset };
    }
};

/// Only fully idle engines are representable here. Certificate ownership,
/// cookie key, future random stream and fingerprint-binding recency survive.
/// Handshake sessions, peer bindings and SRTP replay/nonce state require the
/// separate active continuity schema; none is replaced with an empty witness.
pub const IdleDtls = struct {
    cert_der: [dtls_server.cert_der_cap]u8,
    cert_len: u16,
    secret_key: [32]u8,
    public_key: [65]u8,
    cookie_secret: [32]u8,
    csprng: RngState,
    binding_tick: u64,
    binding_exhausted: bool,
    request_client_cert: bool,

    fn capture(term: anytype) !IdleDtls {
        for (term.sessions) |session| if (session.active) return error.ActiveMediaContinuityUnsupported;
        for (term.verify_bindings.slots) |binding| if (binding.active) return error.ActiveMediaContinuityUnsupported;
        if (term.cert_len == 0 or term.cert_len > dtls_server.cert_der_cap) return error.InvalidSnapshot;
        var idle: IdleDtls = .{ .cert_der = @splat(0), .cert_len = @intCast(term.cert_len), .secret_key = term.cert_key.secret_key.toBytes(), .public_key = term.cert_key.public_key.toUncompressedSec1(), .cookie_secret = term.cookie_secret, .csprng = RngState.capture(&term.csprng), .binding_tick = term.verify_bindings.tick, .binding_exhausted = term.verify_bindings.exhausted, .request_client_cert = term.request_client_cert };
        errdefer idle.wipe();
        @memcpy(idle.cert_der[0..term.cert_len], term.certDer());
        try idle.validate();
        return idle;
    }
    pub fn validate(self: *const IdleDtls) !void {
        if (self.binding_exhausted and self.binding_tick != std.math.maxInt(u64)) return error.InvalidSnapshot;
        if (self.cert_len == 0 or self.cert_len > self.cert_der.len) return error.InvalidSnapshot;
        for (self.cert_der[self.cert_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
        try self.csprng.validate();
        var key = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(self.secret_key));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        if (!std.crypto.timing_safe.eql([65]u8, key.public_key.toUncompressedSec1(), self.public_key)) return error.InvalidSnapshot;
        const der = self.cert_der[0..self.cert_len];
        const cert = try x509.parse(der);
        if (!std.mem.eql(u8, cert.der, der) or !std.mem.eql(u8, cert.subject_der, cert.issuer_der) or !std.mem.eql(u8, cert.subject_public_key, &self.public_key)) return error.InvalidSnapshot;
        const link = try x509_verify.linkInfo(der);
        try x509_verify.verifyCertSignature(link.tbs_der, link.signature_der, link.sig_alg_oid, link.sig_alg_params, link.spki_der);
    }
    fn restore(self: *const IdleDtls, term: anytype, sessions: anytype) void {
        for (sessions) |*session| session.* = .{};
        term.* = .{ .sessions = sessions, .cert_der = self.cert_der, .cert_len = self.cert_len, .cert_key = ecdsa.KeyPair.fromSecretKey(ecdsa.SecretKey.fromBytes(self.secret_key) catch unreachable) catch unreachable, .cookie_secret = self.cookie_secret, .csprng = self.csprng.restore(), .request_client_cert = self.request_client_cert };
        term.verify_bindings.tick = self.binding_tick;
        term.verify_bindings.exhausted = self.binding_exhausted;
    }
    pub fn wipe(self: *IdleDtls) void {
        std.crypto.secureZero(u8, &self.secret_key);
        std.crypto.secureZero(u8, &self.cookie_secret);
        std.crypto.secureZero(u8, &self.csprng.state);
    }
};

pub const Snapshot = struct {
    socket: media_socket.Snapshot,
    csprng: RngState,
    stun_server: ?TransportAddress,
    discovered: ?TransportAddress,
    max_frame_bytes: usize,
    max_upload_bytes: u64,
    dtls_enabled: bool,
    dtls_requested: bool,
    dtls13_enabled: bool,
    dtls13_requested: bool,
    dtls12: ?IdleDtls,
    dtls13: ?IdleDtls,
    srtp_clock: u64,
    cross_configured: bool,
    execution: Execution,
    pub fn deinit(self: *Snapshot) void {
        std.crypto.secureZero(u8, &self.csprng.state);
        if (self.dtls12) |*idle| idle.wipe();
        if (self.dtls13) |*idle| idle.wipe();
        self.* = undefined;
    }
    /// Expected policy must come from the independently validated configured
    /// owner, not a reconstruction of these snapshot fields.
    pub fn validateConfiguration(self: *const Snapshot, expected: Policy) !void {
        try self.validate();
        const actual: Policy = .{ .max_frame_bytes = self.max_frame_bytes, .max_upload_bytes = self.max_upload_bytes, .stun_server = self.stun_server, .dtls_requested = self.dtls_requested, .dtls13_requested = self.dtls13_requested, .cross_configured = self.cross_configured };
        if (!std.meta.eql(actual, expected)) return error.ConfigMismatch;
    }
    pub fn validate(self: *const Snapshot) !void {
        try self.socket.validate();
        try self.csprng.validate();
        if (self.stun_server) |address| try validateCarryAddress(address);
        if (self.discovered) |address| try validateCarryAddress(address);
        if (self.max_frame_bytes == 0 or self.max_frame_bytes > max_datagram or self.max_upload_bytes == 0 or (self.dtls_enabled and !self.dtls_requested) or (self.dtls13_enabled != self.dtls13_requested) or self.dtls_enabled != (self.dtls12 != null) or (self.dtls13 != null and (!self.dtls13_enabled or self.dtls12 == null))) return error.InvalidSnapshot;
        if (self.dtls12) |*idle| try idle.validate();
        if (self.dtls13) |*idle| {
            try idle.validate();
            const old = &self.dtls12.?;
            if (old.cert_len != idle.cert_len or !std.mem.eql(u8, old.cert_der[0..old.cert_len], idle.cert_der[0..idle.cert_len]) or !std.crypto.timing_safe.eql([32]u8, old.secret_key, idle.secret_key) or old.request_client_cert != idle.request_client_cert) return error.InvalidSnapshot;
        }
    }
};

test "companion runtime media plane actual pause idle DTLS identity random stream and rollback" {
    // Raw-fd fcntl has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var owner = try MediaPlane.initFallible(testing.allocator);
    var owner_live = true;
    defer if (owner_live) owner.deinit();
    owner.dtls_enabled = true;
    owner.dtls13_enabled = true;
    try owner.prepareColdResources(testing.io, loopback_be, 0);
    try testing.expect(owner.dtls != null and owner.dtls13 != null);
    // Consume a non-block-aligned amount of future ICE randomness, and retain
    // binding recency even with no current peer. Both are actual engine state.
    var consumed: [19]u8 = undefined;
    owner.csprng.random().bytes(&consumed);
    owner.dtls.?.verify_bindings.tick = 54;
    owner.dtls13.?.verify_bindings.tick = 91;
    owner.srtp_hub.clock = 123;
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .media_plane, .instance = 0, .owner_identity = &owner }};
    const gate = try runtime_pause.start_gate.create(testing.allocator, testing.io, &specs);
    defer {
        owner.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        owner.detachAfterJoined() catch unreachable;
        owner_live = false;
        owner.deinit();
        gate.control.destroyJoined();
    }
    const token = try owner.requestPause(1);
    try owner.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.media_plane, 0, &owner));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    gate.control.releaseAll();
    try owner.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try owner.requireActivated();
    var carry = try owner.capturePaused(token);
    defer carry.deinit();
    var configured: Policy = .{ .max_frame_bytes = max_datagram, .max_upload_bytes = 16 * 1024 * 1024, .stun_server = null, .dtls_requested = true, .dtls13_requested = true, .cross_configured = false };
    try carry.validateConfiguration(configured);
    configured.max_upload_bytes -= 1;
    try testing.expectError(error.ConfigMismatch, carry.validateConfiguration(configured));
    const sys = std.posix.system;
    const arg: if (@import("builtin").os.tag == .linux) usize else c_int = 0;
    for (0..5) |fail_index| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        const fd = sys.fcntl(owner.socket.?.fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), arg);
        try testing.expect(std.posix.errno(fd) == .SUCCESS);
        if (fail_index < 4) {
            try testing.expectError(error.OutOfMemory, MediaPlane.initInherited(failing.allocator(), @intCast(fd), &carry, null));
            try testing.expect(std.posix.errno(sys.fcntl(@intCast(fd), std.posix.F.GETFD, arg)) != .SUCCESS);
        } else {
            var successor = try MediaPlane.initInherited(failing.allocator(), @intCast(fd), &carry, null);
            defer successor.deinit();
            var same = try successor.captureUnstarted();
            defer same.deinit();
            try testing.expectEqualDeep(carry.dtls12, same.dtls12);
            try testing.expectEqualDeep(carry.dtls13, same.dtls13);
            try testing.expectEqualDeep(carry.csprng, same.csprng);
            try testing.expectEqual(carry.srtp_clock, same.srtp_clock);
            try testing.expectEqualSlices(u8, owner.dtls_fingerprint_buf[0..owner.dtls_fingerprint_len], successor.dtls_fingerprint_buf[0..successor.dtls_fingerprint_len]);
            var old_random = owner.csprng;
            var new_random = successor.csprng;
            var old_bytes: [600]u8 = undefined;
            var new_bytes: [600]u8 = undefined;
            old_random.random().bytes(&old_bytes);
            new_random.random().bytes(&new_bytes);
            try testing.expectEqualSlices(u8, &old_bytes, &new_bytes);
            var cookie_old = owner.dtls.?.csprng;
            var cookie_new = successor.dtls.?.csprng;
            cookie_old.random().bytes(&old_bytes);
            cookie_new.random().bytes(&new_bytes);
            try testing.expectEqualSlices(u8, &old_bytes, &new_bytes);
            std.crypto.secureZero(u8, std.mem.asBytes(&old_random));
            std.crypto.secureZero(u8, std.mem.asBytes(&new_random));
            std.crypto.secureZero(u8, std.mem.asBytes(&cookie_old));
            std.crypto.secureZero(u8, std.mem.asBytes(&cookie_new));
        }
        var unchanged = try owner.capturePaused(token);
        defer unchanged.deinit();
        try testing.expectEqualDeep(carry, unchanged);
    }
    carry.dtls12.?.secret_key[1] ^= 1;
    if (carry.validate()) |_| return error.TestExpectedError else |_| {}
    carry.dtls12.?.secret_key[1] ^= 1;
    carry.dtls12.?.cert_der[carry.dtls12.?.cert_len - 1] ^= 1;
    try testing.expectError(error.BadSignature, carry.validate());
    carry.dtls12.?.cert_der[carry.dtls12.?.cert_len - 1] ^= 1;
    carry.csprng.offset = 481;
    try testing.expectError(error.InvalidSnapshot, carry.validate());
    carry.csprng = RngState.capture(&owner.csprng);
    owner.dtls.?.sessions[0].active = true;
    try testing.expectError(error.ActiveMediaContinuityUnsupported, owner.capturePaused(token));
    owner.dtls.?.sessions[0].active = false;
    _ = owner.dtls.?.verify_bindings.bind(.{}, @splat(3));
    try testing.expectError(error.ActiveMediaContinuityUnsupported, owner.capturePaused(token));
    owner.dtls.?.verify_bindings.clear(.{});
    _ = owner.allocate("#active", "alice") orelse return error.TestUnexpectedResult;
    try testing.expectError(error.ActiveMediaContinuityUnsupported, owner.capturePaused(token));
    owner.remove("#active", "alice");
    try owner.resumePaused(token);
    const depart_deadline = std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    const second = while (true) {
        const next = owner.requestPause(2) catch |err| {
            if (err != error.Busy) return err;
            if (std.Io.Clock.awake.now(testing.io).nanoseconds >= depart_deadline.raw.nanoseconds) return error.TestUnexpectedResult;
            std.Thread.yield() catch {};
            continue;
        };
        break next;
    };
    try owner.awaitPaused(second, std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try testing.expectEqual(@as(usize, 1), gate.view.inspect().spawned);
    try owner.resumePaused(second);
}

pub const Policy = struct {
    max_frame_bytes: usize,
    max_upload_bytes: u64,
    stun_server: ?TransportAddress,
    dtls_requested: bool,
    dtls13_requested: bool,
    cross_configured: bool,
};
fn validateCarryAddress(address: TransportAddress) !void {
    if (address.port == 0 or (address.ip_len != 4 and address.ip_len != 16)) return error.InvalidSnapshot;
    for (address.ip[address.ip_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
}

test "active media DTO idle DTLS exhausted negative fingerprint authority survives owned restore" {
    // Raw-fd fcntl has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var owner = try MediaPlane.initFallible(testing.allocator);
    defer owner.deinit();
    owner.dtls_enabled = true;
    owner.dtls13_enabled = true;
    try owner.prepareColdResources(testing.io, loopback_be, 0);
    owner.dtls.?.verify_bindings.tick = std.math.maxInt(u64);
    owner.dtls13.?.verify_bindings.tick = std.math.maxInt(u64);
    // Actual void bind call paths discard the failed bool; the negative latch
    // must survive even though no fingerprint slot was ever installed.
    const addr = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 41234);
    owner.dtls.?.bindExpectedFingerprint(addr, @splat(9));
    owner.dtls13.?.bindExpectedFingerprint(addr, @splat(9));
    var carry = try owner.captureUnstarted();
    defer carry.deinit();
    try testing.expect(carry.dtls12.?.binding_exhausted and carry.dtls13.?.binding_exhausted);
    const sys = std.posix.system;
    const arg: if (@import("builtin").os.tag == .linux) usize else c_int = 0;
    const duplicate = sys.fcntl(owner.socket.?.fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), arg);
    try testing.expect(std.posix.errno(duplicate) == .SUCCESS);
    var restored = try MediaPlane.initInherited(testing.allocator, @intCast(duplicate), &carry, null);
    defer restored.deinit();
    try testing.expect(restored.dtls.?.verify_bindings.exhausted and restored.dtls13.?.verify_bindings.exhausted);
    restored.dtls.?.bindExpectedFingerprint(addr, @splat(10));
    restored.dtls13.?.bindExpectedFingerprint(addr, @splat(10));
    try testing.expect(restored.dtls.?.exportedKeys(addr) == null);
    try testing.expect(restored.dtls13.?.exportedKeys(addr) == null);
    carry.dtls12.?.binding_tick -= 1;
    try testing.expectError(error.InvalidSnapshot, carry.validate());
    carry.dtls12.?.binding_tick += 1;
    try carry.validate();
}

const PhysicalRtcEndpoint = struct {
    max_temporal: u3 = 7,
    identity: routing.EndpointObservation,
    profile: media_rooms.CallProfile,
    kind_bits: u8,
    expected_fp: ?[peer_verify.digest_len]u8,
    physical_cache: rtp_nack.PerSsrcRetransmitBuffer,
    endpoint: media_transport.Endpoint,
    fn wipe(self: *@This()) void {
        std.crypto.secureZero(u8, &self.endpoint.ufrag);
        std.crypto.secureZero(u8, &self.endpoint.pwd);
    }
};
fn validatePhysicalRtpPacket(row: PhysicalRtcEndpoint, bytes: []const u8) !u8 {
    const header = try rtp_profile.decodeHeader(bytes);
    const tag: sdp.CodecTag = switch (header.header.payload_type) {
        111 => .cadencevox,
        96 => .cadencevis,
        else => return error.ProfileDenied,
    };
    if (!profileHasCodec(row.profile, tag) or (tag == .cadencevox and row.kind_bits & 1 == 0) or (tag == .cadencevis and row.kind_bits & 6 == 0)) return error.ProfileDenied;
    const extension = try @import("../proto/rtp_ext.zig").find(bytes, @import("../proto/rtp_ext.zig").spatial_layer_id);
    if (extension) |layer| {
        if (layer.len != 1) return error.InvalidIngress;
        return layer[0];
    }
    return 0;
}
fn requirePhysicalRtpPacketPolicy(row: PhysicalRtcEndpoint, bytes: []const u8) !void {
    const spatial = try validatePhysicalRtpPacket(row, bytes);
    if (spatial > row.endpoint.max_spatial) return error.ProfileDenied;
}
const PhysicalRtcMap = std.AutoHashMapUnmanaged(routing.EndpointKey, PhysicalRtcEndpoint);
const PhysicalUfragMap = std.AutoHashMapUnmanaged([media_transport.ufrag_len]u8, routing.EndpointKey);
const PhysicalGroup = struct { key: [media_transport.group_key_len]u8, count: u32 };
const PhysicalGroupMap = std.AutoHashMapUnmanaged(routing.CallId, PhysicalGroup);
const RtcMapState = struct { metadata: usize, count: u32, capacity: u32 };
fn rtcMapState(map: anytype) RtcMapState {
    return .{ .metadata = if (map.metadata) |ptr| @intFromPtr(ptr) else 0, .count = map.count(), .capacity = map.capacity() };
}
fn rtcDigest(row: PhysicalRtcEndpoint) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    std.hash.autoHash(&hash, row.identity);
    std.hash.autoHash(&hash, row.kind_bits);
    std.hash.autoHash(&hash, row.expected_fp);
    std.hash.autoHash(&hash, row.profile.codec_count);
    std.hash.autoHash(&hash, row.profile.fec);
    for (row.profile.slice()) |codec| std.hash.autoHash(&hash, codec);
    hash.update(&row.endpoint.ufrag);
    hash.update(&row.endpoint.pwd);
    std.hash.autoHash(&hash, row.endpoint.remote);
    std.hash.autoHash(&hash, row.endpoint.max_spatial);
    std.hash.autoHash(&hash, row.max_temporal);
    std.hash.autoHash(&hash, row.endpoint.ssrc);
    std.hash.autoHash(&hash, row.endpoint.rx_packets);
    std.hash.autoHash(&hash, row.endpoint.rx_bytes);
    hash.update(&row.physical_cache.observationDigest());
    std.hash.autoHash(&hash, @intFromPtr(row.physical_cache.allocator.ptr));
    std.hash.autoHash(&hash, @intFromPtr(row.physical_cache.allocator.vtable));
    const rtx = row.endpoint.rtx;
    std.hash.autoHash(&hash, @intFromPtr(rtx.packets.items.ptr));
    std.hash.autoHash(&hash, rtx.packets.items.len);
    std.hash.autoHash(&hash, rtx.packets.capacity);
    std.hash.autoHash(&hash, rtx.capacity);
    std.hash.autoHash(&hash, rtx.newest_ext_seq);
    std.hash.autoHash(&hash, @intFromPtr(rtx.allocator.ptr));
    std.hash.autoHash(&hash, @intFromPtr(rtx.allocator.vtable));
    // OLD retransmission custody includes the actual bytes and original spans.
    for (rtx.packets.items) |packet| {
        std.hash.autoHash(&hash, packet.seq);
        std.hash.autoHash(&hash, packet.ext_seq);
        std.hash.autoHash(&hash, @intFromPtr(packet.bytes.ptr));
        std.hash.autoHash(&hash, packet.bytes.len);
        hash.update(packet.bytes);
    }
    return hash.finalResult();
}
pub const HostAdvertisement = struct {
    host: [255]u8 = @splat(0),
    host_len: u8 = 0,
    pub fn hostSlice(self: *const HostAdvertisement) []const u8 {
        return self.host[0..self.host_len];
    }
};
fn validateAdvertisementHost(host: []const u8) !void {
    if (host.len == 0 or host.len > 255 or std.mem.indexOfAny(u8, host, "\r\n\x00") != null) return error.InvalidHost;
}
fn selectAdvertisementHost(discovered: ?TransportAddress, fallback: []const u8) !HostAdvertisement {
    try validateAdvertisementHost(fallback);
    var result: HostAdvertisement = .{};
    const selected = if (discovered) |address| blk: {
        if (address.ip_len != 4 or address.port == 0) return error.InvalidHost;
        break :blk try std.fmt.bufPrint(&result.host, "{d}.{d}.{d}.{d}", .{ address.ip[0], address.ip[1], address.ip[2], address.ip[3] });
    } else fallback;
    if (discovered == null) @memcpy(result.host[0..selected.len], selected);
    result.host_len = @intCast(selected.len);
    return result;
}
const HostSocketObservation = struct { fd: std.posix.fd_t, snapshot: media_socket.Snapshot };
const AdvertisementHostPlan = struct {
    owner: *MediaPlane,
    domain: *routing.Domain,
    channel: []u8,
    native: routing.EndpointObservation,
    revision: u64,
    preview: HostAdvertisement,
    fallback: HostAdvertisement,
    discovered: ?TransportAddress,
    stun_server: ?TransportAddress,
    socket: ?HostSocketObservation,
    port: u16,
};
fn hostPlan(candidate: *PreparedAdvertisementHost) *AdvertisementHostPlan {
    return @ptrCast(@alignCast(candidate));
}
/// Lifetime is the source-owned candidate's lexical lifetime, not a copied
/// value proof. No independent admission/ready/credential constructor exists.
pub const PreparedAdvertisementHost = opaque {
    pub fn preview(self: *PreparedAdvertisementHost) HostAdvertisement {
        return hostPlan(self).preview;
    }
    pub fn validateLocked(self: *PreparedAdvertisementHost, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers, expected_fallback: []const u8) !void {
        const plan = hostPlan(self);
        if (plan.domain != domain or !std.mem.eql(u8, plan.fallback.hostSlice(), expected_fallback)) return error.StaleCandidate;
        try offers.requireEndpointLocked(domain, scope, plan.channel, plan.native);
        const owner = plan.owner;
        try domain.requireWebrtcBindingLocked(scope, owner.routing_binding orelse return error.NotRoutingBound, owner);
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        if (owner.routing_closed or owner.physical_revision != plan.revision or owner.stop_flag.load(.acquire) or owner.port != plan.port or
            !std.meta.eql(owner.discovered, plan.discovered) or !std.meta.eql(owner.stun_server, plan.stun_server) or
            (owner.socket == null) != (plan.socket == null)) return error.StaleCandidate;
        if (plan.socket) |socket| if (owner.socket.?.fd != socket.fd or owner.socket.?.recv_timeout_ms != socket.snapshot.recv_timeout_ms) return error.StaleCandidate;
    }
    pub fn deinit(self: *PreparedAdvertisementHost) void {
        const plan = hostPlan(self);
        const owner = plan.owner;
        owner.allocator.free(plan.channel);
        owner.allocator.destroy(plan);
        owner.finishPhysicalPlan();
    }
};

pub const WebrtcAdvertisement = struct {
    host: [255]u8 = @splat(0),
    host_len: u8 = 0,
    port: u16,
    fingerprint: [128]u8 = @splat(0),
    fingerprint_len: u8 = 0,
    pub fn hostSlice(self: *const WebrtcAdvertisement) []const u8 {
        return self.host[0..self.host_len];
    }
    pub fn fingerprintSlice(self: *const WebrtcAdvertisement) []const u8 {
        return self.fingerprint[0..self.fingerprint_len];
    }
};
const WebrtcOfferAdvertisement = struct {
    preview: WebrtcAdvertisement,
    socket_fd: std.posix.fd_t,
    socket: media_socket.Snapshot,
    discovered: ?TransportAddress,
    stun_server: ?TransportAddress,
    max_frame_bytes: usize,
    max_upload_bytes: u64,
    dtls_requested: bool,
    dtls13_requested: bool,
    dtls_enabled: bool,
    dtls13_enabled: bool,
    term12: ?*dtls_server.Terminator,
    term13: ?*dtls13_server.Terminator,
    mutual12: ?bool,
    mutual13: ?bool,
};
fn copyCurrentDtlsAdvertisement(owner: *const MediaPlane, out: *[128]u8) !u8 {
    var length: usize = 0;
    if (owner.dtls) |term| {
        if (term.cert_len == 0 or term.cert_len > term.cert_der.len) return error.DtlsUnavailable;
        const line = try term.fingerprintLine(out);
        length = line.len;
    }
    if (owner.dtls13) |term| {
        if (term.cert_len == 0 or term.cert_len > term.cert_der.len) return error.DtlsUnavailable;
        var other: [128]u8 = undefined;
        const line = try term.fingerprintLine(&other);
        if (length != 0 and !std.mem.eql(u8, out[0..length], line)) return error.DtlsCertificateMismatch;
        if (length == 0) {
            @memcpy(out[0..line.len], line);
            length = line.len;
        }
    }
    if (owner.dtls_fingerprint_len > owner.dtls_fingerprint_buf.len or owner.dtls_fingerprint_len != length or
        !std.mem.eql(u8, owner.dtls_fingerprint_buf[0..length], out[0..length])) return error.DtlsCertificateMismatch;
    return @intCast(length);
}
fn webrtcAdvertisementMatches(owner: *const MediaPlane, observation: *const WebrtcOfferAdvertisement) bool {
    const socket = owner.socket orelse return false;
    if (socket.fd != observation.socket_fd or socket.recv_timeout_ms != observation.socket.recv_timeout_ms or owner.port != observation.socket.port or
        !std.meta.eql(owner.discovered, observation.discovered) or !std.meta.eql(owner.stun_server, observation.stun_server) or
        owner.max_frame_bytes != observation.max_frame_bytes or owner.max_upload_bytes != observation.max_upload_bytes or
        owner.dtls_requested != observation.dtls_requested or owner.dtls13_requested != observation.dtls13_requested or
        owner.dtls_enabled != observation.dtls_enabled or owner.dtls13_enabled != observation.dtls13_enabled or
        owner.dtls != observation.term12 or owner.dtls13 != observation.term13 or
        !std.meta.eql(if (owner.dtls) |term| @as(?bool, term.request_client_cert) else null, observation.mutual12) or
        !std.meta.eql(if (owner.dtls13) |term| @as(?bool, term.request_client_cert) else null, observation.mutual13) or owner.stop_flag.load(.acquire)) return false;
    // Certificates are immutable for these source-pinned engine lifetimes. This
    // reads no session/cookie/crypto mutable state and makes no allocator/syscall.
    var actual: [128]u8 = undefined;
    const length = copyCurrentDtlsAdvertisement(owner, &actual) catch return false;
    return length == observation.preview.fingerprint_len and std.mem.eql(u8, actual[0..length], observation.preview.fingerprint[0..length]);
}

const WebrtcOfferPlan = struct {
    owner: *MediaPlane,
    domain: *routing.Domain,
    revision: u64,
    key: routing.EndpointKey,
    channel: []u8 = &.{},
    old: ?PhysicalRtcEndpoint,
    old_digest: ?[32]u8,
    next: PhysicalRtcEndpoint,
    old_group: ?PhysicalGroup,
    group: ?PhysicalGroup,
    rows_state: RtcMapState,
    ufrags_state: RtcMapState,
    groups_state: RtcMapState,
    dtls_enabled: bool,
    dtls13_enabled: bool,
    advertisement: ?WebrtcOfferAdvertisement = null,
    rows: ?PhysicalRtcMap = null,
    ufrags: ?PhysicalUfragMap = null,
    groups: ?PhysicalGroupMap = null,
    validated_scope: u64 = 0,
    committed: bool = false,
    fn wipe(self: *@This()) void {
        self.next.wipe();
        if (self.old) |*row| row.wipe();
        if (self.old_group) |*row| std.crypto.secureZero(u8, &row.key);
        if (self.group) |*row| std.crypto.secureZero(u8, &row.key);
    }
};
fn webrtcPlan(candidate: *PreparedWebrtcOffer) *WebrtcOfferPlan {
    return @ptrCast(@alignCast(candidate));
}
pub const WebrtcCredentialPreview = struct {
    identity: routing.EndpointObservation,
    ufrag: *const [media_transport.ufrag_len]u8,
    pwd: *const [media_transport.pwd_len]u8,
    group_key: ?*const [media_transport.group_key_len]u8,
};
pub const PreparedWebrtcOffer = opaque {
    pub fn negotiation(self: *PreparedWebrtcOffer) routing.TransportNegotiation {
        const row = webrtcPlan(self).next;
        return .{ .profile = row.profile, .kind_bits = row.kind_bits };
    }
    pub fn expectedFingerprint(self: *PreparedWebrtcOffer) ?[peer_verify.digest_len]u8 {
        return webrtcPlan(self).next.expected_fp;
    }
    pub fn preview(self: *PreparedWebrtcOffer) WebrtcCredentialPreview {
        const plan = webrtcPlan(self);
        return .{ .identity = plan.next.identity, .ufrag = &plan.next.endpoint.ufrag, .pwd = &plan.next.endpoint.pwd, .group_key = if (plan.next.identity.mode == .legacy_group) &plan.group.?.key else null };
    }
    /// Actual resource/certificate capture occurs before reply rendering and
    /// outside Domain. The configured fallback is copied, never a mutable borrow.
    pub fn captureAdvertisement(self: *PreparedWebrtcOffer, fallback_host: []const u8) !void {
        try validateAdvertisementHost(fallback_host);
        const plan = webrtcPlan(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        if (plan.committed or plan.advertisement != null or owner.routing_closed or owner.physical_revision != plan.revision or owner.stop_flag.load(.acquire)) return error.StaleCandidate;
        const socket = if (owner.socket) |*held| held else return error.NotPrepared;
        const observed = try socket.capture();
        if (owner.port == 0 or owner.port != observed.port) return error.SocketMismatch;
        var advertised: WebrtcAdvertisement = .{ .port = observed.port };
        const host = try selectAdvertisementHost(owner.discovered, fallback_host);
        advertised.host = host.host;
        advertised.host_len = host.host_len;
        advertised.fingerprint_len = try copyCurrentDtlsAdvertisement(owner, &advertised.fingerprint);
        if (plan.next.identity.mode == .dtls_required) {
            if (advertised.fingerprint_len == 0) return error.DtlsUnavailable;
            if (owner.dtls) |term| if (!term.request_client_cert) return error.DtlsUnavailable;
            if (owner.dtls13) |term| if (!term.request_client_cert) return error.DtlsUnavailable;
        }
        plan.advertisement = .{ .preview = advertised, .socket_fd = socket.fd, .socket = observed, .discovered = owner.discovered, .stun_server = owner.stun_server, .max_frame_bytes = owner.max_frame_bytes, .max_upload_bytes = owner.max_upload_bytes, .dtls_requested = owner.dtls_requested, .dtls13_requested = owner.dtls13_requested, .dtls_enabled = owner.dtls_enabled, .dtls13_enabled = owner.dtls13_enabled, .term12 = owner.dtls, .term13 = owner.dtls13, .mutual12 = if (owner.dtls) |term| term.request_client_cert else null, .mutual13 = if (owner.dtls13) |term| term.request_client_cert else null };
    }
    pub fn advertisement(self: *PreparedWebrtcOffer) !WebrtcAdvertisement {
        return (webrtcPlan(self).advertisement orelse return error.NotPrepared).preview;
    }
    pub fn requireAdvertisementLocked(self: *PreparedWebrtcOffer, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers) !void {
        try self.validateLocked(domain, scope, offers);
        if (webrtcPlan(self).advertisement == null) return error.NotPrepared;
    }
    /// expected is the AGREED transport codec/FEC profile; offered capability
    /// rows belong to MediaRooms and are independently joined by the caller.
    pub fn requireNegotiationLocked(self: *PreparedWebrtcOffer, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers, expected: media_rooms.CallProfile, kind_bits: u8, expected_fp: ?[peer_verify.digest_len]u8) !void {
        try self.validateLocked(domain, scope, offers);
        const row = webrtcPlan(self).next;
        if (row.kind_bits != kind_bits or !row.profile.eql(expected) or !std.meta.eql(row.expected_fp, expected_fp)) return error.InvalidProfile;
    }
    pub fn validateLocked(self: *PreparedWebrtcOffer, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers) !void {
        const serial = try domain.scopeSerial(scope);
        const plan = webrtcPlan(self);
        if (plan.domain != domain or plan.committed) return error.StaleCandidate;
        try offers.requireEndpointLocked(domain, scope, plan.channel, plan.next.identity);
        const owner = plan.owner;
        try domain.requireWebrtcBindingLocked(scope, owner.routing_binding orelse return error.NotRoutingBound, owner);
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        if (owner.routing_closed or owner.physical_revision != plan.revision or !std.meta.eql(rtcMapState(owner.physical_rows), plan.rows_state) or !std.meta.eql(rtcMapState(owner.physical_ufrags), plan.ufrags_state) or !std.meta.eql(rtcMapState(owner.physical_groups), plan.groups_state) or !std.meta.eql(owner.physical_groups.get(plan.key.call), plan.old_group) or owner.dtls_enabled != plan.dtls_enabled or owner.dtls13_enabled != plan.dtls13_enabled) return error.StaleCandidate;
        const current = owner.physical_rows.get(plan.key);
        if ((current == null) != (plan.old == null)) return error.StaleCandidate;
        if (current) |row| {
            if (!std.meta.eql(row.identity, plan.old.?.identity) or !std.mem.eql(u8, &rtcDigest(row), &plan.old_digest.?)) return error.StaleCandidate;
            if (!std.meta.eql(owner.physical_ufrags.get(row.endpoint.ufrag), @as(?routing.EndpointKey, plan.key))) return error.StaleCandidate;
        }
        if (owner.physical_ufrags.contains(plan.next.endpoint.ufrag)) return error.CredentialCollision;
        if (plan.advertisement) |*observation| if (!webrtcAdvertisementMatches(owner, observation)) return error.StaleCandidate;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedWebrtcOffer, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid physical WebRTC publication cut");
        const plan = webrtcPlan(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        std.debug.assert(!plan.committed and plan.domain == domain and plan.validated_scope == serial and owner.physical_revision == plan.revision);
        if (plan.rows) |*map| {
            var it = owner.physical_rows.iterator();
            while (it.next()) |entry| map.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(PhysicalRtcMap, &owner.physical_rows, map);
        }
        if (plan.ufrags) |*map| {
            var it = owner.physical_ufrags.iterator();
            while (it.next()) |entry| map.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(PhysicalUfragMap, &owner.physical_ufrags, map);
        }
        if (plan.groups) |*map| {
            var it = owner.physical_groups.iterator();
            while (it.next()) |entry| map.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(PhysicalGroupMap, &owner.physical_groups, map);
        }
        owner.physical_ufrags.putAssumeCapacity(plan.next.endpoint.ufrag, plan.key);
        if (plan.old) |old| {
            _ = owner.physical_ufrags.remove(old.endpoint.ufrag);
            owner.retireRoutingCryptoLocked(old.identity.stamp.endpoint, old.endpoint.remote);
            owner.physical_rows.getPtr(plan.key).?.wipe();
        }
        owner.physical_rows.putAssumeCapacity(plan.key, plan.next);
        if (plan.group) |group| owner.physical_groups.putAssumeCapacity(plan.key.call, group) else if (plan.old_group != null) {
            std.crypto.secureZero(u8, &owner.physical_groups.getPtr(plan.key.call).?.key);
            _ = owner.physical_groups.remove(plan.key.call);
        }
        owner.physical_revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedWebrtcOffer) void {
        const plan = webrtcPlan(self);
        const owner = plan.owner;
        if (plan.rows) |*map| {
            var it = map.valueIterator();
            while (it.next()) |row| row.wipe();
            map.deinit(owner.allocator);
        }
        if (plan.ufrags) |*map| map.deinit(owner.allocator);
        if (plan.groups) |*map| {
            var it = map.valueIterator();
            while (it.next()) |row| std.crypto.secureZero(u8, &row.key);
            map.deinit(owner.allocator);
        }
        if (plan.committed) {
            if (plan.old) |*row| {
                for (row.endpoint.rtx.packets.items) |packet| std.crypto.secureZero(u8, packet.bytes);
                row.endpoint.rtx.deinit();
                row.physical_cache.deinit();
            }
        } else {
            plan.next.endpoint.rtx.deinit();
            plan.next.physical_cache.deinit();
        }
        plan.wipe();
        owner.allocator.free(plan.channel);
        owner.allocator.destroy(plan);
        owner.finishPhysicalPlan();
    }
};

const WebrtcDeparturePlan = struct {
    owner: *MediaPlane,
    domain: *routing.Domain,
    key: routing.EndpointKey,
    old: ?PhysicalRtcEndpoint,
    old_digest: ?[32]u8,
    old_group: ?PhysicalGroup,
    group: ?PhysicalGroup,
    revision: u64,
    terminal: bool,
    batch_part: bool,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn webrtcDeparture(candidate: *PreparedWebrtcDeparture) *WebrtcDeparturePlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedWebrtcDeparture = opaque {
    pub fn validateLocked(self: *PreparedWebrtcDeparture, domain: *routing.Domain, scope: *const routing.Locked, departure: *routing.PreparedDeparture) !void {
        const serial = try domain.scopeSerial(scope);
        const plan = webrtcDeparture(self);
        if (plan.domain != domain or plan.committed) return error.StaleCandidate;
        try departure.requireOwnerLocked(domain, scope, plan.key);
        if (plan.terminal) try domain.requireTerminalLocked(scope);
        const owner = plan.owner;
        try domain.requireWebrtcBindingLocked(scope, owner.routing_binding orelse return error.NotRoutingBound, owner);
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        if (owner.routing_closed != plan.terminal or owner.physical_revision != plan.revision or
            !std.meta.eql(owner.physical_groups.get(plan.key.call), plan.old_group)) return error.StaleCandidate;
        const current = owner.physical_rows.get(plan.key);
        if ((current == null) != (plan.old == null)) return error.StaleCandidate;
        if (!std.meta.eql(if (current) |row| @as(?routing.EndpointObservation, row.identity) else null, departure.expectedOffer(.webrtc))) return error.StaleCandidate;
        if (current) |row| {
            const digest = rtcDigest(row);
            if (!std.mem.eql(u8, &digest, &plan.old_digest.?)) return error.StaleCandidate;
            if (!std.meta.eql(owner.physical_ufrags.get(row.endpoint.ufrag), @as(?routing.EndpointKey, plan.key))) return error.StaleCandidate;
        }
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedWebrtcDeparture, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid WebRTC departure scope");
        const plan = webrtcDeparture(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        std.debug.assert(!plan.committed and plan.domain == domain and plan.validated_scope == serial and owner.physical_revision == plan.revision);
        std.debug.assert(!plan.batch_part);
        applyWebrtcDeparturePlan(plan);
        if (plan.old != null and !plan.terminal) owner.physical_revision += 1;
    }
    pub fn deinit(self: *PreparedWebrtcDeparture) void {
        const plan = webrtcDeparture(self);
        const owner = plan.owner;
        if (plan.old) |*old| {
            if (plan.committed) {
                for (old.endpoint.rtx.packets.items) |packet| std.crypto.secureZero(u8, packet.bytes);
                old.endpoint.rtx.deinit();
                old.physical_cache.deinit();
            }
            old.wipe();
        }
        if (plan.old_group) |*group| std.crypto.secureZero(u8, &group.key);
        if (plan.group) |*group| std.crypto.secureZero(u8, &group.key);
        owner.allocator.destroy(plan);
        owner.finishPhysicalPlan();
    }
};

fn webrtcCandidateTestProfile() media_rooms.CallProfile {
    var profile = media_rooms.CallProfile{};
    profile.codecs[0] = .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 };
    profile.codec_count = 1;
    return profile;
}
const PublishWebrtcTest = struct {
    domain: *routing.Domain,
    offers: *routing.PreparedOffers,
    candidate: *PreparedWebrtcOffer,
    fn run(scope: *routing.Locked, ctx: @This()) !void {
        try ctx.offers.validateLocked(ctx.domain, scope);
        try ctx.candidate.validateLocked(ctx.domain, scope, ctx.offers);
        ctx.candidate.commitLocked(ctx.domain, scope);
        ctx.offers.commitLocked(ctx.domain, scope);
    }
};
fn retireWebrtcTest(domain: *routing.Domain, owner: *MediaPlane, call: routing.CallId, id: routing.ClientId) !void {
    const departure = try domain.prepareDeparture(call, id);
    defer departure.deinit();
    const candidate = try owner.prepareDeparture(domain, departure);
    defer candidate.deinit();
    const Cut = struct {
        domain: *routing.Domain,
        departure: *routing.PreparedDeparture,
        candidate: *PreparedWebrtcDeparture,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.departure.validateLocked(ctx.domain, scope);
            try ctx.candidate.validateLocked(ctx.domain, scope, ctx.departure);
            ctx.candidate.commitLocked(ctx.domain, scope);
            ctx.departure.commitLocked(ctx.domain, scope);
        }
    };
    const cut = Cut{ .domain = domain, .departure = departure, .candidate = candidate };
    if (owner.routing_closed) try domain.withTerminalLocked(cut, Cut.run) else try domain.withLocked(cut, Cut.run);
}
fn cleanupWebrtcTest(domain: *routing.Domain, owner: *MediaPlane, binding: *routing.WebrtcBinding) void {
    domain.closeForTerminal() catch @panic("WebRTC fixture did not join source custody");
    while (owner.physical_rows.count() != 0) {
        var it = owner.physical_rows.keyIterator();
        const key = it.next().?.*;
        retireWebrtcTest(domain, owner, key.call, key.client) catch @panic("WebRTC fixture lost exact departure");
    }
    domain.releaseWebrtc(binding) catch @panic("WebRTC fixture retained source binding");
}

test "physical WebRTC candidates preserve sibling ICE group and retransmission custody on reoffer and departure" {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("WebRTC fixture retained Domain rows");
    var owner = try MediaPlane.initFallible(testing.allocator);
    defer owner.deinit();
    const binding = try domain.bindWebrtc(&owner);
    defer cleanupWebrtcTest(domain, &owner, binding);
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 1, .slot = 0, .gen = 0 };
    var call: routing.CallId = undefined;
    for ([_]routing.ClientId{ a, b, a }) |id| {
        const offers = try domain.prepareOffers("#physical-rtc", id, &.{.{ .leg = .webrtc, .mode = .legacy_group }});
        defer offers.deinit();
        call = offers.preview().call;
        const key = routing.EndpointKey{ .call = call, .client = id, .leg = .webrtc };
        var previous = owner.physical_rows.get(key);
        defer if (previous) |*row| row.wipe();
        const sibling_key = routing.EndpointKey{ .call = call, .client = b, .leg = .webrtc };
        const sibling_digest = if (owner.physical_rows.get(sibling_key)) |row| @as(?[32]u8, rtcDigest(row)) else null;
        var prior_group = owner.physical_groups.get(call);
        defer if (prior_group) |*group| std.crypto.secureZero(u8, &group.key);
        const candidate = try owner.prepareOffer(domain, offers, "#physical-rtc", webrtcCandidateTestProfile(), 1, null);
        defer candidate.deinit();
        // Credential rendering precedes publication, and borrows only the plan.
        const preview = candidate.preview();
        try testing.expectEqualDeep(offers.preview().endpoints[0], preview.identity);
        if (prior_group) |group| try testing.expectEqualSlices(u8, &group.key, preview.group_key.?);
        try domain.withLocked(PublishWebrtcTest{ .domain = domain, .offers = offers, .candidate = candidate }, PublishWebrtcTest.run);
        if (previous) |row| {
            try testing.expect(!owner.physical_ufrags.contains(row.endpoint.ufrag));
            try testing.expect(!std.mem.eql(u8, &row.endpoint.pwd, preview.pwd));
            try testing.expectEqual(@as(usize, 0), owner.physical_rows.get(key).?.endpoint.rtx.len());
        }
        if (std.meta.eql(id, a) and sibling_digest != null) {
            const current = rtcDigest(owner.physical_rows.get(sibling_key).?);
            try testing.expectEqualSlices(u8, &sibling_digest.?, &current);
        }
        if (std.meta.eql(id, b)) {
            // Actual retained packet storage stays owned by the sibling and must
            // not be copied into the reoffered endpoint or freed with old maps.
            try owner.physical_rows.getPtr(sibling_key).?.endpoint.rtx.onSent(27, "sibling packet");
        }
    }
    try testing.expectEqual(@as(u32, 2), owner.physical_rows.count());
    try testing.expectEqual(@as(u32, 2), owner.physical_groups.get(call).?.count);
    const sibling_key = routing.EndpointKey{ .call = call, .client = b, .leg = .webrtc };
    const saved = rtcDigest(owner.physical_rows.get(sibling_key).?);
    try retireWebrtcTest(domain, &owner, call, a);
    try testing.expectEqual(@as(u32, 1), owner.physical_groups.get(call).?.count);
    const after = rtcDigest(owner.physical_rows.get(sibling_key).?);
    try testing.expectEqualSlices(u8, &saved, &after);
    try testing.expectEqualStrings("sibling packet", owner.physical_rows.get(sibling_key).?.endpoint.rtx.lookup(27).?);
    owner.physical_revision = std.math.maxInt(u64);
    try domain.closeForTerminal();
    try retireWebrtcTest(domain, &owner, call, b);
    try testing.expectEqual(std.math.maxInt(u64), owner.physical_revision);
    try testing.expectEqual(@as(u32, 0), owner.physical_rows.count());
    try testing.expectEqual(@as(u32, 0), owner.physical_groups.count());
    try testing.expectEqual(@as(u32, 0), owner.physical_ufrags.count());
}
fn webrtcCandidateOom(allocator: std.mem.Allocator) !void {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("WebRTC OOM Domain custody");
    var owner = try MediaPlane.initFallible(allocator);
    defer owner.deinit();
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("WebRTC OOM binding custody");
    const offers = try domain.prepareOffers("#oom-rtc", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .webrtc, .mode = .legacy_group }});
    defer offers.deinit();
    const candidate = owner.prepareOffer(domain, offers, "#oom-rtc", webrtcCandidateTestProfile(), 1, null) catch |err| {
        try testing.expectEqual(@as(u64, 1), owner.physical_revision);
        try testing.expectEqual(@as(usize, 0), owner.physical_pending);
        try testing.expectEqualDeep(RtcMapState{ .metadata = 0, .count = 0, .capacity = 0 }, rtcMapState(owner.physical_rows));
        try testing.expectEqualDeep(RtcMapState{ .metadata = 0, .count = 0, .capacity = 0 }, rtcMapState(owner.physical_ufrags));
        try testing.expectEqualDeep(RtcMapState{ .metadata = 0, .count = 0, .capacity = 0 }, rtcMapState(owner.physical_groups));
        return err;
    };
    candidate.deinit();
    try testing.expectEqual(@as(u64, 1), owner.physical_revision);
    try testing.expectEqual(@as(usize, 0), owner.physical_pending);
    try testing.expectEqual(@as(u32, 0), owner.physical_rows.capacity());
    try testing.expectEqual(@as(u32, 0), owner.physical_ufrags.capacity());
    try testing.expectEqual(@as(u32, 0), owner.physical_groups.capacity());
}
test "physical WebRTC preparation every OOM preserves exact OLD backing and shared group custody" {
    try testing.checkAllAllocationFailures(testing.allocator, webrtcCandidateOom, .{});
}

test "physical WebRTC DTLS mode refuses an unavailable real engine before candidate allocation" {
    var fail = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch unreachable;
    var owner = try MediaPlane.initFallible(fail.allocator());
    defer owner.deinit();
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch unreachable;
    const offers = try domain.prepareOffers("#dtls-rtc", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .webrtc, .mode = .dtls_required }});
    defer offers.deinit();
    try testing.expectError(error.DtlsUnavailable, owner.prepareOffer(domain, offers, "#dtls-rtc", webrtcCandidateTestProfile(), 1, @splat(9)));
    try testing.expectEqual(@as(usize, 0), fail.alloc_index);
    try testing.expectEqual(@as(usize, 0), owner.physical_pending);
}

fn applyWebrtcDeparturePlan(plan: *WebrtcDeparturePlan) void {
    const owner = plan.owner;
    if (plan.old) |old| {
        owner.retireRoutingCryptoLocked(old.identity.stamp.endpoint, old.endpoint.remote);
        _ = owner.physical_ufrags.remove(old.endpoint.ufrag);
        owner.physical_rows.getPtr(plan.key).?.wipe();
        _ = owner.physical_rows.remove(plan.key);
        if (plan.group) |group| owner.physical_groups.getPtr(plan.key.call).?.* = group else if (plan.old_group != null) {
            std.crypto.secureZero(u8, &owner.physical_groups.getPtr(plan.key.call).?.key);
            _ = owner.physical_groups.remove(plan.key.call);
        }
    }
    plan.committed = true;
}
const WebrtcClientDeparturePlan = struct {
    owner: *MediaPlane,
    domain: *routing.Domain,
    departure: *routing.PreparedClientDeparture,
    parts: []*PreparedWebrtcDeparture,
    revision: u64,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn planPreparedWebrtcClientDeparture(candidate: *PreparedWebrtcClientDeparture) *WebrtcClientDeparturePlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedWebrtcClientDeparture = opaque {
    pub fn validateLocked(self: *PreparedWebrtcClientDeparture, domain: *routing.Domain, scope: *const routing.Locked, departure: *routing.PreparedClientDeparture) !void {
        const plan = planPreparedWebrtcClientDeparture(self);
        const serial = try domain.scopeSerial(scope);
        if (plan.domain != domain or plan.departure != departure or plan.committed or plan.parts.len != departure.count()) return error.StaleCandidate;
        try departure.validateLocked(domain, scope);
        for (plan.parts, 0..) |part, n| {
            try departure.requirePartLocked(domain, scope, n, departure.part(n));
            if (webrtcDeparture(part).revision != plan.revision or !webrtcDeparture(part).batch_part) return error.StaleCandidate;
            try part.validateLocked(domain, scope, departure.part(n));
        }
        lockSpin(&plan.owner.mutex);
        defer plan.owner.mutex.unlock();
        if (plan.owner.physical_revision != plan.revision) return error.StaleCandidate;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedWebrtcClientDeparture, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid complete source departure cut");
        const plan = planPreparedWebrtcClientDeparture(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        std.debug.assert(!plan.committed and plan.domain == domain and plan.validated_scope == serial and owner.physical_revision == plan.revision);
        var changed = false;
        for (plan.parts) |part| {
            const row = webrtcDeparture(part);
            std.debug.assert(!row.committed and row.validated_scope == serial and row.batch_part);
            changed = changed or (row.old != null);
            applyWebrtcDeparturePlan(row);
        }
        if (changed and !plan.departure.isTerminal()) owner.physical_revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedWebrtcClientDeparture) void {
        const plan = planPreparedWebrtcClientDeparture(self);
        const owner = plan.owner;
        for (plan.parts) |part| part.deinit();
        owner.allocator.free(plan.parts);
        owner.allocator.destroy(plan);
        owner.finishPhysicalPlan();
    }
};

const FullPhysicalOfferTest = struct {
    domain: *routing.Domain,
    offers: *routing.PreparedOffers,
    native: *@import("native_media_transport.zig").PreparedNativeOffer,
    webrtc: *PreparedWebrtcOffer,
    profiles: *media_rooms.PreparedProfiles,
    fn run(scope: *routing.Locked, ctx: @This()) !void {
        try ctx.offers.validateLocked(ctx.domain, scope);
        try ctx.native.validateLocked(ctx.domain, scope, ctx.offers);
        try ctx.webrtc.validateLocked(ctx.domain, scope, ctx.offers);
        try ctx.profiles.validateLocked(ctx.domain, scope, ctx.offers);
        ctx.native.commitLocked(ctx.domain, scope);
        ctx.webrtc.commitLocked(ctx.domain, scope);
        ctx.profiles.commitLocked(ctx.domain, scope);
        ctx.offers.commitLocked(ctx.domain, scope);
    }
};
const FullPhysicalJoinTest = struct {
    domain: *routing.Domain,
    membership: *routing.PreparedMembership,
    room: *media_rooms.PreparedJoin,
    fn run(scope: *routing.Locked, ctx: @This()) !void {
        try ctx.membership.validateLocked(ctx.domain, scope);
        try ctx.room.validateLocked(ctx.domain, scope, ctx.membership);
        ctx.room.commitLocked(ctx.domain, scope);
        ctx.membership.commitLocked(ctx.domain, scope);
    }
};
const FullPhysicalDepartureTest = struct {
    domain: *routing.Domain,
    departure: *routing.PreparedClientDeparture,
    native: *@import("native_media_transport.zig").PreparedNativeClientDeparture,
    webrtc: *PreparedWebrtcClientDeparture,
    rooms: *media_rooms.PreparedRoomClientDeparture,
    fn run(scope: *routing.Locked, ctx: @This()) !void {
        // Deliberately validate Room LAST. No earlier component may publish on
        // a late family refusal. All pure commits follow the complete validator.
        try ctx.departure.validateLocked(ctx.domain, scope);
        try ctx.native.validateLocked(ctx.domain, scope, ctx.departure);
        try ctx.webrtc.validateLocked(ctx.domain, scope, ctx.departure);
        try ctx.rooms.validateLocked(ctx.domain, scope, ctx.departure);
        ctx.native.commitLocked(ctx.domain, scope);
        ctx.webrtc.commitLocked(ctx.domain, scope);
        ctx.rooms.commitLocked(ctx.domain, scope);
        ctx.departure.commitLocked(ctx.domain, scope);
    }
};
fn provisionPhysicalClientTest(domain: *routing.Domain, native: *@import("native_media_transport.zig").NativeMediaTransport, webrtc: *MediaPlane, rooms: *media_rooms.MediaRooms, channel: []const u8, id: routing.ClientId, display: []const u8) !routing.CallId {
    const offers = try domain.prepareOffers(channel, id, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .legacy_group } });
    defer offers.deinit();
    const profile = webrtcCandidateTestProfile();
    const native_plan = try native.prepareOffer(domain, offers, channel, display, profile, 1);
    defer native_plan.deinit();
    const webrtc_plan = try webrtc.prepareOffer(domain, offers, channel, profile, 1, null);
    defer webrtc_plan.deinit();
    const preview = offers.preview();
    var keys: [2]routing.EndpointKey = undefined;
    for (preview.endpoints[0..preview.count], 0..) |endpoint, n| keys[n] = .{ .call = preview.call, .client = id, .leg = endpoint.reference.endpoint.leg };
    const profiles = try rooms.prepareTransportProfiles(&keys, channel, display, profile, profile);
    defer profiles.deinit();
    try domain.withLocked(FullPhysicalOfferTest{ .domain = domain, .offers = offers, .native = native_plan, .webrtc = webrtc_plan, .profiles = profiles }, FullPhysicalOfferTest.run);
    const membership = try domain.prepareMembership(channel, id, 1);
    defer membership.deinit();
    const joined = try rooms.prepareJoin(membership.preview(), channel, display, .voice);
    defer joined.deinit();
    try domain.withLocked(FullPhysicalJoinTest{ .domain = domain, .membership = membership, .room = joined }, FullPhysicalJoinTest.run);
    return preview.call;
}
fn retirePhysicalClientTest(domain: *routing.Domain, native: *@import("native_media_transport.zig").NativeMediaTransport, webrtc: *MediaPlane, rooms: *media_rooms.MediaRooms, id: routing.ClientId) !void {
    const departure = try domain.prepareClientDeparture(id);
    defer departure.deinit();
    const native_plan = try native.prepareClientDeparture(domain, departure);
    defer native_plan.deinit();
    const webrtc_plan = try webrtc.prepareClientDeparture(domain, departure);
    defer webrtc_plan.deinit();
    const room_plan = try rooms.prepareClientDeparture(departure);
    defer room_plan.deinit();
    const cut = FullPhysicalDepartureTest{ .domain = domain, .departure = departure, .native = native_plan, .webrtc = webrtc_plan, .rooms = room_plan };
    if (departure.isTerminal()) try domain.withTerminalLocked(cut, FullPhysicalDepartureTest.run) else try domain.withLocked(cut, FullPhysicalDepartureTest.run);
}
test "complete physical client departure two calls late Room refusal retains all credentials and retries atomically" {
    const native_mod = @import("native_media_transport.zig");
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("complete-client fixture retained Domain");
    var native = native_mod.NativeMediaTransport.init(testing.allocator);
    defer native.deinit();
    var webrtc = try MediaPlane.initFallible(testing.allocator);
    defer webrtc.deinit();
    var rooms = media_rooms.MediaRooms.init(testing.allocator);
    defer rooms.deinit();
    const native_binding = try domain.bindNative(&native);
    const webrtc_binding = domain.bindWebrtc(&webrtc) catch |err| {
        try domain.releaseNative(native_binding);
        return err;
    };
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    defer {
        domain.closeForTerminal() catch @panic("complete-client fixture retained live custody");
        retirePhysicalClientTest(domain, &native, &webrtc, &rooms, a) catch @panic("complete-client A retirement");
        retirePhysicalClientTest(domain, &native, &webrtc, &rooms, b) catch @panic("complete-client B retirement");
        domain.releaseWebrtc(webrtc_binding) catch @panic("complete-client WebRTC binding");
        domain.releaseNative(native_binding) catch @panic("complete-client native binding");
    }
    const call_a = try provisionPhysicalClientTest(domain, &native, &webrtc, &rooms, "#batch-a", a, "owner");
    const call_b = try provisionPhysicalClientTest(domain, &native, &webrtc, &rooms, "#batch-b", a, "owner");
    _ = try provisionPhysicalClientTest(domain, &native, &webrtc, &rooms, "#batch-a", b, "sibling");
    try testing.expect(try rooms.setQuality("#batch-b", "owner", .{ .loss_pct = 3, .rtt_ms = 4, .spatial = 1, .bitrate_kbps = 500 }));
    const saved_a = rtcDigest(webrtc.physical_rows.get(.{ .call = call_a, .client = a, .leg = .webrtc }).?);
    const saved_b = rtcDigest(webrtc.physical_rows.get(.{ .call = call_b, .client = a, .leg = .webrtc }).?);
    const saved_sibling = rtcDigest(webrtc.physical_rows.get(.{ .call = call_a, .client = b, .leg = .webrtc }).?);
    const native_revision = native.physical_revision;
    const webrtc_revision = webrtc.physical_revision;
    const room_revision = rooms.transport_revision;
    const departure = try domain.prepareClientDeparture(a);
    defer departure.deinit();
    try testing.expectEqual(@as(usize, 2), departure.count());
    try testing.expectEqualStrings("#batch-a", departure.part(0).channel());
    try testing.expectEqualStrings("#batch-b", departure.part(1).channel());
    const native_plan = try native.prepareClientDeparture(domain, departure);
    defer native_plan.deinit();
    const webrtc_plan = try webrtc.prepareClientDeparture(domain, departure);
    defer webrtc_plan.deinit();
    const room_plan = try rooms.prepareClientDeparture(departure);
    defer room_plan.deinit();
    try testing.expect(try rooms.setQuality("#batch-b", "owner", .{ .loss_pct = 9, .rtt_ms = 4, .spatial = 1, .bitrate_kbps = 500 }));
    const cut = FullPhysicalDepartureTest{ .domain = domain, .departure = departure, .native = native_plan, .webrtc = webrtc_plan, .rooms = room_plan };
    try testing.expectError(error.StaleCandidate, domain.withLocked(cut, FullPhysicalDepartureTest.run));
    const unchanged_a = rtcDigest(webrtc.physical_rows.get(.{ .call = call_a, .client = a, .leg = .webrtc }).?);
    const unchanged_b = rtcDigest(webrtc.physical_rows.get(.{ .call = call_b, .client = a, .leg = .webrtc }).?);
    try testing.expectEqualSlices(u8, &saved_a, &unchanged_a);
    try testing.expectEqualSlices(u8, &saved_b, &unchanged_b);
    try testing.expectEqual(@as(u32, 3), native.physical_endpoints.count());
    try testing.expectEqual(native_revision, native.physical_revision);
    try testing.expectEqual(webrtc_revision, webrtc.physical_revision);
    try testing.expectEqual(room_revision, rooms.transport_revision);
    try testing.expectEqual(@as(u32, 3), rooms.physical_members.count());
    // Retry the same immutable plans only after the exact original source value
    // returns. No identities, secrets or old locator facts are rebound.
    try testing.expect(try rooms.setQuality("#batch-b", "owner", .{ .loss_pct = 3, .rtt_ms = 4, .spatial = 1, .bitrate_kbps = 500 }));
    try domain.withLocked(cut, FullPhysicalDepartureTest.run);
    try testing.expectEqual(native_revision + 1, native.physical_revision);
    try testing.expectEqual(webrtc_revision + 1, webrtc.physical_revision);
    try testing.expectEqual(room_revision + 1, rooms.transport_revision);
    try testing.expectEqual(@as(u32, 1), native.physical_endpoints.count());
    try testing.expectEqual(@as(u32, 1), webrtc.physical_rows.count());
    try testing.expectEqual(@as(u32, 1), rooms.physical_members.count());
    const sibling_after = rtcDigest(webrtc.physical_rows.get(.{ .call = call_a, .client = b, .leg = .webrtc }).?);
    try testing.expectEqualSlices(u8, &saved_sibling, &sibling_after);
    try testing.expect(rooms.isParticipant("#batch-a", "sibling"));
    try testing.expect(rooms.room("#batch-b") == null);
}

test "physical WebRTC every detached growth failure has same owner retry and original allocation custody" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const domain = try routing.Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("growth retry source custody");
    var owner = try MediaPlane.initFallible(fail.allocator());
    defer owner.deinit();
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("growth retry binding custody");
    const offers = try domain.prepareOffers("#retry", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .webrtc, .mode = .legacy_group }});
    defer offers.deinit();
    const old_0 = rtcMapState(owner.physical_rows);
    const old_1 = rtcMapState(owner.physical_ufrags);
    const old_2 = rtcMapState(owner.physical_groups);
    const old_allocated = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..32) |n| {
        fail.fail_index = fail.alloc_index + n;
        const candidate = owner.prepareOffer(domain, offers, "#retry", webrtcCandidateTestProfile(), 1, null) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
            try std.testing.expectEqual(@as(usize, 0), owner.physical_pending);
            try std.testing.expectEqual(@as(u64, 1), owner.physical_revision);
            try std.testing.expectEqualDeep(old_0, rtcMapState(owner.physical_rows));
            try std.testing.expectEqualDeep(old_1, rtcMapState(owner.physical_ufrags));
            try std.testing.expectEqualDeep(old_2, rtcMapState(owner.physical_groups));
            const retry = try owner.prepareOffer(domain, offers, "#retry", webrtcCandidateTestProfile(), 1, null);
            retry.deinit();
            try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
            failures += 1;
            continue;
        };
        fail.fail_index = std.math.maxInt(usize);
        candidate.deinit();
        succeeded = true;
        break;
    }
    try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
    try std.testing.expect(succeeded and failures >= 5);
    try std.testing.expectEqual(@as(usize, 0), owner.physical_pending);
    try std.testing.expectEqual(@as(u64, 1), owner.physical_revision);
    try std.testing.expectEqualDeep(old_0, rtcMapState(owner.physical_rows));
    try std.testing.expectEqualDeep(old_1, rtcMapState(owner.physical_ufrags));
    try std.testing.expectEqualDeep(old_2, rtcMapState(owner.physical_groups));
}

test "physical WebRTC advertisement binds actual socket discovery certificate and full agreed policy" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("WebRTC advertisement source custody");
    var owner = try MediaPlane.initFallible(testing.allocator);
    defer owner.deinit();
    owner.dtls_enabled = true;
    try owner.prepareColdResources(testing.io, media_socket.loopback_be, 0);
    // This is an actual generated source certificate, not a verdict setter.
    try testing.expect(owner.dtls != null and owner.dtls_fingerprint_len != 0);
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("WebRTC advertisement binding custody");
    const offers = try domain.prepareOffers("#advertisement", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .webrtc, .mode = .dtls_required }});
    defer offers.deinit();
    const profile = webrtcCandidateTestProfile();
    const expected_fp: [peer_verify.digest_len]u8 = @splat(7);
    const candidate = try owner.prepareOffer(domain, offers, "#advertisement", profile, 1, expected_fp);
    defer candidate.deinit();
    try testing.expectError(error.NotPrepared, candidate.advertisement());
    try testing.expectError(error.InvalidHost, candidate.captureAdvertisement("bad\r\nhost"));
    try candidate.captureAdvertisement("media.example.test");
    const advertised = try candidate.advertisement();
    try testing.expectEqual(try owner.socket.?.localPort(), advertised.port);
    try testing.expectEqualStrings("media.example.test", advertised.hostSlice());
    var actual_fp: [128]u8 = undefined;
    try testing.expectEqualStrings(try owner.dtls.?.fingerprintLine(&actual_fp), advertised.fingerprintSlice());
    const Cut = struct {
        domain: *routing.Domain,
        offers: *routing.PreparedOffers,
        candidate: *PreparedWebrtcOffer,
        expected: media_rooms.CallProfile,
        expected_fp: ?[peer_verify.digest_len]u8,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.candidate.requireNegotiationLocked(ctx.domain, scope, ctx.offers, ctx.expected, 1, ctx.expected_fp);
            try ctx.candidate.requireAdvertisementLocked(ctx.domain, scope, ctx.offers);
        }
    };
    const good = Cut{ .domain = domain, .offers = offers, .candidate = candidate, .expected = profile, .expected_fp = expected_fp };
    try domain.withLocked(good, Cut.run);
    var equal_tail = profile;
    for (equal_tail.codecs[equal_tail.codec_count..]) |*codec| codec.* = .{ .tag = .raw, .clock_rate = 913, .params = 21 };
    try domain.withLocked(Cut{ .domain = domain, .offers = offers, .candidate = candidate, .expected = equal_tail, .expected_fp = expected_fp }, Cut.run);
    {
        defer owner.dtls_fingerprint_buf[0] ^= 1;
        owner.dtls_fingerprint_buf[0] ^= 1;
        try testing.expectError(error.StaleCandidate, domain.withLocked(good, Cut.run));
    }
    {
        owner.dtls.?.request_client_cert = false;
        defer owner.dtls.?.request_client_cert = true;
        try testing.expectError(error.StaleCandidate, domain.withLocked(good, Cut.run));
    }
    {
        const before = owner.discovered;
        defer owner.discovered = before;
        owner.discovered = .{ .ip = .{ 203, 0, 113, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .ip_len = 4, .port = advertised.port };
        try testing.expectError(error.StaleCandidate, domain.withLocked(good, Cut.run));
    }
    var foreign = profile;
    foreign.fec.redundancy += 1;
    try testing.expectError(error.InvalidProfile, domain.withLocked(Cut{ .domain = domain, .offers = offers, .candidate = candidate, .expected = foreign, .expected_fp = expected_fp }, Cut.run));
    try testing.expectError(error.InvalidProfile, domain.withLocked(Cut{ .domain = domain, .offers = offers, .candidate = candidate, .expected = profile, .expected_fp = @as([peer_verify.digest_len]u8, @splat(8)) }, Cut.run));
    try domain.withLocked(good, Cut.run);
    try testing.expectEqual(@as(u32, 0), owner.physical_rows.count());
    try testing.expectEqual(@as(u64, 1), owner.physical_revision);
}

const NativeHostCutTest = struct {
    domain: *routing.Domain,
    offers: *routing.PreparedOffers,
    host: *PreparedAdvertisementHost,
    fallback: []const u8,
    fn run(scope: *routing.Locked, ctx: @This()) !void {
        try ctx.host.validateLocked(ctx.domain, scope, ctx.offers, ctx.fallback);
    }
};
test "physical native-only host observation owns no RTC credentials and refuses stale discovery policy" {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("host observation Domain custody");
    var owner = try MediaPlane.initFallible(testing.allocator);
    defer owner.deinit();
    // Actual inline configured owner, deliberately no RTC socket/endpoint.
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("host observation binding custody");
    const offers = try domain.prepareOffers("#native-only", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offers.deinit();
    const host = try owner.prepareAdvertisementHost(domain, offers, "#native-only", "native.example.test");
    defer host.deinit();
    const preview = host.preview();
    try testing.expectEqualStrings("native.example.test", preview.hostSlice());
    const cut = NativeHostCutTest{ .domain = domain, .offers = offers, .host = host, .fallback = "native.example.test" };
    try domain.withLocked(cut, NativeHostCutTest.run);
    try testing.expectError(error.StaleCandidate, domain.withLocked(NativeHostCutTest{ .domain = domain, .offers = offers, .host = host, .fallback = "foreign.example.test" }, NativeHostCutTest.run));
    {
        owner.discovered = .{ .ip = .{ 203, 0, 113, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .ip_len = 4, .port = 9000 };
        defer owner.discovered = null;
        try testing.expectError(error.StaleCandidate, domain.withLocked(cut, NativeHostCutTest.run));
    }
    {
        owner.stop_flag.store(true, .release);
        defer owner.stop_flag.store(false, .release);
        try testing.expectError(error.StaleCandidate, domain.withLocked(cut, NativeHostCutTest.run));
    }
    try testing.expectError(error.Busy, domain.releaseWebrtc(binding));
    try testing.expectError(error.Busy, owner.prepareColdResources(testing.io, loopback_be, 0));
    try domain.withLocked(cut, NativeHostCutTest.run);
    try testing.expect(owner.socket == null);
    try testing.expectEqual(@as(u32, 0), owner.physical_rows.count());
    try testing.expectEqual(@as(u32, 0), owner.physical_ufrags.count());
    try testing.expectEqual(@as(u32, 0), owner.physical_groups.count());
    try testing.expectEqual(@as(u64, 1), owner.physical_revision);
}
test "physical host observation every allocation failure preserves original owner and same candidate retry" {
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("host OOM Domain custody");
    var owner = try MediaPlane.initFallible(fail.allocator());
    defer owner.deinit();
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("host OOM binding custody");
    const offers = try domain.prepareOffers("#host-oom", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offers.deinit();
    const old_bytes = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..8) |index| {
        fail.fail_index = fail.alloc_index + index;
        const candidate = owner.prepareAdvertisementHost(domain, offers, "#host-oom", "host.example.test") catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(old_bytes, fail.allocated_bytes - fail.freed_bytes);
            try testing.expectEqual(@as(usize, 0), owner.physical_pending);
            {
                const retry = try owner.prepareAdvertisementHost(domain, offers, "#host-oom", "host.example.test");
                defer retry.deinit();
                try domain.withLocked(NativeHostCutTest{ .domain = domain, .offers = offers, .host = retry, .fallback = "host.example.test" }, NativeHostCutTest.run);
            }
            try testing.expectEqual(old_bytes, fail.allocated_bytes - fail.freed_bytes);
            failures += 1;
            continue;
        };
        fail.fail_index = std.math.maxInt(usize);
        {
            defer candidate.deinit();
            try domain.withLocked(NativeHostCutTest{ .domain = domain, .offers = offers, .host = candidate, .fallback = "host.example.test" }, NativeHostCutTest.run);
        }
        succeeded = true;
        break;
    }
    try testing.expect(succeeded and failures == 2);
    try testing.expectEqual(old_bytes, fail.allocated_bytes - fail.freed_bytes);
    try testing.expectEqual(@as(usize, 0), owner.physical_pending);
    try testing.expect(owner.socket == null and owner.discovered == null);
    try testing.expectEqual(@as(u64, 1), owner.physical_revision);
}

test "physical routing owned FIFO all allocation failures preserve actual source and retry" {
    var failures: usize = 0;
    var succeeded = false;
    for (0..8) |index| {
        const domain = try routing.Domain.create(testing.allocator);
        defer domain.destroyQuiesced() catch @panic("queue OOM retained Domain");
        var fail = testing.FailingAllocator.init(testing.allocator, .{});
        var owner = try MediaPlane.initFallible(fail.allocator());
        defer owner.deinit();
        const binding = try domain.bindWebrtc(&owner);
        defer domain.releaseWebrtc(binding) catch @panic("queue OOM retained binding");
        defer if (owner.routing_egress != null) owner.disposeRoutingEgress(domain) catch @panic("queue OOM retained owned slots");
        const old = fail.allocated_bytes - fail.freed_bytes;
        fail.fail_index = fail.alloc_index + index;
        owner.prepareRoutingEgress(domain, 3, 256) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(old, fail.allocated_bytes - fail.freed_bytes);
            try testing.expectEqual(@as(usize, 0), owner.physical_pending);
            try testing.expectEqual(@as(u64, 1), owner.physical_revision);
            try testing.expect(owner.routing_egress == null);
            try owner.prepareRoutingEgress(domain, 3, 256);
            try owner.disposeRoutingEgress(domain);
            try testing.expectEqual(old, fail.allocated_bytes - fail.freed_bytes);
            failures += 1;
            continue;
        };
        fail.fail_index = std.math.maxInt(usize);
        try testing.expectEqual(@as(usize, 0), owner.physical_pending);
        try testing.expectEqual(@as(u64, 1), owner.physical_revision);
        try testing.expectEqual(@as(usize, 3), owner.routing_egress.?.rows.len);
        for (owner.routing_egress.?.payloads) |byte| try testing.expectEqual(@as(u8, 0), byte);
        try owner.disposeRoutingEgress(domain);
        try testing.expectEqual(old, fail.allocated_bytes - fail.freed_bytes);
        succeeded = true;
        break;
    }
    try testing.expect(succeeded and failures == 3);
}

test "physical routing producer fence copied old epoch cannot clear current source" {
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("queue fence retained Domain");
    var owner = try MediaPlane.initFallible(testing.allocator);
    defer owner.deinit();
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("queue fence retained binding");
    try owner.prepareRoutingEgress(domain, 2, 256);
    defer owner.disposeRoutingEgress(domain) catch @panic("queue fence retained owned slots");
    const Cut = struct {
        domain: *routing.Domain,
        owner: *MediaPlane,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            const first = try ctx.owner.fenceRoutingProducersLocked(ctx.domain, scope);
            const copy = first;
            try ctx.owner.requireRoutingEgressSettledLocked(ctx.domain, scope, first);
            try ctx.owner.resumeRoutingProducersLocked(ctx.domain, scope, first);
            const second = try ctx.owner.fenceRoutingProducersLocked(ctx.domain, scope);
            try testing.expect(second != copy);
            try testing.expectError(error.InvalidFence, ctx.owner.resumeRoutingProducersLocked(ctx.domain, scope, copy));
            try testing.expect((try ctx.owner.routingEgressStateLocked(ctx.domain, scope)).fenced);
            try ctx.owner.requireRoutingEgressSettledLocked(ctx.domain, scope, second);
            try ctx.owner.resumeRoutingProducersLocked(ctx.domain, scope, second);
            const queue = ctx.owner.routing_egress.?;
            const original = queue.next_fence;
            defer queue.next_fence = original;
            queue.next_fence = std.math.maxInt(u64);
            try testing.expectError(error.SequenceExhausted, ctx.owner.fenceRoutingProducersLocked(ctx.domain, scope));
            try testing.expect(!(try ctx.owner.routingEgressStateLocked(ctx.domain, scope)).fenced);
        }
    };
    try domain.withLocked(Cut{ .domain = domain, .owner = &owner }, Cut.run);
}

test "physical prepared legacy Plane worker actual join retains exact bound socket and owned queue" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const domain = try routing.Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("legacy worker retained Domain");
    var owner = try MediaPlane.initFallible(testing.allocator);
    defer owner.deinit();
    try owner.prepareColdResources(testing.io, loopback_be, 0);
    const socket_before = try owner.socket.?.capture();
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("legacy worker retained binding");
    try owner.prepareRoutingEgress(domain, 2, 256);
    defer owner.disposeRoutingEgress(domain) catch @panic("legacy worker retained queue");
    try owner.startPreparedLegacyWorker();
    defer {
        owner.requestStopAndWake();
        owner.joinLegacyAfterStop() catch @panic("legacy worker real join");
    }
    try testing.expectError(error.Busy, owner.startPreparedLegacyWorker());
    try testing.expectError(error.Busy, owner.requireRoutingTerminal());
    owner.requestStopAndWake();
    try owner.joinLegacyAfterStop();
    try testing.expect(owner.thread == null and owner.worker_id == null and !owner.legacy_joining);
    try testing.expectEqualDeep(socket_before, try owner.socket.?.capture());
    try testing.expect(owner.routing_egress.?.pump_id == null);
    try testing.expectEqual(@as(usize, 0), owner.routing_egress.?.len);
}

const PhysicalOfferedPeerTest = struct { key: routing.EndpointKey, creds: Creds };
const PhysicalIceFixture = struct {
    domain: *routing.Domain,
    owner: *MediaPlane,
    binding: *routing.WebrtcBinding,
    fail: *testing.FailingAllocator,
    fn init(fail: *testing.FailingAllocator) !@This() {
        const domain = try routing.Domain.create(testing.allocator);
        errdefer domain.destroyQuiesced() catch unreachable;
        const owner = try testing.allocator.create(MediaPlane);
        errdefer testing.allocator.destroy(owner);
        owner.* = try MediaPlane.initFallible(fail.allocator());
        errdefer owner.deinit();
        try owner.prepareColdResources(testing.io, loopback_be, 0);
        const binding = try domain.bindWebrtc(owner);
        errdefer domain.releaseWebrtc(binding) catch unreachable;
        try owner.prepareRoutingEgress(domain, 4, 1024);
        return .{ .domain = domain, .owner = owner, .binding = binding, .fail = fail };
    }
    fn deinit(self: *@This()) void {
        self.fail.fail_index = std.math.maxInt(usize);
        self.owner.requestStopAndWake();
        self.owner.joinLegacyAfterStop() catch @panic("ICE fixture worker did not join");
        self.domain.closeForTerminal() catch @panic("ICE fixture retained operation");
        self.owner.finishRoutingTerminalCleanup(self.domain) catch unreachable;
        cleanupWebrtcTest(self.domain, self.owner, self.binding);
        self.owner.deinit();
        testing.allocator.destroy(self.owner);
        self.domain.destroyQuiesced() catch unreachable;
    }
    fn offer(self: *@This(), owner: routing.ClientId) !PhysicalOfferedPeerTest {
        const offers = try self.domain.prepareOffers("#physical-ice", owner, &.{.{ .leg = .webrtc, .mode = .legacy_group }});
        defer offers.deinit();
        const candidate = try self.owner.prepareOffer(self.domain, offers, "#physical-ice", webrtcCandidateTestProfile(), 1, null);
        defer candidate.deinit();
        const preview = candidate.preview();
        const answer: PhysicalOfferedPeerTest = .{ .key = routing.EndpointKey{ .call = preview.identity.stamp.endpoint.call, .client = owner, .leg = .webrtc }, .creds = Creds{ .ufrag = preview.ufrag.*, .pwd = preview.pwd.* } };
        try self.domain.withLocked(PublishWebrtcTest{ .domain = self.domain, .offers = offers, .candidate = candidate }, PublishWebrtcTest.run);
        return answer;
    }
    fn request(creds: *const Creds, transaction: u8) ![]u8 {
        var username: [media_transport.ufrag_len + 5]u8 = undefined;
        @memcpy(username[0..media_transport.ufrag_len], &creds.ufrag);
        @memcpy(username[media_transport.ufrag_len..], ":peer");
        return stun.buildBindingRequest(testing.allocator, @splat(transaction), .{ .username = &username, .integrity_key = &creds.pwd, .fingerprint = true });
    }
    fn paused(self: *@This(), epoch: u64) !runtime_pause.Token {
        const token = try self.owner.requestPause(epoch);
        errdefer self.owner.resumePaused(token) catch {};
        try self.owner.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        return token;
    }
};

test "physical ICE actual bound worker authenticates first binding and refuses migration collision and retired credentials" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture = try PhysicalIceFixture.init(&fail);
    defer fixture.deinit();
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 1, .slot = 0, .gen = 0 };
    var first = try fixture.offer(a);
    defer std.crypto.secureZero(u8, &first.creds.pwd);
    var sibling = try fixture.offer(b);
    defer std.crypto.secureZero(u8, &sibling.creds.pwd);
    var peer = try MediaSocket.bind(loopback_be, 0);
    defer peer.deinit();
    peer.setRecvTimeoutMs(500);
    var foreign = try MediaSocket.bind(loopback_be, 0);
    defer foreign.deinit();
    foreign.setRecvTimeoutMs(500);
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.owner.port);
    const peer_address = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, try peer.localPort());
    try fixture.owner.startPreparedLegacyWorker();
    var bad_creds = first.creds;
    defer std.crypto.secureZero(u8, &bad_creds.pwd);
    bad_creds.pwd[0] ^= 1;
    const bad_request = try PhysicalIceFixture.request(&bad_creds, 0x50);
    defer testing.allocator.free(bad_request);
    peer.sendTo(destination, bad_request);
    var invalid_response: [1024]u8 = undefined;
    try testing.expect(peer.recvFrom(&invalid_response) == null);
    {
        const pause = try fixture.paused(1);
        defer fixture.owner.resumePaused(pause) catch unreachable;
        try testing.expect(fixture.owner.physical_rows.get(first.key).?.endpoint.remote == null);
        try testing.expectEqual(@as(u64, 1), fixture.owner.next_routing_inbound);
        try testing.expectEqual(error.InvalidIngress, fixture.owner.routing_last_ingress_error.?);
    }
    const request = try PhysicalIceFixture.request(&first.creds, 0x51);
    defer testing.allocator.free(request);
    peer.sendTo(destination, request);
    var bytes: [1024]u8 = undefined;
    const response = peer.recvFrom(&bytes) orelse return error.TestUnexpectedResult;
    try testing.expect(try stun.verifyMessageIntegrity(response.data, &first.creds.pwd));
    try testing.expect(try stun.verifyFingerprint(response.data));
    var decoded = try stun.decode(testing.allocator, response.data);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    {
        const pause = try fixture.paused(2);
        defer fixture.owner.resumePaused(pause) catch unreachable;
        try testing.expectEqualDeep(@as(?TransportAddress, peer_address), fixture.owner.physical_rows.get(first.key).?.endpoint.remote);
        try testing.expectEqual(@as(u64, 2), fixture.owner.physical_rows.get(first.key).?.identity.stamp.binding_revision);
        try testing.expect(fixture.owner.routing_inbound == null);
    }
    peer.sendTo(destination, request); // legitimate repeat: binding revision stays 2
    _ = peer.recvFrom(&bytes) orelse return error.TestUnexpectedResult;
    foreign.sendTo(destination, request); // same password does not migrate an existing address
    try testing.expect(foreign.recvFrom(&bytes) == null);
    const collision = try PhysicalIceFixture.request(&sibling.creds, 0x52);
    defer testing.allocator.free(collision);
    peer.sendTo(destination, collision); // another physical owner cannot claim this exact address
    try testing.expect(peer.recvFrom(&bytes) == null);
    {
        const pause = try fixture.paused(3);
        defer fixture.owner.resumePaused(pause) catch unreachable;
        try testing.expectEqualDeep(@as(?TransportAddress, peer_address), fixture.owner.physical_rows.get(first.key).?.endpoint.remote);
        try testing.expectEqual(@as(u64, 2), fixture.owner.physical_rows.get(first.key).?.identity.stamp.binding_revision);
        try testing.expect(fixture.owner.physical_rows.get(sibling.key).?.endpoint.remote == null);
        var replacement = try fixture.offer(a);
        defer std.crypto.secureZero(u8, &replacement.creds.pwd);
        try testing.expect(!std.mem.eql(u8, &first.creds.ufrag, &replacement.creds.ufrag));
    }
    peer.sendTo(destination, request); // exact retired ICE authority never comes back
    try testing.expect(peer.recvFrom(&bytes) == null);
}

test "physical ICE response OOM leaves actual binding unchanged and same request succeeds on retry" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture = try PhysicalIceFixture.init(&fail);
    defer fixture.deinit();
    var initial = try fixture.offer(.{ .shard = 0, .slot = 0, .gen = 0 });
    defer std.crypto.secureZero(u8, &initial.creds.pwd);
    var peer = try MediaSocket.bind(loopback_be, 0);
    defer peer.deinit();
    peer.setRecvTimeoutMs(1000);
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.owner.port);
    try fixture.owner.startPreparedLegacyWorker();
    const request = try PhysicalIceFixture.request(&initial.creds, 0x63);
    defer testing.allocator.free(request);
    const first_pause = try fixture.paused(1);
    const old = rtcDigest(fixture.owner.physical_rows.get(initial.key).?);
    const old_revision = fixture.owner.physical_revision;
    // Decode consumes one attribute backing allocation. Refuse the following
    // complete response buffer, before any accepted slot/binding publication.
    fail.fail_index = fail.alloc_index + 1;
    peer.sendTo(destination, request);
    try fixture.owner.resumePaused(first_pause);
    var bytes: [1024]u8 = undefined;
    try testing.expect(peer.recvFrom(&bytes) == null);
    const second_pause = try fixture.paused(2);
    fail.fail_index = std.math.maxInt(usize);
    try testing.expect(fail.has_induced_failure);
    try testing.expectEqual(error.OutOfMemory, fixture.owner.routing_last_ingress_error.?);
    try testing.expectEqual(old_revision, fixture.owner.physical_revision);
    try testing.expectEqualSlices(u8, &old, &rtcDigest(fixture.owner.physical_rows.get(initial.key).?));
    try testing.expect(fixture.owner.routing_inbound == null);
    try testing.expectEqual(@as(u64, 1), fixture.owner.next_routing_inbound);
    try fixture.owner.resumePaused(second_pause);
    peer.sendTo(destination, request);
    const response = peer.recvFrom(&bytes) orelse return error.TestUnexpectedResult;
    try testing.expect(try stun.verifyMessageIntegrity(response.data, &initial.creds.pwd));
}

fn offerPhysicalGroupBridgeTest(fixture: *PhysicalIceFixture, channel: []const u8, id: routing.ClientId) !PhysicalOfferedPeerTest {
    const offers = try fixture.domain.prepareOffers(channel, id, &.{.{ .leg = .webrtc, .mode = .legacy_group }});
    defer offers.deinit();
    const candidate = try fixture.owner.prepareOffer(fixture.domain, offers, channel, webrtcCandidateTestProfile(), 1, null);
    defer candidate.deinit();
    const bridge = try fixture.domain.preparePhysicalBridge(offers, channel, null, candidate);
    defer bridge.deinit();
    const preview = candidate.preview();
    const answer: PhysicalOfferedPeerTest = .{ .key = routing.EndpointKey{ .call = preview.identity.stamp.endpoint.call, .client = id, .leg = .webrtc }, .creds = Creds{ .ufrag = preview.ufrag.*, .pwd = preview.pwd.* } };
    const Cut = struct {
        fixture: *PhysicalIceFixture,
        offers: *routing.PreparedOffers,
        candidate: *PreparedWebrtcOffer,
        bridge: *routing.PreparedPhysicalBridge,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.offers.validateLocked(ctx.fixture.domain, scope);
            try ctx.candidate.validateLocked(ctx.fixture.domain, scope, ctx.offers);
            try ctx.bridge.validateLocked(ctx.fixture.domain, scope, ctx.offers, null, ctx.candidate);
            ctx.candidate.commitLocked(ctx.fixture.domain, scope);
            ctx.bridge.commitLocked(ctx.fixture.domain, scope);
            ctx.offers.commitLocked(ctx.fixture.domain, scope);
        }
    };
    try fixture.domain.withLocked(Cut{ .fixture = fixture, .offers = offers, .candidate = candidate, .bridge = bridge }, Cut.run);
    return answer;
}
fn bindPhysicalGroupPeerTest(peer: *MediaSocket, destination: TransportAddress, creds: *const Creds, transaction: u8) !void {
    const request = try PhysicalIceFixture.request(creds, transaction);
    defer testing.allocator.free(request);
    peer.sendTo(destination, request);
    var response_buf: [1024]u8 = undefined;
    const response = peer.recvFrom(&response_buf) orelse return error.TestUnexpectedResult;
    try testing.expect(try stun.verifyMessageIntegrity(response.data, &creds.pwd));
    try testing.expect(try stun.verifyFingerprint(response.data));
}
test "physical WebRTC actual group worker relays and refuses foreign or unbound NACK cache access" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture = try PhysicalIceFixture.init(&fail);
    defer fixture.deinit();
    var first = try offerPhysicalGroupBridgeTest(&fixture, "#group-worker", .{ .shard = 0, .slot = 0, .gen = 0 });
    defer std.crypto.secureZero(u8, &first.creds.pwd);
    var second = try offerPhysicalGroupBridgeTest(&fixture, "#group-worker", .{ .shard = 0, .slot = 1, .gen = 0 });
    defer std.crypto.secureZero(u8, &second.creds.pwd);
    var outsider = try offerPhysicalGroupBridgeTest(&fixture, "#foreign-worker", .{ .shard = 1, .slot = 0, .gen = 0 });
    defer std.crypto.secureZero(u8, &outsider.creds.pwd);
    var unbound = try offerPhysicalGroupBridgeTest(&fixture, "#group-worker", .{ .shard = 1, .slot = 1, .gen = 0 });
    defer std.crypto.secureZero(u8, &unbound.creds.pwd);
    var a = try MediaSocket.bind(loopback_be, 0);
    defer a.deinit();
    a.setRecvTimeoutMs(500);
    var b = try MediaSocket.bind(loopback_be, 0);
    defer b.deinit();
    b.setRecvTimeoutMs(500);
    var foreign = try MediaSocket.bind(loopback_be, 0);
    defer foreign.deinit();
    foreign.setRecvTimeoutMs(500);
    var unknown = try MediaSocket.bind(loopback_be, 0);
    defer unknown.deinit();
    unknown.setRecvTimeoutMs(500);
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.owner.port);
    try fixture.owner.startPreparedLegacyWorker();
    try bindPhysicalGroupPeerTest(&b, destination, &second.creds, 0x71);
    try bindPhysicalGroupPeerTest(&a, destination, &first.creds, 0x72);
    try bindPhysicalGroupPeerTest(&foreign, destination, &outsider.creds, 0x73);
    var packet_buf: [128]u8 = undefined;
    const initial = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 1, .timestamp = 480, .ssrc = 991 }, .payload = "actual-physical-group" }, &packet_buf);
    a.sendTo(destination, initial);
    var response_buf: [1024]u8 = undefined;
    const delivered = b.recvFrom(&response_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, initial, delivered.data);
    try testing.expect(foreign.recvFrom(&response_buf) == null);
    var nack_buf: [128]u8 = undefined;
    const request = try rtcp_translate.buildNack(77, 991, &.{1}, &nack_buf);
    foreign.sendTo(destination, request);
    try testing.expect(foreign.recvFrom(&response_buf) == null);
    unknown.sendTo(destination, request);
    try testing.expect(unknown.recvFrom(&response_buf) == null);
    // A current same-call requester receives only the exact accepted publisher
    // cache. This declared group leg is a plaintext-positive transport control,
    // not a claim of DTLS/SRTP authentication or media consent.
    b.sendTo(destination, request);
    const retransmitted = b.recvFrom(&response_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, initial, retransmitted.data);
    const pause = try fixture.paused(1);
    {
        defer fixture.owner.resumePaused(pause) catch unreachable;
        try testing.expect(fixture.owner.routing_ingress_refused >= 2);
        try testing.expect(fixture.owner.routing_inbound == null);
        try testing.expect(fixture.owner.physical_rows.get(unbound.key).?.endpoint.remote == null);
        try testing.expectEqual(@as(usize, 1), fixture.owner.physical_rows.get(first.key).?.physical_cache.len(991));
    }
    // Reusing another call's accepted SSRC cannot change its source/cache join.
    const stolen = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 2, .timestamp = 960, .ssrc = 991 }, .payload = "foreign-owner" }, &packet_buf);
    foreign.sendTo(destination, stolen);
    try testing.expect(b.recvFrom(&response_buf) == null);
    const next = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 2, .timestamp = 960, .ssrc = 991 }, .payload = "original-owner-retry" }, &packet_buf);
    a.sendTo(destination, next);
    const resumed = b.recvFrom(&response_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, next, resumed.data);
}

fn fiveBlockerOfferTest(fixture: *PhysicalIceFixture, id: routing.ClientId, video: bool) !PhysicalOfferedPeerTest {
    const channel = "#five-blocker";
    const offers = try fixture.domain.prepareOffers(channel, id, &.{.{ .leg = .webrtc, .mode = .legacy_group }});
    defer offers.deinit();
    var profile = webrtcCandidateTestProfile();
    if (video) {
        profile.codecs[1] = .{ .tag = .cadencevis, .clock_rate = 90000, .params = 0 };
        profile.codec_count = 2;
    }
    const candidate = try fixture.owner.prepareOffer(fixture.domain, offers, channel, profile, if (video) 7 else 1, null);
    defer candidate.deinit();
    const bridge = try fixture.domain.preparePhysicalBridge(offers, channel, null, candidate);
    defer bridge.deinit();
    const preview = candidate.preview();
    const result: PhysicalOfferedPeerTest = .{ .key = .{ .call = preview.identity.stamp.endpoint.call, .client = id, .leg = .webrtc }, .creds = .{ .ufrag = preview.ufrag.*, .pwd = preview.pwd.* } };
    const Publish = struct {
        fixture: *PhysicalIceFixture,
        offers: *routing.PreparedOffers,
        candidate: *PreparedWebrtcOffer,
        bridge: *routing.PreparedPhysicalBridge,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.offers.validateLocked(ctx.fixture.domain, scope);
            try ctx.candidate.validateLocked(ctx.fixture.domain, scope, ctx.offers);
            try ctx.bridge.validateLocked(ctx.fixture.domain, scope, ctx.offers, null, ctx.candidate);
            ctx.candidate.commitLocked(ctx.fixture.domain, scope);
            ctx.bridge.commitLocked(ctx.fixture.domain, scope);
            ctx.offers.commitLocked(ctx.fixture.domain, scope);
        }
    };
    try fixture.domain.withLocked(Publish{ .fixture = fixture, .offers = offers, .candidate = candidate, .bridge = bridge }, Publish.run);
    return result;
}
const FiveBlockerGroupFixture = struct {
    fail: testing.FailingAllocator,
    physical: PhysicalIceFixture,
    peers: [3]MediaSocket,
    credentials: [3]PhysicalOfferedPeerTest,
    destination: TransportAddress,
    fn create(video_recipient: bool) !*@This() {
        const fixture = try testing.allocator.create(@This());
        errdefer testing.allocator.destroy(fixture);
        fixture.fail = testing.FailingAllocator.init(testing.allocator, .{});
        fixture.physical = try PhysicalIceFixture.init(&fixture.fail);
        errdefer fixture.physical.deinit();
        var opened: usize = 0;
        errdefer for (fixture.peers[0..opened]) |*peer| peer.deinit();
        var issued: usize = 0;
        errdefer for (fixture.credentials[0..issued]) |*peer| std.crypto.secureZero(u8, &peer.creds.pwd);
        for (&fixture.peers, &fixture.credentials, 0..) |*peer, *credential, n| {
            credential.* = try fiveBlockerOfferTest(&fixture.physical, .{ .shard = 0, .slot = @intCast(n), .gen = 0 }, n == 0 or (n == 1 and video_recipient) or n == 2);
            issued += 1;
            peer.* = try MediaSocket.bind(loopback_be, 0);
            opened += 1;
            peer.setRecvTimeoutMs(700);
        }
        fixture.destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.physical.owner.port);
        try fixture.physical.owner.startPreparedLegacyWorker();
        for (&fixture.peers, &fixture.credentials, 0..) |*peer, *credential, n| try bindPhysicalGroupPeerTest(peer, fixture.destination, &credential.creds, @intCast(0x81 + n));
        return fixture;
    }
    fn destroy(self: *@This()) void {
        self.physical.deinit();
        for (&self.peers, &self.credentials) |*peer, *credential| {
            peer.deinit();
            std.crypto.secureZero(u8, &credential.creds.pwd);
        }
        testing.allocator.destroy(self);
    }
};
test "physical media five-blocker causal distinct accepted SSRCs retain independent equal sequence cache" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const fixture = try FiveBlockerGroupFixture.create(true);
    defer fixture.destroy();
    var buffers: [2][128]u8 = undefined;
    const one = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 17, .timestamp = 480, .ssrc = 7001 }, .payload = "SSRC-one" }, &buffers[0]);
    const two = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 17, .timestamp = 960, .ssrc = 7002 }, .payload = "SSRC-two" }, &buffers[1]);
    var got_buf: [1024]u8 = undefined;
    for ([_][]const u8{ one, two }) |packet| {
        fixture.peers[0].sendTo(fixture.destination, packet);
        for (fixture.peers[1..]) |*peer| {
            const got = peer.recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
            try testing.expectEqualSlices(u8, packet, got.data);
        }
    }
    var nack_buf: [64]u8 = undefined;
    const request = try rtcp_translate.buildNack(77, 7001, &.{17}, &nack_buf);
    fixture.peers[1].sendTo(fixture.destination, request);
    const retry = fixture.peers[1].recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
    // Both original authenticated-by-declared-group source packets were actually
    // delivered above. Equal sequence may not replace another SSRC's history.
    try testing.expectEqualSlices(u8, one, retry.data);
}
test "physical media five-blocker causal voice recipient cannot retrieve accepted video through NACK" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const fixture = try FiveBlockerGroupFixture.create(false);
    defer fixture.destroy();
    var packet_buf: [128]u8 = undefined;
    const video = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 96, .sequence = 23, .timestamp = 900, .ssrc = 8001 }, .payload = "actual-video-cache" }, &packet_buf);
    fixture.peers[0].sendTo(fixture.destination, video);
    var got_buf: [1024]u8 = undefined;
    const accepted = fixture.peers[2].recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, video, accepted.data);
    try testing.expect(fixture.peers[1].recvFrom(&got_buf) == null);
    var nack_buf: [64]u8 = undefined;
    const request = try rtcp_translate.buildNack(77, 8001, &.{23}, &nack_buf);
    fixture.peers[1].sendTo(fixture.destination, request);
    // Sequence23 has never been emitted to this recipient; outbound replay or
    // duplicate-nonce denial cannot make this policy refusal vacuously pass.
    try testing.expect(fixture.peers[1].recvFrom(&got_buf) == null);
}
test "physical media five-blocker causal strict PLI rejects extra FCI before routing any compound member" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const fixture = try FiveBlockerGroupFixture.create(true);
    defer fixture.destroy();
    var packet_buf: [128]u8 = undefined;
    const packet = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 96, .sequence = 29, .timestamp = 900, .ssrc = 9001 }, .payload = "actual-PLI-publisher" }, &packet_buf);
    fixture.peers[0].sendTo(fixture.destination, packet);
    var got_buf: [1024]u8 = undefined;
    for (fixture.peers[1..]) |*peer| {
        const got = peer.recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, packet, got.data);
    }
    var feedback_buf: [64]u8 = undefined;
    const good = try rtcp_translate.buildKeyframeRequest(77, 9001, &feedback_buf);
    fixture.peers[1].sendTo(fixture.destination, good);
    const positive = fixture.peers[0].recvFrom(&got_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, good, positive.data);
    @memset(feedback_buf[12..16], 0);
    std.mem.writeInt(u16, feedback_buf[2..4], 3, .big);
    fixture.peers[1].sendTo(fixture.destination, feedback_buf[0..16]);
    try testing.expect(fixture.peers[0].recvFrom(&got_buf) == null);
}

test "physical media strict compound validates later feedback padding FIR and NACK count before selection" {
    var seqs: [64]u16 = undefined;
    const pli: [12]u8 = .{ 0x81, 206, 0, 2, 0, 0, 0, 77, 0, 0, 0, 9 };
    const positive = try MediaPlane.parseRoutingFeedback(&pli, &seqs);
    try testing.expectEqual(@as(u32, 9), positive.keyframe_request.media_ssrc);
    var padded: [16]u8 = @splat(0);
    @memcpy(padded[0..12], &pli);
    padded[0] |= 0x20;
    padded[3] = 3;
    padded[15] = 4;
    try testing.expectEqual(@as(u32, 9), (try MediaPlane.parseRoutingFeedback(&padded, &seqs)).keyframe_request.media_ssrc);
    padded[15] = 0;
    try testing.expectError(error.BadLength, MediaPlane.parseRoutingFeedback(&padded, &seqs));
    padded[15] = 4;
    var compound: [28]u8 = undefined;
    @memcpy(compound[0..16], &padded);
    @memcpy(compound[16..], &pli);
    try testing.expectError(error.InvalidIngress, MediaPlane.parseRoutingFeedback(&compound, &seqs));
    // A valid first feedback must not hide a malformed later member.
    @memcpy(compound[0..12], &pli);
    @memcpy(compound[12..24], &pli);
    @memset(compound[24..], 0);
    compound[15] = 3;
    try testing.expectError(error.InvalidIngress, MediaPlane.parseRoutingFeedback(&compound, &seqs));
    var fir: [20]u8 = .{ 0x84, 206, 0, 4, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0 };
    try testing.expectEqual(@as(u32, 9), (try MediaPlane.parseRoutingFeedback(&fir, &seqs)).keyframe_request.media_ssrc);
    fir[19] = 1;
    try testing.expectError(error.InvalidIngress, MediaPlane.parseRoutingFeedback(&fir, &seqs));
    fir[19] = 0;
    fir[11] = 9;
    try testing.expectError(error.InvalidIngress, MediaPlane.parseRoutingFeedback(&fir, &seqs));
    var nack: [16]u8 = undefined;
    const bytes = try rtcp_translate.buildNack(77, 9, &.{65535}, &nack);
    try testing.expectEqual(@as(u16, 65535), (try MediaPlane.parseRoutingFeedback(bytes, &seqs)).nack.seqs[0]);
    var too_small: [0]u16 = .{};
    try testing.expectError(error.InvalidIngress, MediaPlane.parseRoutingFeedback(bytes, &too_small));
    var malformed_sr: [20]u8 = @splat(0);
    @memcpy(malformed_sr[0..12], &pli);
    malformed_sr[12] = 0x80;
    malformed_sr[13] = 200;
    malformed_sr[15] = 1;
    try testing.expectError(error.BadLength, MediaPlane.parseRoutingFeedback(&malformed_sr, &seqs));
}

test "physical media NACK uses actual current recipient spatial policy and fresh recipient positive" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const fixture = try FiveBlockerGroupFixture.create(true);
    defer fixture.destroy();
    try fixture.physical.domain.setPhysicalSelection("#five-blocker", .{ .shard = 0, .slot = 1, .gen = 0 }, .{ .max_spatial = 0, .max_temporal = 7 });
    var packet: [64]u8 = undefined;
    _ = try rtp_profile.encodeHeader(.{ .payload_type = 96, .sequence = 81, .timestamp = 900, .ssrc = 8101 }, packet[0..12]);
    packet[0] |= 0x10;
    const ext = try @import("../proto/rtp_ext.zig").buildOneByteExtension(&.{.{ .id = 13, .data = &.{1} }}, packet[12..]);
    @memcpy(packet[12 + ext.len ..][0..6], "layer1");
    const bytes = packet[0 .. 18 + ext.len];
    fixture.peers[0].sendTo(fixture.destination, bytes);
    var received: [1024]u8 = undefined;
    const visible = fixture.peers[2].recvFrom(&received) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, bytes, visible.data);
    try testing.expect(fixture.peers[1].recvFrom(&received) == null);
    var request_buffer: [64]u8 = undefined;
    const nack = try rtcp_translate.buildNack(77, 8101, &.{81}, &request_buffer);
    fixture.peers[1].sendTo(fixture.destination, nack);
    try testing.expect(fixture.peers[1].recvFrom(&received) == null);
    // Receiver has never emitted this index. Only the actual source selection
    // changes; cache, source keys and sequence history stay installed.
    try fixture.physical.domain.setPhysicalSelection("#five-blocker", .{ .shard = 0, .slot = 1, .gen = 0 }, .{ .max_spatial = 1, .max_temporal = 7 });
    fixture.peers[1].sendTo(fixture.destination, nack);
    const approved = fixture.peers[1].recvFrom(&received) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, bytes, approved.data);
}
