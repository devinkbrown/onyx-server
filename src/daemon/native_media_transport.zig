// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-owned native media transport: the live UDP leg for Onyx Server's own
//! codec (CadenceVox/CadenceVis). Mirrors `media_plane.MediaPlane` (the WebRTC/UDP leg) but
//! carries `cadence_frame` datagrams instead of RTP, and forwards them through a
//! per-channel `NativeMediaLink` (stream_id → publisher → recipients).
//!
//! Per-channel isolation: each media call (channel) has its own `NativeMediaLink`
//! so media never crosses between channels. A global `stream_id → channel` index
//! lets the pump route an inbound datagram (which carries only a stream_id) to
//! the right channel's link.
//!
//! The pump thread blocks on the socket (short recv timeout to observe the stop
//! flag), and for each datagram that parses as an cadence frame: routes by
//! stream_id to the owning channel, learns the publisher's return address from
//! the datagram origin, computes the SFU forward set, and resends the SAME opaque
//! bytes to each recipient. The server NEVER encodes/decodes/transcodes — frames
//! are forwarded verbatim.
const std = @import("std");
const routing = @import("../substrate/media_routing.zig");
const capability = @import("../substrate/media_capability.zig");
const platform = @import("../substrate/platform.zig");
const rooms = @import("media_room.zig");
const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const native_media_link = @import("native_media_link.zig");
const media_bridge = @import("media_bridge.zig");
const media_socket = @import("../substrate/media_socket.zig");
const windows_udp = @import("helix/native_windows_udp_socket.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const native_feedback = @import("../substrate/native_feedback.zig");

pub const MediaSocket = media_socket.MediaSocket;
pub const TransportAddress = native_media_link.TransportAddress;
pub const MediaKind = native_media_link.MediaKind;
pub const Selection = native_media_link.Selection;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;
pub const max_datagram = media_socket.max_datagram;

/// Max participants per native call (inline forward fan-out bound).
///
/// The native (CadenceVox/CadenceVis) leg is for point-to-point / small calls; group
/// sessions go through the SFU `Room` (ceiling 256, pointer-indirected per room).
/// This `Link` is stored BY VALUE in a rehashing map, so its inline ceiling stays
/// at 64 to keep the per-entry size (and rehash memcpy cost) bounded; the
/// `[media].max_participants` runtime cap still applies (clamped to this ceiling).
pub const default_max_call_participants = 64;
pub const max_call_participants = 64;

pub const Link = native_media_link.NativeMediaLink(max_call_participants);

/// Blocking acquire on the tryLock-only `std.atomic.Mutex`. Contention is
/// near-zero (rare register/remove vs. the single pump thread), so yielding.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

pub const IngressError = routing.Error || cadence_frame.MacError || native_feedback.Error || error{ InvalidIngress, AddressDenied, AddressOwned, ProfileDenied };
/// Bytes borrow the active authenticated callback only. No raw-slice revocation
/// guarantee exists after that callback; consumers must copy before returning.
pub const IngressContent = enum { frame, feedback };
pub const AuthenticatedFrame = struct { content: IngressContent = .frame, source: routing.EndpointStamp, stream_id: u32, profile: rooms.CallProfile, kind_bits: u8, bytes: []const u8, from: TransportAddress, first_bind: bool };
const ActiveIngress = struct { content: IngressContent = .frame, domain: *routing.Domain, context: routing.IngressContext, handle: routing.IngressHandle, key: routing.EndpointKey, source: routing.EndpointStamp, from: TransportAddress, datagram: []const u8, digest: [32]u8, first_bind: bool, validated_binding: bool };
fn ingressDigest(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
fn validIngressAddress(addr: TransportAddress) bool {
    return (addr.ip_len == 4 or addr.ip_len == 16) and addr.port != 0;
}
fn ingressAddressEqual(a: TransportAddress, b: TransportAddress) bool {
    return validIngressAddress(a) and validIngressAddress(b) and a.ip_len == b.ip_len and a.port == b.port and std.mem.eql(u8, a.ip[0..a.ip_len], b.ip[0..b.ip_len]);
}

pub const NativeMediaTransport = struct {
    allocator: std.mem.Allocator,
    routing_domain: ?*routing.Domain = null,
    routing_closed: bool = false,
    routing_binding: ?*routing.NativeBinding = null,
    physical_revision: u64 = 1,
    next_ingress_serial: u64 = 1,
    routed_accepted: std.atomic.Value(u64) = .init(0),
    routed_refused: std.atomic.Value(u64) = .init(0),
    routed_errors: std.atomic.Value(u64) = .init(0),
    active_ingress: ?ActiveIngress = null,
    physical_pending: usize = 0,
    physical_endpoints: NativeEndpointMap = .empty,
    physical_streams: NativeStreamMap = .empty,
    /// channel name (owned key) -> that call's forward link.
    channels: std.StringHashMapUnmanaged(Link) = .empty,
    /// stream_id -> the channel key that owns the publisher (borrows a key from
    /// `channels`, so it is only valid while that channel entry exists).
    stream_index: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    legacy_joining: bool = false,
    worker_id: ?std.Thread.Id = null,
    runtime: runtime_pause.WorkerState = .{},
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Bound local UDP port (0 until started); advertised to native clients.
    port: u16 = 0,
    /// Runtime cap for accepted cadence datagrams.
    max_frame_bytes: usize = media_socket.max_datagram,
    /// Runtime cap reserved for upload-bearing media operations.
    max_upload_bytes: u64 = 16 * 1024 * 1024,
    /// Runtime cap for per-channel native participants below the inline ceiling.
    max_participants: usize = default_max_call_participants,
    /// Require authenticated native-media datagrams. Defaults false so legacy
    /// clients that do not append the MAC tag are still accepted.
    require_mac: bool = false,
    /// Existing stream-id PRF root, copied from LinuxServer.native_stream_key.
    mac_stream_key: [16]u8 = @splat(0),
    mac_key_configured: bool = false,
    /// Optional cross-leg sink: after forwarding a native frame to native peers,
    /// the pump hands it here to also reach the channel's WebRTC members
    /// (rewrapped to RTP). Null = native-only call (no bridging).
    cross: ?media_bridge.CrossLegSink = null,

    pub fn init(allocator: std.mem.Allocator) NativeMediaTransport {
        return initConfig(allocator, default_max_call_participants);
    }

    pub fn initConfig(allocator: std.mem.Allocator, max_participants: usize) NativeMediaTransport {
        return .{
            .allocator = allocator,
            .max_participants = @min(max_participants, max_call_participants),
        };
    }

    /// Install the cross-leg sink (call before `start`, or while stopped).
    pub fn setCrossLegSink(self: *NativeMediaTransport, sink: media_bridge.CrossLegSink) void {
        self.cross = sink;
    }

    pub fn configureMac(self: *NativeMediaTransport, stream_key: *const [16]u8, require_mac: bool) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.mac_stream_key = stream_key.*;
        self.require_mac = require_mac;
        self.mac_key_configured = true;
    }

    /// Invoke a lexical source callback only after actual current c2s FRAME
    /// authentication. The datagram borrow expires on return. Copied handles
    /// carry their own issuance serial and cannot acquire a reused active slot.
    pub fn withAuthenticatedFrameLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, from: TransportAddress, datagram: []const u8, ctx: anytype, comptime body: fn (*const routing.Locked, @TypeOf(ctx), routing.IngressHandle) anyerror!routing.FanoutResult) anyerror!routing.FanoutResult {
        const binding = self.routing_binding orelse return error.InvalidIngress;
        const context = try domain.nativeIngressContextLocked(scope, binding, self);
        const frame_bytes = try cadence_frame.authenticatedFrameBytes(datagram);
        const view = try cadence_frame.decode(frame_bytes);
        lockSpin(&self.mutex);
        const handle = self.issueAuthenticatedFrame(domain, scope, context, from, datagram, view) catch |err| {
            self.mutex.unlock();
            return err;
        };
        self.mutex.unlock();
        defer self.finishAuthenticatedFrame(handle);
        try domain.bindNativeIngressLocked(scope, handle);
        return body(scope, ctx, handle);
    }

    /// Closed v1 canonical payload admission, using the existing bridge's
    /// supported maximum of 64 NACK sequence identifiers. No trailing bytes,
    /// empty request or compiler-dependent shape is accepted here.
    pub fn feedbackTargetStream(payload: []const u8) IngressError!u32 {
        if (payload.len < 5) return error.InvalidIngress;
        switch (payload[0]) {
            1 => {
                if (payload.len < 7) return error.InvalidIngress;
                const count = std.mem.readInt(u16, payload[5..7], .big);
                if (count == 0 or count > 64 or payload.len != 7 + @as(usize, count) * 4) return error.InvalidIngress;
            },
            2 => if (payload.len != 5) return error.InvalidIngress,
            3 => if (payload.len != 18) return error.InvalidIngress,
            else => return error.InvalidIngress,
        }
        return std.mem.readInt(u32, payload[1..5], .big);
    }

    /// Genuine ONFB purpose/direction verifier; the same closed lexical slot
    /// binds original authenticated bytes and independent issuance serial.
    pub fn withAuthenticatedFeedbackLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, from: TransportAddress, datagram: []const u8, ctx: anytype, comptime body: fn (*const routing.Locked, @TypeOf(ctx), routing.IngressHandle) anyerror!routing.FanoutResult) anyerror!routing.FanoutResult {
        const binding = self.routing_binding orelse return error.InvalidIngress;
        const context = try domain.nativeIngressContextLocked(scope, binding, self);
        const envelope = try native_feedback.peekEnvelope(datagram);
        lockSpin(&self.mutex);
        const handle = self.issueAuthenticatedFeedback(domain, scope, context, from, datagram, envelope.sender_stream_id) catch |err| {
            self.mutex.unlock();
            return err;
        };
        self.mutex.unlock();
        defer self.finishAuthenticatedFrame(handle);
        try domain.bindNativeIngressLocked(scope, handle);
        return body(scope, ctx, handle);
    }
    fn issueAuthenticatedFeedback(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, context: routing.IngressContext, from: TransportAddress, datagram: []const u8, stream: u32) IngressError!routing.IngressHandle {
        if (self.routing_domain != domain or self.routing_closed or self.stop_flag.load(.acquire) or self.active_ingress != null or !validIngressAddress(from) or datagram.len > self.max_frame_bytes) return error.InvalidIngress;
        const key = self.physical_streams.get(stream) orelse return error.EndpointUnavailable;
        const row = self.physical_endpoints.get(key) orelse return error.EndpointUnavailable;
        if (row.identity.stream_id != stream or key.leg != .native) return error.InvalidIngress;
        _ = try domain.requireCurrentLocked(scope, row.identity.stamp);
        const opened = try native_feedback.openEnvelope(datagram, &row.keys.c2s_feedback);
        if (opened.sender_stream_id != stream) return error.InvalidIngress;
        _ = try feedbackTargetStream(opened.payload);
        if (row.remote) |remote| {
            if (!ingressAddressEqual(remote, from)) return error.AddressDenied;
        } else {
            var rows = self.physical_endpoints.iterator();
            while (rows.next()) |entry| if (!std.meta.eql(entry.key_ptr.*, key)) {
                if (entry.value_ptr.remote) |remote| if (ingressAddressEqual(remote, from)) return error.AddressOwned;
            };
            if (self.physical_revision == std.math.maxInt(u64)) return error.SequenceExhausted;
            try domain.preflightNativeIngressBindingLocked(scope, row.identity.stamp);
        }
        if (self.next_ingress_serial == 0 or self.next_ingress_serial == std.math.maxInt(u64)) return error.SequenceExhausted;
        const serial = self.next_ingress_serial;
        const word = @as(u256, context.domain) | (@as(u256, context.registration) << 64) | (@as(u256, context.scope) << 128) | (@as(u256, serial) << 192);
        const handle: routing.IngressHandle = @enumFromInt(word);
        self.next_ingress_serial += 1;
        self.active_ingress = .{ .content = .feedback, .domain = domain, .context = context, .handle = handle, .key = key, .source = row.identity.stamp, .from = from, .datagram = datagram, .digest = ingressDigest(datagram), .first_bind = row.remote == null, .validated_binding = false };
        return handle;
    }

    fn issueAuthenticatedFrame(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, context: routing.IngressContext, from: TransportAddress, datagram: []const u8, view: cadence_frame.MediaFrame) IngressError!routing.IngressHandle {
        if (self.routing_domain != domain or self.routing_closed or self.stop_flag.load(.acquire) or self.active_ingress != null) return error.InvalidIngress;
        if (!validIngressAddress(from) or datagram.len > self.max_frame_bytes) return error.InvalidIngress;
        const key = self.physical_streams.get(view.stream_id) orelse return error.EndpointUnavailable;
        const row = self.physical_endpoints.get(key) orelse return error.EndpointUnavailable;
        if (row.identity.stream_id != view.stream_id or key.leg != .native) return error.InvalidIngress;
        _ = try domain.requireCurrentLocked(scope, row.identity.stamp);
        _ = try cadence_frame.verifyNativeMediaMacWithKey(&row.keys.c2s_frame, datagram);
        const bit: u8 = switch (view.codec) {
            .cadencevox_audio => 1,
            .cadencevis_video => 2,
            .raw => 4,
        };
        if (row.codecs & bit == 0 or (view.codec == .cadencevox_audio and row.kind_bits & 1 == 0) or (view.codec == .cadencevis_video and row.kind_bits & 6 == 0)) return error.ProfileDenied;
        if (row.remote) |remote| {
            if (!ingressAddressEqual(remote, from)) return error.AddressDenied;
        } else {
            var rows = self.physical_endpoints.iterator();
            while (rows.next()) |entry| if (!std.meta.eql(entry.key_ptr.*, key)) {
                if (entry.value_ptr.remote) |remote| if (ingressAddressEqual(remote, from)) return error.AddressOwned;
            };
            if (self.physical_revision == std.math.maxInt(u64)) return error.SequenceExhausted;
            try domain.preflightNativeIngressBindingLocked(scope, row.identity.stamp);
        }
        if (self.next_ingress_serial == 0 or self.next_ingress_serial == std.math.maxInt(u64)) return error.SequenceExhausted;
        const serial = self.next_ingress_serial;
        const word = @as(u256, context.domain) | (@as(u256, context.registration) << 64) | (@as(u256, context.scope) << 128) | (@as(u256, serial) << 192);
        const handle: routing.IngressHandle = @enumFromInt(word);
        self.next_ingress_serial = serial + 1;
        self.active_ingress = .{ .domain = domain, .context = context, .handle = handle, .key = key, .source = row.identity.stamp, .from = from, .datagram = datagram, .digest = ingressDigest(datagram), .first_bind = row.remote == null, .validated_binding = false };
        return handle;
    }

    pub fn requireNoActiveIngressLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked) routing.Error!void {
        try domain.requireNativeBindingLocked(scope, self.routing_binding orelse return error.InvalidIdentity, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.active_ingress != null) return error.Busy;
    }

    fn finishAuthenticatedFrame(self: *NativeMediaTransport, handle: routing.IngressHandle) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.active_ingress != null and self.active_ingress.?.handle == handle);
        self.active_ingress = null;
    }

    /// Cross-file mechanical validator. Domain first resolves its own canonical
    /// source; this method verifies the actual slot/serial/bytes/MAC again.
    pub fn inspectAuthenticatedFrameLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, handle: routing.IngressHandle) IngressError!AuthenticatedFrame {
        const binding = self.routing_binding orelse return error.InvalidIngress;
        const context = try domain.nativeIngressContextLocked(scope, binding, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.inspectAuthenticatedFrame(domain, context, handle);
    }

    fn inspectAuthenticatedFrame(self: *NativeMediaTransport, domain: *routing.Domain, context: routing.IngressContext, handle: routing.IngressHandle) IngressError!AuthenticatedFrame {
        const active = self.active_ingress orelse return error.InvalidIngress;
        if (active.handle != handle or active.domain != domain or !std.meta.eql(active.context, context) or self.routing_closed or self.stop_flag.load(.acquire)) return error.InvalidIngress;
        const row = self.physical_endpoints.get(active.key) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(active.source, row.identity.stamp) or !std.meta.eql(self.physical_streams.get(row.identity.stream_id), @as(?routing.EndpointKey, active.key))) return error.InvalidIngress;
        const actual_digest = ingressDigest(active.datagram);
        if (!std.mem.eql(u8, &active.digest, &actual_digest)) return error.InvalidIngress;
        const bytes = switch (active.content) {
            .frame => frame: {
                const exact = try cadence_frame.verifyNativeMediaMacWithKey(&row.keys.c2s_frame, active.datagram);
                const decoded = try cadence_frame.decode(exact);
                if (decoded.stream_id != row.identity.stream_id) return error.InvalidIngress;
                break :frame exact;
            },
            .feedback => feedback: {
                const opened = try native_feedback.openEnvelope(active.datagram, &row.keys.c2s_feedback);
                if (opened.sender_stream_id != row.identity.stream_id) return error.InvalidIngress;
                _ = try feedbackTargetStream(opened.payload);
                break :feedback opened.payload;
            },
        };
        if (!active.first_bind and (row.remote == null or !ingressAddressEqual(row.remote.?, active.from))) return error.InvalidIngress;
        return .{ .content = active.content, .source = active.source, .stream_id = row.identity.stream_id, .profile = row.profile, .kind_bits = row.kind_bits, .bytes = bytes, .from = active.from, .first_bind = active.first_bind };
    }

    pub fn validateIngressBindingLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, handle: routing.IngressHandle) IngressError!void {
        const context = try domain.nativeIngressContextLocked(scope, self.routing_binding orelse return error.InvalidIngress, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        _ = try self.inspectAuthenticatedFrame(domain, context, handle);
        const active = &self.active_ingress.?;
        if (!active.first_bind or self.physical_revision == std.math.maxInt(u64)) return error.InvalidIngress;
        const row = self.physical_endpoints.get(active.key) orelse return error.InvalidIngress;
        if (row.remote != null) return error.InvalidIngress;
        var rows = self.physical_endpoints.iterator();
        while (rows.next()) |entry| if (!std.meta.eql(entry.key_ptr.*, active.key)) {
            if (entry.value_ptr.remote) |remote| if (ingressAddressEqual(remote, active.from)) return error.AddressOwned;
        };
        active.validated_binding = true;
    }

    pub fn commitIngressBindingLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, handle: routing.IngressHandle, observation: routing.EndpointObservation) void {
        const current = domain.requireCurrentLocked(scope, observation.stamp) catch @panic("unpublished native ingress binding");
        const context = domain.nativeIngressContextLocked(scope, self.routing_binding orelse @panic("missing native binding"), self) catch @panic("foreign native ingress binding");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const active = &self.active_ingress.?;
        std.debug.assert(active.handle == handle and active.validated_binding and active.first_bind and std.meta.eql(active.context, context));
        const row = self.physical_endpoints.getPtr(active.key).?;
        std.debug.assert(row.remote == null and std.meta.eql(row.identity.stamp, active.source) and current.stream_id == row.identity.stream_id and current.stamp.binding_revision == active.source.binding_revision + 1);
        row.remote = active.from;
        row.identity = current;
        self.physical_revision += 1;
        active.source = current.stamp;
        active.first_bind = false;
        active.validated_binding = false;
    }

    /// Mechanical source binding: no worker or live graph can be adopted by
    /// merely passing its address. Domain owns the issued canonical binding.
    pub fn requireRoutingAttachable(self: *NativeMediaTransport) routing.Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_domain != null or self.routing_binding != null or self.thread != null or self.runtime.view != null or self.channels.count() != 0 or self.stream_index.count() != 0 or self.physical_pending != 0 or self.physical_endpoints.count() != 0 or self.physical_streams.count() != 0) return error.Busy;
    }
    pub fn attachRoutingLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, binding: *routing.NativeBinding) routing.Error!void {
        try domain.requireNativeBindingLocked(scope, binding, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_domain != null or self.routing_binding != null or self.thread != null or self.runtime.view != null or self.channels.count() != 0 or self.stream_index.count() != 0 or self.physical_pending != 0 or self.physical_endpoints.count() != 0 or self.physical_streams.count() != 0) return error.Busy;
        self.routing_domain = domain;
        self.routing_binding = binding;
    }
    pub fn requireRoutingTerminal(self: *NativeMediaTransport) routing.Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.legacy_joining or self.thread != null or self.runtime.view != null or self.physical_pending != 0 or self.active_ingress != null) return error.Busy;
    }
    pub fn latchRoutingTerminal(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, binding: *routing.NativeBinding) void {
        domain.requireTerminalLocked(scope) catch @panic("terminal routing source is not closed");
        domain.requireNativeBindingLocked(scope, binding, self) catch @panic("unissued terminal source binding");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.thread == null and self.runtime.view == null);
        self.routing_closed = true;
    }
    pub fn requireRoutingReleasable(self: *NativeMediaTransport) routing.Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.legacy_joining or self.thread != null or self.runtime.view != null or self.channels.count() != 0 or self.stream_index.count() != 0 or self.physical_pending != 0 or self.physical_endpoints.count() != 0 or self.physical_streams.count() != 0 or self.active_ingress != null) return error.Busy;
    }
    pub fn detachRoutingLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, binding: *routing.NativeBinding) void {
        domain.requireNativeBindingLocked(scope, binding, self) catch @panic("unissued routing source release");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.routing_domain == domain and self.routing_binding == binding);
        self.routing_domain = null;
        self.routing_binding = null;
    }

    pub fn deinit(self: *NativeMediaTransport) void {
        if (self.routing_binding != null) @panic("routing owner must quiesce and release before deinit");
        self.runtime.requireDetached() catch @panic("managed worker must join and detach before deinit");
        self.shutdown();
        std.crypto.secureZero(u8, self.mac_stream_key[0..]);
        var it = self.channels.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.channels.deinit(self.allocator);
        self.stream_index.deinit(self.allocator);
        std.debug.assert(self.physical_pending == 0);
        var physical = self.physical_endpoints.valueIterator();
        while (physical.next()) |row| row.wipe();
        self.physical_endpoints.deinit(self.allocator);
        self.physical_streams.deinit(self.allocator);
        self.* = undefined;
    }

    /// Whether this native transport has no registered call state that would be
    /// lost by an in-place exec. A bound/idle UDP socket and configured MAC or
    /// cross-leg policy are process configuration, not an active media session.
    /// Both registries are checked under their native mutex so an unregister or
    /// pump address learn cannot race the fail-closed decision.
    pub fn upgradeContinuityReady(self: *NativeMediaTransport) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        // A configured binding alone is inert when media is disabled. The
        // successor reconstructs that binding from configuration.
        const binding_idle = self.routing_binding == null or
            (self.cross == null and self.socket == null);
        return binding_idle and self.active_ingress == null and !self.legacy_joining and
            self.channels.count() == 0 and self.stream_index.count() == 0 and
            self.physical_pending == 0 and self.physical_endpoints.count() == 0 and
            self.physical_streams.count() == 0;
    }

    /// Bind on `bind_be`:`port` (port 0 = ephemeral) and spawn the pump thread.
    /// No-op if already started.
    pub fn start(self: *NativeMediaTransport, bind_be: u32, port: u16) !void {
        if (self.routing_closed) return error.Closing;
        if (self.runtime.view != null) return error.SharedGateOwned;
        if (self.socket != null) return;
        try self.bindResources(bind_be, port);
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch |err| {
            self.socket.?.deinit();
            self.socket = null;
            self.port = 0;
            return err;
        };
    }
    fn validatePolicy(self: *const NativeMediaTransport) !void {
        if (self.max_frame_bytes == 0 or self.max_frame_bytes > max_datagram or self.max_upload_bytes == 0 or self.max_participants == 0 or self.max_participants > max_call_participants) return error.InvalidConfig;
        if (self.require_mac and !self.mac_key_configured) return error.InvalidConfig;
        if (!self.mac_key_configured) for (self.mac_stream_key) |byte| if (byte != 0) return error.InvalidConfig;
    }
    fn bindResources(self: *NativeMediaTransport, bind_be: u32, port: u16) !void {
        if (self.socket != null or self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        try self.validatePolicy();
        var sock = try MediaSocket.bind(bind_be, port);
        errdefer sock.deinit();
        const actual_port = try sock.localPort();
        sock.setRecvTimeoutMs(250);
        _ = try sock.capture();
        self.socket = sock;
        self.port = actual_port;
    }
    /// Actual bound UDP resource, no pump or Thread handle exists yet.
    pub fn prepareColdResources(self: *NativeMediaTransport, io: std.Io, bind_be: u32, port: u16) !void {
        if (self.routing_closed) return error.Closing;
        try self.bindResources(bind_be, port);
        errdefer {
            self.socket.?.deinit();
            self.socket = null;
            self.port = 0;
        }
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *NativeMediaTransport, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .native_media, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *NativeMediaTransport, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        if (self.routing_closed) return error.Closing;
        try self.runtime.validatePreparation(control, view, slot, .native_media, 0, self, dormant_spawn_options);
        if (self.legacy_joining or self.thread != null) return error.AlreadyStarted;
        const socket = if (self.socket) |*sock| sock else return error.NotPrepared;
        _ = try socket.capture();
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .native_media, 0, NativeMediaTransport, self, pumpLoop, dormant_spawn_options);
    }
    /// Signals this owner only. Runtime Control owns all actual joins.
    /// Move the actual legacy handle once, then join outside the metadata gate.
    /// Resources remain owned; terminal release cannot race the joining latch.
    /// Configured View ownership is exclusively joined by its private Control.
    /// Start only the actual already-prepared owner resource. A temporary
    /// source latch pins it through spawn; failure retains the socket/engine
    /// for the caller's complete source-owned unwind. No Control/View join.
    pub fn startPreparedLegacyWorker(self: *NativeMediaTransport) !void {
        lockSpin(&self.mutex);
        if (self.routing_closed or self.runtime.view != null or self.legacy_joining or self.thread != null or self.worker_id != null or self.physical_pending != 0) {
            self.mutex.unlock();
            return error.Busy;
        }
        if (self.socket == null) {
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

    pub fn joinLegacyAfterStop(self: *NativeMediaTransport) !void {
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

    pub fn requestStopAndWake(self: *NativeMediaTransport) void {
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
    }
    pub fn detachAfterJoined(self: *NativeMediaTransport) !void {
        try self.runtime.detachAfterJoined();
    }
    pub fn requireParked(self: *NativeMediaTransport) !void {
        try self.runtime.requireParked();
    }
    pub fn requireActivated(self: *NativeMediaTransport) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime.requireActivated();
    }
    pub fn requestPause(self: *NativeMediaTransport, epoch: u64) !runtime_pause.Token {
        return self.runtime.pause.request(epoch);
    }
    pub fn awaitPaused(self: *NativeMediaTransport, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *NativeMediaTransport, token: runtime_pause.Token) !void {
        try self.runtime.pause.resumePaused(token);
    }
    pub fn capturePaused(self: *NativeMediaTransport, token: runtime_pause.Token) !Snapshot {
        if (self.thread == null and self.runtime.view == null) return error.NotRunning;
        try self.runtime.pause.requirePaused(token);
        return self.captureCut(.paused);
    }
    /// Only the original Domain's pristine configured-media cut may use this
    /// route. The Domain lock is already held; this owner lock closes its graph
    /// and ingress high-water observation around the snapshot.
    pub fn capturePausedPristineRoutingLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, webrtc: *@import("media_plane.zig").MediaPlane, token: runtime_pause.Token) !Snapshot {
        if (self.thread == null and self.runtime.view == null) return error.NotRunning;
        try self.runtime.pause.requirePaused(token);
        try domain.requirePristineConfiguredMediaLocked(scope, self, webrtc);
        try domain.requireNativeBindingLocked(scope, self.routing_binding orelse return error.RoutingContinuityUnsupported, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_domain != domain or self.routing_closed or self.legacy_joining or
            self.stop_flag.load(.acquire) or self.physical_revision != 1 or self.next_ingress_serial != 1 or
            self.active_ingress != null or self.routed_accepted.load(.acquire) != 0 or
            self.routed_refused.load(.acquire) != 0 or self.routed_errors.load(.acquire) != 0)
            return error.ActiveMediaContinuityUnsupported;
        return self.captureCutLocked(.paused, true);
    }
    /// A detached physical DTO for a later aggregate media handoff. The caller
    /// owns the Domain cut and a genuinely parked pump; this does not authorize
    /// an active upgrade by itself.
    pub fn capturePausedPhysicalRoutingLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, token: runtime_pause.Token, allocator: std.mem.Allocator, max_bytes: usize) !PhysicalSnapshot {
        if (self.thread == null and self.runtime.view == null) return error.NotRunning;
        try self.runtime.pause.requirePaused(token);
        try domain.requireNativeBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_domain != domain or self.routing_closed or self.legacy_joining or
            self.stop_flag.load(.acquire) or self.active_ingress != null or self.physical_pending != 0)
            return error.Busy;
        return self.capturePhysicalCutLocked(allocator, max_bytes);
    }

    fn capturePhysicalCutLocked(self: *NativeMediaTransport, allocator: std.mem.Allocator, max_bytes: usize) !PhysicalSnapshot {
        var bytes = try physicalSnapshotBytes(self.physical_endpoints.count(), self.physical_streams.count(), self.channels.count(), self.stream_index.count());
        var names = self.channels.keyIterator();
        while (names.next()) |name| bytes = std.math.add(usize, bytes, name.len) catch return error.Capacity;
        if (bytes > max_bytes) return error.Capacity;

        const sorted_keys = try allocator.alloc(routing.EndpointKey, self.physical_endpoints.count());
        defer allocator.free(sorted_keys);
        var ei = self.physical_endpoints.keyIterator();
        var key_count: usize = 0;
        while (ei.next()) |key| : (key_count += 1) sorted_keys[key_count] = key.*;
        std.mem.sort(routing.EndpointKey, sorted_keys, {}, struct {
            fn less(_: void, a: routing.EndpointKey, b: routing.EndpointKey) bool {
                return endpointKeyLess(a, b);
            }
        }.less);
        const endpoints = try allocator.alloc(PhysicalSnapshot.Endpoint, self.physical_endpoints.count());
        var endpoint_count: usize = 0;
        errdefer {
            for (endpoints[0..endpoint_count]) |*row| row.wipe();
            allocator.free(endpoints);
        }
        for (sorted_keys) |key| {
            endpoints[endpoint_count] = PhysicalSnapshot.Endpoint.fromLive(key, self.physical_endpoints.getPtr(key).?);
            endpoint_count += 1;
        }

        const streams = try allocator.alloc(PhysicalSnapshot.Stream, self.physical_streams.count());
        errdefer allocator.free(streams);
        var si = self.physical_streams.iterator();
        var i: usize = 0;
        while (si.next()) |entry| : (i += 1) streams[i] = .{ .stream_id = entry.key_ptr.*, .key = entry.value_ptr.* };
        std.mem.sort(PhysicalSnapshot.Stream, streams, {}, struct {
            fn less(_: void, a: PhysicalSnapshot.Stream, b: PhysicalSnapshot.Stream) bool {
                return a.stream_id < b.stream_id;
            }
        }.less);

        const channels = try allocator.alloc(PhysicalSnapshot.Channel, self.channels.count());
        var channel_count: usize = 0;
        errdefer {
            for (channels[0..channel_count]) |row| allocator.free(row.name);
            allocator.free(channels);
        }
        var ci = self.channels.iterator();
        while (ci.next()) |entry| {
            const name = try allocator.dupe(u8, entry.key_ptr.*);
            channels[channel_count] = .{ .name = name, .link = entry.value_ptr.capture() catch |err| {
                allocator.free(name);
                return err;
            } };
            channel_count += 1;
        }
        std.mem.sort(PhysicalSnapshot.Channel, channels, {}, struct {
            fn less(_: void, a: PhysicalSnapshot.Channel, b: PhysicalSnapshot.Channel) bool {
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.less);

        const stream_index = try allocator.alloc(PhysicalSnapshot.ChannelIndex, self.stream_index.count());
        errdefer allocator.free(stream_index);
        var ii = self.stream_index.iterator();
        i = 0;
        while (ii.next()) |entry| : (i += 1) {
            // The live value must borrow the exact owned channel key. Capture
            // its ordinal, never an address that could dangle after the cut.
            const key = self.channels.getKey(entry.value_ptr.*) orelse return error.InvalidSnapshot;
            if (key.ptr != entry.value_ptr.ptr or key.len != entry.value_ptr.len) return error.InvalidSnapshot;
            stream_index[i] = .{ .stream_id = entry.key_ptr.*, .channel = try PhysicalSnapshot.channelIndex(channels, key) };
        }
        std.mem.sort(PhysicalSnapshot.ChannelIndex, stream_index, {}, struct {
            fn less(_: void, a: PhysicalSnapshot.ChannelIndex, b: PhysicalSnapshot.ChannelIndex) bool {
                return a.stream_id < b.stream_id;
            }
        }.less);
        const snapshot: PhysicalSnapshot = .{ .allocator = allocator, .endpoints = endpoints, .streams = streams, .channels = channels, .stream_index = stream_index, .physical_revision = self.physical_revision, .next_ingress_serial = self.next_ingress_serial, .routed_accepted = self.routed_accepted.load(.acquire), .routed_refused = self.routed_refused.load(.acquire), .routed_errors = self.routed_errors.load(.acquire) };
        try snapshot.validate(self.max_participants, max_bytes);
        return snapshot;
    }
    pub fn captureUnstarted(self: *NativeMediaTransport) !Snapshot {
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return self.captureCut(.unstarted);
    }
    fn captureCut(self: *NativeMediaTransport, execution: Execution) !Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.captureCutLocked(execution, false);
    }
    fn captureCutLocked(self: *NativeMediaTransport, execution: Execution, pristine_routing: bool) !Snapshot {
        if (self.routing_binding != null and !pristine_routing) return error.RoutingContinuityUnsupported;
        // Exact active forward/MAC/replay state is not approximated by an empty
        // registry. Main freezes producers while retaining this source cut.
        if (self.channels.count() != 0 or self.stream_index.count() != 0 or self.physical_pending != 0 or self.physical_endpoints.count() != 0 or self.physical_streams.count() != 0) return error.ActiveMediaContinuityUnsupported;
        try self.validatePolicy();
        const socket = if (self.socket) |*sock| sock else return error.NotPrepared;
        return .{ .socket = try socket.capture(), .max_frame_bytes = self.max_frame_bytes, .max_upload_bytes = self.max_upload_bytes, .max_participants = self.max_participants, .require_mac = self.require_mac, .mac_stream_key = self.mac_stream_key, .mac_key_configured = self.mac_key_configured, .cross_configured = self.cross != null, .execution = execution };
    }
    /// Consumes a received FD; closes only this reference on refusal. Whole
    /// owner supplies the exact reconstructed cross-leg target; callback pointers
    /// are not serialized. Key bytes live in the protected capsule and are wiped.
    pub fn initInherited(allocator: std.mem.Allocator, fd: std.posix.fd_t, carry: *const Snapshot, cross: ?media_bridge.CrossLegSink) !NativeMediaTransport {
        carry.validate() catch |err| {
            _ = std.posix.system.close(fd);
            return err;
        };
        const socket = try MediaSocket.initInherited(fd, &carry.socket);
        return initRestored(allocator, socket, carry, cross);
    }

    /// Consume an authenticated Windows UDP duplicate into an inert owner.
    /// The existing inherited-resource and dormant-worker preparation paths
    /// can then bind its runtime and park its pump before READY.
    pub fn initTransferred(allocator: std.mem.Allocator, transfer: *windows_udp.Transfer, carry: *const Snapshot, cross: ?media_bridge.CrossLegSink) !NativeMediaTransport {
        const socket = try MediaSocket.initTransferred(transfer, &carry.socket);
        return initRestored(allocator, socket, carry, cross);
    }

    fn initRestored(allocator: std.mem.Allocator, socket: MediaSocket, carry: *const Snapshot, cross: ?media_bridge.CrossLegSink) !NativeMediaTransport {
        var held = socket;
        errdefer held.deinit();
        try carry.validate();
        if (carry.cross_configured != (cross != null)) return error.ConfigMismatch;
        var owner = initConfig(allocator, carry.max_participants);
        owner.socket = held;
        owner.port = carry.socket.port;
        owner.max_frame_bytes = carry.max_frame_bytes;
        owner.max_upload_bytes = carry.max_upload_bytes;
        owner.require_mac = carry.require_mac;
        owner.mac_stream_key = carry.mac_stream_key;
        owner.mac_key_configured = carry.mac_key_configured;
        owner.cross = cross;
        return owner;
    }
    /// Binds only the runtime backend of an already validated inherited owner.
    pub fn prepareInheritedResources(self: *NativeMediaTransport, io: std.Io) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        const socket = if (self.socket) |*sock| sock else return error.NotPrepared;
        _ = try socket.capture();
        try self.runtime.pause.bindIo(io);
    }

    /// Signal the pump to stop, join it, and close the socket.
    pub fn shutdown(self: *NativeMediaTransport) void {
        lockSpin(&self.mutex);
        const held = self.legacy_joining or self.physical_pending != 0 or self.routing_binding != null;
        self.mutex.unlock();
        if (held) @panic("native resource retirement requires actual candidate disposal");
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (self.socket) |*s| {
            s.deinit();
            self.socket = null;
        }
    }

    fn pumpLoop(self: *NativeMediaTransport) void {
        lockSpin(&self.mutex);
        self.worker_id = std.Thread.getCurrentId();
        self.mutex.unlock();
        defer {
            lockSpin(&self.mutex);
            self.worker_id = null;
            self.mutex.unlock();
        }
        self.runtime.markEntered();
        defer self.runtime.markExited();
        var buf: [media_socket.max_datagram]u8 = undefined;
        var targets: [max_call_participants]TransportAddress = undefined;
        while (!self.stop_flag.load(.acquire)) {
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            const sock = &(self.socket orelse return);
            const got = sock.recvFrom(&buf) orelse continue; // timeout/idle
            // Require cadence framing so the port is not an open UDP reflector.
            if (got.data.len > self.max_frame_bytes) continue;
            if (self.routing_domain) |domain| {
                // The actual bound pump authenticates original received bytes.
                // A physical route never invokes the legacy channel-only sink.
                const Routed = struct {
                    owner: *NativeMediaTransport,
                    domain: *routing.Domain,
                    from: TransportAddress,
                    bytes: []const u8,
                    fn accepted(scope: *const routing.Locked, ctx: @This(), handle: routing.IngressHandle) anyerror!routing.FanoutResult {
                        return ctx.domain.fanoutNativeToWebrtcLocked(scope, handle);
                    }
                    fn run(scope: *routing.Locked, ctx: @This()) !routing.FanoutResult {
                        if (native_feedback.isEnvelope(ctx.bytes)) return ctx.owner.withAuthenticatedFeedbackLocked(ctx.domain, scope, ctx.from, ctx.bytes, ctx, accepted);
                        return ctx.owner.withAuthenticatedFrameLocked(ctx.domain, scope, ctx.from, ctx.bytes, ctx, accepted);
                    }
                };
                const result = domain.withLocked(Routed{ .owner = self, .domain = domain, .from = got.from, .bytes = got.data }, Routed.run) catch {
                    _ = self.routed_errors.fetchAdd(1, .monotonic);
                    continue;
                };
                _ = self.routed_accepted.fetchAdd(result.accepted, .monotonic);
                _ = self.routed_refused.fetchAdd(result.refused, .monotonic);
                continue;
            }
            if (native_feedback.isEnvelope(got.data)) {
                self.handleFeedback(got.from, got.data);
                continue;
            }
            if (got.data.len < cadence_frame.MIN_FRAME_WIRE_BYTES) continue;
            const frame_bytes = cadence_frame.authenticatedFrameBytes(got.data) catch continue;
            const view = cadence_frame.decode(frame_bytes) catch continue;

            lockSpin(&self.mutex);
            var n: usize = 0;
            var chanbuf: [256]u8 = undefined;
            var chanlen: usize = 0;
            var forward_datagram: []const u8 = &.{};
            var bridge_datagram: []const u8 = &.{};
            if (self.stream_index.get(view.stream_id)) |chan| {
                if (self.channels.getPtr(chan)) |link| {
                    if (link.idForStream(view.stream_id)) |participant| {
                        const auth_frame = self.authenticateDatagram(chan, participant, got.data) catch null;
                        if (auth_frame) |exact_frame| {
                            n = link.inboundFrom(exact_frame, got.from, &targets);
                            forward_datagram = if (got.data.len == exact_frame.len + cadence_frame.MAC_TAG_BYTES) got.data else exact_frame;
                            bridge_datagram = exact_frame;
                            // Copy the channel name out under the lock so the cross-leg
                            // sink can use it after we unlock (the key may be freed if the
                            // channel is torn down concurrently).
                            if (chan.len <= chanbuf.len) {
                                @memcpy(chanbuf[0..chan.len], chan);
                                chanlen = chan.len;
                            }
                        }
                    }
                }
            }
            self.mutex.unlock();

            for (targets[0..n]) |dst| sock.sendTo(dst, forward_datagram);

            // Bridge the same frame to any WebRTC members of this channel.
            if (chanlen != 0) {
                if (self.cross) |sink| sink.onNativeFrame(chanbuf[0..chanlen], bridge_datagram);
            }
        }
    }

    fn handleFeedback(self: *NativeMediaTransport, from: TransportAddress, datagram: []const u8) void {
        if (!self.mac_key_configured) return;
        const peek = native_feedback.peekEnvelope(datagram) catch return;

        // Pass 1 (AUTH prerequisites): resolve the channel/participant that owns
        // this stream_id and copy them out under the lock, WITHOUT mutating any
        // address-ownership trust state. The envelope is still unauthenticated, so
        // we must not bind (or otherwise trust) the source address yet.
        var channel_buf: [256]u8 = undefined;
        var channel_len: usize = 0;
        var participant_buf: [64]u8 = undefined;
        var participant_len: usize = 0;
        lockSpin(&self.mutex);
        if (self.stream_index.get(peek.sender_stream_id)) |channel| {
            if (channel.len <= channel_buf.len) {
                if (self.channels.getPtr(channel)) |link| {
                    if (link.idForStream(peek.sender_stream_id)) |participant| {
                        if (participant.len <= participant_buf.len) {
                            @memcpy(channel_buf[0..channel.len], channel);
                            channel_len = channel.len;
                            @memcpy(participant_buf[0..participant.len], participant);
                            participant_len = participant.len;
                        }
                    }
                }
            }
        }
        self.mutex.unlock();
        if (channel_len == 0 or participant_len == 0) return;

        // AUTH: verify the envelope MAC before touching any trust state. A forged
        // or short tag is dropped here, so it can never rebind the victim's
        // inbound-media return path. The lock is NOT held across openEnvelope.
        var key: [native_feedback.envelope_key_len]u8 = undefined;
        cadence_frame.deriveNativeMediaMacKey(
            &self.mac_stream_key,
            channel_buf[0..channel_len],
            participant_buf[0..participant_len],
            &key,
        );
        defer std.crypto.secureZero(u8, key[0..]);
        const opened = native_feedback.openEnvelope(datagram, &key) catch return;
        if (opened.sender_stream_id != peek.sender_stream_id) return;

        // Pass 2 (BIND): only now, on an authenticated envelope, take the lock
        // again and bind the sender's address (anti-spoofing address ownership).
        // The channel may have been torn down between passes, so re-resolve.
        lockSpin(&self.mutex);
        const bound = if (self.channels.getPtr(channel_buf[0..channel_len])) |link|
            link.bindAddressForStream(opened.sender_stream_id, from)
        else
            false;
        self.mutex.unlock();
        if (!bound) return;

        if (self.cross) |sink| _ = sink.onNativeFeedback(channel_buf[0..channel_len], opened.sender_stream_id, opened.payload);
    }

    fn authenticateDatagram(
        self: *const NativeMediaTransport,
        channel: []const u8,
        participant: []const u8,
        datagram: []const u8,
    ) cadence_frame.MacError![]const u8 {
        if (!self.mac_key_configured) {
            const exact_frame = try cadence_frame.authenticatedFrameBytes(datagram);
            if (try cadence_frame.hasAuthenticationTag(datagram)) return error.BadTag;
            if (self.require_mac) return error.MissingTag;
            return exact_frame;
        }
        return cadence_frame.acceptNativeMediaMac(&self.mac_stream_key, channel, participant, datagram, self.require_mac);
    }

    fn tagOutbound(
        self: *NativeMediaTransport,
        channel: []const u8,
        bytes: []const u8,
        out: []u8,
    ) cadence_frame.MacError![]const u8 {
        if (!self.require_mac) return bytes;
        if (!self.mac_key_configured) return error.MissingTag;

        const view = try cadence_frame.decode(bytes);
        var participant_buf: [64]u8 = undefined;
        var participant_len: usize = 0;
        lockSpin(&self.mutex);
        if (self.stream_index.get(view.stream_id)) |owner| {
            if (std.mem.eql(u8, owner, channel)) {
                if (self.channels.getPtr(channel)) |link| {
                    if (link.idForStream(view.stream_id)) |participant| {
                        if (participant.len <= participant_buf.len) {
                            @memcpy(participant_buf[0..participant.len], participant);
                            participant_len = participant.len;
                        }
                    }
                }
            }
        }
        self.mutex.unlock();
        if (participant_len == 0) return error.MissingTag;

        return cadence_frame.appendNativeMediaMac(
            &self.mac_stream_key,
            channel,
            participant_buf[0..participant_len],
            bytes,
            out,
        );
    }

    /// Prepare a physical endpoint and its fresh native master BEFORE Domain.
    /// Caller passes the actual Domain preview; final source validation binds it
    /// to the still-current owned offer candidate. No nickname-based takeover.
    pub fn prepareOffer(self: *NativeMediaTransport, domain: *routing.Domain, offers: *routing.PreparedOffers, channel: []const u8, display_nick: []const u8, profile: rooms.CallProfile, kind_bits: u8) !*PreparedNativeOffer {
        if (channel.len == 0 or channel.len > 128 or display_nick.len == 0 or display_nick.len > 64) return error.InvalidRequest;
        const codecs = try nativeCodecs(profile, kind_bits);
        const preview = offers.preview();
        var proposed: ?routing.EndpointObservation = null;
        for (preview.endpoints[0..preview.count]) |row| if (row.reference.endpoint.leg == .native) {
            proposed = row;
            break;
        };
        const identity = proposed orelse return error.EndpointUnavailable;
        const key = routing.EndpointKey{ .call = identity.reference.endpoint.call, .client = identity.reference.offering_client, .leg = .native };
        lockSpin(&self.mutex);
        if (self.routing_closed or self.routing_domain != domain or self.routing_binding == null) {
            self.mutex.unlock();
            return error.NotRoutingBound;
        }
        if (self.physical_revision == std.math.maxInt(u64)) {
            self.mutex.unlock();
            return error.SequenceExhausted;
        }
        var old = self.physical_endpoints.get(key);
        defer if (old) |*row| row.wipe();
        if (self.physical_streams.contains(identity.stream_id)) {
            self.mutex.unlock();
            return error.StreamInUse;
        }
        if (old == null) {
            var count: usize = 0;
            var it = self.physical_endpoints.keyIterator();
            while (it.next()) |current| if (std.meta.eql(current.call, key.call)) {
                count += 1;
            };
            if (count >= self.max_participants) {
                self.mutex.unlock();
                return error.Full;
            }
        }
        const row_required = std.math.add(u32, self.physical_endpoints.count(), if (old == null) 1 else 0) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        const stream_required = std.math.add(u32, self.physical_streams.count(), if (old == null) 1 else 0) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        const revision = self.physical_revision;
        const grow_rows = row_required - self.physical_endpoints.count() > self.physical_endpoints.available;
        const grow_streams = self.physical_streams.available == 0; // insert NEW before retiring OLD index
        const old_rows = nativeMapState(self.physical_endpoints);
        const old_streams = nativeMapState(self.physical_streams);
        self.physical_pending = std.math.add(usize, self.physical_pending, 1) catch {
            self.mutex.unlock();
            return error.SequenceExhausted;
        };
        self.mutex.unlock();
        errdefer self.finishPhysicalPlan();
        const plan = try self.allocator.create(NativeOfferPlan);
        plan.* = .{ .owner = self, .domain = domain, .revision = revision, .key = key, .old = old, .rows_state = old_rows, .streams_state = old_streams, .next = .{ .identity = identity, .profile = profile, .kind_bits = kind_bits, .codecs = codecs } };
        errdefer {
            if (plan.row_growth) |*map| map.deinit(self.allocator);
            if (plan.stream_growth) |*map| map.deinit(self.allocator);
            plan.wipe();
            self.allocator.destroy(plan);
        }
        plan.channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(plan.channel);
        @memcpy(plan.next.display_nick[0..display_nick.len], display_nick);
        plan.next.display_len = @intCast(display_nick.len);
        // Fresh uniform master. Failure retains OLD and never publishes creds.
        try platform.fillOsEntropy(&plan.next.master);
        plan.next.keys = try capability.derive(&plan.next.master, identity.stream_id);
        if (grow_rows) {
            plan.row_growth = .empty;
            try plan.row_growth.?.ensureTotalCapacity(self.allocator, row_required);
        }
        if (grow_streams) {
            plan.stream_growth = .empty;
            // Both the newly inserted index and still-held OLD index fit.
            const required = std.math.add(u32, stream_required, if (old != null) 1 else 0) catch return error.SequenceExhausted;
            try plan.stream_growth.?.ensureTotalCapacity(self.allocator, required);
        }
        return @ptrCast(plan);
    }
    /// Own the exact OLD credential row and conditional stream index before
    /// departure. The source-owned Domain plan is required at the final cut.
    pub fn prepareDeparture(self: *NativeMediaTransport, domain: *routing.Domain, departure: *routing.PreparedDeparture) !*PreparedNativeDeparture {
        const key = departure.ownerKey(.native);
        lockSpin(&self.mutex);
        if (self.routing_domain != domain or self.routing_binding == null) {
            self.mutex.unlock();
            return error.NotRoutingBound;
        }
        var old = self.physical_endpoints.get(key);
        defer if (old) |*row| row.wipe();
        if (old != null and !self.routing_closed and self.physical_revision == std.math.maxInt(u64)) {
            self.mutex.unlock();
            return error.SequenceExhausted;
        }
        if (!std.meta.eql(if (old) |row| @as(?routing.EndpointObservation, row.identity) else null, departure.expectedOffer(.native))) {
            self.mutex.unlock();
            return error.StaleCandidate;
        }
        if (old) |row| {
            if (!std.meta.eql(self.physical_streams.get(row.identity.stream_id), @as(?routing.EndpointKey, key))) {
                self.mutex.unlock();
                return error.StaleCandidate;
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
        const plan = try self.allocator.create(NativeDeparturePlan);
        plan.* = .{ .owner = self, .domain = domain, .key = key, .old = old, .revision = revision, .terminal = terminal, .batch_part = departure.isBatchPart() };
        return @ptrCast(plan);
    }
    pub fn prepareClientDeparture(self: *NativeMediaTransport, domain: *routing.Domain, departure: *routing.PreparedClientDeparture) !*PreparedNativeClientDeparture {
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
        const plan = try self.allocator.create(NativeClientDeparturePlan);
        errdefer self.allocator.destroy(plan);
        const parts = try self.allocator.alloc(*PreparedNativeDeparture, departure.count());
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
    fn finishPhysicalPlan(self: *NativeMediaTransport) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.physical_pending != 0);
        self.physical_pending -= 1;
    }

    // -- Main-thread registry operations (all under the mutex) --------------

    fn linkForChannel(self: *NativeMediaTransport, channel: []const u8) !*Link {
        const gop = try self.channels.getOrPut(self.allocator, channel);
        if (!gop.found_existing) {
            const key = self.allocator.dupe(u8, channel) catch |e| {
                _ = self.channels.remove(channel);
                return e;
            };
            gop.key_ptr.* = key;
            gop.value_ptr.* = Link.initConfig(self.max_participants);
        }
        return gop.value_ptr;
    }

    fn removeStreamEntriesForChannel(self: *NativeMediaTransport, channel_key: []const u8) void {
        while (true) {
            var doomed: ?u32 = null;
            var it = self.stream_index.iterator();
            while (it.next()) |e| {
                if (std.mem.eql(u8, e.value_ptr.*, channel_key)) {
                    doomed = e.key_ptr.*;
                    break;
                }
            }
            if (doomed) |sid| {
                _ = self.stream_index.remove(sid);
            } else {
                break;
            }
        }
    }

    /// Register/update a native participant in `channel` (MEDIA OFFER). `addr`
    /// may be a placeholder; the pump learns the real return path from the
    /// participant's first datagram. `stream_id` is what the publisher stamps
    /// into its cadence frames (advertised back to the client).
    pub fn register(
        self: *NativeMediaTransport,
        channel: []const u8,
        id: []const u8,
        kind: MediaKind,
        stream_id: u32,
        addr: TransportAddress,
    ) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.stream_index.get(stream_id)) |owner| {
            if (!std.mem.eql(u8, owner, channel)) return error.StreamInUse;
        }
        const link = try self.linkForChannel(channel);
        const old_stream_id = link.streamIdFor(id);
        try link.register(id, kind, stream_id, addr);
        if (old_stream_id) |old| {
            if (old != stream_id) _ = self.stream_index.remove(old);
        }
        // Index stream_id -> channel key (borrow the map's stable key pointer).
        const key = self.channels.getKey(channel).?;
        try self.stream_index.put(self.allocator, stream_id, key);
    }

    /// Remove a participant from `channel` (MEDIA LEAVE / disconnect). Drops the
    /// channel (and its stream-index entries) once the last participant leaves.
    pub fn unregister(self: *NativeMediaTransport, channel: []const u8, id: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return;
        if (link.streamIdFor(id)) |sid| _ = self.stream_index.remove(sid);
        link.unregister(id);
        if (link.count() != 0) return;

        // Last participant gone: tear the channel down. Clear stream-index
        // entries that borrow this channel's key BEFORE freeing the key.
        const key = self.channels.getKey(channel).?;
        self.removeStreamEntriesForChannel(key);
        _ = self.channels.remove(channel);
        self.allocator.free(key);
    }

    /// Set a receiver's simulcast spatial/temporal ceiling within `channel`.
    pub fn requireRoutedFrameTargetLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, expected: routing.EndpointObservation, canonical: []const u8) !void {
        try domain.requireNativeBindingLocked(scope, self.routing_binding orelse return error.InvalidIdentity, self);
        const decoded = try cadence_frame.decode(canonical);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_closed or self.stop_flag.load(.acquire)) return error.Closing;
        const row = self.physical_endpoints.get(.{ .call = expected.stamp.endpoint.call, .client = expected.stamp.offering_client, .leg = .native }) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, expected)) return error.StaleCandidate;
        try domain.requireBridgeNegotiationLocked(scope, row.identity.reference, row.profile, row.kind_bits);
        const bit: u8 = switch (decoded.codec) {
            .cadencevox_audio => 1,
            .cadencevis_video => 2,
            .raw => 4,
        };
        if (row.codecs & bit == 0 or (decoded.codec == .cadencevox_audio and row.kind_bits & 1 == 0) or (decoded.codec == .cadencevis_video and row.kind_bits & 6 == 0)) return error.ProfileDenied;
        if (decoded.band_id - cadence_frame.MEDIA_BAND_FLOOR > row.selection.max_spatial or (row.selection.max_temporal == 0 and !decoded.keyframe)) return error.LayerDenied;
    }

    pub fn requireRoutedFeedbackTargetLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, expected: routing.EndpointObservation, payload: []const u8) !void {
        try domain.requireNativeBindingLocked(scope, self.routing_binding orelse return error.InvalidIdentity, self);
        const publisher = try feedbackTargetStream(payload);
        if (publisher != expected.stream_id) return error.RouteDenied;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_closed or self.stop_flag.load(.acquire)) return error.Closing;
        const row = self.physical_endpoints.get(.{ .call = expected.stamp.endpoint.call, .client = expected.stamp.offering_client, .leg = .native }) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, expected)) return error.StaleCandidate;
        try domain.requireBridgeNegotiationLocked(scope, row.identity.reference, row.profile, row.kind_bits);
    }

    /// Actual owned Plane pump row + Domain pin select both canonical bytes
    /// and current recipient capability. Publisher header remains unchanged;
    /// every recipient receives a NEW tag under its s2c_frame subkey. The
    /// c2s key cannot validate a reflected server frame.
    pub fn sendRoutedPacketPinned(self: *NativeMediaTransport, pump: *@import("media_plane.zig").MediaPlane, ordinal: u64) !media_socket.SendDisposition {
        const domain = self.routing_domain orelse return error.InvalidIdentity;
        const target = try domain.nativeEgressTarget(self, pump, ordinal);
        const canonical = try pump.borrowNativeRoutingAttempt(ordinal);
        switch (canonical.kind) {
            .frame => {
                const decoded = try cadence_frame.decode(canonical.bytes);
                if (decoded.stream_id != canonical.source_stream) return error.InvalidIngress;
            },
            .feedback => if (try feedbackTargetStream(canonical.bytes) != target.stream_id) return error.RouteDenied,
        }
        // The genuine Domain pin excludes changes/freeing of this row/socket.
        const row = self.physical_endpoints.get(.{ .call = target.stamp.endpoint.call, .client = target.stamp.offering_client, .leg = .native }) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, target)) return error.StaleCandidate;
        const remote = row.remote orelse return error.EndpointUnavailable;
        const socket = if (self.socket) |*held| held else return error.NotPrepared;
        var out: [media_socket.max_datagram + cadence_frame.MAC_TAG_BYTES]u8 = undefined;
        const wire = switch (canonical.kind) {
            .frame => try cadence_frame.appendNativeMediaMacWithKey(&row.keys.s2c_frame, canonical.bytes, &out),
            .feedback => try native_feedback.encodeEnvelope(canonical.source_stream, canonical.bytes, &row.keys.s2c_feedback, &out),
        };
        return socket.trySendTo(remote, wire);
    }

    pub fn requirePhysicalSelectionLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, expected: routing.EndpointObservation) !void {
        try domain.requireNativeBindingLocked(scope, self.routing_binding orelse return error.NotRoutingBound, self);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.routing_closed or self.active_ingress != null or self.physical_revision == std.math.maxInt(u64)) return error.Busy;
        const row = self.physical_endpoints.get(.{ .call = expected.stamp.endpoint.call, .client = expected.stamp.offering_client, .leg = .native }) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.identity, expected)) return error.StaleCandidate;
    }
    pub fn commitPhysicalSelectionLocked(self: *NativeMediaTransport, domain: *routing.Domain, scope: *const routing.Locked, next: routing.EndpointObservation, selection: Selection) void {
        domain.requireNativeBindingLocked(scope, self.routing_binding.?, self) catch @panic("foreign selection publication");
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const row = self.physical_endpoints.getPtr(.{ .call = next.stamp.endpoint.call, .client = next.stamp.offering_client, .leg = .native }).?;
        row.identity = next;
        row.selection = selection;
        self.physical_revision += 1;
    }

    pub fn setSelection(self: *NativeMediaTransport, channel: []const u8, id: []const u8, sel: Selection) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return;
        link.setSelection(id, sel);
    }

    /// The receiver's stored ceiling, or the default (every layer) when the
    /// channel or participant has no row yet.
    pub fn selectionOf(self: *NativeMediaTransport, channel: []const u8, id: []const u8) Selection {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return .{};
        return link.selectionOf(id);
    }

    /// Send `bytes` to `dest` on the native socket. Used by the WebRTC relay's
    /// cross-leg sink to deliver cadence-rewrapped frames to native peers.
    pub fn sendTo(self: *NativeMediaTransport, channel: []const u8, dest: TransportAddress, bytes: []const u8) void {
        if (self.socket) |*s| {
            var tagged_buf: [media_socket.max_datagram]u8 = undefined;
            const out = self.tagOutbound(channel, bytes, &tagged_buf) catch return;
            s.sendTo(dest, out);
        }
    }

    /// Send a native control-plane feedback message to `dest`. This is not a
    /// cadence media frame and must not pass through media-frame MAC tagging.
    pub fn sendFeedbackTo(self: *NativeMediaTransport, dest: TransportAddress, bytes: []const u8) void {
        if (self.socket) |*s| s.sendTo(dest, bytes);
    }

    /// The learned transport address of a native participant in `channel`, or
    /// null if unknown / not yet learned (the peer hasn't published a datagram).
    pub fn remoteFor(self: *NativeMediaTransport, channel: []const u8, id: []const u8) ?TransportAddress {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return null;
        return link.addrFor(id);
    }

    pub const Stat = Link.Stat;

    /// Snapshot per-participant native transport stats for `channel` into `out`.
    pub fn statsForChannel(self: *NativeMediaTransport, channel: []const u8, out: []Stat) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return 0;
        return link.stats(out);
    }

    /// Participant count in `channel` (0 if the channel has no native call).
    pub fn countChannel(self: *NativeMediaTransport, channel: []const u8) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return 0;
        return link.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn opframe(stream_id: u32, buf: []u8) []const u8 {
    const n = cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR,
        .stream_id = stream_id,
        .sequence = 1,
        .timestamp = 0,
        .keyframe = true,
        .codec = .cadencevox_audio,
        .payload = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
    }, buf) catch unreachable;
    return buf[0..n];
}

fn taggedOpframe(stream_id: u32, key: *const [16]u8, channel: []const u8, participant: []const u8, buf: []u8) []const u8 {
    var frame_buf: [64]u8 = undefined;
    const frame = opframe(stream_id, &frame_buf);
    return cadence_frame.appendNativeMediaMac(key, channel, participant, frame, buf) catch unreachable;
}

fn mkAddr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

test "NativeMediaTransport: pump learns sender + forwards an cadence frame to the receiver" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    var bob = try MediaSocket.bind(loopback_be, 0);
    defer bob.deinit();
    bob.setRecvTimeoutMs(2000);
    const bob_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try bob.localPort());

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, bob_addr);

    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = bob.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, frame, got.data);
}

test "upgrade continuity: NativeMediaTransport ignores idle socket and gates registrations" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    try testing.expect(nmt.upgradeContinuityReady());
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.upgradeContinuityReady());

    try nmt.register("#c", "alice", .voice, 0xA11CE, .{});
    try testing.expect(!nmt.upgradeContinuityReady());
    nmt.unregister("#c", "alice");
    try testing.expect(nmt.upgradeContinuityReady());
}

test "NativeMediaTransport: required MAC drops untagged and accepts valid tagged datagrams" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const mac_key = @as([16]u8, @splat(0x5A));
    nmt.configureMac(&mac_key, true);

    try nmt.register("#secure", "alice", .voice, 100, .{});
    try nmt.register("#secure", "bob", .voice, 200, mkAddr(2, 5000));

    var fbuf: [128]u8 = undefined;
    const untagged = opframe(100, &fbuf);
    try testing.expectError(error.MissingTag, nmt.authenticateDatagram("#secure", "alice", untagged));

    const tagged = taggedOpframe(100, &mac_key, "#secure", "alice", &fbuf);
    const exact_frame = try nmt.authenticateDatagram("#secure", "alice", tagged);
    try testing.expectEqual(tagged.len - cadence_frame.MAC_TAG_BYTES, exact_frame.len);

    const link = nmt.channels.getPtr("#secure").?;
    var out: [max_call_participants]TransportAddress = undefined;
    const n = link.inboundFrom(exact_frame, mkAddr(1, 5000), &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(2, 5000)));
}

test "NativeMediaTransport: MAC flag off preserves untagged datagram behavior" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const mac_key = @as([16]u8, @splat(0x33));
    nmt.configureMac(&mac_key, false);

    try nmt.register("#compat", "alice", .voice, 100, .{});
    try nmt.register("#compat", "bob", .voice, 200, mkAddr(2, 5000));

    var fbuf: [128]u8 = undefined;
    const untagged = opframe(100, &fbuf);
    const exact_frame = try nmt.authenticateDatagram("#compat", "alice", untagged);
    try testing.expectEqualSlices(u8, untagged, exact_frame);

    const link = nmt.channels.getPtr("#compat").?;
    var out: [max_call_participants]TransportAddress = undefined;
    const n = link.inboundFrom(exact_frame, mkAddr(1, 5000), &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(2, 5000)));
}

test "NativeMediaTransport: media never crosses channels" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    // A listener registered in a DIFFERENT channel must never receive the frame.
    var other = try MediaSocket.bind(loopback_be, 0);
    defer other.deinit();
    other.setRecvTimeoutMs(400);
    const other_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try other.localPort());

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();

    try nmt.register("#a", "alice", .voice, 100, .{});
    try nmt.register("#b", "eve", .voice, 999, other_addr); // different channel

    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    try testing.expect(other.recvFrom(&rbuf) == null); // eve hears nothing
}

test "NativeMediaTransport: setSelection drops higher layers over the wire" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    var lowbw = try MediaSocket.bind(loopback_be, 0);
    defer lowbw.deinit();
    lowbw.setRecvTimeoutMs(400);
    const lowbw_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try lowbw.localPort());

    var src = try MediaSocket.bind(loopback_be, 0);
    defer src.deinit();

    try nmt.register("#v", "src", .video, 10, .{});
    try nmt.register("#v", "lowbw", .video, 11, lowbw_addr);
    nmt.setSelection("#v", "lowbw", .{ .max_spatial = 0, .max_temporal = 0 });

    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    var fbuf: [64]u8 = undefined;
    var rbuf: [media_socket.max_datagram]u8 = undefined;

    // A spatial layer-1 (band floor+1) non-keyframe must be dropped for lowbw.
    const hi = cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR + 1,
        .stream_id = 10,
        .sequence = 1,
        .timestamp = 0,
        .keyframe = false,
        .codec = .cadencevis_video,
        .payload = &[_]u8{ 1, 2, 3 },
    }, &fbuf) catch unreachable;
    src.sendTo(server_addr, fbuf[0..hi]);
    try testing.expect(lowbw.recvFrom(&rbuf) == null);

    // The base layer (band floor) is delivered.
    const base = opframe(10, &fbuf);
    src.sendTo(server_addr, base);
    const got = lowbw.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, base, got.data);
}

test "NativeMediaTransport: unregister drops the channel and frees its index" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, .{});
    try testing.expectEqual(@as(usize, 2), nmt.countChannel("#call"));

    nmt.unregister("#call", "alice");
    try testing.expectEqual(@as(usize, 1), nmt.countChannel("#call"));
    nmt.unregister("#call", "bob");
    try testing.expectEqual(@as(usize, 0), nmt.countChannel("#call"));
    // channel torn down; re-registering works cleanly (no stale key/index)
    try nmt.register("#call", "carol", .voice, 300, .{});
    try testing.expectEqual(@as(usize, 1), nmt.countChannel("#call"));
}

test "NativeMediaTransport: register enforces runtime participant cap" {
    var nmt = NativeMediaTransport.initConfig(testing.allocator, 2);
    defer nmt.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, .{});
    try testing.expectError(error.Full, nmt.register("#call", "carol", .voice, 300, .{}));
    try nmt.register("#call", "alice", .video, 400, .{});
    try testing.expectEqual(@as(usize, 2), nmt.countChannel("#call"));
}

const rtp_profile = @import("../proto/rtp_profile.zig");
const TestBridge = media_bridge.ChannelBridge(8);

const TestXCtx = struct {
    bridge: *TestBridge,
    sock: *MediaSocket, // stands in for the media_plane (WebRTC) socket

    fn onNative(ctx: *anyopaque, channel: []const u8, datagram: []const u8) void {
        _ = channel;
        const self: *TestXCtx = @ptrCast(@alignCast(ctx));
        self.bridge.fanoutNativeToWebrtc(datagram, ctx, sendVia);
    }
    fn sendVia(ctx: *anyopaque, target: *const media_bridge.Member, bytes: []const u8) void {
        const self: *TestXCtx = @ptrCast(@alignCast(ctx));
        self.sock.sendTo(target.addr, bytes);
    }
};

const TestFeedbackCtx = struct {
    sock: *MediaSocket,
    dest: TransportAddress,

    fn onNativeFrame(_: *anyopaque, _: []const u8, _: []const u8) void {}

    fn onNativeFeedback(ctx: *anyopaque, channel: []const u8, sender_stream_id: u32, feedback: []const u8) bool {
        _ = sender_stream_id;
        if (!std.mem.eql(u8, channel, "#call")) return false;
        const self: *TestFeedbackCtx = @ptrCast(@alignCast(ctx));
        self.sock.sendTo(self.dest, feedback);
        return true;
    }
};

test "NativeMediaTransport: pump bridges a native frame to a WebRTC member as RTP" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    // WebRTC receiver (mob) + the socket the sink sends RTP from (WebRTC plane).
    var mob = try MediaSocket.bind(loopback_be, 0);
    defer mob.deinit();
    mob.setRecvTimeoutMs(2000);
    const mob_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try mob.localPort());
    var wsock = try MediaSocket.bind(loopback_be, 0);
    defer wsock.deinit();

    var bridge = TestBridge.init();
    try bridge.register("mob", .{ .leg = .webrtc, .addr = mob_addr, .ssrc = 0x1234 });

    var xctx = TestXCtx{ .bridge = &bridge, .sock = &wsock };
    nmt.setCrossLegSink(.{ .ctx = &xctx, .on_native_frame = TestXCtx.onNative });
    try nmt.start(loopback_be, 0);

    try nmt.register("#call", "alice", .voice, 100, .{}); // native publisher

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();
    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    // mob receives the same opaque payload, now wrapped as RTP for its ssrc.
    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = mob.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, rtp_profile.header_len + 4), got.data.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, got.data[rtp_profile.header_len..]);
}

test "NativeMediaTransport: pump accepts authenticated native feedback envelope" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x4B));
    nmt.configureMac(&root, false);

    var capture = try MediaSocket.bind(loopback_be, 0);
    defer capture.deinit();
    capture.setRecvTimeoutMs(2000);
    const capture_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try capture.localPort());

    var feedback_ctx = TestFeedbackCtx{ .sock = &capture, .dest = capture_addr };
    nmt.setCrossLegSink(.{
        .ctx = &feedback_ctx,
        .on_native_frame = TestFeedbackCtx.onNativeFrame,
        .on_native_feedback = TestFeedbackCtx.onNativeFeedback,
    });
    try nmt.start(loopback_be, 0);

    try nmt.register("#call", "alice", .voice, 100, .{});

    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);

    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, envelope);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = capture.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, payload, got.data);
}

test "NativeMediaTransport: pump rejects native feedback with a bad tag" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x4B));
    nmt.configureMac(&root, false);

    var capture = try MediaSocket.bind(loopback_be, 0);
    defer capture.deinit();
    capture.setRecvTimeoutMs(400);
    const capture_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try capture.localPort());

    var feedback_ctx = TestFeedbackCtx{ .sock = &capture, .dest = capture_addr };
    nmt.setCrossLegSink(.{
        .ctx = &feedback_ctx,
        .on_native_frame = TestFeedbackCtx.onNativeFrame,
        .on_native_feedback = TestFeedbackCtx.onNativeFeedback,
    });
    try nmt.start(loopback_be, 0);
    try nmt.register("#call", "alice", .voice, 100, .{});

    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);

    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);
    env_buf[envelope.len - 1] ^= 0x80;

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, envelope);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    try testing.expect(capture.recvFrom(&rbuf) == null);
}

const FeedbackFlagCtx = struct {
    hits: usize = 0,
    last_stream: u32 = 0,

    fn onFrame(_: *anyopaque, _: []const u8, _: []const u8) void {}

    fn onFeedback(ctx: *anyopaque, channel: []const u8, sender_stream_id: u32, feedback: []const u8) bool {
        _ = feedback;
        if (!std.mem.eql(u8, channel, "#call")) return false;
        const self: *FeedbackFlagCtx = @ptrCast(@alignCast(ctx));
        self.hits += 1;
        self.last_stream = sender_stream_id;
        return true;
    }
};

// Regression: the native feedback path must be AUTH-THEN-BIND. A structurally
// valid envelope with a BAD tag, arriving from a WRONG source address under
// require_mac, must NOT rebind the victim's inbound-media return path. Before
// the fix `handleFeedback` bound the address (mutating trust state) off an
// unauthenticated peekEnvelope, so a forged flood right after the victim
// re-OFFERed (addr_bound reset to false) would hijack the return path.
test "NativeMediaTransport: forged feedback with a bad tag does not rebind the victim address" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x77));
    nmt.configureMac(&root, true); // hardened require_mac deployment

    // Victim registered with a placeholder address (addr_bound reset), stream 100.
    try nmt.register("#call", "alice", .voice, 100, .{});

    // Correct per-{channel,participant} key + a valid envelope, then corrupt the tag.
    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);
    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);
    env_buf[envelope.len - 1] ^= 0x80; // forge the tag

    // Attacker source address, distinct from the victim's (still-unbound) addr.
    const attacker = mkAddr(9, 9999);
    nmt.handleFeedback(attacker, envelope);

    // The victim's return path must NOT have moved to the attacker; it is still
    // the unbound placeholder.
    const bound = nmt.remoteFor("#call", "alice").?;
    try testing.expect(!bound.eql(attacker));
    try testing.expect(bound.eql(TransportAddress{}));
}

// The authenticated case is unchanged: a valid feedback envelope from the
// correct source still binds the sender's address and reaches the sink.
test "NativeMediaTransport: valid feedback from the correct source still binds and is processed" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x77));
    nmt.configureMac(&root, true);

    var ctx = FeedbackFlagCtx{};
    nmt.setCrossLegSink(.{
        .ctx = &ctx,
        .on_native_frame = FeedbackFlagCtx.onFrame,
        .on_native_feedback = FeedbackFlagCtx.onFeedback,
    });

    try nmt.register("#call", "alice", .voice, 100, .{});

    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);
    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);

    const sender = mkAddr(3, 4000);
    nmt.handleFeedback(sender, envelope);

    const bound = nmt.remoteFor("#call", "alice").?;
    try testing.expect(bound.eql(sender));
    try testing.expectEqual(@as(usize, 1), ctx.hits);
    try testing.expectEqual(@as(u32, 100), ctx.last_stream);
}

test "NativeMediaTransport: start/shutdown is clean and re-startable" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
    nmt.shutdown();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
}

pub const Execution = enum(u8) { unstarted = 0, paused = 1 };
pub const Snapshot = struct {
    socket: media_socket.Snapshot,
    max_frame_bytes: usize,
    max_upload_bytes: u64,
    max_participants: usize,
    require_mac: bool,
    mac_stream_key: [16]u8,
    mac_key_configured: bool,
    cross_configured: bool,
    execution: Execution,
    pub fn deinit(self: *Snapshot) void {
        std.crypto.secureZero(u8, &self.mac_stream_key);
        self.* = undefined;
    }
    pub fn validateConfiguration(self: *const Snapshot, expected: Policy) !void {
        try self.validate();
        const actual: Policy = .{ .max_frame_bytes = self.max_frame_bytes, .max_upload_bytes = self.max_upload_bytes, .max_participants = self.max_participants, .require_mac = self.require_mac, .mac_stream_key = self.mac_stream_key, .mac_key_configured = self.mac_key_configured, .cross_configured = self.cross_configured };
        if (!std.meta.eql(actual, expected)) return error.ConfigMismatch;
    }
    pub fn validate(self: *const Snapshot) !void {
        try self.socket.validate();
        if (self.max_frame_bytes == 0 or self.max_frame_bytes > media_socket.max_datagram or self.max_participants == 0 or self.max_participants > max_call_participants or self.max_upload_bytes == 0) return error.InvalidSnapshot;
        if (self.require_mac and !self.mac_key_configured) return error.InvalidSnapshot;
        if (!self.mac_key_configured) for (self.mac_stream_key) |byte| if (byte != 0) return error.InvalidSnapshot;
    }
};

test "Windows Helix native media imports idle socket and parks inherited worker" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var source = NativeMediaTransport.init(testing.allocator);
    defer source.deinit();
    source.configureMac(&@as([16]u8, @splat(0x5a)), true);
    source.max_upload_bytes = 3456;
    try source.prepareColdResources(testing.io, loopback_be, 0);
    var carry = try source.captureUnstarted();
    defer carry.deinit();
    const source_fd = source.socket.?.fd;

    var transfer = try windows_udp.duplicateForProcess(source_fd, std.os.windows.GetCurrentProcessId());
    var successor = try NativeMediaTransport.initTransferred(testing.allocator, &transfer, &carry, null);
    defer successor.deinit();
    try testing.expect(transfer.consumed);
    try testing.expect(successor.socket.?.fd != source_fd);
    try testing.expectEqual(carry.socket.port, successor.port);
    try testing.expectEqual(carry.socket.recv_timeout_ms, successor.socket.?.recv_timeout_ms);
    var restored = try successor.captureUnstarted();
    defer restored.deinit();
    try testing.expectEqualSlices(u8, &carry.mac_stream_key, &restored.mac_stream_key);
    try testing.expectEqual(carry.max_upload_bytes, restored.max_upload_bytes);
    try testing.expectEqualDeep(carry.socket, try source.socket.?.capture());

    try successor.prepareInheritedResources(testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .native_media, .instance = 0, .owner_identity = &successor }};
    const gate = try runtime_pause.start_gate.create(testing.allocator, testing.io, &specs);
    defer {
        successor.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        successor.detachAfterJoined() catch unreachable;
        gate.control.destroyJoined();
    }
    try successor.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.native_media, 0, &successor));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try successor.requireParked();
    try testing.expect(!successor.runtime.entered.load(.acquire));

    var invalid = carry;
    defer invalid.deinit();
    invalid.max_frame_bytes = 0;
    var rejected = try windows_udp.duplicateForProcess(source_fd, std.os.windows.GetCurrentProcessId());
    try testing.expectError(error.InvalidSnapshot, NativeMediaTransport.initTransferred(testing.allocator, &rejected, &invalid, null));
    try testing.expect(rejected.consumed);
    try testing.expectEqualDeep(carry.socket, try source.socket.?.capture());
}

test "companion runtime native media actual pump idle MAC snapshot active refusal and owned socket" {
    // Raw-fd fcntl has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var owner = NativeMediaTransport.init(testing.allocator);
    var owner_live = true;
    defer if (owner_live) owner.deinit();
    owner.configureMac(&@as([16]u8, @splat(0x73)), true);
    owner.max_upload_bytes = 3456;
    try owner.prepareColdResources(testing.io, loopback_be, 0);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .native_media, .instance = 0, .owner_identity = &owner }};
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
    try owner.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.native_media, 0, &owner));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    gate.control.releaseAll();
    try owner.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try owner.requireActivated();
    var carry = try owner.capturePaused(token);
    defer carry.deinit();
    var configured: Policy = .{ .max_frame_bytes = max_datagram, .max_upload_bytes = 3456, .max_participants = max_call_participants, .require_mac = true, .mac_stream_key = @splat(0x73), .mac_key_configured = true, .cross_configured = false };
    try carry.validateConfiguration(configured);
    configured.require_mac = false;
    try testing.expectError(error.ConfigMismatch, carry.validateConfiguration(configured));
    const sys = std.posix.system;
    const arg: if (@import("builtin").os.tag == .linux) usize else c_int = 0;
    const fd = sys.fcntl(owner.socket.?.fd, (if (@import("builtin").os.tag == .openbsd) @as(c_int, 10) else std.posix.F.DUPFD_CLOEXEC), arg);
    try testing.expect(std.posix.errno(fd) == .SUCCESS);
    var successor = try NativeMediaTransport.initInherited(testing.allocator, @intCast(fd), &carry, null);
    successor.deinit();
    try testing.expectEqualDeep(carry.socket, try owner.socket.?.capture());
    try testing.expectEqual(@as(u64, 3456), carry.max_upload_bytes);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0x73)), &carry.mac_stream_key);
    try owner.register("#active", "alice", .voice, 10, .{});
    try testing.expectError(error.ActiveMediaContinuityUnsupported, owner.capturePaused(token));
    owner.unregister("#active", "alice");
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
    max_participants: usize,
    require_mac: bool,
    mac_stream_key: [16]u8,
    mac_key_configured: bool,
    cross_configured: bool,
};

const NativeEndpoint = struct {
    selection: Selection = .{},
    profile: rooms.CallProfile,
    identity: routing.EndpointObservation,
    kind_bits: u8,
    codecs: u8,
    master: [32]u8 = @splat(0),
    keys: capability.Keys = .{ .c2s_frame = @splat(0), .s2c_frame = @splat(0), .c2s_feedback = @splat(0), .s2c_feedback = @splat(0) },
    remote: ?TransportAddress = null,
    display_nick: [64]u8 = @splat(0),
    display_len: u8 = 0,
    fn wipe(self: *NativeEndpoint) void {
        std.crypto.secureZero(u8, &self.master);
        self.keys.wipe();
    }
};
fn nativeEndpointEqual(a: ?NativeEndpoint, b: ?NativeEndpoint) bool {
    if (a == null or b == null) return a == null and b == null;
    const x = a.?;
    const y = b.?;
    return x.profile.eql(y.profile) and std.meta.eql(x.identity, y.identity) and
        x.kind_bits == y.kind_bits and x.codecs == y.codecs and std.meta.eql(x.selection, y.selection) and
        std.mem.eql(u8, &x.master, &y.master) and std.meta.eql(x.keys, y.keys) and
        std.meta.eql(x.remote, y.remote) and x.display_len == y.display_len and
        std.mem.eql(u8, &x.display_nick, &y.display_nick);
}
const NativeEndpointMap = std.AutoHashMapUnmanaged(routing.EndpointKey, NativeEndpoint);
const NativeStreamMap = std.AutoHashMapUnmanaged(u32, routing.EndpointKey);
fn endpointKeyLess(a: routing.EndpointKey, b: routing.EndpointKey) bool {
    if (a.call.domain.serial != b.call.domain.serial) return a.call.domain.serial < b.call.domain.serial;
    if (a.call.serial != b.call.serial) return a.call.serial < b.call.serial;
    if (a.client.shard != b.client.shard) return a.client.shard < b.client.shard;
    if (a.client.slot != b.client.slot) return a.client.slot < b.client.slot;
    if (a.client.gen != b.client.gen) return a.client.gen < b.client.gen;
    return @intFromEnum(a.leg) < @intFromEnum(b.leg);
}
fn physicalSnapshotBytes(endpoints: usize, streams: usize, channels: usize, indexes: usize) !usize {
    var bytes: usize = 0;
    inline for (.{ .{ endpoints, @sizeOf(PhysicalSnapshot.Endpoint) }, .{ streams, @sizeOf(PhysicalSnapshot.Stream) }, .{ channels, @sizeOf(PhysicalSnapshot.Channel) }, .{ indexes, @sizeOf(PhysicalSnapshot.ChannelIndex) } }) |part| {
        bytes = std.math.add(usize, bytes, std.math.mul(usize, part[0], part[1]) catch return error.Capacity) catch return error.Capacity;
    }
    return bytes;
}

/// Logical native UDP state only. Every key and credential is owned; no live
/// map pointer, socket, Domain authority, or raw map backing crosses this DTO.
/// The aggregate Helix graph must independently join these rows to its Domain.
pub const PhysicalSnapshot = struct {
    pub const Endpoint = struct {
        key: routing.EndpointKey,
        selection: Selection,
        profile: rooms.CallProfile,
        identity: routing.EndpointObservation,
        kind_bits: u8,
        codecs: u8,
        master: [32]u8,
        keys: capability.Keys,
        remote: ?TransportAddress,
        display_nick: [64]u8,
        display_len: u8,

        fn fromLive(key: routing.EndpointKey, live: *const NativeEndpoint) Endpoint {
            // CallProfile's unused inline tail is undefined in live rows. Give
            // the DTO a canonical, fully initialized tail before encoding.
            var profile: rooms.CallProfile = .{ .codecs = @splat(.{ .tag = .raw, .clock_rate = 0, .params = 0 }), .codec_count = live.profile.codec_count, .fec = live.profile.fec };
            if (profile.codec_count <= rooms.max_profile_codecs) @memcpy(profile.codecs[0..profile.codec_count], live.profile.codecs[0..profile.codec_count]);
            return .{ .key = key, .selection = live.selection, .profile = profile, .identity = live.identity, .kind_bits = live.kind_bits, .codecs = live.codecs, .master = live.master, .keys = live.keys, .remote = live.remote, .display_nick = live.display_nick, .display_len = live.display_len };
        }
        fn toLive(self: Endpoint) NativeEndpoint {
            return .{ .selection = self.selection, .profile = self.profile, .identity = self.identity, .kind_bits = self.kind_bits, .codecs = self.codecs, .master = self.master, .keys = self.keys, .remote = self.remote, .display_nick = self.display_nick, .display_len = self.display_len };
        }
        fn wipe(self: *Endpoint) void {
            std.crypto.secureZero(u8, &self.master);
            self.keys.wipe();
        }
        fn validate(self: *const Endpoint) !void {
            const identity = self.identity;
            if (self.key.leg != .native or identity.stream_id == 0 or
                !std.meta.eql(identity.reference.endpoint, identity.stamp.endpoint) or
                !std.meta.eql(identity.reference.offering_client, identity.stamp.offering_client) or
                !std.meta.eql(self.key.call, identity.reference.endpoint.call) or
                !std.meta.eql(self.key.client, identity.reference.offering_client) or
                identity.reference.endpoint.leg != .native or self.display_len > self.display_nick.len)
                return error.InvalidSnapshot;
            for (self.display_nick[self.display_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
            if (self.profile.codec_count == 0 or self.profile.codec_count > rooms.max_profile_codecs) return error.InvalidSnapshot;
            for (self.profile.codecs[self.profile.codec_count..]) |codec| {
                if (codec.tag != .raw or codec.clock_rate != 0 or codec.params != 0) return error.InvalidSnapshot;
            }
            if (self.codecs != (nativeCodecs(self.profile, self.kind_bits) catch return error.InvalidSnapshot)) return error.InvalidSnapshot;
            if (self.remote) |addr| {
                if (!validIngressAddress(addr)) return error.InvalidSnapshot;
                for (addr.ip[addr.ip_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
            }
            var expected = try capability.derive(&self.master, identity.stream_id);
            defer expected.wipe();
            if (!std.meta.eql(expected, self.keys)) return error.InvalidSnapshot;
        }
    };
    pub const Stream = struct { stream_id: u32, key: routing.EndpointKey };
    pub const Channel = struct { name: []u8, link: Link.Snapshot };
    pub const ChannelIndex = struct { stream_id: u32, channel: usize };

    allocator: std.mem.Allocator,
    endpoints: []Endpoint,
    streams: []Stream,
    channels: []Channel,
    stream_index: []ChannelIndex,
    physical_revision: u64,
    next_ingress_serial: u64,
    routed_accepted: u64,
    routed_refused: u64,
    routed_errors: u64,

    pub fn deinit(self: *PhysicalSnapshot) void {
        for (self.endpoints) |*row| row.wipe();
        for (self.channels) |row| self.allocator.free(row.name);
        self.allocator.free(self.endpoints);
        self.allocator.free(self.streams);
        self.allocator.free(self.channels);
        self.allocator.free(self.stream_index);
        self.* = undefined;
    }
    fn endpointIndex(self: *const PhysicalSnapshot, key: routing.EndpointKey) !usize {
        var lo: usize = 0;
        var hi = self.endpoints.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (std.meta.eql(self.endpoints[mid].key, key)) return mid;
            if (endpointKeyLess(self.endpoints[mid].key, key)) lo = mid + 1 else hi = mid;
        }
        return error.InvalidSnapshot;
    }
    fn channelIndex(channels: []const Channel, name: []const u8) !usize {
        var lo: usize = 0;
        var hi = channels.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, channels[mid].name, name)) {
                .eq => return mid,
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return error.InvalidSnapshot;
    }
    fn streamIndex(self: *const PhysicalSnapshot, stream_id: u32) !usize {
        var lo: usize = 0;
        var hi = self.streams.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.streams[mid].stream_id == stream_id) return mid;
            if (self.streams[mid].stream_id < stream_id) lo = mid + 1 else hi = mid;
        }
        return error.InvalidSnapshot;
    }
    pub fn validate(self: *const PhysicalSnapshot, expected_max_participants: usize, max_bytes: usize) !void {
        if (self.physical_revision == 0 or self.next_ingress_serial == 0 or expected_max_participants == 0 or expected_max_participants > max_call_participants or self.streams.len != self.endpoints.len) return error.InvalidSnapshot;
        var bytes = try physicalSnapshotBytes(self.endpoints.len, self.streams.len, self.channels.len, self.stream_index.len);
        var call_participants: usize = 0;
        for (self.endpoints, 0..) |*row, i| {
            if (i != 0 and !endpointKeyLess(self.endpoints[i - 1].key, row.key)) return error.InvalidSnapshot;
            if (i == 0 or !std.meta.eql(self.endpoints[i - 1].key.call, row.key.call)) call_participants = 0;
            call_participants += 1;
            if (call_participants > expected_max_participants) return error.InvalidSnapshot;
            try row.validate();
            const stream = self.streams[try self.streamIndex(row.identity.stream_id)];
            if (!std.meta.eql(stream.key, row.key)) return error.InvalidSnapshot;
        }
        for (self.streams, 0..) |row, i| {
            if (i != 0 and self.streams[i - 1].stream_id >= row.stream_id) return error.InvalidSnapshot;
            const endpoint = self.endpoints[try self.endpointIndex(row.key)];
            if (endpoint.identity.stream_id != row.stream_id) return error.InvalidSnapshot;
        }
        for (self.channels, 0..) |row, i| {
            if (i != 0 and std.mem.order(u8, self.channels[i - 1].name, row.name) != .lt) return error.InvalidSnapshot;
            try row.link.validate(expected_max_participants);
            bytes = std.math.add(usize, bytes, row.name.len) catch return error.Capacity;
        }
        for (self.stream_index, 0..) |row, i| {
            if (i != 0 and self.stream_index[i - 1].stream_id >= row.stream_id) return error.InvalidSnapshot;
            if (row.channel >= self.channels.len) return error.InvalidSnapshot;
            var found = false;
            for (self.channels[row.channel].link.entries[0..self.channels[row.channel].link.len]) |entry| {
                if (entry.stream_id == row.stream_id) {
                    found = true;
                    break;
                }
            }
            if (!found) return error.InvalidSnapshot;
        }
        if (bytes > max_bytes) return error.Capacity;
    }

    /// Build disjoint maps first. The aggregate may publish them only after its
    /// own Domain and companion-owner cross-checks; no owner is mutated here.
    fn prepareRestore(self: *const PhysicalSnapshot, allocator: std.mem.Allocator, expected_max_participants: usize, max_bytes: usize) !PhysicalState {
        try self.validate(expected_max_participants, max_bytes);
        var candidate = PhysicalState{ .allocator = allocator, .physical_revision = self.physical_revision, .next_ingress_serial = self.next_ingress_serial, .routed_accepted = self.routed_accepted, .routed_refused = self.routed_refused, .routed_errors = self.routed_errors };
        errdefer candidate.deinit();
        try candidate.endpoints.ensureTotalCapacity(allocator, @intCast(self.endpoints.len));
        try candidate.streams.ensureTotalCapacity(allocator, @intCast(self.streams.len));
        try candidate.channels.ensureTotalCapacity(allocator, @intCast(self.channels.len));
        try candidate.stream_index.ensureTotalCapacity(allocator, @intCast(self.stream_index.len));
        for (self.endpoints) |row| candidate.endpoints.putAssumeCapacity(row.key, row.toLive());
        for (self.streams) |row| candidate.streams.putAssumeCapacity(row.stream_id, row.key);
        for (self.channels) |row| {
            const name = try allocator.dupe(u8, row.name);
            errdefer allocator.free(name);
            const link = try Link.prepareRestore(&row.link, expected_max_participants);
            candidate.channels.putAssumeCapacity(name, link);
        }
        for (self.stream_index) |row| {
            const key = candidate.channels.getKey(self.channels[row.channel].name).?;
            candidate.stream_index.putAssumeCapacity(row.stream_id, key);
        }
        return candidate;
    }
};
const PhysicalState = struct {
    allocator: std.mem.Allocator,
    endpoints: NativeEndpointMap = .empty,
    streams: NativeStreamMap = .empty,
    channels: std.StringHashMapUnmanaged(Link) = .empty,
    stream_index: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    physical_revision: u64,
    next_ingress_serial: u64,
    routed_accepted: u64,
    routed_refused: u64,
    routed_errors: u64,
    fn deinit(self: *PhysicalState) void {
        var endpoints = self.endpoints.valueIterator();
        while (endpoints.next()) |row| row.wipe();
        self.endpoints.deinit(self.allocator);
        self.streams.deinit(self.allocator);
        var names = self.channels.keyIterator();
        while (names.next()) |name| self.allocator.free(name.*);
        self.channels.deinit(self.allocator);
        self.stream_index.deinit(self.allocator);
        self.* = undefined;
    }
};

fn populateNativePhysicalDtoFixture(owner: *NativeMediaTransport) !routing.EndpointKey {
    const key: routing.EndpointKey = .{ .call = .{ .domain = .{ .serial = 17 }, .serial = 29 }, .client = .{ .shard = 2, .slot = 3, .gen = 4 }, .leg = .native };
    const endpoint: routing.EndpointId = .{ .call = key.call, .serial = 31, .leg = .native };
    const identity: routing.EndpointObservation = .{
        .reference = .{ .endpoint = endpoint, .offering_client = key.client, .bridge_policy_revision = 5 },
        .stamp = .{ .endpoint = endpoint, .binding_revision = 6, .security_revision = 7, .offering_client = key.client },
        .stream_id = 401,
        .mode = .legacy_group,
    };
    var row: NativeEndpoint = .{ .profile = candidateTestProfile(), .identity = identity, .kind_bits = 1, .codecs = 1, .master = @splat(0x5a) };
    defer row.wipe();
    row.keys = try capability.derive(&row.master, identity.stream_id);
    row.remote = mkAddr(9, 9001);
    @memcpy(row.display_nick[0..5], "alice");
    row.display_len = 5;
    try owner.physical_endpoints.put(owner.allocator, key, row);
    try owner.physical_streams.put(owner.allocator, identity.stream_id, key);
    try owner.register("#one", "alice", .voice, 401, mkAddr(1, 8001));
    try owner.register("#one", "bob", .voice, 402, mkAddr(2, 8002));
    try owner.register("#two", "carol", .voice, 403, mkAddr(3, 8003));
    // register can commit the Link before a fallible index put. Keep the real
    // negative routing state rather than inferring index entries from Link.
    _ = owner.stream_index.remove(402);
    owner.channels.getPtr("#one").?.entries[0].rx_packets = 11;
    owner.channels.getPtr("#one").?.entries[0].rx_bytes = 155;
    owner.physical_revision = 19;
    owner.next_ingress_serial = 23;
    owner.routed_accepted.store(7, .release);
    owner.routed_refused.store(8, .release);
    owner.routed_errors.store(9, .release);
    return key;
}

test "native physical DTO preserves endpoint keys, credentials, indexes, and link counters" {
    var source = NativeMediaTransport.init(testing.allocator);
    defer source.deinit();
    const key = try populateNativePhysicalDtoFixture(&source);
    const source_name = source.channels.getKey("#one").?.ptr;
    const source_master = source.physical_endpoints.get(key).?.master;
    var carry = try source.capturePhysicalCutLocked(testing.allocator, 1 << 20);
    defer carry.deinit();
    try testing.expectEqual(@as(usize, 1), carry.endpoints.len);
    try testing.expectEqual(@as(usize, 1), carry.streams.len);
    try testing.expectEqual(@as(usize, 2), carry.channels.len);
    try testing.expectEqual(@as(usize, 2), carry.stream_index.len);
    var restored = try carry.prepareRestore(testing.allocator, source.max_participants, 1 << 20);
    defer restored.deinit();
    try testing.expect(nativeEndpointEqual(source.physical_endpoints.get(key), restored.endpoints.get(key)));
    try testing.expectEqualDeep(source_master, restored.endpoints.get(key).?.master);
    try testing.expect(restored.channels.getKey("#one").?.ptr != source_name);
    try testing.expectEqual(@as(u32, 1), restored.streams.count());
    try testing.expectEqual(@as(u32, 2), restored.stream_index.count());
    try testing.expect(restored.stream_index.get(402) == null);
    const indexed_name = restored.stream_index.get(401).?;
    try testing.expect(indexed_name.ptr == restored.channels.getKey("#one").?.ptr);
    try testing.expectEqual(@as(u64, 11), restored.channels.getPtr("#one").?.entries[0].rx_packets);
    try testing.expectEqual(@as(u64, 155), restored.channels.getPtr("#one").?.entries[0].rx_bytes);
    try testing.expectEqual(@as(u64, 19), restored.physical_revision);
    try testing.expectEqual(@as(u64, 23), restored.next_ingress_serial);
    try testing.expectEqual(@as(u64, 7), restored.routed_accepted);
    try testing.expectEqual(@as(u64, 8), restored.routed_refused);
    try testing.expectEqual(@as(u64, 9), restored.routed_errors);
    try testing.expectEqualDeep(source_master, source.physical_endpoints.get(key).?.master);
}

test "native physical DTO rejects forged credentials, indexes, and over-budget state" {
    var source = NativeMediaTransport.init(testing.allocator);
    defer source.deinit();
    _ = try populateNativePhysicalDtoFixture(&source);
    var carry = try source.capturePhysicalCutLocked(testing.allocator, 1 << 20);
    defer carry.deinit();
    try testing.expectError(error.Capacity, carry.validate(source.max_participants, 1));
    const original_key = carry.endpoints[0].keys.c2s_frame[0];
    carry.endpoints[0].keys.c2s_frame[0] ^= 1;
    try testing.expectError(error.InvalidSnapshot, carry.validate(source.max_participants, 1 << 20));
    carry.endpoints[0].keys.c2s_frame[0] = original_key;
    const original_index = carry.stream_index[0].channel;
    carry.stream_index[0].channel = carry.channels.len;
    try testing.expectError(error.InvalidSnapshot, carry.prepareRestore(testing.allocator, source.max_participants, 1 << 20));
    carry.stream_index[0].channel = original_index;
    const original_stream = carry.streams[0].stream_id;
    carry.streams[0].stream_id += 1;
    try testing.expectError(error.InvalidSnapshot, carry.validate(source.max_participants, 1 << 20));
    carry.streams[0].stream_id = original_stream;
    try carry.validate(source.max_participants, 1 << 20);
}

fn nativePhysicalDtoOom(allocator: std.mem.Allocator) !void {
    var source = NativeMediaTransport.init(testing.allocator);
    defer source.deinit();
    const key = try populateNativePhysicalDtoFixture(&source);
    const original_name = source.channels.getKey("#one").?.ptr;
    const original_keys = source.physical_endpoints.get(key).?.keys;
    var carry = source.capturePhysicalCutLocked(allocator, 1 << 20) catch |err| {
        try testing.expect(source.channels.getKey("#one").?.ptr == original_name);
        try testing.expectEqualDeep(original_keys, source.physical_endpoints.get(key).?.keys);
        var retry = try source.capturePhysicalCutLocked(testing.allocator, 1 << 20);
        defer retry.deinit();
        return err;
    };
    defer carry.deinit();
    var candidate = carry.prepareRestore(allocator, source.max_participants, 1 << 20) catch |err| {
        var retry = try carry.prepareRestore(testing.allocator, source.max_participants, 1 << 20);
        defer retry.deinit();
        return err;
    };
    defer candidate.deinit();
    try testing.expect(source.channels.getKey("#one").?.ptr == original_name);
    try testing.expectEqualDeep(original_keys, source.physical_endpoints.get(key).?.keys);
}
test "native physical DTO allocation failures leave source and snapshot retryable" {
    try testing.checkAllAllocationFailures(testing.allocator, nativePhysicalDtoOom, .{});
}
const NativeMapState = struct { metadata: usize, count: u32, capacity: u32 };
fn nativeMapState(map: anytype) NativeMapState {
    return .{ .metadata = if (map.metadata) |ptr| @intFromPtr(ptr) else 0, .count = map.count(), .capacity = map.capacity() };
}
fn nativeCodecs(profile: rooms.CallProfile, kind_bits: u8) !u8 {
    if (profile.codec_count == 0 or profile.codec_count > rooms.max_profile_codecs or kind_bits == 0 or kind_bits & ~@as(u8, 7) != 0) return error.InvalidProfile;
    var bits: u8 = 0;
    for (profile.slice()) |codec| switch (codec.tag) {
        .cadencevox => {
            if (kind_bits & 1 == 0) return error.InvalidProfile;
            bits |= 1;
        },
        .cadencevis => {
            if (kind_bits & 6 == 0) return error.InvalidProfile;
            bits |= 2;
        },
        .raw => bits |= 4, // Existing passthrough; kind authority remains explicit.
    };
    return bits;
}
pub const NativeAdvertisement = struct { port: u16 };
const NativeOfferAdvertisement = struct {
    socket_fd: media_socket.SocketHandle,
    socket: media_socket.Snapshot,
    max_frame_bytes: usize,
    max_upload_bytes: u64,
};
fn nativeAdvertisementMatches(owner: *const NativeMediaTransport, observation: NativeOfferAdvertisement) bool {
    const socket = owner.socket orelse return false;
    return socket.fd == observation.socket_fd and socket.recv_timeout_ms == observation.socket.recv_timeout_ms and
        owner.port == observation.socket.port and owner.max_frame_bytes == observation.max_frame_bytes and
        owner.max_upload_bytes == observation.max_upload_bytes and !owner.stop_flag.load(.acquire);
}

const NativeOfferPlan = struct {
    owner: *NativeMediaTransport,
    domain: *routing.Domain,
    revision: u64,
    key: routing.EndpointKey,
    channel: []u8 = &.{},
    old: ?NativeEndpoint,
    next: NativeEndpoint,
    rows_state: NativeMapState,
    streams_state: NativeMapState,
    advertisement: ?NativeOfferAdvertisement = null,
    row_growth: ?NativeEndpointMap = null,
    stream_growth: ?NativeStreamMap = null,
    validated_scope: u64 = 0,
    committed: bool = false,
    fn wipe(self: *NativeOfferPlan) void {
        self.next.wipe();
        if (self.old) |*old| old.wipe();
    }
};
fn nativePlan(candidate: *PreparedNativeOffer) *NativeOfferPlan {
    return @ptrCast(@alignCast(candidate));
}
pub const NativeCredentialPreview = struct {
    identity: routing.EndpointObservation,
    /// Immutable borrow expires when candidate.deinit finishes. Caller wipes
    /// its own reply buffers; this access never authenticates endpoint admission.
    master: *const [32]u8,
};
pub const PreparedNativeOffer = opaque {
    pub fn preview(self: *PreparedNativeOffer) NativeCredentialPreview {
        const plan = nativePlan(self);
        return .{ .identity = plan.next.identity, .master = &plan.next.master };
    }
    pub fn negotiation(self: *PreparedNativeOffer) routing.TransportNegotiation {
        const row = nativePlan(self).next;
        return .{ .profile = row.profile, .kind_bits = row.kind_bits };
    }
    /// Preparation only: actual syscall observation, outside routing exclusion.
    /// The candidate's existing source pin retains this actual owner resource.
    pub fn captureAdvertisement(self: *PreparedNativeOffer) !void {
        const plan = nativePlan(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        if (plan.committed or plan.advertisement != null or owner.routing_closed or owner.physical_revision != plan.revision or owner.stop_flag.load(.acquire)) return error.StaleCandidate;
        const socket = if (owner.socket) |*held| held else return error.NotPrepared;
        const observed = try socket.capture();
        if (owner.port == 0 or owner.port != observed.port) return error.SocketMismatch;
        plan.advertisement = .{ .socket_fd = socket.fd, .socket = observed, .max_frame_bytes = owner.max_frame_bytes, .max_upload_bytes = owner.max_upload_bytes };
    }
    /// Copy-only advertised port; never an admission proof or FD borrow.
    pub fn advertisement(self: *PreparedNativeOffer) !NativeAdvertisement {
        const observed = nativePlan(self).advertisement orelse return error.NotPrepared;
        return .{ .port = observed.socket.port };
    }
    pub fn requireAdvertisementLocked(self: *PreparedNativeOffer, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers) !void {
        try self.validateLocked(domain, scope, offers);
        if (nativePlan(self).advertisement == null) return error.NotPrepared;
    }
    /// expected is the AGREED transport codec/FEC profile; offered capability
    /// rows belong to MediaRooms and are independently joined by the caller.
    pub fn requireNegotiationLocked(self: *PreparedNativeOffer, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers, expected: rooms.CallProfile, kind_bits: u8) !void {
        try self.validateLocked(domain, scope, offers);
        const row = nativePlan(self).next;
        if (row.kind_bits != kind_bits or !row.profile.eql(expected) or row.codecs != try nativeCodecs(expected, kind_bits)) return error.InvalidProfile;
    }
    pub fn validateLocked(self: *PreparedNativeOffer, domain: *routing.Domain, scope: *const routing.Locked, offers: *routing.PreparedOffers) !void {
        const serial = try domain.scopeSerial(scope);
        const plan = nativePlan(self);
        const owner = plan.owner;
        if (plan.domain != domain or plan.committed) return error.StaleCandidate;
        try offers.requireEndpointLocked(domain, scope, plan.channel, plan.next.identity);
        const binding = owner.routing_binding orelse return error.NotRoutingBound;
        try domain.requireNativeBindingLocked(scope, binding, owner);
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        if (owner.routing_domain != domain or owner.physical_revision != plan.revision or !std.meta.eql(plan.rows_state, nativeMapState(owner.physical_endpoints)) or !std.meta.eql(plan.streams_state, nativeMapState(owner.physical_streams)) or !nativeEndpointEqual(plan.old, owner.physical_endpoints.get(plan.key)) or owner.physical_streams.contains(plan.next.identity.stream_id)) return error.StaleCandidate;
        if (plan.old) |old| {
            const old_owner = owner.physical_streams.get(old.identity.stream_id) orelse return error.StaleCandidate;
            if (!std.meta.eql(old_owner, plan.key)) return error.StaleCandidate;
        }
        if (plan.advertisement) |observation| if (!nativeAdvertisementMatches(owner, observation)) return error.StaleCandidate;
        try domain.requireNativeStreamAvailableLocked(scope, plan.next.identity.stream_id);
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedNativeOffer, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid native offer cut");
        const plan = nativePlan(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        std.debug.assert(!plan.committed and plan.domain == domain and plan.validated_scope == serial and owner.physical_revision == plan.revision);
        if (plan.row_growth) |*replacement| {
            var it = owner.physical_endpoints.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(NativeEndpointMap, &owner.physical_endpoints, replacement);
        }
        if (plan.stream_growth) |*replacement| {
            var it = owner.physical_streams.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(NativeStreamMap, &owner.physical_streams, replacement);
        }
        owner.physical_streams.putAssumeCapacity(plan.next.identity.stream_id, plan.key);
        if (plan.old) |old| {
            // OLD removal is conditional on the exact validated index owner.
            _ = owner.physical_streams.remove(old.identity.stream_id);
        }
        if (owner.physical_endpoints.getPtr(plan.key)) |old_row| old_row.wipe();
        owner.physical_endpoints.putAssumeCapacity(plan.key, plan.next);
        owner.physical_revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedNativeOffer) void {
        const plan = nativePlan(self);
        const owner = plan.owner;
        if (plan.row_growth) |*map| {
            // Retired backing contains INLINE duplicate keys; wipe only its own
            // copies, never live current keys now adopted by the owner.
            var it = map.valueIterator();
            while (it.next()) |row| row.wipe();
            map.deinit(owner.allocator);
        }
        if (plan.stream_growth) |*map| map.deinit(owner.allocator);
        plan.wipe();
        owner.allocator.free(plan.channel);
        owner.allocator.destroy(plan);
        owner.finishPhysicalPlan();
    }
};

const NativeDeparturePlan = struct {
    owner: *NativeMediaTransport,
    domain: *routing.Domain,
    key: routing.EndpointKey,
    old: ?NativeEndpoint,
    revision: u64,
    terminal: bool,
    batch_part: bool,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn nativeDeparture(candidate: *PreparedNativeDeparture) *NativeDeparturePlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedNativeDeparture = opaque {
    pub fn validateLocked(self: *PreparedNativeDeparture, domain: *routing.Domain, scope: *const routing.Locked, departure: *routing.PreparedDeparture) !void {
        const serial = try domain.scopeSerial(scope);
        const plan = nativeDeparture(self);
        if (plan.domain != domain or plan.committed) return error.StaleCandidate;
        try departure.requireOwnerLocked(domain, scope, plan.key);
        if (plan.terminal) try domain.requireTerminalLocked(scope);
        const owner = plan.owner;
        try domain.requireNativeBindingLocked(scope, owner.routing_binding orelse return error.NotRoutingBound, owner);
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        if (owner.physical_revision != plan.revision or owner.routing_closed != plan.terminal or !nativeEndpointEqual(owner.physical_endpoints.get(plan.key), plan.old)) return error.StaleCandidate;
        if (!std.meta.eql(if (plan.old) |row| @as(?routing.EndpointObservation, row.identity) else null, departure.expectedOffer(.native))) return error.StaleCandidate;
        if (plan.old) |row| if (!std.meta.eql(owner.physical_streams.get(row.identity.stream_id), @as(?routing.EndpointKey, plan.key))) return error.StaleCandidate;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedNativeDeparture, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid native departure scope");
        const plan = nativeDeparture(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        std.debug.assert(plan.domain == domain and !plan.committed and plan.validated_scope == serial and owner.physical_revision == plan.revision);
        std.debug.assert(!plan.batch_part);
        applyNativeDeparturePlan(plan);
        if (plan.old != null and !plan.terminal) owner.physical_revision += 1;
    }
    pub fn deinit(self: *PreparedNativeDeparture) void {
        const plan = nativeDeparture(self);
        const owner = plan.owner;
        if (plan.old) |*row| row.wipe();
        owner.allocator.destroy(plan);
        owner.finishPhysicalPlan();
    }
};

fn candidateTestProfile() rooms.CallProfile {
    var profile = rooms.CallProfile{};
    profile.codecs[0] = .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 };
    profile.codec_count = 1;
    return profile;
}
const PublishNativeTest = struct {
    domain: *routing.Domain,
    offers: *routing.PreparedOffers,
    native: *PreparedNativeOffer,
    fn run(scope: *routing.Locked, ctx: @This()) !void {
        try ctx.offers.validateLocked(ctx.domain, scope);
        try ctx.native.validateLocked(ctx.domain, scope, ctx.offers);
        ctx.native.commitLocked(ctx.domain, scope);
        ctx.offers.commitLocked(ctx.domain, scope);
    }
};
fn retireNativeTest(domain: *routing.Domain, owner: *NativeMediaTransport, call: routing.CallId, id: routing.ClientId) !void {
    const departure = try domain.prepareDeparture(call, id);
    defer departure.deinit();
    const native = try owner.prepareDeparture(domain, departure);
    defer native.deinit();
    const Cut = struct {
        domain: *routing.Domain,
        departure: *routing.PreparedDeparture,
        native: *PreparedNativeDeparture,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.departure.validateLocked(ctx.domain, scope);
            try ctx.native.validateLocked(ctx.domain, scope, ctx.departure);
            ctx.native.commitLocked(ctx.domain, scope);
            ctx.departure.commitLocked(ctx.domain, scope);
        }
    };
    const cut = Cut{ .domain = domain, .departure = departure, .native = native };
    if (owner.routing_closed) try domain.withTerminalLocked(cut, Cut.run) else try domain.withLocked(cut, Cut.run);
}
fn cleanupNativeTest(domain: *routing.Domain, owner: *NativeMediaTransport, binding: *routing.NativeBinding) void {
    domain.closeForTerminal() catch @panic("native fixture did not join source custody");
    while (owner.physical_endpoints.count() != 0) {
        var it = owner.physical_endpoints.keyIterator();
        const key = it.next().?.*;
        retireNativeTest(domain, owner, key.call, key.client) catch @panic("native fixture lost exact departure");
    }
    domain.releaseNative(binding) catch @panic("native fixture retained source binding");
}

test "physical native candidate rotates only offering leg and terminal retirement preserves siblings" {
    const domain = try routing.Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("native fixture retained Domain rows");
    var owner = NativeMediaTransport.init(std.testing.allocator);
    defer owner.deinit();
    const binding = try domain.bindNative(&owner);
    defer cleanupNativeTest(domain, &owner, binding);
    const a = routing.ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    var call: routing.CallId = undefined;
    for ([_]routing.ClientId{ a, b, a }) |id| {
        const offers = try domain.prepareOffers("#physical", id, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offers.deinit();
        call = offers.preview().call;
        const candidate = try owner.prepareOffer(domain, offers, "#physical", "same", candidateTestProfile(), 1);
        defer candidate.deinit();
        var sibling: ?NativeEndpoint = owner.physical_endpoints.get(.{ .call = call, .client = b, .leg = .native });
        defer if (sibling) |*row| row.wipe();
        var before = owner.physical_endpoints.get(.{ .call = call, .client = id, .leg = .native });
        defer if (before) |*row| row.wipe();
        try domain.withLocked(PublishNativeTest{ .domain = domain, .offers = offers, .native = candidate }, PublishNativeTest.run);
        if (before) |old| {
            try std.testing.expect(!owner.physical_streams.contains(old.identity.stream_id));
            try std.testing.expect(!std.mem.eql(u8, &old.master, candidate.preview().master));
        }
        if (id.slot == a.slot and sibling != null) try std.testing.expect(nativeEndpointEqual(sibling, owner.physical_endpoints.get(.{ .call = call, .client = b, .leg = .native })));
    }
    try std.testing.expectEqual(@as(u32, 2), owner.physical_endpoints.count());
    // A legitimately exhausted source still has total terminal disposition.
    owner.physical_revision = std.math.maxInt(u64);
    try domain.closeForTerminal();
    try std.testing.expectError(error.Closing, domain.prepareOffers("#physical", a, &.{.{ .leg = .native, .mode = .legacy_group }}));
    var saved: NativeEndpoint = owner.physical_endpoints.get(.{ .call = call, .client = b, .leg = .native }).?;
    defer saved.wipe();
    try retireNativeTest(domain, &owner, call, a);
    try std.testing.expectEqual(@as(u32, 1), owner.physical_endpoints.count());
    try std.testing.expect(nativeEndpointEqual(saved, owner.physical_endpoints.get(.{ .call = call, .client = b, .leg = .native })));
    try std.testing.expectEqual(std.math.maxInt(u64), owner.physical_revision);
}
fn nativeCandidateOom(allocator: std.mem.Allocator) !void {
    const domain = try routing.Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("native OOM Domain custody");
    var owner = NativeMediaTransport.init(allocator);
    defer owner.deinit();
    const binding = try domain.bindNative(&owner);
    defer domain.releaseNative(binding) catch @panic("native OOM binding custody");
    const offers = try domain.prepareOffers("#oom", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offers.deinit();
    const candidate = owner.prepareOffer(domain, offers, "#oom", "n", candidateTestProfile(), 1) catch |err| {
        try std.testing.expectEqual(@as(u32, 0), owner.physical_endpoints.count());
        try std.testing.expectEqual(@as(u32, 0), owner.physical_endpoints.capacity());
        try std.testing.expectEqual(@as(u32, 0), owner.physical_streams.capacity());
        try std.testing.expectEqual(@as(usize, 0), owner.physical_pending);
        try std.testing.expectEqual(@as(u64, 1), owner.physical_revision);
        return err;
    };
    candidate.deinit();
    try std.testing.expectEqual(@as(u32, 0), owner.physical_endpoints.capacity());
    try std.testing.expectEqual(@as(u32, 0), owner.physical_streams.capacity());
    try std.testing.expectEqual(@as(usize, 0), owner.physical_pending);
}
test "physical native preparation every OOM retains OLD backing issuers and credential custody" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, nativeCandidateOom, .{});
}

fn applyNativeDeparturePlan(plan: *NativeDeparturePlan) void {
    const owner = plan.owner;
    if (plan.old) |old| {
        _ = owner.physical_streams.remove(old.identity.stream_id);
        owner.physical_endpoints.getPtr(plan.key).?.wipe();
        _ = owner.physical_endpoints.remove(plan.key);
    }
    plan.committed = true;
}
const NativeClientDeparturePlan = struct {
    owner: *NativeMediaTransport,
    domain: *routing.Domain,
    departure: *routing.PreparedClientDeparture,
    parts: []*PreparedNativeDeparture,
    revision: u64,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn planPreparedNativeClientDeparture(candidate: *PreparedNativeClientDeparture) *NativeClientDeparturePlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedNativeClientDeparture = opaque {
    pub fn validateLocked(self: *PreparedNativeClientDeparture, domain: *routing.Domain, scope: *const routing.Locked, departure: *routing.PreparedClientDeparture) !void {
        const plan = planPreparedNativeClientDeparture(self);
        const serial = try domain.scopeSerial(scope);
        if (plan.domain != domain or plan.departure != departure or plan.committed or plan.parts.len != departure.count()) return error.StaleCandidate;
        try departure.validateLocked(domain, scope);
        for (plan.parts, 0..) |part, n| {
            try departure.requirePartLocked(domain, scope, n, departure.part(n));
            if (nativeDeparture(part).revision != plan.revision or !nativeDeparture(part).batch_part) return error.StaleCandidate;
            try part.validateLocked(domain, scope, departure.part(n));
        }
        lockSpin(&plan.owner.mutex);
        defer plan.owner.mutex.unlock();
        if (plan.owner.physical_revision != plan.revision) return error.StaleCandidate;
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedNativeClientDeparture, domain: *routing.Domain, scope: *const routing.Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid complete source departure cut");
        const plan = planPreparedNativeClientDeparture(self);
        const owner = plan.owner;
        lockSpin(&owner.mutex);
        defer owner.mutex.unlock();
        std.debug.assert(!plan.committed and plan.domain == domain and plan.validated_scope == serial and owner.physical_revision == plan.revision);
        var changed = false;
        for (plan.parts) |part| {
            const row = nativeDeparture(part);
            std.debug.assert(!row.committed and row.validated_scope == serial and row.batch_part);
            changed = changed or (row.old != null);
            applyNativeDeparturePlan(row);
        }
        if (changed and !plan.departure.isTerminal()) owner.physical_revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedNativeClientDeparture) void {
        const plan = planPreparedNativeClientDeparture(self);
        const owner = plan.owner;
        for (plan.parts) |part| part.deinit();
        owner.allocator.free(plan.parts);
        owner.allocator.destroy(plan);
        owner.finishPhysicalPlan();
    }
};

test "physical native offered raw passthrough preserves explicit source kind authority" {
    var profile = candidateTestProfile();
    profile.codecs[0].tag = .raw;
    try std.testing.expectEqual(@as(u8, 4), try nativeCodecs(profile, 1));
    try std.testing.expectEqual(@as(u8, 4), try nativeCodecs(profile, 6));
    try std.testing.expectError(error.InvalidProfile, nativeCodecs(profile, 0));
    profile.codecs[0].tag = .cadencevox;
    try std.testing.expectError(error.InvalidProfile, nativeCodecs(profile, 2));
}

test "physical Native every detached growth failure has same owner retry and original allocation custody" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const domain = try routing.Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("growth retry source custody");
    var owner = NativeMediaTransport.init(fail.allocator());
    defer owner.deinit();
    const binding = try domain.bindNative(&owner);
    defer domain.releaseNative(binding) catch @panic("growth retry binding custody");
    const offers = try domain.prepareOffers("#retry", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offers.deinit();
    const old_0 = nativeMapState(owner.physical_endpoints);
    const old_1 = nativeMapState(owner.physical_streams);
    const old_allocated = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..32) |n| {
        fail.fail_index = fail.alloc_index + n;
        const candidate = owner.prepareOffer(domain, offers, "#retry", "n", candidateTestProfile(), 1) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
            try std.testing.expectEqual(@as(usize, 0), owner.physical_pending);
            try std.testing.expectEqual(@as(u64, 1), owner.physical_revision);
            try std.testing.expectEqualDeep(old_0, nativeMapState(owner.physical_endpoints));
            try std.testing.expectEqualDeep(old_1, nativeMapState(owner.physical_streams));
            const retry = try owner.prepareOffer(domain, offers, "#retry", "n", candidateTestProfile(), 1);
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
    try std.testing.expect(succeeded and failures >= 4);
    try std.testing.expectEqual(@as(usize, 0), owner.physical_pending);
    try std.testing.expectEqual(@as(u64, 1), owner.physical_revision);
    try std.testing.expectEqualDeep(old_0, nativeMapState(owner.physical_endpoints));
    try std.testing.expectEqualDeep(old_1, nativeMapState(owner.physical_streams));
}

test "physical native advertisement binds actual held UDP port full negotiation and current source" {
    const domain = try routing.Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("native advertisement source custody");
    var owner = NativeMediaTransport.init(std.testing.allocator);
    defer owner.deinit();
    try owner.prepareColdResources(std.testing.io, media_socket.loopback_be, 0);
    const binding = try domain.bindNative(&owner);
    defer domain.releaseNative(binding) catch @panic("native advertisement binding custody");
    const offers = try domain.prepareOffers("#advertisement", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offers.deinit();
    const profile = candidateTestProfile();
    const candidate = try owner.prepareOffer(domain, offers, "#advertisement", "same", profile, 1);
    defer candidate.deinit();
    try std.testing.expectError(error.NotPrepared, candidate.advertisement());
    try candidate.captureAdvertisement();
    const advertised = try candidate.advertisement();
    try std.testing.expectEqual(try owner.socket.?.localPort(), advertised.port);
    const Cut = struct {
        domain: *routing.Domain,
        offers: *routing.PreparedOffers,
        candidate: *PreparedNativeOffer,
        expected: rooms.CallProfile,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.candidate.requireNegotiationLocked(ctx.domain, scope, ctx.offers, ctx.expected, 1);
            try ctx.candidate.requireAdvertisementLocked(ctx.domain, scope, ctx.offers);
        }
    };
    const good = Cut{ .domain = domain, .offers = offers, .candidate = candidate, .expected = profile };
    try domain.withLocked(good, Cut.run);
    var equal_tail = profile;
    for (equal_tail.codecs[equal_tail.codec_count..]) |*codec| codec.* = .{ .tag = .raw, .clock_rate = 913, .params = 21 };
    try domain.withLocked(Cut{ .domain = domain, .offers = offers, .candidate = candidate, .expected = equal_tail }, Cut.run);
    var original = nativePlan(candidate).next;
    defer original.wipe();
    var twin = original;
    defer twin.wipe();
    twin.profile = equal_tail;
    try std.testing.expect(nativeEndpointEqual(original, twin));
    twin.master[0] ^= 1;
    try std.testing.expect(!nativeEndpointEqual(original, twin));
    {
        const port = owner.port;
        defer owner.port = port;
        owner.port = if (port == 1) 2 else 1;
        try std.testing.expectError(error.StaleCandidate, domain.withLocked(good, Cut.run));
    }
    var foreign = profile;
    foreign.fec.redundancy += 1;
    try std.testing.expectError(error.InvalidProfile, domain.withLocked(Cut{ .domain = domain, .offers = offers, .candidate = candidate, .expected = foreign }, Cut.run));
    {
        owner.stop_flag.store(true, .release);
        defer owner.stop_flag.store(false, .release);
        try std.testing.expectError(error.StaleCandidate, domain.withLocked(good, Cut.run));
    }
    try domain.withLocked(good, Cut.run);
    try std.testing.expectEqual(@as(u32, 0), owner.physical_endpoints.count());
    try std.testing.expectEqual(@as(u64, 1), owner.physical_revision);
}

const NativeIngressProbe = struct {
    owner: *NativeMediaTransport,
    domain: *routing.Domain,
    old: ?routing.IngressHandle = null,
    captured: ?routing.IngressHandle = null,
    bytes: []u8,
    tamper: bool = false,
    fn accepted(scope: *const routing.Locked, ctx: *@This(), handle: routing.IngressHandle) anyerror!routing.FanoutResult {
        const view = try ctx.domain.resolveNativeIngressLocked(scope, handle);
        try std.testing.expect(!view.first_bind);
        try std.testing.expectEqual(@as(u64, 2), view.source.binding_revision);
        if (ctx.old) |previous| try std.testing.expectError(error.InvalidIngress, ctx.domain.resolveNativeIngressLocked(scope, previous));
        try std.testing.expectError(error.Busy, ctx.owner.requireRoutingTerminal());
        const forged: routing.IngressHandle = @enumFromInt(@intFromEnum(handle) + (@as(u256, 1) << 192));
        try std.testing.expectError(error.InvalidIngress, ctx.domain.resolveNativeIngressLocked(scope, forged));
        if (ctx.tamper) {
            const last = ctx.bytes.len - 1;
            ctx.bytes[last] ^= 1;
            defer ctx.bytes[last] ^= 1;
            try std.testing.expectError(error.InvalidIngress, ctx.domain.resolveNativeIngressLocked(scope, handle));
        }
        ctx.captured = handle;
        return .{ .recognized = true };
    }
};
const NativeIngressFixtureTurn = struct {
    domain: *routing.Domain,
    owner: *NativeMediaTransport,
    from: TransportAddress,
    datagram: []u8,
    fn run(scope: *routing.Locked, ctx: @This()) !void {
        var probe = NativeIngressProbe{ .owner = ctx.owner, .domain = ctx.domain, .bytes = ctx.datagram };
        const before = ctx.owner.next_ingress_serial;
        ctx.datagram[ctx.datagram.len - 1] ^= 1;
        try std.testing.expectError(error.BadTag, ctx.owner.withAuthenticatedFrameLocked(ctx.domain, scope, ctx.from, ctx.datagram, &probe, NativeIngressProbe.accepted));
        ctx.datagram[ctx.datagram.len - 1] ^= 1;
        try std.testing.expectEqual(before, ctx.owner.next_ingress_serial);
        const accepted = try ctx.owner.withAuthenticatedFrameLocked(ctx.domain, scope, ctx.from, ctx.datagram, &probe, NativeIngressProbe.accepted);
        try std.testing.expect(accepted.recognized and accepted.accepted == 0);
        try std.testing.expectError(error.InvalidIngress, ctx.domain.resolveNativeIngressLocked(scope, probe.captured.?));
        probe.old = probe.captured;
        probe.tamper = true;
        _ = try ctx.owner.withAuthenticatedFrameLocked(ctx.domain, scope, ctx.from, ctx.datagram, &probe, NativeIngressProbe.accepted);
        try std.testing.expect(probe.old.? != probe.captured.?);
        const bound_serial = ctx.owner.next_ingress_serial;
        var changed_address = ctx.from;
        changed_address.port += 1;
        try std.testing.expectError(error.AddressDenied, ctx.owner.withAuthenticatedFrameLocked(ctx.domain, scope, changed_address, ctx.datagram, &probe, NativeIngressProbe.accepted));
        try std.testing.expectEqual(bound_serial, ctx.owner.next_ingress_serial);
        ctx.owner.next_ingress_serial = std.math.maxInt(u64);
        defer ctx.owner.next_ingress_serial = bound_serial;
        try std.testing.expectError(error.SequenceExhausted, ctx.owner.withAuthenticatedFrameLocked(ctx.domain, scope, ctx.from, ctx.datagram, &probe, NativeIngressProbe.accepted));
        try std.testing.expect(ctx.owner.active_ingress == null);
    }
};
test "physical native authenticated ingress actual MAC bytes scope serial reuse and first binding" {
    const domain = try routing.Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("ingress fixture Domain custody");
    var owner = NativeMediaTransport.init(std.testing.allocator);
    defer owner.deinit();
    const binding = try domain.bindNative(&owner);
    defer cleanupNativeTest(domain, &owner, binding);
    var stream: u32 = undefined;
    var keys: capability.Keys = undefined;
    defer keys.wipe();
    {
        const offers = try domain.prepareOffers("#ingress", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offers.deinit();
        const candidate = try owner.prepareOffer(domain, offers, "#ingress", "same", candidateTestProfile(), 1);
        defer candidate.deinit();
        stream = candidate.preview().identity.stream_id;
        const preview = candidate.preview();
        keys = try capability.derive(preview.master, stream);
        try domain.withLocked(PublishNativeTest{ .domain = domain, .offers = offers, .native = candidate }, PublishNativeTest.run);
    }
    var storage: [256]u8 = undefined;
    var tagged: [272]u8 = undefined;
    const n = try cadence_frame.encode(.{ .band_id = 64, .stream_id = stream, .sequence = 31, .timestamp = 48000, .keyframe = false, .codec = .cadencevox_audio, .payload = "accepted actual audio" }, &storage);
    const datagram = try cadence_frame.appendNativeMediaMacWithKey(&keys.c2s_frame, storage[0..n], &tagged);
    const from = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 17631);
    try domain.withLocked(NativeIngressFixtureTurn{ .domain = domain, .owner = &owner, .from = from, .datagram = tagged[0..datagram.len] }, NativeIngressFixtureTurn.run);
    var iterator = owner.physical_endpoints.valueIterator();
    var row = iterator.next().?.*;
    defer row.wipe();
    try std.testing.expect(ingressAddressEqual(row.remote.?, from));
    try std.testing.expectEqual(@as(u64, 2), row.identity.stamp.binding_revision);
    // Server-directed output and a master-direct tag never authenticate ingress.
    const reflected = try cadence_frame.appendNativeMediaMacWithKey(&keys.s2c_frame, storage[0..n], &tagged);
    const Denied = struct {
        domain: *routing.Domain,
        owner: *NativeMediaTransport,
        from: TransportAddress,
        bytes: []const u8,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            var scratch: [1]u8 = .{0};
            var probe = NativeIngressProbe{ .domain = ctx.domain, .owner = ctx.owner, .bytes = &scratch };
            try std.testing.expectError(error.BadTag, ctx.owner.withAuthenticatedFrameLocked(ctx.domain, scope, ctx.from, ctx.bytes, &probe, NativeIngressProbe.accepted));
        }
    };
    try domain.withLocked(Denied{ .domain = domain, .owner = &owner, .from = from, .bytes = reflected }, Denied.run);
    const after = owner.next_ingress_serial;
    const direct_master = try cadence_frame.appendNativeMediaMacWithKey(&row.master, storage[0..n], &tagged);
    try domain.withLocked(Denied{ .domain = domain, .owner = &owner, .from = from, .bytes = direct_master }, Denied.run);
    try std.testing.expectEqual(after, owner.next_ingress_serial);
    try std.testing.expect(owner.active_ingress == null);
}

test "physical prepared legacy Native worker actual join retains exact source socket" {
    var owner = NativeMediaTransport.init(testing.allocator);
    defer owner.deinit();
    try owner.prepareColdResources(testing.io, loopback_be, 0);
    const socket_before = try owner.socket.?.capture();
    try owner.startPreparedLegacyWorker();
    defer {
        owner.requestStopAndWake();
        owner.joinLegacyAfterStop() catch @panic("Native legacy real join");
    }
    try testing.expectError(error.Busy, owner.startPreparedLegacyWorker());
    owner.requestStopAndWake();
    try owner.joinLegacyAfterStop();
    try testing.expect(owner.thread == null and owner.worker_id == null and !owner.legacy_joining);
    try testing.expectEqualDeep(socket_before, try owner.socket.?.capture());
}

const PhysicalNativeWorkerFixture = struct {
    domain: *routing.Domain,
    native: *NativeMediaTransport,
    plane: *@import("media_plane.zig").MediaPlane,
    native_binding: *routing.NativeBinding,
    plane_binding: *routing.WebrtcBinding,
    rtc_clients: [2]routing.ClientId = undefined,
    rtc_count: usize = 0,
    fn init() !@This() {
        const domain = try routing.Domain.create(testing.allocator);
        errdefer domain.destroyQuiesced() catch unreachable;
        const native = try testing.allocator.create(NativeMediaTransport);
        errdefer testing.allocator.destroy(native);
        native.* = NativeMediaTransport.init(testing.allocator);
        errdefer native.deinit();
        const plane = try testing.allocator.create(@import("media_plane.zig").MediaPlane);
        errdefer testing.allocator.destroy(plane);
        plane.* = try @import("media_plane.zig").MediaPlane.initFallible(testing.allocator);
        errdefer plane.deinit();
        try native.prepareColdResources(testing.io, loopback_be, 0);
        try plane.prepareColdResources(testing.io, loopback_be, 0);
        const native_binding = try domain.bindNative(native);
        errdefer domain.releaseNative(native_binding) catch unreachable;
        const plane_binding = try domain.bindWebrtc(plane);
        errdefer domain.releaseWebrtc(plane_binding) catch unreachable;
        try plane.prepareRoutingEgress(domain, 8, 1024);
        return .{ .domain = domain, .native = native, .plane = plane, .native_binding = native_binding, .plane_binding = plane_binding };
    }
    fn deinit(self: *@This()) void {
        // Close producers while the pump can finish each accepted owned row.
        self.native.requestStopAndWake();
        self.native.joinLegacyAfterStop() catch @panic("native fixture retained worker");
        const Fence = struct {
            fixture: *PhysicalNativeWorkerFixture,
            fn run(scope: *routing.Locked, ctx: @This()) !@import("media_plane.zig").RoutingProducerFence {
                return ctx.fixture.plane.fenceRoutingProducersLocked(ctx.fixture.domain, scope);
            }
        };
        const fence = self.domain.withLocked(Fence{ .fixture = self }, Fence.run) catch @panic("native fixture could not fence queue");
        const Settled = struct {
            fixture: *PhysicalNativeWorkerFixture,
            fence: @import("media_plane.zig").RoutingProducerFence,
            fn run(scope: *routing.Locked, ctx: @This()) !bool {
                ctx.fixture.plane.requireRoutingEgressSettledLocked(ctx.fixture.domain, scope, ctx.fence) catch |err| {
                    if (err == error.Busy) return false;
                    return err;
                };
                return true;
            }
        };
        const deadline = std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
        while (!(self.domain.withLocked(Settled{ .fixture = self, .fence = fence }, Settled.run) catch @panic("native fixture lost source settlement"))) {
            if (deadline.untilNow(testing.io).raw.nanoseconds >= 0) @panic("native fixture queue did not settle");
            std.Thread.yield() catch {};
        }
        self.plane.requestStopAndWake();
        self.plane.joinLegacyAfterStop() catch @panic("native fixture retained egress pump");
        self.domain.closeForTerminal() catch @panic("native fixture retained operation");
        self.plane.finishRoutingTerminalCleanup(self.domain) catch unreachable;
        // Retire each genuinely offered RTC owner after both workers and the
        // actual FIFO have joined. No test-only count substitutes for a source plan.
        for (self.rtc_clients[0..self.rtc_count]) |client| {
            const departure = self.domain.prepareClientDeparture(client) catch unreachable;
            defer departure.deinit();
            const plane = self.plane.prepareClientDeparture(self.domain, departure) catch unreachable;
            defer plane.deinit();
            const Retire = struct {
                fixture: *PhysicalNativeWorkerFixture,
                departure: *routing.PreparedClientDeparture,
                plane: *@import("media_plane.zig").PreparedWebrtcClientDeparture,
                fn run(scope: *routing.Locked, ctx: @This()) !void {
                    try ctx.departure.validateLocked(ctx.fixture.domain, scope);
                    try ctx.plane.validateLocked(ctx.fixture.domain, scope, ctx.departure);
                    ctx.plane.commitLocked(ctx.fixture.domain, scope);
                    ctx.departure.commitLocked(ctx.fixture.domain, scope);
                }
            };
            self.domain.withTerminalLocked(Retire{ .fixture = self, .departure = departure, .plane = plane }, Retire.run) catch unreachable;
        }
        // Actual native row retirements also remove their genuine Bridge rows.
        cleanupNativeTest(self.domain, self.native, self.native_binding);
        self.domain.releaseWebrtc(self.plane_binding) catch unreachable;
        self.plane.deinit();
        self.native.deinit();
        testing.allocator.destroy(self.plane);
        testing.allocator.destroy(self.native);
        self.domain.destroyQuiesced() catch unreachable;
    }
    const Peer = struct {
        identity: routing.EndpointObservation,
        keys: capability.Keys,
        fn wipe(self: *@This()) void {
            self.keys.wipe();
        }
    };
    fn offer(self: *@This(), channel: []const u8, id: routing.ClientId) !Peer {
        const offers = try self.domain.prepareOffers(channel, id, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offers.deinit();
        const candidate = try self.native.prepareOffer(self.domain, offers, channel, "same-nickname", candidateTestProfile(), 1);
        defer candidate.deinit();
        const bridge = try self.domain.preparePhysicalBridge(offers, channel, candidate, null);
        defer bridge.deinit();
        const preview = candidate.preview();
        var peer = Peer{ .identity = preview.identity, .keys = try capability.derive(preview.master, preview.identity.stream_id) };
        errdefer peer.wipe();
        const Publish = struct {
            fixture: *PhysicalNativeWorkerFixture,
            offers: *routing.PreparedOffers,
            candidate: *PreparedNativeOffer,
            bridge: *routing.PreparedPhysicalBridge,
            fn run(scope: *routing.Locked, ctx: @This()) !void {
                try ctx.offers.validateLocked(ctx.fixture.domain, scope);
                try ctx.candidate.validateLocked(ctx.fixture.domain, scope, ctx.offers);
                try ctx.bridge.validateLocked(ctx.fixture.domain, scope, ctx.offers, ctx.candidate, null);
                ctx.candidate.commitLocked(ctx.fixture.domain, scope);
                ctx.bridge.commitLocked(ctx.fixture.domain, scope);
                ctx.offers.commitLocked(ctx.fixture.domain, scope);
            }
        };
        try self.domain.withLocked(Publish{ .fixture = self, .offers = offers, .candidate = candidate, .bridge = bridge }, Publish.run);
        return peer;
    }
    const RtcPeer = struct {
        identity: routing.EndpointObservation,
        ufrag: [@import("../substrate/media_transport.zig").ufrag_len]u8,
        pwd: [@import("../substrate/media_transport.zig").pwd_len]u8,
        fn wipe(self: *@This()) void {
            std.crypto.secureZero(u8, &self.pwd);
        }
    };
    fn offerRtc(self: *@This(), channel: []const u8, client: routing.ClientId) !RtcPeer {
        if (self.rtc_count == self.rtc_clients.len) return error.TestUnexpectedResult;
        const offers = try self.domain.prepareOffers(channel, client, &.{.{ .leg = .webrtc, .mode = .legacy_group }});
        defer offers.deinit();
        const candidate = try self.plane.prepareOffer(self.domain, offers, channel, candidateTestProfile(), 1, null);
        defer candidate.deinit();
        const bridge = try self.domain.preparePhysicalBridge(offers, channel, null, candidate);
        defer bridge.deinit();
        const preview = candidate.preview();
        var peer = RtcPeer{ .identity = preview.identity, .ufrag = preview.ufrag.*, .pwd = preview.pwd.* };
        errdefer peer.wipe();
        const Publish = struct {
            fixture: *PhysicalNativeWorkerFixture,
            offers: *routing.PreparedOffers,
            candidate: *@import("media_plane.zig").PreparedWebrtcOffer,
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
        try self.domain.withLocked(Publish{ .fixture = self, .offers = offers, .candidate = candidate, .bridge = bridge }, Publish.run);
        self.rtc_clients[self.rtc_count] = client;
        self.rtc_count += 1;
        return peer;
    }
    fn bindRtc(peer: *MediaSocket, destination: TransportAddress, creds: *const RtcPeer, transaction: u8) !void {
        const stun = @import("../proto/stun.zig");
        var username: [@import("../substrate/media_transport.zig").ufrag_len + 5]u8 = undefined;
        @memcpy(username[0..creds.ufrag.len], &creds.ufrag);
        @memcpy(username[creds.ufrag.len..], ":peer");
        const request = try stun.buildBindingRequest(testing.allocator, @splat(transaction), .{ .username = &username, .integrity_key = &creds.pwd, .fingerprint = true });
        defer testing.allocator.free(request);
        peer.sendTo(destination, request);
        var response: [512]u8 = undefined;
        const received = peer.recvFrom(&response) orelse return error.TestUnexpectedResult;
        var message = try stun.decode(testing.allocator, received.data);
        defer message.deinit(testing.allocator);
        try testing.expect(try stun.verifyMessageIntegrity(received.data, &creds.pwd));
        try testing.expect(try stun.verifyFingerprint(received.data));
        try testing.expectEqualSlices(u8, &@as([12]u8, @splat(transaction)), &message.transaction_id);
    }
    fn frame(peer: *const Peer, sequence: u32, out: []u8) ![]const u8 {
        var clear: [128]u8 = undefined;
        const size = try cadence_frame.encode(.{ .band_id = cadence_frame.MEDIA_BAND_FLOOR, .stream_id = peer.identity.stream_id, .sequence = sequence, .timestamp = sequence, .keyframe = false, .codec = .cadencevox_audio, .payload = "actual-native-payload" }, &clear);
        return cadence_frame.appendNativeMediaMacWithKey(&peer.keys.c2s_frame, clear[0..size], out);
    }
    fn awaitAccepted(self: *@This(), count: u64) !void {
        const deadline = std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
        while (self.native.routed_accepted.load(.acquire) < count) {
            if (deadline.untilNow(testing.io).raw.nanoseconds >= 0) return error.TestUnexpectedResult;
            std.Thread.yield() catch {};
        }
    }
};

test "physical Native actual workers use recipient directional tags same-nick siblings and authenticated feedback" {
    var fixture = try PhysicalNativeWorkerFixture.init();
    defer fixture.deinit();
    var a = try fixture.offer("#native-physical", .{ .shard = 0, .slot = 0, .gen = 0 });
    defer a.wipe();
    var b = try fixture.offer("#native-physical", .{ .shard = 0, .slot = 1, .gen = 0 });
    defer b.wipe();
    var other = try fixture.offer("#other-call", .{ .shard = 0, .slot = 2, .gen = 0 });
    defer other.wipe();
    try testing.expect(a.identity.stream_id != b.identity.stream_id);
    var first = try MediaSocket.bind(loopback_be, 0);
    defer first.deinit();
    first.setRecvTimeoutMs(400);
    var second = try MediaSocket.bind(loopback_be, 0);
    defer second.deinit();
    second.setRecvTimeoutMs(1000);
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.native.port);
    try fixture.plane.startPreparedLegacyWorker();
    try fixture.native.startPreparedLegacyWorker();
    var sent: [256]u8 = undefined;
    second.sendTo(destination, try PhysicalNativeWorkerFixture.frame(&b, 1, &sent));
    try fixture.awaitAccepted(1); // authentic first B bind, A not bound yet
    first.sendTo(destination, try PhysicalNativeWorkerFixture.frame(&a, 2, &sent));
    var wire: [1024]u8 = undefined;
    const received = second.recvFrom(&wire) orelse return error.TestUnexpectedResult;
    const canonical = try cadence_frame.verifyNativeMediaMacWithKey(&b.keys.s2c_frame, received.data);
    try testing.expectEqual(a.identity.stream_id, (try cadence_frame.decode(canonical)).stream_id);
    try testing.expectEqualStrings("actual-native-payload", (try cadence_frame.decode(canonical)).payload);
    try testing.expectError(error.BadTag, cadence_frame.verifyNativeMediaMacWithKey(&b.keys.c2s_frame, received.data));
    try testing.expectError(error.BadTag, cadence_frame.verifyNativeMediaMacWithKey(&a.keys.s2c_frame, received.data));
    // An emitted packet reflected back from the real original source cannot
    // become a new authenticated client ingress or acquire another operation.
    first.sendTo(destination, received.data);
    try testing.expect(second.recvFrom(&wire) == null);
    var payload: [64]u8 = undefined;
    const pli = try native_feedback.encodeKeyframeRequest(b.identity.stream_id, &payload);
    var envelope_storage: [256]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(a.identity.stream_id, pli, &a.keys.c2s_feedback, &envelope_storage);
    first.sendTo(destination, envelope);
    const feedback = second.recvFrom(&wire) orelse return error.TestUnexpectedResult;
    const opened = try native_feedback.openEnvelope(feedback.data, &b.keys.s2c_feedback);
    try testing.expectEqual(a.identity.stream_id, opened.sender_stream_id);
    try testing.expectEqualSlices(u8, pli, opened.payload);
    try testing.expectError(error.BadTag, native_feedback.openEnvelope(feedback.data, &b.keys.c2s_feedback));
    // Repeated authenticated feedback is a legitimate bounded request. It
    // does not rotate endpoint/binding authority or reset RTP replay history.
    first.sendTo(destination, envelope);
    const repeated = second.recvFrom(&wire) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, pli, (try native_feedback.openEnvelope(repeated.data, &b.keys.s2c_feedback)).payload);
    const foreign_pli = try native_feedback.encodeKeyframeRequest(other.identity.stream_id, &payload);
    const foreign_envelope = try native_feedback.encodeEnvelope(a.identity.stream_id, foreign_pli, &a.keys.c2s_feedback, &envelope_storage);
    first.sendTo(destination, foreign_envelope);
    try testing.expect(second.recvFrom(&wire) == null);
    first.sendTo(destination, try PhysicalNativeWorkerFixture.frame(&a, 3, &sent));
    const retry = second.recvFrom(&wire) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 3), (try cadence_frame.decode(try cadence_frame.verifyNativeMediaMacWithKey(&b.keys.s2c_frame, retry.data))).sequence);
}

test "physical media five-blocker causal Native first issued stream refuses colliding RTC SSRC claim" {
    var fixture = try PhysicalNativeWorkerFixture.init();
    defer fixture.deinit();
    const channel = "#publisher-namespace";
    var native_peer = try fixture.offer(channel, .{ .shard = 0, .slot = 0, .gen = 0 });
    defer native_peer.wipe();
    var publisher = try fixture.offerRtc(channel, .{ .shard = 0, .slot = 1, .gen = 0 });
    defer publisher.wipe();
    var requester = try fixture.offerRtc(channel, .{ .shard = 0, .slot = 2, .gen = 0 });
    defer requester.wipe();
    var native_socket = try MediaSocket.bind(loopback_be, 0);
    defer native_socket.deinit();
    native_socket.setRecvTimeoutMs(700);
    var rtc_source = try MediaSocket.bind(loopback_be, 0);
    defer rtc_source.deinit();
    rtc_source.setRecvTimeoutMs(700);
    var rtc_requester = try MediaSocket.bind(loopback_be, 0);
    defer rtc_requester.deinit();
    rtc_requester.setRecvTimeoutMs(700);
    const native_destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.native.port);
    const rtc_destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.plane.port);
    try fixture.plane.startPreparedLegacyWorker();
    try fixture.native.startPreparedLegacyWorker();
    try PhysicalNativeWorkerFixture.bindRtc(&rtc_source, rtc_destination, &publisher, 0x91);
    try PhysicalNativeWorkerFixture.bindRtc(&rtc_requester, rtc_destination, &requester, 0x92);
    var wire: [1024]u8 = undefined;
    var frame_storage: [256]u8 = undefined;
    native_socket.sendTo(native_destination, try PhysicalNativeWorkerFixture.frame(&native_peer, 1, &frame_storage));
    for ([_]*MediaSocket{ &rtc_source, &rtc_requester }) |peer| {
        const received = peer.recvFrom(&wire) orelse return error.TestUnexpectedResult;
        const rtp = try rtp_profile.decodeHeader(received.data);
        try testing.expectEqual(native_peer.identity.stream_id, rtp.header.ssrc);
        try testing.expectEqualStrings("actual-native-payload", received.data[rtp.len..]);
    }
    // Real issued Native authority already uses this SSRC namespace. A second
    // authentic group RTC publisher must be refused BEFORE cache/replay/index
    // publication; feedback must never acquire ambiguous publisher identity.
    const collision = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 43, .timestamp = 480, .ssrc = native_peer.identity.stream_id }, .payload = "colliding-RTC-publisher" }, &frame_storage);
    rtc_source.sendTo(rtc_destination, collision);
    try testing.expect(native_socket.recvFrom(&wire) == null);
}

test "physical media five-blocker causal RTC first SSRC refuses conflicting later Native publication" {
    var fixture = try PhysicalNativeWorkerFixture.init();
    defer fixture.deinit();
    const channel = "#publisher-namespace";
    var publisher = try fixture.offerRtc(channel, .{ .shard = 0, .slot = 1, .gen = 0 });
    defer publisher.wipe();
    var requester = try fixture.offerRtc(channel, .{ .shard = 0, .slot = 2, .gen = 0 });
    defer requester.wipe();
    var rtc_source = try MediaSocket.bind(loopback_be, 0);
    defer rtc_source.deinit();
    rtc_source.setRecvTimeoutMs(700);
    var rtc_requester = try MediaSocket.bind(loopback_be, 0);
    defer rtc_requester.deinit();
    rtc_requester.setRecvTimeoutMs(700);
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.plane.port);
    try fixture.plane.startPreparedLegacyWorker();
    try PhysicalNativeWorkerFixture.bindRtc(&rtc_source, destination, &publisher, 0x93);
    try PhysicalNativeWorkerFixture.bindRtc(&rtc_requester, destination, &requester, 0x94);
    const offers = try fixture.domain.prepareOffers(channel, .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offers.deinit();
    const candidate = try fixture.native.prepareOffer(fixture.domain, offers, channel, "same-nickname", candidateTestProfile(), 1);
    defer candidate.deinit();
    const bridge = try fixture.domain.preparePhysicalBridge(offers, channel, candidate, null);
    defer bridge.deinit();
    // This stream is the genuine private issuer's candidate preview, not a
    // fabricated current owner. The independent RTC SSRC is accepted first.
    var packet_storage: [128]u8 = undefined;
    const packet = try rtp_profile.encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 47, .timestamp = 480, .ssrc = candidate.preview().identity.stream_id }, .payload = "RTC-first-accepted" }, &packet_storage);
    rtc_source.sendTo(destination, packet);
    var wire: [1024]u8 = undefined;
    const received = rtc_requester.recvFrom(&wire) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, packet, received.data);
    const Publish = struct {
        fixture: *PhysicalNativeWorkerFixture,
        offers: *routing.PreparedOffers,
        candidate: *PreparedNativeOffer,
        bridge: *routing.PreparedPhysicalBridge,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.offers.validateLocked(ctx.fixture.domain, scope);
            try ctx.candidate.validateLocked(ctx.fixture.domain, scope, ctx.offers);
            try ctx.bridge.validateLocked(ctx.fixture.domain, scope, ctx.offers, ctx.candidate, null);
            ctx.candidate.commitLocked(ctx.fixture.domain, scope);
            ctx.bridge.commitLocked(ctx.fixture.domain, scope);
            ctx.offers.commitLocked(ctx.fixture.domain, scope);
        }
    };
    try testing.expectError(error.PublisherCollision, fixture.domain.withLocked(Publish{ .fixture = &fixture, .offers = offers, .candidate = candidate, .bridge = bridge }, Publish.run));
}

test "physical media namespace collision spans distinct calls and real departure releases accepted RTC claim" {
    var fixture = try PhysicalNativeWorkerFixture.init();
    defer fixture.deinit();
    const publisher_id = routing.ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    var publisher = try fixture.offerRtc("#rtc-namespace", publisher_id);
    defer publisher.wipe();
    var requester = try fixture.offerRtc("#rtc-namespace", .{ .shard = 0, .slot = 2, .gen = 0 });
    defer requester.wipe();
    var source_socket = try MediaSocket.bind(loopback_be, 0);
    defer source_socket.deinit();
    source_socket.setRecvTimeoutMs(700);
    var receiver_socket = try MediaSocket.bind(loopback_be, 0);
    defer receiver_socket.deinit();
    receiver_socket.setRecvTimeoutMs(700);
    const destination = try TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, fixture.plane.port);
    try fixture.plane.startPreparedLegacyWorker();
    try PhysicalNativeWorkerFixture.bindRtc(&source_socket, destination, &publisher, 0xa1);
    try PhysicalNativeWorkerFixture.bindRtc(&receiver_socket, destination, &requester, 0xa2);
    var accepted_stream: u32 = undefined;
    {
        const offers = try fixture.domain.prepareOffers("#native-other-call", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offers.deinit();
        const candidate = try fixture.native.prepareOffer(fixture.domain, offers, "#native-other-call", "different-call", candidateTestProfile(), 1);
        defer candidate.deinit();
        accepted_stream = candidate.preview().identity.stream_id;
        var storage: [128]u8 = undefined;
        const packet = try @import("../proto/rtp_profile.zig").encodePacket(.{ .header = .{ .payload_type = 111, .sequence = 61, .timestamp = 480, .ssrc = accepted_stream }, .payload = "other-call-RTC-history" }, &storage);
        source_socket.sendTo(destination, packet);
        var received: [1024]u8 = undefined;
        const actual = receiver_socket.recvFrom(&received) orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, packet, actual.data);
        try testing.expectError(error.PublisherCollision, fixture.domain.withLocked(PublishNativeTest{ .domain = fixture.domain, .offers = offers, .native = candidate }, PublishNativeTest.run));
    }
    const pause = try fixture.plane.requestPause(1);
    defer fixture.plane.resumePaused(pause) catch unreachable;
    try fixture.plane.awaitPaused(pause, std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    {
        const departure = try fixture.domain.prepareClientDeparture(publisher_id);
        defer departure.deinit();
        const plane = try fixture.plane.prepareClientDeparture(fixture.domain, departure);
        defer plane.deinit();
        const Cut = struct {
            fixture: *PhysicalNativeWorkerFixture,
            departure: *routing.PreparedClientDeparture,
            plane: *@import("media_plane.zig").PreparedWebrtcClientDeparture,
            fn run(scope: *routing.Locked, ctx: @This()) !void {
                try ctx.departure.validateLocked(ctx.fixture.domain, scope);
                try ctx.plane.validateLocked(ctx.fixture.domain, scope, ctx.departure);
                ctx.plane.commitLocked(ctx.fixture.domain, scope);
                ctx.departure.commitLocked(ctx.fixture.domain, scope);
            }
        };
        try fixture.domain.withLocked(Cut{ .fixture = &fixture, .departure = departure, .plane = plane }, Cut.run);
    }
    const Available = struct {
        domain: *routing.Domain,
        stream: u32,
        fn run(scope: *routing.Locked, ctx: @This()) !void {
            try ctx.domain.requireNativeStreamAvailableLocked(scope, ctx.stream);
        }
    };
    // The SAME formerly conflicting value becomes available only after the
    // genuine accepted RTC owner and its cache/index graph actually retire.
    try fixture.domain.withLocked(Available{ .domain = fixture.domain, .stream = accepted_stream }, Available.run);
    var current_native = try fixture.offer("#native-other-call", .{ .shard = 0, .slot = 0, .gen = 0 });
    defer current_native.wipe();
    try testing.expect(fixture.native.physical_streams.contains(current_native.identity.stream_id));
}
