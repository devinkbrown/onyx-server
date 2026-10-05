// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared physical media routing identity and lexical publication boundary.
//! Scalar identities are selectors; only current canonical rows authorize them.
//! The source prepares detached storage before entering the final routing cut.
//! This module does not authenticate a client, enroll resource loans, or activate
//! any configured caller. External lifetime ownership must join all callers.
const std = @import("std");
const client = @import("../daemon/client.zig");
const media_rooms = @import("../daemon/media_room.zig");
const native_owner = @import("../daemon/native_media_transport.zig");
const webrtc_owner = @import("../daemon/media_plane.zig");
const runtime_pause = @import("../daemon/runtime_pause.zig");

pub const ClientId = client.ClientId;
pub const Leg = enum { native, webrtc };
pub const PacketKind = enum { rtp, rtcp };
/// Opaque value selector with independently captured issuance. A value alone
/// grants nothing; only the actual registered source's current authenticated
/// slot and exact borrowed bytes validate it during its lexical callback.
pub const IngressHandle = enum(u256) { _ };
pub const IngressContext = struct { domain: u64, registration: u64, scope: u64 };
pub const FanoutResult = struct { accepted: u32 = 0, refused: u32 = 0, recognized: bool = false, last_refusal: ?anyerror = null };

pub const SecurityMode = enum { legacy_group, dtls_required };

/// Preserve a body's exact payload/errors while including refusals made by
/// source admission before the body is invoked. Requiring an error union keeps
/// the synchronous lexical callback contract explicit at instantiation.
fn SourceBodyResult(comptime BodyResult: type, comptime AdmissionErrors: type) type {
    const info = @typeInfo(BodyResult);
    if (info != .error_union) @compileError("routing body must return an error union");
    return (AdmissionErrors || info.error_union.error_set)!info.error_union.payload;
}
pub const DomainId = struct { serial: u64 };
pub const CallId = struct { domain: DomainId, serial: u64 };
pub const EndpointId = struct { call: CallId, serial: u64, leg: Leg };
pub const EndpointKey = struct { call: CallId, client: ClientId, leg: Leg };
pub const PhysicalProfileKey = EndpointKey;
pub const EndpointRef = struct {
    endpoint: EndpointId,
    offering_client: ClientId,
    bridge_policy_revision: u64,
};
pub const EndpointStamp = struct {
    endpoint: EndpointId,
    binding_revision: u64,
    security_revision: u64,
    offering_client: ClientId,
};
pub const Error = std.mem.Allocator.Error || error{
    PublisherCollision,
    InvalidIdentity,
    InvalidScope,
    StaleCandidate,
    SequenceExhausted,
    Busy,
    InvalidRequest,
    EndpointUnavailable,
    Closing,
};

pub const ChannelKey = struct {
    bytes: [client.MAX_CHANNEL_NAME_BYTES]u8 = @splat(0),
    len: u16 = 0,

    pub fn init(value: []const u8) Error!ChannelKey {
        if (value.len == 0 or value.len > client.MAX_CHANNEL_NAME_BYTES) return error.InvalidRequest;
        var key = ChannelKey{ .len = @intCast(value.len) };
        for (value, 0..) |byte, i| {
            if (byte == 0) return error.InvalidRequest;
            key.bytes[i] = std.ascii.toLower(byte);
        }
        return key;
    }
};
pub const CallRow = struct { id: CallId, offers: u32 = 0, memberships: u32 = 0 };
pub const EndpointObservation = struct {
    reference: EndpointRef,
    stamp: EndpointStamp,
    stream_id: u32,
    mode: SecurityMode,
};
const CallMap = std.AutoHashMap(ChannelKey, CallRow);
pub const EndpointEntry = struct { observation: EndpointObservation, retiring: bool = false };
const EndpointMap = std.AutoHashMap(EndpointKey, EndpointEntry);
pub const MembershipKey = struct { call: CallId, client: ClientId };
pub const MembershipEntry = struct { bits: u8, retiring: bool = false };
const MembershipMap = std.AutoHashMap(MembershipKey, MembershipEntry);
const InboundPin = struct { binding: *WebrtcBinding, ordinal: u64, source: EndpointStamp, issued_scope: u64 };
const EgressPin = struct { binding: *WebrtcBinding, ordinal: u64, source: EndpointStamp, target: EndpointStamp, issued_scope: u64 };
const Scope = struct { source: *Backing, serial: u64 };
const Backing = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    id: DomainId,
    revision: u64 = 1,
    closing: bool = false,
    next_call: u64 = 1,
    next_endpoint: u64 = 1,
    next_stream: u32 = 1,
    next_scope: u64 = 1,
    next_binding: u64 = 1,
    native_binding: ?*NativeBinding = null,
    webrtc_binding: ?*WebrtcBinding = null,
    active_scope: ?*const Locked = null,
    active_egress: ?EgressPin = null,
    active_inbound: ?InboundPin = null,
    pending_candidates: usize = 0,
    calls: CallMap,
    endpoints: EndpointMap,
    memberships: MembershipMap,
    bridge_policy: BridgeMap,
};
var next_domain = std.atomic.Value(u64).init(1);

fn issueDomain(counter: *std.atomic.Value(u64)) Error!DomainId {
    var current = counter.load(.monotonic);
    while (true) {
        if (current == 0 or current == std.math.maxInt(u64)) return error.SequenceExhausted;
        if (counter.cmpxchgWeak(current, current + 1, .monotonic, .monotonic)) |actual| current = actual else return .{ .serial = current };
    }
}
fn lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}
fn backing(domain: *Domain) *Backing {
    return @ptrCast(@alignCast(domain));
}
fn checkedNext(comptime T: type, current: T, count: T) Error!T {
    if (current == 0) return error.SequenceExhausted;
    return std.math.add(T, current, count) catch error.SequenceExhausted;
}

pub const Locked = opaque {};
pub const PristineMediaSnapshots = struct {
    native: native_owner.Snapshot,
    webrtc: webrtc_owner.Snapshot,

    pub fn deinit(self: *PristineMediaSnapshots) void {
        self.webrtc.deinit();
        self.native.deinit();
    }
};

pub const max_graph_rows: usize = 4096;
pub const GraphError = Error || error{ InvalidSnapshot, IncompleteRemap };
pub const ClientRemap = struct { source: ClientId, target: ClientId };
pub const GraphCall = struct { channel: ChannelKey, row: CallRow };
pub const GraphEndpoint = struct { key: EndpointKey, row: EndpointEntry };
pub const GraphMembership = struct { key: MembershipKey, row: MembershipEntry };
pub const GraphBridgePolicy = struct { key: EndpointKey, row: BridgePolicyRow };

/// Owned, bounded source graph. It has no Domain/owner pointer, worker, socket,
/// or publication method. A later joint Helix transaction must authenticate
/// and install every leaf together after its own validation.
pub const GraphSnapshot = struct {
    allocator: std.mem.Allocator,
    id: DomainId,
    revision: u64,
    next_call: u64,
    next_endpoint: u64,
    next_stream: u32,
    next_scope: u64,
    next_binding: u64,
    native_binding_serial: u64,
    webrtc_binding_serial: u64,
    calls: []GraphCall,
    endpoints: []GraphEndpoint,
    memberships: []GraphMembership,
    bridge_policy: []GraphBridgePolicy,

    pub fn deinit(self: *GraphSnapshot) void {
        self.allocator.free(self.bridge_policy);
        self.allocator.free(self.memberships);
        self.allocator.free(self.endpoints);
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    pub fn validate(self: *const GraphSnapshot) GraphError!void {
        if (self.id.serial == 0 or self.revision == 0 or self.next_call == 0 or self.next_endpoint == 0 or
            self.next_stream == 0 or self.next_scope == 0 or self.next_binding == 0 or
            self.native_binding_serial == 0 or self.webrtc_binding_serial == 0 or
            self.native_binding_serial == self.webrtc_binding_serial or
            self.native_binding_serial >= self.next_binding or self.webrtc_binding_serial >= self.next_binding or
            self.calls.len > max_graph_rows or self.endpoints.len > max_graph_rows or
            self.memberships.len > max_graph_rows or self.bridge_policy.len > max_graph_rows) return error.InvalidSnapshot;
        for (self.calls, 0..) |call, i| {
            if (call.channel.len == 0 or call.channel.len > call.channel.bytes.len or
                !std.meta.eql(ChannelKey.init(call.channel.bytes[0..call.channel.len]) catch return error.InvalidSnapshot, call.channel) or
                call.row.id.domain.serial != self.id.serial or call.row.id.serial == 0 or call.row.id.serial >= self.next_call or
                (call.row.offers == 0 and call.row.memberships == 0)) return error.InvalidSnapshot;
            for (self.calls[0..i]) |prior| if (std.meta.eql(prior.channel, call.channel) or std.meta.eql(prior.row.id, call.row.id)) return error.InvalidSnapshot;
            var offers: u32 = 0;
            var members: u32 = 0;
            for (self.endpoints) |endpoint| if (std.meta.eql(endpoint.key.call, call.row.id)) {
                offers += 1;
            };
            for (self.memberships) |member| if (std.meta.eql(member.key.call, call.row.id)) {
                members += 1;
            };
            if (offers != call.row.offers or members != call.row.memberships) return error.InvalidSnapshot;
        }
        for (self.endpoints, 0..) |endpoint, i| {
            const key = endpoint.key;
            const obs = endpoint.row.observation;
            if (endpoint.row.retiring or key.client.isNone() or key.call.domain.serial != self.id.serial or
                !self.hasCall(key.call) or obs.reference.offering_client.isNone() or
                !key.client.eql(obs.reference.offering_client) or !key.client.eql(obs.stamp.offering_client) or
                !std.meta.eql(obs.reference.endpoint, obs.stamp.endpoint) or
                !std.meta.eql(obs.reference.endpoint.call, key.call) or obs.reference.endpoint.leg != key.leg or
                obs.reference.endpoint.serial == 0 or obs.reference.endpoint.serial >= self.next_endpoint or
                obs.stream_id == 0 or obs.stream_id >= self.next_stream or
                obs.reference.bridge_policy_revision == 0 or obs.stamp.binding_revision == 0 or obs.stamp.security_revision == 0) return error.InvalidSnapshot;
            for (self.endpoints[0..i]) |prior| {
                if (std.meta.eql(prior.key, key) or prior.row.observation.reference.endpoint.serial == obs.reference.endpoint.serial or
                    prior.row.observation.stream_id == obs.stream_id) return error.InvalidSnapshot;
            }
        }
        for (self.memberships, 0..) |member, i| {
            if (member.row.retiring or member.key.client.isNone() or member.key.call.domain.serial != self.id.serial or
                !self.hasCall(member.key.call) or member.row.bits == 0 or member.row.bits & ~@as(u8, 7) != 0) return error.InvalidSnapshot;
            for (self.memberships[0..i]) |prior| if (std.meta.eql(prior.key, member.key)) return error.InvalidSnapshot;
        }
        for (self.bridge_policy, 0..) |policy, i| {
            const obs = self.findEndpoint(policy.key) orelse return error.InvalidSnapshot;
            if (!std.meta.eql(policy.row.reference, obs.reference) or policy.row.kind_bits == 0 or
                policy.row.kind_bits & ~@as(u8, 7) != 0 or
                !profileCanonical(policy.row.profile)) return error.InvalidSnapshot;
            const available = media_rooms.agreedKindBits(policy.row.profile) catch return error.InvalidSnapshot;
            if (policy.row.kind_bits & ~available != 0) return error.InvalidSnapshot;
            for (self.bridge_policy[0..i]) |prior| if (std.meta.eql(prior.key, policy.key)) return error.InvalidSnapshot;
        }
    }

    fn hasCall(self: *const GraphSnapshot, id: CallId) bool {
        for (self.calls) |call| if (std.meta.eql(call.row.id, id)) return true;
        return false;
    }

    fn findEndpoint(self: *const GraphSnapshot, key: EndpointKey) ?EndpointObservation {
        for (self.endpoints) |endpoint| if (std.meta.eql(endpoint.key, key)) return endpoint.row.observation;
        return null;
    }

    fn usesClient(self: *const GraphSnapshot, id: ClientId) bool {
        for (self.endpoints) |endpoint| if (endpoint.key.client.eql(id)) return true;
        for (self.memberships) |member| if (member.key.client.eql(id)) return true;
        return false;
    }
};

fn canonicalProfile(profile: media_rooms.CallProfile) GraphError!media_rooms.CallProfile {
    if (profile.codec_count == 0 or profile.codec_count > media_rooms.max_profile_codecs or
        @intFromEnum(profile.fec.scheme) > 2) return error.InvalidSnapshot;
    for (profile.codecs[0..profile.codec_count]) |codec| {
        const tag = @intFromEnum(codec.tag);
        if (tag < 1 or tag > 3) return error.InvalidSnapshot;
    }
    _ = media_rooms.agreedKindBits(profile) catch return error.InvalidSnapshot;
    var copy = media_rooms.CallProfile{
        .codecs = @splat(.{ .tag = .cadencevox, .clock_rate = 0, .params = 0 }),
        .codec_count = profile.codec_count,
        .fec = profile.fec,
    };
    @memcpy(copy.codecs[0..profile.codec_count], profile.codecs[0..profile.codec_count]);
    return copy;
}

fn profileCanonical(profile: media_rooms.CallProfile) bool {
    const canonical = canonicalProfile(profile) catch return false;
    return std.meta.eql(profile, canonical);
}

fn remappedClient(remaps: []const ClientRemap, id: ClientId) GraphError!ClientId {
    for (remaps) |remap| if (remap.source.eql(id)) return remap.target;
    return error.IncompleteRemap;
}

/// Validate the complete old-to-new physical identity mapping before any
/// mutation. Extras, duplicate sources and duplicate targets all refuse.
pub fn prepareRemappedGraph(allocator: std.mem.Allocator, source: *const GraphSnapshot, remaps: []const ClientRemap) GraphError!GraphSnapshot {
    try source.validate();
    if (remaps.len > max_graph_rows * 2) return error.InvalidSnapshot;
    for (remaps, 0..) |entry, i| {
        if (entry.source.isNone() or entry.target.isNone() or !source.usesClient(entry.source)) return error.IncompleteRemap;
        for (remaps[0..i]) |prior| if (prior.source.eql(entry.source) or prior.target.eql(entry.target)) return error.InvalidSnapshot;
    }
    for (source.endpoints) |endpoint| _ = try remappedClient(remaps, endpoint.key.client);
    for (source.memberships) |member| _ = try remappedClient(remaps, member.key.client);
    var transferred = false;
    const calls = try allocator.dupe(GraphCall, source.calls);
    errdefer if (!transferred) allocator.free(calls);
    const endpoints = try allocator.dupe(GraphEndpoint, source.endpoints);
    errdefer if (!transferred) allocator.free(endpoints);
    const memberships = try allocator.dupe(GraphMembership, source.memberships);
    errdefer if (!transferred) allocator.free(memberships);
    const policies = try allocator.dupe(GraphBridgePolicy, source.bridge_policy);
    var result = source.*;
    result.allocator = allocator;
    result.calls = calls;
    result.endpoints = endpoints;
    result.memberships = memberships;
    result.bridge_policy = policies;
    transferred = true;
    errdefer result.deinit();
    for (result.endpoints) |*endpoint| {
        endpoint.key.client = try remappedClient(remaps, endpoint.key.client);
        endpoint.row.observation.reference.offering_client = endpoint.key.client;
        endpoint.row.observation.stamp.offering_client = endpoint.key.client;
    }
    for (result.memberships) |*member| member.key.client = try remappedClient(remaps, member.key.client);
    for (result.bridge_policy) |*policy| {
        policy.key.client = try remappedClient(remaps, policy.key.client);
        policy.row.reference.offering_client = policy.key.client;
    }
    try result.validate();
    return result;
}
pub const Domain = opaque {
    pub fn create(allocator: std.mem.Allocator) Error!*Domain {
        // Exhaustion refuses before the constructor touches the backend.
        const id = try issueDomain(&next_domain);
        const source = try allocator.create(Backing);
        source.* = .{ .allocator = allocator, .id = id, .calls = CallMap.init(allocator), .endpoints = EndpointMap.init(allocator), .memberships = MembershipMap.init(allocator), .bridge_policy = BridgeMap.init(allocator) };
        return @ptrCast(source);
    }

    /// Caller must already own the outer lifetime and have joined EVERY worker,
    /// callback and waiter. Empty rows alone are not evidence of that lifetime.
    pub fn destroyQuiesced(self: *Domain) Error!void {
        const source = backing(self);
        lock(&source.mutex);
        if (source.active_inbound != null or source.active_egress != null or source.native_binding != null or source.webrtc_binding != null or source.pending_candidates != 0 or source.endpoints.count() != 0 or source.calls.count() != 0 or source.memberships.count() != 0 or source.bridge_policy.count() != 0) {
            source.mutex.unlock();
            return error.Busy;
        }
        const allocator = source.allocator;
        // Release the embedded mutex before all backend destruction.
        source.mutex.unlock();
        source.bridge_policy.deinit();
        source.memberships.deinit();
        source.endpoints.deinit();
        source.calls.deinit();
        allocator.destroy(source);
    }

    /// Bind actual pristine owner contexts; no callback-provided readiness or
    /// opaque pointer registration. Owner and Domain lifetimes remain joined.
    pub fn bindNative(self: *Domain, owner: *native_owner.NativeMediaTransport) Error!*NativeBinding {
        const source = backing(self);
        lock(&source.mutex);
        if (source.closing) {
            source.mutex.unlock();
            return error.Closing;
        }
        if (source.native_binding != null) {
            source.mutex.unlock();
            return error.Busy;
        }
        const serial = checkedNext(u64, source.next_binding, 1) catch |err| {
            source.mutex.unlock();
            return err;
        };
        source.pending_candidates = std.math.add(usize, source.pending_candidates, 1) catch {
            source.mutex.unlock();
            return error.SequenceExhausted;
        };
        const issuance = source.next_binding;
        source.mutex.unlock();
        defer unpinCandidate(source);
        const record = try source.allocator.create(NativeBindingBacking);
        errdefer source.allocator.destroy(record);
        record.* = .{ .source = source, .owner = owner, .serial = issuance };
        const binding: *NativeBinding = @ptrCast(record);
        const Context = struct {
            domain: *Domain,
            binding: *NativeBinding,
            owner: *native_owner.NativeMediaTransport,
            issuance: u64,
            next: u64,
            fn run(scope: *Locked, ctx: @This()) Error!void {
                const b = backing(ctx.domain);
                if (b.native_binding != null or b.next_binding != ctx.issuance) return error.StaleCandidate;
                b.native_binding = ctx.binding;
                ctx.owner.attachRoutingLocked(ctx.domain, scope, ctx.binding) catch |err| {
                    b.native_binding = null;
                    return err;
                };
                b.next_binding = ctx.next;
            }
        };
        try self.withLocked(Context{ .domain = self, .binding = binding, .owner = owner, .issuance = issuance, .next = serial }, Context.run);
        return binding;
    }
    pub fn bindWebrtc(self: *Domain, owner: *webrtc_owner.MediaPlane) Error!*WebrtcBinding {
        const source = backing(self);
        lock(&source.mutex);
        if (source.closing) {
            source.mutex.unlock();
            return error.Closing;
        }
        if (source.webrtc_binding != null) {
            source.mutex.unlock();
            return error.Busy;
        }
        const serial = checkedNext(u64, source.next_binding, 1) catch |err| {
            source.mutex.unlock();
            return err;
        };
        source.pending_candidates = std.math.add(usize, source.pending_candidates, 1) catch {
            source.mutex.unlock();
            return error.SequenceExhausted;
        };
        const issuance = source.next_binding;
        source.mutex.unlock();
        defer unpinCandidate(source);
        const record = try source.allocator.create(WebrtcBindingBacking);
        errdefer source.allocator.destroy(record);
        record.* = .{ .source = source, .owner = owner, .serial = issuance };
        const binding: *WebrtcBinding = @ptrCast(record);
        const Context = struct {
            domain: *Domain,
            binding: *WebrtcBinding,
            owner: *webrtc_owner.MediaPlane,
            issuance: u64,
            next: u64,
            fn run(scope: *Locked, ctx: @This()) Error!void {
                const b = backing(ctx.domain);
                if (b.webrtc_binding != null or b.next_binding != ctx.issuance) return error.StaleCandidate;
                b.webrtc_binding = ctx.binding;
                ctx.owner.attachRoutingLocked(ctx.domain, scope, ctx.binding) catch |err| {
                    b.webrtc_binding = null;
                    return err;
                };
                b.next_binding = ctx.next;
            }
        };
        try self.withLocked(Context{ .domain = self, .binding = binding, .owner = owner, .issuance = issuance, .next = serial }, Context.run);
        return binding;
    }
    pub fn requireNativeBindingLocked(self: *Domain, token: *const Locked, binding: *NativeBinding, owner: *native_owner.NativeMediaTransport) Error!void {
        _ = try self.requireScope(token);
        const source = backing(self);
        if (source.native_binding != binding) return error.InvalidIdentity;
        const record: *NativeBindingBacking = @ptrCast(@alignCast(binding));
        if (record.source != source or record.owner != owner or record.serial == 0) return error.InvalidIdentity;
    }
    pub fn webrtcSourceContextLocked(self: *Domain, token: *const Locked, binding: *WebrtcBinding, owner: *webrtc_owner.MediaPlane) Error!IngressContext {
        try self.requireWebrtcBindingLocked(token, binding, owner);
        const record: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
        return .{ .domain = backing(self).id.serial, .registration = record.serial, .scope = (try self.requireScope(token)).serial };
    }
    pub fn resolveReferenceLocked(self: *Domain, token: *const Locked, reference: EndpointRef) Error!EndpointObservation {
        const key: EndpointKey = .{ .call = reference.endpoint.call, .client = reference.offering_client, .leg = reference.endpoint.leg };
        const row = (try self.observeLocked(token, key)) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(row.reference, reference)) return error.EndpointUnavailable;
        _ = try self.requireCurrentLocked(token, row.stamp);
        return row;
    }

    pub fn requireWebrtcBindingLocked(self: *Domain, token: *const Locked, binding: *WebrtcBinding, owner: *webrtc_owner.MediaPlane) Error!void {
        _ = try self.requireScope(token);
        const source = backing(self);
        if (source.webrtc_binding != binding) return error.InvalidIdentity;
        const record: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
        if (record.source != source or record.owner != owner or record.serial == 0) return error.InvalidIdentity;
    }

    /// The initial graph issuers prove that an empty graph was never a live
    /// graph later retired. Binding issuers may advance only for the original
    /// native and WebRTC registrations. The lexical Domain lock excludes a
    /// concurrent graph publication throughout both owner snapshots.
    pub fn requirePristineConfiguredMediaLocked(self: *Domain, token: *const Locked, native: *native_owner.NativeMediaTransport, webrtc: *webrtc_owner.MediaPlane) Error!void {
        _ = try self.requireScope(token);
        const source = backing(self);
        const native_binding = source.native_binding orelse return error.InvalidIdentity;
        const webrtc_binding = source.webrtc_binding orelse return error.InvalidIdentity;
        try self.requireNativeBindingLocked(token, native_binding, native);
        try self.requireWebrtcBindingLocked(token, webrtc_binding, webrtc);
        if (source.closing or source.next_binding != 3 or source.revision != 1 or
            source.next_call != 1 or source.next_endpoint != 1 or source.next_stream != 1 or
            source.pending_candidates != 0 or source.active_inbound != null or source.active_egress != null or
            source.calls.count() != 0 or source.endpoints.count() != 0 or
            source.memberships.count() != 0 or source.bridge_policy.count() != 0)
            return error.Busy;
    }

    /// Capture the exact original owners while both workers are paused. This
    /// dedicated cut permits only read-only local socket identity observation
    /// under the Domain lock; no networking, allocation, or external callback.
    pub fn capturePausedPristineMedia(self: *Domain, native: *native_owner.NativeMediaTransport, native_token: runtime_pause.Token, webrtc: *webrtc_owner.MediaPlane, webrtc_token: runtime_pause.Token) !PristineMediaSnapshots {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        if (source.closing) return error.Closing;
        if (source.next_scope == std.math.maxInt(u64)) return error.SequenceExhausted;
        var scope = Scope{ .source = source, .serial = source.next_scope };
        source.next_scope += 1;
        const token: *Locked = @ptrCast(&scope);
        source.active_scope = token;
        defer source.active_scope = null;
        try self.requirePristineConfiguredMediaLocked(token, native, webrtc);
        var native_snapshot = try native.capturePausedPristineRoutingLocked(self, token, webrtc, native_token);
        errdefer native_snapshot.deinit();
        const webrtc_snapshot = try webrtc.capturePausedPristineRoutingLocked(self, token, native, webrtc_token);
        return .{ .native = native_snapshot, .webrtc = webrtc_snapshot };
    }

    /// Copy the active routing graph only while both exact physical owners are
    /// paused and the Domain has no in-flight scope, pin, or prepared row. The
    /// returned DTO carries no owner capability and cannot route packets.
    pub fn captureGraph(self: *Domain, native: *native_owner.NativeMediaTransport, native_token: runtime_pause.Token, webrtc: *webrtc_owner.MediaPlane, webrtc_token: runtime_pause.Token) !GraphSnapshot {
        try native.runtime.pause.requirePaused(native_token);
        try webrtc.runtime.pause.requirePaused(webrtc_token);
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        if (source.closing) return error.Closing;
        const native_binding = source.native_binding orelse return error.InvalidIdentity;
        const webrtc_binding = source.webrtc_binding orelse return error.InvalidIdentity;
        const native_record: *NativeBindingBacking = @ptrCast(@alignCast(native_binding));
        const webrtc_record: *WebrtcBindingBacking = @ptrCast(@alignCast(webrtc_binding));
        if (native_record.source != source or native_record.owner != native or native_record.serial == 0 or
            webrtc_record.source != source or webrtc_record.owner != webrtc or webrtc_record.serial == 0) return error.InvalidIdentity;
        if (source.active_scope != null or source.active_inbound != null or source.active_egress != null or
            source.pending_candidates != 0 or native.physical_pending != 0 or native.active_ingress != null or
            webrtc.physical_pending != 0 or webrtc.routing_inbound != null or
            webrtc.retired_routing_egress != null or webrtc.rtcp_out_len != 0) return error.Busy;
        if (source.calls.count() > max_graph_rows or source.endpoints.count() > max_graph_rows or
            source.memberships.count() > max_graph_rows or source.bridge_policy.count() > max_graph_rows) return error.Busy;
        const allocator = source.allocator;
        const calls = try allocator.alloc(GraphCall, source.calls.count());
        errdefer allocator.free(calls);
        const endpoints = try allocator.alloc(GraphEndpoint, source.endpoints.count());
        errdefer allocator.free(endpoints);
        const memberships = try allocator.alloc(GraphMembership, source.memberships.count());
        errdefer allocator.free(memberships);
        const policies = try allocator.alloc(GraphBridgePolicy, source.bridge_policy.count());
        errdefer allocator.free(policies);
        var ci: usize = 0;
        var call_it = source.calls.iterator();
        while (call_it.next()) |entry| : (ci += 1) calls[ci] = .{ .channel = entry.key_ptr.*, .row = entry.value_ptr.* };
        var ei: usize = 0;
        var endpoint_it = source.endpoints.iterator();
        while (endpoint_it.next()) |entry| : (ei += 1) endpoints[ei] = .{ .key = entry.key_ptr.*, .row = entry.value_ptr.* };
        var mi: usize = 0;
        var member_it = source.memberships.iterator();
        while (member_it.next()) |entry| : (mi += 1) memberships[mi] = .{ .key = entry.key_ptr.*, .row = entry.value_ptr.* };
        var pi: usize = 0;
        var policy_it = source.bridge_policy.iterator();
        while (policy_it.next()) |entry| : (pi += 1) policies[pi] = .{
            .key = entry.key_ptr.*,
            .row = .{
                .reference = entry.value_ptr.reference,
                .profile = try canonicalProfile(entry.value_ptr.profile),
                .kind_bits = entry.value_ptr.kind_bits,
            },
        };
        const graph = GraphSnapshot{
            .allocator = allocator,
            .id = source.id,
            .revision = source.revision,
            .next_call = source.next_call,
            .next_endpoint = source.next_endpoint,
            .next_stream = source.next_stream,
            .next_scope = source.next_scope,
            .next_binding = source.next_binding,
            .native_binding_serial = native_record.serial,
            .webrtc_binding_serial = webrtc_record.serial,
            .calls = calls,
            .endpoints = endpoints,
            .memberships = memberships,
            .bridge_policy = policies,
        };
        try graph.validate();
        return graph;
    }
    pub fn releaseNative(self: *Domain, binding: *NativeBinding) Error!void {
        const source = backing(self);
        const Context = struct {
            domain: *Domain,
            binding: *NativeBinding,
            fn run(scope: *Locked, ctx: @This()) Error!void {
                const b = backing(ctx.domain);
                if (b.native_binding != ctx.binding) return error.InvalidIdentity;
                const record: *NativeBindingBacking = @ptrCast(@alignCast(ctx.binding));
                try ctx.domain.requireNativeBindingLocked(scope, ctx.binding, record.owner);
                if (b.pending_candidates != 0) return error.Busy;
                var endpoints = b.endpoints.keyIterator();
                while (endpoints.next()) |key| if (key.leg == .native) return error.Busy;
                try record.owner.requireRoutingReleasable();
                record.owner.detachRoutingLocked(ctx.domain, scope, ctx.binding);
                b.native_binding = null;
            }
        };
        if (source.closing) try self.withTerminalLocked(Context{ .domain = self, .binding = binding }, Context.run) else try self.withLocked(Context{ .domain = self, .binding = binding }, Context.run);
        // External lifetime joins all callers; no one can use binding after this.
        source.allocator.destroy(@as(*NativeBindingBacking, @ptrCast(@alignCast(binding))));
    }
    pub fn releaseWebrtc(self: *Domain, binding: *WebrtcBinding) Error!void {
        const source = backing(self);
        const Context = struct {
            domain: *Domain,
            binding: *WebrtcBinding,
            fn run(scope: *Locked, ctx: @This()) Error!void {
                const b = backing(ctx.domain);
                if (b.webrtc_binding != ctx.binding) return error.InvalidIdentity;
                const record: *WebrtcBindingBacking = @ptrCast(@alignCast(ctx.binding));
                try ctx.domain.requireWebrtcBindingLocked(scope, ctx.binding, record.owner);
                if (b.pending_candidates != 0) return error.Busy;
                var endpoints = b.endpoints.keyIterator();
                while (endpoints.next()) |key| if (key.leg == .webrtc) return error.Busy;
                try record.owner.requireRoutingReleasable();
                record.owner.detachRoutingLocked(ctx.domain, scope, ctx.binding);
                b.webrtc_binding = null;
            }
        };
        if (source.closing) try self.withTerminalLocked(Context{ .domain = self, .binding = binding }, Context.run) else try self.withLocked(Context{ .domain = self, .binding = binding }, Context.run);
        source.allocator.destroy(@as(*WebrtcBindingBacking, @ptrCast(@alignCast(binding))));
    }

    /// Body is a source-owned synchronous operation returning an error union.
    /// No backend, network wait, World acquisition or external callback in body.
    pub fn withLocked(self: *Domain, ctx: anytype, comptime body: anytype) SourceBodyResult(@TypeOf(body(@as(*Locked, undefined), ctx)), error{ Closing, SequenceExhausted }) {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        if (source.closing) return error.Closing;
        if (source.next_scope == std.math.maxInt(u64)) return error.SequenceExhausted;
        var scope = Scope{ .source = source, .serial = source.next_scope };
        source.next_scope += 1;
        const token: *Locked = @ptrCast(&scope);
        source.active_scope = token;
        defer source.active_scope = null;
        return body(token, ctx);
    }

    /// One joined update for every actually offered leg of this physical caller.
    /// Prevalidation touches no allocator, socket or crypto state. Stamp advance
    /// invalidates queued OLD selection while preserving accepted SRTP history.
    pub fn setPhysicalSelection(self: *Domain, channel_name: []const u8, client_id: ClientId, selection: native_owner.Selection) !void {
        const channel = try ChannelKey.init(channel_name);
        if (client_id.isNone()) return error.InvalidIdentity;
        const Update = struct {
            domain: *Domain,
            channel: ChannelKey,
            client_id: ClientId,
            selection: native_owner.Selection,
            fn run(scope: *Locked, ctx: @This()) !void {
                try ctx.domain.requireNoActiveIngressLocked(scope);
                const source = backing(ctx.domain);
                const call = source.calls.get(ctx.channel) orelse return error.EndpointUnavailable;
                if (clientRetiring(source, ctx.client_id)) return error.EndpointUnavailable;
                const next_revision = try checkedNext(u64, source.revision, 1);
                var observations: [2]?EndpointObservation = .{ null, null };
                for ([_]Leg{ .native, .webrtc }, 0..) |leg, i| {
                    const key = EndpointKey{ .call = call.id, .client = ctx.client_id, .leg = leg };
                    const old = endpointObservation(source, key) orelse continue;
                    _ = try ctx.domain.requireCurrentLocked(scope, old.stamp);
                    var next = old;
                    next.stamp.security_revision = try checkedNext(u64, old.stamp.security_revision, 1);
                    switch (leg) {
                        .native => {
                            const binding = source.native_binding orelse return error.InvalidIdentity;
                            const record: *NativeBindingBacking = @ptrCast(@alignCast(binding));
                            try record.owner.requirePhysicalSelectionLocked(ctx.domain, scope, old);
                        },
                        .webrtc => {
                            const binding = source.webrtc_binding orelse return error.InvalidIdentity;
                            const record: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
                            try record.owner.requirePhysicalSelectionLocked(ctx.domain, scope, old);
                        },
                    }
                    observations[i] = next;
                }
                if (observations[0] == null and observations[1] == null) return error.EndpointUnavailable;
                for (observations) |maybe| if (maybe) |next| {
                    const key = EndpointKey{ .call = call.id, .client = ctx.client_id, .leg = next.stamp.endpoint.leg };
                    switch (key.leg) {
                        .native => {
                            const record: *NativeBindingBacking = @ptrCast(@alignCast(source.native_binding.?));
                            record.owner.commitPhysicalSelectionLocked(ctx.domain, scope, next, ctx.selection);
                        },
                        .webrtc => {
                            const record: *WebrtcBindingBacking = @ptrCast(@alignCast(source.webrtc_binding.?));
                            record.owner.commitPhysicalSelectionLocked(ctx.domain, scope, next, ctx.selection);
                        },
                    }
                    source.endpoints.getPtr(key).?.observation = next;
                };
                source.revision = next_revision;
            }
        };
        try self.withLocked(Update{ .domain = self, .channel = channel, .client_id = client_id, .selection = selection }, Update.run);
    }

    /// Immediate irreversible admission denial BEFORE fallible client cleanup.
    /// It mutates only actual existing source rows; no allocation/counter/new
    /// proof issuer is required. Existing accepted send pins retain their exact
    /// bytes and crypto custody until completion, but no new ingress/queue
    /// attempt or stale preprepared OFFER/JOIN can use this client afterwards.
    /// Full ClientId comes from the actual Server source, never a nickname.
    pub fn fenceClientRetirement(self: *Domain, client_id: ClientId) Error!ClientRetirementObservation {
        if (client_id.isNone()) return error.InvalidIdentity;
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        var observed = ClientRetirementObservation{};
        var endpoints = source.endpoints.iterator();
        while (endpoints.next()) |entry| if (entry.key_ptr.client.eql(client_id)) {
            entry.value_ptr.retiring = true;
            observed.offers += 1;
        };
        var memberships = source.memberships.iterator();
        while (memberships.next()) |entry| if (entry.key_ptr.client.eql(client_id)) {
            entry.value_ptr.retiring = true;
            observed.memberships += 1;
        };
        return observed;
    }

    /// Irreversible source closure follows actual worker join/View detach. No
    /// caller boolean can assert those facts. Pending candidates and queues
    /// must settle before this phase; ordinary admissions can never resume.
    pub fn closeForTerminal(self: *Domain) Error!void {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        if (source.closing) return;
        if (source.pending_candidates != 0 or source.active_egress != null or source.active_inbound != null) return error.Busy;
        if (source.native_binding) |binding| {
            const record: *NativeBindingBacking = @ptrCast(@alignCast(binding));
            try record.owner.requireRoutingTerminal();
        }
        if (source.webrtc_binding) |binding| {
            const record: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
            try record.owner.requireRoutingTerminal();
        }
        source.closing = true;
        var scope = Scope{ .source = source, .serial = std.math.maxInt(u64) };
        const token: *Locked = @ptrCast(&scope);
        source.active_scope = token;
        defer source.active_scope = null;
        if (source.native_binding) |binding| {
            const record: *NativeBindingBacking = @ptrCast(@alignCast(binding));
            record.owner.latchRoutingTerminal(self, token, binding);
        }
        if (source.webrtc_binding) |binding| {
            const record: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
            record.owner.latchRoutingTerminal(self, token, binding);
        }
    }

    /// Reserved lexical terminal scope, never an ordinary operation issuer.
    /// Exact retirement plans compare OLD rows, and no new rows can be admitted.
    /// Reuse of the lexical token outside this callback is forbidden, as for
    /// withLocked; this is not an authenticated ingress-operation handle.
    pub fn withTerminalLocked(self: *Domain, ctx: anytype, comptime body: anytype) SourceBodyResult(@TypeOf(body(@as(*Locked, undefined), ctx)), error{Busy}) {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        if (!source.closing) return error.Busy;
        var scope = Scope{ .source = source, .serial = std.math.maxInt(u64) };
        const token: *Locked = @ptrCast(&scope);
        source.active_scope = token;
        defer source.active_scope = null;
        return body(token, ctx);
    }
    pub fn requireTerminalLocked(self: *Domain, token: *const Locked) Error!void {
        _ = try self.requireScope(token);
        if (!backing(self).closing) return error.Busy;
    }

    fn requireScope(self: *Domain, token: *const Locked) Error!*Scope {
        const source = backing(self);
        if (source.active_scope != token) return error.InvalidScope;
        // Compare the exact canonical pointer before reading the borrowed scope.
        const scope: *Scope = @ptrCast(@alignCast(@constCast(token)));
        if (scope.source != source or scope.serial == 0) return error.InvalidScope;
        return scope;
    }

    pub fn scopeSerial(self: *Domain, token: *const Locked) Error!u64 {
        return (try self.requireScope(token)).serial;
    }

    pub fn observeLocked(self: *Domain, token: *const Locked, key: EndpointKey) Error!?EndpointObservation {
        _ = try self.requireScope(token);
        if (key.call.domain.serial != backing(self).id.serial or key.client.isNone()) return error.InvalidIdentity;
        return endpointObservation(backing(self), key);
    }

    pub fn requireCurrentLocked(self: *Domain, token: *const Locked, expected: EndpointStamp) Error!EndpointObservation {
        _ = try self.requireScope(token);
        const entry = backing(self).endpoints.get(.{ .call = expected.endpoint.call, .client = expected.offering_client, .leg = expected.endpoint.leg }) orelse return error.EndpointUnavailable;
        if (entry.retiring) return error.EndpointUnavailable;
        const row = entry.observation;
        if (!std.meta.eql(row.stamp, expected)) return error.EndpointUnavailable;
        return row;
    }

    /// Registration selectors are observations, never authenticated issuers.
    pub fn nativeIngressContextLocked(self: *Domain, token: *const Locked, binding: *NativeBinding, owner: *native_owner.NativeMediaTransport) Error!IngressContext {
        try self.requireNativeBindingLocked(token, binding, owner);
        if (backing(self).closing) return error.Closing;
        if (backing(self).webrtc_binding) |queue_binding| {
            const queue_owner: *WebrtcBindingBacking = @ptrCast(@alignCast(queue_binding));
            try queue_owner.owner.requireRoutingProducerAdmissionLocked(self, token);
        }
        const registration: *NativeBindingBacking = @ptrCast(@alignCast(binding));
        return .{ .domain = backing(self).id.serial, .registration = registration.serial, .scope = (try self.requireScope(token)).serial };
    }

    /// Resolve a selector only through the canonical registered source's live
    /// authenticated operation. In particular no caller-chosen bytes enter here.
    pub fn resolveNativeIngressLocked(self: *Domain, token: *const Locked, handle: IngressHandle) native_owner.IngressError!native_owner.AuthenticatedFrame {
        const scope = try self.requireScope(token);
        const source = backing(self);
        if (source.closing) return error.Closing;
        const word = @intFromEnum(handle);
        if (@as(u64, @truncate(word)) != source.id.serial or @as(u64, @truncate(word >> 128)) != scope.serial) return error.InvalidIngress;
        const binding = source.native_binding orelse return error.InvalidIngress;
        const record: *NativeBindingBacking = @ptrCast(@alignCast(binding));
        if (record.source != source or record.serial != @as(u64, @truncate(word >> 64))) return error.InvalidIngress;
        const frame = try record.owner.inspectAuthenticatedFrameLocked(self, token, handle);
        _ = try self.requireCurrentLocked(token, frame.source);
        return frame;
    }

    pub fn preflightNativeIngressBindingLocked(self: *Domain, token: *const Locked, expected: EndpointStamp) Error!void {
        _ = try self.requireCurrentLocked(token, expected);
        if (backing(self).active_egress != null or backing(self).active_inbound != null) return error.Busy;
        if (backing(self).closing) return error.Closing;
        _ = try checkedNext(u64, backing(self).revision, 1);
        _ = try checkedNext(u64, expected.binding_revision, 1);
    }

    pub fn requireBridgeNegotiationLocked(self: *Domain, token: *const Locked, reference: EndpointRef, profile: media_rooms.CallProfile, kind_bits: u8) Error!void {
        _ = try self.resolveReferenceLocked(token, reference);
        const row = backing(self).bridge_policy.get(.{ .call = reference.endpoint.call, .client = reference.offering_client, .leg = reference.endpoint.leg }) orelse return error.InvalidIdentity;
        if (!std.meta.eql(row.reference, reference) or !row.profile.eql(profile) or row.kind_bits != kind_bits) return error.InvalidIdentity;
    }

    /// Complete actual physical endpoint traversal; source operations are
    /// verified first and each exact recipient owns its packet independently.
    /// This inventory is physical, so nickname siblings never overwrite it.
    pub fn fanoutNativeToWebrtcLocked(self: *Domain, token: *const Locked, handle: IngressHandle) !FanoutResult {
        const frame = try self.resolveNativeIngressLocked(token, handle);
        if (frame.content == .feedback) return self.fanoutNativeFeedbackLocked(token, handle);
        const source = backing(self);
        var result = FanoutResult{ .recognized = true };
        const source_policy = source.bridge_policy.get(.{ .call = frame.source.endpoint.call, .client = frame.source.offering_client, .leg = .native }) orelse return error.RouteDenied;
        const current_source = try self.requireCurrentLocked(token, frame.source);
        if (!std.meta.eql(source_policy.reference, current_source.reference) or !source_policy.profile.eql(frame.profile) or source_policy.kind_bits != frame.kind_bits) return error.RouteDenied;
        const binding = source.webrtc_binding orelse return result;
        const registered: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
        var rows = source.endpoints.valueIterator();
        while (rows.next()) |entry| {
            if (entry.retiring) continue;
            const target = &entry.observation;
            if (!std.meta.eql(target.stamp.endpoint.call, frame.source.endpoint.call) or std.meta.eql(target.stamp.offering_client, frame.source.offering_client)) continue;
            const target_policy = source.bridge_policy.get(.{ .call = target.stamp.endpoint.call, .client = target.stamp.offering_client, .leg = target.stamp.endpoint.leg }) orelse {
                result.refused += 1;
                result.last_refusal = error.RouteDenied;
                continue;
            };
            if (!std.meta.eql(target_policy.reference, target.reference)) {
                result.refused += 1;
                result.last_refusal = error.RouteDenied;
                continue;
            }
            _ = registered.owner.enqueueNativeFrameLocked(self, token, handle, target.stamp) catch |err| {
                result.last_refusal = err;
                result.refused = std.math.add(u32, result.refused, 1) catch return error.SequenceExhausted;
                continue;
            };
            result.accepted = std.math.add(u32, result.accepted, 1) catch return error.SequenceExhausted;
        }
        return result;
    }

    pub fn fanoutNativeFeedbackLocked(self: *Domain, scope: *const Locked, handle: IngressHandle) !FanoutResult {
        const frame = try self.resolveNativeIngressLocked(scope, handle);
        if (frame.content != .feedback) return error.InvalidIngress;
        const selected = try native_owner.NativeMediaTransport.feedbackTargetStream(frame.bytes);
        const current = try self.requireCurrentLocked(scope, frame.source);
        try self.requireBridgeNegotiationLocked(scope, current.reference, frame.profile, frame.kind_bits);
        const source = backing(self);
        const binding = source.webrtc_binding orelse return error.InvalidIdentity;
        const queue_owner: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
        var rows = source.endpoints.valueIterator();
        while (rows.next()) |entry| {
            const target = entry.observation;
            if (target.stream_id != selected or entry.retiring) continue;
            if (!std.meta.eql(target.stamp.endpoint.call, frame.source.endpoint.call) or target.stamp.offering_client.eql(frame.source.offering_client)) return error.RouteDenied;
            _ = queue_owner.owner.enqueueNativeFeedbackLocked(self, scope, handle, target.stamp) catch |err| return .{ .recognized = true, .refused = 1, .last_refusal = err };
            return .{ .recognized = true, .accepted = 1 };
        }
        return error.RouteDenied;
    }
    pub fn requireNativeFeedbackTargetLocked(self: *Domain, scope: *const Locked, target: EndpointStamp, payload: []const u8) !void {
        const current = try self.requireCurrentLocked(scope, target);
        if (target.endpoint.leg != .native) return error.InvalidIdentity;
        const binding = backing(self).native_binding orelse return error.InvalidIdentity;
        const actual: *NativeBindingBacking = @ptrCast(@alignCast(binding));
        try actual.owner.requireRoutedFeedbackTargetLocked(self, scope, current, payload);
    }

    /// Genuine native-target packet policy under the shared cut. No key,
    /// socket, allocator or caller-authenticated boolean is returned.
    pub fn requireNativeTargetLocked(self: *Domain, scope: *const Locked, target: EndpointStamp, bytes: []const u8) !void {
        const current = try self.requireCurrentLocked(scope, target);
        if (target.endpoint.leg != .native) return error.InvalidIdentity;
        const binding = backing(self).native_binding orelse return error.InvalidIdentity;
        const actual: *NativeBindingBacking = @ptrCast(@alignCast(binding));
        try actual.owner.requireRoutedFrameTargetLocked(self, scope, current, bytes);
    }

    /// Only the privately issued owned queue operation can resolve this source
    /// relation. Publication/retirement remains blocked by its retained pin.
    pub fn nativeEgressTarget(self: *Domain, native: *native_owner.NativeMediaTransport, owner: *webrtc_owner.MediaPlane, ordinal: u64) !EndpointObservation {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        const pin = source.active_egress orelse return error.InvalidIdentity;
        if (pin.ordinal != ordinal or source.closing or pin.target.endpoint.leg != .native) return error.InvalidIdentity;
        var reserved = Scope{ .source = source, .serial = pin.issued_scope };
        const scope: *Locked = @ptrCast(&reserved);
        std.debug.assert(source.active_scope == null);
        source.active_scope = scope;
        defer source.active_scope = null;
        try self.requireWebrtcBindingLocked(scope, pin.binding, owner);
        try self.requireNativeBindingLocked(scope, source.native_binding orelse return error.InvalidIdentity, native);
        const row = try owner.inspectRoutingEgressAttemptLocked(self, scope, ordinal);
        if (!std.meta.eql(row.source, pin.source) or !std.meta.eql(row.target, pin.target)) return error.InvalidIdentity;
        _ = try self.requireCurrentLocked(scope, row.source);
        return self.requireCurrentLocked(scope, row.target);
    }

    /// Concrete source dispatch, never a generic callback under the gate.
    /// Native's method obtains the actual pin/canonical owned bytes and emits
    /// after every source lock is released. It cannot use arbitrary bytes.
    pub fn sendNativeRoutingEgress(self: *Domain, owner: *webrtc_owner.MediaPlane, ordinal: u64) !@import("media_socket.zig").SendDisposition {
        const source = backing(self);
        const native = acquire: {
            lock(&source.mutex);
            defer source.mutex.unlock();
            const pin = source.active_egress orelse return error.InvalidIdentity;
            if (source.closing or pin.ordinal != ordinal or pin.target.endpoint.leg != .native) return error.InvalidIdentity;
            var reserved = Scope{ .source = source, .serial = pin.issued_scope };
            const scope: *Locked = @ptrCast(&reserved);
            std.debug.assert(source.active_scope == null);
            source.active_scope = scope;
            defer source.active_scope = null;
            try self.requireWebrtcBindingLocked(scope, pin.binding, owner);
            const owned = try owner.inspectRoutingEgressAttemptLocked(self, scope, ordinal);
            if (!std.meta.eql(owned.source, pin.source) or !std.meta.eql(owned.target, pin.target)) return error.InvalidIdentity;
            const binding = source.native_binding orelse return error.InvalidIdentity;
            const actual: *NativeBindingBacking = @ptrCast(@alignCast(binding));
            try self.requireNativeBindingLocked(scope, binding, actual.owner);
            // The real pin now proves the captured owner cannot be released
            // between lock exit and its source-only send method below.
            break :acquire actual.owner;
        };
        return native.sendRoutedPacketPinned(owner, ordinal);
    }

    /// Actual source pump owns the original datagram slot; this is a lifetime
    /// pin, not a claim that DTLS or SRTP authentication has already completed.
    pub fn holdWebrtcInboundLocked(self: *Domain, token: *const Locked, owner: *webrtc_owner.MediaPlane, ordinal: u64) !void {
        const source = backing(self);
        const binding = source.webrtc_binding orelse return error.InvalidIdentity;
        try self.requireWebrtcBindingLocked(token, binding, owner);
        if (source.closing or source.active_egress != null or source.active_inbound != null) return error.Busy;
        const actual = try owner.inspectRoutingInboundLocked(self, token, ordinal);
        _ = try self.requireCurrentLocked(token, actual);
        source.active_inbound = .{ .binding = binding, .ordinal = ordinal, .source = actual, .issued_scope = try self.scopeSerial(token) };
    }

    /// A STUN response has already been completely prepared. Recheck the real
    /// private authenticated request and capacity before any binding mutation.
    pub fn publishWebrtcBindingLocked(self: *Domain, token: *const Locked, owner: *webrtc_owner.MediaPlane, ordinal: u64) !void {
        const source = backing(self);
        const pin = source.active_inbound orelse return error.InvalidIdentity;
        if (pin.ordinal != ordinal) return error.InvalidIdentity;
        try self.requireWebrtcBindingLocked(token, pin.binding, owner);
        const old = try self.requireCurrentLocked(token, pin.source);
        const first = try owner.validateRoutingStunBindingLocked(self, token, ordinal);
        if (!first) return;
        const next_revision = try checkedNext(u64, source.revision, 1);
        var next = old;
        next.stamp.binding_revision = try checkedNext(u64, old.stamp.binding_revision, 1);
        owner.commitRoutingStunBindingLocked(self, token, ordinal, next);
        source.endpoints.getPtr(.{ .call = next.stamp.endpoint.call, .client = next.stamp.offering_client, .leg = .webrtc }).?.observation = next;
        source.active_inbound.?.source = next.stamp;
        source.revision = next_revision;
    }

    /// Resolve the already-issued actual pump operation at exhaustion without
    /// new admission or callbacks. Retained original bytes remain checked.
    pub fn completeWebrtcInbound(self: *Domain, owner: *webrtc_owner.MediaPlane, ordinal: u64) !void {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        const pin = source.active_inbound orelse return error.InvalidIdentity;
        if (source.closing or pin.ordinal != ordinal or pin.issued_scope == 0 or pin.issued_scope == std.math.maxInt(u64)) return error.InvalidIdentity;
        std.debug.assert(source.active_scope == null);
        var reserved = Scope{ .source = source, .serial = pin.issued_scope };
        const token: *Locked = @ptrCast(&reserved);
        source.active_scope = token;
        defer source.active_scope = null;
        try self.requireWebrtcBindingLocked(token, pin.binding, owner);
        const actual = try owner.inspectRoutingInboundLocked(self, token, ordinal);
        if (!std.meta.eql(actual, pin.source)) return error.InvalidIdentity;
        source.active_inbound = null;
    }

    /// Resolve canonical media only from the actual private pump operation,
    /// after genuine source decryption/declared group-leg admission. The scalar
    /// ordinal, copied stamp and arbitrary producer bytes cannot issue it.
    pub fn resolveWebrtcCanonicalLocked(self: *Domain, token: *const Locked, owner: *webrtc_owner.MediaPlane, ordinal: u64) !webrtc_owner.AuthenticatedWebrtcFrame {
        const source = backing(self);
        const pin = source.active_inbound orelse return error.InvalidIdentity;
        if (pin.ordinal != ordinal) return error.InvalidIdentity;
        try self.requireWebrtcBindingLocked(token, pin.binding, owner);
        const frame = try owner.inspectRoutingCanonicalLocked(self, token, ordinal);
        if (!std.meta.eql(frame.source, pin.source)) return error.InvalidIdentity;
        const current = try self.requireCurrentLocked(token, frame.source);
        try self.requireBridgeNegotiationLocked(token, current.reference, frame.profile, frame.kind_bits);
        return frame;
    }

    /// Uses only the reserved issuance of the actual held inbound operation.
    /// All target admissions own their canonical packet copy independently.
    /// Native-issued RTP identities and accepted physical RTC SSRCs share the
    /// actual receiver namespace. Refuse a collision before either source can
    /// publish replay, cache or identifier ownership; never choose by priority.
    pub fn requireWebrtcSsrcAvailableLocked(self: *Domain, token: *const Locked, ssrc: u32) Error!void {
        _ = try self.requireScope(token);
        var it = backing(self).endpoints.valueIterator();
        while (it.next()) |row| if (!row.retiring and row.observation.stamp.endpoint.leg == .native and row.observation.stream_id == ssrc) return error.PublisherCollision;
    }
    pub fn requireNativeStreamAvailableLocked(self: *Domain, token: *const Locked, stream: u32) Error!void {
        _ = try self.requireScope(token);
        if (backing(self).webrtc_binding) |binding| {
            const actual: *WebrtcBindingBacking = @ptrCast(@alignCast(binding));
            try actual.owner.requireUnclaimedRoutingSsrcLocked(self, token, stream);
        }
    }

    pub fn publishWebrtcMedia(self: *Domain, owner: *webrtc_owner.MediaPlane, ordinal: u64) !FanoutResult {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        const pin = source.active_inbound orelse return error.InvalidIdentity;
        if (pin.ordinal != ordinal or pin.issued_scope == 0 or pin.issued_scope == std.math.maxInt(u64) or source.closing) return error.InvalidIdentity;
        var reserved = Scope{ .source = source, .serial = pin.issued_scope };
        const scope: *Locked = @ptrCast(&reserved);
        std.debug.assert(source.active_scope == null);
        source.active_scope = scope;
        defer source.active_scope = null;
        const frame = try self.resolveWebrtcCanonicalLocked(scope, owner, ordinal);
        if (frame.kind == .rtcp) {
            var seqs: [64]u16 = undefined;
            const feedback = try webrtc_owner.MediaPlane.parseRoutingFeedback(frame.bytes, &seqs);
            const selected: ?u32 = switch (feedback) {
                .nack => |value| value.media_ssrc,
                .keyframe_request => |value| value.media_ssrc,
                .other => null,
            };
            if (selected) |ssrc| {
                // Native RTP bridge SSRC is the actual issued publisher stream.
                // Resolve only a real current native row, never a missing-map
                // all-target fallback or recipient-derived publisher identity.
                var publishers = source.endpoints.valueIterator();
                while (publishers.next()) |entry| {
                    const target = entry.observation;
                    if (target.stamp.endpoint.leg != .native or target.stream_id != ssrc or entry.retiring) continue;
                    if (!std.meta.eql(target.stamp.endpoint.call, frame.source.endpoint.call) or target.stamp.offering_client.eql(frame.source.offering_client)) return error.RouteDenied;
                    _ = owner.enqueueWebrtcFeedbackLocked(self, scope, ordinal, target.stamp) catch |err| return .{ .recognized = true, .refused = 1, .last_refusal = err };
                    return .{ .recognized = true, .accepted = 1 };
                }
                const publisher = try owner.routingPublisherForFeedbackLocked(self, scope, ordinal, ssrc);
                switch (feedback) {
                    .nack => return owner.enqueueRoutingNackLocked(self, scope, ordinal),
                    .keyframe_request => {
                        _ = owner.enqueueWebrtcFeedbackLocked(self, scope, ordinal, publisher) catch |err| return .{ .recognized = true, .refused = 1, .last_refusal = err };
                        return .{ .recognized = true, .accepted = 1 };
                    },
                    .other => unreachable,
                }
            }
        }
        var result = FanoutResult{ .recognized = true };
        var targets = source.endpoints.valueIterator();
        while (targets.next()) |entry| {
            const target = entry.observation;
            if (entry.retiring or !std.meta.eql(target.stamp.endpoint.call, frame.source.endpoint.call) or target.stamp.offering_client.eql(frame.source.offering_client)) continue;
            _ = owner.enqueueWebrtcCanonicalLocked(self, scope, ordinal, target.stamp) catch |err| {
                result.refused += 1;
                result.last_refusal = err;
                continue;
            };
            result.accepted += 1;
        }
        return result;
    }

    /// Cross-file ABI resolves the actual current pump's privately selected
    /// owned queue row. Scalars alone cannot manufacture this retained pin.
    pub fn holdWebrtcEgressLocked(self: *Domain, token: *const Locked, owner: *webrtc_owner.MediaPlane, ordinal: u64) !void {
        _ = try self.requireScope(token);
        const source = backing(self);
        const binding = source.webrtc_binding orelse return error.InvalidIdentity;
        try self.requireWebrtcBindingLocked(token, binding, owner);
        if (source.closing or source.active_egress != null or source.active_inbound != null) return error.Busy;
        const row = try owner.inspectRoutingEgressAttemptLocked(self, token, ordinal);
        _ = try self.requireCurrentLocked(token, row.source);
        _ = try self.requireCurrentLocked(token, row.target);
        if (!std.meta.eql(row.source.endpoint.call, row.target.endpoint.call)) return error.InvalidIdentity;
        source.active_egress = .{ .binding = binding, .ordinal = ordinal, .source = row.source, .target = row.target, .issued_scope = try self.scopeSerial(token) };
    }
    /// Completion spends no new admission serial. Only the actual private
    /// canonical pin plus current source pump/head/ordinal/bytes can resolve
    /// this reserved lexical finish authority; there is no caller callback.
    pub fn completeWebrtcEgress(self: *Domain, owner: *webrtc_owner.MediaPlane, ordinal: u64) !void {
        const source = backing(self);
        lock(&source.mutex);
        defer source.mutex.unlock();
        const pin = source.active_egress orelse return error.InvalidIdentity;
        if (source.closing or pin.ordinal != ordinal or pin.issued_scope == 0 or pin.issued_scope == std.math.maxInt(u64)) return error.InvalidIdentity;
        std.debug.assert(source.active_scope == null);
        var finish = Scope{ .source = source, .serial = pin.issued_scope };
        const scope: *Locked = @ptrCast(&finish);
        source.active_scope = scope;
        defer source.active_scope = null;
        try self.finishWebrtcEgressLocked(scope, owner, ordinal);
    }

    pub fn finishWebrtcEgressLocked(self: *Domain, token: *const Locked, owner: *webrtc_owner.MediaPlane, ordinal: u64) !void {
        _ = try self.requireScope(token);
        const source = backing(self);
        const pin = source.active_egress orelse return error.InvalidIdentity;
        try self.requireWebrtcBindingLocked(token, pin.binding, owner);
        if (pin.ordinal != ordinal) return error.InvalidIdentity;
        const row = try owner.inspectRoutingEgressAttemptLocked(self, token, ordinal);
        if (!std.meta.eql(row.source, pin.source) or !std.meta.eql(row.target, pin.target)) return error.InvalidIdentity;
        source.active_egress = null;
    }

    pub fn requireNoActiveIngressLocked(self: *Domain, token: *const Locked) Error!void {
        _ = try self.requireScope(token);
        if (backing(self).active_egress != null or backing(self).active_inbound != null) return error.Busy;
        if (backing(self).native_binding) |binding| {
            const record: *NativeBindingBacking = @ptrCast(@alignCast(binding));
            try record.owner.requireNoActiveIngressLocked(self, token);
        }
    }

    /// The only first-address publication path in this bounded native FRAME
    /// slice. Its input resolves to an actually MAC-verified source operation.
    /// All admissions precede the two no-fail, allocation-free row updates.
    pub fn bindNativeIngressLocked(self: *Domain, token: *const Locked, handle: IngressHandle) native_owner.IngressError!void {
        const frame = try self.resolveNativeIngressLocked(token, handle);
        if (!frame.first_bind) return;
        const source = backing(self);
        var observation = try self.requireCurrentLocked(token, frame.source);
        const next_revision = try checkedNext(u64, source.revision, 1);
        observation.stamp.binding_revision = try checkedNext(u64, observation.stamp.binding_revision, 1);
        const record: *NativeBindingBacking = @ptrCast(@alignCast(source.native_binding.?));
        try record.owner.validateIngressBindingLocked(self, token, handle);
        const key: EndpointKey = .{ .call = frame.source.endpoint.call, .client = frame.source.offering_client, .leg = .native };
        source.endpoints.getPtr(key).?.observation = observation;
        source.revision = next_revision;
        record.owner.commitIngressBindingLocked(self, token, handle, observation);
    }

    /// Prepare physical bridge policy from genuine source candidates, not an
    /// independently supplied nickname/profile/ready verdict. Its original
    /// allocator owns both detached and retired map storage through cleanup.
    pub fn preparePhysicalBridge(self: *Domain, offers: *PreparedOffers, channel: []const u8, native: ?*native_owner.PreparedNativeOffer, webrtc: ?*webrtc_owner.PreparedWebrtcOffer) !*PreparedPhysicalBridge {
        const source = backing(self);
        const preview = offers.preview();
        var rows: [2]BridgePolicyRow = undefined;
        var count: usize = 0;
        if (native) |candidate| {
            const negotiation = candidate.negotiation();
            rows[count] = .{ .reference = candidate.preview().identity.reference, .profile = negotiation.profile, .kind_bits = negotiation.kind_bits };
            count += 1;
        }
        if (webrtc) |candidate| {
            const negotiation = candidate.negotiation();
            rows[count] = .{ .reference = candidate.preview().identity.reference, .profile = negotiation.profile, .kind_bits = negotiation.kind_bits };
            count += 1;
        }
        if (count != preview.count) return error.InvalidRequest;
        const CaptureBridge = struct {
            domain: *Domain,
            offers: *PreparedOffers,
            channel: []const u8,
            rows: []const BridgePolicyRow,
            fn run(scope: *Locked, ctx: @This()) !BridgeCapture {
                try ctx.offers.validateLocked(ctx.domain, scope);
                const b = backing(ctx.domain);
                var required = b.bridge_policy.count();
                for (ctx.rows) |row| {
                    const observation = try ctx.offers.observationLocked(ctx.domain, scope, ctx.channel, row.reference.endpoint.leg);
                    if (!std.meta.eql(observation.reference, row.reference)) return error.InvalidIdentity;
                    const key: EndpointKey = .{ .call = row.reference.endpoint.call, .client = row.reference.offering_client, .leg = row.reference.endpoint.leg };
                    if (!b.bridge_policy.contains(key)) required = std.math.add(u32, required, 1) catch return error.SequenceExhausted;
                }
                b.pending_candidates = std.math.add(usize, b.pending_candidates, 1) catch return error.SequenceExhausted;
                return .{ .revision = b.revision, .count = b.bridge_policy.count(), .capacity = b.bridge_policy.capacity(), .metadata = if (b.bridge_policy.unmanaged.metadata) |p| @intFromPtr(p) else 0, .required = required, .grow = required - b.bridge_policy.count() > b.bridge_policy.unmanaged.available };
            }
        };
        const facts = try self.withLocked(CaptureBridge{ .domain = self, .offers = offers, .channel = channel, .rows = rows[0..count] }, CaptureBridge.run);
        errdefer unpinCandidate(source);
        const plan = try source.allocator.create(BridgePlan);
        errdefer source.allocator.destroy(plan);
        var growth: ?BridgeMap = null;
        errdefer if (growth) |*map| map.deinit();
        if (facts.grow) {
            growth = BridgeMap.init(source.allocator);
            try growth.?.ensureTotalCapacity(facts.required);
        }
        plan.* = .{ .source = source, .offers = offers, .native = native, .webrtc = webrtc, .channel = try ChannelKey.init(channel), .facts = facts, .rows = rows, .count = @intCast(count), .growth = growth };
        return @ptrCast(plan);
    }

    /// Prepare one physical client's actual advertised legs together. No serial
    /// or live map capacity is consumed by failure. Replies use preview first.
    pub fn prepareOffers(self: *Domain, channel: []const u8, owner: ClientId, legs: []const OfferLeg) Error!*PreparedOffers {
        if (owner.isNone() or legs.len == 0 or legs.len > 2) return error.InvalidRequest;
        if (legs.len == 2 and legs[0].leg == legs[1].leg) return error.InvalidRequest;
        const key = try ChannelKey.init(channel);
        const source = backing(self);
        var facts: Capture = undefined;
        lock(&source.mutex);
        if (source.closing) {
            source.mutex.unlock();
            return error.Closing;
        }
        facts = capture(source, key, owner, legs) catch |err| {
            source.mutex.unlock();
            return err;
        };
        source.pending_candidates = std.math.add(usize, source.pending_candidates, 1) catch {
            source.mutex.unlock();
            return error.SequenceExhausted;
        };
        source.mutex.unlock();
        errdefer unpinCandidate(source);
        const plan = try source.allocator.create(OfferBacking);
        plan.* = .{ .source = source, .facts = facts };
        errdefer source.allocator.destroy(plan);
        errdefer {
            if (plan.calls) |*map| map.deinit();
            if (plan.endpoints) |*map| map.deinit();
        }
        // Storage only; copying/reindexing OLD happens in final cut after its
        // revision is validated. No borrowed OLD map payload is owned by plan.
        if (facts.grow_calls) {
            plan.calls = CallMap.init(source.allocator);
            try plan.calls.?.ensureTotalCapacity(facts.calls_required);
        }
        if (facts.grow_endpoints) {
            plan.endpoints = EndpointMap.init(source.allocator);
            try plan.endpoints.?.ensureTotalCapacity(facts.endpoints_required);
        }
        return @ptrCast(plan);
    }

    /// Actual logical physical membership is independent of transport offers.
    /// This preserves OFFER without JOIN and sibling JOIN ownership separately.
    pub fn prepareMembership(self: *Domain, channel: []const u8, owner: ClientId, kind_bits: u8) Error!*PreparedMembership {
        if (owner.isNone() or kind_bits == 0 or kind_bits & ~@as(u8, 7) != 0) return error.InvalidRequest;
        const key = try ChannelKey.init(channel);
        const source = backing(self);
        lock(&source.mutex);
        if (source.closing) {
            source.mutex.unlock();
            return error.Closing;
        }
        const facts = captureMembership(source, key, owner, kind_bits) catch |err| {
            source.mutex.unlock();
            return err;
        };
        source.pending_candidates = std.math.add(usize, source.pending_candidates, 1) catch {
            source.mutex.unlock();
            return error.SequenceExhausted;
        };
        source.mutex.unlock();
        errdefer unpinCandidate(source);
        const plan = try source.allocator.create(MembershipBacking);
        plan.* = .{ .source = source, .facts = facts };
        errdefer source.allocator.destroy(plan);
        errdefer {
            if (plan.calls) |*map| map.deinit();
            if (plan.memberships) |*map| map.deinit();
        }
        if (facts.grow_calls) {
            plan.calls = CallMap.init(source.allocator);
            try plan.calls.?.ensureTotalCapacity(facts.calls_required);
        }
        if (facts.grow_memberships) {
            plan.memberships = MembershipMap.init(source.allocator);
            try plan.memberships.?.ensureTotalCapacity(facts.memberships_required);
        }
        return @ptrCast(plan);
    }

    pub fn revokeMembershipLocked(self: *Domain, token: *const Locked, call: CallId, owner: ClientId) Error!void {
        _ = try self.requireScope(token);
        try self.requireNoActiveIngressLocked(token);
        const source = backing(self);
        if (call.domain.serial != source.id.serial or owner.isNone()) return error.InvalidIdentity;
        const key = MembershipKey{ .call = call, .client = owner };
        if (!source.memberships.contains(key)) return;
        const next_revision = try checkedNext(u64, source.revision, 1);
        var actual_key: ?ChannelKey = null;
        var it = source.calls.iterator();
        while (it.next()) |entry| if (std.meta.eql(entry.value_ptr.id, call)) {
            actual_key = entry.key_ptr.*;
            break;
        };
        const channel = actual_key orelse return error.InvalidIdentity;
        const row = source.calls.getPtr(channel).?;
        if (row.memberships == 0) return error.InvalidIdentity;
        _ = source.memberships.remove(key);
        row.memberships -= 1;
        if (row.offers == 0 and row.memberships == 0) _ = source.calls.remove(channel);
        source.revision = next_revision;
    }

    /// Allocate the exact physical departure before the final routing cut.
    /// Every joined leaf/Room/output validates before its first void commit.
    pub fn prepareDeparture(self: *Domain, call: CallId, owner: ClientId) Error!*PreparedDeparture {
        const source = backing(self);
        if (owner.isNone() or call.domain.serial != source.id.serial or call.serial == 0) return error.InvalidIdentity;
        lock(&source.mutex);
        var found: ?struct { channel: ChannelKey, row: CallRow } = null;
        var it = source.calls.iterator();
        while (it.next()) |entry| if (std.meta.eql(entry.value_ptr.id, call)) {
            found = .{ .channel = entry.key_ptr.*, .row = entry.value_ptr.* };
            break;
        };
        const actual = found orelse {
            source.mutex.unlock();
            return error.EndpointUnavailable;
        };
        var facts = DepartureCapture{ .channel = actual.channel, .call = actual.row, .owner = owner, .revision = source.revision, .membership = membershipBits(source, .{ .call = call, .client = owner }) };
        for ([_]Leg{ .native, .webrtc }, 0..) |leg, n| {
            facts.offers[n] = endpointObservation(source, .{ .call = call, .client = owner, .leg = leg });
            if (facts.offers[n] != null) facts.removed_offers += 1;
        }
        if (actual.row.offers < facts.removed_offers or actual.row.memberships < @as(u32, if (facts.membership != null) 1 else 0)) {
            source.mutex.unlock();
            return error.InvalidIdentity;
        }
        if (!source.closing and (facts.removed_offers != 0 or facts.membership != null)) _ = checkedNext(u64, source.revision, 1) catch |err| {
            source.mutex.unlock();
            return err;
        };
        source.pending_candidates = std.math.add(usize, source.pending_candidates, 1) catch {
            source.mutex.unlock();
            return error.SequenceExhausted;
        };
        const terminal = source.closing;
        source.mutex.unlock();
        errdefer unpinCandidate(source);
        const plan = try source.allocator.create(DepartureBacking);
        plan.* = .{ .source = source, .facts = facts, .terminal = terminal };
        return @ptrCast(plan);
    }
    /// One complete physical-client departure: discover every actual call,
    /// prepare all copied OLD facts, validate once, then publish one revision.
    /// No per-call singleton commits or backend calls occur in the final cut.
    /// Resolve one actual owned call under the source gate. The returned
    /// candidate captures retained OLD rows, including denied cleanup custody;
    /// no map getter, nickname lookup or all-call retirement is exposed.
    pub fn prepareChannelDeparture(self: *Domain, channel_name: []const u8, owner: ClientId) Error!?*PreparedDeparture {
        const key = try ChannelKey.init(channel_name);
        if (owner.isNone()) return error.InvalidIdentity;
        const source = backing(self);
        lock(&source.mutex);
        if (source.closing) {
            source.mutex.unlock();
            return error.Closing;
        }
        const call = source.calls.get(key) orelse {
            source.mutex.unlock();
            return null;
        };
        const owned = source.memberships.contains(.{ .call = call.id, .client = owner }) or
            source.endpoints.contains(.{ .call = call.id, .client = owner, .leg = .native }) or
            source.endpoints.contains(.{ .call = call.id, .client = owner, .leg = .webrtc });
        source.mutex.unlock();
        if (!owned) return null;
        // Actual preparation recaptures the source after allocation-free
        // lookup. Changed/departed state is validated again by the candidate.
        return try self.prepareDeparture(call.id, owner);
    }

    pub fn prepareClientDeparture(self: *Domain, owner: ClientId) Error!*PreparedClientDeparture {
        if (owner.isNone()) return error.InvalidIdentity;
        const source = backing(self);
        lock(&source.mutex);
        var count: usize = 0;
        var calls = source.calls.valueIterator();
        while (calls.next()) |row| if (clientOwnsCall(source, row.id, owner)) {
            count = std.math.add(usize, count, 1) catch {
                source.mutex.unlock();
                return error.SequenceExhausted;
            };
        };
        if (!source.closing and count != 0) _ = checkedNext(u64, source.revision, 1) catch |err| {
            source.mutex.unlock();
            return err;
        };
        const revision = source.revision;
        const terminal = source.closing;
        source.pending_candidates = std.math.add(usize, source.pending_candidates, 1) catch {
            source.mutex.unlock();
            return error.SequenceExhausted;
        };
        source.mutex.unlock();
        errdefer unpinCandidate(source);
        const batch = try source.allocator.create(ClientDepartureBacking);
        errdefer source.allocator.destroy(batch);
        const parts = try source.allocator.alloc(DepartureBacking, count);
        errdefer source.allocator.free(parts);
        batch.* = .{ .source = source, .owner = owner, .revision = revision, .terminal = terminal, .parts = parts };
        lock(&source.mutex);
        defer source.mutex.unlock();
        if (source.revision != revision or source.closing != terminal) return error.StaleCandidate;
        var n: usize = 0;
        var it = source.calls.iterator();
        while (it.next()) |entry| if (clientOwnsCall(source, entry.value_ptr.id, owner)) {
            if (n == count) return error.StaleCandidate;
            const row = entry.value_ptr.*;
            var facts = DepartureCapture{ .channel = entry.key_ptr.*, .call = row, .owner = owner, .revision = revision, .membership = membershipBits(source, .{ .call = row.id, .client = owner }) };
            for ([_]Leg{ .native, .webrtc }, 0..) |leg, k| {
                facts.offers[k] = endpointObservation(source, .{ .call = row.id, .client = owner, .leg = leg });
                if (facts.offers[k] != null) facts.removed_offers += 1;
            }
            if (row.offers < facts.removed_offers or row.memberships < @as(u32, if (facts.membership != null) 1 else 0)) return error.InvalidIdentity;
            parts[n] = .{ .source = source, .facts = facts, .terminal = terminal, .batch_parent = batch };
            n += 1;
        };
        if (n != count) return error.StaleCandidate;
        // Canonical order is independent of table geometry and probe order.
        std.mem.sort(DepartureBacking, parts, {}, struct {
            fn less(_: void, lhs: DepartureBacking, rhs: DepartureBacking) bool {
                return lhs.facts.call.id.serial < rhs.facts.call.id.serial;
            }
        }.less);
        return @ptrCast(batch);
    }

    pub fn callForChannelLocked(self: *Domain, token: *const Locked, channel: []const u8) Error!?CallId {
        _ = try self.requireScope(token);
        const key = try ChannelKey.init(channel);
        const row = backing(self).calls.get(key) orelse return null;
        return row.id;
    }

    /// Revokes ONLY one exact physical owner's offers. All allocations/crypto
    /// cleanup are retained by the leaf owner for disposal outside this cut.
    pub fn revokeOffersLocked(self: *Domain, token: *const Locked, call: CallId, owner: ClientId) Error!void {
        _ = try self.requireScope(token);
        try self.requireNoActiveIngressLocked(token);
        const source = backing(self);
        if (call.domain.serial != source.id.serial or owner.isNone()) return error.InvalidIdentity;
        var removed: u32 = 0;
        for ([_]Leg{ .native, .webrtc }) |leg| {
            if (source.endpoints.contains(.{ .call = call, .client = owner, .leg = leg })) removed += 1;
        }
        if (removed == 0) return;
        const next_revision = try checkedNext(u64, source.revision, 1);
        var call_key: ?ChannelKey = null;
        var it = source.calls.iterator();
        while (it.next()) |entry| {
            if (std.meta.eql(entry.value_ptr.id, call)) {
                call_key = entry.key_ptr.*;
                break;
            }
        }
        const actual_key = call_key orelse return error.InvalidIdentity;
        const row = source.calls.getPtr(actual_key).?;
        if (row.offers < removed) return error.InvalidIdentity;
        for ([_]Leg{ .native, .webrtc }) |leg| {
            const key: EndpointKey = .{ .call = call, .client = owner, .leg = leg };
            removeBridgePolicy(source, key, endpointObservation(source, key));
            _ = source.endpoints.remove(key);
        }
        row.offers -= removed;
        if (row.offers == 0 and row.memberships == 0) _ = source.calls.remove(actual_key);
        source.revision = next_revision;
    }
};

pub const ClientRetirementObservation = struct { offers: u32 = 0, memberships: u32 = 0 };
fn endpointObservation(source: *Backing, key: EndpointKey) ?EndpointObservation {
    const row = source.endpoints.get(key) orelse return null;
    return row.observation;
}
fn membershipBits(source: *Backing, key: MembershipKey) ?u8 {
    const row = source.memberships.get(key) orelse return null;
    return row.bits;
}
fn clientRetiring(source: *Backing, client_id: ClientId) bool {
    var endpoints = source.endpoints.iterator();
    while (endpoints.next()) |entry| if (entry.key_ptr.client.eql(client_id) and entry.value_ptr.retiring) return true;
    var memberships = source.memberships.iterator();
    while (memberships.next()) |entry| if (entry.key_ptr.client.eql(client_id) and entry.value_ptr.retiring) return true;
    return false;
}

pub const OfferLeg = struct { leg: Leg, mode: SecurityMode };
pub const OfferPreview = struct {
    call: CallId,
    endpoints: [2]EndpointObservation,
    count: u8,
};
const Capture = struct {
    channel: ChannelKey,
    owner: ClientId,
    revision: u64,
    next_call: u64,
    next_endpoint: u64,
    next_stream: u32,
    new_call: bool,
    old: [2]?EndpointObservation = .{ null, null },
    preview: OfferPreview,
    calls_required: u32,
    endpoints_required: u32,
    grow_calls: bool,
    grow_endpoints: bool,
};
fn capture(source: *Backing, key: ChannelKey, owner: ClientId, legs: []const OfferLeg) Error!Capture {
    if (clientRetiring(source, owner)) return error.Closing;
    _ = try checkedNext(u64, source.revision, 1);
    const call_row = source.calls.get(key);
    const call = if (call_row) |row| row.id else CallId{ .domain = source.id, .serial = source.next_call };
    _ = try checkedNext(u64, source.next_call, if (call_row == null) 1 else 0);
    _ = try checkedNext(u64, source.next_endpoint, @intCast(legs.len));
    _ = try checkedNext(u32, source.next_stream, @intCast(legs.len));
    var facts = Capture{ .channel = key, .owner = owner, .revision = source.revision, .next_call = source.next_call, .next_endpoint = source.next_endpoint, .next_stream = source.next_stream, .new_call = call_row == null, .preview = .{ .call = call, .endpoints = @splat(std.mem.zeroes(EndpointObservation)), .count = @intCast(legs.len) }, .calls_required = source.calls.count(), .endpoints_required = source.endpoints.count(), .grow_calls = false, .grow_endpoints = false };
    if (call_row == null) facts.calls_required = std.math.add(u32, facts.calls_required, 1) catch return error.SequenceExhausted;
    for (legs, 0..) |leg, i| {
        const endpoint = EndpointId{ .call = call, .serial = source.next_endpoint + i, .leg = leg.leg };
        facts.old[i] = endpointObservation(source, .{ .call = call, .client = owner, .leg = leg.leg });
        if (facts.old[i] == null) facts.endpoints_required = std.math.add(u32, facts.endpoints_required, 1) catch return error.SequenceExhausted;
        facts.preview.endpoints[i] = .{ .reference = .{ .endpoint = endpoint, .offering_client = owner, .bridge_policy_revision = 1 }, .stamp = .{ .endpoint = endpoint, .binding_revision = 1, .security_revision = 1, .offering_client = owner }, .stream_id = source.next_stream + @as(u32, @intCast(i)), .mode = leg.mode };
    }
    // Counts may legitimately be zero after JOIN or the last offer retirement.
    // Identity/revision/stream issuers retain checkedNext's nonzero rule.
    if (call_row) |row| _ = std.math.add(u32, row.offers, facts.endpoints_required - source.endpoints.count()) catch return error.SequenceExhausted;
    facts.grow_calls = facts.calls_required - source.calls.count() > source.calls.unmanaged.available;
    facts.grow_endpoints = facts.endpoints_required - source.endpoints.count() > source.endpoints.unmanaged.available;
    return facts;
}
fn unpinCandidate(source: *Backing) void {
    lock(&source.mutex);
    std.debug.assert(source.pending_candidates != 0);
    source.pending_candidates -= 1;
    source.mutex.unlock();
}
const OfferBacking = struct {
    source: *Backing,
    facts: Capture,
    calls: ?CallMap = null,
    endpoints: ?EndpointMap = null,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn offerBacking(plan: *PreparedOffers) *OfferBacking {
    return @ptrCast(@alignCast(plan));
}

pub const PreparedOffers = opaque {
    /// Copy-only preview. No mutable candidate or live registry borrow escapes.
    pub fn preview(self: *PreparedOffers) OfferPreview {
        return offerBacking(self).facts.preview;
    }

    pub fn validateLocked(self: *PreparedOffers, domain: *Domain, token: *const Locked) Error!void {
        try domain.requireNoActiveIngressLocked(token);
        const source = backing(domain);
        const scope = try domain.requireScope(token);
        const plan = offerBacking(self);
        if (clientRetiring(source, plan.facts.owner)) return error.Closing;
        if (plan.source != source or plan.committed or source.revision != plan.facts.revision or source.next_call != plan.facts.next_call or source.next_endpoint != plan.facts.next_endpoint or source.next_stream != plan.facts.next_stream) return error.StaleCandidate;
        for (plan.facts.preview.endpoints[0..plan.facts.preview.count], 0..) |row, i| {
            const current = endpointObservation(source, .{ .call = row.reference.endpoint.call, .client = row.reference.offering_client, .leg = row.reference.endpoint.leg });
            if (!std.meta.eql(current, plan.facts.old[i])) return error.StaleCandidate;
        }
        plan.validated_scope = scope.serial;
    }

    /// Source proof for joined leaf plans. Selectors alone do not authorize a
    /// future CallId: require this actual owned candidate and its exact preview.
    pub fn requireKeysLocked(self: *PreparedOffers, domain: *Domain, token: *const Locked, channel: []const u8, keys: []const EndpointKey) Error!void {
        try self.validateLocked(domain, token);
        const plan = offerBacking(self);
        if (!std.meta.eql(try ChannelKey.init(channel), plan.facts.channel) or keys.len != plan.facts.preview.count) return error.InvalidIdentity;
        for (keys, plan.facts.preview.endpoints[0..keys.len]) |key, row| {
            if (!std.meta.eql(key, EndpointKey{ .call = row.reference.endpoint.call, .client = row.reference.offering_client, .leg = row.reference.endpoint.leg })) return error.InvalidIdentity;
        }
    }

    pub fn observationLocked(self: *PreparedOffers, domain: *Domain, token: *const Locked, channel_name: []const u8, leg: Leg) Error!EndpointObservation {
        try self.validateLocked(domain, token);
        const plan = offerBacking(self);
        if (!std.meta.eql(try ChannelKey.init(channel_name), plan.facts.channel)) return error.InvalidIdentity;
        for (plan.facts.preview.endpoints[0..plan.facts.preview.count]) |row| if (row.reference.endpoint.leg == leg) return row;
        return error.EndpointUnavailable;
    }

    pub fn requireEndpointLocked(self: *PreparedOffers, domain: *Domain, token: *const Locked, channel: []const u8, expected: EndpointObservation) Error!void {
        try self.validateLocked(domain, token);
        const plan = offerBacking(self);
        if (!std.meta.eql(try ChannelKey.init(channel), plan.facts.channel)) return error.InvalidIdentity;
        for (plan.facts.preview.endpoints[0..plan.facts.preview.count]) |row| if (std.meta.eql(row, expected)) return;
        return error.InvalidIdentity;
    }

    /// Trusted source publication after EVERY joined candidate/output validates.
    /// No allocator call/free occurs here. Superseded backing remains in plan.
    pub fn commitLocked(self: *PreparedOffers, domain: *Domain, token: *const Locked) void {
        const plan = offerBacking(self);
        const source = backing(domain);
        const scope = domain.requireScope(token) catch @panic("invalid media publication scope");
        std.debug.assert(plan.source == source and !plan.committed and plan.validated_scope == scope.serial and source.revision == plan.facts.revision);
        if (plan.calls) |*replacement| {
            var it = source.calls.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(CallMap, &source.calls, replacement);
        }
        if (plan.endpoints) |*replacement| {
            var it = source.endpoints.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(EndpointMap, &source.endpoints, replacement);
        }
        if (plan.facts.new_call) source.calls.putAssumeCapacity(plan.facts.channel, .{ .id = plan.facts.preview.call });
        const call = source.calls.getPtr(plan.facts.channel).?;
        for (plan.facts.preview.endpoints[0..plan.facts.preview.count], 0..) |row, i| {
            source.endpoints.putAssumeCapacity(.{ .call = row.reference.endpoint.call, .client = row.reference.offering_client, .leg = row.reference.endpoint.leg }, .{ .observation = row });
            if (plan.facts.old[i] == null) call.offers += 1;
        }
        source.next_call += if (plan.facts.new_call) @as(u64, 1) else 0;
        source.next_endpoint += plan.facts.preview.count;
        source.next_stream += plan.facts.preview.count;
        source.revision += 1;
        plan.committed = true;
    }

    /// Abort or finish AFTER Domain.withLocked has returned. Frees only owned
    /// detached/retired backing, never live rows or source authority.
    pub fn deinit(self: *PreparedOffers) void {
        const plan = offerBacking(self);
        const source = plan.source;
        if (plan.calls) |*map| map.deinit();
        if (plan.endpoints) |*map| map.deinit();
        source.allocator.destroy(plan);
        unpinCandidate(source);
    }
};

const PublishContext = struct { domain: *Domain, plan: *PreparedOffers };
fn publishForTest(scope: *Locked, ctx: PublishContext) Error!void {
    try ctx.plan.validateLocked(ctx.domain, scope);
    ctx.plan.commitLocked(ctx.domain, scope);
}
const RevokeContext = struct { domain: *Domain, call: CallId, owner: ClientId };
fn revokeForTest(scope: *Locked, ctx: RevokeContext) Error!void {
    try ctx.domain.revokeOffersLocked(scope, ctx.call, ctx.owner);
}

// These helpers are private; tests call the actual source publication path.
test "media routing physical sibling offers preserve independent identities" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("test source custody not closed");
    const alice = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const bob = ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    const a = try domain.prepareOffers("#Call", alice, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .dtls_required } });
    const original = a.preview();
    try domain.withLocked(PublishContext{ .domain = domain, .plan = a }, publishForTest);
    a.deinit();
    const b = try domain.prepareOffers("#call", bob, &.{.{ .leg = .native, .mode = .legacy_group }});
    const sibling = b.preview();
    try std.testing.expect(std.meta.eql(original.call, sibling.call));
    try std.testing.expect(original.endpoints[0].stream_id != sibling.endpoints[0].stream_id);
    try domain.withLocked(PublishContext{ .domain = domain, .plan = b }, publishForTest);
    b.deinit();
    const replacement = try domain.prepareOffers("#CALL", alice, &.{.{ .leg = .native, .mode = .legacy_group }});
    const fresh = replacement.preview();
    try std.testing.expect(fresh.endpoints[0].reference.endpoint.serial != original.endpoints[0].reference.endpoint.serial);
    try domain.withLocked(PublishContext{ .domain = domain, .plan = replacement }, publishForTest);
    replacement.deinit();
    const Checks = struct {
        domain: *Domain,
        sibling: EndpointStamp,
        retired: EndpointStamp,
        untouched: EndpointStamp,
        fn run(scope: *Locked, ctx: @This()) anyerror!void {
            _ = try ctx.domain.requireCurrentLocked(scope, ctx.sibling);
            _ = try ctx.domain.requireCurrentLocked(scope, ctx.untouched);
            try std.testing.expectError(error.EndpointUnavailable, ctx.domain.requireCurrentLocked(scope, ctx.retired));
        }
    };
    try domain.withLocked(Checks{ .domain = domain, .sibling = sibling.endpoints[0].stamp, .retired = original.endpoints[0].stamp, .untouched = original.endpoints[1].stamp }, Checks.run);
    try domain.withLocked(RevokeContext{ .domain = domain, .call = original.call, .owner = alice }, revokeForTest);
    try domain.withLocked(RevokeContext{ .domain = domain, .call = original.call, .owner = bob }, revokeForTest);
}

test "media routing stale preprepared preview cannot rebind after sibling commit" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("test source custody not closed");
    const a = ClientId{ .shard = 1, .slot = 2, .gen = 3 };
    const b = ClientId{ .shard = 1, .slot = 3, .gen = 3 };
    const first = try domain.prepareOffers("#c", a, &.{.{ .leg = .native, .mode = .legacy_group }});
    const second = try domain.prepareOffers("#c", b, &.{.{ .leg = .native, .mode = .legacy_group }});
    const before = second.preview();
    try domain.withLocked(PublishContext{ .domain = domain, .plan = first }, publishForTest);
    first.deinit();
    try std.testing.expectError(error.StaleCandidate, domain.withLocked(PublishContext{ .domain = domain, .plan = second }, publishForTest));
    try std.testing.expect(std.meta.eql(before.endpoints[0], second.preview().endpoints[0]));
    second.deinit();
    try domain.withLocked(RevokeContext{ .domain = domain, .call = before.call, .owner = a }, revokeForTest);
}

fn candidateAllocationFailureTest(allocator: std.mem.Allocator) !void {
    const domain = try Domain.create(allocator);
    defer domain.destroyQuiesced() catch @panic("candidate lost constructor custody");
    const source = backing(domain);
    const initial_revision = source.revision;
    const initial_call = source.next_call;
    const initial_endpoint = source.next_endpoint;
    const initial_stream = source.next_stream;
    const plan = domain.prepareOffers("#allocation", .{ .shard = 2, .slot = 3, .gen = 4 }, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .dtls_required } }) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
        try std.testing.expectEqual(initial_revision, source.revision);
        try std.testing.expectEqual(initial_call, source.next_call);
        try std.testing.expectEqual(initial_endpoint, source.next_endpoint);
        try std.testing.expectEqual(initial_stream, source.next_stream);
        try std.testing.expectEqual(@as(u32, 0), source.calls.count());
        try std.testing.expectEqual(@as(u32, 0), source.endpoints.count());
        try std.testing.expectEqual(@as(u32, 0), source.calls.capacity());
        try std.testing.expectEqual(@as(u32, 0), source.endpoints.capacity());
        return err;
    };
    // Abort is the real candidate disposal path; no fixture counters are forged.
    plan.deinit();
    try std.testing.expectEqual(initial_revision, source.revision);
    try std.testing.expectEqual(initial_call, source.next_call);
    try std.testing.expectEqual(@as(u32, 0), source.calls.capacity());
    try std.testing.expectEqual(@as(u32, 0), source.endpoints.capacity());
}

test "media routing all detached candidate OOM boundaries preserve exact OLD" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, candidateAllocationFailureTest, .{});
}

test "media routing retained candidates block destruction and exhausted issuers refuse preparation" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("test source custody not closed");
    const plan = try domain.prepareOffers("#c", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }});
    try std.testing.expectError(error.Busy, domain.destroyQuiesced());
    plan.deinit();
    const source = backing(domain);
    source.next_stream = std.math.maxInt(u32);
    try std.testing.expectError(error.SequenceExhausted, domain.prepareOffers("#c", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }}));
    try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
    try std.testing.expectEqual(@as(u32, 0), source.calls.capacity());
    try std.testing.expectEqual(@as(u32, 0), source.endpoints.capacity());
}

pub const MembershipPreview = struct { call: CallId, client: ClientId, kind_bits: u8 };
const MembershipCapture = struct {
    channel: ChannelKey,
    revision: u64,
    next_call: u64,
    new_call: bool,
    old: ?u8,
    preview: MembershipPreview,
    calls_required: u32,
    memberships_required: u32,
    grow_calls: bool,
    grow_memberships: bool,
};
fn captureMembership(source: *Backing, channel: ChannelKey, owner: ClientId, bits: u8) Error!MembershipCapture {
    if (clientRetiring(source, owner)) return error.Closing;
    _ = try checkedNext(u64, source.revision, 1);
    const old_call = source.calls.get(channel);
    const call = if (old_call) |row| row.id else CallId{ .domain = source.id, .serial = source.next_call };
    _ = try checkedNext(u64, source.next_call, if (old_call == null) 1 else 0);
    const old = membershipBits(source, .{ .call = call, .client = owner });
    if (old == null and old_call != null and old_call.?.memberships == std.math.maxInt(u32)) return error.SequenceExhausted;
    const calls_required = std.math.add(u32, source.calls.count(), if (old_call == null) 1 else 0) catch return error.SequenceExhausted;
    const memberships_required = std.math.add(u32, source.memberships.count(), if (old == null) 1 else 0) catch return error.SequenceExhausted;
    return .{ .channel = channel, .revision = source.revision, .next_call = source.next_call, .new_call = old_call == null, .old = old, .preview = .{ .call = call, .client = owner, .kind_bits = (old orelse 0) | bits }, .calls_required = calls_required, .memberships_required = memberships_required, .grow_calls = calls_required - source.calls.count() > source.calls.unmanaged.available, .grow_memberships = memberships_required - source.memberships.count() > source.memberships.unmanaged.available };
}
const MembershipBacking = struct {
    source: *Backing,
    facts: MembershipCapture,
    calls: ?CallMap = null,
    memberships: ?MembershipMap = null,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn membershipBacking(plan: *PreparedMembership) *MembershipBacking {
    return @ptrCast(@alignCast(plan));
}
pub const PreparedMembership = opaque {
    pub fn preview(self: *PreparedMembership) MembershipPreview {
        return membershipBacking(self).facts.preview;
    }
    pub fn validateLocked(self: *PreparedMembership, domain: *Domain, token: *const Locked) Error!void {
        try domain.requireNoActiveIngressLocked(token);
        const scope = try domain.requireScope(token);
        const plan = membershipBacking(self);
        const source = backing(domain);
        if (clientRetiring(source, plan.facts.preview.client)) return error.Closing;
        if (plan.source != source or plan.committed or source.revision != plan.facts.revision or source.next_call != plan.facts.next_call) return error.StaleCandidate;
        if (!std.meta.eql(plan.facts.old, membershipBits(source, .{ .call = plan.facts.preview.call, .client = plan.facts.preview.client }))) return error.StaleCandidate;
        plan.validated_scope = scope.serial;
    }
    pub fn requireJoinLocked(self: *PreparedMembership, domain: *Domain, token: *const Locked, channel: []const u8, expected: MembershipPreview) Error!void {
        try self.validateLocked(domain, token);
        if (!std.meta.eql(try ChannelKey.init(channel), membershipBacking(self).facts.channel) or !std.meta.eql(expected, self.preview())) return error.InvalidIdentity;
    }
    pub fn commitLocked(self: *PreparedMembership, domain: *Domain, token: *const Locked) void {
        const plan = membershipBacking(self);
        const source = backing(domain);
        const scope = domain.requireScope(token) catch @panic("invalid membership publication scope");
        std.debug.assert(plan.source == source and !plan.committed and plan.validated_scope == scope.serial and source.revision == plan.facts.revision);
        if (plan.calls) |*replacement| {
            var it = source.calls.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(CallMap, &source.calls, replacement);
        }
        if (plan.memberships) |*replacement| {
            var it = source.memberships.iterator();
            while (it.next()) |entry| replacement.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(MembershipMap, &source.memberships, replacement);
        }
        if (plan.facts.new_call) source.calls.putAssumeCapacity(plan.facts.channel, .{ .id = plan.facts.preview.call });
        source.memberships.putAssumeCapacity(.{ .call = plan.facts.preview.call, .client = plan.facts.preview.client }, .{ .bits = plan.facts.preview.kind_bits });
        if (plan.facts.old == null) source.calls.getPtr(plan.facts.channel).?.memberships += 1;
        source.next_call += if (plan.facts.new_call) @as(u64, 1) else 0;
        source.revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedMembership) void {
        const plan = membershipBacking(self);
        const source = plan.source;
        if (plan.calls) |*map| map.deinit();
        if (plan.memberships) |*map| map.deinit();
        source.allocator.destroy(plan);
        unpinCandidate(source);
    }
};

const MembershipPublish = struct {
    domain: *Domain,
    plan: *PreparedMembership,
    fn run(scope: *Locked, ctx: @This()) Error!void {
        try ctx.plan.validateLocked(ctx.domain, scope);
        ctx.plan.commitLocked(ctx.domain, scope);
    }
};
const MembershipRevoke = struct {
    domain: *Domain,
    call: CallId,
    client: ClientId,
    fn run(scope: *Locked, ctx: @This()) Error!void {
        try ctx.domain.revokeMembershipLocked(scope, ctx.call, ctx.client);
    }
};
test "media routing JOIN membership preserves offer-only sibling authority" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("unclosed physical routing state");
    const a = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const b = ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    const offer = try domain.prepareOffers("#call", a, &.{.{ .leg = .webrtc, .mode = .dtls_required }});
    const original = offer.preview();
    try std.testing.expect(std.meta.eql(original.endpoints[1], std.mem.zeroes(EndpointObservation)));
    try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
    offer.deinit();
    const join = try domain.prepareMembership("#CALL", b, 1);
    const membership = join.preview();
    try std.testing.expect(std.meta.eql(membership.call, original.call));
    try domain.withLocked(MembershipPublish{ .domain = domain, .plan = join }, MembershipPublish.run);
    join.deinit();
    try domain.withLocked(MembershipRevoke{ .domain = domain, .call = membership.call, .client = b }, MembershipRevoke.run);
    const Check = struct {
        domain: *Domain,
        expected: EndpointStamp,
        fn run(scope: *Locked, ctx: @This()) Error!void {
            _ = try ctx.domain.requireCurrentLocked(scope, ctx.expected);
        }
    };
    try domain.withLocked(Check{ .domain = domain, .expected = original.endpoints[0].stamp }, Check.run);
    try domain.withLocked(RevokeContext{ .domain = domain, .call = original.call, .owner = a }, revokeForTest);
}
fn membershipOom(allocator: std.mem.Allocator) !void {
    const domain = try Domain.create(allocator);
    defer domain.destroyQuiesced() catch @panic("candidate allocation leaked source custody");
    const source = backing(domain);
    const plan = domain.prepareMembership("#join", .{ .shard = 0, .slot = 0, .gen = 0 }, 1) catch |err| {
        try std.testing.expectEqual(@as(u64, 1), source.revision);
        try std.testing.expectEqual(@as(u64, 1), source.next_call);
        try std.testing.expectEqual(@as(u32, 0), source.calls.capacity());
        try std.testing.expectEqual(@as(u32, 0), source.memberships.capacity());
        try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
        return err;
    };
    plan.deinit();
}
test "media routing JOIN preparation OOM preserves exact source capacity and issuers" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, membershipOom, .{});
}

pub const NativeBinding = opaque {};
pub const WebrtcBinding = opaque {};
const NativeBindingBacking = struct { source: *Backing, owner: *native_owner.NativeMediaTransport, serial: u64 };
const WebrtcBindingBacking = struct { source: *Backing, owner: *webrtc_owner.MediaPlane, serial: u64 };

const DepartureCapture = struct {
    channel: ChannelKey,
    call: CallRow,
    owner: ClientId,
    revision: u64,
    membership: ?u8,
    offers: [2]?EndpointObservation = .{ null, null },
    removed_offers: u32 = 0,
};
const DepartureBacking = struct { source: *Backing, facts: DepartureCapture, terminal: bool, batch_parent: ?*ClientDepartureBacking = null, validated_scope: u64 = 0, committed: bool = false };
fn departureBacking(plan: *PreparedDeparture) *DepartureBacking {
    return @ptrCast(@alignCast(plan));
}
pub const PreparedDeparture = opaque {
    /// Borrows this source candidate. Batch parts expire with their batch.
    pub fn channel(self: *PreparedDeparture) []const u8 {
        const row = &departureBacking(self).facts.channel;
        return row.bytes[0..row.len];
    }
    pub fn isBatchPart(self: *PreparedDeparture) bool {
        return departureBacking(self).batch_parent != null;
    }
    pub fn isTerminal(self: *PreparedDeparture) bool {
        return departureBacking(self).terminal;
    }
    pub fn requireChannelLocked(self: *PreparedDeparture, domain: *Domain, token: *const Locked, channel_name: []const u8) Error!void {
        try self.validateLocked(domain, token);
        if (!std.meta.eql(try ChannelKey.init(channel_name), departureBacking(self).facts.channel)) return error.InvalidIdentity;
    }
    pub fn ownerKey(self: *PreparedDeparture, leg: Leg) EndpointKey {
        const facts = departureBacking(self).facts;
        return .{ .call = facts.call.id, .client = facts.owner, .leg = leg };
    }
    pub fn requireOwnerLocked(self: *PreparedDeparture, domain: *Domain, token: *const Locked, key: EndpointKey) Error!void {
        try self.validateLocked(domain, token);
        if (!std.meta.eql(self.ownerKey(key.leg), key)) return error.InvalidIdentity;
    }
    pub fn expectedOffer(self: *PreparedDeparture, leg: Leg) ?EndpointObservation {
        return departureBacking(self).facts.offers[@intFromEnum(leg)];
    }
    pub fn removesCall(self: *PreparedDeparture) bool {
        const facts = departureBacking(self).facts;
        return facts.call.offers == facts.removed_offers and facts.call.memberships == @as(u32, if (facts.membership != null) 1 else 0);
    }
    pub fn validateLocked(self: *PreparedDeparture, domain: *Domain, token: *const Locked) Error!void {
        try domain.requireNoActiveIngressLocked(token);
        const scope = try domain.requireScope(token);
        const plan = departureBacking(self);
        const source = backing(domain);
        if (plan.source != source or plan.committed or plan.terminal != source.closing or source.revision != plan.facts.revision or !std.meta.eql(source.calls.get(plan.facts.channel), @as(?CallRow, plan.facts.call))) return error.StaleCandidate;
        if (!std.meta.eql(plan.facts.membership, membershipBits(source, .{ .call = plan.facts.call.id, .client = plan.facts.owner }))) return error.StaleCandidate;
        for ([_]Leg{ .native, .webrtc }, 0..) |leg, n| {
            if (!std.meta.eql(plan.facts.offers[n], endpointObservation(source, .{ .call = plan.facts.call.id, .client = plan.facts.owner, .leg = leg }))) return error.StaleCandidate;
        }
        plan.validated_scope = scope.serial;
    }
    pub fn requireEndpointLocked(self: *PreparedDeparture, domain: *Domain, token: *const Locked, expected: EndpointObservation) Error!void {
        try self.validateLocked(domain, token);
        const actual = self.expectedOffer(expected.reference.endpoint.leg) orelse return error.EndpointUnavailable;
        if (!std.meta.eql(actual, expected)) return error.InvalidIdentity;
    }
    pub fn commitLocked(self: *PreparedDeparture, domain: *Domain, token: *const Locked) void {
        const plan = departureBacking(self);
        const source = backing(domain);
        const scope = domain.requireScope(token) catch @panic("invalid physical departure cut");
        std.debug.assert(!plan.committed and plan.source == source and plan.validated_scope == scope.serial and source.revision == plan.facts.revision);
        std.debug.assert(plan.batch_parent == null);
        publishDeparture(source, plan, true);
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedDeparture) void {
        const plan = departureBacking(self);
        const source = plan.source;
        std.debug.assert(plan.batch_parent == null);
        source.allocator.destroy(plan);
        unpinCandidate(source);
    }
};

fn cleanupBoundNativeRoutingTest(domain: *Domain, binding: *NativeBinding) void {
    domain.closeForTerminal() catch @panic("routing fixture retained source candidate");
    const source = backing(domain);
    while (source.endpoints.count() != 0 or source.memberships.count() != 0) {
        var call: CallId = undefined;
        var owner: ClientId = undefined;
        if (source.endpoints.count() != 0) {
            var it = source.endpoints.keyIterator();
            const key = it.next().?.*;
            call = key.call;
            owner = key.client;
        } else {
            var it = source.memberships.keyIterator();
            const key = it.next().?.*;
            call = key.call;
            owner = key.client;
        }
        const departure = domain.prepareDeparture(call, owner) catch @panic("routing fixture lost exact departure");
        defer departure.deinit();
        domain.withTerminalLocked(DepartureTestCut{ .domain = domain, .plan = departure }, DepartureTestCut.run) catch @panic("routing fixture failed exact terminal retirement");
    }
    domain.releaseNative(binding) catch @panic("routing fixture retained native binding");
}
test "Windows Helix configured pristine media captures exact paused owners and rejects retired graph" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    const testing = std.testing;
    const domain = try Domain.create(testing.allocator);
    defer domain.destroyQuiesced() catch @panic("pristine media test retained Domain");
    var native = native_owner.NativeMediaTransport.init(testing.allocator);
    defer native.deinit();
    var webrtc = try webrtc_owner.MediaPlane.initFallible(testing.allocator);
    defer webrtc.deinit();
    webrtc.dtls_enabled = true;
    webrtc.dtls13_enabled = true;
    const Sink = struct {
        fn nativeFrame(_: *anyopaque, _: []const u8, _: []const u8) void {}
        fn rtpFrame(_: *anyopaque, _: []const u8, _: []const u8, _: bool) void {}
    };
    var sink_ctx: u8 = 0;
    native.setCrossLegSink(.{ .ctx = &sink_ctx, .on_native_frame = Sink.nativeFrame });
    webrtc.setCrossLegSink(.{ .ctx = &sink_ctx, .on_rtp_frame = Sink.rtpFrame });
    try native.prepareColdResources(testing.io, native_owner.loopback_be, 0);
    try webrtc.prepareColdResources(testing.io, webrtc_owner.loopback_be, 0);
    const native_binding = try domain.bindNative(&native);
    defer domain.releaseNative(native_binding) catch @panic("pristine media test retained native binding");
    const webrtc_binding = try domain.bindWebrtc(&webrtc);
    defer domain.releaseWebrtc(webrtc_binding) catch @panic("pristine media test retained WebRTC binding");
    try webrtc.prepareRoutingEgress(domain, 4, 256);
    defer webrtc.disposeRoutingEgress(domain) catch @panic("pristine media test retained FIFO");
    try native.startPreparedLegacyWorker();
    defer {
        native.requestStopAndWake();
        native.joinLegacyAfterStop() catch @panic("pristine native worker did not join");
    }
    try webrtc.startPreparedLegacyWorker();
    defer {
        webrtc.requestStopAndWake();
        webrtc.joinLegacyAfterStop() catch @panic("pristine WebRTC worker did not join");
    }
    const native_token = try native.requestPause(1);
    const webrtc_token = try webrtc.requestPause(1);
    const native_deadline = std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    const webrtc_deadline = std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    try native.awaitPaused(native_token, native_deadline);
    try webrtc.awaitPaused(webrtc_token, webrtc_deadline);
    try testing.expectError(error.RoutingContinuityUnsupported, native.capturePaused(native_token));
    try testing.expectError(error.RoutingContinuityUnsupported, webrtc.capturePaused(webrtc_token));
    var carry = try domain.capturePausedPristineMedia(&native, native_token, &webrtc, webrtc_token);
    defer carry.deinit();
    try testing.expect(carry.native.cross_configured and carry.webrtc.cross_configured);
    try testing.expect(carry.webrtc.dtls12 != null and carry.webrtc.dtls13 != null);
    try testing.expect(carry.native.socket.port != 0 and carry.webrtc.socket.port != 0);
    try testing.expectEqual(native.port, carry.native.socket.port);
    try testing.expectEqual(webrtc.port, carry.webrtc.socket.port);

    var foreign = native_owner.NativeMediaTransport.init(testing.allocator);
    defer foreign.deinit();
    try testing.expectError(error.InvalidIdentity, domain.capturePausedPristineMedia(&foreign, native_token, &webrtc, webrtc_token));
    const queue = webrtc.routing_egress.?;
    queue.next_ordinal = 2; // Settled, empty FIFO with prior accepted ordinal.
    try testing.expectError(error.ActiveMediaContinuityUnsupported, domain.capturePausedPristineMedia(&native, native_token, &webrtc, webrtc_token));
    queue.next_ordinal = 1;
    native.next_ingress_serial = 2; // No current ingress, but one was issued.
    try testing.expectError(error.ActiveMediaContinuityUnsupported, domain.capturePausedPristineMedia(&native, native_token, &webrtc, webrtc_token));
    native.next_ingress_serial = 1;
    webrtc.next_routing_inbound = 2;
    try testing.expectError(error.ActiveMediaContinuityUnsupported, domain.capturePausedPristineMedia(&native, native_token, &webrtc, webrtc_token));
    webrtc.next_routing_inbound = 1;

    const id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const membership = try domain.prepareMembership("#history", id, 1);
    const call = membership.preview().call;
    const CommitMembership = struct {
        domain: *Domain,
        plan: *PreparedMembership,
        fn run(scope: *Locked, ctx: @This()) Error!void {
            try ctx.plan.validateLocked(ctx.domain, scope);
            ctx.plan.commitLocked(ctx.domain, scope);
        }
    };
    try domain.withLocked(CommitMembership{ .domain = domain, .plan = membership }, CommitMembership.run);
    membership.deinit();
    const sibling = ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    const sibling_membership = try domain.prepareMembership("#history", sibling, 2);
    try domain.withLocked(CommitMembership{ .domain = domain, .plan = sibling_membership }, CommitMembership.run);
    sibling_membership.deinit();
    var graph = try domain.captureGraph(&native, native_token, &webrtc, webrtc_token);
    defer graph.deinit();
    {
        native.physical_pending = 1;
        defer native.physical_pending = 0;
        try testing.expectError(error.Busy, domain.captureGraph(&native, native_token, &webrtc, webrtc_token));
    }
    {
        webrtc.physical_pending = 1;
        defer webrtc.physical_pending = 0;
        try testing.expectError(error.Busy, domain.captureGraph(&native, native_token, &webrtc, webrtc_token));
    }
    try testing.expectEqual(@as(usize, 2), graph.memberships.len);
    const target = ClientId{ .shard = 1, .slot = 11, .gen = 2 };
    const sibling_target = ClientId{ .shard = 1, .slot = 12, .gen = 2 };
    var remapped = try prepareRemappedGraph(testing.allocator, &graph, &.{ .{ .source = id, .target = target }, .{ .source = sibling, .target = sibling_target } });
    defer remapped.deinit();
    try remapped.validate();
    try testing.expectEqual(graph.id.serial, remapped.id.serial);
    try testing.expectEqual(graph.next_call, remapped.next_call);
    try testing.expect(remapped.usesClient(target) and remapped.usesClient(sibling_target));
    try testing.expect(!remapped.usesClient(id) and !remapped.usesClient(sibling));
    try testing.expectError(error.IncompleteRemap, prepareRemappedGraph(testing.allocator, &graph, &.{.{ .source = id, .target = target }}));
    try testing.expectError(error.InvalidSnapshot, prepareRemappedGraph(testing.allocator, &graph, &.{ .{ .source = id, .target = target }, .{ .source = sibling, .target = target } }));
    try testing.expectError(error.InvalidSnapshot, prepareRemappedGraph(testing.allocator, &graph, &.{ .{ .source = id, .target = target }, .{ .source = id, .target = sibling_target } }));
    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    const baseline = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..8) |n| {
        fail.fail_index = fail.alloc_index + n;
        var retry = prepareRemappedGraph(fail.allocator(), &graph, &.{ .{ .source = id, .target = target }, .{ .source = sibling, .target = sibling_target } }) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
            try graph.validate();
            failures += 1;
            continue;
        };
        fail.fail_index = std.math.maxInt(usize);
        retry.deinit();
        try testing.expectEqual(baseline, fail.allocated_bytes - fail.freed_bytes);
        succeeded = true;
        break;
    }
    // This fixture has nonempty call and membership slices; zero-length
    // endpoint/policy slices need no backing allocation.
    try testing.expect(succeeded and failures >= 2);
    try testing.expectError(error.Busy, domain.capturePausedPristineMedia(&native, native_token, &webrtc, webrtc_token));
    const departure = try domain.prepareDeparture(call, id);
    defer departure.deinit();
    try domain.withLocked(DepartureTestCut{ .domain = domain, .plan = departure }, DepartureTestCut.run);
    const sibling_departure = try domain.prepareDeparture(call, sibling);
    defer sibling_departure.deinit();
    try domain.withLocked(DepartureTestCut{ .domain = domain, .plan = sibling_departure }, DepartureTestCut.run);
    try testing.expectError(error.Busy, domain.capturePausedPristineMedia(&native, native_token, &webrtc, webrtc_token));
}
const DepartureTestCut = struct {
    domain: *Domain,
    plan: *PreparedDeparture,
    fn run(scope: *Locked, ctx: @This()) Error!void {
        try ctx.plan.validateLocked(ctx.domain, scope);
        ctx.plan.commitLocked(ctx.domain, scope);
    }
};
test "media routing actual native binding rejects foreign selector and pending departure" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("unclosed bound source");
    var native = native_owner.NativeMediaTransport.init(std.testing.allocator);
    defer native.deinit();
    const binding = try domain.bindNative(&native);
    defer cleanupBoundNativeRoutingTest(domain, binding);
    try std.testing.expectError(error.Busy, domain.destroyQuiesced());
    const Check = struct {
        domain: *Domain,
        native: *native_owner.NativeMediaTransport,
        fn run(scope: *Locked, ctx: @This()) anyerror!void {
            try std.testing.expectError(error.InvalidIdentity, ctx.domain.requireNativeBindingLocked(scope, @ptrFromInt(@alignOf(NativeBindingBacking)), ctx.native));
        }
    };
    try domain.withLocked(Check{ .domain = domain, .native = &native }, Check.run);
    const owner = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    var call: CallId = undefined;
    {
        const offer = try domain.prepareOffers("#binding", owner, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offer.deinit();
        call = offer.preview().call;
        try std.testing.expectError(error.Busy, domain.releaseNative(binding));
        try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
    }
    try std.testing.expectError(error.Busy, domain.releaseNative(binding));
    const departure = try domain.prepareDeparture(call, owner);
    defer departure.deinit();
    try domain.withLocked(DepartureTestCut{ .domain = domain, .plan = departure }, DepartureTestCut.run);
    try std.testing.expectError(error.Busy, domain.releaseNative(binding));
}
test "media routing terminal source closes ordinary issuers and retires exact rows at exhausted counters" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("terminal routing rows survived");
    const owner = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    var call: CallId = undefined;
    {
        const offer = try domain.prepareOffers("#last", owner, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offer.deinit();
        call = offer.preview().call;
        try std.testing.expectError(error.Busy, domain.closeForTerminal());
        try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
    }
    const source = backing(domain);
    source.revision = std.math.maxInt(u64);
    source.next_scope = std.math.maxInt(u64);
    try std.testing.expectError(error.SequenceExhausted, domain.prepareDeparture(call, owner));
    try domain.closeForTerminal();
    try std.testing.expectError(error.Closing, domain.prepareMembership("#last", owner, 1));
    const departure = try domain.prepareDeparture(call, owner);
    defer departure.deinit();
    try std.testing.expectError(error.Closing, domain.withLocked(DepartureTestCut{ .domain = domain, .plan = departure }, DepartureTestCut.run));
    try domain.withTerminalLocked(DepartureTestCut{ .domain = domain, .plan = departure }, DepartureTestCut.run);
    try std.testing.expectEqual(@as(u32, 0), source.endpoints.count());
    try std.testing.expectEqual(@as(u32, 0), source.calls.count());
    try std.testing.expectEqual(std.math.maxInt(u64), source.revision);
    try std.testing.expectEqual(std.math.maxInt(u64), source.next_scope);
}

fn clientOwnsCall(source: *Backing, call: CallId, owner: ClientId) bool {
    return source.memberships.contains(.{ .call = call, .client = owner }) or
        source.endpoints.contains(.{ .call = call, .client = owner, .leg = .native }) or
        source.endpoints.contains(.{ .call = call, .client = owner, .leg = .webrtc });
}
fn publishDeparture(source: *Backing, plan: *DepartureBacking, advance: bool) void {
    if (plan.facts.removed_offers == 0 and plan.facts.membership == null) return;
    for ([_]Leg{ .native, .webrtc }, 0..) |leg, i| {
        const key: EndpointKey = .{ .call = plan.facts.call.id, .client = plan.facts.owner, .leg = leg };
        removeBridgePolicy(source, key, plan.facts.offers[i]);
        _ = source.endpoints.remove(key);
    }
    _ = source.memberships.remove(.{ .call = plan.facts.call.id, .client = plan.facts.owner });
    var row = plan.facts.call;
    row.offers -= plan.facts.removed_offers;
    row.memberships -= if (plan.facts.membership != null) @as(u32, 1) else 0;
    if (row.offers == 0 and row.memberships == 0) _ = source.calls.remove(plan.facts.channel) else source.calls.getPtr(plan.facts.channel).?.* = row;
    if (advance and !plan.terminal) source.revision += 1;
}
const ClientDepartureBacking = struct {
    source: *Backing,
    owner: ClientId,
    revision: u64,
    terminal: bool,
    parts: []DepartureBacking,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn clientDeparture(batch: *PreparedClientDeparture) *ClientDepartureBacking {
    return @ptrCast(@alignCast(batch));
}
pub const PreparedClientDeparture = opaque {
    pub fn count(self: *PreparedClientDeparture) usize {
        return clientDeparture(self).parts.len;
    }
    /// Lifetime is borrowed from the complete batch; a part cannot publish or
    /// deinitialize independently. Leaf/Room plans MUST finish before the batch.
    pub fn part(self: *PreparedClientDeparture, index: usize) *PreparedDeparture {
        return @ptrCast(&clientDeparture(self).parts[index]);
    }
    pub fn isTerminal(self: *PreparedClientDeparture) bool {
        return clientDeparture(self).terminal;
    }
    pub fn requirePartLocked(self: *PreparedClientDeparture, domain: *Domain, scope: *const Locked, index: usize, expected: *PreparedDeparture) Error!void {
        const plan = clientDeparture(self);
        if (index >= plan.parts.len or expected != self.part(index) or departureBacking(expected).batch_parent != plan) return error.InvalidIdentity;
        const source = backing(domain);
        if (plan.source != source or plan.committed or plan.revision != source.revision or plan.terminal != source.closing) return error.StaleCandidate;
        try expected.validateLocked(domain, scope);
    }
    pub fn validateLocked(self: *PreparedClientDeparture, domain: *Domain, scope: *const Locked) Error!void {
        try domain.requireNoActiveIngressLocked(scope);
        const serial = try domain.scopeSerial(scope);
        const plan = clientDeparture(self);
        const source = backing(domain);
        if (plan.source != source or plan.committed or plan.revision != source.revision or plan.terminal != source.closing) return error.StaleCandidate;
        for (plan.parts, 0..) |*row, n| {
            if (row.batch_parent != plan or row.committed or !std.meta.eql(row.facts.owner, plan.owner)) return error.InvalidIdentity;
            try self.part(n).validateLocked(domain, scope);
        }
        plan.validated_scope = serial;
    }
    pub fn commitLocked(self: *PreparedClientDeparture, domain: *Domain, scope: *const Locked) void {
        const serial = domain.scopeSerial(scope) catch @panic("invalid complete-client departure cut");
        const plan = clientDeparture(self);
        const source = backing(domain);
        std.debug.assert(plan.source == source and !plan.committed and plan.validated_scope == serial and source.revision == plan.revision);
        for (plan.parts) |*row| {
            std.debug.assert(!row.committed and row.validated_scope == serial);
            publishDeparture(source, row, false);
            row.committed = true;
        }
        if (plan.parts.len != 0 and !plan.terminal) source.revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *PreparedClientDeparture) void {
        const plan = clientDeparture(self);
        const source = plan.source;
        source.allocator.free(plan.parts);
        source.allocator.destroy(plan);
        unpinCandidate(source);
    }
};

fn batchTestMapState(map: anytype) struct { metadata: usize, count: u32, capacity: u32, available: u32 } {
    return .{ .metadata = if (map.unmanaged.metadata) |ptr| @intFromPtr(ptr) else 0, .count = map.count(), .capacity = map.capacity(), .available = map.unmanaged.available };
}
fn cleanupClientBatchTest(domain: *Domain) void {
    const source = backing(domain);
    while (source.calls.count() != 0) {
        var calls = source.calls.valueIterator();
        const call = calls.next().?.id;
        var found: ?ClientId = null;
        var offers = source.endpoints.keyIterator();
        while (offers.next()) |key| if (std.meta.eql(key.call, call)) {
            found = key.client;
            break;
        };
        if (found == null) {
            var members = source.memberships.keyIterator();
            while (members.next()) |key| if (std.meta.eql(key.call, call)) {
                found = key.client;
                break;
            };
        }
        const Ctx = struct {
            domain: *Domain,
            call: CallId,
            client_id: ClientId,
            fn run(scope: *Locked, ctx: @This()) Error!void {
                try ctx.domain.revokeOffersLocked(scope, ctx.call, ctx.client_id);
                try ctx.domain.revokeMembershipLocked(scope, ctx.call, ctx.client_id);
            }
        };
        domain.withLocked(Ctx{ .domain = domain, .call = call, .client_id = found orelse @panic("source call has no live custody") }, Ctx.run) catch @panic("unbound batch fixture retained rows");
    }
}
test "media routing complete client departure every OOM retains all OLD calls indices and issuers" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const domain = try Domain.create(fail.allocator());
    defer domain.destroyQuiesced() catch @panic("batch OOM source retained graph");
    defer cleanupClientBatchTest(domain);
    const source = backing(domain);
    const id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    for ([_][]const u8{ "#a", "#b" }) |channel| {
        const offer = try domain.prepareOffers(channel, id, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .legacy_group } });
        defer offer.deinit();
        try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
    }
    const revision = source.revision;
    const calls_state = batchTestMapState(source.calls);
    const endpoints_state = batchTestMapState(source.endpoints);
    const next_call = source.next_call;
    const next_endpoint = source.next_endpoint;
    const next_stream = source.next_stream;
    var failures: usize = 0;
    var reached_success = false;
    for (0..16) |n| {
        fail.fail_index = fail.alloc_index + n;
        const batch = domain.prepareClientDeparture(id) catch |err| {
            fail.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(revision, source.revision);
            try std.testing.expectEqualDeep(calls_state, batchTestMapState(source.calls));
            try std.testing.expectEqualDeep(endpoints_state, batchTestMapState(source.endpoints));
            try std.testing.expectEqual(next_call, source.next_call);
            try std.testing.expectEqual(next_endpoint, source.next_endpoint);
            try std.testing.expectEqual(next_stream, source.next_stream);
            try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
            // Exact same owner can prepare and abort immediately after failure.
            {
                const retry = try domain.prepareClientDeparture(id);
                defer retry.deinit();
                try std.testing.expectEqual(@as(usize, 2), retry.count());
            }
            failures += 1;
            continue;
        };
        {
            defer batch.deinit();
            fail.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(@as(usize, 2), batch.count());
            try std.testing.expectEqualStrings("#a", batch.part(0).channel());
            try std.testing.expectEqualStrings("#b", batch.part(1).channel());
        }
        reached_success = true;
        break;
    }
    try std.testing.expect(failures != 0 and reached_success);
    try std.testing.expectEqual(revision, source.revision);
    try std.testing.expectEqualDeep(calls_state, batchTestMapState(source.calls));
    try std.testing.expectEqualDeep(endpoints_state, batchTestMapState(source.endpoints));
    try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
}

const ZeroOfferCleanup = struct {
    domain: *Domain,
    call: CallId,
    owner: ClientId,
    fn run(scope: *Locked, ctx: @This()) Error!void {
        try ctx.domain.revokeOffersLocked(scope, ctx.call, ctx.owner);
        try ctx.domain.revokeMembershipLocked(scope, ctx.call, ctx.owner);
    }
    fn finish(ctx: @This()) void {
        ctx.domain.withLocked(ctx, run) catch @panic("zero-offer fixture retained actual source rows");
    }
};

test "media routing count causal JOIN first accepts first offer on zero count" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("JOIN-first source custody");
    const id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const call = blk: {
        const membership = try domain.prepareMembership("#join-first", id, 1);
        defer membership.deinit();
        const preview = membership.preview();
        try domain.withLocked(MembershipPublish{ .domain = domain, .plan = membership }, MembershipPublish.run);
        break :blk preview.call;
    };
    defer (ZeroOfferCleanup{ .domain = domain, .call = call, .owner = id }).finish();
    const source = backing(domain);
    const key = try ChannelKey.init("#join-first");
    try std.testing.expectEqual(@as(u32, 0), source.calls.get(key).?.offers);
    try std.testing.expectEqual(@as(u32, 1), source.calls.get(key).?.memberships);
    const offer = try domain.prepareOffers("#JOIN-FIRST", id, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer offer.deinit();
    try std.testing.expect(std.meta.eql(call, offer.preview().call));
    try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
    try std.testing.expectEqual(@as(u32, 1), source.calls.get(key).?.offers);
    try std.testing.expectEqual(@as(u32, 1), source.calls.get(key).?.memberships);
}

test "media routing count causal last offer retirement preserves membership and allows reoffer" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("retired-offer source custody");
    const id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const initial = blk: {
        const first = try domain.prepareOffers("#reoffer", id, &.{.{ .leg = .webrtc, .mode = .dtls_required }});
        defer first.deinit();
        const preview = first.preview();
        try domain.withLocked(PublishContext{ .domain = domain, .plan = first }, publishForTest);
        break :blk preview;
    };
    defer (ZeroOfferCleanup{ .domain = domain, .call = initial.call, .owner = id }).finish();
    {
        const membership = try domain.prepareMembership("#reoffer", id, 1);
        defer membership.deinit();
        try domain.withLocked(MembershipPublish{ .domain = domain, .plan = membership }, MembershipPublish.run);
    }
    try domain.withLocked(RevokeContext{ .domain = domain, .call = initial.call, .owner = id }, revokeForTest);
    const key = try ChannelKey.init("#reoffer");
    const source = backing(domain);
    try std.testing.expectEqual(@as(u32, 0), source.calls.get(key).?.offers);
    try std.testing.expectEqual(@as(u32, 1), source.calls.get(key).?.memberships);
    const replacement = try domain.prepareOffers("#reoffer", id, &.{.{ .leg = .webrtc, .mode = .dtls_required }});
    defer replacement.deinit();
    try std.testing.expect(std.meta.eql(initial.call, replacement.preview().call));
    try std.testing.expect(replacement.preview().endpoints[0].stamp.endpoint.serial > initial.endpoints[0].stamp.endpoint.serial);
    try domain.withLocked(PublishContext{ .domain = domain, .plan = replacement }, publishForTest);
    try std.testing.expectEqual(@as(u32, 1), source.calls.get(key).?.offers);
}

test "media routing count causal exhausted count refuses before allocation without weakening issuers" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const domain = try Domain.create(fail.allocator());
    defer domain.destroyQuiesced() catch @panic("count-boundary source custody");
    const id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const call = blk: {
        const offer = try domain.prepareOffers("#count-max", id, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offer.deinit();
        const preview = offer.preview();
        try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
        break :blk preview.call;
    };
    defer (ZeroOfferCleanup{ .domain = domain, .call = call, .owner = id }).finish();
    const source = backing(domain);
    const key = try ChannelKey.init("#count-max");
    // Private numeric-boundary injection; no claim of billions of live rows.
    source.calls.getPtr(key).?.offers = std.math.maxInt(u32);
    defer source.calls.getPtr(key).?.offers = 1;
    const index = fail.alloc_index;
    const revision = source.revision;
    const stream = source.next_stream;
    fail.fail_index = index;
    defer fail.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.SequenceExhausted, domain.prepareOffers("#count-max", .{ .shard = 0, .slot = 1, .gen = 0 }, &.{.{ .leg = .native, .mode = .legacy_group }}));
    try std.testing.expectEqual(index, fail.alloc_index);
    try std.testing.expectEqual(revision, source.revision);
    try std.testing.expectEqual(stream, source.next_stream);
    try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
    try std.testing.expectEqual(@as(u32, 1), source.endpoints.count());
}

test "media routing count causal zero identity issuers still refuse before allocation" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const domain = try Domain.create(fail.allocator());
    defer domain.destroyQuiesced() catch @panic("identity-boundary source custody");
    const source = backing(domain);
    const id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const index = fail.alloc_index;
    fail.fail_index = index;
    defer fail.fail_index = std.math.maxInt(usize);
    const original_stream = source.next_stream;
    source.next_stream = 0;
    defer source.next_stream = original_stream;
    try std.testing.expectError(error.SequenceExhausted, domain.prepareOffers("#issuer", id, &.{.{ .leg = .native, .mode = .legacy_group }}));
    source.next_stream = original_stream;
    const original_revision = source.revision;
    source.revision = 0;
    defer source.revision = original_revision;
    try std.testing.expectError(error.SequenceExhausted, domain.prepareOffers("#issuer", id, &.{.{ .leg = .native, .mode = .legacy_group }}));
    try std.testing.expectEqual(index, fail.alloc_index);
    try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
    try std.testing.expectEqual(@as(u32, 0), source.calls.capacity());
    try std.testing.expectEqual(@as(u32, 0), source.endpoints.capacity());
}

fn retrySweepMapState(map: anytype) struct { metadata: usize, count: u32, capacity: u32, available: u32 } {
    return .{ .metadata = if (map.unmanaged.metadata) |ptr| @intFromPtr(ptr) else 0, .count = map.count(), .capacity = map.capacity(), .available = map.unmanaged.available };
}
fn routingPreparationRetrySweep(membership: bool) !void {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const domain = try Domain.create(fail.allocator());
    defer domain.destroyQuiesced() catch @panic("routing retry sweep retained candidate");
    const source = backing(domain);
    const id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const old_calls = retrySweepMapState(source.calls);
    const old_endpoints = retrySweepMapState(source.endpoints);
    const old_memberships = retrySweepMapState(source.memberships);
    const old_allocated = fail.allocated_bytes - fail.freed_bytes;
    var failures: usize = 0;
    var succeeded = false;
    for (0..32) |n| {
        fail.fail_index = fail.alloc_index + n;
        if (membership) {
            const plan = domain.prepareMembership("#retry", id, 1) catch |err| {
                fail.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
                try std.testing.expectEqualDeep(old_calls, retrySweepMapState(source.calls));
                try std.testing.expectEqualDeep(old_memberships, retrySweepMapState(source.memberships));
                const retry = try domain.prepareMembership("#retry", id, 1);
                retry.deinit();
                try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                failures += 1;
                continue;
            };
            fail.fail_index = std.math.maxInt(usize);
            plan.deinit();
        } else {
            const plan = domain.prepareOffers("#retry", id, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .legacy_group } }) catch |err| {
                fail.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
                try std.testing.expectEqualDeep(old_calls, retrySweepMapState(source.calls));
                try std.testing.expectEqualDeep(old_endpoints, retrySweepMapState(source.endpoints));
                const retry = try domain.prepareOffers("#retry", id, &.{ .{ .leg = .native, .mode = .legacy_group }, .{ .leg = .webrtc, .mode = .legacy_group } });
                retry.deinit();
                try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
                failures += 1;
                continue;
            };
            fail.fail_index = std.math.maxInt(usize);
            plan.deinit();
        }
        succeeded = true;
        break;
    }
    try std.testing.expectEqual(old_allocated, fail.allocated_bytes - fail.freed_bytes);
    try std.testing.expect(succeeded and failures >= 3);
    try std.testing.expectEqual(@as(usize, 0), source.pending_candidates);
    try std.testing.expectEqualDeep(old_calls, retrySweepMapState(source.calls));
    try std.testing.expectEqualDeep(old_endpoints, retrySweepMapState(source.endpoints));
    try std.testing.expectEqualDeep(old_memberships, retrySweepMapState(source.memberships));
    try std.testing.expectEqual(@as(u64, 1), source.revision);
    try std.testing.expectEqual(@as(u64, 1), source.next_call);
    try std.testing.expectEqual(@as(u64, 1), source.next_endpoint);
    try std.testing.expectEqual(@as(u32, 1), source.next_stream);
}
test "media routing both growth maps every failure restores exact OLD and same owner retry" {
    try routingPreparationRetrySweep(false);
    try routingPreparationRetrySweep(true);
}

pub const TransportNegotiation = struct { profile: media_rooms.CallProfile, kind_bits: u8 };
pub const BridgePolicyRow = struct { reference: EndpointRef, profile: media_rooms.CallProfile, kind_bits: u8 };
const BridgeMap = std.AutoHashMap(EndpointKey, BridgePolicyRow);
const BridgeCapture = struct { revision: u64, count: u32, capacity: u32, metadata: usize, required: u32, grow: bool };
const BridgePlan = struct {
    source: *Backing,
    offers: *PreparedOffers,
    native: ?*native_owner.PreparedNativeOffer,
    webrtc: ?*webrtc_owner.PreparedWebrtcOffer,
    channel: ChannelKey,
    facts: BridgeCapture,
    rows: [2]BridgePolicyRow,
    count: u8,
    growth: ?BridgeMap,
    validated_scope: u64 = 0,
    committed: bool = false,
};
fn bridgePlan(plan: *PreparedPhysicalBridge) *BridgePlan {
    return @ptrCast(@alignCast(plan));
}
pub const PreparedPhysicalBridge = opaque {
    pub fn validateLocked(self: *PreparedPhysicalBridge, domain: *Domain, scope: *const Locked, offers: *PreparedOffers, native: ?*native_owner.PreparedNativeOffer, webrtc: ?*webrtc_owner.PreparedWebrtcOffer) !void {
        const p = bridgePlan(self);
        const source = backing(domain);
        const serial = try domain.scopeSerial(scope);
        if (p.source != source or p.offers != offers or p.native != native or p.webrtc != webrtc or p.committed) return error.StaleCandidate;
        try offers.validateLocked(domain, scope);
        if (source.revision != p.facts.revision or source.bridge_policy.count() != p.facts.count or source.bridge_policy.capacity() != p.facts.capacity or (if (source.bridge_policy.unmanaged.metadata) |ptr| @intFromPtr(ptr) else 0) != p.facts.metadata) return error.StaleCandidate;
        for (p.rows[0..p.count]) |row| {
            const observed = try offers.observationLocked(domain, scope, p.channel.bytes[0..p.channel.len], row.reference.endpoint.leg);
            if (!std.meta.eql(observed.reference, row.reference)) return error.InvalidIdentity;
            switch (row.reference.endpoint.leg) {
                .native => try native.?.requireNegotiationLocked(domain, scope, offers, row.profile, row.kind_bits),
                .webrtc => try webrtc.?.requireNegotiationLocked(domain, scope, offers, row.profile, row.kind_bits, webrtc.?.expectedFingerprint()),
            }
        }
        p.validated_scope = serial;
    }
    /// All authoritative plans validate before any publication. This map swap
    /// and its inline rows contain no backend callbacks; retired backing stays
    /// on this candidate until caller cleanup AFTER the shared cut.
    pub fn commitLocked(self: *PreparedPhysicalBridge, domain: *Domain, scope: *const Locked) void {
        const p = bridgePlan(self);
        const source = backing(domain);
        const serial = domain.scopeSerial(scope) catch @panic("invalid bridge cut");
        std.debug.assert(p.source == source and !p.committed and p.validated_scope == serial and source.revision == p.facts.revision);
        if (p.growth) |*map| {
            var iterator = source.bridge_policy.iterator();
            while (iterator.next()) |entry| map.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(BridgeMap, &source.bridge_policy, map);
        }
        for (p.rows[0..p.count]) |row| source.bridge_policy.putAssumeCapacity(.{ .call = row.reference.endpoint.call, .client = row.reference.offering_client, .leg = row.reference.endpoint.leg }, row);
        p.committed = true;
    }
    pub fn deinit(self: *PreparedPhysicalBridge) void {
        const p = bridgePlan(self);
        const source = p.source;
        if (p.growth) |*map| map.deinit();
        source.allocator.destroy(p);
        unpinCandidate(source);
    }
};
fn removeBridgePolicy(source: *Backing, key: EndpointKey, expected: ?EndpointObservation) void {
    if (source.bridge_policy.get(key)) |row| {
        if (expected) |endpoint| {
            std.debug.assert(std.meta.eql(row.reference, endpoint.reference));
        } else @panic("bridge policy has no exact departing endpoint");
        _ = source.bridge_policy.remove(key);
    }
}

test "media routing authentic terminal queue retirement succeeds at exhausted scope and fence issuers" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("terminal queue Domain retained");
    var owner = try webrtc_owner.MediaPlane.initFallible(std.testing.allocator);
    defer owner.deinit();
    const binding = try domain.bindWebrtc(&owner);
    defer domain.releaseWebrtc(binding) catch @panic("terminal queue binding retained");
    try owner.prepareRoutingEgress(domain, 2, 128);
    // No forged worker counters: this source never started a worker, and has
    // no pending candidates, accepted queued payload or outstanding operation.
    const source = backing(domain);
    source.next_scope = std.math.maxInt(u64);
    const Refused = struct {
        owner: *webrtc_owner.MediaPlane,
        domain: *Domain,
        fn run(scope: *Locked, ctx: @This()) !void {
            _ = try ctx.owner.fenceRoutingProducersLocked(ctx.domain, scope);
        }
    };
    try std.testing.expectError(error.SequenceExhausted, domain.withLocked(Refused{ .owner = &owner, .domain = domain }, Refused.run));
    try domain.closeForTerminal();
    try std.testing.expectError(error.Busy, domain.releaseWebrtc(binding));
    try owner.finishRoutingTerminalCleanup(domain);
    try owner.finishRoutingTerminalCleanup(domain);
    try std.testing.expectEqual(std.math.maxInt(u64), source.next_scope);
    try std.testing.expectError(error.Closing, domain.prepareOffers("#closed", .{ .shard = 0, .slot = 0, .gen = 0 }, &.{.{ .leg = .webrtc, .mode = .legacy_group }}));
}

test "media routing physical client denial precedes OOM cleanup and preserves sibling across detached growth" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch @panic("denial fixture retained source rows");
    const client_id = ClientId{ .shard = 0, .slot = 0, .gen = 0 };
    const sibling = ClientId{ .shard = 0, .slot = 1, .gen = 0 };
    var original: OfferPreview = undefined;
    {
        const initial = try domain.prepareOffers("#denial", client_id, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer initial.deinit();
        original = initial.preview();
        try domain.withLocked(PublishContext{ .domain = domain, .plan = initial }, publishForTest);
    }
    const stale = try domain.prepareOffers("#denial", client_id, &.{.{ .leg = .native, .mode = .legacy_group }});
    defer stale.deinit();
    const source = backing(domain);
    const old_scope = source.next_scope;
    {
        source.next_scope = std.math.maxInt(u64);
        defer source.next_scope = old_scope;
        const denied = try domain.fenceClientRetirement(client_id);
        try std.testing.expectEqual(@as(u32, 1), denied.offers);
        try std.testing.expectEqual(std.math.maxInt(u64), source.next_scope);
    }
    try std.testing.expectError(error.Closing, domain.withLocked(PublishContext{ .domain = domain, .plan = stale }, publishForTest));
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const original_allocator = source.allocator;
    {
        source.allocator = fail.allocator();
        defer source.allocator = original_allocator;
        try std.testing.expectError(error.OutOfMemory, domain.prepareClientDeparture(client_id));
    }
    const Inspect = struct {
        domain: *Domain,
        original: EndpointObservation,
        fn run(scope: *Locked, ctx: @This()) !void {
            try std.testing.expectError(error.EndpointUnavailable, ctx.domain.requireCurrentLocked(scope, ctx.original.stamp));
            try std.testing.expectEqualDeep(@as(?EndpointObservation, ctx.original), try ctx.domain.observeLocked(scope, .{ .call = ctx.original.stamp.endpoint.call, .client = ctx.original.stamp.offering_client, .leg = .native }));
        }
    };
    try domain.withLocked(Inspect{ .domain = domain, .original = original.endpoints[0] }, Inspect.run);
    for (0..12) |i| {
        const owner = ClientId{ .shard = 1, .slot = @intCast(i), .gen = 0 };
        const offer = try domain.prepareOffers("#denial", owner, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offer.deinit();
        try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
    }
    try domain.withLocked(Inspect{ .domain = domain, .original = original.endpoints[0] }, Inspect.run);
    // Same nickname is deliberately absent: full physical identity controls
    // denial, and siblings retain independent source authority.
    {
        const offer = try domain.prepareOffers("#denial", sibling, &.{.{ .leg = .native, .mode = .legacy_group }});
        defer offer.deinit();
        try domain.withLocked(PublishContext{ .domain = domain, .plan = offer }, publishForTest);
    }
    try std.testing.expectError(error.Closing, domain.prepareMembership("#denial", client_id, 1));
    try std.testing.expectError(error.Closing, domain.prepareOffers("#denial", client_id, &.{.{ .leg = .native, .mode = .legacy_group }}));
    // Final cleanup is actual source retirement; flags never erase its census.
    for (0..12) |i| try domain.withLocked(RevokeContext{ .domain = domain, .call = original.call, .owner = .{ .shard = 1, .slot = @intCast(i), .gen = 0 } }, revokeForTest);
    try domain.withLocked(RevokeContext{ .domain = domain, .call = original.call, .owner = sibling }, revokeForTest);
    try domain.withLocked(RevokeContext{ .domain = domain, .call = original.call, .owner = client_id }, revokeForTest);
}

test "media routing lexical result preserves narrow callback payload and all source admission errors" {
    const domain = try Domain.create(std.testing.allocator);
    defer domain.destroyQuiesced() catch unreachable;
    var calls: usize = 0;
    const Narrow = struct {
        calls: *usize,
        refuse: bool = false,
        fn run(_: *Locked, ctx: @This()) error{CallbackRefused}!u32 {
            ctx.calls.* += 1;
            if (ctx.refuse) return error.CallbackRefused;
            return 41;
        }
    };
    const ctx = Narrow{ .calls = &calls };
    try std.testing.expectEqual(@as(u32, 41), try domain.withLocked(ctx, Narrow.run));
    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expectError(error.CallbackRefused, domain.withLocked(Narrow{ .calls = &calls, .refuse = true }, Narrow.run));
    try std.testing.expectEqual(@as(usize, 2), calls);
    const source = backing(domain);
    {
        const previous = source.next_scope;
        defer source.next_scope = previous;
        source.next_scope = std.math.maxInt(u64);
        try std.testing.expectError(error.SequenceExhausted, domain.withLocked(ctx, Narrow.run));
        try std.testing.expectEqual(@as(usize, 2), calls);
    }
    try std.testing.expectError(error.Busy, domain.withTerminalLocked(ctx, Narrow.run));
    try std.testing.expectEqual(@as(usize, 2), calls);
    try domain.closeForTerminal();
    try std.testing.expectError(error.Closing, domain.withLocked(ctx, Narrow.run));
    try std.testing.expectEqual(@as(usize, 2), calls);
    try std.testing.expectEqual(@as(u32, 41), try domain.withTerminalLocked(ctx, Narrow.run));
    try std.testing.expectEqual(@as(usize, 3), calls);
    try std.testing.expectError(error.CallbackRefused, domain.withTerminalLocked(Narrow{ .calls = &calls, .refuse = true }, Narrow.run));
    try std.testing.expectEqual(@as(usize, 4), calls);
}
