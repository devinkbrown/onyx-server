// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reactor-independent buffering adapter around `s2s_peer.S2sPeer`.
//!
//! `s2s_peer` is a pure server-to-server connection driver that emits outbound
//! bytes through a `ByteSink` callback and consumes a caller-supplied clock/rng.
//! The io_uring reactor, however, speaks in *buffers*: a recv completion hands
//! us inbound bytes, and a send completion drains an outbound buffer. `S2sLink`
//! bridges the two — it owns the per-peer CRDT state, a monotonic `now_ms` cell
//! the driver's clock reads, and a growable outbound buffer the sink appends to.
//!
//! Lifecycle (in-place, because the driver's clock holds a pointer to this
//! struct's `now_ms` field, which must stay at a stable address):
//!   var link: S2sLink = undefined;
//!   try link.init(allocator, opts);
//!   defer link.deinit();
//!   try link.start(now_ms);          // local side opens the handshake
//!   try link.feed(inbound, now, rng) // drive on each recv
//!   const out = link.outbound();     // send these bytes, then link.clearOutbound()
const std = @import("std");

const s2s_peer = @import("../substrate/undertow/s2s_peer.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");
const partition_detector = @import("../substrate/undertow/partition_detector.zig");
const s2s_frame = @import("../proto/s2s_frame.zig");
const sign = @import("../crypto/sign.zig");
const channel_mode_state_event = @import("../proto/channel_mode_state_event.zig");
const entity_prop_event = @import("../proto/entity_prop_event.zig");
const meshpass = @import("../proto/meshpass.zig");
const message_relay_v2 = @import("../substrate/undertow/message_relay_v2.zig");

/// Cross-node relay message types (re-exported at module scope for the daemon).
pub const RelayMessage = s2s_peer.RelayMessage;
pub const RelayVerb = s2s_peer.RelayVerb;
pub const RelayMessageV2 = s2s_peer.RelayMessageV2;
pub const RelayVerbV2 = s2s_peer.RelayVerbV2;
pub const InboundMessageV2 = s2s_peer.InboundMessageV2;
pub const SignedOperEventV2 = s2s_peer.SignedOperEventV2;
pub const InboundOperEventV2 = s2s_peer.InboundOperEventV2;
const channel_crdt = @import("../substrate/undertow/channel_crdt.zig");
const peer_link = @import("../substrate/undertow/peer_link.zig");

pub const NodeId = s2s_peer.NodeId;
pub const NickClaim = s2s_peer.NickClaim;
pub const ChannelCrdt = s2s_peer.ChannelCrdt;
pub const ChannelModeStateEvent = s2s_peer.ChannelModeStateEvent;
pub const PeerConfig = s2s_peer.Config;
pub const SessionReplicaKind = s2s_peer.SessionReplicaKind;
pub const InboundSessionReplica = s2s_peer.InboundSessionReplica;

/// Caller-supplied identity/config for one S2S link. The sovereign node_id is the
/// single mesh identity (no legacy server-id): it keys the registry and is the
/// CRDT replica lane.
pub const Options = struct {
    allocator: std.mem.Allocator,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    local_epoch_ms: u64,
    server_name: []const u8,
    description: []const u8 = "",
    channel_name: []const u8 = "#undertow",
    /// Undertow peer-driver limits/timers/capacities from daemon config.
    config: s2s_peer.Config = .{},
    now_ms: u64 = 0,
    /// Optional node Ed25519 signing keypair for end-to-end origin
    /// authentication of direct-owned state frames (secured links pass the node
    /// identity's key; plaintext links leave it null to keep the unsigned path).
    /// When set, `local_node_id` MUST equal
    /// `signed_frame.originShortId(key.public_key)` so receivers self-certify the
    /// origin — the secured link guarantees this by deriving both from the same
    /// identity.
    signing_key: ?sign.KeyPair = null,
    /// Signed MeshPass frame-family rights admitted for the remote peer. Zero
    /// preserves open/shared-secret behavior.
    admitted_frame_families: u32 = 0,
    /// Internal outer-transport assertion. Only `SecuredLink` sets this after a
    /// successful Mooring AKE; standalone/plaintext links must leave it false.
    session_replica_transport_enabled: bool = false,
    /// Independent Mooring transport assertion for secure relay v2.
    secure_relay_transport_enabled: bool = false,
    /// Independent Mooring transport assertion for Event Spine v2.
    event_spine_v2_transport_enabled: bool = false,
};

pub const S2sLink = struct {
    allocator: std.mem.Allocator,
    /// Monotonic clock cell read by the driver's `peer_link.Clock`. Stable
    /// address required: the clock captures `&self`.
    now_ms: u64,
    /// Per-peer convergent channel state (heap-owned; the driver borrows it).
    state: *ChannelCrdt,
    peer: s2s_peer.S2sPeer,
    /// Bytes the driver wants written to the wire, awaiting the send path.
    out: std.ArrayList(u8) = .empty,

    fn clockNow(ptr: *anyopaque) u64 {
        const self: *S2sLink = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn sinkWrite(ptr: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *S2sLink = @ptrCast(@alignCast(ptr));
        try self.out.appendSlice(self.allocator, bytes);
    }

    fn sink(self: *S2sLink) s2s_peer.ByteSink {
        return .{ .ptr = self, .write_fn = sinkWrite };
    }

    /// Reserve the exact inner-wire bytes for a transactional secured-link
    /// emission. Once this succeeds, the ByteSink append at the end of the pure
    /// peer encoder cannot fail after the peer has finished signing the frame.
    pub fn reserveOutboundCapacity(self: *S2sLink, additional: usize) !void {
        try self.out.ensureUnusedCapacity(self.allocator, additional);
    }

    /// Initialize in place. `self` must already live at its final address.
    pub fn init(self: *S2sLink, opts: Options) !void {
        self.* = .{
            .allocator = opts.allocator,
            .now_ms = opts.now_ms,
            .state = undefined,
            .peer = undefined,
            .out = .empty,
        };
        const state = try opts.allocator.create(ChannelCrdt);
        errdefer opts.allocator.destroy(state);
        // The CRDT replica lane is the sovereign node id (ReplicaId is u64).
        state.* = ChannelCrdt.init(opts.allocator, opts.local_node_id);
        errdefer state.deinit();
        self.state = state;

        self.peer = try s2s_peer.S2sPeer.init(.{
            .allocator = opts.allocator,
            .state = state,
            .clock = .{ .ptr = self, .now_fn = clockNow },
            .local_node_id = opts.local_node_id,
            .remote_node_id = opts.remote_node_id,
            .local_epoch_ms = opts.local_epoch_ms,
            .server_name = opts.server_name,
            .description = opts.description,
            .channel_name = opts.channel_name,
            .initial_send_credit = opts.config.link.peer_link_config.send_credit,
            .config = opts.config,
            .signing_key = opts.signing_key,
            .admitted_frame_families = opts.admitted_frame_families,
            .session_replica_transport_enabled = opts.session_replica_transport_enabled,
            .secure_relay_transport_enabled = opts.secure_relay_transport_enabled,
            .event_spine_v2_transport_enabled = opts.event_spine_v2_transport_enabled,
        });
    }

    pub fn deinit(self: *S2sLink) void {
        self.peer.deinit();
        self.state.deinit();
        self.allocator.destroy(self.state);
        self.out.deinit(self.allocator);
        self.* = undefined;
    }

    /// Open the handshake from the local side (the connecting peer calls this).
    pub fn start(self: *S2sLink, now_ms: u64) !void {
        self.now_ms = now_ms;
        try self.peer.startHandshake(self.sink());
    }

    /// Drive the link with inbound bytes; outbound frames accumulate in `out`.
    pub fn feed(self: *S2sLink, bytes: []const u8, now_ms: u64, rng_seed: u64) !void {
        self.now_ms = now_ms;
        try self.peer.feed(bytes, self.sink(), now_ms, rng_seed);
    }

    /// Emit a PING with `payload` (heartbeat / liveness probe).
    pub fn ping(self: *S2sLink, payload: []const u8, now_ms: u64) !void {
        self.now_ms = now_ms;
        try self.peer.sendPing(payload, self.sink());
    }

    /// Pending outbound bytes; copy to the wire, then call `clearOutbound`.
    pub fn outbound(self: *const S2sLink) []const u8 {
        return self.out.items;
    }

    /// Drop the first `n` outbound bytes (a partial send) or all of them.
    pub fn consumeOutbound(self: *S2sLink, n: usize) void {
        const take = @min(n, self.out.items.len);
        const rest = self.out.items.len - take;
        std.mem.copyForwards(u8, self.out.items[0..rest], self.out.items[take..]);
        self.out.shrinkRetainingCapacity(rest);
    }

    pub fn clearOutbound(self: *S2sLink) void {
        self.out.clearRetainingCapacity();
    }

    pub fn established(self: *const S2sLink) bool {
        return self.peer.linkState() == .established;
    }

    pub const ResumeHeader = s2s_peer.S2sPeer.ResumeHeader;

    /// Bounded identity/transport header to resume this link across a hot upgrade.
    /// The converged CRDT/route state is NOT captured here — the remote-member
    /// roster rides the capsule's separate v4 roster block (restored via
    /// `primeResumedMember`), and a RESYNC burst reconverges the rest (see
    /// `s2s_peer.resumeEstablished`).
    pub fn snapshotResume(self: *const S2sLink) ResumeHeader {
        return self.peer.snapshotResume();
    }

    /// The remote server name (for the resume capsule's variable-length field).
    pub fn snapshotRemoteName(self: *const S2sLink) []const u8 {
        return self.peer.remoteName();
    }

    /// Initialize in place directly in the established state from a resume header,
    /// bypassing the handshake. `self` must already live at its final address (the
    /// inner peer's clock captures `&self`). Stands up a FRESH empty CRDT replica;
    /// the caller primes the carried roster via `primeResumedMember` and then
    /// RESYNCs to reconverge (the primed rows make the re-burst dedup instead of
    /// re-announcing every member).
    pub fn resumeEstablished(self: *S2sLink, opts: Options, hdr: ResumeHeader, remote_name: []const u8, rng_seed: u64) !void {
        self.* = .{
            .allocator = opts.allocator,
            .now_ms = opts.now_ms,
            .state = undefined,
            .peer = undefined,
            .out = .empty,
        };
        const state = try opts.allocator.create(ChannelCrdt);
        errdefer opts.allocator.destroy(state);
        state.* = ChannelCrdt.init(opts.allocator, opts.local_node_id);
        errdefer state.deinit();
        self.state = state;

        self.peer = try s2s_peer.S2sPeer.resumeEstablished(.{
            .allocator = opts.allocator,
            .state = state,
            .clock = .{ .ptr = self, .now_fn = clockNow },
            .local_node_id = opts.local_node_id,
            .remote_node_id = hdr.remote_node_id,
            .local_epoch_ms = opts.local_epoch_ms,
            .server_name = opts.server_name,
            .description = opts.description,
            .channel_name = opts.channel_name,
            .initial_send_credit = opts.config.link.peer_link_config.send_credit,
            .config = opts.config,
            .signing_key = opts.signing_key,
            .admitted_frame_families = opts.admitted_frame_families,
            .session_replica_transport_enabled = opts.session_replica_transport_enabled,
            .secure_relay_transport_enabled = opts.secure_relay_transport_enabled,
            .event_spine_v2_transport_enabled = opts.event_spine_v2_transport_enabled,
        }, hdr, remote_name, opts.now_ms, rng_seed);
    }

    /// Ask the peer to re-send its full converged state (post-resume reconverge).
    pub fn sendResync(self: *S2sLink) !void {
        try self.peer.sendResync(self.sink());
    }

    /// Prime one converged remote channel member into this link's route table,
    /// restoring the pre-upgrade roster on a link stood up via
    /// `resumeEstablished` BEFORE any RESYNC/burst bytes are processed. This
    /// deliberately bypasses `recvMembership`'s collision/residence machinery:
    /// the record is the RECEIVER's own converged state (sealed by the Helix
    /// predecessor), not a new peer claim, so it is applied verbatim — original
    /// nick spelling (including loser-UID aliases), origin node, status bits,
    /// HLC, propagated identity, and the receiver-derived session token. With
    /// the roster primed, the peer's RESYNC re-burst of the same members dedups
    /// to `.unchanged` instead of queueing a spurious client-visible JOIN, and
    /// NAMES projects the member even before the re-burst lands. No delta is
    /// queued: restored state was already visible to local clients pre-swap.
    /// Every prime must land as a fresh `.joined` row (the resumed replica
    /// starts empty); anything else is a duplicate/conflicting roster record
    /// and fails closed so the caller can abort adoption transactionally.
    pub fn primeResumedMember(
        self: *S2sLink,
        channel: []const u8,
        nick: []const u8,
        node: NodeId,
        status: u4,
        hlc: u64,
        ident: MemberIdentity,
        now_ms: i64,
    ) !void {
        const res = try self.peer.routes.applyMembership(channel, nick, node, status, hlc, true, ident, now_ms);
        if (res.outcome != .joined) return error.RosterConflict;
    }

    /// Consume a pending peer RESYNC request (the daemon answers with a full burst).
    pub fn takeResyncRequest(self: *S2sLink) bool {
        return self.peer.takeResyncRequest();
    }

    /// Consume a repair-triggered daemon resync request. A valid repair response
    /// updated the peer driver's CRDT shadow; the daemon bridges it to live state
    /// through the existing full-burst protocol.
    pub fn takeRepairResyncRequest(self: *S2sLink) bool {
        return self.peer.takeRepairResyncRequest();
    }

    /// Install (or clear) the borrowed local-world nick predicate used for
    /// cross-namespace NICK collision resolution (a remote nick that matches a
    /// LOCAL one is renamed to its mesh UID rather than overwriting the holder).
    pub fn setLocalNickResolver(self: *S2sLink, resolver: ?LocalNickResolver) void {
        self.peer.routes.setLocalNickResolver(resolver);
    }

    /// Install (or clear) the daemon's residence-proof verifier (Design C / F1).
    pub fn setResidenceVerifier(self: *S2sLink, verifier: ?ResidenceVerifier) void {
        self.peer.setResidenceVerifier(verifier);
    }

    /// Install (or clear) the receiver-owned signed-session resolver.
    pub fn setSessionTokenResolver(self: *S2sLink, resolver: ?SessionTokenResolver) void {
        self.peer.setSessionTokenResolver(resolver);
    }

    pub fn setSessionTokenNickAuthorizer(self: *S2sLink, authorizer: ?SessionTokenNickAuthorizer) void {
        self.peer.setSessionTokenNickAuthorizer(authorizer);
    }

    pub fn rebindSessionToken(self: *S2sLink, origin_node: NodeId, nick: []const u8, token: ?SessionToken) !usize {
        return self.peer.rebindSessionToken(origin_node, nick, token);
    }

    pub fn reconcileSessionToken(
        self: *S2sLink,
        token: SessionToken,
        desired_nick: ?[]const u8,
        desired_channels: []const []const u8,
    ) !SessionTokenReconcileResult {
        return self.peer.reconcileSessionToken(token, desired_nick, desired_channels);
    }

    /// Which remote node currently owns `nick`, per the route table.
    pub fn routeNickNode(self: *const S2sLink, nick: []const u8) ?NodeId {
        return self.peer.routeNickNode(nick);
    }

    pub fn bestNickClaim(self: *const S2sLink, nick: []const u8) ?NickClaim {
        return self.peer.bestNickClaim(nick);
    }

    /// Find `nick` in this peer's converged remote channel rosters (ASCII
    /// case-insensitive). Borrowed; valid until the next membership mutation.
    pub fn findRemoteMember(self: *const S2sLink, nick: []const u8) ?s2s_peer.MemberInfo {
        return self.peer.findRemoteMember(nick);
    }

    /// Server name registered for `node` (handshake or gossiped registry).
    pub fn nodeName(self: *const S2sLink, node: NodeId) ?[]const u8 {
        return self.peer.nodeName(node);
    }

    /// Server description registered for `node`, or null when unknown/empty.
    pub fn nodeDescription(self: *const S2sLink, node: NodeId) ?[]const u8 {
        return self.peer.nodeDescription(node);
    }

    /// The remote server's name once the handshake has been processed (empty
    /// before establishment).
    pub fn remoteName(self: *const S2sLink) []const u8 {
        return self.peer.remoteName();
    }

    /// The remote peer's own gossiped server description, resolved in the
    /// route-table/registry id space (matching WHOIS 312), or null when unknown.
    pub fn remoteDescription(self: *const S2sLink) ?[]const u8 {
        return self.peer.remoteDescription();
    }

    /// The remote node id once learned from the handshake (null before).
    pub fn remoteNodeId(self: *const S2sLink) ?NodeId {
        return self.peer.remoteNodeId();
    }

    pub fn knownServers(self: *const S2sLink) usize {
        return self.peer.registryCount();
    }

    pub const MemberIdentity = s2s_peer.MemberIdentity;
    pub const LocalNickResolver = s2s_peer.LocalNickResolver;
    pub const ResidenceDecision = s2s_peer.ResidenceDecision;
    pub const ResidenceVerifier = s2s_peer.ResidenceVerifier;
    pub const SessionToken = s2s_peer.SessionToken;
    pub const SessionTokenDecision = s2s_peer.SessionTokenDecision;
    pub const SessionTokenResolver = s2s_peer.SessionTokenResolver;
    pub const SessionTokenNickDecision = s2s_peer.SessionTokenNickDecision;
    pub const SessionTokenNickAuthorizer = s2s_peer.SessionTokenNickAuthorizer;
    pub const SessionTokenReconcileResult = s2s_peer.SessionTokenReconcileResult;

    /// Announce a local member's presence/departure in `channel` to the peer,
    /// carrying the member's real username/realname/visible-host identity.
    /// Outbound frames accumulate in `out`. Best-effort: only meaningful once the
    /// link is established.
    pub fn sendMembership(
        self: *S2sLink,
        channel: []const u8,
        nick: []const u8,
        status: u4,
        hlc: u64,
        present: bool,
        ident: MemberIdentity,
        setter: []const u8,
    ) !void {
        try self.peer.sendMembership(self.sink(), channel, nick, status, hlc, present, ident, setter);
    }

    /// Announce a local IRCX channel PROP set/delete (or re-broadcast a remote
    /// one) to the peer. Outbound frames accumulate in `out`. `origin` selects
    /// local-authored vs re-broadcast attribution and carries the self-contained
    /// multi-hop origin signature (see `S2sPeer.PropOrigin`).
    pub fn sendChannelProp(
        self: *S2sLink,
        channel: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
        origin: s2s_peer.S2sPeer.PropOrigin,
    ) !void {
        try self.peer.sendChannelProp(self.sink(), channel, key, value, owner, hlc, present, origin);
    }

    /// Announce a local IRCX user/member PROP set/delete (or re-broadcast a remote
    /// one) to the peer over ENTITY_PROP. Outbound frames accumulate in `out`.
    /// `origin` selects local-authored vs re-broadcast attribution and carries the
    /// self-contained multi-hop origin signature (see `S2sPeer.PropOrigin`).
    pub fn sendEntityProp(
        self: *S2sLink,
        kind: entity_prop_event.EntityKind,
        entity: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
        origin: s2s_peer.S2sPeer.PropOrigin,
    ) !void {
        try self.peer.sendEntityProp(self.sink(), kind, entity, key, value, owner, hlc, present, origin);
    }

    /// Announce a local channel topic change to the peer.
    pub fn sendTopic(
        self: *S2sLink,
        channel: []const u8,
        topic: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) !void {
        try self.peer.sendTopic(self.sink(), channel, topic, setter, set_at, hlc, present);
    }

    /// Announce a local user's nick change to the peer.
    pub fn sendNickChange(
        self: *S2sLink,
        old_nick: []const u8,
        new_nick: []const u8,
        ident: s2s_peer.MemberIdentity,
        hlc: u64,
    ) !void {
        try self.peer.sendNickChange(self.sink(), old_nick, new_nick, ident, hlc);
    }

    /// Drain remote channel topic changes the daemon should apply + emit.
    pub fn takeTopicChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.TopicDelta {
        return self.peer.takeTopicChanges();
    }

    /// Drain remote user nick changes the daemon should surface as NICK lines.
    pub fn takeNickChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.NickDelta {
        return self.peer.takeNickChanges();
    }

    /// Transfer the next MEMBERSHIP/NICK delta in peer application order.
    pub fn takeNextIdentityTransition(self: *S2sLink) ?s2s_peer.S2sPeer.IdentityTransition {
        return self.peer.takeNextIdentityTransition();
    }

    /// Peek a leading membership delta so the daemon can retain NETJOIN batching
    /// without crossing an intervening NICK transition.
    pub fn peekNextMembershipTransition(self: *const S2sLink) ?*const s2s_peer.S2sPeer.MembershipDelta {
        return self.peer.peekNextMembershipTransition();
    }

    /// Remote members the peer has announced for `channel` (borrowed roster).
    pub fn channelMembers(self: *const S2sLink, channel: []const u8) []const s2s_peer.MemberInfo {
        return self.peer.channelMembers(channel);
    }

    /// Aggregate mesh-replicated channel MODE flags for `channel` (null if the
    /// peer has never gossiped an aggregate for it). Bit layout matches the
    /// daemon's `channel_mode_flag_specs`.
    pub fn channelModeFlags(self: *const S2sLink, channel: []const u8) ?s2s_peer.ChannelModeFlags {
        return self.peer.channelModeFlags(channel);
    }

    /// Iterator over channel names with a live remote roster on this peer (used
    /// by LIST/LISTX for mesh-wide channel enumeration).
    pub fn channelNames(self: *const S2sLink) s2s_peer.ChannelNameIterator {
        return self.peer.channelNames();
    }

    /// Distinct remote nicks announced across this link (mesh user-count input).
    pub fn remoteNickCount(self: *const S2sLink) usize {
        return self.peer.remoteNickCount();
    }

    pub const RelayMessage = s2s_peer.RelayMessage;
    pub const RelayVerb = s2s_peer.RelayVerb;
    pub const RelayMessageV2 = s2s_peer.RelayMessageV2;
    pub const RelayVerbV2 = s2s_peer.RelayVerbV2;

    /// Forward a cross-node user message (PRIVMSG/NOTICE/TAGMSG) to the peer.
    pub fn sendMessage(self: *S2sLink, msg: s2s_peer.RelayMessage) !void {
        try self.peer.sendMessage(self.sink(), msg);
    }

    /// Drain inbound cross-node messages decoded from this peer. Caller owns the
    /// returned slice + each Owned (deinit each, free the slice).
    pub fn takeInbound(self: *S2sLink) ![]s2s_peer.InboundMessage {
        return self.peer.takeInbound();
    }

    pub fn supportsSecureRelayV2(self: *const S2sLink) bool {
        return self.peer.supportsSecureRelayV2();
    }

    pub fn supportsRelayV2AckConfirm(self: *const S2sLink) bool {
        return self.peer.supportsRelayV2AckConfirm();
    }

    pub fn sendMessageV2(self: *S2sLink, msg: s2s_peer.RelayMessageV2) !void {
        try self.peer.sendMessageV2(self.sink(), msg);
    }

    pub fn forwardMessageV2(self: *S2sLink, wire: []const u8) !bool {
        return self.peer.forwardMessageV2(self.sink(), wire);
    }

    pub fn replayRetainedMessageV2Wire(self: *S2sLink, wire: []const u8) !void {
        try self.peer.replayRetainedMessageV2Wire(self.sink(), wire);
    }

    pub fn takeInboundV2(self: *S2sLink) ![]s2s_peer.InboundMessageV2 {
        return self.peer.takeInboundV2();
    }

    pub fn sendMessageV2Ack(self: *S2sLink, id: message_relay_v2.RelayId) !void {
        try self.peer.sendMessageV2Ack(self.sink(), id);
    }

    pub fn sendMessageV2AckConfirm(self: *S2sLink, id: message_relay_v2.RelayId) !void {
        try self.peer.sendMessageV2AckConfirm(self.sink(), id);
    }

    pub fn probeRelayV2Current(self: *S2sLink) !void {
        try self.peer.probeRelayV2Current(self.sink());
    }

    pub fn takeInboundV2Acks(self: *S2sLink) ![]message_relay_v2.RelayId {
        return self.peer.takeInboundV2Acks();
    }

    pub fn takeInboundV2AckConfirms(self: *S2sLink) ![]message_relay_v2.RelayId {
        return self.peer.takeInboundV2AckConfirms();
    }

    pub fn takeDroppedRelayV2Frames(self: *S2sLink) u64 {
        return self.peer.takeDroppedRelayV2Frames();
    }

    pub fn takeRejectedRelayV2Frames(self: *S2sLink) u64 {
        return self.peer.takeRejectedRelayV2Frames();
    }

    /// Drain remote channel membership changes (JOIN/PART) the daemon should
    /// surface to local members. Caller owns the slice + each delta's strings.
    pub fn takeMembershipChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.MembershipDelta {
        return self.peer.takeMembershipChanges();
    }

    pub fn processDeferredResidenceFrames(self: *S2sLink, now_ms: u64) void {
        self.peer.processDeferredResidenceFrames(now_ms);
    }

    pub fn discardDeferredResidenceFrames(self: *S2sLink) void {
        self.peer.discardDeferredResidenceFrames();
    }

    /// Announce aggregate local boolean MODE flags for `channel` to the peer.
    /// Outbound frames accumulate in `out`.
    pub fn sendChannelModeFlags(self: *S2sLink, channel: []const u8, flags: u16, hlc: u64) !void {
        try self.peer.sendChannelModeFlags(self.sink(), channel, flags, hlc);
    }

    /// Announce a full local parameter/IRCX channel-state snapshot to the peer.
    /// Outbound frames accumulate in `out`.
    pub fn sendChannelModeState(self: *S2sLink, ev: ChannelModeStateEvent) !void {
        try self.peer.sendChannelModeState(self.sink(), ev);
    }

    /// Drain remote channel MODE flag changes the daemon should apply and
    /// surface to local members.
    pub fn takeChannelModeFlagChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.ChannelModeFlagsDelta {
        return self.peer.takeChannelModeFlagChanges();
    }

    /// Drain remote parameter/IRCX channel-state snapshots the daemon should
    /// apply and surface to local members.
    pub fn takeChannelModeStateChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.ChannelModeStateDelta {
        return self.peer.takeChannelModeStateChanges();
    }

    /// Drain remote direct-owned frames rejected for origin/peer mismatch.
    pub fn takeRejectedOriginFrames(self: *S2sLink) u64 {
        return self.peer.takeRejectedOriginFrames();
    }

    /// Announce a local channel list-mode (+b/+e/+I) change to the peer.
    pub fn sendChannelList(
        self: *S2sLink,
        channel: []const u8,
        kind: s2s_peer.S2sPeer.ChannelListDelta.Kind,
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) !void {
        try self.peer.sendChannelList(self.sink(), channel, kind, mask, setter, set_at, hlc, present);
    }

    /// Drain remote channel list-mode changes (+b/+e/+I) the daemon should apply
    /// to local world state and surface as MODE lines.
    pub fn takeChannelListChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.ChannelListDelta {
        return self.peer.takeChannelListChanges();
    }

    /// Drain remote channel PROP changes for daemon-side LWW apply. Caller owns
    /// the slice + each delta's strings.
    pub fn takeChannelPropChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.ChannelPropDelta {
        return self.peer.takeChannelPropChanges();
    }

    /// Drain remote user/member PROP changes (ENTITY_PROP) for daemon-side LWW
    /// apply. Caller owns the slice + each delta's strings.
    pub fn takeEntityPropChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.EntityPropDelta {
        return self.peer.takeEntityPropChanges();
    }

    /// Forward a signed cross-mesh operator grant to the peer (best-effort; only
    /// meaningful once established). `signed` is opaque `oper_cred_share` bytes.
    pub fn sendOperGrant(self: *S2sLink, signed: []const u8) !void {
        try self.peer.sendOperGrant(self.sink(), signed);
    }

    /// Drain queued inbound oper-grant payloads decoded from this peer. Caller
    /// owns + frees each slice and the outer slice.
    pub fn takeOperGrants(self: *S2sLink) ![][]u8 {
        return self.peer.takeOperGrants();
    }

    /// Ship a live-session migration capsule (`migration_relay` frame bytes) to
    /// the peer (best-effort; only meaningful once established).
    pub fn sendSessionMigrate(self: *S2sLink, frame_bytes: []const u8) !void {
        try self.peer.sendSessionMigrate(self.sink(), frame_bytes);
    }

    /// Drain queued inbound session-migration capsules decoded from this peer.
    /// Caller owns + frees each raw frame-bytes slice and the outer slice; each
    /// is handed to `MigrationTarget.accept` for verification.
    pub fn takeSessionMigrations(self: *S2sLink) ![][]u8 {
        return self.peer.takeSessionMigrations();
    }

    pub fn sendSessionMigrateConsumed(self: *S2sLink, payload: []const u8) !void {
        try self.peer.sendSessionMigrateConsumed(self.sink(), payload);
    }

    pub fn takeSessionMigrateConsumed(self: *S2sLink) ![][]u8 {
        return self.peer.takeSessionMigrateConsumed();
    }

    /// SESSION_REPLICA v2 is active only after secured signing + explicit remote
    /// capability negotiation. Plaintext and rolling-old links return false.
    pub fn supportsSessionReplicaV2(self: *const S2sLink) bool {
        return self.peer.supportsSessionReplicaV2();
    }

    pub fn supportsSessionAttachmentLeaseV2(self: *const S2sLink) bool {
        return self.peer.supportsSessionAttachmentLeaseV2();
    }

    pub fn sendSessionReplica(self: *S2sLink, kind: SessionReplicaKind, signed_payload: []const u8) !void {
        try self.peer.sendSessionReplica(self.sink(), kind, signed_payload);
    }

    pub fn sendSessionReplicaOffer(self: *S2sLink, signed_offer: []const u8) !void {
        try self.peer.sendSessionReplicaOffer(self.sink(), signed_offer);
    }

    pub fn sendSessionReplicaAck(self: *S2sLink, signed_ack: []const u8) !void {
        try self.peer.sendSessionReplicaAck(self.sink(), signed_ack);
    }

    pub fn sendSessionReplicaRevoke(self: *S2sLink, signed_revoke: []const u8) !void {
        try self.peer.sendSessionReplicaRevoke(self.sink(), signed_revoke);
    }

    pub fn sendSessionAttachmentLease(self: *S2sLink, signed_lease: []const u8) !void {
        try self.peer.sendSessionAttachmentLease(self.sink(), signed_lease);
    }

    /// Caller owns the slice and must deinit every item. Each item includes the
    /// authenticated immediate hop as `via_peer` for future multipath storage.
    pub fn takeSessionReplicaFrames(self: *S2sLink) ![]InboundSessionReplica {
        return self.peer.takeSessionReplicaFrames();
    }

    pub fn takeNextSessionReplicaFrame(self: *S2sLink) ?InboundSessionReplica {
        return self.peer.takeNextSessionReplicaFrame();
    }

    pub fn takeDroppedSessionReplicaFrames(self: *S2sLink) u64 {
        return self.peer.takeDroppedSessionReplicaFrames();
    }

    /// Emit a CLONE_COUNT batch (`mesh_clones` counts bytes) to this peer.
    pub fn sendCloneCounts(self: *S2sLink, payload: []const u8) !void {
        try self.peer.sendCloneCounts(self.sink(), payload);
    }

    /// Drain queued inbound CLONE_COUNT payloads from this peer (caller owns +
    /// frees each slice and the outer slice).
    pub fn takeCloneCounts(self: *S2sLink) ![][]u8 {
        return self.peer.takeCloneCounts();
    }

    /// Emit a signed OPER_EVENT to this peer (network-wide Event-Spine fan-out).
    pub fn sendOperEvent(self: *S2sLink, category: u6, severity: u8, origin_server: []const u8, message: []const u8) !void {
        try self.peer.sendOperEvent(self.sink(), category, severity, origin_server, message);
    }

    pub fn sendLegacyOperEvent(self: *S2sLink, category: u6, severity: u8, origin_server: []const u8, message: []const u8) !void {
        try self.peer.sendLegacyOperEvent(self.sink(), category, severity, origin_server, message);
    }

    /// Drain queued inbound OPER_EVENT payloads from this peer (caller owns +
    /// frees each slice and the outer slice; decode with `oper_event.decode`).
    pub fn takeOperEvents(self: *S2sLink) ![][]u8 {
        return self.peer.takeOperEvents();
    }

    pub fn supportsEventSpineV2(self: *const S2sLink) bool {
        return self.peer.supportsEventSpineV2();
    }

    pub fn sendOperEventV2Authored(self: *S2sLink, category: u6, severity: u8, hlc: u64, origin_server: []const u8, subject: []const u8, message: []const u8) !bool {
        return self.peer.sendOperEventV2Authored(self.sink(), category, severity, hlc, origin_server, subject, message);
    }

    pub fn sendOperEventV2(self: *S2sLink, event: SignedOperEventV2) !bool {
        return self.peer.sendOperEventV2(self.sink(), event);
    }

    pub fn forwardOperEventV2(self: *S2sLink, wire: []const u8) !bool {
        return self.peer.forwardOperEventV2(self.sink(), wire);
    }

    pub fn takeOperEventsV2(self: *S2sLink) ![]InboundOperEventV2 {
        return self.peer.takeOperEventsV2();
    }

    pub fn takeDroppedOperEventV2Frames(self: *S2sLink) u64 {
        return self.peer.takeDroppedOperEventV2Frames();
    }

    pub fn takeRejectedOperEventV2Frames(self: *S2sLink) u64 {
        return self.peer.takeRejectedOperEventV2Frames();
    }

    /// Emit a signed OBSERVE_EVENT to this peer (network-wide OBSERVE fan-out).
    pub fn sendObserveEvent(self: *S2sLink, action: u8, origin_server: []const u8, nick: []const u8, user: []const u8, host: []const u8, account: ?[]const u8, detail: []const u8) !void {
        try self.peer.sendObserveEvent(self.sink(), action, origin_server, nick, user, host, account, detail);
    }

    /// Drain queued inbound OBSERVE_EVENT payloads from this peer (caller owns +
    /// frees each slice and the outer slice; decode with `observe_event.decode`).
    pub fn takeObserveEvents(self: *S2sLink) ![][]u8 {
        return self.peer.takeObserveEvents();
    }

    /// Emit a signed targeted KILL to this peer (cross-mesh operator KILL).
    pub fn sendKill(self: *S2sLink, origin_server: []const u8, killer: []const u8, target: []const u8, reason: []const u8) !void {
        try self.peer.sendKill(self.sink(), origin_server, killer, target, reason);
    }

    /// Drain queued inbound KILL payloads from this peer (caller owns + frees each
    /// slice and the outer slice; decode with `kill_relay.decode`).
    pub fn takeKills(self: *S2sLink) ![][]u8 {
        return self.peer.takeKills();
    }

    /// Emit a signed WARD to this peer (network-wide mesh-scope ban convergence).
    /// `wire` is a `warden.encodeWire` record (add or remove).
    pub fn sendWard(self: *S2sLink, wire: []const u8) !void {
        try self.peer.sendWard(self.sink(), wire);
    }

    /// Drain queued inbound WARD payloads from this peer (caller owns + frees each
    /// slice and the outer slice; decode with `warden.decodeWire`).
    pub fn takeWards(self: *S2sLink) ![][]u8 {
        return self.peer.takeWards();
    }

    /// Emit a signed, signing-required Web Push hint for an offline memo/DM.
    /// The peer driver no-ops for non-signing peers so this never rides legacy
    /// plaintext S2S.
    pub fn sendMemoPush(self: *S2sLink, account: []const u8, from: []const u8, text: []const u8) !void {
        try self.peer.sendMemoPush(self.sink(), account, from, text);
    }

    /// Drain queued MEMO_PUSH payloads from this peer (caller owns + frees each
    /// slice and the outer slice; decode with `memo_push_relay.decode`).
    pub fn takeMemoPushes(self: *S2sLink) ![][]u8 {
        return self.peer.takeMemoPushes();
    }

    /// Emit a signed origin-only MEDIA_WS_DATAGRAM cascade for an already-
    /// validated browser Cadence WS media datagram. Peer driver no-ops for
    /// non-signing peers.
    pub fn sendMediaWsDatagram(self: *S2sLink, channel: []const u8, datagram: []const u8) !void {
        try self.peer.sendMediaWsDatagram(self.sink(), channel, datagram);
    }

    /// Drain queued MEDIA_WS_DATAGRAM payloads from this peer (caller owns +
    /// frees each slice and the outer slice; decode with `media_ws_relay.decode`).
    pub fn takeMediaWsDatagrams(self: *S2sLink) ![][]u8 {
        return self.peer.takeMediaWsDatagrams();
    }

    /// Copy this peer's known-server topology into `out` for partition analysis.
    pub fn collectTopology(self: *const S2sLink, out: []partition_detector.TopoNode) usize {
        return self.peer.collectTopology(out);
    }
};

/// These link-mechanics tests stand up KEYLESS (plaintext) links with no node
/// signing key threaded. `require_signed_frames` defaults ON, and a keyless node
/// now fails CLOSED on unsigned in-scope direct-owned frames (dropping + counting
/// them) rather than raw-passing them. Since these tests exercise frame
/// PROPAGATION mechanics — not the signing policy — they model an
/// explicitly-permitted unsigned deployment, exactly as a plaintext operator
/// would (`require_signed_frames = false`). The policy itself is proven by the
/// dedicated s2s_peer keyless fail-closed / fail-open tests.
const plaintext_link_config: PeerConfig = .{ .require_signed_frames = false };

test "two links handshake and converge over a byte loopback" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{
        .allocator = allocator,
        .local_node_id = 1,
        .remote_node_id = 2,
        .local_epoch_ms = 1000,
        .server_name = "a.onyx",
    });
    defer a.deinit();

    var b: S2sLink = undefined;
    try b.init(.{
        .allocator = allocator,
        .local_node_id = 2,
        .remote_node_id = 1,
        .local_epoch_ms = 1001,
        .server_name = "b.onyx",
    });
    defer b.deinit();

    // A opens the handshake; pump bytes back and forth until both quiesce.
    try a.start(10);
    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;

        // Snapshot each side's output, clear, then feed to the other.
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();

        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    try std.testing.expect(a.established());
    try std.testing.expect(b.established());
    // Each side learned the other server through the registry burst.
    try std.testing.expect(a.knownServers() >= 2);
    try std.testing.expect(b.knownServers() >= 2);
}

test "MEMBERSHIP propagates a member across the link into channelMembers" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    // Establish, then A announces alice (op) on #chat with her real identity;
    // pump to B.
    try a.start(10);
    var now: u64 = 11;
    try a.sendMembership("#chat", "alice", 0b0010, 100, true, .{
        .username = "alice",
        .realname = "Alice Liddell",
        .host = "cloak-1a2b.users.onyx",
    }, ""); // op bit
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    // B now sees alice on #chat as a remote member homed on node 1, with op
    // status AND her propagated real identity (no mesh@server placeholder).
    const members = b.channelMembers("#chat");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("alice", members[0].nick);
    try std.testing.expectEqual(@as(u64, 1), members[0].node);
    try std.testing.expectEqual(@as(u4, 0b0010), members[0].status);
    try std.testing.expectEqualStrings("alice", members[0].username);
    try std.testing.expectEqualStrings("Alice Liddell", members[0].realname);
    try std.testing.expectEqualStrings("cloak-1a2b.users.onyx", members[0].host);

    // The daemon-facing wrappers retain the receiver-only token contract; the
    // compatibility frame itself arrived unbound, then signed authority tags it.
    b.setSessionTokenResolver(null);
    const token: S2sLink.SessionToken = @splat(0xA4);
    try std.testing.expectEqual(@as(usize, 1), try b.rebindSessionToken(1, "alice", token));
    try std.testing.expect(std.crypto.timing_safe.eql(S2sLink.SessionToken, token, b.channelMembers("#chat")[0].session_token.?));
    const desired = [_][]const u8{"#chat"};
    const reconciled = try b.reconcileSessionToken(token, "alice", &desired);
    try std.testing.expectEqual(@as(usize, 0), reconciled.removed);
    try std.testing.expectEqual(@as(usize, 0), reconciled.renamed);

    // The queued live-IRC delta carries the identity too (for the JOIN line).
    const deltas = try b.takeMembershipChanges();
    defer {
        for (deltas) |*d| d.deinit(allocator);
        allocator.free(deltas);
    }
    try std.testing.expectEqual(@as(usize, 1), deltas.len);
    try std.testing.expectEqualStrings("alice", deltas[0].username);
    try std.testing.expectEqualStrings("cloak-1a2b.users.onyx", deltas[0].host);

    // A part removes her on B too.
    try a.sendMembership("#chat", "alice", 0, 101, false, .{}, "");
    rounds = 0;
    while (rounds < 16) : (rounds += 1) {
        const a_out = a.outbound();
        if (a_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        a.clearOutbound();
        try b.feed(a_copy, now, 7);
        now += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#chat").len);
}

test "CLONE_COUNT batch propagates across the link and decodes intact" {
    const allocator = std.testing.allocator;
    const mesh_clones = @import("mesh_clones.zig");

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    try a.start(10);
    // A ships a counts batch; pump both directions to deliver it to B.
    var wire: [64]u8 = undefined;
    const entries = [_]mesh_clones.Entry{ .{ .hash = 0xAABBCCDD11223344, .count = 4 }, .{ .hash = 7, .count = 1 } };
    const payload = try mesh_clones.encodeCounts(&wire, &entries);
    try a.sendCloneCounts(payload);

    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const got = try b.takeCloneCounts();
    defer {
        for (got) |p| allocator.free(p);
        allocator.free(got);
    }
    try std.testing.expectEqual(@as(usize, 1), got.len);
    const view = try mesh_clones.decodeCounts(got[0]);
    try std.testing.expectEqual(@as(u32, 2), view.n);
    try std.testing.expectEqual(@as(u64, 0xAABBCCDD11223344), view.get(0).hash);
    try std.testing.expectEqual(@as(u32, 4), view.get(0).count);
    try std.testing.expectEqual(@as(u64, 7), view.get(1).hash);
    try std.testing.expectEqual(@as(u32, 1), view.get(1).count);
}

test "CHANNEL_MODE_FLAGS propagates aggregate flag state across the link" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    try a.start(10);
    var now: u64 = 11;
    try a.sendChannelModeFlags("#chat", 0b1011, 100);
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeChannelModeFlagChanges();
    defer {
        for (changes) |*ch| ch.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("#chat", changes[0].channel);
    try std.testing.expectEqual(@as(u16, 0b1011), changes[0].flags);

    try a.sendChannelModeFlags("#chat", 0b0101, 99); // stale
    rounds = 0;
    while (rounds < 16) : (rounds += 1) {
        const a_out = a.outbound();
        if (a_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        a.clearOutbound();
        try b.feed(a_copy, now, 7);
        now += 1;
    }
    const stale = try b.takeChannelModeFlagChanges();
    defer allocator.free(stale);
    try std.testing.expectEqual(@as(usize, 0), stale.len);
}

test "CHANNEL_PROP payload round-trips across the link into takeChannelPropChanges" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    try a.start(10);
    try a.sendChannelProp("#chat", "TOPIC", "hello mesh", "alice", 100, true, .{});
    try a.sendChannelProp("#chat", "SUBJECT", "", "alice", 101, false, .{});

    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeChannelPropChanges();
    defer {
        for (changes) |*ch| ch.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 2), changes.len);
    try std.testing.expect(changes[0].present);
    try std.testing.expectEqual(@as(u64, 100), changes[0].hlc);
    try std.testing.expectEqualStrings("#chat", changes[0].channel);
    try std.testing.expectEqualStrings("TOPIC", changes[0].key);
    try std.testing.expectEqualStrings("hello mesh", changes[0].value);
    try std.testing.expectEqualStrings("alice", changes[0].owner);
    try std.testing.expect(!changes[1].present);
    try std.testing.expectEqualStrings("SUBJECT", changes[1].key);
}

test "ENTITY_PROP payload round-trips across the link into takeEntityPropChanges" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    try a.start(10);
    try a.sendEntityProp(.user, "alice", "STATUS", "away mesh", "alice", 100, true, .{});
    try a.sendEntityProp(.member, "#chat:bob", "ROLE", "", "founder", 101, false, .{});

    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeEntityPropChanges();
    defer {
        for (changes) |*ch| ch.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 2), changes.len);
    try std.testing.expectEqual(entity_prop_event.EntityKind.user, changes[0].kind);
    try std.testing.expect(changes[0].present);
    try std.testing.expectEqual(@as(u64, 100), changes[0].hlc);
    try std.testing.expectEqualStrings("alice", changes[0].entity);
    try std.testing.expectEqualStrings("STATUS", changes[0].key);
    try std.testing.expectEqualStrings("away mesh", changes[0].value);
    try std.testing.expectEqualStrings("alice", changes[0].owner);
    try std.testing.expectEqual(entity_prop_event.EntityKind.member, changes[1].kind);
    try std.testing.expect(!changes[1].present);
    try std.testing.expectEqualStrings("#chat:bob", changes[1].entity);
    try std.testing.expectEqualStrings("ROLE", changes[1].key);
}

test "CHANNEL_MODE_STATE propagates parameter and IRCX state across the link" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    try a.start(10);
    try a.sendChannelModeState(.{
        .origin_node = 0,
        .hlc = 100,
        .channel = "#chat",
        .private = true,
        .hidden = true,
        .ext_bits = 1 << 9, // noformat
        .key = "sekret",
        .limit = 50,
        .throttle_joins = 3,
        .throttle_secs = 20,
        .forward = "#overflow",
    });

    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeChannelModeStateChanges();
    defer {
        for (changes) |*ch| ch.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("#chat", changes[0].channel);
    try std.testing.expect(changes[0].private);
    try std.testing.expect(changes[0].hidden);
    try std.testing.expectEqual(@as(u32, 1 << 9), changes[0].ext_bits);
    try std.testing.expectEqualStrings("sekret", changes[0].key.?);
    try std.testing.expectEqual(@as(?u32, 50), changes[0].limit);
    try std.testing.expectEqual(@as(u16, 3), changes[0].throttle_joins);
    try std.testing.expectEqual(@as(u32, 20), changes[0].throttle_secs);
    try std.testing.expectEqualStrings("#overflow", changes[0].forward.?);

    const forged_ev = channel_mode_state_event.ChannelModeStateEvent{
        .origin_node = 99,
        .hlc = 101,
        .channel = "#chat",
        .key = "forged",
    };
    var payload_buf: [256]u8 = undefined;
    const payload = try channel_mode_state_event.encode(forged_ev, &payload_buf);
    var frame_buf: [512]u8 = undefined;
    const frame = try s2s_frame.encode(.CHANNEL_MODE_STATE, payload, frame_buf[0..try s2s_frame.encodedLen(payload.len)]);
    try b.feed(frame, now, 7);
    const forged = try b.takeChannelModeStateChanges();
    defer allocator.free(forged);
    try std.testing.expectEqual(@as(usize, 0), forged.len);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
}

test "TOPIC payload round-trips across the link into takeTopicChanges" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    try a.start(10);
    try a.sendTopic("#chat", "welcome to the mesh", "alice!u@h", 1700, 100, true);

    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeTopicChanges();
    defer {
        for (changes) |*ch| ch.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expect(changes[0].present);
    try std.testing.expectEqualStrings("#chat", changes[0].channel);
    try std.testing.expectEqualStrings("welcome to the mesh", changes[0].topic);
    try std.testing.expectEqualStrings("alice!u@h", changes[0].setter);
    try std.testing.expectEqual(@as(i64, 1700), changes[0].set_at);

    // A staler topic (lower hlc) is dropped by the route-table LWW.
    try a.sendTopic("#chat", "old", "bob", 1600, 50, true);
    rounds = 0;
    while (rounds < 16) : (rounds += 1) {
        const a_out = a.outbound();
        if (a_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        a.clearOutbound();
        try b.feed(a_copy, now, 7);
        now += 1;
    }
    const stale = try b.takeTopicChanges();
    defer allocator.free(stale);
    try std.testing.expectEqual(@as(usize, 0), stale.len);
}

test "NICKCHANGE renames a remote member and yields a delta" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    try a.start(10);
    // Announce the member first so b's roster knows it, then rename.
    try a.sendMembership("#chat", "Guest1", 0, 100, true, .{ .username = "guest", .realname = "G", .host = "old.host" }, "");
    try a.sendNickChange("Guest1", "kain", .{ .username = "kain", .realname = "Devin", .host = "cloak.host" }, 200);

    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeNickChanges();
    defer {
        for (changes) |*d| d.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("Guest1", changes[0].old_nick);
    try std.testing.expectEqualStrings("kain", changes[0].new_nick);
    try std.testing.expectEqualStrings("kain", changes[0].username);
    try std.testing.expectEqualStrings("cloak.host", changes[0].host);

    // The roster now resolves the new nick and no longer the old one.
    try std.testing.expect(b.findRemoteMember("kain") != null);
    try std.testing.expect(b.findRemoteMember("Guest1") == null);
}

const LocalNickStub = struct {
    held: []const u8,
    fn isHeld(ctx: *anyopaque, nick: []const u8) bool {
        const self: *LocalNickStub = @ptrCast(@alignCast(ctx));
        return std.ascii.eqlIgnoreCase(self.held, nick);
    }
    fn resolver(self: *LocalNickStub) S2sLink.LocalNickResolver {
        return .{ .ctx = self, .held_fn = isHeld };
    }
};

fn pumpLinks(a: *S2sLink, b: *S2sLink, allocator: std.mem.Allocator, start_now: u64) !void {
    var now = start_now;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }
}

test "session replica v2 signed plaintext S2sLink remains disabled" {
    const allocator = std.testing.allocator;
    const kp_a = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0xa1)));
    const kp_b = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0xa2)));
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a: S2sLink = undefined;
    try a.init(.{
        .allocator = allocator,
        .local_node_id = a_short,
        .remote_node_id = b_short,
        .local_epoch_ms = 1000,
        .server_name = "a.onyx",
        .signing_key = kp_a,
    });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{
        .allocator = allocator,
        .local_node_id = b_short,
        .remote_node_id = a_short,
        .local_epoch_ms = 1001,
        .server_name = "b.onyx",
        .signing_key = kp_b,
    });
    defer b.deinit();

    try a.start(10);
    try pumpLinks(&a, &b, allocator, 11);
    try std.testing.expect(a.peer.peer_supports_signing);
    try std.testing.expect(b.peer.peer_supports_signing);
    try std.testing.expect(!a.supportsSessionReplicaV2());
    try std.testing.expect(!b.supportsSessionReplicaV2());

    var ack: [189]u8 = @splat(0);
    @memcpy(ack[0..4], "SRA2");
    ack[4] = 1;
    try std.testing.expectError(error.SecuredLinkRequired, a.sendSessionReplicaAck(&ack));
    try std.testing.expectEqual(@as(usize, 0), a.outbound().len);
}

test "a remote nick colliding with a LOCAL nick is renamed to its UID, not overwritten" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    // b's local world already holds "kain". An incoming remote "kain" from a
    // must lose (local is authoritative) and be stored under its mesh UID.
    var stub = LocalNickStub{ .held = "kain" };
    b.setLocalNickResolver(stub.resolver());

    try a.start(10);
    try a.sendMembership("#chat", "kain", 0, 100, true, .{ .username = "k", .realname = "K", .host = "a.host" }, "");
    try pumpLinks(&a, &b, allocator, 11);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*d| d.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqual(@as(usize, 16), changes[0].nick.len); // forced UID
    try std.testing.expect(!std.ascii.eqlIgnoreCase(changes[0].nick, "kain"));

    // The route table never stored the contested nick verbatim; it resolves the
    // UID instead, so a local "kain" and the remote member never both answer.
    try std.testing.expect(b.findRemoteMember("kain") == null);
    try std.testing.expect(b.findRemoteMember(changes[0].nick) != null);
}

test "a remote RENAME into a locally-held nick redirects the renamer to its UID" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    // b's local world holds "kain". A remote user announces under Guest1, then
    // tries to rename to "kain": the renamer loses and lands on its mesh UID.
    var stub = LocalNickStub{ .held = "kain" };
    b.setLocalNickResolver(stub.resolver());

    try a.start(10);
    try a.sendMembership("#chat", "Guest1", 0, 100, true, .{ .username = "g", .realname = "G", .host = "a.host" }, "");
    try a.sendNickChange("Guest1", "kain", .{ .username = "g", .realname = "G", .host = "a.host" }, 200);
    try pumpLinks(&a, &b, allocator, 11);

    const changes = try b.takeNickChanges();
    defer {
        for (changes) |*d| d.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("Guest1", changes[0].old_nick);
    try std.testing.expectEqual(@as(usize, 16), changes[0].new_nick.len); // UID, not "kain"
    try std.testing.expect(!std.ascii.eqlIgnoreCase(changes[0].new_nick, "kain"));

    // The contested local nick was never taken by the remote member.
    try std.testing.expect(b.findRemoteMember("kain") == null);
    try std.testing.expect(b.findRemoteMember(changes[0].new_nick) != null);
}

test "a same-node re-affirmation keeps the nick (no spurious collision rename)" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();
    // No local holder; "mei" is uncontested.
    var stub = LocalNickStub{ .held = "someone-else" };
    b.setLocalNickResolver(stub.resolver());

    try a.start(10);
    try a.sendMembership("#chat", "mei", 0, 100, true, .{ .username = "m", .realname = "M", .host = "a.host" }, "");
    try a.sendMembership("#other", "mei", 0, 200, true, .{ .username = "m", .realname = "M", .host = "a.host" }, "");
    try pumpLinks(&a, &b, allocator, 11);

    // The member is stored under its real nick on both channels — the second
    // (same-node) claim is an ordinary join, never a self-collision rename.
    const member = b.findRemoteMember("mei") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("mei", member.nick);
    try std.testing.expectEqual(@as(?NodeId, 1), b.routeNickNode("mei"));
}

test "OPER_GRANT payload round-trips across the link into takeOperGrants" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.onyx", .config = plaintext_link_config });
    defer b.deinit();

    // Establish, then A sends an opaque signed grant blob; pump to B.
    try a.start(10);
    const grant = "signed-oper-grant-bytes-opaque-to-the-link";
    try a.sendOperGrant(grant);
    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const grants = try b.takeOperGrants();
    defer {
        for (grants) |g| allocator.free(g);
        allocator.free(grants);
    }
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqualSlices(u8, grant, grants[0]);
    // Drained: a second take yields nothing.
    const empty = try b.takeOperGrants();
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "MeshPass admitted frame families drop app frames while sync still flows" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.onyx", .config = plaintext_link_config });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{
        .allocator = allocator,
        .local_node_id = 2,
        .remote_node_id = 1,
        .local_epoch_ms = 1001,
        .server_name = "b.onyx",
        .admitted_frame_families = meshpass.frameFamilies(&.{ .control, .sync }),
        .config = plaintext_link_config,
    });
    defer b.deinit();

    try a.start(10);
    try pumpLinks(&a, &b, allocator, 11);
    try std.testing.expect(a.established());
    try std.testing.expect(b.established());

    try a.sendMembership("#chat", "alice", 0, 100, true, .{ .username = "alice", .realname = "Alice", .host = "host.a" }, "");
    try pumpLinks(&a, &b, allocator, 20);
    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*d| d.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("alice", changes[0].nick);

    try a.sendOperGrant("signed-oper-grant-bytes");
    try pumpLinks(&a, &b, allocator, 30);
    const grants = try b.takeOperGrants();
    defer {
        for (grants) |g| allocator.free(g);
        allocator.free(grants);
    }
    try std.testing.expectEqual(@as(usize, 0), grants.len);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
}

test "consumeOutbound drops a partial-send prefix" {
    const allocator = std.testing.allocator;
    var link: S2sLink = undefined;
    try link.init(.{
        .allocator = allocator,
        .local_node_id = 1,
        .remote_node_id = 2,
        .local_epoch_ms = 1000,
        .server_name = "a.onyx",
    });
    defer link.deinit();

    try link.start(10);
    const total = link.outbound().len;
    try std.testing.expect(total > 0);
    link.consumeOutbound(1);
    try std.testing.expectEqual(total - 1, link.outbound().len);
    link.clearOutbound();
    try std.testing.expectEqual(@as(usize, 0), link.outbound().len);
}

test "S2sLink.init threads peer driver config into live link state" {
    const allocator = std.testing.allocator;
    var cfg = PeerConfig{};
    cfg.routes.max_nicks = 128;
    cfg.registry.max_nodes = 32;
    cfg.link.peer_link_config.send_credit = 8192;
    cfg.link.peer_link_config.replay_window = 128;
    cfg.link.peer_link_config.handshake_timeout_ms = 7000;
    cfg.link.peer_link_config.heartbeat_interval_ms = 8000;
    cfg.link.peer_link_config.idle_timeout_ms = 9000;
    cfg.link.peer_link_config.drain_timeout_ms = 1000;
    cfg.link.gossip_interval_ms = 1500;
    cfg.link.repair_interval_ms = 2500;
    cfg.link.gossip_config.fanout = 2;
    cfg.link.view_config.active_capacity = 4;
    cfg.link.view_config.passive_capacity = 12;

    var link: S2sLink = undefined;
    try link.init(.{
        .allocator = allocator,
        .local_node_id = 1,
        .remote_node_id = 2,
        .local_epoch_ms = 1000,
        .server_name = "a.onyx",
        .config = cfg,
    });
    defer link.deinit();

    try std.testing.expectEqual(@as(usize, 128), link.peer.config.routes.max_nicks);
    try std.testing.expectEqual(@as(usize, 32), link.peer.config.registry.max_nodes);
    try std.testing.expectEqual(@as(u32, 8192), link.peer.session.link.send_credit);
    try std.testing.expectEqual(@as(u64, 128), link.peer.session.link.replay_window);
    try std.testing.expectEqual(@as(u64, 7000), link.peer.session.link.handshake_timeout_ms);
    try std.testing.expectEqual(@as(u64, 8000), link.peer.session.link.heartbeat_interval_ms);
    try std.testing.expectEqual(@as(u64, 9000), link.peer.session.link.idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 1000), link.peer.session.link.drain_timeout_ms);
    try std.testing.expectEqual(@as(u64, 1500), link.peer.session.config.gossip_interval_ms);
    try std.testing.expectEqual(@as(u64, 2500), link.peer.session.config.repair_interval_ms);
    try std.testing.expectEqual(@as(usize, 2), link.peer.session.config.gossip_config.fanout);
    try std.testing.expectEqual(@as(usize, 4), link.peer.session.config.view_config.active_capacity);
    try std.testing.expectEqual(@as(usize, 12), link.peer.session.config.view_config.passive_capacity);
}
