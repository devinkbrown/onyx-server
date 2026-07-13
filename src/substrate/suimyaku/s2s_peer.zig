// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure S2S peer driver for one Suimyaku server-to-server connection.
//!
//! The caller owns sockets, timers, and randomness. This driver consumes
//! inbound bytes, streaming-decodes `s2s_frame` frames, dispatches them into the
//! Suimyaku state modules, and writes encoded outbound bytes to a caller sink.
const std = @import("std");

const link_session = @import("link_session.zig");
const burst = @import("burst.zig");
const server_registry = @import("server_registry.zig");
const route_table = @import("route_table.zig");
const nick_collision = @import("nick_collision.zig");
const channel_crdt = @import("channel_crdt.zig");
const gossip_round = @import("gossip_round.zig");
const anti_entropy_repair = @import("anti_entropy_repair.zig");
const membership_view = @import("membership_view.zig");
const merkle = @import("merkle.zig");
const peer_link = @import("peer_link.zig");
const message_relay = @import("message_relay.zig");
const toml = @import("../../proto/toml.zig");

const Allocator = std.mem.Allocator;

pub const ChannelCrdt = channel_crdt.ChannelCrdt;
pub const NodeId = gossip_round.NodeId;
pub const MemberInfo = route_table.Member;
pub const MemberIdentity = route_table.MemberIdentity;
pub const ChannelModeFlags = route_table.ChannelModeFlags;
pub const ChannelNameIterator = route_table.RouteTable.ChannelNameIterator;
pub const RelayMessage = message_relay.RelayMessage;
pub const InboundMessage = message_relay.Owned;
pub const RelayVerb = message_relay.Verb;
pub const ChannelModeStateEvent = channel_mode_state_event.ChannelModeStateEvent;
pub const LocalNickResolver = route_table.LocalNickResolver;

/// RECEIVER-SIDE account-residence verifier seam (Design C, the F1 proper fix).
/// The daemon supplies a callback that verifies an incoming claim's residence
/// proof — looked up from the RECEIVER-OWNED replicated `identity.residence.*`
/// and `identity.key.*` props, never from any wire field — binding
/// `{account, origin_node}`. The peer driver consults it to compute the
/// PER-CLAIM `account_trusted` bool it passes to `resolveIncomingNick`.
/// Absent (null) ⇒ nothing is ever trusted ⇒ the conservative UID path.
pub const ResidenceVerifier = struct {
    ctx: *anyopaque,
    verify_fn: *const fn (ctx: *anyopaque, account: []const u8, origin_node: NodeId) bool,

    pub fn verify(self: ResidenceVerifier, account: []const u8, origin_node: NodeId) bool {
        return self.verify_fn(self.ctx, account, origin_node);
    }
};

/// Length of a mesh UID, sized for the stack scratch the collision paths use to
/// hold a forced-rename fallback nick.
const nick_collision_uid_len = @import("uid_alloc.zig").encoded_len;

const handshake_magic = [_]u8{ 'S', '2', 'P', 'H' };
/// Wire version of the S2S handshake. v1 carried no capability byte; v2 appends a
/// single forward-compatible capability bitfield after the description so a mixed
/// mesh stays interoperable: a v1 peer omits the byte (parsed as caps == 0), and
/// a v2 peer that sees an unknown future version still reads the caps byte it
/// understands. Bumping this is backward-compatible — see `decodeHandshake`.
const handshake_version: u8 = 2;

/// Handshake capability bits (forward-compatible bitfield). Unknown bits are
/// ignored on decode, so future capabilities never break an older peer. The
/// public wire catalog lives in `proto/s2s_frame.zig`; keep the peer on that
/// source of truth so handshake and snapshot resume cannot drift.
const cap_frame_signing: u8 = s2s_frame.cap_frame_signing;
/// The peer understands the optional `account` block on MEMBERSHIP/NICKCHANGE
/// events (account-aware collision reconcile). Gated so we only ever append the
/// extra wire bytes to a peer that advertised support — an older peer (which
/// strictly rejects trailing bytes) never receives them.
const cap_member_account: u8 = s2s_frame.cap_member_account;
/// The peer understands the optional `real_host` + `certfp` blocks on MEMBERSHIP
/// events (oper-visible identity for remote-user WHOIS). Advertised ONLY by a
/// SECURED link (one that holds a node signing key) — these fields are sensitive,
/// so they must never traverse a plaintext S2S leg. Gated like `member_account`:
/// the extra trailing bytes are appended only to a peer that advertised support.
const cap_member_oper_info: u8 = s2s_frame.cap_member_oper_info;
/// The peer understands Merkle-guided anti-entropy repair frames
/// (REPAIR_SUMMARY/REQUEST/RESPONSE).
const cap_repair_frames: u8 = s2s_frame.cap_repair_frames;

const s2s_frame = @import("../../proto/s2s_frame.zig");
const meshpass = @import("../../proto/meshpass.zig");
const membership_event = @import("../../proto/membership_event.zig");
const oper_event = @import("../../proto/oper_event.zig");
const observe_event = @import("../../proto/observe_event.zig");
const kill_relay = @import("../../proto/kill_relay.zig");
const tegami_push_relay = @import("../../proto/tegami_push_relay.zig");
const channel_mode_flags_event = @import("../../proto/channel_mode_flags_event.zig");
const channel_list_event = @import("../../proto/channel_list_event.zig");
const channel_mode_state_event = @import("../../proto/channel_mode_state_event.zig");
const channel_prop_event = @import("../../proto/channel_prop_event.zig");
const entity_prop_event = @import("../../proto/entity_prop_event.zig");
const topic_event = @import("../../proto/topic_event.zig");
const nick_event = @import("../../proto/nick_event.zig");
const partition_detector = @import("partition_detector.zig");
const signed_frame = @import("signed_frame.zig");
const sign = @import("../../crypto/sign.zig");

pub const ByteSink = struct {
    ptr: *anyopaque,
    write_fn: *const fn (*anyopaque, []const u8) anyerror!void,

    pub fn writeAll(self: ByteSink, bytes: []const u8) !void {
        try self.write_fn(self.ptr, bytes);
    }
};

pub const Config = struct {
    max_frame_size: usize = s2s_frame.default_max_frame_size,
    link: link_session.Config = .{
        .gossip_interval_ms = 1_000,
        .repair_interval_ms = 2_000,
        .gossip_config = .{ .fanout = 1 },
    },
    registry: server_registry.Config = .{},
    routes: route_table.Config = .{},
    /// Receiver-side policy: reject unsigned direct-owned state frames. A keyed
    /// peer additionally requires the remote handshake to advertise frame signing
    /// (a non-signing peer is faulted at handshake). A KEYLESS peer cannot sign
    /// its own egress, but it STILL enforces the inbound gate — an unsigned
    /// in-scope frame is dropped + counted rather than applied (fail closed).
    /// Set false only for an explicitly-permitted unsigned/plaintext deployment.
    require_signed_frames: bool = true,

    /// Consolidated applier for the EFFECTIVE production path
    /// (`s2s_peer` → `link_session` → peer-link/gossip/sazanami/burst). Overlays
    /// every `[mesh.*]` section this driver owns. Missing keys leave fields at
    /// their defaults, so behavior is unchanged until the orchestrator supplies
    /// a parsed config. The aggregate `[mesh.gossip]`/`[mesh.sazanami]` sections are
    /// applied to the embedded session sub-configs here (link.applyToml only
    /// handles the `[mesh.link]` per-session overrides + transport + burst).
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        // Apply the broad `[mesh.gossip]`/`[mesh.sazanami]` sections to the embedded
        // session sub-configs first, then the narrower `[mesh.link]` per-session
        // overrides last so an explicit per-session override always wins.
        cfg.link.gossip_config.applyToml(doc);
        cfg.link.sazanami_config.applyToml(doc);
        cfg.link.view_config.applyToml(doc);
        cfg.link.applyToml(doc);
        cfg.registry.applyToml(doc);
        cfg.routes.applyToml(doc);
        if (doc.getBool("mesh.require_signed_frames")) |b| cfg.require_signed_frames = b;
    }
};

pub const Options = struct {
    allocator: Allocator,
    state: *ChannelCrdt,
    clock: peer_link.Clock,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    local_epoch_ms: u64,
    server_name: []const u8,
    description: []const u8 = "",
    channel_name: []const u8 = "#suimyaku",
    initial_send_credit: u32 = peer_link.default_send_credit,
    config: Config = .{},
    /// Optional node Ed25519 signing keypair for END-TO-END origin authentication
    /// of direct-owned state frames. When set (secured links pass the node
    /// identity's key), this peer advertises `frame_signing` in its handshake and
    /// signs every in-scope outbound frame; receivers self-certify the origin.
    /// Null (plaintext links) cannot SIGN, so it cannot fault a non-signing peer
    /// on egress; it still ENFORCES `require_signed_frames` on ingress by dropping
    /// unsigned in-scope frames (fail closed) — see `inboundSignedFramesRequired`.
    ///
    /// INVARIANT for self-certification to hold: when a key is supplied,
    /// `local_node_id` MUST equal `signed_frame.originShortId(key.public_key)`
    /// (i.e. `shortId(nodeIdFromPublicKey(pubkey))`). The secured link guarantees
    /// this by deriving `local_node_id` from the same identity it signs with.
    signing_key: ?sign.KeyPair = null,
    /// Signed MeshPass frame-family rights admitted for the remote peer. Zero
    /// means this link was not admitted by a signed MeshPass token, preserving
    /// legacy/open/shared-secret behavior.
    admitted_frame_families: u32 = 0,
};

const Handshake = struct {
    node_id: NodeId,
    epoch_ms: u64,
    name: []const u8,
    description: []const u8,
    /// Capability bitfield (v2+); 0 for a v1 peer that omitted it.
    caps: u8 = 0,
};

pub const S2sPeer = struct {
    allocator: Allocator,
    decoder: s2s_frame.Decoder,
    state: *ChannelCrdt,
    session: link_session.LinkSession,
    registry: server_registry.ServerRegistry,
    routes: route_table.RouteTable,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    local_epoch_ms: u64,
    server_name: []u8,
    description: []u8,
    channel_name: []u8,
    remote_epoch_ms: ?u64 = null,
    remote_name: []u8 = &.{},
    handshake_sent: bool = false,
    established: bool = false,
    burst_sent: bool = false,
    /// A peer asked us (via a RESYNC frame) to re-send our full state after it
    /// resumed a mesh link across a hot upgrade. The daemon drains this and runs
    /// its full membership/mode/prop/topic burst to this conn. Substrate-pure: the
    /// driver only records the request; the daemon owns the burst.
    resync_requested: bool = false,
    /// A valid REPAIR_RESPONSE updated the substrate CRDT shadow. The daemon drains
    /// this as a conservative live-state bridge: request and send the existing full
    /// state burst rather than surfacing repair records directly.
    repair_resync_requested: bool = false,
    ping_rx_count: usize = 0,
    pong_rx_count: usize = 0,
    config: Config,
    /// This node's Ed25519 signing keypair (set on secured links), or null on the
    /// legacy unsigned (plaintext) path. When set, in-scope outbound frames are
    /// wrapped in a `signed_frame` envelope iff the peer advertised signing.
    signing_key: ?sign.KeyPair = null,
    /// Signed MeshPass frame-family rights admitted for the remote peer. Zero
    /// means this link was not admitted by a signed MeshPass token, preserving
    /// legacy/open/shared-secret behavior.
    admitted_frame_families: u32 = 0,
    /// Whether the remote peer advertised the `frame_signing` capability in its
    /// handshake. Learned on `recvHandshake`; gates both outbound wrapping (only
    /// wrap for a signing-capable peer) and inbound enforcement (a signing-capable
    /// peer's in-scope frames MUST be signed, else they are rejected).
    peer_supports_signing: bool = false,
    /// Whether the remote peer advertised the `member_account` capability. Gates
    /// emission of the optional `account` block on MEMBERSHIP/NICKCHANGE events so
    /// an older peer (strict trailing-byte rejection) never receives the extra
    /// bytes. Learned on `recvHandshake`.
    peer_supports_account: bool = false,
    /// Whether the remote peer advertised `member_oper_info` (a SECURED, oper-info
    /// capable link). Gates emission of the optional real_host/certfp blocks on
    /// MEMBERSHIP events so they only ever ride a secured leg to a capable peer.
    peer_supports_oper_info: bool = false,
    /// Whether the remote peer advertised Merkle/RBSR anti-entropy repair frames.
    /// Gated because these are newer S2S frame tags; older peers keep relying on
    /// the daemon's coarse full-state re-burst fallback.
    peer_supports_repair: bool = false,
    /// Daemon-supplied residence-proof verifier (Design C / F1). Null (default,
    /// and always on non-daemon/test peers) ⇒ no account is ever trusted ⇒ every
    /// same-account short-circuit stays on the conservative UID path.
    residence_verifier: ?ResidenceVerifier = null,
    /// Frames dropped because the peer's signed MeshPass token did not authorize
    /// the frame catalog family at runtime.
    rejected_admission_frames: u64 = 0,
    /// In-scope frames rejected because their signed-envelope verification failed
    /// or the self-certified origin did not match the claimed origin. Folded into
    /// the same audit drain as `rejected_origin_frames` (see `acceptsDirectOrigin`).
    rejected_signature_frames: u64 = 0,
    /// Inbound cross-node user messages decoded from MESSAGE frames, awaiting the
    /// daemon to drain + deliver to local clients (the daemon owns delivery; the
    /// peer driver stays substrate-pure). Loop-guarded by `seen`.
    inbound: std.ArrayListUnmanaged(message_relay.Owned) = .empty,
    /// Inbound signed oper-grant payloads (raw oper_cred_share bytes) decoded
    /// from OPER_GRANT frames, awaiting the daemon to verify + ingest them.
    inbound_grants: std.ArrayListUnmanaged([]u8) = .empty,
    /// Remote channel membership changes (a peer's user joined/parted a channel)
    /// that actually altered the route table, awaiting the daemon to surface them
    /// as live `:nick JOIN/PART #chan` lines to local members. Re-affirmations
    /// (anti-entropy re-bursts) never enqueue here, so no duplicate JOINs.
    membership_changes: std.ArrayListUnmanaged(MembershipDelta) = .empty,
    /// Remote aggregate channel MODE flag changes that won the LWW route-table
    /// state, awaiting the daemon to apply them to the local world and emit MODE.
    channel_mode_flag_changes: std.ArrayListUnmanaged(ChannelModeFlagsDelta) = .empty,
    /// Remote parameter/IRCX channel-state snapshots that won a per-channel LWW
    /// clock, awaiting daemon-side application and MODE emission.
    channel_mode_state_changes: std.ArrayListUnmanaged(ChannelModeStateDelta) = .empty,
    channel_mode_state_clocks: std.StringHashMapUnmanaged(u64) = .empty,
    /// Direct-owned state frames rejected because their claimed origin did not
    /// match the authenticated peer. Drained by the daemon for audit logging.
    rejected_origin_frames: u64 = 0,
    /// Remote channel list-mode changes (+b/+e/+I) that altered LWW state,
    /// awaiting the daemon to apply them to its local world and emit MODE lines.
    channel_list_changes: std.ArrayListUnmanaged(ChannelListDelta) = .empty,
    /// Remote IRCX channel PROP events awaiting daemon-side LWW apply into the
    /// local prop store. The daemon owns prop clocks and client emission policy.
    prop_changes: std.ArrayListUnmanaged(ChannelPropDelta) = .empty,
    /// Remote IRCX user/member PROP events (ENTITY_PROP) awaiting daemon-side LWW
    /// apply. The non-channel counterpart of `prop_changes`; same ownership model.
    entity_prop_changes: std.ArrayListUnmanaged(EntityPropDelta) = .empty,
    /// Remote channel topic changes that altered LWW state, awaiting the daemon
    /// to apply them to its local world and emit a live `TOPIC` line.
    topic_changes: std.ArrayListUnmanaged(TopicDelta) = .empty,
    /// Remote user nick changes, awaiting the daemon to rename the user in its
    /// world and surface a live `:old!u@h NICK new` line to shared-channel members.
    nick_changes: std.ArrayListUnmanaged(NickDelta) = .empty,
    /// Inbound live-session migration capsules (raw `migration_relay` frame
    /// bytes) decoded from SESSION_MIGRATE frames, awaiting the daemon to verify
    /// (MigrationTarget.accept) + stage into PendingMigrations. The peer driver
    /// stays substrate-pure: it never opens the signed capsule, only stages it.
    session_migrations: std.ArrayListUnmanaged([]u8) = .empty,
    /// Inbound CLONE_COUNT payloads (raw `mesh_clones` counts-codec bytes) from
    /// this peer, awaiting the daemon to decode + fold into its network-wide clone
    /// aggregate. The peer driver stays substrate-pure: it never decodes them.
    clone_counts: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified OPER_EVENT payloads received from this peer, awaiting the daemon
    /// to decode + deliver to its local oper subscribers. Substrate-pure: never
    /// decoded here.
    oper_events: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified OBSERVE_EVENT payloads received from this peer, awaiting the daemon
    /// to decode + match against its local OBSERVE registry. Substrate-pure: never
    /// decoded here.
    observe_events: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified KILL payloads received from this peer, awaiting the daemon to
    /// decode + disconnect the named local target. Substrate-pure: never decoded
    /// here.
    kills: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified WARD payloads received from this peer, awaiting the daemon to
    /// decode + apply (add/remove) into its local Warden store. Substrate-pure:
    /// never decoded here.
    wards: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified TEGAMI_PUSH payloads received from this peer, awaiting the daemon
    /// to decode and run local Web Push delivery. These are signing-required:
    /// legacy/plaintext peers are ignored so DM previews do not ride unsigned S2S.
    tegami_pushes: std.ArrayListUnmanaged([]u8) = .empty,
    seen: message_relay.SeenSet,

    pub fn init(options: Options) !S2sPeer {
        const server_name = try options.allocator.dupe(u8, options.server_name);
        errdefer options.allocator.free(server_name);
        const description = try options.allocator.dupe(u8, options.description);
        errdefer options.allocator.free(description);
        const channel_name = try options.allocator.dupe(u8, options.channel_name);
        errdefer options.allocator.free(channel_name);

        var registry = try server_registry.ServerRegistry.init(options.allocator, options.config.registry);
        errdefer registry.deinit();
        try registry.add(.{
            .node_id = options.local_node_id,
            .name = server_name,
            .description = description,
            .last_seen_ms = try i64Ms(options.local_epoch_ms),
        });

        var routes = try route_table.RouteTable.init(options.allocator, options.config.routes);
        errdefer routes.deinit();
        try routes.setNickLocation(server_name, options.local_node_id);

        var session = try link_session.LinkSession.init(options.allocator, options.state, .{
            .clock = options.clock,
            .local_epoch_ms = options.local_epoch_ms,
            .local_node_id = options.local_node_id,
            .remote_node_id = options.remote_node_id,
            .initial_send_credit = options.initial_send_credit,
            .config = options.config.link,
        });
        errdefer session.deinit();

        return .{
            .allocator = options.allocator,
            .decoder = s2s_frame.Decoder.init(options.allocator, options.config.max_frame_size),
            .state = options.state,
            .session = session,
            .registry = registry,
            .routes = routes,
            .local_node_id = options.local_node_id,
            .remote_node_id = options.remote_node_id,
            .local_epoch_ms = options.local_epoch_ms,
            .server_name = server_name,
            .description = description,
            .channel_name = channel_name,
            .config = options.config,
            .signing_key = options.signing_key,
            .admitted_frame_families = options.admitted_frame_families,
            .seen = message_relay.SeenSet.init(options.allocator, 1024),
        };
    }

    /// Bounded identity/capability header needed to resume a peer across a Helix
    /// hot upgrade. The converged CRDT/route/registry state is NOT captured — the
    /// resumed node re-fetches it from the peer via a RESYNC-triggered full burst
    /// (the peer's socket was preserved, so it never saw a drop). `remote_name` is
    /// carried alongside as a length-delimited string.
    pub const ResumeHeader = struct {
        link: peer_link.PeerLink.ResumeHeader,
        remote_node_id: NodeId,
        remote_epoch_ms: u64,
        peer_supports_signing: bool,
        peer_supports_account: bool,
        peer_supports_oper_info: bool,
        peer_supports_repair: bool,
    };

    pub fn snapshotResume(self: *const S2sPeer) ResumeHeader {
        return .{
            .link = self.session.snapshotResume(),
            .remote_node_id = self.remote_node_id,
            .remote_epoch_ms = self.remote_epoch_ms orelse 0,
            .peer_supports_signing = self.peer_supports_signing,
            .peer_supports_account = self.peer_supports_account,
            .peer_supports_oper_info = self.peer_supports_oper_info,
            .peer_supports_repair = self.peer_supports_repair,
        };
    }

    /// Rebuild a peer driver directly in the established state from a resume header
    /// (post-upgrade), bypassing the handshake. Mirrors `init` but stands the link
    /// up established with the peer's identity/caps restored and a FRESH empty CRDT
    /// replica. The caller must send a RESYNC to the peer to refill the converged
    /// roster/props/topics, and re-burst its own local state.
    pub fn resumeEstablished(options: Options, hdr: ResumeHeader, remote_name: []const u8, now_ms: u64, rng_seed: u64) !S2sPeer {
        if (options.config.require_signed_frames and options.signing_key != null and !hdr.peer_supports_signing) {
            return error.SignedFramesRequired;
        }

        const server_name = try options.allocator.dupe(u8, options.server_name);
        errdefer options.allocator.free(server_name);
        const description = try options.allocator.dupe(u8, options.description);
        errdefer options.allocator.free(description);
        const channel_name = try options.allocator.dupe(u8, options.channel_name);
        errdefer options.allocator.free(channel_name);
        const owned_remote_name = try options.allocator.dupe(u8, remote_name);
        errdefer options.allocator.free(owned_remote_name);

        var registry = try server_registry.ServerRegistry.init(options.allocator, options.config.registry);
        errdefer registry.deinit();
        try registry.add(.{
            .node_id = options.local_node_id,
            .name = server_name,
            .description = description,
            .last_seen_ms = try i64Ms(options.local_epoch_ms),
        });
        // Re-register the remote server so WHOIS/LINKS name it immediately; its
        // members/routes are refilled by the RESYNC burst.
        if (remote_name.len != 0 and hdr.remote_node_id != 0) {
            _ = try registry.addOrUpdate(.{
                .node_id = hdr.remote_node_id,
                .name = remote_name,
                .description = "",
                .hopcount = 1,
                .uplink = options.local_node_id,
                .last_seen_ms = try i64Ms(now_ms),
            });
        }

        var routes = try route_table.RouteTable.init(options.allocator, options.config.routes);
        errdefer routes.deinit();
        try routes.setNickLocation(server_name, options.local_node_id);
        if (remote_name.len != 0 and hdr.remote_node_id != 0) {
            try routes.setNickLocation(remote_name, hdr.remote_node_id);
        }

        var session = try link_session.LinkSession.resumeEstablished(
            options.allocator,
            options.state,
            .{
                .clock = options.clock,
                .local_epoch_ms = options.local_epoch_ms,
                .local_node_id = options.local_node_id,
                .remote_node_id = hdr.remote_node_id,
                .initial_send_credit = options.initial_send_credit,
                .config = options.config.link,
            },
            hdr.link,
            now_ms,
            rng_seed,
        );
        errdefer session.deinit();

        return .{
            .allocator = options.allocator,
            .decoder = s2s_frame.Decoder.init(options.allocator, options.config.max_frame_size),
            .state = options.state,
            .session = session,
            .registry = registry,
            .routes = routes,
            .local_node_id = options.local_node_id,
            .remote_node_id = hdr.remote_node_id,
            .local_epoch_ms = options.local_epoch_ms,
            .server_name = server_name,
            .description = description,
            .channel_name = channel_name,
            .remote_epoch_ms = hdr.remote_epoch_ms,
            .remote_name = owned_remote_name,
            .handshake_sent = true,
            .established = true,
            .burst_sent = true,
            .peer_supports_signing = hdr.peer_supports_signing,
            .peer_supports_account = hdr.peer_supports_account,
            .peer_supports_oper_info = hdr.peer_supports_oper_info,
            .peer_supports_repair = hdr.peer_supports_repair,
            .config = options.config,
            .signing_key = options.signing_key,
            .admitted_frame_families = options.admitted_frame_families,
            .seen = message_relay.SeenSet.init(options.allocator, 1024),
        };
    }

    pub fn deinit(self: *S2sPeer) void {
        for (self.inbound.items) |*owned| owned.deinit(self.allocator);
        self.inbound.deinit(self.allocator);
        for (self.inbound_grants.items) |g| self.allocator.free(g);
        self.inbound_grants.deinit(self.allocator);
        for (self.membership_changes.items) |*d| d.deinit(self.allocator);
        self.membership_changes.deinit(self.allocator);
        for (self.channel_mode_flag_changes.items) |*d| d.deinit(self.allocator);
        self.channel_mode_flag_changes.deinit(self.allocator);
        for (self.channel_mode_state_changes.items) |*d| d.deinit(self.allocator);
        self.channel_mode_state_changes.deinit(self.allocator);
        var state_clocks = self.channel_mode_state_clocks.iterator();
        while (state_clocks.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.channel_mode_state_clocks.deinit(self.allocator);
        for (self.channel_list_changes.items) |*d| d.deinit(self.allocator);
        self.channel_list_changes.deinit(self.allocator);
        for (self.prop_changes.items) |*d| d.deinit(self.allocator);
        self.prop_changes.deinit(self.allocator);
        for (self.entity_prop_changes.items) |*d| d.deinit(self.allocator);
        self.entity_prop_changes.deinit(self.allocator);
        for (self.topic_changes.items) |*d| d.deinit(self.allocator);
        self.topic_changes.deinit(self.allocator);
        for (self.nick_changes.items) |*d| d.deinit(self.allocator);
        self.nick_changes.deinit(self.allocator);
        for (self.session_migrations.items) |m| self.allocator.free(m);
        self.session_migrations.deinit(self.allocator);
        for (self.clone_counts.items) |m| self.allocator.free(m);
        self.clone_counts.deinit(self.allocator);
        for (self.oper_events.items) |m| self.allocator.free(m);
        self.oper_events.deinit(self.allocator);
        for (self.observe_events.items) |m| self.allocator.free(m);
        self.observe_events.deinit(self.allocator);
        for (self.kills.items) |m| self.allocator.free(m);
        self.kills.deinit(self.allocator);
        for (self.wards.items) |m| self.allocator.free(m);
        self.wards.deinit(self.allocator);
        for (self.tegami_pushes.items) |m| self.allocator.free(m);
        self.tegami_pushes.deinit(self.allocator);
        self.seen.deinit();
        self.allocator.free(self.remote_name);
        self.allocator.free(self.channel_name);
        self.allocator.free(self.description);
        self.allocator.free(self.server_name);
        self.session.deinit();
        self.routes.deinit();
        self.registry.deinit();
        self.decoder.deinit();
        if (self.signing_key) |*kp| kp.deinit(); // wipe our copy of the secret key
        self.* = undefined;
    }

    pub fn startHandshake(self: *S2sPeer, sink: ByteSink) !void {
        if (self.handshake_sent) return;
        if (self.session.link.state == .idle) try self.session.link.beginHandshake();
        try self.emitHandshake(sink);
    }

    pub fn feed(self: *S2sPeer, bytes: []const u8, sink: ByteSink, now_ms: u64, rng_seed: u64) !void {
        try self.decoder.feed(bytes);
        while (try self.decoder.next()) |frame| {
            try self.dispatch(frame, sink, now_ms, rng_seed);
        }
    }

    pub fn finish(self: *S2sPeer) !void {
        try self.decoder.finish();
    }

    pub fn sendDelta(self: *S2sPeer, delta: *const ChannelCrdt, sink: ByteSink) !void {
        if (!self.established) return error.NotEstablished;
        const encoded = try burst.serialize(self.allocator, delta, self.config.link.burst_limits);
        defer self.allocator.free(encoded);
        try emitFrame(self.allocator, sink, .DELTA, encoded);
    }

    pub fn sendPing(self: *S2sPeer, payload: []const u8, sink: ByteSink) !void {
        try emitFrame(self.allocator, sink, .PING, payload);
    }

    /// Ask the peer to re-send its full converged state (used right after a Helix
    /// resume). Unsigned control frame — carries no trusted state itself.
    pub fn sendResync(self: *S2sPeer, sink: ByteSink) !void {
        try emitFrame(self.allocator, sink, .RESYNC, "");
    }

    /// Consume a pending RESYNC request from the peer (see `resync_requested`).
    pub fn takeResyncRequest(self: *S2sPeer) bool {
        defer self.resync_requested = false;
        return self.resync_requested;
    }

    /// Consume a pending daemon-side resync bridge requested by a valid repair
    /// response. The repair frame updates the pure CRDT shadow; live server state
    /// reconverges through the existing full-burst frame families.
    pub fn takeRepairResyncRequest(self: *S2sPeer) bool {
        defer self.repair_resync_requested = false;
        return self.repair_resync_requested;
    }

    pub fn tick(self: *S2sPeer, sink: ByteSink, now_ms: u64, rng_seed: u64, peers: []const NodeId) !void {
        if (self.session.link.tick() == .heartbeat_due) {
            try emitFrame(self.allocator, sink, .PING, "");
        }
        if (!self.established) return;

        var result = try self.session.gossip.run(
            try i64Ms(now_ms),
            rng_seed,
            peers,
            &.{},
            self.config.link.gossip_config,
        );
        defer result.deinit(self.allocator);
        if (containsNode(result.peers.items, self.remote_node_id)) {
            const payload = try encodeGossip(self.allocator, &result.payload);
            defer self.allocator.free(payload);
            try emitFrame(self.allocator, sink, .GOSSIP, payload);
        }

        if (self.peer_supports_repair and elapsed(now_ms, self.session.last_repair_ms) >= self.config.link.repair_interval_ms) {
            const payload = try encodeRepairSummary(self.allocator, self.state);
            defer self.allocator.free(payload);
            try self.emitSignable(sink, .REPAIR_SUMMARY, payload);
            self.session.last_repair_ms = now_ms;
        }
    }

    pub fn linkState(self: *const S2sPeer) peer_link.State {
        return self.session.linkState();
    }

    pub fn registryCount(self: *const S2sPeer) usize {
        return self.registry.count();
    }

    /// The remote server's name once learned from the handshake (empty before).
    pub fn remoteName(self: *const S2sPeer) []const u8 {
        return self.remote_name;
    }

    /// The remote node id once learned from the handshake (null before).
    pub fn remoteNodeId(self: *const S2sPeer) ?NodeId {
        if (!self.established or self.remote_node_id == 0) return null;
        return self.remote_node_id;
    }

    /// The remote peer's own server description, or null before establishment /
    /// when the peer carried none.
    ///
    /// The peer's description can land in the registry under EITHER of two u64
    /// node-id spaces: the id it advertised in the direct handshake (for a
    /// secured link, `shortId(identity)`; for a plaintext link, its
    /// `config.node_id`) and the id its gossiped registry/membership frames carry
    /// — and, depending on which leg populated which entry, only one of them may
    /// hold a non-empty description. Keying by `remoteNodeId()` therefore missed
    /// the populated entry (LINKS fell back to "Suimyaku peer") while the WHOIS
    /// 312 path, keyed by the membership-frame `member.node`, resolved it.
    ///
    /// Resolve by the one identifier both spaces agree on — the server NAME —
    /// preferring an entry that actually carries a description. Borrowed from the
    /// registry entry; valid until the next mutation.
    pub fn remoteDescription(self: *const S2sPeer) ?[]const u8 {
        if (!self.established or self.remote_name.len == 0) return null;
        for (self.registry.list()) |node| {
            if (node.description.len != 0 and std.ascii.eqlIgnoreCase(node.name, self.remote_name)) {
                return node.description;
            }
        }
        return null;
    }

    pub fn routeNickNode(self: *const S2sPeer, nick: []const u8) ?NodeId {
        return self.routes.nickNode(nick);
    }

    /// Find `nick` in this peer's converged remote channel rosters (ASCII
    /// case-insensitive). The returned member's `nick` slice is borrowed from
    /// the route table — valid until the next membership mutation.
    pub fn findRemoteMember(self: *const S2sPeer, nick: []const u8) ?MemberInfo {
        return self.routes.findMember(nick);
    }

    /// Server name registered for `node` (handshake or gossiped registry), or
    /// null when the node is unknown. Borrowed from the registry entry.
    pub fn nodeName(self: *const S2sPeer, node: NodeId) ?[]const u8 {
        const entry = self.registry.get(node) orelse return null;
        return entry.name;
    }

    /// Server description registered for `node`, or null when unknown/empty.
    pub fn nodeDescription(self: *const S2sPeer, node: NodeId) ?[]const u8 {
        const entry = self.registry.get(node) orelse return null;
        return if (entry.description.len != 0) entry.description else null;
    }

    /// Copy this peer's known-server registry into `out` as (node_id, uplink)
    /// topology entries for partition analysis, returning the count written. The
    /// gossiped registry encodes the mesh as a tree via each node's uplink.
    pub fn collectTopology(self: *const S2sPeer, out: []partition_detector.TopoNode) usize {
        const nodes = self.registry.list();
        var n: usize = 0;
        for (nodes) |node| {
            if (n == out.len) break;
            out[n] = .{ .node_id = node.node_id, .uplink = node.uplink };
            n += 1;
        }
        return n;
    }

    pub fn repairRoot(self: *const S2sPeer) !anti_entropy_repair.Hash {
        var summary = try anti_entropy_repair.summarize(self.allocator, self.state);
        defer summary.deinit();
        return summary.root();
    }

    fn dispatch(self: *S2sPeer, frame: s2s_frame.Frame, sink: ByteSink, now_ms: u64, rng_seed: u64) !void {
        if (!self.meshPassAllowsFrame(frame.frame_type)) {
            self.rejected_admission_frames +|= 1;
            return;
        }
        switch (frame.frame_type) {
            .HANDSHAKE => try self.recvHandshake(frame.payload, sink, now_ms, rng_seed),
            .BURST => try burst.apply(self.allocator, self.state, frame.payload, self.config.link.burst_limits),
            .DELTA => try self.mergeDelta(frame.payload),
            .GOSSIP => try self.recvGossip(frame.payload, now_ms, rng_seed),
            .PING => {
                self.ping_rx_count += 1;
                try emitFrame(self.allocator, sink, .PONG, frame.payload);
            },
            .PONG => self.pong_rx_count += 1,
            .QUIT => self.closeRemote(),
            .MEMBERSHIP => try self.recvMembership(frame.payload, now_ms),
            .CHANNEL_MODE_FLAGS => try self.recvChannelModeFlags(frame.payload),
            .CHANNEL_LIST => try self.recvChannelList(frame.payload),
            .TOPIC => try self.recvTopic(frame.payload),
            .NICKCHANGE => try self.recvNickChange(frame.payload),
            .MESSAGE => try self.recvMessage(frame.payload),
            .OPER_GRANT => try self.recvOperGrant(frame.payload),
            .CHANNEL_PROP => try self.recvChannelProp(frame.payload),
            .ENTITY_PROP => try self.recvEntityProp(frame.payload),
            .CHANNEL_MODE_STATE => try self.recvChannelModeState(frame.payload),
            .SESSION_MIGRATE => try self.recvSessionMigrate(frame.payload),
            .CLONE_COUNT => try self.recvCloneCounts(frame.payload),
            .OPER_EVENT => try self.recvOperEvent(frame.payload),
            .OBSERVE_EVENT => try self.recvObserveEvent(frame.payload),
            .KILL => try self.recvKill(frame.payload),
            .WARD => try self.recvWard(frame.payload),
            .RESYNC => self.resync_requested = true,
            .REPAIR_SUMMARY => try self.recvRepairSummary(frame.payload, sink),
            .REPAIR_REQUEST => try self.recvRepairRequest(frame.payload, sink),
            .REPAIR_RESPONSE => try self.recvRepairResponse(frame.payload),
            .TEGAMI_PUSH => try self.recvTegamiPush(frame.payload),
        }
    }

    /// Queue an inbound signed oper-grant payload for the daemon to verify (against
    /// this peer's identity) and ingest. A copy is taken; oversize/alloc failures
    /// drop it rather than fault the link.
    fn recvOperGrant(self: *S2sPeer, payload: []const u8) !void {
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.inbound_grants.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound oper-grant payloads (caller owns + frees each slice).
    pub fn takeOperGrants(self: *S2sPeer) ![][]u8 {
        return self.inbound_grants.toOwnedSlice(self.allocator);
    }

    /// Emit a signed oper-grant to this peer (best-effort; only once established).
    pub fn sendOperGrant(self: *S2sPeer, sink: ByteSink, signed: []const u8) !void {
        try emitFrame(self.allocator, sink, .OPER_GRANT, signed);
    }

    /// Queue an inbound live-session migration capsule (raw `migration_relay`
    /// frame bytes) for the daemon to verify + stage. The capsule carries its own
    /// signed token, so the daemon authenticates it cryptographically; here we
    /// only gate on the link being an authenticated direct peer (mirroring the
    /// `acceptsDirectOrigin` gate the other direct-owned frames use) and stage a
    /// copy. Oversize/alloc failures drop it rather than fault the link.
    fn recvSessionMigrate(self: *S2sPeer, payload: []const u8) !void {
        if (!self.acceptsDirectOrigin(self.remote_node_id)) return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.session_migrations.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound session-migration capsules (caller owns + frees each
    /// raw frame-bytes slice and the outer slice). Each is a `migration_relay`
    /// frame the daemon hands to `MigrationTarget.accept`.
    pub fn takeSessionMigrations(self: *S2sPeer) ![][]u8 {
        return self.session_migrations.toOwnedSlice(self.allocator);
    }

    /// Emit a live-session migration capsule to this peer. `frame_bytes` are the
    /// `migration_relay` offer frame minted by `MigrationOrigin.prepare`. The
    /// daemon stamps + signs the capsule; this peer only frames + ships it.
    /// Best-effort; only meaningful once established.
    pub fn sendSessionMigrate(self: *S2sPeer, sink: ByteSink, frame_bytes: []const u8) !void {
        try emitFrame(self.allocator, sink, .SESSION_MIGRATE, frame_bytes);
    }

    /// Queue an inbound CLONE_COUNT payload (raw `mesh_clones` counts bytes) for
    /// the daemon to decode + aggregate. Gated to authenticated direct peers
    /// (matching the other direct-owned frames); a copy is taken, and oversize /
    /// alloc failures drop it rather than fault the link. The daemon attributes
    /// the counts to THIS peer's node id, so a peer cannot inject another node's.
    fn recvCloneCounts(self: *S2sPeer, payload: []const u8) !void {
        if (!self.acceptsDirectOrigin(self.remote_node_id)) return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.clone_counts.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound CLONE_COUNT payloads (caller owns + frees each slice
    /// and the outer slice). Each is decoded with `mesh_clones.decodeCounts`.
    pub fn takeCloneCounts(self: *S2sPeer) ![][]u8 {
        return self.clone_counts.toOwnedSlice(self.allocator);
    }

    /// Emit a CLONE_COUNT batch to this peer. `payload` is a `mesh_clones`
    /// counts-codec buffer. Best-effort; only meaningful once established.
    pub fn sendCloneCounts(self: *S2sPeer, sink: ByteSink, payload: []const u8) !void {
        try emitFrame(self.allocator, sink, .CLONE_COUNT, payload);
    }

    /// Queue a verified inbound OPER_EVENT for the daemon to decode and deliver to
    /// its local oper subscribers. Signed-frame gated (a peer cannot inject
    /// unsigned alerts); a copy is taken, oversize/alloc failures drop it.
    fn recvOperEvent(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.OPER_EVENT, frame_payload) orelse return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.oper_events.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound OPER_EVENT payloads (caller owns + frees each slice and
    /// the outer slice). Each decodes with `oper_event.decode`.
    pub fn takeOperEvents(self: *S2sPeer) ![][]u8 {
        return self.oper_events.toOwnedSlice(self.allocator);
    }

    /// Emit a signed OPER_EVENT to this peer (network-wide Event-Spine fan-out).
    /// Best-effort; only meaningful once established.
    pub fn sendOperEvent(self: *S2sPeer, sink: ByteSink, category: u6, severity: u8, origin_server: []const u8, message: []const u8) !void {
        const ev = oper_event.OperEvent{
            .category = category,
            .severity = severity,
            .origin_server = truncated(origin_server, oper_event.max_origin_len),
            .message = truncated(message, oper_event.max_message_len),
        };
        var buf: [oper_event.max_encoded_len]u8 = undefined;
        const wire = try oper_event.encode(ev, &buf);
        try self.emitSignable(sink, .OPER_EVENT, wire);
    }

    /// Queue a verified inbound OBSERVE_EVENT for the daemon to decode and match
    /// against its local OBSERVE registry. Signed-frame gated (the subject's real
    /// host is operator-trust); a copy is taken, oversize/alloc failures drop it.
    fn recvObserveEvent(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.OBSERVE_EVENT, frame_payload) orelse return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.observe_events.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound OBSERVE_EVENT payloads (caller owns + frees each slice
    /// and the outer slice). Each decodes with `observe_event.decode`.
    pub fn takeObserveEvents(self: *S2sPeer) ![][]u8 {
        return self.observe_events.toOwnedSlice(self.allocator);
    }

    /// Queue a verified inbound KILL for the daemon to decode and apply (disconnect
    /// the named local target). Substrate-pure: never decoded here.
    fn recvKill(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.KILL, frame_payload) orelse return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.kills.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound KILL payloads (caller owns + frees each slice and the
    /// outer slice). Each decodes with `kill_relay.decode`.
    pub fn takeKills(self: *S2sPeer) ![][]u8 {
        return self.kills.toOwnedSlice(self.allocator);
    }

    /// Emit a signed KILL to this peer (targeted cross-mesh operator KILL).
    pub fn sendKill(
        self: *S2sPeer,
        sink: ByteSink,
        origin_server: []const u8,
        killer: []const u8,
        target: []const u8,
        reason: []const u8,
    ) !void {
        const ev = kill_relay.KillRelay{
            .origin_server = truncated(origin_server, kill_relay.max_name_len),
            .killer = truncated(killer, kill_relay.max_name_len),
            .target = truncated(target, kill_relay.max_name_len),
            .reason = truncated(reason, kill_relay.max_reason_len),
        };
        var buf: [kill_relay.max_encoded_len]u8 = undefined;
        const wire = try kill_relay.encode(ev, &buf);
        try self.emitSignable(sink, .KILL, wire);
    }

    /// Queue a verified inbound WARD for the daemon to decode + apply (add/remove
    /// a mesh-scope network ban). Signed-frame gated (setting a network ban is
    /// operator authority); a copy is taken, oversize/alloc failures drop it.
    /// Substrate-pure: never decoded here.
    fn recvWard(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.WARD, frame_payload) orelse return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.wards.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound WARD payloads (caller owns + frees each slice and the
    /// outer slice). Each decodes with `warden.decodeWire`.
    pub fn takeWards(self: *S2sPeer) ![][]u8 {
        return self.wards.toOwnedSlice(self.allocator);
    }

    /// Emit a signed WARD to this peer (network-wide mesh-scope ban convergence).
    /// `wire` is a `warden.encodeWire` record. Best-effort; only meaningful once
    /// established.
    pub fn sendWard(self: *S2sPeer, sink: ByteSink, wire: []const u8) !void {
        try self.emitSignable(sink, .WARD, wire);
    }

    /// Queue a verified inbound TEGAMI_PUSH hint for daemon-side Web Push
    /// delivery. Unlike older direct-owned frames, this is signing-required:
    /// peers that did not negotiate frame signing are ignored, because the payload
    /// carries a DM preview and should only ride the secured node-identity path.
    fn recvTegamiPush(self: *S2sPeer, frame_payload: []const u8) !void {
        if (!self.peer_supports_signing) return;
        const payload = self.verifiedPayload(.TEGAMI_PUSH, frame_payload) orelse return;
        _ = tegami_push_relay.decode(payload) catch return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.tegami_pushes.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued TEGAMI_PUSH payloads (caller owns + frees each slice and the
    /// outer slice). Each decodes with `tegami_push_relay.decode`.
    pub fn takeTegamiPushes(self: *S2sPeer) ![][]u8 {
        return self.tegami_pushes.toOwnedSlice(self.allocator);
    }

    /// Emit a signed TEGAMI_PUSH hint to this peer. No-op unless the peer
    /// negotiated frame signing and this node has a signing key; this avoids
    /// leaking DM previews onto legacy/plaintext S2S links.
    pub fn sendTegamiPush(self: *S2sPeer, sink: ByteSink, account: []const u8, from: []const u8, text: []const u8) !void {
        if (!self.peer_supports_signing or self.signing_key == null) return;
        var buf: [tegami_push_relay.max_encoded_len]u8 = undefined;
        const wire = try tegami_push_relay.encode(.{ .account = account, .from = from, .text = text }, &buf);
        try self.emitSignable(sink, .TEGAMI_PUSH, wire);
    }

    /// Emit a signed OBSERVE_EVENT to this peer (network-wide OBSERVE fan-out).
    /// Best-effort; only meaningful once established.
    pub fn sendObserveEvent(
        self: *S2sPeer,
        sink: ByteSink,
        action: u8,
        origin_server: []const u8,
        nick: []const u8,
        user: []const u8,
        host: []const u8,
        account: ?[]const u8,
        detail: []const u8,
    ) !void {
        const ev = observe_event.ObserveEvent{
            .action = action,
            .origin_server = truncated(origin_server, observe_event.max_origin_len),
            .nick = truncated(nick, observe_event.max_nick_len),
            .user = truncated(user, observe_event.max_user_len),
            .host = truncated(host, observe_event.max_host_len),
            .account = if (account) |a| truncated(a, observe_event.max_account_len) else null,
            .detail = truncated(detail, observe_event.max_detail_len),
        };
        var buf: [observe_event.max_encoded_len]u8 = undefined;
        const wire = try observe_event.encode(ev, &buf);
        try self.emitSignable(sink, .OBSERVE_EVENT, wire);
    }

    /// Decode an inbound cross-node MESSAGE and queue it for the daemon to
    /// deliver locally. Loop-guarded by (origin_node, hlc): a duplicate that has
    /// already traversed this node is dropped (never re-queued/re-forwarded). A
    /// malformed payload is dropped, never fatal to the link.
    fn recvMessage(self: *S2sPeer, payload: []const u8) !void {
        var owned = message_relay.decode(self.allocator, payload) catch return;
        if (self.seen.observe(owned.msg.origin_node, owned.msg.hlc)) {
            owned.deinit(self.allocator); // duplicate — already seen
            return;
        }
        self.inbound.append(self.allocator, owned) catch {
            owned.deinit(self.allocator);
        };
    }

    /// Emit a cross-node user message to this peer. Records it in the loop-guard
    /// so an echo back is dropped. Best-effort; only meaningful once established.
    pub fn sendMessage(self: *S2sPeer, sink: ByteSink, msg: message_relay.RelayMessage) !void {
        _ = self.seen.observe(msg.origin_node, msg.hlc);
        const wire = try message_relay.encode(self.allocator, msg);
        defer self.allocator.free(wire);
        try emitFrame(self.allocator, sink, .MESSAGE, wire);
    }

    /// Transfer ownership of all queued inbound messages to the caller, which
    /// must `deinit` each `Owned` and free the returned slice. Resets the queue.
    pub fn takeInbound(self: *S2sPeer) ![]message_relay.Owned {
        return self.inbound.toOwnedSlice(self.allocator);
    }

    /// A remote channel membership transition the daemon should reflect as a live
    /// IRC line. All strings are heap-owned; the daemon frees them via `deinit`
    /// after emitting the JOIN/PART. `username`/`realname`/`host` carry the
    /// member's propagated identity ("" = unknown; render the placeholder).
    pub const MembershipDelta = struct {
        /// `ghost_reclaim` is NOT a roster transition — it asks the daemon to retire
        /// the LOCAL session holding `nick` (same authenticated account, strictly
        /// older mesh claim) in favour of the live remote one. `account` carries the
        /// remote claim's account for a daemon-side safety re-check before any kill.
        pub const Kind = enum { joined, parted, status, ghost_reclaim };

        channel: []u8,
        nick: []u8,
        username: []u8,
        realname: []u8,
        host: []u8,
        /// The nick that set this status (explicit `/MODE`), so the daemon renders
        /// `:setter MODE …` instead of the origin server. "" = none.
        setter: []u8,
        /// The remote claim's authenticated account ("" = none); used by the daemon
        /// to re-verify a `ghost_reclaim` before retiring a local session.
        account: []u8,
        kind: Kind,
        /// New status bits (for joined/status); the member's prefix modes.
        status: u4,
        /// Previous status bits (for a `status` change), to diff the MODE.
        prev_status: u4,

        pub fn deinit(self: *MembershipDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.channel);
            allocator.free(self.nick);
            allocator.free(self.username);
            allocator.free(self.realname);
            allocator.free(self.host);
            allocator.free(self.setter);
            allocator.free(self.account);
            self.* = undefined;
        }
    };

    /// Drain the queued remote membership changes. Caller owns the slice and each
    /// delta's strings (call `deinit` per entry, then free the slice).
    pub fn takeMembershipChanges(self: *S2sPeer) ![]MembershipDelta {
        return self.membership_changes.toOwnedSlice(self.allocator);
    }

    /// A remote channel's aggregate boolean MODE flags changed. `channel` is
    /// heap-owned; the daemon frees it via `deinit` after applying/emitting.
    pub const ChannelModeFlagsDelta = struct {
        channel: []u8,
        flags: u16,

        pub fn deinit(self: *ChannelModeFlagsDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.channel);
            self.* = undefined;
        }
    };

    pub const ChannelModeStateDelta = struct {
        channel: []u8,
        private: bool,
        hidden: bool,
        ext_bits: u32,
        key: ?[]u8,
        limit: ?u32,
        throttle_joins: u16,
        throttle_secs: u32,
        forward: ?[]u8,

        pub fn deinit(self: *ChannelModeStateDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.channel);
            if (self.key) |key| allocator.free(key);
            if (self.forward) |forward| allocator.free(forward);
            self.* = undefined;
        }
    };

    pub const ChannelListDelta = struct {
        pub const Kind = route_table.ChannelListKind;

        channel: []u8,
        mask: []u8,
        setter: []u8,
        set_at: i64,
        kind: Kind,
        present: bool,

        pub fn deinit(self: *ChannelListDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.channel);
            allocator.free(self.mask);
            allocator.free(self.setter);
            self.* = undefined;
        }
    };

    /// A remote IRCX channel PROP mutation. Strings are heap-owned by the delta.
    /// `origin_node` is the ORIGINAL author's node short id (preserved verbatim
    /// across re-broadcast, NOT the immediate link peer). `origin_pubkey`/
    /// `origin_sig` carry the self-contained multi-hop origin signature when the
    /// fact was authored by a signing-capable node (empty on the legacy path);
    /// the daemon verifies them against `origin_node` before applying and stores
    /// them so a re-broadcast/burst re-emits the ORIGINAL author's signature.
    pub const ChannelPropDelta = struct {
        channel: []u8,
        key: []u8,
        value: []u8,
        owner: []u8,
        hlc: u64,
        present: bool,
        origin_node: NodeId,
        origin_pubkey: []u8,
        origin_sig: []u8,

        pub fn deinit(self: *ChannelPropDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.channel);
            allocator.free(self.key);
            allocator.free(self.value);
            allocator.free(self.owner);
            allocator.free(self.origin_pubkey);
            allocator.free(self.origin_sig);
            self.* = undefined;
        }
    };

    /// A remote IRCX user/member PROP mutation (ENTITY_PROP). The non-channel
    /// counterpart of `ChannelPropDelta`: `kind` distinguishes user vs member and
    /// `entity` is the raw entity id ("alice" or "#chat:bob"). Strings are
    /// heap-owned by the delta. `origin_node` is the ORIGINAL author's node short
    /// id (preserved verbatim across re-broadcast). `origin_pubkey`/`origin_sig`
    /// carry the self-contained multi-hop origin signature when signed (empty on
    /// the legacy path); the daemon verifies them against `origin_node` before
    /// applying and stores them so a re-broadcast/burst re-emits the ORIGINAL
    /// author's signature.
    pub const EntityPropDelta = struct {
        kind: entity_prop_event.EntityKind,
        entity: []u8,
        key: []u8,
        value: []u8,
        owner: []u8,
        hlc: u64,
        present: bool,
        origin_node: NodeId,
        origin_pubkey: []u8,
        origin_sig: []u8,

        pub fn deinit(self: *EntityPropDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.entity);
            allocator.free(self.key);
            allocator.free(self.value);
            allocator.free(self.owner);
            allocator.free(self.origin_pubkey);
            allocator.free(self.origin_sig);
            self.* = undefined;
        }
    };

    /// Drain queued remote channel MODE flag changes. Caller owns the slice and
    /// each delta's channel string (call `deinit` per entry, then free slice).
    pub fn takeChannelModeFlagChanges(self: *S2sPeer) ![]ChannelModeFlagsDelta {
        return self.channel_mode_flag_changes.toOwnedSlice(self.allocator);
    }

    /// Drain remote channel parameter/IRCX state changes. Caller owns the slice
    /// and each delta's strings.
    pub fn takeChannelModeStateChanges(self: *S2sPeer) ![]ChannelModeStateDelta {
        return self.channel_mode_state_changes.toOwnedSlice(self.allocator);
    }

    /// Drain remote channel list-mode changes (+b/+e/+I). Caller owns the slice
    /// and each delta's strings.
    pub fn takeChannelListChanges(self: *S2sPeer) ![]ChannelListDelta {
        return self.channel_list_changes.toOwnedSlice(self.allocator);
    }

    /// Drain queued remote channel PROP changes. Caller owns the slice and each
    /// delta's strings (call `deinit` per entry, then free the slice).
    pub fn takeChannelPropChanges(self: *S2sPeer) ![]ChannelPropDelta {
        return self.prop_changes.toOwnedSlice(self.allocator);
    }

    /// Drain queued remote user/member PROP changes (ENTITY_PROP). Caller owns the
    /// slice and each delta's strings (call `deinit` per entry, then free slice).
    pub fn takeEntityPropChanges(self: *S2sPeer) ![]EntityPropDelta {
        return self.entity_prop_changes.toOwnedSlice(self.allocator);
    }

    /// A remote channel's topic changed (LWW winner). Strings are heap-owned.
    pub const TopicDelta = struct {
        channel: []u8,
        topic: []u8,
        setter: []u8,
        set_at: i64,
        present: bool,

        pub fn deinit(self: *TopicDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.channel);
            allocator.free(self.topic);
            allocator.free(self.setter);
            self.* = undefined;
        }
    };

    /// A remote user changed nick (with refreshed identity). Strings heap-owned.
    pub const NickDelta = struct {
        old_nick: []u8,
        new_nick: []u8,
        username: []u8,
        realname: []u8,
        host: []u8,

        pub fn deinit(self: *NickDelta, allocator: std.mem.Allocator) void {
            allocator.free(self.old_nick);
            allocator.free(self.new_nick);
            allocator.free(self.username);
            allocator.free(self.realname);
            allocator.free(self.host);
            self.* = undefined;
        }
    };

    /// Drain remote channel topic changes. Caller owns the slice + each delta's
    /// strings (call `deinit` per entry, then free the slice).
    pub fn takeTopicChanges(self: *S2sPeer) ![]TopicDelta {
        return self.topic_changes.toOwnedSlice(self.allocator);
    }

    /// Drain remote user nick changes. Caller owns the slice + each delta's
    /// strings (call `deinit` per entry, then free the slice).
    pub fn takeNickChanges(self: *S2sPeer) ![]NickDelta {
        return self.nick_changes.toOwnedSlice(self.allocator);
    }

    /// Drain origin-mismatch + signature-rejection counts for daemon-side audit
    /// logging. Both the link-trust origin check (`acceptsDirectOrigin`) and the
    /// cryptographic envelope check (`verifiedPayload`) feed this one counter so
    /// the daemon's existing audit drain surfaces every rejected direct-owned
    /// frame regardless of which gate dropped it.
    pub fn takeRejectedOriginFrames(self: *S2sPeer) u64 {
        const n = self.rejected_origin_frames +| self.rejected_signature_frames +| self.rejected_admission_frames;
        self.rejected_origin_frames = 0;
        self.rejected_signature_frames = 0;
        self.rejected_admission_frames = 0;
        return n;
    }

    fn meshPassAllowsFrame(self: *const S2sPeer, frame_type: s2s_frame.FrameType) bool {
        if (self.admitted_frame_families == 0) return true;
        const family = meshPassFamilyForFrame(frame_type);
        return (self.admitted_frame_families & meshpassFrameFamilyBit(family)) != 0;
    }

    fn meshPassFamilyForFrame(frame_type: s2s_frame.FrameType) meshpass.FrameFamily {
        return switch (s2s_frame.frameSpec(frame_type).family) {
            .handshake, .control => .control,
            .crdt, .membership, .repair => .sync,
            .relay, .oper, .notification => .irc_app,
        };
    }

    fn meshpassFrameFamilyBit(family: meshpass.FrameFamily) u32 {
        return @as(u32, 1) << @as(u5, @intCast(@intFromEnum(family)));
    }

    /// Install (or clear) the daemon's residence-proof verifier. Borrowed; the
    /// daemon must outlive the peer (it does — links tear down before shutdown).
    pub fn setResidenceVerifier(self: *S2sPeer, verifier: ?ResidenceVerifier) void {
        self.residence_verifier = verifier;
    }

    /// The PER-CLAIM `account_trusted` bool for an incoming membership/nick
    /// claim (Design C verify order, fail-closed — ALL must hold or false):
    ///   1. the claim carries an account at all;
    ///   2. the carrying frame rode the ORIGIN-AUTHENTICATED path: the peer is
    ///      signing-capable (so `verifiedPayload` verified the envelope and
    ///      pinned `originShortId(pubkey)`) against a KNOWN remote node id —
    ///      an unsigned/plaintext link can never yield trust;
    ///   3. the daemon's verifier confirms a live residence proof binding
    ///      `{account, origin_node}` against the receiver-owned replicated
    ///      account pubkey.
    /// False ⇒ the resolver blanks the wire account and the claim takes the
    /// conservative UID path — today's safe behaviour, so F1 never reopens.
    fn accountResidenceTrusted(self: *S2sPeer, account: []const u8, origin_node: NodeId) bool {
        if (account.len == 0) return false;
        if (!self.peer_supports_signing or self.remote_node_id == 0) return false;
        const verifier = self.residence_verifier orelse return false;
        return verifier.verify(account, origin_node);
    }

    fn acceptsDirectOrigin(self: *S2sPeer, origin_node: NodeId) bool {
        if (self.remote_node_id != 0 and origin_node == self.remote_node_id) return true;
        self.rejected_origin_frames +|= 1;
        return false;
    }

    /// OUTBOUND fault predicate: whether we must FAULT the link rather than emit
    /// an unsigned frame to a non-signing peer. Gated on `signing_key != null`
    /// because a keyless node cannot sign its own egress at all — it must not
    /// fault every outbound frame just because the policy is set; it simply emits
    /// unsigned (and the far side's inbound gate decides whether to keep it).
    fn signedFramesRequired(self: *const S2sPeer) bool {
        return self.config.require_signed_frames and self.signing_key != null;
    }

    /// INBOUND admission predicate: whether an unsigned in-scope frame from a
    /// non-signing peer must be REJECTED. This is a receiver-side policy and is
    /// intentionally NOT gated on `signing_key != null`: verifying a signed
    /// envelope only needs the peer's embedded pubkey, so a keyless node can (and
    /// under `require_signed_frames` MUST) fail CLOSED on unsigned direct-owned
    /// state rather than raw-pass it. Decoupling this from `signedFramesRequired`
    /// closes the keyless fail-OPEN where a plaintext link applied unauthenticated
    /// peer state despite the operator setting the policy.
    fn inboundSignedFramesRequired(self: *const S2sPeer) bool {
        return self.config.require_signed_frames;
    }

    /// Emit an in-scope direct-owned frame, wrapping it in a `signed_frame`
    /// envelope (origin pubkey + signature over `type ++ payload`) when the peer
    /// advertised signing AND we hold a signing key. If signing is required, a
    /// non-signing peer faults instead of receiving unsigned state. Otherwise it
    /// is emitted as before for explicitly-permitted unsigned deployments. The
    /// wrap allocates a `header_len`-larger scratch; on any wrap failure we fall
    /// back to faulting the link (the caller's `try`).
    fn emitSignable(self: *S2sPeer, sink: ByteSink, frame_type: s2s_frame.FrameType, payload: []const u8) !void {
        if (!self.peer_supports_signing or self.signing_key == null) {
            if (self.signedFramesRequired()) return error.SignedFramesRequired;
            return emitFrame(self.allocator, sink, frame_type, payload);
        }
        const kp = &self.signing_key.?;
        const buf = try self.allocator.alloc(u8, signed_frame.header_len + payload.len);
        defer self.allocator.free(buf);
        const env = try signed_frame.wrap(buf, kp, @intFromEnum(frame_type), payload);
        try emitFrame(self.allocator, sink, frame_type, env);
    }

    /// Unwrap + verify an inbound in-scope frame against the peer's negotiated
    /// signing capability, returning the inner (authenticated) payload to hand to
    /// the existing `recvXxx`. Returns null when the frame must be dropped:
    ///   * a signing-capable peer sent an UNSIGNED (too-short / unverifiable)
    ///     frame — rejected (a signing peer MUST sign);
    ///   * the signature failed; or
    ///   * the self-certified origin `shortId(nodeIdFromPublicKey(pubkey))` did
    ///     not equal the remote peer's authenticated node id.
    /// Every rejection increments the signature-audit counter. For a non-signing
    /// peer the raw payload is returned unchanged only when unsigned operation is
    /// explicitly permitted (`require_signed_frames = false`) — even a KEYLESS
    /// node fails closed here when the policy is set (see
    /// `inboundSignedFramesRequired`).
    fn verifiedPayload(self: *S2sPeer, frame_type: s2s_frame.FrameType, payload: []const u8) ?[]const u8 {
        if (!self.peer_supports_signing) {
            if (self.inboundSignedFramesRequired()) {
                self.rejected_signature_frames +|= 1;
                return null;
            }
            return payload;
        }
        const u = signed_frame.unwrap(payload) catch {
            // A signing-capable peer's in-scope frame MUST be a signed envelope.
            self.rejected_signature_frames +|= 1;
            return null;
        };
        if (!signed_frame.verify(u, @intFromEnum(frame_type))) {
            self.rejected_signature_frames +|= 1;
            return null;
        }
        // Self-certifying origin: the key that signed must DERIVE the peer's
        // authenticated node id. This is the cryptographic upgrade of
        // `acceptsDirectOrigin` — a trust-pinned peer cannot assert another
        // node's origin because it lacks that node's private key.
        if (self.remote_node_id != 0 and signed_frame.originShortId(u.pubkey) != self.remote_node_id) {
            self.rejected_signature_frames +|= 1;
            return null;
        }
        return u.payload;
    }

    fn noteChannelModeStateClock(self: *S2sPeer, channel: []const u8, hlc: u64) bool {
        if (self.channel_mode_state_clocks.getPtr(channel)) |cur| {
            if (hlc <= cur.*) return false;
            cur.* = hlc;
            return true;
        }
        const owned = self.allocator.dupe(u8, channel) catch return false;
        self.channel_mode_state_clocks.put(self.allocator, owned, hlc) catch {
            self.allocator.free(owned);
            return false;
        };
        return true;
    }

    /// Apply an inbound MEMBERSHIP event to the route table (LWW by hlc). A
    /// malformed payload is dropped, never fatal to the link. A real add/remove/
    /// status-change is queued so the daemon can emit the matching live IRC line.
    fn recvMembership(self: *S2sPeer, frame_payload: []const u8, now_ms: u64) !void {
        const payload = self.verifiedPayload(.MEMBERSHIP, frame_payload) orelse return;
        const ev = membership_event.decode(payload) catch return;
        if (!self.acceptsDirectOrigin(ev.origin_node)) return;
        // The RECEIVER's local clock at apply time; stamped onto each present
        // member so the local-clock staleness GC (RouteTable.pruneStale) ages
        // members against this node's clock, never the announcer's wire hlc.
        const local_now: i64 = i64Ms(now_ms) catch 0;

        // Resolve a cross-namespace (local) or cross-node (remote) NICK collision
        // BEFORE applying, so the loser is renamed to its stable mesh UID rather
        // than silently overwriting an existing holder. Only present (join/status)
        // events introduce a claim; a part can never collide.
        var apply_nick: []const u8 = ev.nick;
        var surfaced_nick: ?[]const u8 = null;
        var skip_displace = false;
        var uid_buf: [nick_collision_uid_len]u8 = undefined;
        if (ev.present) {
            // Design C: the plaintext wire `account` is only honored by the
            // same-identity short-circuits when a residence proof verifies for
            // exactly this (account, origin) — per claim, receiver-owned keys.
            const account_trusted = self.accountResidenceTrusted(ev.account, ev.origin_node);
            switch (self.routes.resolveIncomingNick(ev.nick, ev.origin_node, ev.hlc, ev.account, account_trusted)) {
                .keep => {},
                .rename_to_uid => |uid| {
                    // Newcomer lost: store + surface this member under its UID.
                    @memcpy(uid_buf[0..uid.len], uid[0..]);
                    apply_nick = uid_buf[0..uid.len];
                    surfaced_nick = apply_nick;
                },
                .remote_same_account, .local_same_account => {
                    // Same authenticated identity duplicated across the mesh — a
                    // logged-in user present on more than one node, or a same-account
                    // remote incumbent. Apply the membership under the REAL nick
                    // (never a UID, never dropped): the cross-node channel relay gate
                    // is `channelMembers(channel) > 0`, so if this remote member is
                    // dropped and they are the ONLY member of the channel on their
                    // node, this node never relays channel messages to them. hlc LWW
                    // collapses the duplicate; the daemon's nickIsLiveLocal echo-
                    // suppression hides the duplicate JOIN/PART for a locally-homed
                    // nick. Never displace the holder to a UID.
                    skip_displace = true;
                },
                .reclaim_local => {
                    // The LOCAL holder is the STALE session (strictly-older mesh
                    // claim, checked by the resolver) and this remote claim is the
                    // live one. Store the remote claim so it is addressable, and ask
                    // the daemon to retire the local ghost. Suppress the normal JOIN
                    // delta — the ghost's QUIT surfaces the transition, and emitting
                    // a JOIN for a still-present local nick would be a duplicate.
                    _ = self.routes.applyMembership(ev.channel, ev.nick, ev.origin_node, ev.status, ev.hlc, true, .{
                        .username = ev.username,
                        .realname = ev.realname,
                        .host = ev.host,
                        .account = ev.account,
                        .real_host = ev.real_host,
                        .certfp = ev.certfp,
                    }, local_now) catch {};
                    self.queueMembershipDelta(&ev, .ghost_reclaim, 0, null) catch {};
                    return;
                },
            }
            // Newcomer wins over a different-node incumbent: displace the
            // incumbent to ITS uid first so two holders never coexist. Skipped for
            // a same-account reconcile, where LWW collapses the duplicate instead.
            if (surfaced_nick == null and !skip_displace) self.displaceIncumbent(&ev);
        }

        const res = self.routes.applyMembership(ev.channel, apply_nick, ev.origin_node, ev.status, ev.hlc, ev.present, .{
            .username = ev.username,
            .realname = ev.realname,
            .host = ev.host,
            .account = ev.account,
            .real_host = ev.real_host,
            .certfp = ev.certfp,
        }, local_now) catch return;
        const kind: MembershipDelta.Kind = switch (res.outcome) {
            .joined => .joined,
            .parted => .parted,
            .status_changed => .status,
            .unchanged => return,
        };
        self.queueMembershipDelta(&ev, kind, res.prev_status, surfaced_nick) catch return; // best-effort
    }

    /// When an incoming higher-priority claim wins a contested nick over a
    /// DIFFERENT-node incumbent, rename that incumbent to its own mesh UID across
    /// the route table and surface a `:contested NICK <incumbentUID>` line, so
    /// local clients never see the same nick held by two mesh users at once. No-op
    /// when there is no incumbent or the incumbent is the SAME node (own update).
    fn displaceIncumbent(self: *S2sPeer, ev: *const membership_event.MembershipEvent) void {
        self.displaceIncumbentForRename(ev.nick, ev.origin_node);
    }

    /// Shared incumbent-displacement: when a winning newcomer from `winner_node`
    /// takes `nick` from a DIFFERENT-node incumbent, rename that incumbent to its
    /// own mesh UID across the route table and surface a `:nick NICK <incumbentUID>`
    /// line, so local clients never see two mesh users holding one nick. No-op when
    /// there is no incumbent or it is the same node (an own update, not a contest).
    fn displaceIncumbentForRename(self: *S2sPeer, nick: []const u8, winner_node: NodeId) void {
        const incumbent_node = self.routes.nickNode(nick) orelse return;
        if (incumbent_node == winner_node) return;
        const uid = self.routes.incumbentLoserUid(nick) orelse return;
        var uid_buf: [nick_collision_uid_len]u8 = undefined;
        @memcpy(uid_buf[0..uid.len], uid[0..]);
        const new_nick = uid_buf[0..uid.len];
        // Pull the incumbent's stored identity so the NICK line renders its real
        // user@host (falls back to empties when the member is route-only).
        var ident = MemberIdentity{};
        if (self.routes.findMember(nick)) |m| {
            ident = .{ .username = m.username, .realname = m.realname, .host = m.host, .account = m.account };
        }
        const renamed = self.routes.renameNick(nick, new_nick, incumbent_node, ident) catch return;
        if (!renamed) return;
        self.queueForcedNickRename(nick, new_nick, ident) catch {}; // best-effort surface
    }

    /// Queue a NickDelta for a forced collision rename so the daemon emits the
    /// live `:old NICK new` line. Mirrors `recvNickChange`'s queueing, factored
    /// out so the displacement path reuses it.
    fn queueForcedNickRename(
        self: *S2sPeer,
        old_nick: []const u8,
        new_nick: []const u8,
        ident: MemberIdentity,
    ) !void {
        const on = try self.allocator.dupe(u8, old_nick);
        errdefer self.allocator.free(on);
        const nn = try self.allocator.dupe(u8, new_nick);
        errdefer self.allocator.free(nn);
        const un = try self.allocator.dupe(u8, ident.username);
        errdefer self.allocator.free(un);
        const rn = try self.allocator.dupe(u8, ident.realname);
        errdefer self.allocator.free(rn);
        const ho = try self.allocator.dupe(u8, ident.host);
        errdefer self.allocator.free(ho);
        try self.nick_changes.append(self.allocator, .{
            .old_nick = on,
            .new_nick = nn,
            .username = un,
            .realname = rn,
            .host = ho,
        });
    }

    /// Dupe an event's strings into an owned `MembershipDelta` and queue it.
    /// Any allocation failure unwinds the partial copies (errdefer chain).
    /// `nick_override`, when non-null, replaces `ev.nick` so a collision loser
    /// surfaces under its forced mesh UID instead of the contested wire nick.
    fn queueMembershipDelta(
        self: *S2sPeer,
        ev: *const membership_event.MembershipEvent,
        kind: MembershipDelta.Kind,
        prev_status: u4,
        nick_override: ?[]const u8,
    ) !void {
        const ch = try self.allocator.dupe(u8, ev.channel);
        errdefer self.allocator.free(ch);
        const nk = try self.allocator.dupe(u8, nick_override orelse ev.nick);
        errdefer self.allocator.free(nk);
        const un = try self.allocator.dupe(u8, ev.username);
        errdefer self.allocator.free(un);
        const rn = try self.allocator.dupe(u8, ev.realname);
        errdefer self.allocator.free(rn);
        const ho = try self.allocator.dupe(u8, ev.host);
        errdefer self.allocator.free(ho);
        const st = try self.allocator.dupe(u8, ev.setter);
        errdefer self.allocator.free(st);
        const ac = try self.allocator.dupe(u8, ev.account);
        errdefer self.allocator.free(ac);
        try self.membership_changes.append(self.allocator, .{
            .channel = ch,
            .nick = nk,
            .username = un,
            .realname = rn,
            .host = ho,
            .setter = st,
            .account = ac,
            .kind = kind,
            .status = ev.status,
            .prev_status = prev_status,
        });
    }

    /// Apply an inbound CHANNEL_MODE_FLAGS event to the route table (LWW by hlc).
    /// Malformed/stale/no-op payloads are dropped; only a real aggregate change is
    /// queued for the daemon to apply to its local world.
    fn recvChannelModeFlags(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.CHANNEL_MODE_FLAGS, frame_payload) orelse return;
        const ev = channel_mode_flags_event.decode(payload) catch return;
        if (!self.acceptsDirectOrigin(ev.origin_node)) return;
        const outcome = self.routes.applyChannelModeFlags(ev.channel, ev.origin_node, ev.flags, ev.hlc) catch return;
        if (outcome == .unchanged) return;
        const ch = self.allocator.dupe(u8, ev.channel) catch return;
        self.channel_mode_flag_changes.append(self.allocator, .{
            .channel = ch,
            .flags = ev.flags,
        }) catch self.allocator.free(ch);
    }

    /// Apply an inbound CHANNEL_LIST event to the route table (LWW by hlc), then
    /// queue add/remove transitions for the daemon. Malformed or stale payloads
    /// are dropped and never fault the link.
    fn recvChannelList(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.CHANNEL_LIST, frame_payload) orelse return;
        const ev = channel_list_event.decode(payload) catch return;
        if (!self.acceptsDirectOrigin(ev.origin_node)) return;
        const res = self.routes.applyChannelList(ev.channel, ev.kind, ev.mask, ev.setter, ev.set_at, ev.origin_node, ev.hlc, ev.present) catch return;
        if (res.outcome == .unchanged) return;

        const ch = self.allocator.dupe(u8, ev.channel) catch return;
        const mask = self.allocator.dupe(u8, ev.mask) catch {
            self.allocator.free(ch);
            return;
        };
        const setter = self.allocator.dupe(u8, ev.setter) catch {
            self.allocator.free(ch);
            self.allocator.free(mask);
            return;
        };

        self.channel_list_changes.append(self.allocator, .{
            .channel = ch,
            .mask = mask,
            .setter = setter,
            .set_at = ev.set_at,
            .kind = ev.kind,
            .present = ev.present,
        }) catch {
            self.allocator.free(ch);
            self.allocator.free(mask);
            self.allocator.free(setter);
        };
    }

    /// Emit a MEMBERSHIP event to the peer announcing a local member's presence
    /// (or departure) in `channel`, carrying the member's real identity
    /// (username/realname/visible host) so the peer renders `user@host` instead
    /// of a placeholder. Best-effort; only meaningful once established.
    pub fn sendMembership(
        self: *S2sPeer,
        sink: ByteSink,
        channel: []const u8,
        nick: []const u8,
        status: u4,
        hlc: u64,
        present: bool,
        ident: MemberIdentity,
        setter: []const u8,
    ) !void {
        const ev = membership_event.MembershipEvent{
            .present = present,
            .status = status,
            .origin_node = self.local_node_id,
            .hlc = hlc,
            .channel = channel,
            .nick = nick,
            .username = truncated(ident.username, membership_event.max_username_len),
            .realname = truncated(ident.realname, membership_event.max_realname_len),
            .host = truncated(ident.host, membership_event.max_host_len),
            .setter = truncated(setter, membership_event.max_setter_len),
            // Only append the account block to a peer that negotiated support, so an
            // older peer never sees the extra trailing bytes (which it would reject).
            .account = if (self.peer_supports_account) truncated(ident.account, membership_event.max_account_len) else "",
            // SENSITIVE: real_host/certfp ride ONLY a secured, oper-info-capable peer
            // (peer_supports_oper_info is set only when a signing-keyed link advertised
            // cap_member_oper_info), so they never traverse a plaintext leg.
            .real_host = if (self.peer_supports_oper_info) truncated(ident.real_host, membership_event.max_real_host_len) else "",
            .certfp = if (self.peer_supports_oper_info) truncated(ident.certfp, membership_event.max_certfp_len) else "",
        };
        var buf: [membership_event.max_encoded_len]u8 = undefined;
        const wire = try membership_event.encode(ev, &buf);
        try self.emitSignable(sink, .MEMBERSHIP, wire);
    }

    /// Emit a CHANNEL_MODE_FLAGS aggregate to the peer. Best-effort; only
    /// meaningful once established.
    pub fn sendChannelModeFlags(
        self: *S2sPeer,
        sink: ByteSink,
        channel: []const u8,
        flags: u16,
        hlc: u64,
    ) !void {
        const ev = channel_mode_flags_event.ChannelModeFlagsEvent{
            .flags = flags,
            .origin_node = self.local_node_id,
            .hlc = hlc,
            .channel = channel,
        };
        var buf: [channel_mode_flags_event.max_channel_len + 32]u8 = undefined;
        const wire = try channel_mode_flags_event.encode(ev, &buf);
        try self.emitSignable(sink, .CHANNEL_MODE_FLAGS, wire);
    }

    /// Emit a CHANNEL_LIST event to announce local +b/+e/+I state.
    pub fn sendChannelList(
        self: *S2sPeer,
        sink: ByteSink,
        channel: []const u8,
        kind: route_table.ChannelListKind,
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) !void {
        const ev = channel_list_event.ChannelListEvent{
            .present = present,
            .kind = kind,
            .origin_node = self.local_node_id,
            .hlc = hlc,
            .set_at = set_at,
            .channel = channel,
            .mask = mask,
            .setter = setter,
        };
        var buf: [channel_list_event.max_channel_len + channel_list_event.max_mask_len + channel_list_event.max_setter_len + 40]u8 = undefined;
        const wire = try channel_list_event.encode(ev, &buf);
        try self.emitSignable(sink, .CHANNEL_LIST, wire);
    }

    /// Queue an inbound CHANNEL_PROP event for daemon-side LWW apply. Malformed
    /// payloads and allocation failures are dropped without faulting the link.
    ///
    /// A CHANNEL_PROP fact is a CRDT fact that the mesh RE-BROADCASTS with the
    /// ORIGINAL `origin_node` preserved, so the direct-peer origin gate is only
    /// the LEGACY (unsigned) trust level: it applies when the fact carries no
    /// self-contained multi-hop signature (the immediate peer is then asserted as
    /// the author). When the fact carries a `(origin_pubkey, origin_sig)` pair,
    /// the origin is a (possibly third) node certified end-to-end by the daemon's
    /// `verifyOrigin` check, so the direct-origin gate is intentionally bypassed
    /// here — a relay legitimately forwards a fact authored elsewhere. The pubkey/
    /// sig are staged so the daemon can verify against the claimed origin and
    /// preserve the ORIGINAL signature on re-broadcast.
    fn recvChannelProp(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.CHANNEL_PROP, frame_payload) orelse return;
        const ev = channel_prop_event.decode(payload) catch return;
        const signed = ev.origin_pubkey.len != 0;
        // Legacy unsigned facts keep the direct-owned origin gate (the peer must
        // BE the asserted origin). Signed multi-hop facts skip it: the daemon's
        // self-certifying signature check is the authoritative origin gate.
        if (!signed and !self.acceptsDirectOrigin(ev.origin_node)) return;

        const ch = self.allocator.dupe(u8, ev.channel) catch return;
        errdefer self.allocator.free(ch);
        const key = self.allocator.dupe(u8, ev.key) catch return;
        errdefer self.allocator.free(key);
        const value = self.allocator.dupe(u8, ev.value) catch return;
        errdefer self.allocator.free(value);
        const owner = self.allocator.dupe(u8, ev.owner) catch return;
        errdefer self.allocator.free(owner);
        const origin_pubkey = self.allocator.dupe(u8, ev.origin_pubkey) catch return;
        errdefer self.allocator.free(origin_pubkey);
        const origin_sig = self.allocator.dupe(u8, ev.origin_sig) catch return;
        errdefer self.allocator.free(origin_sig);

        self.prop_changes.append(self.allocator, .{
            .channel = ch,
            .key = key,
            .value = value,
            .owner = owner,
            .hlc = ev.hlc,
            .present = ev.present,
            .origin_node = ev.origin_node,
            .origin_pubkey = origin_pubkey,
            .origin_sig = origin_sig,
        }) catch return;
    }

    /// Origin attribution for a CHANNEL_PROP emit. A prop fact is a CRDT fact the
    /// mesh re-broadcasts with the ORIGINAL author preserved, so the caller can
    /// override the stamped origin and carry the author's self-contained multi-hop
    /// signature verbatim:
    ///   * `node == 0`  => the LOCAL node is the author (legacy/direct-owned path);
    ///     `self.local_node_id` is stamped. `pubkey`/`sig` may still be supplied
    ///     when this node signs its own freshly-authored fact.
    ///   * `node != 0`  => a RE-BROADCAST of a fact authored elsewhere; `node` is
    ///     stamped as the origin and `pubkey`/`sig` are the original author's,
    ///     forwarded byte-for-byte (this node never re-signs).
    /// `pubkey`/`sig` are empty on the unsigned path. They are encoded inside the
    /// CHANNEL_PROP payload (NOT the per-link `signed_frame` envelope, which still
    /// authenticates the immediate hop independently).
    pub const PropOrigin = struct {
        node: NodeId = 0,
        pubkey: []const u8 = "",
        sig: []const u8 = "",
    };

    /// Emit a CHANNEL_PROP event to the peer. Best-effort; only meaningful once
    /// established. `origin` selects local-authored vs re-broadcast attribution
    /// and carries the multi-hop origin signature (see `PropOrigin`).
    pub fn sendChannelProp(
        self: *S2sPeer,
        sink: ByteSink,
        channel: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
        origin: PropOrigin,
    ) !void {
        const ev = channel_prop_event.ChannelPropEvent{
            .present = present,
            .origin_node = if (origin.node != 0) origin.node else self.local_node_id,
            .hlc = hlc,
            .channel = channel,
            .key = key,
            .value = value,
            .owner = owner,
            .origin_pubkey = origin.pubkey,
            .origin_sig = origin.sig,
        };
        var buf: [channel_prop_event.max_channel_len + channel_prop_event.max_key_len + channel_prop_event.max_value_len + channel_prop_event.max_owner_len + 32 + 1 + channel_prop_event.pubkey_len + channel_prop_event.sig_len]u8 = undefined;
        const wire = try channel_prop_event.encode(ev, &buf);
        try self.emitSignable(sink, .CHANNEL_PROP, wire);
    }

    /// Queue an inbound ENTITY_PROP (user/member) event for daemon-side LWW apply.
    /// Malformed payloads and allocation failures are dropped without faulting the
    /// link. Mirrors `recvChannelProp` exactly: a signed fact bypasses the
    /// direct-peer origin gate (the daemon's self-certifying signature check is the
    /// authoritative origin gate for a re-broadcast authored elsewhere), while a
    /// legacy unsigned fact keeps the direct-owned origin gate.
    fn recvEntityProp(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.ENTITY_PROP, frame_payload) orelse return;
        const ev = entity_prop_event.decode(payload) catch return;
        const signed = ev.origin_pubkey.len != 0;
        if (!signed and !self.acceptsDirectOrigin(ev.origin_node)) return;

        const entity = self.allocator.dupe(u8, ev.entity) catch return;
        errdefer self.allocator.free(entity);
        const key = self.allocator.dupe(u8, ev.key) catch return;
        errdefer self.allocator.free(key);
        const value = self.allocator.dupe(u8, ev.value) catch return;
        errdefer self.allocator.free(value);
        const owner = self.allocator.dupe(u8, ev.owner) catch return;
        errdefer self.allocator.free(owner);
        const origin_pubkey = self.allocator.dupe(u8, ev.origin_pubkey) catch return;
        errdefer self.allocator.free(origin_pubkey);
        const origin_sig = self.allocator.dupe(u8, ev.origin_sig) catch return;
        errdefer self.allocator.free(origin_sig);

        self.entity_prop_changes.append(self.allocator, .{
            .kind = ev.kind,
            .entity = entity,
            .key = key,
            .value = value,
            .owner = owner,
            .hlc = ev.hlc,
            .present = ev.present,
            .origin_node = ev.origin_node,
            .origin_pubkey = origin_pubkey,
            .origin_sig = origin_sig,
        }) catch return;
    }

    /// Emit an ENTITY_PROP (user/member) event to the peer. Best-effort; only
    /// meaningful once established. `origin` selects local-authored vs re-broadcast
    /// attribution and carries the multi-hop origin signature (see `PropOrigin`).
    pub fn sendEntityProp(
        self: *S2sPeer,
        sink: ByteSink,
        kind: entity_prop_event.EntityKind,
        entity: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
        origin: PropOrigin,
    ) !void {
        const ev = entity_prop_event.EntityPropEvent{
            .present = present,
            .kind = kind,
            .origin_node = if (origin.node != 0) origin.node else self.local_node_id,
            .hlc = hlc,
            .entity = entity,
            .key = key,
            .value = value,
            .owner = owner,
            .origin_pubkey = origin.pubkey,
            .origin_sig = origin.sig,
        };
        var buf: [entity_prop_event.max_entity_len + entity_prop_event.max_key_len + entity_prop_event.max_value_len + entity_prop_event.max_owner_len + 32 + 1 + entity_prop_event.pubkey_len + entity_prop_event.sig_len]u8 = undefined;
        const wire = try entity_prop_event.encode(ev, &buf);
        try self.emitSignable(sink, .ENTITY_PROP, wire);
    }

    /// Queue a remote parameter/IRCX channel-state snapshot for daemon apply.
    /// Only the authenticated direct peer may assert direct-owned state frames.
    fn recvChannelModeState(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.CHANNEL_MODE_STATE, frame_payload) orelse return;
        const ev = channel_mode_state_event.decode(payload) catch return;
        if (!self.acceptsDirectOrigin(ev.origin_node)) return;
        if (!self.noteChannelModeStateClock(ev.channel, ev.hlc)) return;

        const ch = self.allocator.dupe(u8, ev.channel) catch return;
        errdefer self.allocator.free(ch);
        const key = if (ev.key) |k| try self.allocator.dupe(u8, k) else null;
        errdefer if (key) |k| self.allocator.free(k);
        const forward = if (ev.forward) |f| try self.allocator.dupe(u8, f) else null;
        errdefer if (forward) |f| self.allocator.free(f);

        try self.channel_mode_state_changes.append(self.allocator, .{
            .channel = ch,
            .private = ev.private,
            .hidden = ev.hidden,
            .ext_bits = ev.ext_bits,
            .key = key,
            .limit = ev.limit,
            .throttle_joins = ev.throttle_joins,
            .throttle_secs = ev.throttle_secs,
            .forward = forward,
        });
    }

    /// Emit a full parameter/IRCX channel-state snapshot. The caller supplies the
    /// state; this peer stamps its authenticated local origin into the envelope.
    pub fn sendChannelModeState(
        self: *S2sPeer,
        sink: ByteSink,
        ev: channel_mode_state_event.ChannelModeStateEvent,
    ) !void {
        var out_ev = ev;
        out_ev.origin_node = self.local_node_id;
        var buf: [channel_mode_state_event.max_channel_len + channel_mode_state_event.max_key_len + channel_mode_state_event.max_forward_len + 80]u8 = undefined;
        const wire = try channel_mode_state_event.encode(out_ev, &buf);
        try self.emitSignable(sink, .CHANNEL_MODE_STATE, wire);
    }

    /// Apply an inbound TOPIC event to the route table (LWW by hlc). Malformed or
    /// stale payloads are dropped; a real change is queued so the daemon can apply
    /// it to its world and emit a live `TOPIC` line.
    fn recvTopic(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.TOPIC, frame_payload) orelse return;
        const ev = topic_event.decode(payload) catch return;
        if (!self.acceptsDirectOrigin(ev.origin_node)) return;
        const outcome = self.routes.applyTopic(ev.channel, ev.origin_node, ev.hlc) catch return;
        if (outcome == .unchanged) return;

        const ch = self.allocator.dupe(u8, ev.channel) catch return;
        const topic = self.allocator.dupe(u8, ev.topic) catch {
            self.allocator.free(ch);
            return;
        };
        const setter = self.allocator.dupe(u8, ev.setter) catch {
            self.allocator.free(ch);
            self.allocator.free(topic);
            return;
        };
        self.topic_changes.append(self.allocator, .{
            .channel = ch,
            .topic = topic,
            .setter = setter,
            .set_at = ev.set_at,
            .present = ev.present,
        }) catch {
            self.allocator.free(ch);
            self.allocator.free(topic);
            self.allocator.free(setter);
        };
    }

    /// Emit a TOPIC event to the peer announcing a local channel topic change.
    pub fn sendTopic(
        self: *S2sPeer,
        sink: ByteSink,
        channel: []const u8,
        topic: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) !void {
        const ev = topic_event.TopicEvent{
            .present = present,
            .origin_node = self.local_node_id,
            .hlc = hlc,
            .set_at = set_at,
            .channel = channel,
            .topic = topic,
            .setter = setter,
        };
        var buf: [topic_event.max_channel_len + topic_event.max_topic_len + topic_event.max_setter_len + 40]u8 = undefined;
        const wire = try topic_event.encode(ev, &buf);
        try self.emitSignable(sink, .TOPIC, wire);
    }

    /// Apply an inbound NICKCHANGE event: rename the user in the route table +
    /// rosters, then queue a delta so the daemon can emit the live `NICK` line.
    /// Malformed payloads and no-op renames are dropped.
    fn recvNickChange(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.NICKCHANGE, frame_payload) orelse return;
        const ev = nick_event.decode(payload) catch return;
        if (!self.acceptsDirectOrigin(ev.origin_node)) return;

        // A remote rename into a nick already held (locally, or by a different
        // mesh node) makes the RENAMER the loser: redirect it to its mesh UID
        // instead of clobbering the holder. A same-node incumbent is the user's
        // own prior nick, never a collision (resolveIncomingNick handles both).
        const ident = MemberIdentity{
            .username = ev.username,
            .realname = ev.realname,
            .host = ev.host,
            .account = ev.account,
        };
        var target_nick: []const u8 = ev.new_nick;
        var uid_buf: [nick_collision_uid_len]u8 = undefined;
        switch (self.routes.resolveIncomingNick(ev.new_nick, ev.origin_node, ev.hlc, ev.account, self.accountResidenceTrusted(ev.account, ev.origin_node))) {
            .keep => self.displaceIncumbentForRename(ev.new_nick, ev.origin_node),
            .rename_to_uid => |uid| {
                @memcpy(uid_buf[0..uid.len], uid[0..]);
                target_nick = uid_buf[0..uid.len];
            },
            // Same logged-in identity renaming into a nick a LOCAL client holds:
            // never UID-rename the live user. Keep the wire nick and let the
            // holders' nodes reconcile (the account-keyed reclaim retires the ghost).
            // The reclaim itself is driven by the MEMBERSHIP path (a nick-change
            // collision is rarer and the same burst re-announces memberships), so
            // both same-account outcomes are a no-op here.
            .local_same_account, .reclaim_local => {},
            // Same identity as a different-node incumbent: accept the rename and let
            // LWW converge; do NOT displace the incumbent to a UID.
            .remote_same_account => {},
        }

        const renamed = self.routes.renameNick(ev.old_nick, target_nick, ev.origin_node, ident) catch return;
        if (!renamed) return;

        const old_nick = self.allocator.dupe(u8, ev.old_nick) catch return;
        const new_nick = self.allocator.dupe(u8, target_nick) catch {
            self.allocator.free(old_nick);
            return;
        };
        const username = self.allocator.dupe(u8, ev.username) catch {
            self.allocator.free(old_nick);
            self.allocator.free(new_nick);
            return;
        };
        const realname = self.allocator.dupe(u8, ev.realname) catch {
            self.allocator.free(old_nick);
            self.allocator.free(new_nick);
            self.allocator.free(username);
            return;
        };
        const host = self.allocator.dupe(u8, ev.host) catch {
            self.allocator.free(old_nick);
            self.allocator.free(new_nick);
            self.allocator.free(username);
            self.allocator.free(realname);
            return;
        };
        self.nick_changes.append(self.allocator, .{
            .old_nick = old_nick,
            .new_nick = new_nick,
            .username = username,
            .realname = realname,
            .host = host,
        }) catch {
            self.allocator.free(old_nick);
            self.allocator.free(new_nick);
            self.allocator.free(username);
            self.allocator.free(realname);
            self.allocator.free(host);
        };
    }

    /// Emit a NICKCHANGE event to the peer for a local user's nick change.
    pub fn sendNickChange(
        self: *S2sPeer,
        sink: ByteSink,
        old_nick: []const u8,
        new_nick: []const u8,
        ident: MemberIdentity,
        hlc: u64,
    ) !void {
        const ev = nick_event.NickEvent{
            .origin_node = self.local_node_id,
            .hlc = hlc,
            .old_nick = old_nick,
            .new_nick = new_nick,
            .username = ident.username,
            .realname = ident.realname,
            .host = ident.host,
            // Gated like MEMBERSHIP: only a member-account-capable peer gets it.
            .account = if (self.peer_supports_account) truncated(ident.account, nick_event.max_account_len) else "",
        };
        var buf: [nick_event.max_nick_len * 2 + nick_event.max_user_len + nick_event.max_real_len + nick_event.max_host_len + nick_event.max_account_len + 32]u8 = undefined;
        const wire = try nick_event.encode(ev, &buf);
        try self.emitSignable(sink, .NICKCHANGE, wire);
    }

    /// Remote members the peer has announced for `channel` (borrowed roster).
    pub fn channelMembers(self: *const S2sPeer, channel: []const u8) []const route_table.Member {
        return self.routes.channelMembers(channel);
    }

    /// Count of distinct remote nicks this peer has announced into the route
    /// table — i.e. users homed on the node across this link. Used to compute a
    /// mesh-wide user total (local nicks + remote nicks).
    pub fn remoteNickCount(self: *const S2sPeer) usize {
        return self.routes.nickCount();
    }

    pub fn channelModeFlags(self: *const S2sPeer, channel: []const u8) ?route_table.ChannelModeFlags {
        return self.routes.channelModeFlags(channel);
    }

    /// Iterator over channel names with a live remote roster on this peer (used
    /// by LIST/LISTX for mesh-wide channel enumeration). Borrowed names, valid
    /// until the next membership mutation.
    pub fn channelNames(self: *const S2sPeer) ChannelNameIterator {
        return self.routes.channelNames();
    }

    fn recvHandshake(self: *S2sPeer, payload: []const u8, sink: ByteSink, now_ms: u64, rng_seed: u64) !void {
        const hs = try decodeHandshake(payload);
        // remote_node_id == 0 means "unknown peer" (an accepting/dialing side that
        // does not know the remote's node id in advance): adopt it from the first
        // handshake. Otherwise enforce the expected identity.
        if (self.remote_node_id == 0) {
            self.remote_node_id = hs.node_id;
        } else if (hs.node_id != self.remote_node_id) {
            return error.UnexpectedRemote;
        }

        // Record the negotiated signing capability. From here on, in-scope frames
        // to/from a signing-capable peer travel inside a `signed_frame` envelope,
        // and an UNSIGNED in-scope frame from such a peer is rejected.
        self.peer_supports_signing = (hs.caps & cap_frame_signing) != 0;
        self.peer_supports_account = (hs.caps & cap_member_account) != 0;
        self.peer_supports_oper_info = (hs.caps & cap_member_oper_info) != 0;
        self.peer_supports_repair = (hs.caps & cap_repair_frames) != 0;
        if (self.signedFramesRequired() and !self.peer_supports_signing) {
            return error.SignedFramesRequired;
        }

        try self.rememberRemote(hs, now_ms);
        if (!self.handshake_sent) try self.emitHandshake(sink);
        if (!self.established) {
            try self.session.establish(hs.epoch_ms, now_ms, rng_seed);
            self.session.clearOutbound();
            self.established = true;
            try self.emitBurst(sink);
        }
    }

    fn rememberRemote(self: *S2sPeer, hs: Handshake, now_ms: u64) !void {
        // Run all fallible work first so a registry/route failure cannot leave a
        // dangling self.remote_name. Only after everything succeeds do we swap in
        // the freshly-duped name (transactional: old name freed last).
        const owned_name = try self.allocator.dupe(u8, hs.name);
        errdefer self.allocator.free(owned_name);

        _ = try self.registry.addOrUpdate(.{
            .node_id = hs.node_id,
            .name = hs.name,
            .description = hs.description,
            .hopcount = 1,
            .uplink = self.local_node_id,
            .last_seen_ms = try i64Ms(now_ms),
        });
        try self.routes.setNickLocation(hs.name, hs.node_id);

        self.remote_epoch_ms = hs.epoch_ms;
        self.allocator.free(self.remote_name);
        self.remote_name = owned_name;
    }

    fn emitHandshake(self: *S2sPeer, sink: ByteSink) !void {
        // Advertise frame signing only when we actually hold a signing key (i.e.
        // a secured link supplied the node identity). Plaintext links have no key,
        // so they never advertise it and stay on the legacy unsigned path.
        // We always understand the optional member-account block, so advertise it
        // unconditionally; emission still only happens to a peer that does too.
        var caps: u8 = cap_member_account | cap_repair_frames;
        // Frame signing AND oper-info ride ONLY a secured link (one holding a node
        // signing key). real_host/certfp are sensitive, so a plaintext leg never
        // advertises — and thus never receives — them.
        if (self.signing_key != null) caps |= cap_frame_signing | cap_member_oper_info;
        const payload = try encodeHandshake(self.allocator, .{
            .node_id = self.local_node_id,
            .epoch_ms = self.local_epoch_ms,
            .name = self.server_name,
            .description = self.description,
            .caps = caps,
        });
        defer self.allocator.free(payload);
        try emitFrame(self.allocator, sink, .HANDSHAKE, payload);
        self.handshake_sent = true;
    }

    fn emitBurst(self: *S2sPeer, sink: ByteSink) !void {
        if (self.burst_sent) return;
        const encoded = try burst.serialize(self.allocator, self.state, self.config.link.burst_limits);
        defer self.allocator.free(encoded);
        try emitFrame(self.allocator, sink, .BURST, encoded);
        self.burst_sent = true;
    }

    fn mergeDelta(self: *S2sPeer, payload: []const u8) !void {
        var incoming = ChannelCrdt.init(self.allocator, self.state.replica_id);
        defer incoming.deinit();
        try burst.apply(self.allocator, &incoming, payload, self.config.link.burst_limits);
        try self.state.merge(&incoming);
        try self.refreshChannelRoute();
    }

    fn recvGossip(self: *S2sPeer, payload: []const u8, now_ms: u64, rng_seed: u64) !void {
        var gossip_payload = try decodeGossip(self.allocator, payload);
        defer gossip_payload.deinit(self.allocator);
        var rng = membership_view.Rng.init(mixSeed(rng_seed, self.local_node_id, self.remote_node_id));
        try self.session.gossip.applyPayload(&gossip_payload, try i64Ms(now_ms), &rng);
    }

    fn recvRepairSummary(self: *S2sPeer, frame_payload: []const u8, sink: ByteSink) !void {
        const payload = self.verifiedPayload(.REPAIR_SUMMARY, frame_payload) orelse return;
        var remote = decodeRepairSummary(self.allocator, payload) catch return;
        defer remote.deinit();
        var local = anti_entropy_repair.summarize(self.allocator, self.state) catch return;
        defer local.deinit();
        var ranges = anti_entropy_repair.diff(self.allocator, &local, &remote) catch return;
        defer ranges.deinit();
        if (ranges.ranges.len == 0) return;
        var request = anti_entropy_repair.buildRepairRequest(self.allocator, &ranges) catch return;
        defer request.deinit();
        const bytes = encodeRepairRequest(self.allocator, &request) catch return;
        defer self.allocator.free(bytes);
        try self.emitSignable(sink, .REPAIR_REQUEST, bytes);
    }

    fn recvRepairRequest(self: *S2sPeer, frame_payload: []const u8, sink: ByteSink) !void {
        const payload = self.verifiedPayload(.REPAIR_REQUEST, frame_payload) orelse return;
        var request = decodeRepairRequest(self.allocator, payload) catch return;
        defer request.deinit();
        var response = anti_entropy_repair.buildRepairResponse(self.allocator, self.state, &request) catch return;
        defer response.deinit();
        if (response.records.len == 0) return;
        const bytes = encodeRepairResponse(self.allocator, &response) catch return;
        defer self.allocator.free(bytes);
        try self.emitSignable(sink, .REPAIR_RESPONSE, bytes);
    }

    fn recvRepairResponse(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.REPAIR_RESPONSE, frame_payload) orelse return;
        var response = decodeRepairResponse(self.allocator, payload) catch return;
        defer response.deinit();
        anti_entropy_repair.applyRepairResponse(self.allocator, self.state, &response) catch return;
        if (response.records.len != 0) self.repair_resync_requested = true;
        try self.refreshChannelRoute();
    }

    fn refreshChannelRoute(self: *S2sPeer) !void {
        if (self.channel_name.len == 0) return;
        self.routes.removeNode(self.remote_node_id);
        var live: usize = 0;
        for (self.state.members.items) |entry| {
            if (entry.adds.items.len == 0) continue;
            live += 1;
        }
        if (live == 0) return;
        try self.routes.addChannelMember(self.channel_name, self.remote_node_id);
    }

    fn closeRemote(self: *S2sPeer) void {
        self.established = false;
        if (self.remote_node_id != 0) _ = self.registry.remove(self.remote_node_id) catch false;
        self.routes.removeNode(self.remote_node_id);
        self.session.link.close();
    }
};

pub const Peer = S2sPeer;

fn emitFrame(allocator: Allocator, sink: ByteSink, frame_type: s2s_frame.FrameType, payload: []const u8) !void {
    const total = try s2s_frame.encodedLen(payload.len);
    const out = try allocator.alloc(u8, total);
    defer allocator.free(out);
    const encoded = try s2s_frame.encode(frame_type, payload, out);
    try sink.writeAll(encoded);
}

fn encodeHandshake(allocator: Allocator, hs: Handshake) ![]u8 {
    if (hs.name.len > std.math.maxInt(u16) or hs.description.len > std.math.maxInt(u16)) return error.HandshakeTooLarge;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &handshake_magic);
    try out.append(allocator, handshake_version);
    try writeU64(&out, allocator, hs.node_id);
    try writeU64(&out, allocator, hs.epoch_ms);
    try writeBytes16(&out, allocator, hs.name);
    try writeBytes16(&out, allocator, hs.description);
    // v2 capability bitfield. A v1 peer omits this; our decoder treats a missing
    // byte as caps == 0, so emitting it never breaks an old peer.
    try out.append(allocator, hs.caps);
    return out.toOwnedSlice(allocator);
}

fn decodeHandshake(bytes: []const u8) !Handshake {
    var r = Reader{ .buf = bytes };
    for (handshake_magic) |want| {
        if (try r.readByte() != want) return error.BadHandshake;
    }
    // Accept this version and any older one we still understand. v1 omitted the
    // capability byte; v2 appends it. A newer (unknown) version is rejected.
    const ver = try r.readByte();
    if (ver == 0 or ver > handshake_version) return error.UnsupportedHandshake;
    var out = Handshake{
        .node_id = try r.readU64(),
        .epoch_ms = try r.readU64(),
        .name = try r.readBytes16(),
        .description = try r.readBytes16(),
        .caps = 0,
    };
    // v2+ carries a trailing capability bitfield; v1 ends after the description.
    if (ver >= 2) out.caps = try r.readByte();
    if (!r.done()) return error.TrailingBytes;
    return out;
}

fn encodeGossip(allocator: Allocator, payload: *const gossip_round.GossipPayload) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try writeU64(&out, allocator, payload.origin);
    try writeU64(&out, allocator, payload.origin_incarnation);
    try writeVarint(&out, allocator, payload.member_deltas.items.len);
    for (payload.member_deltas.items) |delta| {
        try writeU64(&out, allocator, delta.id);
        try out.append(allocator, @intFromEnum(delta.state));
        try writeU64(&out, allocator, delta.incarnation);
    }
    try writeVarint(&out, allocator, payload.suspicions.items.len);
    for (payload.suspicions.items) |s| {
        try writeU64(&out, allocator, s.node);
        try writeU64(&out, allocator, s.incarnation);
        try writeU64(&out, allocator, s.witness);
    }
    return out.toOwnedSlice(allocator);
}

fn decodeGossip(allocator: Allocator, bytes: []const u8) !gossip_round.GossipPayload {
    var r = Reader{ .buf = bytes };
    var out = gossip_round.GossipPayload{
        .origin = try r.readU64(),
        .origin_incarnation = try r.readU64(),
    };
    errdefer out.deinit(allocator);
    const deltas = try r.readVarint();
    var i: usize = 0;
    while (i < deltas) : (i += 1) {
        try out.member_deltas.append(allocator, .{
            .id = try r.readU64(),
            .state = try decodeMemberState(try r.readByte()),
            .incarnation = try r.readU64(),
        });
    }
    const suspicions = try r.readVarint();
    i = 0;
    while (i < suspicions) : (i += 1) {
        try out.suspicions.append(allocator, .{
            .node = try r.readU64(),
            .incarnation = try r.readU64(),
            .witness = try r.readU64(),
        });
    }
    if (!r.done()) return error.TrailingBytes;
    return out;
}

fn encodeRepairSummary(allocator: Allocator, state: *const ChannelCrdt) ![]u8 {
    var summary = try anti_entropy_repair.summarize(allocator, state);
    defer summary.deinit();

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try writeVarint(&out, allocator, summary.entries.items.len);
    for (summary.entries.items) |entry| {
        try writeBytes(&out, allocator, entry.key);
        try out.appendSlice(allocator, &entry.hash);
    }
    return out.toOwnedSlice(allocator);
}

fn decodeRepairSummary(allocator: Allocator, bytes: []const u8) !anti_entropy_repair.Summary {
    var r = Reader{ .buf = bytes };
    var out = anti_entropy_repair.Summary{
        .allocator = allocator,
        .tree = merkle.MerkleTree.init(allocator),
    };
    errdefer out.deinit();

    const count = try r.readVarint();
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const key_view = try r.readBytes();
        const hash = try r.readHash();
        const key = try allocator.dupe(u8, key_view);
        errdefer allocator.free(key);
        try out.tree.put(key, hash);
        try out.entries.append(allocator, .{ .key = key, .hash = hash });
    }
    if (!r.done()) return error.TrailingBytes;
    return out;
}

fn encodeRepairRequest(allocator: Allocator, request: *const anti_entropy_repair.RepairRequest) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try writeVarint(&out, allocator, request.keys.len);
    for (request.keys) |key| try writeBytes(&out, allocator, key);
    return out.toOwnedSlice(allocator);
}

fn decodeRepairRequest(allocator: Allocator, bytes: []const u8) !anti_entropy_repair.RepairRequest {
    var r = Reader{ .buf = bytes };
    var keys = std.ArrayList([]u8).empty;
    errdefer {
        for (keys.items) |key| allocator.free(key);
        keys.deinit(allocator);
    }
    const count = try r.readVarint();
    var i: usize = 0;
    while (i < count) : (i += 1) try keys.append(allocator, try allocator.dupe(u8, try r.readBytes()));
    if (!r.done()) return error.TrailingBytes;
    return .{ .allocator = allocator, .keys = try keys.toOwnedSlice(allocator) };
}

fn encodeRepairResponse(allocator: Allocator, response: *const anti_entropy_repair.RepairResponse) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try writeU64(&out, allocator, response.hlc.toU64());
    try writeVersionVector(&out, allocator, response.vv);
    try writeVarint(&out, allocator, response.records.len);
    for (response.records) |record| {
        try out.append(allocator, @intFromEnum(record.kind));
        try writeBytes(&out, allocator, record.key);
        try writeBytes(&out, allocator, record.payload);
    }
    return out.toOwnedSlice(allocator);
}

fn decodeRepairResponse(allocator: Allocator, bytes: []const u8) !anti_entropy_repair.RepairResponse {
    var r = Reader{ .buf = bytes };
    const hlc = hlcFromKey(try r.readU64());
    const vv = try r.readVersionVector();
    var records = std.ArrayList(anti_entropy_repair.RepairRecord).empty;
    errdefer {
        for (records.items) |record| {
            allocator.free(record.key);
            allocator.free(record.payload);
        }
        records.deinit(allocator);
    }
    const count = try r.readVarint();
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const kind: anti_entropy_repair.RecordKind = switch (try r.readByte()) {
            1 => .member,
            2 => .mode,
            else => return error.InvalidRepairRecord,
        };
        const key = try allocator.dupe(u8, try r.readBytes());
        errdefer allocator.free(key);
        const payload = try allocator.dupe(u8, try r.readBytes());
        errdefer allocator.free(payload);
        try records.append(allocator, .{ .kind = kind, .key = key, .payload = payload });
    }
    if (!r.done()) return error.TrailingBytes;
    return .{ .allocator = allocator, .hlc = hlc, .vv = vv, .records = try records.toOwnedSlice(allocator) };
}

fn writeVersionVector(out: *std.ArrayList(u8), allocator: Allocator, vv: channel_crdt.VersionVector) !void {
    try writeVarint(out, allocator, vv.len);
    for (vv.entries[0..vv.len]) |entry| {
        try writeU64(out, allocator, entry.replica);
        try writeU64(out, allocator, entry.counter);
    }
}

fn writeBytes(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8) !void {
    try writeVarint(out, allocator, bytes.len);
    try out.appendSlice(allocator, bytes);
}

fn writeBytes16(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8) !void {
    try writeU16(out, allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

fn writeU16(out: *std.ArrayList(u8), allocator: Allocator, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn writeU64(out: *std.ArrayList(u8), allocator: Allocator, value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn writeVarint(out: *std.ArrayList(u8), allocator: Allocator, value: usize) !void {
    var n: u64 = @intCast(value);
    while (n >= 0x80) {
        try out.append(allocator, @as(u8, @intCast(n & 0x7f)) | 0x80);
        n >>= 7;
    }
    try out.append(allocator, @intCast(n));
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }

    fn readByte(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readU16(self: *Reader) !u16 {
        const bytes = try self.readFixed(2);
        return std.mem.readInt(u16, bytes[0..2], .little);
    }

    fn readU64(self: *Reader) !u64 {
        const bytes = try self.readFixed(8);
        return std.mem.readInt(u64, bytes[0..8], .little);
    }

    fn readVarint(self: *Reader) !usize {
        var value: u64 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const byte = try self.readByte();
            // Derive the shift from the bounded loop index (i < 10 ⇒ i*7 ≤ 63)
            // rather than accumulating `shift += 7`, which overflows the u6 shift
            // amount on a 10th continuation byte: a trap under ReleaseSafe and a
            // silent wrap under ReleaseFast. This form fails closed with
            // VarintTooLong in every build mode.
            const shift = @as(u6, @intCast(i * 7));
            value |= @as(u64, byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) {
                if (value > std.math.maxInt(usize)) return error.Oversize;
                return @intCast(value);
            }
        }
        return error.VarintTooLong;
    }

    fn readBytes16(self: *Reader) ![]const u8 {
        return self.readFixed(try self.readU16());
    }

    fn readBytes(self: *Reader) ![]const u8 {
        return self.readFixed(try self.readVarint());
    }

    fn readHash(self: *Reader) !anti_entropy_repair.Hash {
        const bytes = try self.readFixed(@sizeOf(anti_entropy_repair.Hash));
        var out: anti_entropy_repair.Hash = undefined;
        @memcpy(&out, bytes);
        return out;
    }

    fn readVersionVector(self: *Reader) !channel_crdt.VersionVector {
        var out = channel_crdt.VersionVector.init();
        const count = try self.readVarint();
        if (count > out.entries.len) return error.Oversize;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            out.entries[i] = .{
                .replica = try self.readU64(),
                .counter = try self.readU64(),
            };
        }
        out.len = count;
        return out;
    }

    fn readFixed(self: *Reader, len: usize) ![]const u8 {
        // Overflow-free bounds check: `len` can be a varint approaching usize-max,
        // so `self.pos + len` would wrap and pass a naive check, yielding an OOB
        // slice. `self.pos <= self.buf.len` always holds, so the subtraction is
        // safe.
        if (len > self.buf.len - self.pos) return error.Truncated;
        const out = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }
};

fn decodeMemberState(value: u8) !gossip_round.MemberState {
    return switch (value) {
        0 => .alive,
        1 => .suspect,
        2 => .dead,
        3 => .left,
        else => error.UnknownMemberState,
    };
}

fn containsNode(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |candidate| if (candidate == node) return true;
    return false;
}

fn elapsed(now_ms: u64, since_ms: u64) u64 {
    return if (now_ms > since_ms) now_ms - since_ms else 0;
}

/// Clamp an identity string to its wire limit (an over-long local value is
/// propagated truncated rather than failing the whole announcement).
fn truncated(s: []const u8, max: usize) []const u8 {
    return if (s.len > max) s[0..max] else s;
}

fn i64Ms(ms: u64) !i64 {
    if (ms > @as(u64, @intCast(std.math.maxInt(i64)))) return error.TimeOutOfRange;
    return @intCast(ms);
}

fn hlcFromKey(key: u64) channel_crdt.Hlc {
    return .{ .wall_ms = @intCast(key >> 16), .logical = @intCast(key & 0xffff) };
}

fn mixSeed(a: u64, b: u64, c: u64) u64 {
    var x = a ^ (b *% 0x9e3779b97f4a7c15) ^ (c *% 0xbf58476d1ce4e5b9);
    x ^= x >> 30;
    x *%= 0xbf58476d1ce4e5b9;
    x ^= x >> 27;
    x *%= 0x94d049bb133111eb;
    return x ^ (x >> 31);
}

const TestClock = struct {
    now_ms: u64,

    fn clock(self: *TestClock) peer_link.Clock {
        return .{ .ptr = self, .now_fn = nowFn };
    }

    fn nowFn(ptr: *anyopaque) u64 {
        const self: *TestClock = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }
};

const BufferSink = struct {
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *BufferSink, allocator: Allocator) void {
        self.bytes.deinit(allocator);
    }

    fn sink(self: *BufferSink) ByteSink {
        return .{ .ptr = self, .write_fn = writeFn };
    }

    fn writeFn(ptr: *anyopaque, bytes: []const u8) !void {
        const self: *BufferSink = @ptrCast(@alignCast(ptr));
        try self.bytes.appendSlice(std.testing.allocator, bytes);
    }

    fn clear(self: *BufferSink) void {
        self.bytes.clearRetainingCapacity();
    }
};

fn discard(delta: anytype) void {
    var owned = delta;
    owned.deinit();
}

fn pump(a: *S2sPeer, b: *S2sPeer, a_to_b: *BufferSink, b_to_a: *BufferSink, now_ms: u64, seed: u64) !void {
    var rounds: usize = 0;
    while (rounds < 128) : (rounds += 1) {
        var moved = false;
        if (a_to_b.bytes.items.len != 0) {
            try b.feed(a_to_b.bytes.items, b_to_a.sink(), now_ms, seed +% @as(u64, @intCast(rounds)));
            a_to_b.clear();
            moved = true;
        }
        if (b_to_a.bytes.items.len != 0) {
            try a.feed(b_to_a.bytes.items, a_to_b.sink(), now_ms, seed +% 0x100 +% @as(u64, @intCast(rounds)));
            b_to_a.clear();
            moved = true;
        }
        if (!moved) return;
    }
    return error.PumpDidNotSettle;
}

fn newPeer(
    allocator: Allocator,
    state: *ChannelCrdt,
    tc: *TestClock,
    local_node: NodeId,
    remote_node: NodeId,
    epoch: u64,
    name: []const u8,
) !S2sPeer {
    return S2sPeer.init(.{
        .allocator = allocator,
        .state = state,
        .clock = tc.clock(),
        .local_node_id = local_node,
        .remote_node_id = remote_node,
        .local_epoch_ms = epoch,
        .server_name = name,
        .description = "test",
        .config = .{
            .link = .{
                .gossip_interval_ms = 10,
                .repair_interval_ms = 20,
                .gossip_config = .{ .fanout = 1 },
            },
        },
    });
}

test "two s2s peer drivers handshake and converge channel CRDT state" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    discard(try a_state.localJoin(10, .{ .op = true }, 10));
    discard(try a_state.localSetMode(.{ .invite_only = true }, 11));
    discard(try b_state.localJoin(20, .{ .voice = true }, 12));
    discard(try b_state.localSetMode(.{ .topic_protected = true }, 13));

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);

    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));
    try std.testing.expectEqual(peer_link.State.established, a.linkState());
    try std.testing.expectEqual(peer_link.State.established, b.linkState());
    try std.testing.expectEqual(@as(usize, 2), a.registryCount());
    try std.testing.expectEqual(@as(?NodeId, 2), a.routeNickNode("b.test"));

    var delta = try a_state.localJoin(30, .{ .founder = true }, 30);
    defer delta.deinit();
    try a.sendDelta(&delta, a_to_b.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xD317A);
    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));
}

// Regression: LINKS rendered a remote peer's description as the generic
// "Suimyaku peer" placeholder because it keyed `nodeDescription` on
// `remoteNodeId()` (a secured link's authenticated shortId), while the peer's
// real description was homed under its OTHER node-id space (its gossiped
// config.node_id) — the same space the working WHOIS 312 path resolves via
// `member.node`. `remoteDescription()` must resolve by the stable server NAME,
// so it finds the populated entry regardless of which u64 key holds it.
test "remoteDescription resolves the peer description by name across the node-id split" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    // `b` carries NO handshake description (mirrors the plaintext accept path,
    // which passes an empty description), so a's direct-handshake registry entry
    // for `b` — keyed under b's advertised node id (2, == a.remoteNodeId) — has an
    // empty description.
    var b = try S2sPeer.init(.{
        .allocator = allocator,
        .state = &b_state,
        .clock = tc.clock(),
        .local_node_id = 2,
        .remote_node_id = 1,
        .local_epoch_ms = 2000,
        .server_name = "b.test",
        .description = "",
        .config = .{ .link = .{ .gossip_interval_ms = 10, .repair_interval_ms = 20, .gossip_config = .{ .fanout = 1 } } },
    });
    defer b.deinit();

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);
    try std.testing.expect(a.established);

    // The OLD path: keyed on remoteNodeId() (2), the description is empty →
    // exactly the null that made LINKS fall back to the placeholder.
    try std.testing.expectEqual(@as(?NodeId, 2), a.remoteNodeId());
    try std.testing.expectEqual(@as(?[]const u8, null), a.nodeDescription(2));

    // Now the peer's real description arrives gossiped under its OTHER node-id
    // space (77), keyed under the SAME server name.
    _ = try a.registry.addOrUpdate(.{
        .node_id = 77,
        .name = "b.test",
        .description = "i fucking hate winter",
        .hopcount = 1,
        .uplink = 1,
        .last_seen_ms = 3000,
    });

    // The FIX: resolve by name, finding the populated entry regardless of key.
    try std.testing.expectEqualStrings("i fucking hate winter", a.remoteDescription().?);
}

test "two s2s peer drivers repair divergent state without explicit delta send" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    discard(try a_state.localJoin(10, .{ .voice = true }, 10));
    discard(try b_state.localJoin(20, .{ .op = true }, 11));

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    // Keyless (plaintext) peers exchanging REPAIR_* (in-scope) frames: model an
    // explicitly-permitted unsigned deployment so the anti-entropy repair path is
    // exercised on its own terms. The keyless signing policy is proven separately.
    a.config.require_signed_frames = false;
    b.config.require_signed_frames = false;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);
    try std.testing.expect(a.peer_supports_repair);
    try std.testing.expect(b.peer_supports_repair);
    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));

    discard(try a_state.localJoin(30, .{ .founder = true }, 30));
    discard(try a_state.localSetMode(.{ .secret = true }, 31));
    discard(try b_state.localJoin(40, .{ .voice = true }, 32));
    discard(try b_state.localSetMode(.{ .topic_protected = true }, 33));
    a_to_b.clear();
    b_to_a.clear();

    tc.now_ms += 25;
    const peers = [_]NodeId{ 1, 2 };
    try a.tick(a_to_b.sink(), tc.now_ms, 0xCAFE, &peers);
    try b.tick(b_to_a.sink(), tc.now_ms, 0xBEEF, &peers);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xD00D);

    try std.testing.expect(a.takeRepairResyncRequest());
    try std.testing.expect(b.takeRepairResyncRequest());
    try std.testing.expect(!a.takeRepairResyncRequest());
    try std.testing.expect(!b.takeRepairResyncRequest());
    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));
    try std.testing.expect(a_state.containsMember(30));
    try std.testing.expect(a_state.containsMember(40));
    try std.testing.expect(b_state.containsMember(30));
    try std.testing.expect(b_state.containsMember(40));
}

test "malformed repair frames are dropped without closing the peer driver" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);
    try std.testing.expect(b.peer_supports_repair);

    a_to_b.clear();
    b_to_a.clear();
    try emitFrame(allocator, a_to_b.sink(), .REPAIR_SUMMARY, "bad");
    try emitFrame(allocator, a_to_b.sink(), .REPAIR_REQUEST, "bad");
    try emitFrame(allocator, a_to_b.sink(), .REPAIR_RESPONSE, "bad");
    try b.feed(a_to_b.bytes.items, b_to_a.sink(), tc.now_ms, 0xBAD);

    try std.testing.expectEqual(peer_link.State.established, b.linkState());
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);
    try std.testing.expect(!b.takeRepairResyncRequest());
}

test "s2s peer resume header preserves repair capability" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);

    const hdr = a.snapshotResume();
    try std.testing.expect(hdr.peer_supports_repair);

    var resumed_state = ChannelCrdt.init(allocator, 1);
    defer resumed_state.deinit();
    var resumed = try S2sPeer.resumeEstablished(.{
        .allocator = allocator,
        .state = &resumed_state,
        .clock = tc.clock(),
        .local_node_id = 1,
        .remote_node_id = 2,
        .local_epoch_ms = 3000,
        .server_name = "a.test",
        .description = "test",
        .config = a.config,
    }, hdr, a.remoteName(), tc.now_ms + 1, 0xC0DE);
    defer resumed.deinit();

    try std.testing.expect(resumed.peer_supports_repair);
    try std.testing.expectEqual(@as(?NodeId, 2), resumed.remoteNodeId());
}

test "PING emits matching PONG" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 10, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 20, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.sendPing("hello", a_to_b.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x51);
    try std.testing.expectEqual(@as(usize, 1), b.ping_rx_count);
    try std.testing.expectEqual(@as(usize, 1), a.pong_rx_count);
}

test "partial inbound bytes are buffered until complete frame" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 10, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 20, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.sendPing("split", a_to_b.sink());
    const bytes = a_to_b.bytes.items;
    try b.feed(bytes[0..3], b_to_a.sink(), tc.now_ms, 1);
    try std.testing.expectEqual(@as(usize, 0), b.ping_rx_count);
    try b.feed(bytes[3..], b_to_a.sink(), tc.now_ms, 1);
    try std.testing.expectEqual(@as(usize, 1), b.ping_rx_count);
    try a.feed(b_to_a.bytes.items, a_to_b.sink(), tc.now_ms, 1);
    try std.testing.expectEqual(@as(usize, 1), a.pong_rx_count);
}

test "SESSION_MIGRATE frame is dispatched and staged for the daemon to drain" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 10, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 20, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    // A ships an opaque migration capsule (the daemon mints the real one; here
    // any bytes exercise the frame/dispatch/stage seam) to B, which knows A as
    // its authenticated direct peer (remote_node_id == 1).
    const capsule_bytes = "migration-capsule-frame-bytes";
    try a.sendSessionMigrate(a_to_b.sink(), capsule_bytes);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5E55);

    const staged = try b.takeSessionMigrations();
    defer {
        for (staged) |m| allocator.free(m);
        allocator.free(staged);
    }
    try std.testing.expectEqual(@as(usize, 1), staged.len);
    try std.testing.expectEqualStrings(capsule_bytes, staged[0]);
    // Drained: a second take yields nothing.
    const again = try b.takeSessionMigrations();
    defer allocator.free(again);
    try std.testing.expectEqual(@as(usize, 0), again.len);
}

test "SESSION_MIGRATE from an unknown origin is rejected, not staged" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1 };
    var state = ChannelCrdt.init(allocator, 2);
    defer state.deinit();
    // remote_node_id == 0 => the peer has no authenticated direct origin yet.
    var b = try newPeer(allocator, &state, &tc, 2, 0, 20, "b.test");
    defer b.deinit();

    // Feed a SESSION_MIGRATE frame directly (no handshake => remote unknown).
    const payload = "capsule";
    var buf: [s2s_frame.header_len + payload.len]u8 = undefined;
    const wire = try s2s_frame.encode(.SESSION_MIGRATE, payload, &buf);
    var sink = BufferSink{};
    defer sink.deinit(allocator);
    try b.feed(wire, sink.sink(), tc.now_ms, 1);

    const staged = try b.takeSessionMigrations();
    defer allocator.free(staged);
    try std.testing.expectEqual(@as(usize, 0), staged.len);
    // The rejection was accounted for in the origin-mismatch audit counter.
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
}

test "Config.applyToml consolidated EFFECTIVE prod path overlay" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.gossip]
        \\round_fanout = 5
        \\[mesh.sazanami]
        \\witness_quorum = 3
        \\[mesh.link]
        \\gossip_interval_ms = 1750
        \\idle_timeout_ms = 90000
        \\[mesh]
        \\require_signed_frames = false
        \\[mesh.routing]
        \\max_servers = 256
        \\max_nicks = 2048
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    // [mesh.gossip]/[mesh.sazanami] flow into the session sub-configs.
    try std.testing.expectEqual(@as(usize, 5), cfg.link.gossip_config.fanout);
    try std.testing.expectEqual(@as(u8, 3), cfg.link.sazanami_config.witness_quorum);
    // [mesh.link] session cadence + transport.
    try std.testing.expectEqual(@as(u64, 1750), cfg.link.gossip_interval_ms);
    try std.testing.expectEqual(@as(u64, 90000), cfg.link.peer_link_config.idle_timeout_ms);
    try std.testing.expect(!cfg.require_signed_frames);
    // [mesh.routing] registry + routes.
    try std.testing.expectEqual(@as(usize, 256), cfg.registry.max_nodes);
    try std.testing.expectEqual(@as(usize, 2048), cfg.routes.max_nicks);
}

// ---------------------------------------------------------------------------
// Frame-signing (end-to-end origin authentication) tests
// ---------------------------------------------------------------------------

fn signingKeyFor(seed_byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
}

/// Stand up a signing-capable peer. The self-certifying invariant REQUIRES
/// `local_node_id == originShortId(kp.public_key)`, so we derive it the same way
/// the secured link does. `remote_short` is the peer's authenticated origin id.
fn newSigningPeer(
    allocator: Allocator,
    state: *ChannelCrdt,
    tc: *TestClock,
    kp: sign.KeyPair,
    remote_short: NodeId,
    epoch: u64,
    name: []const u8,
) !S2sPeer {
    return S2sPeer.init(.{
        .allocator = allocator,
        .state = state,
        .clock = tc.clock(),
        .local_node_id = signed_frame.originShortId(kp.public_key),
        .remote_node_id = remote_short,
        .local_epoch_ms = epoch,
        .server_name = name,
        .description = "test",
        .signing_key = kp,
        .config = .{
            .link = .{
                .gossip_interval_ms = 10,
                .repair_interval_ms = 20,
                .gossip_config = .{ .fanout = 1 },
            },
        },
    });
}

test "signing peers negotiate frame_signing and a signed CHANNEL_PROP round-trips" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x11);
    const kp_b = try signingKeyFor(0x22);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);

    // Both sides advertised + recorded the signing capability.
    try std.testing.expect(a.peer_supports_signing);
    try std.testing.expect(b.peer_supports_signing);

    // A announces a signed CHANNEL_PROP; B accepts it after self-certifying A's
    // origin, with no rejection counted. (Per-link signed_frame envelope; no
    // multi-hop origin signature carried here — origin defaults to local.)
    try a.sendChannelProp(a_to_b.sink(), "#room", "TOPICLOCK", "1", "alice", 100, true, .{});
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xC0FFEE);

    const props = try b.takeChannelPropChanges();
    defer {
        for (props) |*p| p.deinit(allocator);
        allocator.free(props);
    }
    try std.testing.expectEqual(@as(usize, 1), props.len);
    try std.testing.expectEqualStrings("#room", props[0].channel);
    try std.testing.expectEqualStrings("TOPICLOCK", props[0].key);
    try std.testing.expectEqualStrings("1", props[0].value);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "signing peers round-trip a signed ENTITY_PROP (user and member)" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x13);
    const kp_b = try signingKeyFor(0x24);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);
    try std.testing.expect(a.peer_supports_signing);
    try std.testing.expect(b.peer_supports_signing);

    try a.sendEntityProp(a_to_b.sink(), .user, "alice", "STATUS", "away", "alice", 100, true, .{});
    try a.sendEntityProp(a_to_b.sink(), .member, "#room:bob", "ROLE", "mod", "founder", 101, true, .{});
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xC0FFEE);

    const props = try b.takeEntityPropChanges();
    defer {
        for (props) |*p| p.deinit(allocator);
        allocator.free(props);
    }
    try std.testing.expectEqual(@as(usize, 2), props.len);
    try std.testing.expectEqual(entity_prop_event.EntityKind.user, props[0].kind);
    try std.testing.expectEqualStrings("alice", props[0].entity);
    try std.testing.expectEqualStrings("STATUS", props[0].key);
    try std.testing.expectEqualStrings("away", props[0].value);
    try std.testing.expectEqual(entity_prop_event.EntityKind.member, props[1].kind);
    try std.testing.expectEqualStrings("#room:bob", props[1].entity);
    try std.testing.expectEqualStrings("mod", props[1].value);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "signing peers round-trip a signed MEMBERSHIP frame" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x31);
    const kp_b = try signingKeyFor(0x32);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x3EE);

    try a.sendMembership(a_to_b.sink(), "#room", "alice", 0, 50, true, .{ .username = "u", .realname = "r", .host = "h" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x3EF);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("alice", changes[0].nick);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

/// A local resolver stub for the account-aware collision tests: it reports one
/// held nick with a fixed account and last-claim HLC.
const ReclaimResolverStub = struct {
    held_nick: []const u8,
    acct: []const u8,
    hlc: u64,
    fn isHeld(ctx: *anyopaque, nick: []const u8) bool {
        const self: *ReclaimResolverStub = @ptrCast(@alignCast(ctx));
        return std.ascii.eqlIgnoreCase(self.held_nick, nick);
    }
    fn acctOf(ctx: *anyopaque, nick: []const u8) ?[]const u8 {
        const self: *ReclaimResolverStub = @ptrCast(@alignCast(ctx));
        if (!std.ascii.eqlIgnoreCase(self.held_nick, nick)) return null;
        return if (self.acct.len != 0) self.acct else null;
    }
    fn hlcOf(ctx: *anyopaque, nick: []const u8) u64 {
        const self: *ReclaimResolverStub = @ptrCast(@alignCast(ctx));
        if (!std.ascii.eqlIgnoreCase(self.held_nick, nick)) return 0;
        return self.hlc;
    }
    fn resolver(self: *ReclaimResolverStub) LocalNickResolver {
        return .{ .ctx = self, .held_fn = isHeld, .account_fn = acctOf, .hlc_fn = hlcOf };
    }
};

/// Test residence verifier that trusts a fixed (account, origin) pair — stands
/// in for the daemon's real receiver-owned proof lookup so the account-aware
/// collision tests can exercise the TRUSTED path (Design C). With NO verifier
/// installed, `accountResidenceTrusted` returns false and every same-account
/// short-circuit falls to the conservative UID path (the F1 fail-closed default).
const TrustVerifierStub = struct {
    account: []const u8,
    origin_node: NodeId,
    fn verify(ctx: *anyopaque, account: []const u8, origin_node: NodeId) bool {
        const self: *TrustVerifierStub = @ptrCast(@alignCast(ctx));
        return origin_node == self.origin_node and std.mem.eql(u8, account, self.account);
    }
    fn verifier(self: *TrustVerifierStub) ResidenceVerifier {
        return .{ .ctx = self, .verify_fn = verify };
    }
};

test "same-account MEMBERSHIP short-circuits require a VERIFIED residence proof (F1: no verifier ⇒ UID)" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x71);
    const kp_b = try signingKeyFor(0x72);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7EE);

    // b holds "kain" locally with a STALE claim; a forges account=kain at a newer
    // hlc. WITHOUT a residence verifier the plaintext account is untrusted, so no
    // ghost_reclaim fires — the forged claim is homed under a UID instead.
    var stub = ReclaimResolverStub{ .held_nick = "kain", .acct = "kain", .hlc = 50 };
    b.routes.setLocalNickResolver(stub.resolver());

    try a.sendMembership(a_to_b.sink(), "#room", "kain", 0, 200, true, .{ .username = "u", .realname = "r", .host = "h", .account = "kain" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7EF);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
    // A join under a forced UID, NOT a ghost_reclaim of the live local session.
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.joined, changes[0].kind);
    try std.testing.expect(!std.mem.eql(u8, "kain", changes[0].nick)); // forced to its mesh UID
}

test "a strictly-newer same-account MEMBERSHIP surfaces a ghost_reclaim for the stale local session" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x51);
    const kp_b = try signingKeyFor(0x52);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5EE);

    // b holds "kain" locally, logged in to account "kain", with a STALE claim (50).
    var stub = ReclaimResolverStub{ .held_nick = "kain", .acct = "kain", .hlc = 50 };
    b.routes.setLocalNickResolver(stub.resolver());
    // a's kain carries a VERIFIED residence proof (Design C) — the receiver trusts
    // the account for a's origin, so the same-account reclaim short-circuit fires.
    var vstub = TrustVerifierStub{ .account = "kain", .origin_node = a_short };
    b.setResidenceVerifier(vstub.verifier());

    // a (the live node) announces kain on the SAME account with a NEWER claim (200).
    try a.sendMembership(a_to_b.sink(), "#room", "kain", 0, 200, true, .{ .username = "u", .realname = "r", .host = "h", .account = "kain" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5EF);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.ghost_reclaim, changes[0].kind);
    try std.testing.expectEqualStrings("kain", changes[0].nick);
    try std.testing.expectEqualStrings("kain", changes[0].account); // carried for the daemon's re-check
}

test "a same-account MEMBERSHIP that is NOT newer keeps the live local session (no reclaim)" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x61);
    const kp_b = try signingKeyFor(0x62);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6EE);

    // b's local "kain" is the LIVE one (newer claim, 300) than a's claim (200).
    var stub = ReclaimResolverStub{ .held_nick = "kain", .acct = "kain", .hlc = 300 };
    b.routes.setLocalNickResolver(stub.resolver());
    var vstub = TrustVerifierStub{ .account = "kain", .origin_node = a_short };
    b.setResidenceVerifier(vstub.verifier());

    try a.sendMembership(a_to_b.sink(), "#room", "kain", 0, 200, true, .{ .username = "u", .realname = "r", .host = "h", .account = "kain" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6EF);

    // local_same_account APPLIES the membership under the REAL nick (no UID, no
    // reclaim): the channel→node relay gate is `channelMembers > 0`, so dropping it
    // would isolate a user who is the only channel member on their node from
    // cross-node messages. The daemon's nickIsLiveLocal suppression hides the
    // duplicate JOIN display for the locally-homed nick.
    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.joined, changes[0].kind);
    try std.testing.expectEqualStrings("kain", changes[0].nick); // real nick, NOT a UID
}

test "signing peers round-trip a signed KILL frame" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x41);
    const kp_b = try signingKeyFor(0x42);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x4EE);

    try a.sendKill(a_to_b.sink(), "a.test", "kain!~k@admin.example", "spammer", "flooding the network");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x4EF);

    const kills = try b.takeKills();
    defer {
        for (kills) |k| allocator.free(k);
        allocator.free(kills);
    }
    try std.testing.expectEqual(@as(usize, 1), kills.len);
    const ev = try kill_relay.decode(kills[0]);
    try std.testing.expectEqualStrings("a.test", ev.origin_server);
    try std.testing.expectEqualStrings("kain!~k@admin.example", ev.killer);
    try std.testing.expectEqualStrings("spammer", ev.target);
    try std.testing.expectEqualStrings("flooding the network", ev.reason);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "signing peers round-trip a signed WARD frame" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x41);
    const kp_b = try signingKeyFor(0x42);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5EE);

    // The substrate never decodes a WARD record (the daemon's `warden` codec does);
    // here we send an opaque payload and assert the verified bytes arrive intact.
    const ward_wire = "mesh-ward-wire-record-bytes";
    try a.sendWard(a_to_b.sink(), ward_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5EF);

    const wards = try b.takeWards();
    defer {
        for (wards) |wd| allocator.free(wd);
        allocator.free(wards);
    }
    try std.testing.expectEqual(@as(usize, 1), wards.len);
    try std.testing.expectEqualStrings(ward_wire, wards[0]);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "signing peers round-trip a signed TEGAMI_PUSH frame" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x61);
    const kp_b = try signingKeyFor(0x62);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6EE);

    try a.sendTegamiPush(a_to_b.sink(), "alice", "bob", "offline dm preview");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6EF);

    const pushes = try b.takeTegamiPushes();
    defer {
        for (pushes) |p| allocator.free(p);
        allocator.free(pushes);
    }
    try std.testing.expectEqual(@as(usize, 1), pushes.len);
    const ev = try tegami_push_relay.decode(pushes[0]);
    try std.testing.expectEqualStrings("alice", ev.account);
    try std.testing.expectEqualStrings("bob", ev.from);
    try std.testing.expectEqualStrings("offline dm preview", ev.text);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "a forged frame (wrong signature) is rejected and counted" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x41);
    const kp_b = try signingKeyFor(0x42);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    // B is established and knows A as its signing-capable direct peer.
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();

    // Drive A->B handshake so B records peer_supports_signing for A.
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x4F0);
    try std.testing.expect(b.peer_supports_signing);

    // Build a VALID signed CHANNEL_PROP envelope from A, then corrupt the
    // signature so verification fails. Frame it and feed B directly.
    var ev_buf: [channel_prop_event.max_channel_len + channel_prop_event.max_key_len + channel_prop_event.max_value_len + channel_prop_event.max_owner_len + 32]u8 = undefined;
    const ev = channel_prop_event.ChannelPropEvent{
        .present = true,
        .origin_node = a_short,
        .hlc = 200,
        .channel = "#room",
        .key = "K",
        .value = "V",
        .owner = "alice",
    };
    const inner = try channel_prop_event.encode(ev, &ev_buf);
    var env_buf: [512]u8 = undefined;
    const env = try signed_frame.wrap(&env_buf, &kp_a, @intFromEnum(s2s_frame.FrameType.CHANNEL_PROP), inner);
    env[signed_frame.pubkey_len] ^= 0x80; // corrupt the signature

    var fbuf: [1024]u8 = undefined;
    const wire = try s2s_frame.encode(.CHANNEL_PROP, env, &fbuf);
    var sink = BufferSink{};
    defer sink.deinit(allocator);
    try b.feed(wire, sink.sink(), tc.now_ms, 1);

    const props = try b.takeChannelPropChanges();
    defer allocator.free(props);
    try std.testing.expectEqual(@as(usize, 0), props.len);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
}

test "a forged frame (attacker key, origin mismatch) is rejected and counted" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x51); // the legitimate peer A
    const kp_x = try signingKeyFor(0x5A); // an attacker key (NOT A)
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId((try signingKeyFor(0x52)).public_key);

    var b = try newSigningPeer(allocator, &b_state, &tc, try signingKeyFor(0x52), a_short, 2000, "b.test");
    defer b.deinit();

    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5F0);
    try std.testing.expect(b.peer_supports_signing);

    // The attacker mints a structurally-valid, correctly-signed CHANNEL_PROP that
    // CLAIMS A's origin id, but signs with its OWN key. The signature verifies,
    // but `originShortId(attacker_pubkey) != a_short`, so B rejects it.
    var ev_buf: [channel_prop_event.max_channel_len + channel_prop_event.max_key_len + channel_prop_event.max_value_len + channel_prop_event.max_owner_len + 32]u8 = undefined;
    const ev = channel_prop_event.ChannelPropEvent{
        .present = true,
        .origin_node = a_short, // claims to be A
        .hlc = 300,
        .channel = "#room",
        .key = "K",
        .value = "evil",
        .owner = "mallory",
    };
    const inner = try channel_prop_event.encode(ev, &ev_buf);
    var env_buf: [512]u8 = undefined;
    const env = try signed_frame.wrap(&env_buf, &kp_x, @intFromEnum(s2s_frame.FrameType.CHANNEL_PROP), inner);

    var fbuf: [1024]u8 = undefined;
    const wire = try s2s_frame.encode(.CHANNEL_PROP, env, &fbuf);
    var sink = BufferSink{};
    defer sink.deinit(allocator);
    try b.feed(wire, sink.sink(), tc.now_ms, 1);

    const props = try b.takeChannelPropChanges();
    defer allocator.free(props);
    try std.testing.expectEqual(@as(usize, 0), props.len);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
}

test "a signing peer rejects a non-signing peer by default" {
    // A has no signing key (plaintext-style peer); B has one and requires signed
    // frames, so B rejects A during capability negotiation.
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    // A: legacy peer, plain u64 ids, NO signing key.
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    // B: signing-capable, but its remote (A) id is the legacy u64 1.
    const kp_b = try signingKeyFor(0x62);
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, 1, 2000, "b.test");
    defer b.deinit();
    // A must believe B's id is whatever B advertises (B's derived short id).
    a.remote_node_id = signed_frame.originShortId(kp_b.public_key);

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try std.testing.expectError(error.SignedFramesRequired, pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6A0));
}

test "explicitly-permitted non-signing peers still interoperate unsigned" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    const kp_b = try signingKeyFor(0x62);
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, 1, 2000, "b.test");
    defer b.deinit();
    b.config.require_signed_frames = false;
    a.remote_node_id = signed_frame.originShortId(kp_b.public_key);

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6A0);

    try std.testing.expect(!b.peer_supports_signing);
    try std.testing.expect(a.peer_supports_signing);

    // A sends an UNSIGNED membership; B accepts it (legacy path, no rejection).
    try a.sendMembership(a_to_b.sink(), "#room", "bob", 0, 60, true, .{ .username = "u", .realname = "r", .host = "h" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6A1);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("bob", changes[0].nick);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "keyless node fails CLOSED: require_signed_frames rejects an unsigned in-scope frame" {
    // Reviewer-flagged fail-OPEN (fixed here): a node with NO signing key (a
    // plaintext link) used to RAW-PASS an unsigned direct-owned frame even when
    // the operator set `require_signed_frames`, because the inbound gate was
    // wrongly coupled to `signing_key != null`. A keyless receiver CAN still
    // enforce the policy (it just cannot sign its OWN egress), so it must now
    // DROP + COUNT the unsigned in-scope frame instead of applying it.
    //
    // Deterministic: fixed TestClock + fixed pump seeds, so any failure replays
    // byte-for-byte.
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    // Both peers are keyless (plaintext-style). B keeps the default policy on.
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    try std.testing.expect(b.config.require_signed_frames); // default: policy ON
    try std.testing.expect(b.signing_key == null); // and B holds no key

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xFA11);

    // Neither side negotiated signing (both keyless).
    try std.testing.expect(!a.peer_supports_signing);
    try std.testing.expect(!b.peer_supports_signing);

    // A emits an UNSIGNED membership; keyless B WITH the policy must reject it:
    // zero state applied, exactly one rejection counted.
    try a.sendMembership(a_to_b.sink(), "#room", "bob", 0, 60, true, .{ .username = "u", .realname = "r", .host = "h" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xFA12);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 0), changes.len);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
}

test "keyless node with require_signed_frames disabled still accepts an unsigned in-scope frame" {
    // The negative of the fail-CLOSED fix: an explicitly-permitted unsigned
    // deployment (policy OFF) on a keyless node keeps applying unsigned
    // direct-owned frames, unchanged from legacy behavior.
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    b.config.require_signed_frames = false; // opt into unsigned interop

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xFB11);

    try std.testing.expect(!a.peer_supports_signing);
    try std.testing.expect(!b.peer_supports_signing);

    try a.sendMembership(a_to_b.sink(), "#room", "bob", 0, 60, true, .{ .username = "u", .realname = "r", .host = "h" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xFB12);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("bob", changes[0].nick);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "a signing peer's UNSIGNED in-scope frame is rejected" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x71);
    const kp_b = try signingKeyFor(0x72);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();

    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7F0);
    try std.testing.expect(b.peer_supports_signing);

    // Hand-frame an UNSIGNED CHANNEL_PROP (raw event, no envelope) from A and feed
    // B directly. Because A advertised signing, B MUST reject the unsigned frame.
    var ev_buf: [channel_prop_event.max_channel_len + channel_prop_event.max_key_len + channel_prop_event.max_value_len + channel_prop_event.max_owner_len + 32]u8 = undefined;
    const ev = channel_prop_event.ChannelPropEvent{
        .present = true,
        .origin_node = a_short,
        .hlc = 400,
        .channel = "#room",
        .key = "K",
        .value = "V",
        .owner = "alice",
    };
    const inner = try channel_prop_event.encode(ev, &ev_buf);
    var fbuf: [1024]u8 = undefined;
    const wire = try s2s_frame.encode(.CHANNEL_PROP, inner, &fbuf);
    var sink = BufferSink{};
    defer sink.deinit(allocator);
    try b.feed(wire, sink.sink(), tc.now_ms, 1);

    const props = try b.takeChannelPropChanges();
    defer allocator.free(props);
    try std.testing.expectEqual(@as(usize, 0), props.len);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
}

// ---------------------------------------------------------------------------
// Adversarial exploit/attack corpus: the S2S frame-dispatch parse surface.
//
// A Byzantine (or, for unsigned frames, unauthenticated) mesh peer controls the
// bytes inside every well-framed S2S frame. `S2sPeer.feed` streaming-decodes the
// frame header and dispatches the attacker-controlled payload straight into the
// per-type parsers (burst/delta/gossip/membership/channel-mode/… decode). This
// corpus drives that surface with hostile payloads and asserts the ONLY
// observable outcome is a returned value or a returned error — never a panic,
// OOB slice, integer overflow, or unbounded growth. It mirrors the doctrine in
// `crypto/tls_fuzz.zig`: feed hostile bytes to the attacker-facing parsers and
// prove they fail closed. Deterministic + fixed-seed, so it runs in the full
// suite AND under `zig build test-exploit`, and any trap replays byte-for-byte.
// ---------------------------------------------------------------------------

/// Frame the payload for `frame_type` and feed it through a fresh-ish peer. The
/// peer carries no MeshPass admission set, so `meshPassAllowsFrame` permits every
/// family and the payload reaches the real parser. Errors are the fail-closed
/// outcome and are swallowed; a panic/OOB is what this asserts cannot happen.
fn feedHostileFrame(
    peer: *S2sPeer,
    sink: *BufferSink,
    frame_type: s2s_frame.FrameType,
    payload: []const u8,
    now_ms: u64,
    seed: u64,
) void {
    sink.clear();
    var hdr: [s2s_frame.header_len]u8 = undefined;
    hdr[0] = frame_type.tag();
    std.mem.writeInt(u32, hdr[1..][0..4], @intCast(payload.len), .little);
    // Feed header then body so the streaming decoder reassembles a complete frame.
    peer.feed(&hdr, sink.sink(), now_ms, seed) catch return;
    peer.feed(payload, sink.sink(), now_ms, seed) catch return;
}

test "exploit: s2s frame dispatch survives hostile payloads for every frame type (fail-closed)" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1_000 };
    var state = ChannelCrdt.init(allocator, 1);
    defer state.deinit();
    var peer = try newPeer(allocator, &state, &tc, 1, 2, 1000, "atk.test");
    defer peer.deinit();
    var sink = BufferSink{};
    defer sink.deinit(allocator);

    // Every wire frame type, including unknown/unmapped tags (skipped, not fatal).
    const frame_types = [_]s2s_frame.FrameType{
        .HANDSHAKE,          .BURST,           .DELTA,        .GOSSIP,      .PING,
        .PONG,               .QUIT,            .MEMBERSHIP,   .MESSAGE,     .OPER_GRANT,
        .CHANNEL_MODE_FLAGS, .CHANNEL_LIST,    .CHANNEL_PROP, .TOPIC,       .NICKCHANGE,
        .CHANNEL_MODE_STATE, .SESSION_MIGRATE, .ENTITY_PROP,  .CLONE_COUNT, .OPER_EVENT,
        .OBSERVE_EVENT,      .KILL,            .WARD,         .RESYNC,      .REPAIR_SUMMARY,
        .REPAIR_REQUEST,     .REPAIR_RESPONSE, .TEGAMI_PUSH,
    };

    // Boundary payloads that target the integer-overflow / length-confusion bug
    // class directly: a leading varint (or magic + varint) claiming a length at
    // or near usize-max, which a naive `pos + len` bounds check wraps past.
    const usize_max_varint = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    const burst_header_overflow = [_]u8{ 'S', 'B', 'S', 'T', 1, 1 } ++ usize_max_varint;
    const burst_member_overflow = [_]u8{ 'S', 'B', 'S', 'T', 1, 4 } ++ usize_max_varint;
    const structured = [_][]const u8{
        &usize_max_varint, //                                        lone giant varint
        &burst_header_overflow, //                                   burst record len = 2^64-1
        &burst_member_overflow, //                                   member_compact record len
        &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, //                         all-ones prefix
        &[_]u8{ 0, 0, 0, 0 }, //                                     all-zero prefix
        &[_]u8{ 'S', 'B', 'S', 'T', 1 }, //                          valid magic, truncated
        "", //                                                       empty payload
        &[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 }, // never-terminating varint
    };

    // 1) Every structured boundary payload against every frame type.
    for (structured) |payload| {
        for (frame_types) |ft| {
            feedHostileFrame(&peer, &sink, ft, payload, tc.now_ms, 0xB17E);
        }
    }

    // 2) A seeded pseudorandom corpus: pure-random and near-structured bodies.
    //    Fixed seed ⇒ any trap replays deterministically on re-run.
    var prng = std.Random.DefaultPrng.init(0x5EED_A77ACC);
    const rng = prng.random();
    var buf: [512]u8 = undefined;
    var iter: usize = 0;
    while (iter < 3000) : (iter += 1) {
        const len = rng.intRangeAtMost(usize, 0, buf.len);
        rng.bytes(buf[0..len]);
        // Bias a slice toward a plausible burst/coilpack magic so the parser gets
        // past the header guard and reaches the length-driven inner reads.
        if (len >= 6 and (iter & 3) == 0) {
            buf[0] = 'S';
            buf[1] = 'B';
            buf[2] = 'S';
            buf[3] = 'T';
            buf[4] = 1;
            buf[5] = @as(u8, @intCast(1 + (iter % 4)));
        }
        const ft = frame_types[iter % frame_types.len];
        feedHostileFrame(&peer, &sink, ft, buf[0..len], tc.now_ms, 0x5EED +% iter);
    }

    // Surviving to here with the testing allocator (leak-checked on deinit) is the
    // proof: no parser trapped, over-read, or leaked on any hostile input.
    try std.testing.expect(true);
}
