// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure S2S peer driver for one Undertow server-to-server connection.
//!
//! The caller owns sockets, timers, and randomness. This driver consumes
//! inbound bytes, streaming-decodes `s2s_frame` frames, dispatches them into the
//! Undertow state modules, and writes encoded outbound bytes to a caller sink.
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
const message_relay_v2 = @import("message_relay_v2.zig");
const e2ee_group_relay = @import("e2ee_group_relay.zig");
const toml = @import("../../proto/toml.zig");

const Allocator = std.mem.Allocator;

pub const ChannelCrdt = channel_crdt.ChannelCrdt;
pub const NodeId = gossip_round.NodeId;
pub const MemberInfo = route_table.Member;
pub const MemberIdentity = route_table.MemberIdentity;
pub const SessionToken = route_table.SessionToken;
pub const NickClaim = route_table.NickClaim;
pub const ChannelModeFlags = route_table.ChannelModeFlags;
pub const ChannelNameIterator = route_table.RouteTable.ChannelNameIterator;
pub const RelayMessage = message_relay.RelayMessage;
pub const InboundMessage = message_relay.Owned;
pub const RelayVerb = message_relay.Verb;
pub const RelayMessageV2 = message_relay_v2.RelayMessage;
pub const RelayVerbV2 = message_relay_v2.Verb;
pub const E2eeGroupRelay = e2ee_group_relay.RelayRecord;
pub const E2eeGroupRelayId = e2ee_group_relay.RelayId;
pub const SignedOperEventV2 = oper_event.SignedOperEventV2;
pub const ChannelModeStateEvent = channel_mode_state_event.ChannelModeStateEvent;
pub const LocalNickResolver = route_table.LocalNickResolver;
pub const SessionReplicaKind = session_replica_frame.Kind;
pub const SessionTokenReconcileResult = route_table.SessionTokenReconcileResult;

/// RECEIVER-SIDE account-residence verifier seam (Design C, the F1 proper fix).
/// The daemon supplies a callback that verifies an incoming claim's residence
/// proof — looked up from the RECEIVER-OWNED replicated `identity.residence.*`
/// and `identity.key.*` props, never from any wire field — binding
/// `{account, nick, origin_node}`. The peer driver consults it per claim: trusted
/// reaches account-aware collision resolution, untrusted takes the conservative
/// path, and reject is dropped before RouteTable mutation. Absent means untrusted.
pub const ResidenceDecision = enum {
    untrusted,
    trusted,
    reject,
};

pub const ResidenceVerifier = struct {
    ctx: *anyopaque,
    verify_fn: *const fn (
        ctx: *anyopaque,
        account: []const u8,
        nick: []const u8,
        origin_node: NodeId,
        session_replica_v2_negotiated: bool,
    ) ResidenceDecision,

    pub fn verify(
        self: ResidenceVerifier,
        account: []const u8,
        nick: []const u8,
        origin_node: NodeId,
        session_replica_v2_negotiated: bool,
    ) ResidenceDecision {
        return self.verify_fn(self.ctx, account, nick, origin_node, session_replica_v2_negotiated);
    }
};

/// Receiver-side decision for attaching a signed logical-session identity to a
/// compatibility MEMBERSHIP row. The token is never decoded from that frame:
/// the daemon derives it from its own signed SESSION_REPLICA authority.
pub const SessionTokenDecision = union(enum) {
    /// No unique live authority exists. Preserve interoperability, but leave the
    /// row unbound so exact-token reconciliation can never delete it.
    unbound,
    /// This membership fact belongs to the exact signed logical session.
    bind: SessionToken,
    /// Receiver-owned authority proves the fact stale or contradictory. Drop it
    /// before collision resolution, route-table mutation, or daemon deltas.
    reject,
};

pub const SessionTokenResolver = struct {
    ctx: *anyopaque,
    resolve_fn: *const fn (
        ctx: *anyopaque,
        origin_node: NodeId,
        nick: []const u8,
        channel: []const u8,
        present: bool,
    ) SessionTokenDecision,

    pub fn resolve(
        self: SessionTokenResolver,
        origin_node: NodeId,
        nick: []const u8,
        channel: []const u8,
        present: bool,
    ) SessionTokenDecision {
        return self.resolve_fn(self.ctx, origin_node, nick, channel, present);
    }
};

pub const SessionTokenNickDecision = union(enum) {
    reject,
    /// No retained signed authority exists for either identity. Preserve the
    /// compatibility NICK path without inventing receiver token metadata.
    legacy,
    /// Store selected one exact logical session. The route layer binds this
    /// token to every affected row before its transactional rename.
    bind: SessionToken,
};

/// Receiver-owned authorization for a peer-controlled NICKCHANGE touching an
/// exact-token roster identity. The daemon returns the Store-selected token,
/// distinguishes true legacy traffic, or rejects the transition.
pub const SessionTokenNickAuthorizer = struct {
    ctx: *anyopaque,
    authorize_fn: *const fn (
        ctx: *anyopaque,
        origin_node: NodeId,
        old_nick: []const u8,
        tagged_token: ?SessionToken,
        new_nick: []const u8,
    ) SessionTokenNickDecision,

    pub fn authorize(
        self: SessionTokenNickAuthorizer,
        origin_node: NodeId,
        old_nick: []const u8,
        tagged_token: ?SessionToken,
        new_nick: []const u8,
    ) SessionTokenNickDecision {
        return self.authorize_fn(self.ctx, origin_node, old_nick, tagged_token, new_nick);
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
const relay_v2_extension_probe = "onyx-xcap-relay-v2-1?";
const relay_v2_extension_reply = "onyx-xcap-relay-v2-1!";
const relay_v2_ack_confirm_probe = "onyx-xcap-relay-v2-ack-confirm?";
const relay_v2_ack_confirm_reply = "onyx-xcap-relay-v2-ack-confirm!";
/// v2 negotiates safe-retirement ACK/ACK_CONFIRM (flag byte on E2EE_GROUP_ACK).
/// v1 peers never answer this probe and never receive tag 0x26/0x27.
const e2ee_group_extension_probe = "onyx-xcap-e2ee-group-2?";
const e2ee_group_extension_reply = "onyx-xcap-e2ee-group-2!";
const session_replica_v3_probe = "onyx-xcap-session-replica-v3?";
const session_replica_v3_reply = "onyx-xcap-session-replica-v3!";

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
/// The peer understands secured SESSION_REPLICA v2 OFFER/ACK/REVOKE frames.
const cap_session_replica_v2: u8 = s2s_frame.cap_session_replica_v2;
/// The peer understands secured MESSAGE_V2 origin-signed flooding frames.
const cap_secure_relay_v2: u8 = s2s_frame.cap_secure_relay_v2;
/// The peer understands positive short-lived SESSION_REPLICA attachment leases.
const cap_session_attachment_lease_v2: u8 = s2s_frame.cap_session_attachment_lease_v2;
/// The peer understands secured immutable-origin Event Spine v2 frames.
const cap_event_spine_v2: u8 = s2s_frame.cap_event_spine_v2;

/// Hard cap on the per-peer `channel_mode_state_clocks` LWW-dedup map. Each
/// distinct `CHANNEL_MODE_STATE` channel name dupes an owned key, so without a
/// bound an admitted signing peer streaming unbounded distinct channel names
/// would grow the map without limit. Beyond the cap the oldest-inserted channel
/// is FIFO-evicted (its owned key freed), matching `message_relay.SeenSet`. A
/// legitimate mesh carries far fewer distinct channels than this; overflow only
/// occurs under a name flood, where evicting a stale clock is a bounded-memory
/// tradeoff (a later replay of that channel re-arms it, exactly as SeenSet).
const max_channel_mode_state_clocks: usize = 4096;

/// Bounded per-channel LWW-dedup clock map. Caps distinct channel-name keys at
/// `max_channel_mode_state_clocks` with FIFO eviction — the same shape as
/// `message_relay.SeenSet` — so an admitted signing peer streaming unbounded
/// distinct `CHANNEL_MODE_STATE` channel names cannot exhaust memory. Owns each
/// channel-name key; `order` BORROWS those owned slices (freed once, via the
/// map, at eviction or `deinit`) and `next_evict` is the FIFO ring cursor. The
/// map `count()` and `order.items.len` are kept in lockstep, so `next_evict`
/// (always < capacity) is a valid `order` index whenever the cap is reached.
const ChannelClockSet = struct {
    clocks: std.StringHashMapUnmanaged(u64) = .empty,
    order: std.ArrayListUnmanaged([]const u8) = .empty,
    next_evict: usize = 0,

    fn deinit(self: *ChannelClockSet, allocator: Allocator) void {
        var it = self.clocks.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.clocks.deinit(allocator);
        self.order.deinit(allocator);
        self.* = undefined;
    }

    /// LWW admit: true iff `hlc` strictly beats the last clock seen for
    /// `channel` (or the channel is new), recording it. False on a stale/equal
    /// clock, and false (fail-closed drop) on any allocation failure. Updating
    /// an existing channel never grows the map, so only a genuinely new key can
    /// trip the cap.
    fn observe(self: *ChannelClockSet, allocator: Allocator, channel: []const u8, hlc: u64) bool {
        if (max_channel_mode_state_clocks == 0) return false;
        if (self.clocks.getPtr(channel)) |cur| {
            if (hlc <= cur.*) return false;
            cur.* = hlc;
            return true;
        }
        const owned = allocator.dupe(u8, channel) catch return false;

        if (self.clocks.count() >= max_channel_mode_state_clocks) {
            // At capacity: FIFO-evict the oldest-inserted channel, freeing its
            // owned key, then reuse its ring slot. The put runs BEFORE the
            // remove so a mid-op OOM leaves the map fully populated (never
            // under-capacity), and `victim` is always distinct from `owned`
            // (a new key missed `getPtr` above).
            const victim = self.order.items[self.next_evict];
            self.clocks.put(allocator, owned, hlc) catch {
                allocator.free(owned);
                return false;
            };
            if (self.clocks.fetchRemove(victim)) |kv| allocator.free(kv.key);
            self.order.items[self.next_evict] = owned;
            self.next_evict = (self.next_evict + 1) % max_channel_mode_state_clocks;
            return true;
        }

        self.clocks.put(allocator, owned, hlc) catch {
            allocator.free(owned);
            return false;
        };
        self.order.append(allocator, owned) catch {
            // Keep `order` and the map in lockstep: undo the map insert
            // (freeing the just-duped key) rather than orphan an untracked
            // entry the FIFO cursor could never reach.
            if (self.clocks.fetchRemove(owned)) |kv| allocator.free(kv.key);
            return false;
        };
        return true;
    }

    fn count(self: *const ChannelClockSet) usize {
        return self.clocks.count();
    }
};

const s2s_frame = @import("../../proto/s2s_frame.zig");
const session_replica_frame = @import("../../proto/session_replica_frame.zig");
const meshpass = @import("../../proto/meshpass.zig");
const membership_event = @import("../../proto/membership_event.zig");
const oper_event = @import("../../proto/oper_event.zig");
const observe_event = @import("../../proto/observe_event.zig");
const kill_relay = @import("../../proto/kill_relay.zig");
const memo_push_relay = @import("../../proto/memo_push_relay.zig");
const media_ws_relay = @import("../../proto/media_ws_relay.zig");
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
    /// Per-peer complete-frame ceiling (header + payload). Defaults to the
    /// shared S2S 1 MiB bound; secured media-cascade links raise this to
    /// `media_ws_relay.required_max_frame_size` so a Cadence keyframe fits.
    max_frame_size: usize = s2s_frame.default_max_frame_size,
    /// Maximum decoded SESSION_REPLICA transport objects staged for the daemon.
    /// The queue fails closed at the bound; it never evicts an earlier fact.
    max_session_replica_frames: usize = 64,
    /// Maximum verified MESSAGE_V2 objects staged for the daemon. The queue is
    /// fail-closed and never evicts an earlier accepted user event.
    max_relay_v2_frames: usize = 256,
    /// Per-link exact-event reflection cache. This is intentionally only a loop
    /// optimization; authoritative replay retirement is daemon-global.
    relay_v2_seen_capacity: usize = 4096,
    /// Maximum verified E2EEGROUP controls staged for daemon-global replay
    /// admission. The queue never evicts an earlier accepted control.
    max_e2ee_group_frames: usize = 256,
    /// Maximum immediate-hop E2EEGROUP ACK or ACK_CONFIRM receipts staged for
    /// daemon outbox/receipt retirement. Distinct from MESSAGE_V2 ACK queues
    /// even when both payloads are 16-byte RelayIds (confirm adds a flag byte).
    max_e2ee_group_ack_frames: usize = 256,
    /// Per-link E2EEGROUP reflection cache only. It is not replay authority.
    e2ee_group_seen_capacity: usize = 4096,
    /// Maximum verified OPER_EVENT_V2 wires staged for daemon-global replay
    /// admission. This per-link queue never evicts an earlier accepted event.
    max_oper_event_v2_frames: usize = 256,
    /// Maximum verified MEDIA_WS_DATAGRAM payloads staged for local WS fanout.
    /// Bounded tightly: each entry can be up to ~4 MiB (Cadence keyframe).
    /// Fail-closed on overflow (drop newest) rather than growing unboundedly.
    max_media_ws_datagrams: usize = 8,
    /// Per-link exact-event reflection cache for Event Spine v2. The daemon's
    /// durable global guard remains the only replay/delivery authority.
    oper_event_v2_seen_capacity: usize = 4096,
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
    /// (`s2s_peer` → `link_session` → peer-link/gossip/ripple/burst). Overlays
    /// every `[mesh.*]` section this driver owns. Missing keys leave fields at
    /// their defaults, so behavior is unchanged until the orchestrator supplies
    /// a parsed config. The aggregate `[mesh.gossip]`/`[mesh.ripple]` sections are
    /// applied to the embedded session sub-configs here (link.applyToml only
    /// handles the `[mesh.link]` per-session overrides + transport + burst).
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        // Apply the broad `[mesh.gossip]`/`[mesh.ripple]` sections to the embedded
        // session sub-configs first, then the narrower `[mesh.link]` per-session
        // overrides last so an explicit per-session override always wins.
        cfg.link.gossip_config.applyToml(doc);
        cfg.link.ripple_config.applyToml(doc);
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
    channel_name: []const u8 = "#undertow",
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
    /// Set only by the Mooring `SecuredLink` adapter after its AKE establishes.
    /// A standalone/plaintext S2sLink remains false even if it has a signing key.
    session_replica_transport_enabled: bool = false,
    /// Enables the attachment-scoped SRTF3 schema only after the base secured
    /// replica transport is active. Kept separate so a rolling deployment can
    /// ship codecs before switching the live authority store.
    session_replica_attachment_transport_enabled: bool = false,
    /// Independent outer-transport assertion for MESSAGE_V2. Only the Mooring
    /// SecuredLink adapter sets this after its AKE; a keyed plaintext test/link
    /// cannot activate secure flooding by advertising capability bits.
    secure_relay_transport_enabled: bool = false,
    /// Independent outer-transport assertion for OPER_EVENT_V2. Only the
    /// Mooring SecuredLink adapter may enable this after its AKE completes.
    event_spine_v2_transport_enabled: bool = false,
};

const Handshake = struct {
    node_id: NodeId,
    epoch_ms: u64,
    name: []const u8,
    description: []const u8,
    /// Capability bitfield (v2+); 0 for a v1 peer that omitted it.
    caps: u8 = 0,
};

pub const InboundSessionReplica = struct {
    version: session_replica_frame.WireVersion,
    kind: session_replica_frame.Kind,
    via_peer: NodeId,
    signed_payload: []u8,

    pub fn deinit(self: *InboundSessionReplica, allocator: Allocator) void {
        allocator.free(self.signed_payload);
        self.* = undefined;
    }
};

pub const InboundMessageV2 = struct {
    owned: message_relay_v2.Owned,
    /// Exact canonical inner MESSAGE_V2 bytes received after immediate-hop
    /// authentication. Accepted mesh forwarding reuses this image verbatim.
    wire: []u8,
    /// Authenticated immediate hop. The immutable inner origin may legitimately
    /// name a different node on a pure-transit A-B-C path.
    via_peer: NodeId,

    pub fn deinit(self: *InboundMessageV2, allocator: Allocator) void {
        self.owned.deinit(allocator);
        allocator.free(self.wire);
        self.* = undefined;
    }
};

/// One strictly decoded, origin-verified E2EEGROUP control plus the exact
/// canonical inner wire image and authenticated immediate transport hop.
pub const InboundE2eeGroup = struct {
    owned: e2ee_group_relay.Owned,
    wire: []u8,
    relay_id: e2ee_group_relay.RelayId,
    via_peer: NodeId,

    pub fn deinit(self: *InboundE2eeGroup, allocator: Allocator) void {
        self.owned.deinit(allocator);
        allocator.free(self.wire);
        self.* = undefined;
    }
};

/// One verified immutable Event Spine object plus the authenticated immediate
/// transport hop. `wire` is the exact canonical OEVT v2 byte image received and
/// is suitable for byte-identical forwarding after daemon-global admission.
pub const InboundOperEventV2 = struct {
    wire: []u8,
    via_peer: NodeId,

    pub fn deinit(self: *InboundOperEventV2, allocator: Allocator) void {
        allocator.free(self.wire);
        self.* = undefined;
    }
};

/// NICK/MEMBERSHIP frames on a negotiated v2 link are residence-dependent.
/// They must remain in original wire order until the daemon has applied every
/// SESSION_REPLICA object from the same socket read to its authoritative Store.
const DeferredResidenceFrame = struct {
    const Kind = enum { membership, nick_change };

    kind: Kind,
    payload: []u8,

    fn deinit(self: *DeferredResidenceFrame, allocator: Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const S2sPeer = struct {
    allocator: Allocator,
    decoder: s2s_frame.Decoder,
    /// Advisory per-link anti-entropy shadow of the `#undertow` control channel,
    /// merged from `BURST`/`DELTA`/`REPAIR_RESPONSE`. It carries NO per-fact
    /// origin authentication (`BURST`/`DELTA` skip `verifiedPayload`; only
    /// MeshPass admits the link), so a Byzantine admitted peer can forge any
    /// field here. It MUST NOT feed an authority/attribution decision: the
    /// client-visible roster/oper/modes surface flows through the SEPARATE,
    /// origin-gated `MEMBERSHIP` + `CHANNEL_MODE_STATE` paths. Today only member
    /// LIVENESS is read (`refreshChannelRoute`); `members[].dot.replica_id` and
    /// `.modes` have zero readers. The moment any consumer reads those for a
    /// decision — or this shadow becomes a delivered user channel — the per-fact
    /// signing gap (`signed_frame.zig:126-133`) must be closed FIRST, or forged
    /// facts stop being inert. The committed Byzantine tripwire test pins this.
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
    /// Most recent mesh PING→PONG round-trip in ms (null until the first sample).
    /// Heartbeat / explicit RTT probes stamp an 8-byte little-endian monotonic
    /// send time into the PING payload; the matching PONG echoes it.
    last_rtt_ms: ?u32 = null,
    config: Config,
    /// This node's Ed25519 signing keypair (set on secured links), or null on the
    /// legacy unsigned (plaintext) path. When set, in-scope outbound frames are
    /// wrapped in a `signed_frame` envelope iff the peer advertised signing.
    signing_key: ?sign.KeyPair = null,
    /// Signed MeshPass frame-family rights admitted for the remote peer. Zero
    /// means this link was not admitted by a signed MeshPass token, preserving
    /// legacy/open/shared-secret behavior.
    admitted_frame_families: u32 = 0,
    /// Local transport authorization from the outer Mooring-secured adapter.
    /// Signing ability alone is insufficient: signed plaintext stays disabled.
    session_replica_transport_enabled: bool = false,
    /// Local authorization to negotiate and accept only SRTF3 attachment-scoped
    /// objects on this link. False keeps the established v2 behavior intact.
    session_replica_attachment_transport_enabled: bool = false,
    /// Local authorization from the outer Mooring-secured adapter for relay v2.
    secure_relay_transport_enabled: bool = false,
    /// Local authorization from the outer Mooring-secured adapter for Event
    /// Spine v2. A signing key alone cannot activate this transport.
    event_spine_v2_transport_enabled: bool = false,
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
    /// True only when the remote advertised both frame signing and the explicit
    /// SESSION_REPLICA v2 capability. Local key presence is checked separately,
    /// so plaintext links cannot activate the transport by forging capability bits.
    peer_supports_session_replica_v2: bool = false,
    /// Remote advertised signing, SESSION_REPLICA v2, and the independently
    /// rolling-upgrade-safe attachment-lease extension.
    peer_supports_session_attachment_lease_v2: bool = false,
    /// Remote answered the append-only SRTF3 extension probe. Once true, every
    /// replica frame on this link must carry version 3; no decoder fallback is
    /// allowed after malformed or mismatched input.
    peer_supports_session_replica_v3: bool = false,
    /// Remote advertised frame signing plus the explicit secure-relay-v2 bit.
    peer_supports_secure_relay_v2: bool = false,
    /// Negotiated safely over the legacy PING/PONG extension probe. Old peers
    /// merely echo/ignore these payloads, so they never receive the 17-field
    /// relay schema or MESSAGE_V2_ACK tag they cannot decode.
    peer_supports_relay_v2_current: bool = false,
    /// Remote negotiated the ACK-confirm extension. This lets admitted receipts
    /// remain durable until the original sender explicitly confirms ACK receipt,
    /// instead of relying on a finite replay-window guess.
    peer_supports_relay_v2_ack_confirm: bool = false,
    /// Remote answered the append-only E2EEGROUP v2 schema probe (ACK/ACK_CONFIRM
    /// retirement). Separate from the handshake byte; valid only atop secure
    /// relay v2 base.
    peer_supports_e2ee_group_current: bool = false,
    /// Remote advertised frame signing plus the explicit event-spine-v2 bit.
    peer_supports_event_spine_v2: bool = false,
    /// Daemon-supplied residence-proof verifier (Design C / F1). Null (default,
    /// and always on non-daemon/test peers) ⇒ no account is ever trusted ⇒ every
    /// same-account short-circuit stays on the conservative UID path.
    residence_verifier: ?ResidenceVerifier = null,
    /// Receiver-owned exact-session resolver. Null deliberately means unbound:
    /// compatibility MEMBERSHIP still converges, but later token reconciliation
    /// cannot mistake an ambiguous row for signed session authority.
    session_token_resolver: ?SessionTokenResolver = null,
    /// Exact-token NICKCHANGE gate. Null is deliberately fail-closed for a
    /// token-tagged old identity; unbound compatibility nicks remain legacy.
    session_token_nick_authorizer: ?SessionTokenNickAuthorizer = null,
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
    /// Verified secured relay-v2 events awaiting daemon-global replay admission,
    /// local delivery, and correctness-first re-flooding.
    inbound_v2: std.ArrayListUnmanaged(InboundMessageV2) = .empty,
    /// Secured hop receipts awaiting daemon-global retained-outbox removal.
    inbound_v2_acks: std.ArrayListUnmanaged(message_relay_v2.RelayId) = .empty,
    inbound_v2_ack_confirms: std.ArrayListUnmanaged(message_relay_v2.RelayId) = .empty,
    dropped_relay_v2_frames: u64 = 0,
    rejected_relay_v2_frames: u64 = 0,
    /// Verified opaque group controls awaiting daemon-global replay admission.
    inbound_e2ee_group: std.ArrayListUnmanaged(InboundE2eeGroup) = .empty,
    /// Secured immediate-hop E2EEGROUP ACKs awaiting retained-outbox removal.
    inbound_e2ee_group_acks: std.ArrayListUnmanaged(e2ee_group_relay.RelayId) = .empty,
    /// Secured immediate-hop E2EEGROUP ACK_CONFIRMs awaiting ingress-receipt
    /// retirement (sender of the ACK confirms it saw the receipt).
    inbound_e2ee_group_ack_confirms: std.ArrayListUnmanaged(e2ee_group_relay.RelayId) = .empty,
    dropped_e2ee_group_frames: u64 = 0,
    rejected_e2ee_group_frames: u64 = 0,
    /// Inbound signed oper-grant payloads (raw oper_cred_share bytes) decoded
    /// from OPER_GRANT frames, awaiting the daemon to verify + ingest them.
    inbound_grants: std.ArrayListUnmanaged([]u8) = .empty,
    /// Remote channel membership changes (a peer's user joined/parted a channel)
    /// that actually altered the route table, awaiting the daemon to surface them
    /// as live `:nick JOIN/PART #chan` lines to local members. Re-affirmations
    /// (anti-entropy re-bursts) never enqueue here, so no duplicate JOINs.
    membership_changes: std.ArrayListUnmanaged(MembershipDelta) = .empty,
    /// Wire/application order shared by MEMBERSHIP and NICKCHANGE deltas. The
    /// payloads remain in their long-standing typed queues for compatibility;
    /// these markers let the daemon drain an identity transition atomically in
    /// the same order in which the route table accepted it.
    identity_transition_order: std.ArrayListUnmanaged(IdentityTransitionKind) = .empty,
    /// Remote aggregate channel MODE flag changes that won the LWW route-table
    /// state, awaiting the daemon to apply them to the local world and emit MODE.
    channel_mode_flag_changes: std.ArrayListUnmanaged(ChannelModeFlagsDelta) = .empty,
    /// Remote parameter/IRCX channel-state snapshots that won a per-channel LWW
    /// clock, awaiting daemon-side application and MODE emission.
    channel_mode_state_changes: std.ArrayListUnmanaged(ChannelModeStateDelta) = .empty,
    /// Per-channel LWW-dedup clocks for inbound `CHANNEL_MODE_STATE`, bounded to
    /// `max_channel_mode_state_clocks` with FIFO eviction (see `ChannelClockSet`).
    channel_mode_state_clocks: ChannelClockSet = .{},
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
    /// Inbound signed session-consumption tombstones. The daemon drains these
    /// before offers so a delayed offer cannot resurrect consumed state.
    session_migration_consumed: std.ArrayListUnmanaged([]u8) = .empty,
    /// Bounded, outer-authenticated SESSION_REPLICA v2 objects awaiting the
    /// daemon's inner Helix signature/semantic verification. Each item retains
    /// the authenticated immediate hop for future multipath routing decisions.
    session_replica_frames: std.ArrayListUnmanaged(InboundSessionReplica) = .empty,
    /// Bounded wire-ordered sidecars held across the feed/daemon Store boundary.
    /// Legacy/non-v2 links never enter this queue and retain immediate behavior.
    deferred_residence_frames: std.ArrayListUnmanaged(DeferredResidenceFrame) = .empty,
    dropped_session_replica_frames: u64 = 0,
    rejected_session_replica_frames: u64 = 0,
    /// Inbound CLONE_COUNT payloads (raw `mesh_clones` counts-codec bytes) from
    /// this peer, awaiting the daemon to decode + fold into its network-wide clone
    /// aggregate. The peer driver stays substrate-pure: it never decodes them.
    clone_counts: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified OPER_EVENT payloads received from this peer, awaiting the daemon
    /// to decode + deliver to its local oper subscribers. Substrate-pure: never
    /// decoded here.
    oper_events: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified OEVT v2 wires awaiting daemon-global replay admission, local
    /// delivery, and correctness-first forwarding across other secured legs.
    oper_events_v2: std.ArrayListUnmanaged(InboundOperEventV2) = .empty,
    dropped_oper_event_v2_frames: u64 = 0,
    rejected_oper_event_v2_frames: u64 = 0,
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
    /// Verified MEMO_PUSH payloads received from this peer, awaiting the daemon
    /// to decode and run local Web Push delivery. These are signing-required:
    /// legacy/plaintext peers are ignored so DM previews do not ride unsigned S2S.
    memo_pushes: std.ArrayListUnmanaged([]u8) = .empty,
    /// Verified MEDIA_WS_DATAGRAM payloads received from this peer, awaiting the
    /// daemon to fan out to local WS call participants. Signing-required;
    /// receivers never re-mesh (origin-only emit is the loop guard).
    media_ws_datagrams: std.ArrayListUnmanaged([]u8) = .empty,
    seen: message_relay.SeenSet,
    /// Per-link reflection cache only; not authoritative replay protection.
    seen_v2: message_relay_v2.SeenSet,
    /// Per-link E2EEGROUP reflection cache only; never replay authority.
    seen_e2ee_group: message_relay_v2.SeenSet,
    /// Event Spine v2 per-link reflection cache only. Never a replay authority.
    seen_oper_event_v2: message_relay_v2.SeenSet,

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
            .session_replica_transport_enabled = options.session_replica_transport_enabled,
            .session_replica_attachment_transport_enabled = options.session_replica_attachment_transport_enabled,
            .secure_relay_transport_enabled = options.secure_relay_transport_enabled,
            .event_spine_v2_transport_enabled = options.event_spine_v2_transport_enabled,
            .seen = message_relay.SeenSet.init(options.allocator, 1024),
            .seen_v2 = message_relay_v2.SeenSet.init(options.allocator, options.config.relay_v2_seen_capacity),
            .seen_e2ee_group = message_relay_v2.SeenSet.init(options.allocator, options.config.e2ee_group_seen_capacity),
            .seen_oper_event_v2 = message_relay_v2.SeenSet.init(options.allocator, options.config.oper_event_v2_seen_capacity),
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
        peer_supports_session_replica_v2: bool,
        peer_supports_session_attachment_lease_v2: bool,
        peer_supports_session_replica_v3: bool = false,
        /// Defaults preserve source compatibility for older snapshot producers;
        /// current Helix capture must set both fields explicitly.
        peer_supports_secure_relay_v2: bool = false,
        peer_supports_event_spine_v2: bool = false,
        peer_supports_relay_v2_current: bool = false,
        peer_supports_relay_v2_ack_confirm: bool = false,
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
            .peer_supports_session_replica_v2 = self.peer_supports_session_replica_v2,
            .peer_supports_session_attachment_lease_v2 = self.peer_supports_session_attachment_lease_v2,
            .peer_supports_session_replica_v3 = self.peer_supports_session_replica_v3,
            .peer_supports_secure_relay_v2 = self.peer_supports_secure_relay_v2,
            .peer_supports_event_spine_v2 = self.peer_supports_event_spine_v2,
            .peer_supports_relay_v2_current = self.peer_supports_relay_v2_current,
            .peer_supports_relay_v2_ack_confirm = self.peer_supports_relay_v2_ack_confirm,
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
            .peer_supports_session_replica_v2 = hdr.peer_supports_signing and hdr.peer_supports_session_replica_v2,
            .peer_supports_session_attachment_lease_v2 = hdr.peer_supports_signing and
                hdr.peer_supports_session_replica_v2 and
                hdr.peer_supports_session_attachment_lease_v2,
            .peer_supports_session_replica_v3 = options.session_replica_attachment_transport_enabled and
                hdr.peer_supports_signing and hdr.peer_supports_session_replica_v2 and
                hdr.peer_supports_session_replica_v3,
            .peer_supports_secure_relay_v2 = hdr.peer_supports_signing and hdr.peer_supports_secure_relay_v2,
            .peer_supports_event_spine_v2 = hdr.peer_supports_signing and hdr.peer_supports_event_spine_v2,
            .peer_supports_relay_v2_current = hdr.peer_supports_signing and
                hdr.peer_supports_secure_relay_v2 and hdr.peer_supports_relay_v2_current,
            .peer_supports_relay_v2_ack_confirm = hdr.peer_supports_signing and
                hdr.peer_supports_secure_relay_v2 and hdr.peer_supports_relay_v2_current and
                hdr.peer_supports_relay_v2_ack_confirm,
            .config = options.config,
            .signing_key = options.signing_key,
            .admitted_frame_families = options.admitted_frame_families,
            .session_replica_transport_enabled = options.session_replica_transport_enabled,
            .session_replica_attachment_transport_enabled = options.session_replica_attachment_transport_enabled,
            .secure_relay_transport_enabled = options.secure_relay_transport_enabled,
            .event_spine_v2_transport_enabled = options.event_spine_v2_transport_enabled,
            .seen = message_relay.SeenSet.init(options.allocator, 1024),
            .seen_v2 = message_relay_v2.SeenSet.init(options.allocator, options.config.relay_v2_seen_capacity),
            .seen_e2ee_group = message_relay_v2.SeenSet.init(options.allocator, options.config.e2ee_group_seen_capacity),
            .seen_oper_event_v2 = message_relay_v2.SeenSet.init(options.allocator, options.config.oper_event_v2_seen_capacity),
        };
    }

    pub fn deinit(self: *S2sPeer) void {
        for (self.inbound.items) |*owned| owned.deinit(self.allocator);
        self.inbound.deinit(self.allocator);
        for (self.inbound_v2.items) |*owned| owned.deinit(self.allocator);
        self.inbound_v2.deinit(self.allocator);
        self.inbound_v2_acks.deinit(self.allocator);
        self.inbound_v2_ack_confirms.deinit(self.allocator);
        for (self.inbound_e2ee_group.items) |*record| record.deinit(self.allocator);
        self.inbound_e2ee_group.deinit(self.allocator);
        self.inbound_e2ee_group_acks.deinit(self.allocator);
        self.inbound_e2ee_group_ack_confirms.deinit(self.allocator);
        for (self.inbound_grants.items) |g| self.allocator.free(g);
        self.inbound_grants.deinit(self.allocator);
        for (self.membership_changes.items) |*d| d.deinit(self.allocator);
        self.membership_changes.deinit(self.allocator);
        self.identity_transition_order.deinit(self.allocator);
        for (self.channel_mode_flag_changes.items) |*d| d.deinit(self.allocator);
        self.channel_mode_flag_changes.deinit(self.allocator);
        for (self.channel_mode_state_changes.items) |*d| d.deinit(self.allocator);
        self.channel_mode_state_changes.deinit(self.allocator);
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
        for (self.session_migration_consumed.items) |m| self.allocator.free(m);
        self.session_migration_consumed.deinit(self.allocator);
        for (self.session_replica_frames.items) |*frame| frame.deinit(self.allocator);
        self.session_replica_frames.deinit(self.allocator);
        for (self.deferred_residence_frames.items) |*frame| frame.deinit(self.allocator);
        self.deferred_residence_frames.deinit(self.allocator);
        for (self.clone_counts.items) |m| self.allocator.free(m);
        self.clone_counts.deinit(self.allocator);
        for (self.oper_events.items) |m| self.allocator.free(m);
        self.oper_events.deinit(self.allocator);
        for (self.oper_events_v2.items) |*event| event.deinit(self.allocator);
        self.oper_events_v2.deinit(self.allocator);
        for (self.observe_events.items) |m| self.allocator.free(m);
        self.observe_events.deinit(self.allocator);
        for (self.kills.items) |m| self.allocator.free(m);
        self.kills.deinit(self.allocator);
        for (self.wards.items) |m| self.allocator.free(m);
        self.wards.deinit(self.allocator);
        for (self.memo_pushes.items) |m| self.allocator.free(m);
        self.memo_pushes.deinit(self.allocator);
        for (self.media_ws_datagrams.items) |m| self.allocator.free(m);
        self.media_ws_datagrams.deinit(self.allocator);
        self.seen.deinit();
        self.seen_v2.deinit();
        self.seen_e2ee_group.deinit();
        self.seen_oper_event_v2.deinit();
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

    /// Emit a timestamped PING so the matching PONG can sample mesh RTT.
    /// Payload is an 8-byte little-endian monotonic `now_ms` (echoed by peers).
    pub fn sendRttProbe(self: *S2sPeer, sink: ByteSink, now_ms: u64) !void {
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, payload[0..8], now_ms, .little);
        try emitFrame(self.allocator, sink, .PING, &payload);
    }

    /// Latest observed PING→PONG RTT in milliseconds, or null if never sampled.
    pub fn lastRttMs(self: *const S2sPeer) ?u32 {
        return self.last_rtt_ms;
    }

    fn noteRttSample(self: *S2sPeer, payload: []const u8, now_ms: u64) void {
        if (payload.len != 8) return;
        const sent = std.mem.readInt(u64, payload[0..8], .little);
        if (now_ms < sent) return;
        const delta = now_ms - sent;
        // Cap pathological samples (clock jumps, stalled peers) so public status
        // never claims multi-hour "latency".
        if (delta > 600_000) return;
        self.last_rtt_ms = @intCast(delta);
    }

    /// Ask the peer to re-send its full converged state (used right after a Helix
    /// resume). Unsigned control frame — carries no trusted state itself.
    pub fn sendResync(self: *S2sPeer, sink: ByteSink) !void {
        // A preserved Helix link bypasses the ordinary handshake after exec, so
        // refresh our current capability byte before asking for state replay.
        // The receiver answers RESYNC with one HANDSHAKE of its own; unlike a
        // HANDSHAKE-triggered reply this cannot ping-pong indefinitely.
        try self.emitHandshake(sink);
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
            // Timestamped heartbeat: peer echoes the payload as PONG so we can
            // sample mesh RTT for status/MESH without a separate probe family.
            try self.sendRttProbe(sink, now_ms);
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
    /// the populated entry (LINKS fell back to "Undertow peer") while the WHOIS
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

    pub fn bestNickClaim(self: *const S2sPeer, nick: []const u8) ?NickClaim {
        return self.routes.bestNickClaim(nick);
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
                if (std.mem.eql(u8, frame.payload, relay_v2_extension_probe))
                    try emitFrame(self.allocator, sink, .PONG, relay_v2_extension_reply);
                if (std.mem.eql(u8, frame.payload, relay_v2_ack_confirm_probe))
                    try emitFrame(self.allocator, sink, .PONG, relay_v2_ack_confirm_reply);
                if (std.mem.eql(u8, frame.payload, e2ee_group_extension_probe) and
                    self.supportsSecureRelayV2Base())
                    try emitFrame(self.allocator, sink, .PONG, e2ee_group_extension_reply);
                if (std.mem.eql(u8, frame.payload, session_replica_v3_probe) and
                    self.session_replica_attachment_transport_enabled and
                    self.session_replica_transport_enabled and self.signing_key != null and
                    self.peer_supports_signing and self.peer_supports_session_replica_v2)
                {
                    try emitFrame(self.allocator, sink, .PONG, session_replica_v3_reply);
                }
            },
            .PONG => {
                self.pong_rx_count += 1;
                self.noteRttSample(frame.payload, now_ms);
                if (std.mem.eql(u8, frame.payload, relay_v2_extension_reply) and
                    self.peer_supports_secure_relay_v2)
                    self.peer_supports_relay_v2_current = true;
                if (std.mem.eql(u8, frame.payload, relay_v2_ack_confirm_reply) and
                    self.peer_supports_secure_relay_v2)
                    self.peer_supports_relay_v2_ack_confirm = true;
                if (std.mem.eql(u8, frame.payload, e2ee_group_extension_reply) and
                    self.supportsSecureRelayV2Base())
                    self.peer_supports_e2ee_group_current = true;
                if (std.mem.eql(u8, frame.payload, session_replica_v3_reply) and
                    self.session_replica_attachment_transport_enabled and
                    self.peer_supports_signing and self.peer_supports_session_replica_v2)
                {
                    self.peer_supports_session_replica_v3 = true;
                }
            },
            .QUIT => self.closeRemote(),
            .MEMBERSHIP => if (self.supportsSessionReplicaV2())
                self.deferResidenceFrame(.membership, frame.payload)
            else
                try self.recvMembership(frame.payload, now_ms),
            .CHANNEL_MODE_FLAGS => try self.recvChannelModeFlags(frame.payload),
            .CHANNEL_LIST => try self.recvChannelList(frame.payload),
            .TOPIC => try self.recvTopic(frame.payload),
            .NICKCHANGE => if (self.supportsSessionReplicaV2())
                self.deferResidenceFrame(.nick_change, frame.payload)
            else
                try self.recvNickChange(frame.payload),
            .MESSAGE => try self.recvMessage(frame.payload),
            .MESSAGE_V2 => try self.recvMessageV2(frame.payload),
            .MESSAGE_V2_ACK => try self.recvMessageV2Ack(frame.payload),
            .E2EE_GROUP => try self.recvE2eeGroup(frame.payload),
            .E2EE_GROUP_ACK => try self.recvE2eeGroupAck(frame.payload),
            .OPER_GRANT => try self.recvOperGrant(frame.payload),
            .CHANNEL_PROP => try self.recvChannelProp(frame.payload),
            .ENTITY_PROP => try self.recvEntityProp(frame.payload),
            .CHANNEL_MODE_STATE => try self.recvChannelModeState(frame.payload),
            .SESSION_MIGRATE => try self.recvSessionMigrate(frame.payload),
            .SESSION_MIGRATE_CONSUMED => try self.recvSessionMigrateConsumed(frame.payload),
            .SESSION_REPLICA_OFFER => self.recvSessionReplica(.offer, frame.payload),
            .SESSION_REPLICA_ACK => self.recvSessionReplica(.ack, frame.payload),
            .SESSION_REPLICA_REVOKE => self.recvSessionReplica(.revoke, frame.payload),
            .SESSION_REPLICA_ATTACHMENT_LEASE => self.recvSessionReplica(.attachment_lease, frame.payload),
            .CLONE_COUNT => try self.recvCloneCounts(frame.payload),
            .OPER_EVENT => try self.recvOperEvent(frame.payload),
            .OPER_EVENT_V2 => self.recvOperEventV2(frame.payload),
            .OBSERVE_EVENT => try self.recvObserveEvent(frame.payload),
            .KILL => try self.recvKill(frame.payload),
            .WARD => try self.recvWard(frame.payload),
            .RESYNC => {
                self.resync_requested = true;
                // RESYNC is also the one-shot capability-refresh request for a
                // preserved established stream. Reply with HANDSHAKE, but never
                // reply merely because a HANDSHAKE arrived: that would create an
                // unbounded control-frame echo between two upgraded peers.
                if (self.established) try self.emitHandshake(sink);
            },
            .REPAIR_SUMMARY => try self.recvRepairSummary(frame.payload, sink),
            .REPAIR_REQUEST => try self.recvRepairRequest(frame.payload, sink),
            .REPAIR_RESPONSE => try self.recvRepairResponse(frame.payload),
            .MEMO_PUSH => try self.recvMemoPush(frame.payload),
            .MEDIA_WS_DATAGRAM => try self.recvMediaWsDatagram(frame.payload),
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
        const framed_len = try s2s_frame.encodedLen(frame_bytes.len);
        if (framed_len > self.config.max_frame_size) return error.PayloadTooLarge;
        try emitFrame(self.allocator, sink, .SESSION_MIGRATE, frame_bytes);
    }

    fn recvSessionMigrateConsumed(self: *S2sPeer, payload: []const u8) !void {
        if (!self.acceptsDirectOrigin(self.remote_node_id)) return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.session_migration_consumed.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    pub fn takeSessionMigrateConsumed(self: *S2sPeer) ![][]u8 {
        return self.session_migration_consumed.toOwnedSlice(self.allocator);
    }

    pub fn sendSessionMigrateConsumed(self: *S2sPeer, sink: ByteSink, payload: []const u8) !void {
        try emitFrame(self.allocator, sink, .SESSION_MIGRATE_CONSUMED, payload);
    }

    /// Stage one exactly-negotiated SESSION_REPLICA object after capability and
    /// direct-peer outer-signature checks. The Helix object remains opaque here;
    /// the daemon callback verifies its inner origin signature and applies it to
    /// the future per-destination replica store. Malformed, unnegotiated, and
    /// over-capacity input is dropped without faulting the mesh link.
    fn recvSessionReplica(self: *S2sPeer, kind: session_replica_frame.Kind, frame_payload: []const u8) void {
        if (!self.supportsSessionReplicaV2() or
            (kind == .attachment_lease and !self.supportsSessionAttachmentLeaseV2()))
        {
            self.rejected_session_replica_frames +|= 1;
            return;
        }
        const frame_type = replicaFrameType(kind);
        const authenticated = self.verifiedPayload(frame_type, frame_payload) orelse return;
        const version = session_replica_frame.inspectVersion(authenticated) catch {
            self.rejected_session_replica_frames +|= 1;
            return;
        };
        const expected_version: session_replica_frame.WireVersion =
            if (self.peer_supports_session_replica_v3) .attachment_v3 else .token_v2;
        if (version != expected_version) {
            self.rejected_session_replica_frames +|= 1;
            return;
        }
        const decoded = switch (version) {
            .token_v2 => session_replica_frame.decode(kind, authenticated),
            .attachment_v3 => session_replica_frame.decodeAttachment(kind, authenticated),
        } catch {
            self.rejected_session_replica_frames +|= 1;
            return;
        };
        if (self.session_replica_frames.items.len >= self.config.max_session_replica_frames) {
            self.dropped_session_replica_frames +|= 1;
            return;
        }
        const owned = self.allocator.dupe(u8, decoded.signed_payload) catch {
            self.dropped_session_replica_frames +|= 1;
            return;
        };
        self.session_replica_frames.append(self.allocator, .{
            .version = version,
            .kind = kind,
            .via_peer = self.remote_node_id,
            .signed_payload = owned,
        }) catch {
            self.allocator.free(owned);
            self.dropped_session_replica_frames +|= 1;
        };
    }

    /// Drain authenticated transport objects. Caller owns the returned slice and
    /// must `deinit` every item. `via_peer` is the authenticated immediate hop.
    pub fn takeSessionReplicaFrames(self: *S2sPeer) ![]InboundSessionReplica {
        return self.session_replica_frames.toOwnedSlice(self.allocator);
    }

    /// Allocation-free ordered ownership transfer for the daemon hot path. The
    /// queue is capped at 64, so ordered removal is bounded and preserves wire
    /// order without a toOwnedSlice allocation that could split the authority
    /// and residence sides of one feed under OOM.
    pub fn takeNextSessionReplicaFrame(self: *S2sPeer) ?InboundSessionReplica {
        if (self.session_replica_frames.items.len == 0) return null;
        return self.session_replica_frames.orderedRemove(0);
    }

    pub fn takeDroppedSessionReplicaFrames(self: *S2sPeer) u64 {
        const count = self.dropped_session_replica_frames;
        self.dropped_session_replica_frames = 0;
        return count;
    }

    fn deferResidenceFrame(
        self: *S2sPeer,
        kind: DeferredResidenceFrame.Kind,
        outer_payload: []const u8,
    ) void {
        const frame_type: s2s_frame.FrameType = switch (kind) {
            .membership => .MEMBERSHIP,
            .nick_change => .NICKCHANGE,
        };
        // Authenticate the outer hop before allocating, then validate the small
        // family codec and retain only its inner payload. An attacker can no
        // longer pin max-frame-sized signed envelopes in this 64-item queue.
        const payload = self.verifiedPayload(frame_type, outer_payload) orelse return;
        switch (kind) {
            .membership => _ = membership_event.decode(payload) catch return,
            .nick_change => _ = nick_event.decode(payload) catch return,
        }
        if (self.deferred_residence_frames.items.len >= self.config.max_session_replica_frames) {
            self.dropped_session_replica_frames +|= 1;
            return;
        }
        const owned = self.allocator.dupe(u8, payload) catch {
            self.dropped_session_replica_frames +|= 1;
            return;
        };
        self.deferred_residence_frames.append(self.allocator, .{
            .kind = kind,
            .payload = owned,
        }) catch {
            self.allocator.free(owned);
            self.dropped_session_replica_frames +|= 1;
        };
    }

    /// Apply v2 residence-dependent sidecars only after the daemon has committed
    /// every queued authority object from the same feed. One mixed queue retains
    /// NICK/MEMBERSHIP wire order across the family boundary.
    pub fn processDeferredResidenceFrames(self: *S2sPeer, now_ms: u64) void {
        // Processing cannot append to this queue, so consume in place. This
        // avoids a toOwnedSlice allocation whose OOM path could strand an old
        // batch until after unrelated authority arrived.
        for (self.deferred_residence_frames.items) |*frame| {
            defer frame.deinit(self.allocator);
            switch (frame.kind) {
                .membership => self.applyMembershipPayload(frame.payload, now_ms) catch {},
                .nick_change => self.applyNickChangePayload(frame.payload) catch {},
            }
        }
        self.deferred_residence_frames.clearRetainingCapacity();
    }

    /// A dropped authority/sidecar frame makes the feed incomplete. Discard all
    /// correlated token-less claims; the daemon requests RESYNC from the peer.
    pub fn discardDeferredResidenceFrames(self: *S2sPeer) void {
        for (self.deferred_residence_frames.items) |*frame| frame.deinit(self.allocator);
        self.deferred_residence_frames.clearRetainingCapacity();
    }

    /// True only on an established, signing-key-backed link where the remote
    /// negotiated both direct-frame signing and SESSION_REPLICA v2.
    pub fn supportsSessionReplicaV2(self: *const S2sPeer) bool {
        return self.established and self.session_replica_transport_enabled and self.signing_key != null and self.peer_supports_signing and self.peer_supports_session_replica_v2;
    }

    pub fn supportsSessionAttachmentLeaseV2(self: *const S2sPeer) bool {
        return self.supportsSessionReplicaV2() and self.peer_supports_session_attachment_lease_v2;
    }

    /// Once negotiated, version 3 is the only accepted replica schema for this
    /// preserved link. The v2 base bit still proves the outer frame family and
    /// signing support; this append-only extension selects the inner schema.
    pub fn supportsSessionReplicaV3(self: *const S2sPeer) bool {
        return self.supportsSessionReplicaV2() and
            self.session_replica_attachment_transport_enabled and
            self.peer_supports_session_replica_v3;
    }

    /// Encode, capability-gate, outer-sign, and emit one opaque Helix object.
    /// This never falls back to plaintext or legacy SESSION_MIGRATE frames.
    pub fn sendSessionReplica(self: *S2sPeer, sink: ByteSink, kind: session_replica_frame.Kind, signed_payload: []const u8) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.session_replica_transport_enabled or self.signing_key == null or !self.peer_supports_signing) return error.SecuredLinkRequired;
        if (!self.peer_supports_session_replica_v2) return error.CapabilityNotNegotiated;
        if (self.peer_supports_session_replica_v3) return error.CapabilityVersionMismatch;
        if (kind == .attachment_lease and !self.peer_supports_session_attachment_lease_v2)
            return error.CapabilityNotNegotiated;

        const len = try session_replica_frame.encodedLen(signed_payload.len);
        const framed_len = s2s_frame.header_len + signed_frame.header_len + len;
        if (framed_len > self.config.max_frame_size) return error.PayloadTooLarge;
        const transport = try self.allocator.alloc(u8, len);
        defer self.allocator.free(transport);
        const encoded = try session_replica_frame.encode(kind, signed_payload, transport);
        try self.emitSignable(sink, replicaFrameType(kind), encoded);
    }

    /// Attachment-scoped counterpart to `sendSessionReplica`. There is no
    /// compatibility fallback: until the distinct extension reply is observed,
    /// SRA3 objects remain local and the caller retries later.
    pub fn sendAttachmentSessionReplica(
        self: *S2sPeer,
        sink: ByteSink,
        kind: session_replica_frame.Kind,
        signed_payload: []const u8,
    ) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.session_replica_transport_enabled or
            !self.session_replica_attachment_transport_enabled or
            self.signing_key == null or !self.peer_supports_signing)
        {
            return error.SecuredLinkRequired;
        }
        if (!self.peer_supports_session_replica_v2 or !self.peer_supports_session_replica_v3)
            return error.CapabilityNotNegotiated;

        const len = try session_replica_frame.encodedLen(signed_payload.len);
        const framed_len = s2s_frame.header_len + signed_frame.header_len + len;
        if (framed_len > self.config.max_frame_size) return error.PayloadTooLarge;
        const transport = try self.allocator.alloc(u8, len);
        defer self.allocator.free(transport);
        const encoded = try session_replica_frame.encodeAttachment(kind, signed_payload, transport);
        try self.emitSignable(sink, replicaFrameType(kind), encoded);
    }

    pub fn sendSessionReplicaOffer(self: *S2sPeer, sink: ByteSink, signed_offer: []const u8) !void {
        try self.sendSessionReplica(sink, .offer, signed_offer);
    }

    pub fn sendSessionReplicaAck(self: *S2sPeer, sink: ByteSink, signed_ack: []const u8) !void {
        try self.sendSessionReplica(sink, .ack, signed_ack);
    }

    pub fn sendSessionReplicaRevoke(self: *S2sPeer, sink: ByteSink, signed_revoke: []const u8) !void {
        try self.sendSessionReplica(sink, .revoke, signed_revoke);
    }

    pub fn sendSessionAttachmentLease(self: *S2sPeer, sink: ByteSink, signed_lease: []const u8) !void {
        try self.sendSessionReplica(sink, .attachment_lease, signed_lease);
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

    /// Queue a verified legacy OPER_EVENT v1 for local daemon delivery only.
    /// It has no immutable event identity or end-to-end origin signature and
    /// therefore has deliberately no forwarding API.
    fn recvOperEvent(self: *S2sPeer, frame_payload: []const u8) !void {
        const payload = self.verifiedPayload(.OPER_EVENT, frame_payload) orelse return;
        _ = oper_event.decodeLegacyV1(payload) catch return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.oper_events.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued inbound OPER_EVENT payloads (caller owns + frees each slice and
    /// the outer slice). Each decodes with `oper_event.decode`.
    pub fn takeOperEvents(self: *S2sPeer) ![][]u8 {
        return self.oper_events.toOwnedSlice(self.allocator);
    }

    /// Emit a direct-leaf legacy OPER_EVENT v1. It is retained for rolling
    /// compatibility but receivers must never re-flood it.
    pub fn sendLegacyOperEvent(self: *S2sPeer, sink: ByteSink, category: u6, severity: u8, origin_server: []const u8, message: []const u8) !void {
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

    /// Source-compatible name for the deployed v1 direct-leaf API. New mesh
    /// flooding must use the explicit v2 author/forward methods below.
    pub fn sendOperEvent(self: *S2sPeer, sink: ByteSink, category: u6, severity: u8, origin_server: []const u8, message: []const u8) !void {
        try self.sendLegacyOperEvent(sink, category, severity, origin_server, message);
    }

    /// True only on an established Mooring-authorized link where both ends
    /// negotiated frame signing and Event Spine v2.
    pub fn supportsEventSpineV2(self: *const S2sPeer) bool {
        return self.established and self.event_spine_v2_transport_enabled and
            self.signing_key != null and self.peer_supports_signing and
            self.peer_supports_event_spine_v2;
    }

    /// Verify immediate-hop authentication and the immutable author's signature
    /// before touching the per-link reflection cache. Invalid or unnegotiated
    /// traffic therefore cannot poison a later valid event's replay identity.
    fn recvOperEventV2(self: *S2sPeer, outer_payload: []const u8) void {
        if (!self.supportsEventSpineV2()) {
            self.rejected_oper_event_v2_frames +|= 1;
            return;
        }
        const payload = self.verifiedPayload(.OPER_EVENT_V2, outer_payload) orelse {
            self.rejected_oper_event_v2_frames +|= 1;
            return;
        };
        const event = oper_event.decodeV2(payload) catch {
            self.rejected_oper_event_v2_frames +|= 1;
            return;
        };
        const verified = switch (oper_event.verifyAndEventId(event)) {
            .verified => |value| value,
            .origin_mismatch, .bad_signature, .invalid_semantic => {
                self.rejected_oper_event_v2_frames +|= 1;
                return;
            },
        };
        // Never suppress verified ingress with this non-authoritative cache.
        // The daemon may have rejected a prior queued copy recoverably, so a
        // same-leg retry must reach the durable global guard again. The cache
        // only suppresses outbound reflection.
        if (self.oper_events_v2.items.len >= self.config.max_oper_event_v2_frames) {
            self.dropped_oper_event_v2_frames +|= 1;
            return;
        }
        const wire = self.allocator.dupe(u8, payload) catch {
            self.dropped_oper_event_v2_frames +|= 1;
            return;
        };
        self.oper_events_v2.append(self.allocator, .{
            .wire = wire,
            .via_peer = self.remote_node_id,
        }) catch {
            self.dropped_oper_event_v2_frames +|= 1;
            self.allocator.free(wire);
            return;
        };
        // Record only after queue ownership succeeds. This remains a per-link
        // reflection optimization; daemon-global replay admission is authoritative.
        _ = self.seen_oper_event_v2.observe(verified.event_id);
    }

    fn requireEventSpineV2(self: *const S2sPeer) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.event_spine_v2_transport_enabled or self.signing_key == null or !self.peer_supports_signing)
            return error.SecuredLinkRequired;
        if (!self.peer_supports_event_spine_v2) return error.CapabilityNotNegotiated;
    }

    /// Emit canonical v2 bytes from an already-stamped event object. The inner
    /// author may be this node or a third node; no origin field is rewritten.
    pub fn sendOperEventV2(self: *S2sPeer, sink: ByteSink, event: oper_event.SignedOperEventV2) !bool {
        try self.requireEventSpineV2();
        const verified = switch (oper_event.verifyAndEventId(event)) {
            .verified => |value| value,
            .origin_mismatch => return error.OriginMismatch,
            .bad_signature => return error.BadOriginSignature,
            .invalid_semantic => return error.InvalidOperEvent,
        };
        if (self.seen_oper_event_v2.contains(verified.event_id)) return false;
        var buf: [oper_event.max_v2_encoded_len]u8 = undefined;
        const wire = try oper_event.encodeV2(event, &buf);
        try self.sendOperEventV2Wire(sink, wire, verified.event_id);
        return true;
    }

    /// Author, origin-sign, and send one canonical Event Spine v2 object. Signed
    /// fields are never truncated: oversize/invalid input fails before emission.
    pub fn sendOperEventV2Authored(
        self: *S2sPeer,
        sink: ByteSink,
        category: u6,
        severity: u8,
        hlc: u64,
        origin_server: []const u8,
        subject: []const u8,
        message: []const u8,
    ) !bool {
        try self.requireEventSpineV2();
        var pubkey: [oper_event.pubkey_len]u8 = undefined;
        var signature: [oper_event.sig_len]u8 = undefined;
        var event = oper_event.SignedOperEventV2{
            .category = category,
            .severity = severity,
            .origin_node = self.local_node_id,
            .hlc = hlc,
            .origin_server = origin_server,
            .subject = subject,
            .message = message,
        };
        try oper_event.stampOrigin(&event, &self.signing_key.?, &pubkey, &signature);
        return self.sendOperEventV2(sink, event);
    }

    /// Relay the exact received OEVT v2 byte image under this immediate hop's
    /// outer signed envelope. Strict decode and origin verification occur before
    /// the reflection cache is consulted or mutated.
    pub fn forwardOperEventV2(self: *S2sPeer, sink: ByteSink, wire: []const u8) !bool {
        try self.requireEventSpineV2();
        const event = oper_event.decodeV2(wire) catch return error.InvalidOperEvent;
        const verified = switch (oper_event.verifyAndEventId(event)) {
            .verified => |value| value,
            .origin_mismatch => return error.OriginMismatch,
            .bad_signature => return error.BadOriginSignature,
            .invalid_semantic => return error.InvalidOperEvent,
        };
        if (self.seen_oper_event_v2.contains(verified.event_id)) return false;
        try self.sendOperEventV2Wire(sink, wire, verified.event_id);
        return true;
    }

    fn sendOperEventV2Wire(self: *S2sPeer, sink: ByteSink, wire: []const u8, event_id: oper_event.EventId) !void {
        const framed_len = s2s_frame.header_len + signed_frame.header_len + wire.len;
        if (framed_len > self.config.max_frame_size) return error.PayloadTooLarge;
        try self.emitSignable(sink, .OPER_EVENT_V2, wire);
        _ = self.seen_oper_event_v2.observe(event_id);
    }

    /// Transfer verified immutable wires to the daemon. Caller deinitializes each
    /// item and frees the returned slice.
    pub fn takeOperEventsV2(self: *S2sPeer) ![]InboundOperEventV2 {
        return self.oper_events_v2.toOwnedSlice(self.allocator);
    }

    pub fn takeDroppedOperEventV2Frames(self: *S2sPeer) u64 {
        defer self.dropped_oper_event_v2_frames = 0;
        return self.dropped_oper_event_v2_frames;
    }

    pub fn takeRejectedOperEventV2Frames(self: *S2sPeer) u64 {
        defer self.rejected_oper_event_v2_frames = 0;
        return self.rejected_oper_event_v2_frames;
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

    /// Queue a verified inbound MEMO_PUSH hint for daemon-side Web Push
    /// delivery. Unlike older direct-owned frames, this is signing-required:
    /// peers that did not negotiate frame signing are ignored, because the payload
    /// carries a DM preview and should only ride the secured node-identity path.
    fn recvMemoPush(self: *S2sPeer, frame_payload: []const u8) !void {
        if (!self.peer_supports_signing) return;
        const payload = self.verifiedPayload(.MEMO_PUSH, frame_payload) orelse return;
        _ = memo_push_relay.decode(payload) catch return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.memo_pushes.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued MEMO_PUSH payloads (caller owns + frees each slice and the
    /// outer slice). Each decodes with `memo_push_relay.decode`.
    pub fn takeMemoPushes(self: *S2sPeer) ![][]u8 {
        return self.memo_pushes.toOwnedSlice(self.allocator);
    }

    /// Emit a signed MEMO_PUSH hint to this peer. No-op unless the peer
    /// negotiated frame signing and this node has a signing key; this avoids
    /// leaking DM previews onto legacy/plaintext S2S links.
    pub fn sendMemoPush(self: *S2sPeer, sink: ByteSink, account: []const u8, from: []const u8, text: []const u8) !void {
        if (!self.peer_supports_signing or self.signing_key == null) return;
        var buf: [memo_push_relay.max_encoded_len]u8 = undefined;
        const wire = try memo_push_relay.encode(.{ .account = account, .from = from, .text = text }, &buf);
        try self.emitSignable(sink, .MEMO_PUSH, wire);
    }

    /// Queue a verified inbound MEDIA_WS_DATAGRAM for daemon-side local WS
    /// fanout. Signing-required (same fail-closed posture as MEMO_PUSH). Decode
    /// validates channel/datagram bounds before the copy is retained; queue
    /// overflow drops the newest frame rather than growing unboundedly.
    fn recvMediaWsDatagram(self: *S2sPeer, frame_payload: []const u8) !void {
        if (!self.peer_supports_signing) return;
        const payload = self.verifiedPayload(.MEDIA_WS_DATAGRAM, frame_payload) orelse return;
        _ = media_ws_relay.decode(payload) catch return;
        if (self.media_ws_datagrams.items.len >= self.config.max_media_ws_datagrams) return;
        const owned = self.allocator.dupe(u8, payload) catch return;
        self.media_ws_datagrams.append(self.allocator, owned) catch self.allocator.free(owned);
    }

    /// Drain queued MEDIA_WS_DATAGRAM payloads (caller owns + frees each slice
    /// and the outer slice). Each decodes with `media_ws_relay.decode`.
    pub fn takeMediaWsDatagrams(self: *S2sPeer) ![][]u8 {
        return self.media_ws_datagrams.toOwnedSlice(self.allocator);
    }

    /// Emit a signed MEDIA_WS_DATAGRAM to this peer. Origin-only cascade of an
    /// already-validated browser Cadence datagram; no-op unless the peer
    /// negotiated frame signing and this node has a signing key. Oversize
    /// (relative to the peer's max_frame_size) fails closed as PayloadTooLarge.
    pub fn sendMediaWsDatagram(self: *S2sPeer, sink: ByteSink, channel: []const u8, datagram: []const u8) !void {
        if (!self.peer_supports_signing or self.signing_key == null) return;
        if (datagram.len == 0 or datagram.len > media_ws_relay.max_datagram_len) return error.PayloadTooLarge;
        if (channel.len == 0 or channel.len > media_ws_relay.max_channel_len) return error.InvalidField;

        const encoded_len = media_ws_relay.header_len + channel.len + datagram.len;
        const framed_len = s2s_frame.header_len + signed_frame.header_len + encoded_len;
        if (framed_len > self.config.max_frame_size) return error.PayloadTooLarge;

        const buf = try self.allocator.alloc(u8, encoded_len);
        defer self.allocator.free(buf);
        const wire = try media_ws_relay.encode(.{ .channel = channel, .datagram = datagram }, buf);
        try self.emitSignable(sink, .MEDIA_WS_DATAGRAM, wire);
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
        const auth = message_relay.verifyOrigin(self.allocator, owned.msg) catch {
            owned.deinit(self.allocator);
            return;
        };
        const duplicate = switch (auth) {
            .verified => self.seen.observe(owned.msg.origin_node, owned.msg.hlc),
            .unsigned => self.seen.observeUnsigned(owned.msg.origin_node, owned.msg.hlc),
            .origin_mismatch, .bad_signature => {
                owned.deinit(self.allocator);
                return;
            },
        };
        if (duplicate) {
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
        if (msg.origin_sig.len == 0) {
            _ = self.seen.observeUnsigned(msg.origin_node, msg.hlc);
        } else {
            _ = self.seen.observe(msg.origin_node, msg.hlc);
        }
        const wire = try message_relay.encode(self.allocator, msg);
        defer self.allocator.free(wire);
        try emitFrame(self.allocator, sink, .MESSAGE, wire);
    }

    /// Transfer ownership of all queued inbound messages to the caller, which
    /// must `deinit` each `Owned` and free the returned slice. Resets the queue.
    pub fn takeInbound(self: *S2sPeer) ![]message_relay.Owned {
        return self.inbound.toOwnedSlice(self.allocator);
    }

    /// True only on an established Mooring-authorized, signing-key-backed link
    /// where the remote negotiated frame signing and secure relay v2.
    fn supportsSecureRelayV2Base(self: *const S2sPeer) bool {
        return self.established and self.secure_relay_transport_enabled and
            self.signing_key != null and self.peer_supports_signing and
            self.peer_supports_secure_relay_v2;
    }

    pub fn supportsSecureRelayV2(self: *const S2sPeer) bool {
        return self.supportsSecureRelayV2Base() and self.peer_supports_relay_v2_current and
            self.peer_supports_relay_v2_ack_confirm;
    }

    pub fn supportsRelayV2AckConfirm(self: *const S2sPeer) bool {
        return self.supportsSecureRelayV2() and self.peer_supports_relay_v2_ack_confirm;
    }

    /// Verify the hop envelope and immutable origin signature before touching
    /// the per-link reflection cache. Invalid traffic can therefore never poison
    /// the key of a later valid event. Malformed input is dropped, not link-fatal.
    fn recvMessageV2(self: *S2sPeer, outer_payload: []const u8) !void {
        if (!self.supportsSecureRelayV2()) {
            self.rejected_relay_v2_frames +|= 1;
            return;
        }
        const payload = self.verifiedPayload(.MESSAGE_V2, outer_payload) orelse {
            self.rejected_relay_v2_frames +|= 1;
            return;
        };
        var owned = message_relay_v2.decode(self.allocator, payload) catch {
            self.rejected_relay_v2_frames +|= 1;
            return;
        };
        const outcome = message_relay_v2.verifyAndRelayId(self.allocator, owned.msg) catch {
            self.rejected_relay_v2_frames +|= 1;
            owned.deinit(self.allocator);
            return;
        };
        const id = switch (outcome) {
            .verified => |verified| verified,
            .origin_mismatch, .bad_signature, .invalid_semantic => {
                self.rejected_relay_v2_frames +|= 1;
                owned.deinit(self.allocator);
                return;
            },
        };
        // A verified same-leg retry must reach daemon-global admission again:
        // the prior queued copy may have failed recoverably after drain. This
        // cache is only an outbound reflection optimization.
        if (self.inbound_v2.items.len >= self.config.max_relay_v2_frames) {
            self.dropped_relay_v2_frames +|= 1;
            owned.deinit(self.allocator);
            return error.RelayV2Backpressure;
        }
        const wire = self.allocator.dupe(u8, payload) catch |err| {
            self.dropped_relay_v2_frames +|= 1;
            owned.deinit(self.allocator);
            return err;
        };
        self.inbound_v2.append(self.allocator, .{
            .owned = owned,
            .wire = wire,
            .via_peer = self.remote_node_id,
        }) catch |err| {
            self.dropped_relay_v2_frames +|= 1;
            self.allocator.free(wire);
            owned.deinit(self.allocator);
            return err;
        };
        // Record only after queue ownership transfers successfully. This is a
        // per-link reflection cache, not the daemon's authoritative replay
        // guard, so a rare cache allocation failure must not reject delivery.
        _ = self.seen_v2.observe(id);
    }

    fn recvMessageV2Ack(self: *S2sPeer, outer_payload: []const u8) !void {
        if (!self.supportsSecureRelayV2()) return error.SecuredLinkRequired;
        const payload = self.verifiedPayload(.MESSAGE_V2_ACK, outer_payload) orelse
            return error.BadFrameSignature;
        const is_confirm = payload.len == message_relay_v2.relay_id_len + 1;
        if (payload.len != message_relay_v2.relay_id_len and !is_confirm)
            return error.InvalidRelayMessage;
        if (is_confirm and
            (!self.supportsRelayV2AckConfirm() or payload[message_relay_v2.relay_id_len] != 1))
            return error.CapabilityNotNegotiated;
        const id: message_relay_v2.RelayId = payload[0..message_relay_v2.relay_id_len].*;
        const queue = if (is_confirm) &self.inbound_v2_ack_confirms else &self.inbound_v2_acks;
        for (queue.items) |queued| {
            if (std.crypto.timing_safe.eql(message_relay_v2.RelayId, queued, id)) return;
        }
        // ACK is advisory retransmission progress, not delivery authority. A
        // coalesced feed may legitimately contain more ACKs than the bounded
        // daemon handoff queue; soft-drop excess so the sender retries instead
        // of faulting an otherwise healthy secured stream.
        if (queue.items.len >= self.config.max_relay_v2_frames) return;
        try queue.append(self.allocator, id);
    }

    /// Send one immutable origin-signed relay over a negotiated secured leg.
    /// The inner origin may be a third node on transit; `emitSignable` adds the
    /// immediate hop's outer signature without rewriting the origin object.
    pub fn sendMessageV2(self: *S2sPeer, sink: ByteSink, msg: message_relay_v2.RelayMessage) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.secure_relay_transport_enabled or self.signing_key == null or !self.peer_supports_signing)
            return error.SecuredLinkRequired;
        if (!self.peer_supports_secure_relay_v2) return error.CapabilityNotNegotiated;
        if (!self.peer_supports_relay_v2_current or !self.peer_supports_relay_v2_ack_confirm)
            return error.CapabilityNotNegotiated;

        const outcome = try message_relay_v2.verifyAndRelayId(self.allocator, msg);
        const id = switch (outcome) {
            .verified => |verified| verified,
            .origin_mismatch => return error.OriginMismatch,
            .bad_signature => return error.BadOriginSignature,
            .invalid_semantic => return error.InvalidRelayMessage,
        };
        const wire = try message_relay_v2.encode(self.allocator, msg);
        defer self.allocator.free(wire);
        try self.sendMessageV2Wire(sink, wire);
        _ = self.seen_v2.observe(id);
    }

    /// Forward an accepted immutable MESSAGE_V2 object without decode/re-encode
    /// drift. Strict canonical decode and origin verification precede the
    /// per-link reflection probe; the daemon-global replay guard remains the
    /// only delivery authority.
    pub fn forwardMessageV2(self: *S2sPeer, sink: ByteSink, wire: []const u8) !bool {
        if (!self.established) return error.NotEstablished;
        if (!self.secure_relay_transport_enabled or self.signing_key == null or !self.peer_supports_signing)
            return error.SecuredLinkRequired;
        if (!self.peer_supports_secure_relay_v2) return error.CapabilityNotNegotiated;
        if (!self.peer_supports_relay_v2_current or !self.peer_supports_relay_v2_ack_confirm)
            return error.CapabilityNotNegotiated;
        var owned = message_relay_v2.decode(self.allocator, wire) catch return error.InvalidRelayMessage;
        defer owned.deinit(self.allocator);
        const id = switch (try message_relay_v2.verifyAndRelayId(self.allocator, owned.msg)) {
            .verified => |verified| verified,
            .origin_mismatch => return error.OriginMismatch,
            .bad_signature => return error.BadOriginSignature,
            .invalid_semantic => return error.InvalidRelayMessage,
        };
        if (self.seen_v2.contains(id)) return false;
        try self.sendMessageV2Wire(sink, wire);
        _ = self.seen_v2.observe(id);
        return true;
    }

    /// Retransmit an outbox-retained exact wire after a lost ACK. This validates
    /// the immutable origin object and negotiated transport exactly like first
    /// forwarding, but deliberately bypasses the link-local reflection cache:
    /// that cache was populated by the first send and is not delivery proof.
    pub fn replayRetainedMessageV2Wire(self: *S2sPeer, sink: ByteSink, wire: []const u8) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.secure_relay_transport_enabled or self.signing_key == null or !self.peer_supports_signing)
            return error.SecuredLinkRequired;
        if (!self.peer_supports_secure_relay_v2 or !self.peer_supports_relay_v2_current or
            !self.peer_supports_relay_v2_ack_confirm)
            return error.CapabilityNotNegotiated;
        var owned = message_relay_v2.decode(self.allocator, wire) catch return error.InvalidRelayMessage;
        defer owned.deinit(self.allocator);
        const id = switch (try message_relay_v2.verifyAndRelayId(self.allocator, owned.msg)) {
            .verified => |verified| verified,
            .origin_mismatch => return error.OriginMismatch,
            .bad_signature => return error.BadOriginSignature,
            .invalid_semantic => return error.InvalidRelayMessage,
        };
        try self.sendMessageV2Wire(sink, wire);
        _ = self.seen_v2.observe(id);
    }

    fn sendMessageV2Wire(self: *S2sPeer, sink: ByteSink, wire: []const u8) !void {
        const framed_len = s2s_frame.header_len + signed_frame.header_len + wire.len;
        if (framed_len > self.config.max_frame_size) return error.PayloadTooLarge;
        try self.emitSignable(sink, .MESSAGE_V2, wire);
    }

    /// Transfer all verified v2 events to the daemon. Caller deinitializes each
    /// item and frees the returned slice.
    pub fn takeInboundV2(self: *S2sPeer) ![]InboundMessageV2 {
        return self.inbound_v2.toOwnedSlice(self.allocator);
    }

    pub fn supportsE2eeGroup(self: *const S2sPeer) bool {
        return self.supportsSecureRelayV2Base() and self.peer_supports_e2ee_group_current;
    }

    /// E2EEGROUP v2 extension authorizes both hop ACK and ACK_CONFIRM (flag=1).
    /// Same gate as `supportsE2eeGroup` — no separate capability bit.
    pub fn supportsE2eeGroupAckConfirm(self: *const S2sPeer) bool {
        return self.supportsE2eeGroup();
    }

    fn requireE2eeGroup(self: *const S2sPeer) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.secure_relay_transport_enabled or self.signing_key == null or
            !self.peer_supports_signing)
            return error.SecuredLinkRequired;
        if (!self.peer_supports_secure_relay_v2 or
            !self.peer_supports_e2ee_group_current)
            return error.CapabilityNotNegotiated;
    }

    const VerifiedE2eeGroup = struct {
        owned: e2ee_group_relay.Owned,
        relay_id: e2ee_group_relay.RelayId,
    };

    /// Decode only the one canonical wire image and verify the immutable origin
    /// signature before returning a RelayId. Allocation failure remains
    /// recoverable and explicit; all attacker-controlled structural failures
    /// collapse to InvalidE2eeGroup.
    fn decodeVerifiedE2eeGroup(self: *S2sPeer, wire: []const u8) !VerifiedE2eeGroup {
        var owned = e2ee_group_relay.decode(self.allocator, wire) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidE2eeGroup,
        };
        errdefer owned.deinit(self.allocator);
        const relay_id = switch (try e2ee_group_relay.verifyAndRelayId(self.allocator, owned.record)) {
            .verified => |id| id,
            .origin_mismatch => return error.OriginMismatch,
            .bad_signature => return error.BadOriginSignature,
            .invalid_semantic => return error.InvalidE2eeGroup,
        };
        const canonical = e2ee_group_relay.encode(self.allocator, owned.record) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidE2eeGroup,
        };
        defer self.allocator.free(canonical);
        if (!std.mem.eql(u8, canonical, wire)) return error.NonCanonicalE2eeGroup;
        return .{ .owned = owned, .relay_id = relay_id };
    }

    /// Hop-authenticate, strictly decode, canonicalize, and origin-verify before
    /// touching queue or reflection state. Malformed and tampered inputs soft
    /// drop; OOM and bounded-queue backpressure remain visible to the caller.
    fn recvE2eeGroup(self: *S2sPeer, outer_payload: []const u8) !void {
        if (!self.supportsE2eeGroup()) {
            self.rejected_e2ee_group_frames +|= 1;
            return;
        }
        const payload = self.verifiedPayload(.E2EE_GROUP, outer_payload) orelse {
            self.rejected_e2ee_group_frames +|= 1;
            return;
        };
        var verified = self.decodeVerifiedE2eeGroup(payload) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                self.rejected_e2ee_group_frames +|= 1;
                return;
            },
        };
        if (self.inbound_e2ee_group.items.len >= self.config.max_e2ee_group_frames) {
            self.dropped_e2ee_group_frames +|= 1;
            verified.owned.deinit(self.allocator);
            return error.E2eeGroupBackpressure;
        }
        const wire = self.allocator.dupe(u8, payload) catch |err| {
            self.dropped_e2ee_group_frames +|= 1;
            verified.owned.deinit(self.allocator);
            return err;
        };
        self.inbound_e2ee_group.append(self.allocator, .{
            .owned = verified.owned,
            .wire = wire,
            .relay_id = verified.relay_id,
            .via_peer = self.remote_node_id,
        }) catch |err| {
            self.dropped_e2ee_group_frames +|= 1;
            self.allocator.free(wire);
            verified.owned.deinit(self.allocator);
            return err;
        };
        // Reflection optimization only. Same-leg retries still queue for the
        // daemon's authoritative global replay admission.
        _ = self.seen_e2ee_group.observe(verified.relay_id);
    }

    /// Send one already origin-stamped E2EEGROUP control in canonical form.
    pub fn sendE2eeGroup(
        self: *S2sPeer,
        sink: ByteSink,
        record: e2ee_group_relay.RelayRecord,
    ) !void {
        try self.requireE2eeGroup();
        const relay_id = switch (try e2ee_group_relay.verifyAndRelayId(self.allocator, record)) {
            .verified => |id| id,
            .origin_mismatch => return error.OriginMismatch,
            .bad_signature => return error.BadOriginSignature,
            .invalid_semantic => return error.InvalidE2eeGroup,
        };
        const wire = try e2ee_group_relay.encode(self.allocator, record);
        defer self.allocator.free(wire);
        try self.sendE2eeGroupWire(sink, wire, relay_id);
    }

    /// Forward the exact canonical inner bytes. Validation happens before the
    /// link-local reflection cache, so forged identities cannot poison it.
    pub fn forwardE2eeGroup(self: *S2sPeer, sink: ByteSink, wire: []const u8) !bool {
        try self.requireE2eeGroup();
        var verified = try self.decodeVerifiedE2eeGroup(wire);
        defer verified.owned.deinit(self.allocator);
        if (self.seen_e2ee_group.contains(verified.relay_id)) return false;
        try self.sendE2eeGroupWire(sink, wire, verified.relay_id);
        return true;
    }

    /// Retransmit a retained exact wire after recoverable downstream failure.
    /// Strict canonical/origin validation and negotiated transport gates still
    /// apply, but the reflection cache is deliberately not delivery proof and
    /// therefore cannot suppress this retry.
    pub fn replayRetainedE2eeGroupWire(
        self: *S2sPeer,
        sink: ByteSink,
        wire: []const u8,
    ) !void {
        try self.requireE2eeGroup();
        var verified = try self.decodeVerifiedE2eeGroup(wire);
        defer verified.owned.deinit(self.allocator);
        try self.sendE2eeGroupWire(sink, wire, verified.relay_id);
    }

    fn sendE2eeGroupWire(
        self: *S2sPeer,
        sink: ByteSink,
        wire: []const u8,
        relay_id: e2ee_group_relay.RelayId,
    ) !void {
        const framed_len = s2s_frame.header_len + signed_frame.header_len + wire.len;
        if (framed_len > self.config.max_frame_size) return error.PayloadTooLarge;
        try self.emitSignable(sink, .E2EE_GROUP, wire);
        _ = self.seen_e2ee_group.observe(relay_id);
    }

    pub fn takeInboundE2eeGroup(self: *S2sPeer) ![]InboundE2eeGroup {
        return self.inbound_e2ee_group.toOwnedSlice(self.allocator);
    }

    /// Hop-authenticate and strictly accept E2EEGROUP ACK (RelayId) or
    /// ACK_CONFIRM (RelayId + flag=1). Malformed, unsigned, unnegotiated,
    /// wrong-flag, duplicate, and queue-pressure traffic is advisory and
    /// soft-dropped; allocation failure stays visible.
    fn recvE2eeGroupAck(self: *S2sPeer, outer_payload: []const u8) !void {
        if (!self.supportsE2eeGroup()) {
            self.rejected_e2ee_group_frames +|= 1;
            return;
        }
        const payload = self.verifiedPayload(.E2EE_GROUP_ACK, outer_payload) orelse {
            self.rejected_e2ee_group_frames +|= 1;
            return;
        };
        const is_confirm = payload.len == e2ee_group_relay.relay_id_len + 1;
        if (payload.len != e2ee_group_relay.relay_id_len and !is_confirm) {
            self.rejected_e2ee_group_frames +|= 1;
            return;
        }
        if (is_confirm and payload[e2ee_group_relay.relay_id_len] != 1) {
            self.rejected_e2ee_group_frames +|= 1;
            return;
        }
        const id: e2ee_group_relay.RelayId = payload[0..e2ee_group_relay.relay_id_len].*;
        const queue = if (is_confirm)
            &self.inbound_e2ee_group_ack_confirms
        else
            &self.inbound_e2ee_group_acks;
        for (queue.items) |queued| {
            if (std.crypto.timing_safe.eql(e2ee_group_relay.RelayId, queued, id)) return;
        }
        // Soft-drop under pressure: ACK/confirm is progress, not authority.
        // Sender retries retained custody wire or the receipt ACK itself.
        if (queue.items.len >= self.config.max_e2ee_group_ack_frames) {
            self.dropped_e2ee_group_frames +|= 1;
            return;
        }
        queue.append(self.allocator, id) catch |err| {
            self.dropped_e2ee_group_frames +|= 1;
            return err;
        };
    }

    /// Send hop ACK for one admitted E2EEGROUP RelayId (custody retirement path).
    pub fn sendE2eeGroupAck(
        self: *S2sPeer,
        sink: ByteSink,
        id: e2ee_group_relay.RelayId,
    ) !void {
        try self.requireE2eeGroup();
        try self.emitSignable(sink, .E2EE_GROUP_ACK, &id);
    }

    /// Confirm that this peer received the ingress peer's ACK for RelayId.
    /// Payload is RelayId || 0x01, domain-separated under E2EE_GROUP_ACK.
    pub fn sendE2eeGroupAckConfirm(
        self: *S2sPeer,
        sink: ByteSink,
        id: e2ee_group_relay.RelayId,
    ) !void {
        try self.requireE2eeGroup();
        var payload: [e2ee_group_relay.relay_id_len + 1]u8 = undefined;
        @memcpy(payload[0..e2ee_group_relay.relay_id_len], &id);
        payload[e2ee_group_relay.relay_id_len] = 1;
        try self.emitSignable(sink, .E2EE_GROUP_ACK, &payload);
    }

    pub fn takeInboundE2eeGroupAcks(self: *S2sPeer) ![]e2ee_group_relay.RelayId {
        return self.inbound_e2ee_group_acks.toOwnedSlice(self.allocator);
    }

    pub fn takeInboundE2eeGroupAckConfirms(self: *S2sPeer) ![]e2ee_group_relay.RelayId {
        return self.inbound_e2ee_group_ack_confirms.toOwnedSlice(self.allocator);
    }

    /// Re-negotiate the append-only E2EEGROUP schema after Helix resume. An old
    /// peer sees only an ordinary bounded PING and never receives tags 0x26/0x27.
    pub fn probeE2eeGroupCurrent(self: *S2sPeer, sink: ByteSink) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.supportsSecureRelayV2Base()) return;
        try emitFrame(self.allocator, sink, .PING, e2ee_group_extension_probe);
    }

    pub fn takeDroppedE2eeGroupFrames(self: *S2sPeer) u64 {
        defer self.dropped_e2ee_group_frames = 0;
        return self.dropped_e2ee_group_frames;
    }

    pub fn takeRejectedE2eeGroupFrames(self: *S2sPeer) u64 {
        defer self.rejected_e2ee_group_frames = 0;
        return self.rejected_e2ee_group_frames;
    }

    pub fn sendMessageV2Ack(self: *S2sPeer, sink: ByteSink, id: message_relay_v2.RelayId) !void {
        if (!self.supportsSecureRelayV2()) return error.SecuredLinkRequired;
        try self.emitSignable(sink, .MESSAGE_V2_ACK, &id);
    }

    pub fn sendMessageV2AckConfirm(self: *S2sPeer, sink: ByteSink, id: message_relay_v2.RelayId) !void {
        if (!self.supportsRelayV2AckConfirm()) return error.CapabilityNotNegotiated;
        var payload: [message_relay_v2.relay_id_len + 1]u8 = undefined;
        @memcpy(payload[0..message_relay_v2.relay_id_len], &id);
        payload[message_relay_v2.relay_id_len] = 1;
        try self.emitSignable(sink, .MESSAGE_V2_ACK, &payload);
    }

    /// Re-negotiate the append-only relay-v2 extension on an already-established
    /// stream restored from a legacy Helix capsule. This is an ordinary PING to
    /// an older peer and therefore safe across rolling upgrades.
    pub fn probeRelayV2Current(self: *S2sPeer, sink: ByteSink) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.supportsSecureRelayV2Base()) return;
        try emitFrame(self.allocator, sink, .PING, relay_v2_extension_probe);
        try emitFrame(self.allocator, sink, .PING, relay_v2_ack_confirm_probe);
    }

    /// Negotiate SRTF3 on an already-established preserved stream. An older
    /// peer sees only an ordinary PING and never receives a v3 replica frame.
    pub fn probeSessionReplicaV3(self: *S2sPeer, sink: ByteSink) !void {
        if (!self.established) return error.NotEstablished;
        if (!self.session_replica_attachment_transport_enabled or
            !self.supportsSessionReplicaV2()) return;
        try emitFrame(self.allocator, sink, .PING, session_replica_v3_probe);
    }

    pub fn takeInboundV2Acks(self: *S2sPeer) ![]message_relay_v2.RelayId {
        return self.inbound_v2_acks.toOwnedSlice(self.allocator);
    }

    pub fn takeInboundV2AckConfirms(self: *S2sPeer) ![]message_relay_v2.RelayId {
        return self.inbound_v2_ack_confirms.toOwnedSlice(self.allocator);
    }

    pub fn takeDroppedRelayV2Frames(self: *S2sPeer) u64 {
        defer self.dropped_relay_v2_frames = 0;
        return self.dropped_relay_v2_frames;
    }

    pub fn takeRejectedRelayV2Frames(self: *S2sPeer) u64 {
        defer self.rejected_relay_v2_frames = 0;
        return self.rejected_relay_v2_frames;
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
        const changes = try self.membership_changes.toOwnedSlice(self.allocator);
        self.discardIdentityTransitionMarkers(.membership);
        return changes;
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

    pub const IdentityTransitionKind = enum { membership, nick };

    /// One identity transition in the exact order accepted by this peer. The
    /// caller owns the selected delta and must call its `deinit` method.
    pub const IdentityTransition = union(IdentityTransitionKind) {
        membership: MembershipDelta,
        nick: NickDelta,
    };

    /// Drain remote channel topic changes. Caller owns the slice + each delta's
    /// strings (call `deinit` per entry, then free the slice).
    pub fn takeTopicChanges(self: *S2sPeer) ![]TopicDelta {
        return self.topic_changes.toOwnedSlice(self.allocator);
    }

    /// Drain remote user nick changes. Caller owns the slice + each delta's
    /// strings (call `deinit` per entry, then free the slice).
    pub fn takeNickChanges(self: *S2sPeer) ![]NickDelta {
        const changes = try self.nick_changes.toOwnedSlice(self.allocator);
        self.discardIdentityTransitionMarkers(.nick);
        return changes;
    }

    /// Peek the next ordered membership transition without transferring it.
    /// Returns null when the queue is empty or a NICK must be observed first.
    pub fn peekNextMembershipTransition(self: *const S2sPeer) ?*const MembershipDelta {
        if (self.identity_transition_order.items.len == 0 or
            self.identity_transition_order.items[0] != .membership or
            self.membership_changes.items.len == 0)
        {
            return null;
        }
        return &self.membership_changes.items[0];
    }

    /// Transfer the next MEMBERSHIP/NICK delta in application order.
    pub fn takeNextIdentityTransition(self: *S2sPeer) ?IdentityTransition {
        if (self.identity_transition_order.items.len == 0) return null;
        return switch (self.identity_transition_order.orderedRemove(0)) {
            .membership => blk: {
                std.debug.assert(self.membership_changes.items.len != 0);
                break :blk .{ .membership = self.membership_changes.orderedRemove(0) };
            },
            .nick => blk: {
                std.debug.assert(self.nick_changes.items.len != 0);
                break :blk .{ .nick = self.nick_changes.orderedRemove(0) };
            },
        };
    }

    fn discardIdentityTransitionMarkers(self: *S2sPeer, kind: IdentityTransitionKind) void {
        var write: usize = 0;
        for (self.identity_transition_order.items) |queued| {
            if (queued == kind) continue;
            self.identity_transition_order.items[write] = queued;
            write += 1;
        }
        self.identity_transition_order.shrinkRetainingCapacity(write);
    }

    /// Drain origin-mismatch + signature-rejection counts for daemon-side audit
    /// logging. Both the link-trust origin check (`acceptsDirectOrigin`) and the
    /// cryptographic envelope check (`verifiedPayload`) feed this one counter so
    /// the daemon's existing audit drain surfaces every rejected direct-owned
    /// frame regardless of which gate dropped it.
    pub fn takeRejectedOriginFrames(self: *S2sPeer) u64 {
        const n = self.rejected_origin_frames +| self.rejected_signature_frames +| self.rejected_admission_frames +| self.rejected_session_replica_frames;
        self.rejected_origin_frames = 0;
        self.rejected_signature_frames = 0;
        self.rejected_admission_frames = 0;
        self.rejected_session_replica_frames = 0;
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
            .relay, .oper, .notification, .session => .irc_app,
            .media => .media,
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

    /// Install (or clear) the receiver-owned signed-session resolver. Borrowed;
    /// the daemon must keep the callback context alive for the link lifetime.
    pub fn setSessionTokenResolver(self: *S2sPeer, resolver: ?SessionTokenResolver) void {
        self.session_token_resolver = resolver;
    }

    /// Install (or clear) the receiver-owned exact-token NICKCHANGE gate.
    pub fn setSessionTokenNickAuthorizer(self: *S2sPeer, authorizer: ?SessionTokenNickAuthorizer) void {
        self.session_token_nick_authorizer = authorizer;
    }

    /// Retroactively bind or clear exact-token metadata after signed authority
    /// arrives later than the compatibility MEMBERSHIP fact.
    pub fn rebindSessionToken(self: *S2sPeer, origin_node: NodeId, nick: []const u8, token: ?SessionToken) route_table.Error!usize {
        return self.routes.rebindSessionToken(origin_node, nick, token);
    }

    /// Reconcile exact-token rows against the signed Store projection. Owned
    /// NICK/PART deltas are queued before route mutation; allocation failure
    /// leaves the affected identity present and is returned for daemon retry.
    pub fn reconcileSessionToken(
        self: *S2sPeer,
        token: SessionToken,
        desired_nick: ?[]const u8,
        desired_channels: []const []const u8,
    ) route_table.Error!route_table.SessionTokenReconcileResult {
        return self.routes.reconcileSessionTokenObserved(token, desired_nick, desired_channels, .{
            .ctx = self,
            .part_fn = queueReconciledSessionPart,
            .rename_fn = queueReconciledSessionRename,
        });
    }

    /// Reap stale compatibility-roster rows while retaining the derived PART
    /// transitions first. The daemon drains the same ordered identity queue as
    /// ordinary MEMBERSHIP and signed-session reconciliation, so incremental
    /// clients cannot keep a zombie that NAMES has already forgotten.
    pub fn pruneStaleMembers(self: *S2sPeer, now_ms: i64, window_ms: i64) route_table.Error!usize {
        return self.routes.pruneStaleObserved(now_ms, window_ms, .{
            .ctx = self,
            .part_fn = queueReconciledSessionPart,
            .rename_fn = rejectStaleMemberRename,
        });
    }

    fn rejectStaleMemberRename(_: *anyopaque, _: []const u8, _: []const u8, _: *const route_table.Member) std.mem.Allocator.Error!void {
        unreachable;
    }

    fn queueReconciledSessionPart(ctx: *anyopaque, channel: []const u8, member: *const route_table.Member) std.mem.Allocator.Error!void {
        const self: *S2sPeer = @ptrCast(@alignCast(ctx));
        try self.queueMembershipValues(channel, member.nick, member.username, member.realname, member.host, "", member.account, .parted, member.status, member.status);
    }

    fn queueReconciledSessionRename(ctx: *anyopaque, old_nick: []const u8, new_nick: []const u8, member: *const route_table.Member) std.mem.Allocator.Error!void {
        const self: *S2sPeer = @ptrCast(@alignCast(ctx));
        try self.queueForcedNickRename(old_nick, new_nick, .{
            .username = member.username,
            .realname = member.realname,
            .host = member.host,
            .account = member.account,
        });
    }

    const WireNickRenameContext = struct {
        peer: *S2sPeer,
        ident: MemberIdentity,
    };

    fn rejectWireNickPart(_: *anyopaque, _: []const u8, _: *const route_table.Member) std.mem.Allocator.Error!void {
        unreachable;
    }

    fn queueAuthorizedWireNick(ctx: *anyopaque, old_nick: []const u8, new_nick: []const u8, _: *const route_table.Member) std.mem.Allocator.Error!void {
        const wire: *WireNickRenameContext = @ptrCast(@alignCast(ctx));
        try wire.peer.queueForcedNickRename(old_nick, new_nick, wire.ident);
    }

    pub fn setLocalNickResolver(self: *S2sPeer, resolver: ?LocalNickResolver) void {
        self.routes.setLocalNickResolver(resolver);
    }

    /// The PER-CLAIM `account_trusted` bool for an incoming membership/nick
    /// claim (Design C verify order, fail-closed — ALL must hold or false):
    ///   1. the claim carries an account at all;
    ///   2. the carrying frame rode the ORIGIN-AUTHENTICATED path: the peer is
    ///      signing-capable (so `verifiedPayload` verified the envelope and
    ///      pinned `originShortId(pubkey)`) against a KNOWN remote node id —
    ///      an unsigned/plaintext link can never yield trust;
    ///   3. the daemon's verifier confirms a live residence proof binding
    ///      `{account, nick, origin_node}` against the receiver-owned replicated
    ///      account pubkey.
    /// Untrusted ⇒ the resolver blanks the wire account and takes the conservative
    /// collision path. Reject ⇒ the claim is dropped before RouteTable mutation.
    fn accountResidenceDecision(self: *S2sPeer, account: []const u8, nick: []const u8, origin_node: NodeId) ResidenceDecision {
        const verifier = self.residence_verifier orelse return .untrusted;
        const decision = verifier.verify(account, nick, origin_node, self.supportsSessionReplicaV2());
        // Downgrade rejection is receiver-owned and must run even when the peer
        // also omits signing. Only positive trust depends on authenticated origin;
        // an unsigned/plaintext transport can never upgrade an account claim.
        if (decision == .trusted and
            (account.len == 0 or !self.peer_supports_signing or self.remote_node_id == 0)) return .untrusted;
        return decision;
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
        return self.channel_mode_state_clocks.observe(self.allocator, channel, hlc);
    }

    /// Apply an inbound MEMBERSHIP event to the route table (LWW by hlc). A
    /// malformed payload is dropped, never fatal to the link. A real add/remove/
    /// status-change is queued so the daemon can emit the matching live IRC line.
    fn recvMembership(self: *S2sPeer, frame_payload: []const u8, now_ms: u64) !void {
        const payload = self.verifiedPayload(.MEMBERSHIP, frame_payload) orelse return;
        try self.applyMembershipPayload(payload, now_ms);
    }

    fn applyMembershipPayload(self: *S2sPeer, payload: []const u8, now_ms: u64) !void {
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
        // P2 (F1 store-side blank): the account PERSISTED into the route table is
        // the wire account ONLY when this claim's residence proof verifies; else
        // "". A forged (untrusted) incumbent is therefore stored account-less and
        // can NEVER later let a TRUSTED newcomer `remote_same_account`-merge with
        // it on a third node (route_table compares against the STORED incumbent
        // account). Blank by default so a part (present=false) is also account-
        // less; set below for a trusted present claim.
        var store_account: []const u8 = "";
        const residence = self.accountResidenceDecision(ev.account, ev.nick, ev.origin_node);
        // A non-v2 claim for an identity already governed by retained signed
        // token authority is a downgrade, not an ordinary untrusted collision.
        // Drop it before RouteTable resolution so it cannot create a UID phantom
        // route, daemon delta, or NAMES entry.
        if (residence == .reject) return;
        const session_token: ?SessionToken = if (self.session_token_resolver) |resolver|
            switch (resolver.resolve(ev.origin_node, ev.nick, ev.channel, ev.present)) {
                .unbound => null,
                .bind => |token| token,
                .reject => return,
            }
        else
            null;
        var prior_alias = false;
        // A prior JOIN may have lost a collision and been stored under this
        // origin's deterministic UID. Prefer that receiver-owned alias for every
        // later status/reaffirm/PART, even if the original collision disappeared,
        // so the route never splits into real-nick + UID zombies and deltas name
        // what clients actually saw.
        const prior_uid = if (ev.present)
            self.routes.storedLoserUid(ev.origin_node, ev.nick)
        else
            self.routes.channelLoserUid(ev.channel, ev.origin_node, ev.nick);
        if (prior_uid) |uid| {
            @memcpy(uid_buf[0..uid.len], uid[0..]);
            apply_nick = uid_buf[0..uid.len];
            surfaced_nick = apply_nick;
            prior_alias = true;
        }
        if (ev.present) {
            // Design C (F1): the plaintext wire `account` is only honored by the
            // same-identity collision short-circuits when a residence proof
            // verifies for exactly this (account, origin) — per claim, over an
            // origin-authenticated link, against receiver-owned keys. When
            // false, resolveIncomingNick blanks the account internally so the
            // claim takes the conservative UID path.
            const account_trusted = residence == .trusted;
            store_account = if (account_trusted) ev.account else "";
            if (!prior_alias) switch (self.routes.resolveIncomingNick(ev.nick, ev.origin_node, ev.hlc, ev.account, account_trusted)) {
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
                        .account = store_account, // P2: only the trusted account is persisted
                        .real_host = ev.real_host,
                        .certfp = ev.certfp,
                        .session_token = session_token,
                    }, local_now) catch {};
                    self.queueMembershipDelta(&ev, .ghost_reclaim, 0, null) catch {};
                    return;
                },
            };
            // Newcomer wins over a different-node incumbent: displace the
            // incumbent to ITS uid first so two holders never coexist. Skipped for
            // a same-account reconcile, where LWW collapses the duplicate instead.
            if (!prior_alias and surfaced_nick == null and !skip_displace and
                !self.displaceIncumbent(&ev)) return;
        }

        const res = self.routes.applyMembership(ev.channel, apply_nick, ev.origin_node, ev.status, ev.hlc, ev.present, .{
            .username = ev.username,
            .realname = ev.realname,
            .host = ev.host,
            .account = store_account, // P2: blanked unless residence-trusted
            .real_host = ev.real_host,
            .certfp = ev.certfp,
            .session_token = session_token,
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
    fn displaceIncumbent(self: *S2sPeer, ev: *const membership_event.MembershipEvent) bool {
        return self.displaceIncumbentForRename(ev.nick, ev.origin_node);
    }

    /// Shared incumbent-displacement: when a winning newcomer from `winner_node`
    /// takes `nick` from a DIFFERENT-node incumbent, rename that incumbent to its
    /// own mesh UID across the route table and surface a `:nick NICK <incumbentUID>`
    /// line, so local clients never see two mesh users holding one nick. No-op when
    /// there is no incumbent or it is the same node (an own update, not a contest).
    fn displaceIncumbentForRename(self: *S2sPeer, nick: []const u8, winner_node: NodeId) bool {
        const incumbent_node = self.routes.nickNode(nick) orelse return true;
        if (incumbent_node == winner_node) return true;
        const uid = self.routes.incumbentLoserUid(nick) orelse return false;
        var uid_buf: [nick_collision_uid_len]u8 = undefined;
        @memcpy(uid_buf[0..uid.len], uid[0..]);
        const new_nick = uid_buf[0..uid.len];
        // Pull the incumbent's stored identity so the NICK line renders its real
        // user@host (falls back to empties when the member is route-only).
        var ident = MemberIdentity{};
        if (self.routes.findMember(nick)) |m| {
            ident = .{ .username = m.username, .realname = m.realname, .host = m.host, .account = m.account };
        }
        const renamed = self.routes.renameNick(nick, new_nick, incumbent_node, ident) catch return false;
        if (!renamed) return false;
        self.queueForcedNickRename(nick, new_nick, ident) catch {}; // best-effort surface
        return true;
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
        var delta = try self.ownedNickDelta(old_nick, new_nick, ident);
        errdefer delta.deinit(self.allocator);
        try self.nick_changes.ensureUnusedCapacity(self.allocator, 1);
        try self.identity_transition_order.ensureUnusedCapacity(self.allocator, 1);
        self.nick_changes.appendAssumeCapacity(delta);
        self.identity_transition_order.appendAssumeCapacity(.nick);
    }

    /// Build one fully-owned NICK delta without publishing it. Collision
    /// transactions use this to stage both the incumbent displacement and exact
    /// rename before either route-table identity is allowed to move.
    fn ownedNickDelta(
        self: *S2sPeer,
        old_nick: []const u8,
        new_nick: []const u8,
        ident: MemberIdentity,
    ) !NickDelta {
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
        return .{
            .old_nick = on,
            .new_nick = nn,
            .username = un,
            .realname = rn,
            .host = ho,
        };
    }

    /// Commit the exact-token winner and foreign incumbent as one collision
    /// transaction. Both deltas and queue capacity exist before the RouteTable's
    /// no-fail commit; false/error leaves spellings, routes, token tags, and the
    /// observable delta queue unchanged.
    fn applyAuthorizedSessionTokenCollisionRename(
        self: *S2sPeer,
        node: NodeId,
        old_nick: []const u8,
        new_nick: []const u8,
        token: SessionToken,
        ident: MemberIdentity,
        incumbent_node: NodeId,
        incumbent_uid: []const u8,
    ) !bool {
        const incumbent = self.routes.findMemberOwnedBy(new_nick, incumbent_node) orelse return false;
        const incumbent_ident = MemberIdentity{
            .username = incumbent.username,
            .realname = incumbent.realname,
            .host = incumbent.host,
            .account = incumbent.account,
        };

        var incumbent_delta = try self.ownedNickDelta(new_nick, incumbent_uid, incumbent_ident);
        var incumbent_delta_owned = true;
        defer if (incumbent_delta_owned) incumbent_delta.deinit(self.allocator);
        var exact_delta = try self.ownedNickDelta(old_nick, new_nick, ident);
        var exact_delta_owned = true;
        defer if (exact_delta_owned) exact_delta.deinit(self.allocator);
        try self.nick_changes.ensureUnusedCapacity(self.allocator, 2);
        try self.identity_transition_order.ensureUnusedCapacity(self.allocator, 2);

        const renamed = try self.routes.renameNickBindingSessionTokenDisplacing(
            node,
            old_nick,
            new_nick,
            token,
            ident,
            incumbent_node,
            incumbent_uid,
        );
        if (!renamed) return false;

        // Vacate the contested nick before publishing the exact winner, matching
        // IRC's required observable order while both state mutations are atomic.
        self.nick_changes.appendAssumeCapacity(incumbent_delta);
        self.identity_transition_order.appendAssumeCapacity(.nick);
        incumbent_delta_owned = false;
        self.nick_changes.appendAssumeCapacity(exact_delta);
        self.identity_transition_order.appendAssumeCapacity(.nick);
        exact_delta_owned = false;
        return true;
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
        try self.queueMembershipValues(
            ev.channel,
            nick_override orelse ev.nick,
            ev.username,
            ev.realname,
            ev.host,
            ev.setter,
            ev.account,
            kind,
            ev.status,
            prev_status,
        );
    }

    fn queueMembershipValues(
        self: *S2sPeer,
        channel: []const u8,
        nick: []const u8,
        username_value: []const u8,
        realname_value: []const u8,
        host_value: []const u8,
        setter_value: []const u8,
        account_value: []const u8,
        kind: MembershipDelta.Kind,
        status: u4,
        prev_status: u4,
    ) !void {
        const ch = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(ch);
        const nk = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(nk);
        const un = try self.allocator.dupe(u8, username_value);
        errdefer self.allocator.free(un);
        const rn = try self.allocator.dupe(u8, realname_value);
        errdefer self.allocator.free(rn);
        const ho = try self.allocator.dupe(u8, host_value);
        errdefer self.allocator.free(ho);
        const st = try self.allocator.dupe(u8, setter_value);
        errdefer self.allocator.free(st);
        const ac = try self.allocator.dupe(u8, account_value);
        errdefer self.allocator.free(ac);
        try self.membership_changes.ensureUnusedCapacity(self.allocator, 1);
        try self.identity_transition_order.ensureUnusedCapacity(self.allocator, 1);
        self.membership_changes.appendAssumeCapacity(.{
            .channel = ch,
            .nick = nk,
            .username = un,
            .realname = rn,
            .host = ho,
            .setter = st,
            .account = ac,
            .kind = kind,
            .status = status,
            .prev_status = prev_status,
        });
        self.identity_transition_order.appendAssumeCapacity(.membership);
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

        // The first dupe is `catch return` (nothing to unwind yet); every later
        // step is `try` so the `errdefer` chain above it is LIVE and frees the
        // already-duped strings on a mid-sequence allocation failure instead of
        // leaking them (mirrors `recvChannelModeState`). Both this fn and its
        // caller are `!void`, so the OOM propagates and faults the link closed.
        const ch = self.allocator.dupe(u8, ev.channel) catch return;
        errdefer self.allocator.free(ch);
        const key = try self.allocator.dupe(u8, ev.key);
        errdefer self.allocator.free(key);
        const value = try self.allocator.dupe(u8, ev.value);
        errdefer self.allocator.free(value);
        const owner = try self.allocator.dupe(u8, ev.owner);
        errdefer self.allocator.free(owner);
        const origin_pubkey = try self.allocator.dupe(u8, ev.origin_pubkey);
        errdefer self.allocator.free(origin_pubkey);
        const origin_sig = try self.allocator.dupe(u8, ev.origin_sig);
        errdefer self.allocator.free(origin_sig);

        try self.prop_changes.append(self.allocator, .{
            .channel = ch,
            .key = key,
            .value = value,
            .owner = owner,
            .hlc = ev.hlc,
            .present = ev.present,
            .origin_node = ev.origin_node,
            .origin_pubkey = origin_pubkey,
            .origin_sig = origin_sig,
        });
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

        // See `recvChannelProp`: the first dupe is `catch return`, then every
        // later step is `try` so the `errdefer` chain is LIVE and frees the
        // already-duped strings on a mid-sequence OOM rather than leaking them.
        const entity = self.allocator.dupe(u8, ev.entity) catch return;
        errdefer self.allocator.free(entity);
        const key = try self.allocator.dupe(u8, ev.key);
        errdefer self.allocator.free(key);
        const value = try self.allocator.dupe(u8, ev.value);
        errdefer self.allocator.free(value);
        const owner = try self.allocator.dupe(u8, ev.owner);
        errdefer self.allocator.free(owner);
        const origin_pubkey = try self.allocator.dupe(u8, ev.origin_pubkey);
        errdefer self.allocator.free(origin_pubkey);
        const origin_sig = try self.allocator.dupe(u8, ev.origin_sig);
        errdefer self.allocator.free(origin_sig);

        try self.entity_prop_changes.append(self.allocator, .{
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
        });
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
        try self.applyNickChangePayload(payload);
    }

    fn applyNickChangePayload(self: *S2sPeer, payload: []const u8) !void {
        const ev = nick_event.decode(payload) catch return;
        if (!self.acceptsDirectOrigin(ev.origin_node)) return;

        // A remote rename into a nick already held (locally, or by a different
        // mesh node) makes the RENAMER the loser: redirect it to its mesh UID
        // instead of clobbering the holder. A same-node incumbent is the user's
        // own prior nick, never a collision (resolveIncomingNick handles both).
        // Design C (F1): the wire account is only honored by the same-identity
        // short-circuits when a residence proof verifies (per claim, receiver-
        // owned keys, origin-authenticated link); else it is blanked internally
        // and the claim takes the conservative UID path. P2: the account PERSISTED
        // via renameNick is likewise the wire account only when trusted, so a
        // forged rename is stored account-less (no later coexistence merge).
        const old_residence = self.accountResidenceDecision(ev.account, ev.old_nick, ev.origin_node);
        const new_residence = self.accountResidenceDecision(ev.account, ev.new_nick, ev.origin_node);
        // A downgraded rename can move a retained signed identity away from its
        // protected old nick even when the free destination has no Store fact.
        // Reject if either end is governed by v2 authority; trust of an accepted
        // rename remains bound to the new identity claim.
        if (old_residence == .reject or new_residence == .reject) return;
        const account_trusted = new_residence == .trusted;
        const ident = MemberIdentity{
            .username = ev.username,
            .realname = ev.realname,
            .host = ev.host,
            .account = if (account_trusted) ev.account else "",
        };
        var old_nick: []const u8 = ev.old_nick;
        var old_uid_buf: [nick_collision_uid_len]u8 = undefined;
        if (self.routes.storedLoserUid(ev.origin_node, ev.old_nick)) |uid| {
            @memcpy(old_uid_buf[0..uid.len], uid[0..]);
            old_nick = old_uid_buf[0..uid.len];
        }
        var bind_token: ?SessionToken = null;
        if (self.supportsSessionReplicaV2()) {
            const authorizer = self.session_token_nick_authorizer orelse return;
            const tagged_token: ?SessionToken = switch (self.routes.sessionTokenForOriginNick(ev.origin_node, ev.old_nick)) {
                .none => null,
                // Contradictory receiver tags are always denied, but still run
                // the receiver-owned callback exactly once for every v2 rename.
                // Null forces its independent Store lookup down the untagged
                // origin/old-nick path without exposing either conflicting tag.
                .ambiguous => {
                    _ = authorizer.authorize(ev.origin_node, ev.old_nick, null, ev.new_nick);
                    return;
                },
                .unique => |token| token,
            };
            switch (authorizer.authorize(ev.origin_node, ev.old_nick, tagged_token, ev.new_nick)) {
                .reject => return,
                .legacy => if (tagged_token != null) return,
                .bind => |token| {
                    if (tagged_token) |tagged| {
                        if (!std.crypto.timing_safe.eql(SessionToken, tagged, token)) return;
                    }
                    bind_token = token;
                },
            }
        }
        var target_nick: []const u8 = ev.new_nick;
        var uid_buf: [nick_collision_uid_len]u8 = undefined;
        var collision_incumbent: ?NodeId = null;
        var incumbent_uid_buf: [nick_collision_uid_len]u8 = undefined;
        var incumbent_uid: []const u8 = "";
        switch (self.routes.resolveIncomingNick(ev.new_nick, ev.origin_node, ev.hlc, ev.account, account_trusted)) {
            .keep => {
                if (self.routes.nickNode(ev.new_nick)) |incumbent_node| {
                    if (incumbent_node != ev.origin_node and bind_token != null) {
                        const uid = self.routes.incumbentLoserUid(ev.new_nick) orelse return;
                        @memcpy(incumbent_uid_buf[0..uid.len], uid[0..]);
                        incumbent_uid = incumbent_uid_buf[0..uid.len];
                        collision_incumbent = incumbent_node;
                    } else if (!self.displaceIncumbentForRename(ev.new_nick, ev.origin_node)) return;
                }
            },
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

        if (bind_token) |token| {
            if (collision_incumbent) |incumbent_node| {
                const renamed = self.applyAuthorizedSessionTokenCollisionRename(
                    ev.origin_node,
                    old_nick,
                    target_nick,
                    token,
                    ident,
                    incumbent_node,
                    incumbent_uid,
                ) catch return;
                if (!renamed) return;
                return;
            }
            var wire_ctx = WireNickRenameContext{ .peer = self, .ident = ident };
            const renamed = self.routes.renameNickBindingSessionToken(
                ev.origin_node,
                old_nick,
                target_nick,
                token,
                ident,
                .{
                    .ctx = &wire_ctx,
                    .part_fn = rejectWireNickPart,
                    .rename_fn = queueAuthorizedWireNick,
                },
            ) catch return;
            if (!renamed) return;
        } else {
            const renamed = self.routes.renameNick(old_nick, target_nick, ev.origin_node, ident) catch return;
            if (!renamed) return;
            self.queueForcedNickRename(old_nick, target_nick, ident) catch return;
        }
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
        const had_attachment_lease_v2 = self.peer_supports_session_attachment_lease_v2;
        self.peer_supports_session_replica_v2 = self.peer_supports_signing and (hs.caps & cap_session_replica_v2) != 0;
        self.peer_supports_session_attachment_lease_v2 = self.peer_supports_session_replica_v2 and
            (hs.caps & cap_session_attachment_lease_v2) != 0;
        // The base caps byte cannot represent another version (all eight bits
        // are assigned). A new handshake therefore returns to v2 until the
        // authenticated append-only PING/PONG extension is observed again.
        self.peer_supports_session_replica_v3 = false;
        // A preserved established stream can transition from the old negotiated
        // capability set without receiving another RESYNC in this direction.
        // Surface that false->true edge through the daemon's existing gated
        // authority-before-membership replay path so retained leases converge
        // immediately instead of waiting for their periodic renewal.
        if (self.established and !had_attachment_lease_v2 and self.peer_supports_session_attachment_lease_v2)
            self.resync_requested = true;
        self.peer_supports_secure_relay_v2 = self.peer_supports_signing and (hs.caps & cap_secure_relay_v2) != 0;
        // The fixed handshake byte only establishes the secured relay base.
        // Re-authorize the current E2EEGROUP schema on every handshake.
        self.peer_supports_e2ee_group_current = false;
        self.peer_supports_event_spine_v2 = self.peer_supports_signing and (hs.caps & cap_event_spine_v2) != 0;
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
        // The handshake capability byte is full, so every received handshake
        // invalidates the append-only E2EEGROUP extension above and must trigger
        // a fresh bounded proof once the secured relay base is established. This
        // covers reciprocal RESYNC handshakes where `handshake_sent` is already
        // true, while a same-socket Helix downgrade remains fail-closed.
        if (self.supportsSecureRelayV2Base())
            try emitFrame(self.allocator, sink, .PING, e2ee_group_extension_probe);
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
        if (self.signing_key != null) {
            caps |= cap_frame_signing | cap_member_oper_info;
            if (self.session_replica_transport_enabled)
                caps |= cap_session_replica_v2 | cap_session_attachment_lease_v2;
            if (self.secure_relay_transport_enabled) caps |= cap_secure_relay_v2;
            if (self.event_spine_v2_transport_enabled) caps |= cap_event_spine_v2;
        }
        const payload = try encodeHandshake(self.allocator, .{
            .node_id = self.local_node_id,
            .epoch_ms = self.local_epoch_ms,
            .name = self.server_name,
            .description = self.description,
            .caps = caps,
        });
        defer self.allocator.free(payload);
        try emitFrame(self.allocator, sink, .HANDSHAKE, payload);
        // Safe extension negotiation: a legacy peer treats this as an ordinary
        // PING and echoes it. Only a current peer sends the distinct reply that
        // authorizes current MESSAGE_V2 schema and ACK emission.
        if (self.secure_relay_transport_enabled and self.signing_key != null) {
            try emitFrame(self.allocator, sink, .PING, relay_v2_extension_probe);
            try emitFrame(self.allocator, sink, .PING, relay_v2_ack_confirm_probe);
        }
        if (self.session_replica_transport_enabled and
            self.session_replica_attachment_transport_enabled and self.signing_key != null)
        {
            try emitFrame(self.allocator, sink, .PING, session_replica_v3_probe);
        }
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

    // ADVISORY ANTI-ENTROPY SHADOW — NO per-fact origin authentication.
    // `self.state` is merged from `BURST`/`DELTA`/`REPAIR_RESPONSE`, and `BURST`
    // and `DELTA` are NOT routed through `verifiedPayload` (only MeshPass admits
    // them). It MUST NOT feed any authority/attribution decision: real
    // client-visible membership/oper/modes flow through the SEPARATE,
    // origin-gated `MEMBERSHIP` + `CHANNEL_MODE_STATE` paths, which populate the
    // authoritative `routes.channel_members`/`nick_to_node` maps that
    // NAMES/delivery/401/WHOIS read. Reading `dot.replica_id` or `.modes` here
    // for any decision requires FIRST closing the per-fact-signing gap
    // (`signed_frame.zig:126-133`); until then those fields are inert.
    //
    // This function reflects THIS peer's own liveness in the control channel's
    // node-set and NOTHING else. The prior implementation opened with a
    // node-GLOBAL `routes.removeNode(self.remote_node_id)`, wiping
    // `channel_members`+`nick_to_node` as collateral on the unauthenticated
    // `DELTA` path with `live == 0` — the shipped member-staleness-prune outage
    // shape (empty NAMES / 401 cross-node PM). The mutation is now scoped to the
    // single node-set entry this shadow actually owns, updated idempotently by
    // liveness, and never touches the authoritative roster (audit H2).
    fn refreshChannelRoute(self: *S2sPeer) !void {
        if (self.channel_name.len == 0) return;
        // No coherent origin to track yet (unknown/unauthenticated peer, or a
        // Helix-resumed link before its handshake refills the id): the advisory
        // node-set keys on `remote_node_id`, so there is nothing to set. Return a
        // clean no-op rather than letting `setChannelNodePresence`'s `validateNode`
        // reject 0 and tear down the link on an otherwise-harmless DELTA/REPAIR.
        if (self.remote_node_id == 0) return;
        var live: usize = 0;
        for (self.state.members.items) |entry| {
            if (entry.adds.items.len == 0) continue;
            live += 1;
        }
        try self.routes.setChannelNodePresence(self.channel_name, self.remote_node_id, live != 0);
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

fn replicaFrameType(kind: session_replica_frame.Kind) s2s_frame.FrameType {
    return switch (kind) {
        .offer => .SESSION_REPLICA_OFFER,
        .ack => .SESSION_REPLICA_ACK,
        .revoke => .SESSION_REPLICA_REVOKE,
        .attachment_lease => .SESSION_REPLICA_ATTACHMENT_LEASE,
    };
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

test "ChannelClockSet enforces LWW per channel and rejects stale/equal clocks" {
    const allocator = std.testing.allocator;
    var set = ChannelClockSet{};
    defer set.deinit(allocator);

    try std.testing.expect(set.observe(allocator, "#a", 10));
    try std.testing.expect(!set.observe(allocator, "#a", 10)); // equal -> stale
    try std.testing.expect(!set.observe(allocator, "#a", 5)); // older -> stale
    try std.testing.expect(set.observe(allocator, "#a", 11)); // newer -> admit
    try std.testing.expect(set.observe(allocator, "#b", 1)); // new channel -> admit
    try std.testing.expectEqual(@as(usize, 2), set.count());
}

test "ChannelClockSet is bounded and FIFO-evicts the oldest channel under a name flood" {
    const allocator = std.testing.allocator;
    var set = ChannelClockSet{};
    defer set.deinit(allocator);

    // Stream well past the cap with distinct channel names; the map must never
    // exceed the cap (no unbounded growth) and each owned key is freed on
    // eviction (the testing allocator would flag any leak at deinit).
    var i: usize = 0;
    while (i < max_channel_mode_state_clocks + 500) : (i += 1) {
        var name_buf: [24]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "#flood{d}", .{i}) catch unreachable;
        try std.testing.expect(set.observe(allocator, name, 1));
        try std.testing.expect(set.count() <= max_channel_mode_state_clocks);
    }
    try std.testing.expectEqual(max_channel_mode_state_clocks, set.count());

    // The earliest-inserted channel (#flood0) was FIFO-evicted, so its clock is
    // gone: a replay re-arms it (returns true, treated as a fresh channel).
    try std.testing.expect(set.observe(allocator, "#flood0", 1));
    // A recently-inserted channel is still tracked, so a stale replay is
    // rejected as a duplicate.
    var last_buf: [24]u8 = undefined;
    const last = std.fmt.bufPrint(&last_buf, "#flood{d}", .{max_channel_mode_state_clocks + 499}) catch unreachable;
    try std.testing.expect(!set.observe(allocator, last, 1));
}

test "ChannelClockSet observe under allocation failure fails closed, never leaks, stays in lockstep" {
    // Sweep every allocation-failure index across a short insert sequence. At
    // whatever point the OOM lands (dupe, map put, or order append), `observe`
    // must fail closed (drop, no partial state), the map and order list must
    // stay in lockstep (`count == order.items.len`), and nothing may leak — the
    // testing allocator flags any leaked owned key at `deinit`. This pins the
    // three rollback branches the reviewers verified by hand.
    var fail_at: usize = 0;
    while (fail_at < 16) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_at });
        const allocator = failing.allocator();
        var set = ChannelClockSet{};
        _ = set.observe(allocator, "#a", 1);
        _ = set.observe(allocator, "#b", 2);
        _ = set.observe(allocator, "#a", 3); // getPtr hit: updates in place, no alloc
        _ = set.observe(allocator, "#c", 4);
        try std.testing.expectEqual(set.count(), set.order.items.len);
        set.deinit(allocator);
    }
}

test "identity transition queue preserves mixed order and legacy drains discard matching markers" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var state = ChannelCrdt.init(allocator, 1);
    defer state.deinit();
    var peer = try newPeer(allocator, &state, &tc, 1, 2, 1000, "a.test");
    defer peer.deinit();
    const ident = MemberIdentity{ .username = "device", .realname = "Device B", .host = "mesh.test" };

    try peer.queueMembershipValues("#old", "DeviceB", ident.username, ident.realname, ident.host, "", "", .parted, 0, 0);
    try peer.queueForcedNickRename("DeviceB", "Nova", ident);
    try peer.queueMembershipValues("#new", "Nova", ident.username, ident.realname, ident.host, "", "", .joined, 0, 0);

    var first = peer.takeNextIdentityTransition() orelse return error.TestUnexpectedResult;
    switch (first) {
        .membership => |*change| {
            try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.parted, change.kind);
            try std.testing.expectEqualStrings("#old", change.channel);
            change.deinit(allocator);
        },
        .nick => return error.TestUnexpectedResult,
    }
    var second = peer.takeNextIdentityTransition() orelse return error.TestUnexpectedResult;
    switch (second) {
        .nick => |*change| {
            try std.testing.expectEqualStrings("DeviceB", change.old_nick);
            try std.testing.expectEqualStrings("Nova", change.new_nick);
            change.deinit(allocator);
        },
        .membership => return error.TestUnexpectedResult,
    }
    var third = peer.takeNextIdentityTransition() orelse return error.TestUnexpectedResult;
    switch (third) {
        .membership => |*change| {
            try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.joined, change.kind);
            try std.testing.expectEqualStrings("#new", change.channel);
            change.deinit(allocator);
        },
        .nick => return error.TestUnexpectedResult,
    }
    try std.testing.expect(peer.takeNextIdentityTransition() == null);

    // Historical typed drains remain valid: taking only memberships removes
    // only membership markers, leaving the intervening NICK as the next mixed
    // transition instead of stranding stale markers behind empty typed queues.
    try peer.queueMembershipValues("#old", "DeviceB", ident.username, ident.realname, ident.host, "", "", .parted, 0, 0);
    try peer.queueForcedNickRename("DeviceB", "Nova", ident);
    try peer.queueMembershipValues("#new", "Nova", ident.username, ident.realname, ident.host, "", "", .joined, 0, 0);
    const memberships = try peer.takeMembershipChanges();
    defer allocator.free(memberships);
    try std.testing.expectEqual(@as(usize, 2), memberships.len);
    for (memberships) |*change| change.deinit(allocator);
    var remaining = peer.takeNextIdentityTransition() orelse return error.TestUnexpectedResult;
    switch (remaining) {
        .nick => |*change| change.deinit(allocator),
        .membership => return error.TestUnexpectedResult,
    }
    try std.testing.expect(peer.takeNextIdentityTransition() == null);

    try peer.queueMembershipValues("#old", "DeviceB", ident.username, ident.realname, ident.host, "", "", .parted, 0, 0);
    try peer.queueForcedNickRename("DeviceB", "Nova", ident);
    try peer.queueMembershipValues("#new", "Nova", ident.username, ident.realname, ident.host, "", "", .joined, 0, 0);
    const nicks = try peer.takeNickChanges();
    defer allocator.free(nicks);
    try std.testing.expectEqual(@as(usize, 1), nicks.len);
    for (nicks) |*change| change.deinit(allocator);
    var old_part = peer.takeNextIdentityTransition() orelse return error.TestUnexpectedResult;
    switch (old_part) {
        .membership => |*change| {
            try std.testing.expectEqualStrings("#old", change.channel);
            change.deinit(allocator);
        },
        .nick => return error.TestUnexpectedResult,
    }
    var new_join = peer.takeNextIdentityTransition() orelse return error.TestUnexpectedResult;
    switch (new_join) {
        .membership => |*change| {
            try std.testing.expectEqualStrings("#new", change.channel);
            change.deinit(allocator);
        },
        .nick => return error.TestUnexpectedResult,
    }
    try std.testing.expect(peer.takeNextIdentityTransition() == null);
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

// Regression (audit H2 correctness item): `refreshChannelRoute` must scope its
// mutation to the advisory `#undertow` node-set entry it owns and NEVER wipe the
// authoritative `channel_members`/`nick_to_node` maps that NAMES/delivery/401/
// WHOIS read. Before the fix it opened with a node-GLOBAL
// `routes.removeNode(remote_node_id)` — reachable on the unauthenticated DELTA
// path with `live == 0` — evicting the roster the peer's honest MEMBERSHIP
// frames populated (the shipped member-staleness-prune outage shape).
test "refreshChannelRoute scopes to the control-channel node-set and never wipes the authoritative roster" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var state = ChannelCrdt.init(allocator, 1);
    defer state.deinit();
    var peer = try newPeer(allocator, &state, &tc, 1, 2, 1000, "a.test");
    defer peer.deinit();

    // Authoritative roster: an origin-gated MEMBERSHIP frame from node 2 placed
    // alice@node2 into #chat (channel_members + nick_to_node) — exactly the maps
    // the client-visible surface reads.
    _ = try peer.routes.applyMembership("#chat", "alice", 2, 0, 100, true, .{}, 10);
    try std.testing.expectEqual(@as(?NodeId, 2), peer.routeNickNode("alice"));

    // A DELTA/REPAIR churn event whose merged shadow has ZERO live members must
    // NOT evict node 2's authoritative roster.
    try std.testing.expectEqual(@as(usize, 0), state.members.items.len);
    try peer.refreshChannelRoute();

    // Roster intact (the bug wiped it via node-GLOBAL removeNode)...
    try std.testing.expectEqual(@as(?NodeId, 2), peer.routeNickNode("alice"));
    var nodes: [4]NodeId = undefined;
    // ...and the advisory node-set correctly excludes node 2 (no live members).
    try std.testing.expectEqual(@as(usize, 0), try peer.routes.channelNodes("#undertow", &nodes));

    // A live member now appears in the shadow: node 2 joins the control-channel
    // node-set, still without disturbing the #chat roster.
    discard(try state.localJoin(30, .{ .op = true }, 30));
    try peer.refreshChannelRoute();
    try std.testing.expectEqual(@as(?NodeId, 2), peer.routeNickNode("alice"));
    try std.testing.expectEqual(@as(usize, 1), try peer.routes.channelNodes("#undertow", &nodes));
    try std.testing.expectEqual(@as(NodeId, 2), nodes[0]);

    // Idempotency: repeated live refreshes keep the node-set at exactly one entry
    // (no accumulated refcount), roster still intact.
    try peer.refreshChannelRoute();
    try peer.refreshChannelRoute();
    try std.testing.expectEqual(@as(usize, 1), try peer.routes.channelNodes("#undertow", &nodes));
    try std.testing.expectEqual(@as(?NodeId, 2), peer.routeNickNode("alice"));

    // Liveness drops back to zero: node 2 leaves the node-set, roster STILL intact.
    discard(try state.localPart(30));
    try peer.refreshChannelRoute();
    try std.testing.expectEqual(@as(?NodeId, 2), peer.routeNickNode("alice"));
    try std.testing.expectEqual(@as(usize, 0), try peer.routes.channelNodes("#undertow", &nodes));
}

// Regression (review MEDIUM): a link with no coherent origin yet
// (remote_node_id == 0 — an unknown/unauthenticated or Helix-resumed link before
// its handshake refills the id) must NOT tear down on a DELTA/REPAIR. The
// advisory node-set keys on remote_node_id, so refreshChannelRoute is a clean
// no-op; setChannelNodePresence(node=0) would otherwise hit `validateNode` and
// propagate error.InvalidNode through feed().
test "refreshChannelRoute is a clean no-op on an origin-less (remote_node_id==0) link" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var state = ChannelCrdt.init(allocator, 1);
    defer state.deinit();
    var peer = try newPeer(allocator, &state, &tc, 1, 0, 1000, "a.test");
    defer peer.deinit();
    const limits = peer.config.link.burst_limits;

    // An unrelated node's roster row must survive untouched.
    _ = try peer.routes.applyMembership("#chat", "carol", 5, 0, 100, true, .{}, 10);

    // live == 0 branch (the diff's net-new exposure)...
    try peer.refreshChannelRoute();
    // ...and the live != 0 branch (which the OLD code also errored on)...
    discard(try state.localJoin(30, .{ .op = true }, 30));
    try peer.refreshChannelRoute();
    // ...and through the real DELTA path (mergeDelta → refreshChannelRoute).
    const bytes = try burst.serialize(allocator, &state, limits);
    defer allocator.free(bytes);
    try peer.mergeDelta(bytes);

    try std.testing.expectEqual(@as(?NodeId, 5), peer.routeNickNode("carol"));
    var nodes: [2]NodeId = undefined;
    try std.testing.expectEqual(@as(usize, 0), try peer.routes.channelNodes("#undertow", &nodes));
}

// Byzantine tripwire (audit H2): an admitted (possibly Byzantine) MeshPass peer
// can push BURST/DELTA/REPAIR_RESPONSE into the advisory `self.state` shadow with
// NO per-fact origin authentication. This pins the self-limited boundary as a
// PERMANENT CI gate: forged shadow facts — including a `dot.replica_id` naming a
// THIRD victim node and forged channel modes — must NOT reach the authoritative
// client-visible roster (`channel_members`/`nick_to_node`), and a forged
// all-tombstone DELTA must NOT evict a third node's roster. The day a future
// change lets forged shadow state reach a third node or an authority decision,
// this test reds (see the `self.state` field-declaration contract).
test "forged mesh shadow facts never reach the authoritative roster (Byzantine tripwire)" {
    const allocator = std.testing.allocator;
    // An oper prefix bit in the route table's MemberStatus layout. The exact
    // value is immaterial to the invariant — the test asserts it round-trips
    // UNCHANGED through the forged frames, whatever it is.
    const victim_status: u4 = 0b0100;

    var tc = TestClock{ .now_ms = 10 };
    var state = ChannelCrdt.init(allocator, 1);
    defer state.deinit();
    // The receiver's admitted peer link is node 2.
    var peer = try newPeer(allocator, &state, &tc, 1, 2, 1000, "a.test");
    defer peer.deinit();
    const limits = peer.config.link.burst_limits;

    // Authoritative roster, as origin-gated MEMBERSHIP frames populate it:
    //  - "vic" is an oper homed on a THIRD node (3), NOT the sender.
    //  - "peeruser" is homed on the sender's own node (2).
    _ = try peer.routes.applyMembership("#chat", "vic", 3, victim_status, 200, true, .{}, 10);
    _ = try peer.routes.applyMembership("#chat", "peeruser", 2, 0, 210, true, .{}, 10);

    const before_vic = peer.findRemoteMember("vic") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(NodeId, 3), before_vic.node);
    try std.testing.expectEqual(victim_status, before_vic.status);

    // Forge a CRDT that CLAIMS to be node 3 (replica_id = 3) and carries a member
    // with founder+op status AND forged channel modes — the exact fields
    // (dot.replica_id, modes) an attacker would target.
    var forged = ChannelCrdt.init(allocator, 3);
    defer forged.deinit();
    discard(try forged.localJoin(99, .{ .founder = true, .op = true }, 20));
    discard(try forged.localSetMode(.{ .invite_only = true }, 21));
    const forged_bytes = try burst.serialize(allocator, &forged, limits);
    defer allocator.free(forged_bytes);

    // Drive it through BOTH shadow-merge paths an admitted peer can reach: BURST
    // (burst.apply) and DELTA (mergeDelta → refreshChannelRoute).
    try burst.apply(allocator, peer.state, forged_bytes, limits);
    try peer.mergeDelta(forged_bytes);

    // The victim's authoritative roster row is unchanged: same node, same oper
    // status. The forgery landed only in the inert shadow.
    const after_vic = peer.findRemoteMember("vic") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(NodeId, 3), after_vic.node);
    try std.testing.expectEqual(victim_status, after_vic.status);
    try std.testing.expectEqual(@as(?NodeId, 3), peer.routeNickNode("vic"));
    try std.testing.expectEqual(@as(?NodeId, 2), peer.routeNickNode("peeruser"));

    // A forged ALL-TOMBSTONE DELTA (member present, zero live adds → live==0) must
    // evict AT MOST the sender's own node's routing presence — never a third
    // node's roster.
    var tombstone = ChannelCrdt.init(allocator, 3);
    defer tombstone.deinit();
    discard(try tombstone.localJoin(99, .{}, 22));
    discard(try tombstone.localPart(99));
    const tomb_bytes = try burst.serialize(allocator, &tombstone, limits);
    defer allocator.free(tomb_bytes);
    try peer.mergeDelta(tomb_bytes);

    // Third node's roster survives; the sender's own roster survives too (the fix
    // scopes refreshChannelRoute to the advisory node-set, never the roster).
    try std.testing.expectEqual(@as(?NodeId, 3), peer.routeNickNode("vic"));
    try std.testing.expectEqual(@as(?NodeId, 2), peer.routeNickNode("peeruser"));
    const survived_vic = peer.findRemoteMember("vic") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(victim_status, survived_vic.status);

    // Recovery on re-burst is clean: a re-affirming MEMBERSHIP keeps the roster.
    _ = try peer.routes.applyMembership("#chat", "vic", 3, victim_status, 220, true, .{}, 20);
    const recovered = peer.findRemoteMember("vic") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(victim_status, recovered.status);
}

// Regression: LINKS rendered a remote peer's description as the generic
// "Undertow peer" placeholder because it keyed `nodeDescription` on
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

test "timestamped RTT probe samples PING to PONG latency" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1_000 };
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

    try std.testing.expect(a.lastRttMs() == null);
    try a.sendRttProbe(a_to_b.sink(), tc.now_ms);
    tc.now_ms += 42;
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x52);
    try std.testing.expectEqual(@as(?u32, 42), a.lastRttMs());
    // Capability-probe string PONGs must not clobber the sample.
    try a.sendPing(relay_v2_extension_probe, a_to_b.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms + 5, 0x53);
    try std.testing.expectEqual(@as(?u32, 42), a.lastRttMs());
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

    // The configured decoder ceiling is also the egress ceiling. An exact-fit
    // frame is emitted; one byte less rejects before allocation or sink output.
    const framed_len = try s2s_frame.encodedLen(capsule_bytes.len);
    a.config.max_frame_size = framed_len;
    try a.sendSessionMigrate(a_to_b.sink(), capsule_bytes);
    try std.testing.expectEqual(framed_len, a_to_b.bytes.items.len);
    a_to_b.clear();
    a.config.max_frame_size = framed_len - 1;
    try std.testing.expectError(error.PayloadTooLarge, a.sendSessionMigrate(a_to_b.sink(), capsule_bytes));
    try std.testing.expectEqual(@as(usize, 0), a_to_b.bytes.items.len);
}

test "SESSION_MIGRATE_CONSUMED is dispatched to its convergence queue" {
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

    try a.sendSessionMigrateConsumed(a_to_b.sink(), "consume-tombstone");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xC0DE);

    const staged = try b.takeSessionMigrateConsumed();
    defer {
        for (staged) |item| allocator.free(item);
        allocator.free(staged);
    }
    try std.testing.expectEqual(@as(usize, 1), staged.len);
    try std.testing.expectEqualStrings("consume-tombstone", staged[0]);
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
        \\[mesh.ripple]
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
    // [mesh.gossip]/[mesh.ripple] flow into the session sub-configs.
    try std.testing.expectEqual(@as(usize, 5), cfg.link.gossip_config.fanout);
    try std.testing.expectEqual(@as(u8, 3), cfg.link.ripple_config.witness_quorum);
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

fn stampedRelayV2(
    allocator: Allocator,
    kp: *const sign.KeyPair,
    target: []const u8,
    scope: message_relay_v2.ScopeKind,
    hlc: u64,
    pubkey: *[message_relay_v2.pubkey_len]u8,
    signature: *[message_relay_v2.sig_len]u8,
) !message_relay_v2.RelayMessage {
    var msg = message_relay_v2.RelayMessage{
        .verb = .privmsg,
        .target = target,
        .source_prefix = "alice!u@example.invalid",
        .account = "alice",
        .tags = "+draft/reply=42",
        .text = "secure relay v2",
        .scope_kind = scope,
        .sender_route_id = try message_relay_v2.routeId(@splat(0x31)),
        .recipient_route_id = if (scope == .direct) try message_relay_v2.routeId(@splat(0x32)) else null,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try message_relay_v2.stampOrigin(allocator, &msg, kp, pubkey, signature);
    return msg;
}

fn stampedE2eeGroup(
    allocator: Allocator,
    kp: *const sign.KeyPair,
    hlc: u64,
    pubkey: *[e2ee_group_relay.pubkey_len]u8,
    signature: *[e2ee_group_relay.sig_len]u8,
) !e2ee_group_relay.RelayRecord {
    var record = e2ee_group_relay.RelayRecord{
        .kind = .commit,
        .channel = "#root",
        .source_prefix = "alice!u@example.invalid",
        .account = "alice",
        .from_device = "laptop.1",
        .payload = "AQIDBA",
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try e2ee_group_relay.stampOrigin(allocator, &record, kp, pubkey, signature);
    return record;
}

fn stampedOperEventV2(
    kp: *const sign.KeyPair,
    hlc: u64,
    pubkey: *[oper_event.pubkey_len]u8,
    signature: *[oper_event.sig_len]u8,
) !oper_event.SignedOperEventV2 {
    var event = oper_event.SignedOperEventV2{
        .category = 13,
        .severity = 2,
        .origin_node = oper_event.originShortId(kp.public_key),
        .hlc = hlc,
        .origin_server = "a.test",
        .subject = "#mesh",
        .message = "raid threshold crossed in #mesh",
    };
    try oper_event.stampOrigin(&event, kp, pubkey, signature);
    return event;
}

test "E2EEGROUP negotiation gates valid canonical receive and rejects unsigned tampered wire" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0x91);
    const kp_b = try signingKeyFor(0x92);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.secure_relay_transport_enabled = true;
    b.secure_relay_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6410);
    try std.testing.expect(a.supportsE2eeGroup());
    try std.testing.expect(b.supportsE2eeGroup());
    try a.sendResync(a_to_b.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6411);
    try std.testing.expect(a.supportsE2eeGroup());
    try std.testing.expect(b.supportsE2eeGroup());

    var pubkey: [e2ee_group_relay.pubkey_len]u8 = undefined;
    var signature: [e2ee_group_relay.sig_len]u8 = undefined;
    const valid = try stampedE2eeGroup(allocator, &a.signing_key.?, 700, &pubkey, &signature);
    const valid_wire = try e2ee_group_relay.encode(allocator, valid);
    defer allocator.free(valid_wire);
    const valid_id = switch (try e2ee_group_relay.verifyAndRelayId(allocator, valid)) {
        .verified => |id| id,
        else => return error.TestUnexpectedResult,
    };
    a.peer_supports_e2ee_group_current = false;
    try std.testing.expectError(
        error.CapabilityNotNegotiated,
        a.sendE2eeGroup(a_to_b.sink(), valid),
    );
    try std.testing.expectEqual(@as(usize, 0), a_to_b.bytes.items.len);
    a.peer_supports_e2ee_group_current = true;

    // Negotiated signing makes a raw inner record an invalid hop envelope.
    try emitFrame(allocator, a_to_b.sink(), .E2EE_GROUP, valid_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6412);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedE2eeGroupFrames());
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());

    // A valid outer hop cannot rescue a tampered immutable origin signature.
    var tampered = valid;
    tampered.payload = "tampered";
    const tampered_wire = try e2ee_group_relay.encode(allocator, tampered);
    defer allocator.free(tampered_wire);
    try a.emitSignable(a_to_b.sink(), .E2EE_GROUP, tampered_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6413);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedE2eeGroupFrames());

    // An overlong two-byte map-count varint is structurally equivalent to the
    // canonical one-byte count, but CoilPack must reject that wire image.
    const noncanonical = try allocator.alloc(u8, valid_wire.len + 1);
    defer allocator.free(noncanonical);
    noncanonical[0] = valid_wire[0];
    noncanonical[1] = valid_wire[1] | 0x80;
    noncanonical[2] = 0;
    @memcpy(noncanonical[3..], valid_wire[2..]);
    try a.emitSignable(a_to_b.sink(), .E2EE_GROUP, noncanonical);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6414);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedE2eeGroupFrames());

    // Invalid claims never reserve the later authentic RelayId.
    try a.sendE2eeGroup(a_to_b.sink(), valid);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6415);
    const inbound = try b.takeInboundE2eeGroup();
    defer {
        for (inbound) |*item| item.deinit(allocator);
        allocator.free(inbound);
    }
    try std.testing.expectEqual(@as(usize, 1), inbound.len);
    try std.testing.expectEqual(valid_id, inbound[0].relay_id);
    try std.testing.expectEqual(a_short, inbound[0].via_peer);
    try std.testing.expectEqualSlices(u8, valid_wire, inbound[0].wire);
    try std.testing.expectEqualStrings("AQIDBA", inbound[0].owned.record.payload);
    try std.testing.expect(!(try b.forwardE2eeGroup(b_to_a.sink(), inbound[0].wire)));
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);
}

test "E2EEGROUP forwarding is byte-identical across transit and queue backpressure is retryable" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_ab_state = ChannelCrdt.init(allocator, 2);
    defer b_ab_state.deinit();
    var b_bc_state = ChannelCrdt.init(allocator, 3);
    defer b_bc_state.deinit();
    var c_state = ChannelCrdt.init(allocator, 4);
    defer c_state.deinit();
    const kp_a = try signingKeyFor(0x93);
    const kp_b_ab = try signingKeyFor(0x94);
    const kp_b_bc = try signingKeyFor(0x94);
    const kp_c = try signingKeyFor(0x95);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b_ab.public_key);
    const c_node = signed_frame.originShortId(kp_c.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b_from_a = try newSigningPeer(allocator, &b_ab_state, &tc, kp_b_ab, a_short, 2000, "b.test");
    defer b_from_a.deinit();
    var b_to_c = try newSigningPeer(allocator, &b_bc_state, &tc, kp_b_bc, c_node, 2000, "b.test");
    defer b_to_c.deinit();
    var c = try newSigningPeer(allocator, &c_state, &tc, kp_c, b_short, 3000, "c.test");
    defer c.deinit();
    a.secure_relay_transport_enabled = true;
    b_from_a.secure_relay_transport_enabled = true;
    b_to_c.secure_relay_transport_enabled = true;
    c.secure_relay_transport_enabled = true;
    c.config.max_e2ee_group_frames = 1;

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b_from_a.startHandshake(b_to_a.sink());
    try pump(&a, &b_from_a, &a_to_b, &b_to_a, tc.now_ms, 0x6420);
    var b_to_c_wire = BufferSink{};
    defer b_to_c_wire.deinit(allocator);
    var c_to_b_wire = BufferSink{};
    defer c_to_b_wire.deinit(allocator);
    try b_to_c.startHandshake(b_to_c_wire.sink());
    try c.startHandshake(c_to_b_wire.sink());
    try pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x6421);

    var pubkey: [e2ee_group_relay.pubkey_len]u8 = undefined;
    var signature: [e2ee_group_relay.sig_len]u8 = undefined;
    const first = try stampedE2eeGroup(allocator, &a.signing_key.?, 701, &pubkey, &signature);
    try a.sendE2eeGroup(a_to_b.sink(), first);
    try pump(&a, &b_from_a, &a_to_b, &b_to_a, tc.now_ms, 0x6422);
    const at_b = try b_from_a.takeInboundE2eeGroup();
    defer {
        for (at_b) |*item| item.deinit(allocator);
        allocator.free(at_b);
    }
    try std.testing.expectEqual(@as(usize, 1), at_b.len);
    try std.testing.expect(!(try b_from_a.forwardE2eeGroup(b_to_a.sink(), at_b[0].wire)));
    try std.testing.expect(try b_to_c.forwardE2eeGroup(b_to_c_wire.sink(), at_b[0].wire));
    try pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x6423);
    const at_c = try c.takeInboundE2eeGroup();
    defer {
        for (at_c) |*item| item.deinit(allocator);
        allocator.free(at_c);
    }
    try std.testing.expectEqual(@as(usize, 1), at_c.len);
    try std.testing.expectEqualSlices(u8, at_b[0].wire, at_c[0].wire);
    try std.testing.expectEqual(b_short, at_c[0].via_peer);
    try std.testing.expectEqual(a_short, at_c[0].owned.record.origin_node);

    // Keep one accepted record queued, reject the next with explicit
    // backpressure, then prove draining allows the exact record to retry.
    var pubkey2: [e2ee_group_relay.pubkey_len]u8 = undefined;
    var signature2: [e2ee_group_relay.sig_len]u8 = undefined;
    const second = try stampedE2eeGroup(allocator, &a.signing_key.?, 702, &pubkey2, &signature2);
    const second_wire = try e2ee_group_relay.encode(allocator, second);
    defer allocator.free(second_wire);
    try std.testing.expect(try b_to_c.forwardE2eeGroup(b_to_c_wire.sink(), second_wire));
    var pubkey3: [e2ee_group_relay.pubkey_len]u8 = undefined;
    var signature3: [e2ee_group_relay.sig_len]u8 = undefined;
    const third = try stampedE2eeGroup(allocator, &a.signing_key.?, 703, &pubkey3, &signature3);
    const third_wire = try e2ee_group_relay.encode(allocator, third);
    defer allocator.free(third_wire);
    try std.testing.expect(try b_to_c.forwardE2eeGroup(b_to_c_wire.sink(), third_wire));
    try std.testing.expectError(
        error.E2eeGroupBackpressure,
        pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x6424),
    );
    b_to_c_wire.clear();
    try std.testing.expectEqual(@as(u64, 1), c.takeDroppedE2eeGroupFrames());
    const queued = try c.takeInboundE2eeGroup();
    defer {
        for (queued) |*item| item.deinit(allocator);
        allocator.free(queued);
    }
    try std.testing.expectEqual(@as(usize, 1), queued.len);
    try std.testing.expectEqual(@as(u64, 702), queued[0].owned.record.hlc);
    try b_to_c.replayRetainedE2eeGroupWire(b_to_c_wire.sink(), third_wire);
    try pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x6425);
    const retried = try c.takeInboundE2eeGroup();
    defer {
        for (retried) |*item| item.deinit(allocator);
        allocator.free(retried);
    }
    try std.testing.expectEqual(@as(usize, 1), retried.len);
    try std.testing.expectEqual(@as(u64, 703), retried[0].owned.record.hlc);
}

test "E2EEGROUP ACK is domain separated authenticated deduplicated bounded and capability gated" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0x96);
    const kp_b = try signingKeyFor(0x97);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.secure_relay_transport_enabled = true;
    b.secure_relay_transport_enabled = true;
    a.config.max_e2ee_group_ack_frames = 2;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6430);
    try std.testing.expect(a.supportsE2eeGroup());
    try std.testing.expect(b.supportsE2eeGroup());
    try std.testing.expect(a.supportsE2eeGroupAckConfirm());
    try std.testing.expect(b.supportsE2eeGroupAckConfirm());

    // Legacy e2ee-group-1 PONG never arms v2 (ACK/ACK_CONFIRM) capability.
    a.peer_supports_e2ee_group_current = false;
    try emitFrame(allocator, b_to_a.sink(), .PONG, "onyx-xcap-e2ee-group-1!");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6429);
    try std.testing.expect(!a.supportsE2eeGroup());
    try std.testing.expect(!a.supportsE2eeGroupAckConfirm());
    a.peer_supports_e2ee_group_current = true;

    const first: e2ee_group_relay.RelayId = @splat(0x51);
    b.peer_supports_e2ee_group_current = false;
    try std.testing.expectError(
        error.CapabilityNotNegotiated,
        b.sendE2eeGroupAck(b_to_a.sink(), first),
    );
    try std.testing.expectError(
        error.CapabilityNotNegotiated,
        b.sendE2eeGroupAckConfirm(b_to_a.sink(), first),
    );
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);
    b.peer_supports_e2ee_group_current = true;

    // The exact secured receipt round-trips once; same-batch duplicates coalesce.
    try b.sendE2eeGroupAck(b_to_a.sink(), first);
    try b.sendE2eeGroupAck(b_to_a.sink(), first);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6431);
    var acks = try a.takeInboundE2eeGroupAcks();
    try std.testing.expectEqual(@as(usize, 1), acks.len);
    try std.testing.expectEqualSlices(u8, &first, &acks[0]);
    allocator.free(acks);
    var confirms = try a.takeInboundE2eeGroupAckConfirms();
    try std.testing.expectEqual(@as(usize, 0), confirms.len);
    allocator.free(confirms);
    const chat_acks = try a.takeInboundV2Acks();
    defer allocator.free(chat_acks);
    try std.testing.expectEqual(@as(usize, 0), chat_acks.len);

    // ACK_CONFIRM uses the same frame tag with flag=1 and a separate queue.
    try b.sendE2eeGroupAckConfirm(b_to_a.sink(), first);
    try b.sendE2eeGroupAckConfirm(b_to_a.sink(), first);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6431);
    confirms = try a.takeInboundE2eeGroupAckConfirms();
    try std.testing.expectEqual(@as(usize, 1), confirms.len);
    try std.testing.expectEqualSlices(u8, &first, &confirms[0]);
    allocator.free(confirms);
    acks = try a.takeInboundE2eeGroupAcks();
    try std.testing.expectEqual(@as(usize, 0), acks.len);
    allocator.free(acks);

    // Queue allocation failure is explicit and reserves no receipt identity, so
    // the same authenticated ACK succeeds on retry with the normal allocator.
    const retry_id: e2ee_group_relay.RelayId = @splat(0x50);
    var retry_env_buf: [signed_frame.header_len + e2ee_group_relay.relay_id_len]u8 = undefined;
    const retry_env = try signed_frame.wrap(
        &retry_env_buf,
        &b.signing_key.?,
        @intFromEnum(s2s_frame.FrameType.E2EE_GROUP_ACK),
        &retry_id,
    );
    {
        const normal_allocator = a.allocator;
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        a.allocator = failing.allocator();
        defer a.allocator = normal_allocator;
        try std.testing.expectError(error.OutOfMemory, a.recvE2eeGroupAck(retry_env));
    }
    try std.testing.expectEqual(@as(u64, 1), a.takeDroppedE2eeGroupFrames());
    try a.recvE2eeGroupAck(retry_env);
    acks = try a.takeInboundE2eeGroupAcks();
    try std.testing.expectEqual(@as(usize, 1), acks.len);
    try std.testing.expectEqualSlices(u8, &retry_id, &acks[0]);
    allocator.free(acks);

    // Strict length/flag and signed-hop gates soft-drop malformed or unsigned input.
    try b.emitSignable(b_to_a.sink(), .E2EE_GROUP_ACK, "short");
    try emitFrame(allocator, b_to_a.sink(), .E2EE_GROUP_ACK, &first);
    var bad_flag: [e2ee_group_relay.relay_id_len + 1]u8 = undefined;
    @memcpy(bad_flag[0..e2ee_group_relay.relay_id_len], &first);
    bad_flag[e2ee_group_relay.relay_id_len] = 2;
    try b.emitSignable(b_to_a.sink(), .E2EE_GROUP_ACK, &bad_flag);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6432);
    try std.testing.expectEqual(@as(u64, 3), a.takeRejectedE2eeGroupFrames());
    try std.testing.expectEqual(@as(u64, 1), a.takeRejectedOriginFrames());
    acks = try a.takeInboundE2eeGroupAcks();
    try std.testing.expectEqual(@as(usize, 0), acks.len);
    allocator.free(acks);
    confirms = try a.takeInboundE2eeGroupAckConfirms();
    try std.testing.expectEqual(@as(usize, 0), confirms.len);
    allocator.free(confirms);

    // An envelope signed in MESSAGE_V2_ACK's tag domain is invalid when replayed
    // under E2EE_GROUP_ACK even though both payload types are 16-byte arrays.
    var wrong_domain_buf: [signed_frame.header_len + e2ee_group_relay.relay_id_len]u8 = undefined;
    const wrong_domain = try signed_frame.wrap(
        &wrong_domain_buf,
        &b.signing_key.?,
        @intFromEnum(s2s_frame.FrameType.MESSAGE_V2_ACK),
        &first,
    );
    try emitFrame(allocator, b_to_a.sink(), .E2EE_GROUP_ACK, wrong_domain);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6433);
    try std.testing.expectEqual(@as(u64, 1), a.takeRejectedE2eeGroupFrames());
    try std.testing.expectEqual(@as(u64, 1), a.takeRejectedOriginFrames());

    // Queue overflow is advisory: preserve the first two receipts and soft-drop
    // the excess so its sender will retry the exact retained E2EEGROUP wire.
    // ACK and ACK_CONFIRM queues are independently bounded — fill both before
    // draining either so neither queue's pressure blocks the other.
    const second: e2ee_group_relay.RelayId = @splat(0x52);
    const third: e2ee_group_relay.RelayId = @splat(0x53);
    const fourth: e2ee_group_relay.RelayId = @splat(0x54);
    try b.sendE2eeGroupAck(b_to_a.sink(), second);
    try b.sendE2eeGroupAck(b_to_a.sink(), third);
    try b.sendE2eeGroupAck(b_to_a.sink(), fourth);
    const conf_a: e2ee_group_relay.RelayId = @splat(0x61);
    const conf_b: e2ee_group_relay.RelayId = @splat(0x62);
    const conf_c: e2ee_group_relay.RelayId = @splat(0x63);
    try b.sendE2eeGroupAckConfirm(b_to_a.sink(), conf_a);
    try b.sendE2eeGroupAckConfirm(b_to_a.sink(), conf_b);
    try b.sendE2eeGroupAckConfirm(b_to_a.sink(), conf_c);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6434);
    // One overflowed ACK + one overflowed confirm.
    try std.testing.expectEqual(@as(u64, 2), a.takeDroppedE2eeGroupFrames());
    acks = try a.takeInboundE2eeGroupAcks();
    defer allocator.free(acks);
    try std.testing.expectEqual(@as(usize, 2), acks.len);
    try std.testing.expectEqualSlices(u8, &second, &acks[0]);
    try std.testing.expectEqualSlices(u8, &third, &acks[1]);
    confirms = try a.takeInboundE2eeGroupAckConfirms();
    defer allocator.free(confirms);
    try std.testing.expectEqual(@as(usize, 2), confirms.len);
    try std.testing.expectEqualSlices(u8, &conf_a, &confirms[0]);
    try std.testing.expectEqualSlices(u8, &conf_b, &confirms[1]);
}

test "secure relay v2 negotiates only on secured peers and round-trips once" {
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
    a.secure_relay_transport_enabled = true;
    b.secure_relay_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6100);
    try std.testing.expect(a.supportsSecureRelayV2());
    try std.testing.expect(b.supportsSecureRelayV2());

    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    const msg = try stampedRelayV2(allocator, &a.signing_key.?, "#room", .channel, 100, &pubkey, &signature);
    try a.sendMessageV2(a_to_b.sink(), msg);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6101);
    var inbound = try b.takeInboundV2();
    try std.testing.expectEqual(@as(usize, 1), inbound.len);
    try std.testing.expectEqual(a_short, inbound[0].via_peer);
    try std.testing.expectEqualStrings("#room", inbound[0].owned.msg.target);
    try std.testing.expectEqual(message_relay_v2.ScopeKind.channel, inbound[0].owned.msg.scope_kind);
    try std.testing.expectEqual(message_relay_v2.VerifyOutcome.verified, try message_relay_v2.verifyOrigin(allocator, inbound[0].owned.msg));
    for (inbound) |*item| item.deinit(allocator);
    allocator.free(inbound);

    // Draining without daemon-global admission must not make a retry disappear.
    // The per-link cache is outbound-only; the durable guard classifies this.
    try a.sendMessageV2(a_to_b.sink(), msg);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6102);
    inbound = try b.takeInboundV2();
    defer {
        for (inbound) |*item| item.deinit(allocator);
        allocator.free(inbound);
    }
    try std.testing.expectEqual(@as(usize, 1), inbound.len);
    try std.testing.expect(!(try b.forwardMessageV2(b_to_a.sink(), inbound[0].wire)));
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);
}

test "secure relay v2 ACK is authenticated deduplicated bounded and capability gated" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0x41);
    const kp_b = try signingKeyFor(0x42);
    var a = try newSigningPeer(
        allocator,
        &a_state,
        &tc,
        kp_a,
        signed_frame.originShortId(kp_b.public_key),
        1000,
        "a.test",
    );
    defer a.deinit();
    var b = try newSigningPeer(
        allocator,
        &b_state,
        &tc,
        kp_b,
        signed_frame.originShortId(kp_a.public_key),
        2000,
        "b.test",
    );
    defer b.deinit();
    a.secure_relay_transport_enabled = true;
    b.secure_relay_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6150);

    const first: message_relay_v2.RelayId = @splat(0x55);
    try b.sendMessageV2Ack(b_to_a.sink(), first);
    try b.sendMessageV2Ack(b_to_a.sink(), first);
    const ack_batch = try allocator.dupe(u8, b_to_a.bytes.items);
    defer allocator.free(ack_batch);
    b_to_a.clear();
    try a.feed(ack_batch, a_to_b.sink(), tc.now_ms, 0x6151);
    var acks = try a.takeInboundV2Acks();
    try std.testing.expectEqual(@as(usize, 1), acks.len);
    try std.testing.expectEqualSlices(u8, &first, &acks[0]);
    allocator.free(acks);

    try std.testing.expect(a.supportsRelayV2AckConfirm());
    try std.testing.expect(b.supportsRelayV2AckConfirm());
    try b.sendMessageV2AckConfirm(b_to_a.sink(), first);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6155);
    const confirms = try a.takeInboundV2AckConfirms();
    defer allocator.free(confirms);
    try std.testing.expectEqual(@as(usize, 1), confirms.len);
    try std.testing.expectEqualSlices(u8, &first, &confirms[0]);

    // One coalesced socket read can exceed the handoff queue. Excess ACKs are
    // safely soft-dropped (the exact sender outbox retries) and never fault the
    // authenticated stream.
    for (0..a.config.max_relay_v2_frames + 32) |index| {
        var id: message_relay_v2.RelayId = @splat(0);
        std.mem.writeInt(u64, id[0..8], index + 1, .little);
        try b.sendMessageV2Ack(b_to_a.sink(), id);
    }
    const large_batch = try allocator.dupe(u8, b_to_a.bytes.items);
    defer allocator.free(large_batch);
    b_to_a.clear();
    try a.feed(large_batch, a_to_b.sink(), tc.now_ms, 0x6152);
    acks = try a.takeInboundV2Acks();
    try std.testing.expectEqual(a.config.max_relay_v2_frames, acks.len);
    allocator.free(acks);

    // A rolling predecessor that negotiated the v2.1 schema but not durable
    // ACK confirmation must not enter this generation's daemon admission queue:
    // the receiver could otherwise retain a receipt it is unable to retire.
    var legacy_pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var legacy_signature: [message_relay_v2.sig_len]u8 = undefined;
    const legacy_msg = try stampedRelayV2(
        allocator,
        &b.signing_key.?,
        "#legacy-current",
        .channel,
        77,
        &legacy_pubkey,
        &legacy_signature,
    );
    const legacy_wire = try message_relay_v2.encode(allocator, legacy_msg);
    defer allocator.free(legacy_wire);
    a.peer_supports_relay_v2_ack_confirm = false;
    try b.emitSignable(b_to_a.sink(), .MESSAGE_V2, legacy_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6156);
    const refused = try a.takeInboundV2();
    defer allocator.free(refused);
    try std.testing.expectEqual(@as(usize, 0), refused.len);
    try std.testing.expectEqual(@as(u64, 1), a.takeRejectedRelayV2Frames());
    a.peer_supports_relay_v2_ack_confirm = true;

    b.peer_supports_relay_v2_current = false;
    try std.testing.expectError(error.SecuredLinkRequired, b.sendMessageV2Ack(b_to_a.sink(), first));
    b.peer_supports_relay_v2_current = true;
    b.peer_supports_relay_v2_ack_confirm = false;
    try std.testing.expectError(
        error.CapabilityNotNegotiated,
        b.sendMessageV2AckConfirm(b_to_a.sink(), first),
    );
    b.peer_supports_relay_v2_ack_confirm = true;

    try b.emitSignable(b_to_a.sink(), .MESSAGE_V2_ACK, "short");
    const malformed = try allocator.dupe(u8, b_to_a.bytes.items);
    defer allocator.free(malformed);
    b_to_a.clear();
    try std.testing.expectError(
        error.InvalidRelayMessage,
        a.feed(malformed, a_to_b.sink(), tc.now_ms, 0x6153),
    );

    try b.sendMessageV2Ack(b_to_a.sink(), first);
    b_to_a.bytes.items[b_to_a.bytes.items.len - 1] ^= 1;
    const forged = try allocator.dupe(u8, b_to_a.bytes.items);
    defer allocator.free(forged);
    b_to_a.clear();
    try std.testing.expectError(
        error.BadFrameSignature,
        a.feed(forged, a_to_b.sink(), tc.now_ms, 0x6154),
    );
}

test "secure relay v2 preserves the original signature across pure transit A B C" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_ab_state = ChannelCrdt.init(allocator, 2);
    defer b_ab_state.deinit();
    var b_bc_state = ChannelCrdt.init(allocator, 3);
    defer b_bc_state.deinit();
    var c_state = ChannelCrdt.init(allocator, 4);
    defer c_state.deinit();

    const kp_a = try signingKeyFor(0x73);
    const kp_b_ab = try signingKeyFor(0x74);
    const kp_b_bc = try signingKeyFor(0x74);
    const kp_c = try signingKeyFor(0x75);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b_ab.public_key);
    const c_node = signed_frame.originShortId(kp_c.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b_from_a = try newSigningPeer(allocator, &b_ab_state, &tc, kp_b_ab, a_short, 2000, "b.test");
    defer b_from_a.deinit();
    var b_to_c = try newSigningPeer(allocator, &b_bc_state, &tc, kp_b_bc, c_node, 2000, "b.test");
    defer b_to_c.deinit();
    var c = try newSigningPeer(allocator, &c_state, &tc, kp_c, b_short, 3000, "c.test");
    defer c.deinit();
    a.secure_relay_transport_enabled = true;
    b_from_a.secure_relay_transport_enabled = true;
    b_to_c.secure_relay_transport_enabled = true;
    c.secure_relay_transport_enabled = true;

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b_from_a.startHandshake(b_to_a.sink());
    try pump(&a, &b_from_a, &a_to_b, &b_to_a, tc.now_ms, 0x6200);
    var b_to_c_wire = BufferSink{};
    defer b_to_c_wire.deinit(allocator);
    var c_to_b_wire = BufferSink{};
    defer c_to_b_wire.deinit(allocator);
    try b_to_c.startHandshake(b_to_c_wire.sink());
    try c.startHandshake(c_to_b_wire.sink());
    try pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x6201);

    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    const origin_msg = try stampedRelayV2(allocator, &a.signing_key.?, "bob", .direct, 101, &pubkey, &signature);
    const origin_id = switch (try message_relay_v2.verifyAndRelayId(allocator, origin_msg)) {
        .verified => |id| id,
        else => return error.TestUnexpectedResult,
    };
    try a.sendMessageV2(a_to_b.sink(), origin_msg);
    try pump(&a, &b_from_a, &a_to_b, &b_to_a, tc.now_ms, 0x6202);
    const at_b = try b_from_a.takeInboundV2();
    defer {
        for (at_b) |*item| item.deinit(allocator);
        allocator.free(at_b);
    }
    try std.testing.expectEqual(@as(usize, 1), at_b.len);
    // The ingress leg suppresses reflection without emitting an outer frame.
    try std.testing.expect(!(try b_from_a.forwardMessageV2(b_to_a.sink(), at_b[0].wire)));
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);

    // A distinct B-C leg forwards the exact immutable canonical inner image.
    try std.testing.expect(try b_to_c.forwardMessageV2(b_to_c_wire.sink(), at_b[0].wire));
    try pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x6203);
    const at_c = try c.takeInboundV2();
    defer {
        for (at_c) |*item| item.deinit(allocator);
        allocator.free(at_c);
    }
    try std.testing.expectEqual(@as(usize, 1), at_c.len);
    try std.testing.expectEqualSlices(u8, at_b[0].wire, at_c[0].wire);
    try std.testing.expectEqual(b_short, at_c[0].via_peer);
    try std.testing.expectEqual(a_short, at_c[0].owned.msg.origin_node);
    try std.testing.expectEqualSlices(u8, origin_msg.origin_pubkey, at_c[0].owned.msg.origin_pubkey);
    try std.testing.expectEqualSlices(u8, origin_msg.origin_sig, at_c[0].owned.msg.origin_sig);
    const at_c_id = switch (try message_relay_v2.verifyAndRelayId(allocator, at_c[0].owned.msg)) {
        .verified => |id| id,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(origin_id, at_c_id);
}

test "secure relay v2 forged input cannot poison dedup and queue bound fails closed" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0x76);
    const kp_b = try signingKeyFor(0x77);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.secure_relay_transport_enabled = true;
    b.secure_relay_transport_enabled = true;
    b.config.max_relay_v2_frames = 1;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6300);

    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    const valid = try stampedRelayV2(allocator, &a.signing_key.?, "#room", .channel, 102, &pubkey, &signature);
    const valid_wire = try message_relay_v2.encode(allocator, valid);
    defer allocator.free(valid_wire);
    // Once signing was negotiated, a raw MESSAGE_V2 payload is a bad outer
    // envelope and must be visible in both generic and relay-specific telemetry.
    try emitFrame(allocator, a_to_b.sink(), .MESSAGE_V2, valid_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6301);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedRelayV2Frames());
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());

    var forged = valid;
    forged.text = "tampered";
    const forged_wire = try message_relay_v2.encode(allocator, forged);
    defer allocator.free(forged_wire);
    try a.emitSignable(a_to_b.sink(), .MESSAGE_V2, forged_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6302);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedRelayV2Frames());

    // The valid object with the same claimed origin/HLC is still admitted.
    try a.sendMessageV2(a_to_b.sink(), valid);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6303);

    var pubkey2: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature2: [message_relay_v2.sig_len]u8 = undefined;
    const second = try stampedRelayV2(allocator, &a.signing_key.?, "#room", .channel, 103, &pubkey2, &signature2);
    try a.sendMessageV2(a_to_b.sink(), second);
    try std.testing.expectError(
        error.RelayV2Backpressure,
        pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6304),
    );
    // A real feed closes on backpressure. Model that transport boundary before
    // the retained sender replays on a fresh connection.
    a_to_b.clear();
    try std.testing.expectEqual(@as(u64, 1), b.takeDroppedRelayV2Frames());
    const inbound = try b.takeInboundV2();
    defer allocator.free(inbound);
    defer {
        for (inbound) |*item| item.deinit(allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), inbound.len);
    try std.testing.expectEqual(@as(u64, 102), inbound[0].owned.msg.hlc);

    // Queue rejection is not a dedup decision. Once capacity is drained, the
    // exact event that was dropped above must be accepted on retransmission.
    try a.sendMessageV2(a_to_b.sink(), second);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6305);
    const retried = try b.takeInboundV2();
    defer {
        for (retried) |*item| item.deinit(allocator);
        allocator.free(retried);
    }
    try std.testing.expectEqual(@as(usize, 1), retried.len);
    try std.testing.expectEqual(@as(u64, 103), retried[0].owned.msg.hlc);
    try std.testing.expectEqual(@as(u64, 0), b.takeDroppedRelayV2Frames());
}

test "secure relay v2 keyed plaintext and rolling-old peers stay inert" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var state = ChannelCrdt.init(allocator, 1);
    defer state.deinit();
    const kp_local = try signingKeyFor(0x78);
    var kp_remote = try signingKeyFor(0x79);
    defer kp_remote.deinit();
    const remote_short = signed_frame.originShortId(kp_remote.public_key);
    var peer = try newSigningPeer(allocator, &state, &tc, kp_local, remote_short, 1000, "local.test");
    defer peer.deinit();
    peer.established = true;
    peer.peer_supports_signing = true;
    peer.peer_supports_secure_relay_v2 = true;
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    const msg = try stampedRelayV2(allocator, &peer.signing_key.?, "#room", .channel, 104, &pubkey, &signature);
    var sink = BufferSink{};
    defer sink.deinit(allocator);
    try std.testing.expectError(error.SecuredLinkRequired, peer.sendMessageV2(sink.sink(), msg));

    peer.secure_relay_transport_enabled = true;
    peer.peer_supports_secure_relay_v2 = false;
    try std.testing.expectError(error.CapabilityNotNegotiated, peer.sendMessageV2(sink.sink(), msg));
    try std.testing.expectEqual(@as(usize, 0), sink.bytes.items.len);
}

test "event spine v2 preserves exact wire through non-clique A B C and never reflects" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_ab_state = ChannelCrdt.init(allocator, 2);
    defer b_ab_state.deinit();
    var b_bc_state = ChannelCrdt.init(allocator, 3);
    defer b_bc_state.deinit();
    var c_state = ChannelCrdt.init(allocator, 4);
    defer c_state.deinit();

    const kp_a = try signingKeyFor(0x81);
    const kp_b_ab = try signingKeyFor(0x82);
    const kp_b_bc = try signingKeyFor(0x82);
    const kp_c = try signingKeyFor(0x83);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b_ab.public_key);
    const c_node = signed_frame.originShortId(kp_c.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b_from_a = try newSigningPeer(allocator, &b_ab_state, &tc, kp_b_ab, a_short, 2000, "b.test");
    defer b_from_a.deinit();
    var b_to_c = try newSigningPeer(allocator, &b_bc_state, &tc, kp_b_bc, c_node, 2000, "b.test");
    defer b_to_c.deinit();
    var c = try newSigningPeer(allocator, &c_state, &tc, kp_c, b_short, 3000, "c.test");
    defer c.deinit();
    a.event_spine_v2_transport_enabled = true;
    b_from_a.event_spine_v2_transport_enabled = true;
    b_to_c.event_spine_v2_transport_enabled = true;
    c.event_spine_v2_transport_enabled = true;

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b_from_a.startHandshake(b_to_a.sink());
    try pump(&a, &b_from_a, &a_to_b, &b_to_a, tc.now_ms, 0x7100);
    var b_to_c_wire = BufferSink{};
    defer b_to_c_wire.deinit(allocator);
    var c_to_b_wire = BufferSink{};
    defer c_to_b_wire.deinit(allocator);
    try b_to_c.startHandshake(b_to_c_wire.sink());
    try c.startHandshake(c_to_b_wire.sink());
    try pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x7101);
    try std.testing.expect(a.supportsEventSpineV2());
    try std.testing.expect(b_from_a.supportsEventSpineV2());
    try std.testing.expect(b_to_c.supportsEventSpineV2());
    try std.testing.expect(c.supportsEventSpineV2());

    try std.testing.expect(try a.sendOperEventV2Authored(
        a_to_b.sink(),
        13,
        2,
        0x100_000,
        "a.test",
        "#mesh",
        "raid threshold crossed in #mesh",
    ));
    try pump(&a, &b_from_a, &a_to_b, &b_to_a, tc.now_ms, 0x7102);
    const at_b = try b_from_a.takeOperEventsV2();
    defer {
        for (at_b) |*item| item.deinit(allocator);
        allocator.free(at_b);
    }
    try std.testing.expectEqual(@as(usize, 1), at_b.len);
    try std.testing.expectEqual(a_short, at_b[0].via_peer);

    // The ingress cache suppresses a reflection onto the same A-B leg without
    // writing even an outer frame.
    try std.testing.expect(!(try b_from_a.forwardOperEventV2(b_to_a.sink(), at_b[0].wire)));
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);

    // B has a separate B-C leg and forwards the exact immutable inner bytes.
    try std.testing.expect(try b_to_c.forwardOperEventV2(b_to_c_wire.sink(), at_b[0].wire));
    try pump(&b_to_c, &c, &b_to_c_wire, &c_to_b_wire, tc.now_ms, 0x7103);
    const at_c = try c.takeOperEventsV2();
    defer {
        for (at_c) |*item| item.deinit(allocator);
        allocator.free(at_c);
    }
    try std.testing.expectEqual(@as(usize, 1), at_c.len);
    try std.testing.expectEqual(b_short, at_c[0].via_peer);
    try std.testing.expectEqualSlices(u8, at_b[0].wire, at_c[0].wire);
    const decoded = try oper_event.decodeV2(at_c[0].wire);
    try std.testing.expectEqual(a_short, decoded.origin_node);
    try std.testing.expectEqualStrings("#mesh", decoded.subject);
    try std.testing.expectEqual(oper_event.VerifyOutcome.verified, oper_event.verifyOrigin(decoded));

    // Legacy v1 is accepted for local compatibility delivery, but it cannot be
    // fed to the v2 forwarder and never appears in the v2 queue on C.
    try a.sendLegacyOperEvent(a_to_b.sink(), 3, 1, "a.test", "legacy leaf only");
    try pump(&a, &b_from_a, &a_to_b, &b_to_a, tc.now_ms, 0x7104);
    const legacy = try b_from_a.takeOperEvents();
    defer {
        for (legacy) |wire| allocator.free(wire);
        allocator.free(legacy);
    }
    try std.testing.expectEqual(@as(usize, 1), legacy.len);
    try std.testing.expectError(error.InvalidOperEvent, b_to_c.forwardOperEventV2(b_to_c_wire.sink(), legacy[0]));
    try std.testing.expectEqual(@as(usize, 0), b_to_c_wire.bytes.items.len);
}

test "event spine v2 tamper and unnegotiated traffic cannot poison reflection state" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0x84);
    const kp_b = try signingKeyFor(0x85);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.event_spine_v2_transport_enabled = true;
    b.event_spine_v2_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7200);

    var pubkey: [oper_event.pubkey_len]u8 = undefined;
    var signature: [oper_event.sig_len]u8 = undefined;
    const valid = try stampedOperEventV2(&a.signing_key.?, 0x200_000, &pubkey, &signature);
    const verified = switch (oper_event.verifyAndEventId(valid)) {
        .verified => |value| value,
        else => return error.TestUnexpectedResult,
    };
    var valid_buf: [oper_event.max_v2_encoded_len]u8 = undefined;
    const valid_wire = try oper_event.encodeV2(valid, &valid_buf);
    var tampered_buf: [oper_event.max_v2_encoded_len]u8 = undefined;
    @memcpy(tampered_buf[0..valid_wire.len], valid_wire);
    tampered_buf[valid_wire.len - 1] ^= 1;
    try a.emitSignable(a_to_b.sink(), .OPER_EVENT_V2, tampered_buf[0..valid_wire.len]);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7201);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOperEventV2Frames());
    try std.testing.expect(!b.seen_oper_event_v2.contains(verified.event_id));
    const rejected = try b.takeOperEventsV2();
    defer allocator.free(rejected);
    try std.testing.expectEqual(@as(usize, 0), rejected.len);

    // The later valid object with the same author/HLC remains admissible.
    try std.testing.expect(try a.sendOperEventV2(a_to_b.sink(), valid));
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7202);
    const accepted = try b.takeOperEventsV2();
    defer {
        for (accepted) |*item| item.deinit(allocator);
        allocator.free(accepted);
    }
    try std.testing.expectEqual(@as(usize, 1), accepted.len);

    // Simulate a recoverable daemon rejection after drain. An identical
    // same-leg retry is queued again, while outbound reflection on that leg is
    // still suppressed without writing a frame.
    try a.emitSignable(a_to_b.sink(), .OPER_EVENT_V2, valid_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7203);
    const retried = try b.takeOperEventsV2();
    defer {
        for (retried) |*item| item.deinit(allocator);
        allocator.free(retried);
    }
    try std.testing.expectEqual(@as(usize, 1), retried.len);
    try std.testing.expectEqualSlices(u8, valid_wire, retried[0].wire);
    try std.testing.expect(!(try b.forwardOperEventV2(b_to_a.sink(), retried[0].wire)));
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);

    // A rolling-old peer neither negotiates nor mutates its reflection cache.
    b.peer_supports_event_spine_v2 = false;
    b.seen_oper_event_v2.deinit();
    b.seen_oper_event_v2 = message_relay_v2.SeenSet.init(allocator, b.config.oper_event_v2_seen_capacity);
    try a.emitSignable(a_to_b.sink(), .OPER_EVENT_V2, valid_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7204);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOperEventV2Frames());
    try std.testing.expect(!b.seen_oper_event_v2.contains(verified.event_id));
}

test "event spine v2 resume header preserves negotiated capability" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0x86);
    const kp_b = try signingKeyFor(0x87);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.event_spine_v2_transport_enabled = true;
    b.event_spine_v2_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7300);

    const hdr = a.snapshotResume();
    try std.testing.expect(hdr.peer_supports_event_spine_v2);
    var resumed_state = ChannelCrdt.init(allocator, 1);
    defer resumed_state.deinit();
    var resumed = try S2sPeer.resumeEstablished(.{
        .allocator = allocator,
        .state = &resumed_state,
        .clock = tc.clock(),
        .local_node_id = a_short,
        .remote_node_id = b_short,
        .local_epoch_ms = 3000,
        .server_name = "a.test",
        .description = "test",
        .config = a.config,
        .signing_key = try signingKeyFor(0x86),
        .event_spine_v2_transport_enabled = true,
    }, hdr, a.remoteName(), tc.now_ms + 1, 0x7301);
    defer resumed.deinit();
    try std.testing.expect(resumed.supportsEventSpineV2());
}

fn fakeSessionReplicaObject(allocator: Allocator, kind: session_replica_frame.Kind) ![]u8 {
    const offer_fixed_len: usize = 69;
    const inner_signature_len: usize = 96;
    const account_len_offset: usize = 61;
    return switch (kind) {
        .offer, .revoke => blk: {
            const upsert = kind == .offer;
            const variable_len: usize = if (upsert) 3 else 0;
            const out = try allocator.alloc(u8, offer_fixed_len + variable_len + inner_signature_len);
            @memset(out, 0);
            @memcpy(out[0..4], "SRO2");
            out[4] = if (upsert) 1 else 2;
            if (upsert) {
                std.mem.writeInt(u16, out[account_len_offset..][0..2], 1, .big);
                std.mem.writeInt(u16, out[account_len_offset + 2 ..][0..2], 1, .big);
                std.mem.writeInt(u32, out[account_len_offset + 4 ..][0..4], 1, .big);
                @memcpy(out[offer_fixed_len .. offer_fixed_len + variable_len], "ans");
            }
            break :blk out;
        },
        .ack => blk: {
            const out = try allocator.alloc(u8, 189);
            @memset(out, 0);
            @memcpy(out[0..4], "SRA2");
            out[4] = 1;
            break :blk out;
        },
        .attachment_lease => blk: {
            const out = try allocator.alloc(u8, 156);
            @memset(out, 0);
            @memcpy(out[0..4], "SRL2");
            break :blk out;
        },
    };
}

fn fakeAttachmentSessionReplicaObject(
    allocator: Allocator,
    kind: session_replica_frame.Kind,
) ![]u8 {
    const signature_len: usize = 96;
    const identity_len: usize = 32;
    const revision_len: usize = 24;
    return switch (kind) {
        .offer => blk: {
            const fixed_len: usize = 4 + identity_len + revision_len + 8 + 8 + 2 + 2 + 4;
            const account_len_offset: usize = 4 + identity_len + revision_len + 8 + 8;
            const variable = "ans";
            const out = try allocator.alloc(u8, fixed_len + variable.len + signature_len);
            @memset(out, 0);
            @memcpy(out[0..4], "SRO3");
            out[4] = 1;
            out[20] = 2;
            std.mem.writeInt(u16, out[account_len_offset..][0..2], 1, .big);
            std.mem.writeInt(u16, out[account_len_offset + 2 ..][0..2], 1, .big);
            std.mem.writeInt(u32, out[account_len_offset + 4 ..][0..4], 1, .big);
            @memcpy(out[fixed_len .. fixed_len + variable.len], variable);
            break :blk out;
        },
        .revoke => blk: {
            const account = "a";
            const identity_offset = 4 + 1 + account.len;
            const tail_len = identity_len + revision_len + 8 + 8 + signature_len;
            const out = try allocator.alloc(u8, identity_offset + tail_len);
            @memset(out, 0);
            @memcpy(out[0..4], "SRV3");
            out[4] = @intCast(account.len);
            @memcpy(out[5 .. 5 + account.len], account);
            out[identity_offset] = 1;
            out[identity_offset + 16] = 2;
            break :blk out;
        },
        .ack => blk: {
            const out = try allocator.alloc(u8, 4 + 1 + identity_len + revision_len * 2 + 8 + 8 + 8 + signature_len);
            @memset(out, 0);
            @memcpy(out[0..4], "SRA3");
            out[4] = 1;
            out[5] = 1;
            out[21] = 2;
            break :blk out;
        },
        .attachment_lease => blk: {
            const out = try allocator.alloc(u8, 4 + identity_len + revision_len + 8 + 8 + signature_len);
            @memset(out, 0);
            @memcpy(out[0..4], "SRL3");
            out[4] = 1;
            out[20] = 2;
            break :blk out;
        },
    };
}

test "session replica v3 negotiates one strict attachment schema per secured link" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0xa1);
    const kp_b = try signingKeyFor(0xa2);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    a.session_replica_attachment_transport_enabled = true;
    b.session_replica_attachment_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5250);
    try std.testing.expect(a.supportsSessionReplicaV3());
    try std.testing.expect(b.supportsSessionReplicaV3());

    const kinds = [_]session_replica_frame.Kind{ .offer, .ack, .revoke, .attachment_lease };
    var objects: [kinds.len][]u8 = undefined;
    var initialized: usize = 0;
    defer for (objects[0..initialized]) |object| allocator.free(object);
    for (kinds, 0..) |kind, index| {
        objects[index] = try fakeAttachmentSessionReplicaObject(allocator, kind);
        initialized += 1;
        try a.sendAttachmentSessionReplica(a_to_b.sink(), kind, objects[index]);
    }
    // Version choice is link-wide: a negotiated-v3 sender must not put a v2
    // object on the same outer frame tags.
    const v2_offer = try fakeSessionReplicaObject(allocator, .offer);
    defer allocator.free(v2_offer);
    try std.testing.expectError(error.CapabilityVersionMismatch, a.sendSessionReplicaOffer(a_to_b.sink(), v2_offer));

    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5251);
    const frames = try b.takeSessionReplicaFrames();
    defer {
        for (frames) |*frame| frame.deinit(allocator);
        allocator.free(frames);
    }
    try std.testing.expectEqual(kinds.len, frames.len);
    for (frames, kinds, objects) |frame, kind, object| {
        try std.testing.expectEqual(session_replica_frame.WireVersion.attachment_v3, frame.version);
        try std.testing.expectEqual(kind, frame.kind);
        try std.testing.expectEqualSlices(u8, object, frame.signed_payload);
    }

    // A malicious or stale same-link v2 object is rejected at the version gate;
    // the receiver never tries a second decoder or faults the established link.
    const v2_transport = try allocator.alloc(u8, try session_replica_frame.encodedLen(v2_offer.len));
    defer allocator.free(v2_transport);
    const v2_wire = try session_replica_frame.encode(.offer, v2_offer, v2_transport);
    try a.emitSignable(a_to_b.sink(), .SESSION_REPLICA_OFFER, v2_wire);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5252);
    try std.testing.expectEqual(@as(u64, 1), b.takeRejectedOriginFrames());
    try std.testing.expectEqual(peer_link.State.established, b.linkState());
    const rejected = try b.takeSessionReplicaFrames();
    defer allocator.free(rejected);
    try std.testing.expectEqual(@as(usize, 0), rejected.len);

    // A preserved link retains its exact negotiated schema; a successor cannot
    // silently reset to v2 and reinterpret the next queued frame.
    const hdr = a.snapshotResume();
    try std.testing.expect(hdr.peer_supports_session_replica_v3);
    var resumed_state = ChannelCrdt.init(allocator, 1);
    defer resumed_state.deinit();
    var resumed = try S2sPeer.resumeEstablished(.{
        .allocator = allocator,
        .state = &resumed_state,
        .clock = tc.clock(),
        .local_node_id = a_short,
        .remote_node_id = b_short,
        .local_epoch_ms = 3000,
        .server_name = "a.test",
        .description = "test",
        .config = a.config,
        .signing_key = try signingKeyFor(0xa1),
        .session_replica_transport_enabled = true,
        .session_replica_attachment_transport_enabled = true,
    }, hdr, a.remoteName(), tc.now_ms + 1, 0x5253);
    defer resumed.deinit();
    try std.testing.expect(resumed.supportsSessionReplicaV3());
}

test "session replica v3 probe leaves a rolling v2 peer on v2" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0xa3);
    const kp_b = try signingKeyFor(0xa4);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    a.session_replica_attachment_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5260);
    try std.testing.expect(a.supportsSessionReplicaV2());
    try std.testing.expect(b.supportsSessionReplicaV2());
    try std.testing.expect(!a.supportsSessionReplicaV3());
    try std.testing.expect(!b.supportsSessionReplicaV3());

    const offer = try fakeSessionReplicaObject(allocator, .offer);
    defer allocator.free(offer);
    try a.sendSessionReplicaOffer(a_to_b.sink(), offer);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5261);
    const frames = try b.takeSessionReplicaFrames();
    defer {
        for (frames) |*frame| frame.deinit(allocator);
        allocator.free(frames);
    }
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expectEqual(session_replica_frame.WireVersion.token_v2, frames[0].version);
}

test "session replica v2 inner peer transports offers acks revokes and attachment leases" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x91);
    const kp_b = try signingKeyFor(0x92);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    // Model the private assertion SecuredLink sets only after its Mooring AKE.
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5210);
    try std.testing.expect(a.supportsSessionReplicaV2());
    try std.testing.expect(b.supportsSessionReplicaV2());
    try std.testing.expect(a.supportsSessionAttachmentLeaseV2());
    try std.testing.expect(b.supportsSessionAttachmentLeaseV2());

    const offer = try fakeSessionReplicaObject(allocator, .offer);
    defer allocator.free(offer);
    const ack = try fakeSessionReplicaObject(allocator, .ack);
    defer allocator.free(ack);
    const revoke = try fakeSessionReplicaObject(allocator, .revoke);
    defer allocator.free(revoke);
    const lease = try fakeSessionReplicaObject(allocator, .attachment_lease);
    defer allocator.free(lease);
    try a.sendSessionReplicaOffer(a_to_b.sink(), offer);
    try a.sendSessionReplicaAck(a_to_b.sink(), ack);
    try a.sendSessionReplicaRevoke(a_to_b.sink(), revoke);
    try a.sendSessionAttachmentLease(a_to_b.sink(), lease);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5211);

    const frames = try b.takeSessionReplicaFrames();
    defer {
        for (frames) |*frame| frame.deinit(allocator);
        allocator.free(frames);
    }
    try std.testing.expectEqual(@as(usize, 4), frames.len);
    const expected = [_]session_replica_frame.Kind{ .offer, .ack, .revoke, .attachment_lease };
    const payloads = [_][]const u8{ offer, ack, revoke, lease };
    for (frames, 0..) |frame, i| {
        try std.testing.expectEqual(session_replica_frame.WireVersion.token_v2, frame.version);
        try std.testing.expectEqual(expected[i], frame.kind);
        try std.testing.expectEqual(a_short, frame.via_peer);
        try std.testing.expectEqualSlices(u8, payloads[i], frame.signed_payload);
    }

    // A tighter deployment frame limit is also honored on egress; no oversized
    // frame is allocated/emitted merely because it fits the protocol default.
    a.config.max_frame_size = 128;
    try std.testing.expectError(error.PayloadTooLarge, a.sendSessionReplicaAck(a_to_b.sink(), ack));
    try std.testing.expectEqual(@as(usize, 0), a_to_b.bytes.items.len);
}

test "session replica v2 rolling old and plaintext peers stay inert" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var state = ChannelCrdt.init(allocator, 1);
    defer state.deinit();
    const kp_local = try signingKeyFor(0x93);
    var kp_remote = try signingKeyFor(0x94);
    defer kp_remote.deinit();
    const remote_short = signed_frame.originShortId(kp_remote.public_key);
    var peer = try newSigningPeer(allocator, &state, &tc, kp_local, remote_short, 1000, "new.test");
    defer peer.deinit();
    peer.session_replica_transport_enabled = true;
    var wire = BufferSink{};
    defer wire.deinit(allocator);

    // A signing-capable rolling-old peer advertises frame signing but no v2 bit.
    const old_hs = try encodeHandshake(allocator, .{
        .node_id = remote_short,
        .epoch_ms = 2000,
        .name = "old.test",
        .description = "old",
        .caps = cap_frame_signing,
    });
    defer allocator.free(old_hs);
    try emitFrame(allocator, wire.sink(), .HANDSHAKE, old_hs);
    var response = BufferSink{};
    defer response.deinit(allocator);
    try peer.feed(wire.bytes.items, response.sink(), tc.now_ms, 1);
    try std.testing.expect(peer.established);
    try std.testing.expect(peer.peer_supports_signing);
    try std.testing.expect(!peer.supportsSessionReplicaV2());
    const offer = try fakeSessionReplicaObject(allocator, .offer);
    defer allocator.free(offer);
    try std.testing.expectError(error.CapabilityNotNegotiated, peer.sendSessionReplicaOffer(response.sink(), offer));

    // A rolling peer with base SESSION_REPLICA v2 but without the separately
    // negotiated lease extension keeps ordinary objects active and leases inert.
    peer.peer_supports_session_replica_v2 = true;
    const lease = try fakeSessionReplicaObject(allocator, .attachment_lease);
    defer allocator.free(lease);
    try std.testing.expect(peer.supportsSessionReplicaV2());
    try std.testing.expect(!peer.supportsSessionAttachmentLeaseV2());
    try std.testing.expectError(error.CapabilityNotNegotiated, peer.sendSessionAttachmentLease(response.sink(), lease));

    // A plaintext driver cannot activate v2 even if a hostile handshake sets its
    // capability bit. No compatibility fallback emits the sensitive object.
    var plain_state = ChannelCrdt.init(allocator, 2);
    defer plain_state.deinit();
    var plain = try newPeer(allocator, &plain_state, &tc, 2, 3, 1000, "plain.test");
    defer plain.deinit();
    plain.established = true;
    plain.peer_supports_session_replica_v2 = true;
    try std.testing.expect(!plain.supportsSessionReplicaV2());
    try std.testing.expectError(error.SecuredLinkRequired, plain.sendSessionReplicaOffer(response.sink(), offer));
}

test "session replica v2 hot resume preserves negotiated capability" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const kp_a = try signingKeyFor(0x97);
    const kp_b = try signingKeyFor(0x98);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5230);
    try std.testing.expect(a.supportsSessionReplicaV2());
    try std.testing.expect(a.supportsSessionAttachmentLeaseV2());

    // The peer does not re-handshake on a preserved socket, so its negotiated
    // capability must ride the resume header exactly like frame-signing/repair.
    const hdr = a.snapshotResume();
    var resumed_state = ChannelCrdt.init(allocator, 1);
    defer resumed_state.deinit();
    const resumed_key = try signingKeyFor(0x97);
    var resumed = try S2sPeer.resumeEstablished(.{
        .allocator = allocator,
        .state = &resumed_state,
        .clock = tc.clock(),
        .local_node_id = a_short,
        .remote_node_id = b_short,
        .local_epoch_ms = 3000,
        .server_name = "a.test",
        .description = "test",
        .config = a.config,
        .signing_key = resumed_key,
        .session_replica_transport_enabled = true,
    }, hdr, a.remoteName(), tc.now_ms + 1, 0x5231);
    defer resumed.deinit();
    try std.testing.expect(resumed.supportsSessionReplicaV2());
    try std.testing.expect(resumed.supportsSessionAttachmentLeaseV2());
    const offer = try fakeSessionReplicaObject(allocator, .offer);
    defer allocator.free(offer);
    try resumed.sendSessionReplicaOffer(a_to_b.sink(), offer);
    try std.testing.expect(a_to_b.bytes.items.len != 0);
}

test "session attachment lease capability refreshes across staggered preserved upgrades" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var old_a_state = ChannelCrdt.init(allocator, 1);
    defer old_a_state.deinit();
    var old_b_state = ChannelCrdt.init(allocator, 2);
    defer old_b_state.deinit();
    const kp_a = try signingKeyFor(0x99);
    const kp_b = try signingKeyFor(0x9a);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var old_a = try newSigningPeer(allocator, &old_a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer old_a.deinit();
    var old_b = try newSigningPeer(allocator, &old_b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer old_b.deinit();
    old_a.session_replica_transport_enabled = true;
    old_b.session_replica_transport_enabled = true;

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try old_a.startHandshake(a_to_b.sink());
    try old_b.startHandshake(b_to_a.sink());
    try pump(&old_a, &old_b, &a_to_b, &b_to_a, tc.now_ms, 0x5240);

    // Model a link negotiated by the pre-extension binaries: base replica v2
    // survived in the resume header, but neither endpoint recorded the later
    // attachment-lease bit.
    var a_hdr = old_a.snapshotResume();
    var b_hdr = old_b.snapshotResume();
    a_hdr.peer_supports_session_attachment_lease_v2 = false;
    b_hdr.peer_supports_session_attachment_lease_v2 = false;

    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    const resumed_a_key = try signingKeyFor(0x99);
    var a = try S2sPeer.resumeEstablished(.{
        .allocator = allocator,
        .state = &a_state,
        .clock = tc.clock(),
        .local_node_id = a_short,
        .remote_node_id = b_short,
        .local_epoch_ms = 3000,
        .server_name = "a.test",
        .description = "test",
        .config = old_a.config,
        .signing_key = resumed_a_key,
        .session_replica_transport_enabled = true,
    }, a_hdr, old_a.remoteName(), tc.now_ms + 1, 0x5241);
    defer a.deinit();
    try std.testing.expect(a.supportsSessionReplicaV2());
    try std.testing.expect(!a.supportsSessionAttachmentLeaseV2());

    // A upgrades first and writes HANDSHAKE+RESYNC to the still-old endpoint.
    // The old process consumes those frames without retaining the unknown bit;
    // its later resume header therefore remains the captured false value.
    try a.sendResync(a_to_b.sink());
    try std.testing.expect(a_to_b.bytes.items.len != 0);
    a_to_b.clear();
    try std.testing.expect(!a.supportsSessionAttachmentLeaseV2());

    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    const resumed_b_key = try signingKeyFor(0x9a);
    var b = try S2sPeer.resumeEstablished(.{
        .allocator = allocator,
        .state = &b_state,
        .clock = tc.clock(),
        .local_node_id = b_short,
        .remote_node_id = a_short,
        .local_epoch_ms = 4000,
        .server_name = "b.test",
        .description = "test",
        .config = old_b.config,
        .signing_key = resumed_b_key,
        .session_replica_transport_enabled = true,
    }, b_hdr, old_b.remoteName(), tc.now_ms + 2, 0x5242);
    defer b.deinit();
    try std.testing.expect(b.supportsSessionReplicaV2());
    try std.testing.expect(!b.supportsSessionAttachmentLeaseV2());

    // When B upgrades later, its fresh HANDSHAKE updates A. The RESYNC response
    // carries A's fresh HANDSHAKE back exactly once, updating B without an echo.
    try b.sendResync(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms + 2, 0x5243);
    try std.testing.expect(a.supportsSessionAttachmentLeaseV2());
    try std.testing.expect(b.supportsSessionAttachmentLeaseV2());
    try std.testing.expectEqual(@as(usize, 0), a_to_b.bytes.items.len);
    try std.testing.expectEqual(@as(usize, 0), b_to_a.bytes.items.len);

    const lease = try fakeSessionReplicaObject(allocator, .attachment_lease);
    defer allocator.free(lease);
    try a.sendSessionAttachmentLease(a_to_b.sink(), lease);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms + 3, 0x5244);
    const frames = try b.takeSessionReplicaFrames();
    defer {
        for (frames) |*frame| frame.deinit(allocator);
        allocator.free(frames);
    }
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expectEqual(session_replica_frame.Kind.attachment_lease, frames[0].kind);
    try std.testing.expectEqualSlices(u8, lease, frames[0].signed_payload);
}

test "session replica v2 malformed cross-tag and bounded queue input fail closed" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x95);
    const kp_b = try signingKeyFor(0x96);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    b.config.max_session_replica_frames = 1;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5220);

    const offer = try fakeSessionReplicaObject(allocator, .offer);
    defer allocator.free(offer);
    const ack = try fakeSessionReplicaObject(allocator, .ack);
    defer allocator.free(ack);
    try a.sendSessionReplicaOffer(a_to_b.sink(), offer);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5221);
    try a.sendSessionReplicaAck(a_to_b.sink(), ack);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5222);
    try std.testing.expectEqual(@as(u64, 1), b.takeDroppedSessionReplicaFrames());

    // Valid outer authentication cannot rescue a malformed inner transport.
    try a.emitSignable(a_to_b.sink(), .SESSION_REPLICA_OFFER, "malformed");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5223);

    // Nor may an OFFER transport be reclassified under the ACK frame tag.
    const transport_len = try session_replica_frame.encodedLen(offer.len);
    const transport = try allocator.alloc(u8, transport_len);
    defer allocator.free(transport);
    const encoded = try session_replica_frame.encode(.offer, offer, transport);
    try a.emitSignable(a_to_b.sink(), .SESSION_REPLICA_ACK, encoded);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x5224);
    try std.testing.expectEqual(@as(u64, 2), b.takeRejectedOriginFrames());
    try std.testing.expectEqual(peer_link.State.established, b.linkState());

    const frames = try b.takeSessionReplicaFrames();
    defer {
        for (frames) |*frame| frame.deinit(allocator);
        allocator.free(frames);
    }
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expectEqual(session_replica_frame.Kind.offer, frames[0].kind);
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

/// Test residence verifier that trusts a fixed (account, origin) pair for any
/// nick — stands
/// in for the daemon's real receiver-owned proof lookup so the account-aware
/// collision tests can exercise the TRUSTED path (Design C). With NO verifier
/// installed, `accountResidenceDecision` returns untrusted and every same-account
/// short-circuit falls to the conservative UID path (the F1 fail-closed default).
const TrustVerifierStub = struct {
    account: []const u8,
    origin_node: NodeId,
    fn verify(ctx: *anyopaque, account: []const u8, _: []const u8, origin_node: NodeId, _: bool) ResidenceDecision {
        const self: *TrustVerifierStub = @ptrCast(@alignCast(ctx));
        return if (origin_node == self.origin_node and std.mem.eql(u8, account, self.account)) .trusted else .untrusted;
    }
    fn verifier(self: *TrustVerifierStub) ResidenceVerifier {
        return .{ .ctx = self, .verify_fn = verify };
    }
};

const MutableTrustVerifierStub = struct {
    account: []const u8,
    origin_node: NodeId,
    trusted: bool = false,
    fn verify(ctx: *anyopaque, account: []const u8, _: []const u8, origin_node: NodeId, _: bool) ResidenceDecision {
        const self: *MutableTrustVerifierStub = @ptrCast(@alignCast(ctx));
        return if (self.trusted and origin_node == self.origin_node and std.mem.eql(u8, account, self.account))
            .trusted
        else
            .untrusted;
    }
    fn verifier(self: *MutableTrustVerifierStub) ResidenceVerifier {
        return .{ .ctx = self, .verify_fn = verify };
    }
};

const RejectVerifierStub = struct {
    fn verify(_: *anyopaque, _: []const u8, _: []const u8, _: NodeId, _: bool) ResidenceDecision {
        return .reject;
    }
    fn verifier(self: *RejectVerifierStub) ResidenceVerifier {
        return .{ .ctx = self, .verify_fn = verify };
    }
};

const SessionTokenResolverStub = struct {
    origin_node: NodeId,
    token: SessionToken,
    calls: usize = 0,
    present_calls: usize = 0,
    part_calls: usize = 0,

    fn resolve(
        ctx: *anyopaque,
        origin_node: NodeId,
        _: []const u8,
        channel: []const u8,
        present: bool,
    ) SessionTokenDecision {
        const self: *SessionTokenResolverStub = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (present) self.present_calls += 1 else self.part_calls += 1;
        if (origin_node != self.origin_node) return .reject;
        if (std.ascii.eqlIgnoreCase(channel, "#reject")) return .reject;
        if (std.ascii.eqlIgnoreCase(channel, "#bind")) return .{ .bind = self.token };
        return .unbound;
    }

    fn resolver(self: *SessionTokenResolverStub) SessionTokenResolver {
        return .{ .ctx = self, .resolve_fn = resolve };
    }
};

const SessionTokenNickAuthorizerStub = struct {
    const Authority = enum { none, single, ambiguous };

    origin_node: NodeId,
    token: SessionToken,
    best_nick: []const u8,
    authority: Authority = .single,
    calls: usize = 0,

    fn authorize(
        ctx: *anyopaque,
        origin_node: NodeId,
        _: []const u8,
        tagged_token: ?SessionToken,
        new_nick: []const u8,
    ) SessionTokenNickDecision {
        const self: *SessionTokenNickAuthorizerStub = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (origin_node != self.origin_node) return .reject;
        return switch (self.authority) {
            .none => if (tagged_token == null) .legacy else .reject,
            .ambiguous => .reject,
            .single => if ((tagged_token == null or std.crypto.timing_safe.eql(SessionToken, self.token, tagged_token.?)) and
                std.ascii.eqlIgnoreCase(self.best_nick, new_nick))
                .{ .bind = self.token }
            else
                .reject,
        };
    }

    fn authorizer(self: *SessionTokenNickAuthorizerStub) SessionTokenNickAuthorizer {
        return .{ .ctx = self, .authorize_fn = authorize };
    }
};

test "session token resolver rejects or binds channel-aware membership before route mutation" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x6B);
    const kp_b = try signingKeyFor(0x6C);
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
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6B0);

    var token: SessionToken = @splat(0x8D);
    token[15] = 0xE1;
    var resolver = SessionTokenResolverStub{ .origin_node = a_short, .token = token };
    b.setSessionTokenResolver(resolver.resolver());

    try a.sendMembership(a_to_b.sink(), "#reject", "reject-me", 0, 100, true, .{}, "");
    try a.sendMembership(a_to_b.sink(), "#bind", "bound", 0, 101, true, .{}, "");
    try a.sendMembership(a_to_b.sink(), "#plain", "legacy", 0, 102, true, .{}, "");
    try a.sendMembership(a_to_b.sink(), "#plain", "legacy", 0, 103, false, .{}, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6B1);

    try std.testing.expectEqual(@as(usize, 4), resolver.calls);
    try std.testing.expectEqual(@as(usize, 3), resolver.present_calls);
    try std.testing.expectEqual(@as(usize, 1), resolver.part_calls);
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#reject").len);
    try std.testing.expect(b.routeNickNode("reject-me") == null);
    const bound = b.channelMembers("#bind");
    try std.testing.expectEqual(@as(usize, 1), bound.len);
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, token, bound[0].session_token.?));
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#plain").len);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*change| change.deinit(allocator);
        allocator.free(changes);
    }
    // reject emits nothing; bind joins; unbound compatibility membership joins
    // and parts normally.
    try std.testing.expectEqual(@as(usize, 3), changes.len);
}

test "session token reconcile revoke queues one PART and a later wire PART is unchanged" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x7B);
    const kp_b = try signingKeyFor(0x7C);
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
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7B0);

    const token: SessionToken = @splat(0xB1);
    var resolver = SessionTokenResolverStub{ .origin_node = a_short, .token = token };
    b.setSessionTokenResolver(resolver.resolver());
    var trust = TrustVerifierStub{ .account = "alice", .origin_node = a_short };
    b.setResidenceVerifier(trust.verifier());
    try a.sendMembership(a_to_b.sink(), "#bind", "alice", 0, 100, true, .{
        .username = "user",
        .realname = "Alice Real",
        .host = "alice.test",
        .account = "alice",
    }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7B1);
    const joined = try b.takeMembershipChanges();
    defer allocator.free(joined);
    try std.testing.expectEqual(@as(usize, 1), joined.len);
    for (joined) |*change| change.deinit(allocator);

    const revoked = try b.reconcileSessionToken(token, null, &.{});
    try std.testing.expectEqual(@as(usize, 1), revoked.removed);
    try std.testing.expectEqual(@as(usize, 0), revoked.renamed);
    const revoke_changes = try b.takeMembershipChanges();
    defer allocator.free(revoke_changes);
    try std.testing.expectEqual(@as(usize, 1), revoke_changes.len);
    try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.parted, revoke_changes[0].kind);
    try std.testing.expectEqualStrings("#bind", revoke_changes[0].channel);
    try std.testing.expectEqualStrings("alice", revoke_changes[0].nick);
    try std.testing.expectEqualStrings("user", revoke_changes[0].username);
    try std.testing.expectEqualStrings("Alice Real", revoke_changes[0].realname);
    try std.testing.expectEqualStrings("alice.test", revoke_changes[0].host);
    try std.testing.expectEqualStrings("alice", revoke_changes[0].account);
    for (revoke_changes) |*change| change.deinit(allocator);

    // The authority-first removal consumed the route fact. A deferred wire PART
    // is now an idempotent no-op and cannot enqueue a duplicate client line.
    try a.sendMembership(a_to_b.sink(), "#bind", "alice", 0, 101, false, .{}, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7B2);
    const deferred = try b.takeMembershipChanges();
    defer allocator.free(deferred);
    try std.testing.expectEqual(@as(usize, 0), deferred.len);
}

test "session token reconcile and NICKCHANGE honor Store-selected nick authority" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x7D);
    const kp_b = try signingKeyFor(0x7E);
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
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D0);
    b.session_replica_transport_enabled = true;
    b.peer_supports_signing = true;
    b.peer_supports_session_replica_v2 = true;

    const token: SessionToken = @splat(0xB2);
    var authorizer = SessionTokenNickAuthorizerStub{ .origin_node = a_short, .token = token, .best_nick = "store-new" };
    b.setSessionTokenNickAuthorizer(authorizer.authorizer());
    _ = try b.routes.applyMembership("#bind", "old", a_short, 0, 100, true, .{
        .username = "user",
        .realname = "Old Real",
        .host = "old.test",
        .account = "alice",
        .session_token = token,
    }, @intCast(tc.now_ms));
    const bound_old = b.channelMembers("#bind");
    try std.testing.expectEqual(@as(usize, 1), bound_old.len);
    try std.testing.expect(bound_old[0].session_token != null);

    // OFFER-only authority change: no NICKCHANGE frame is needed. Reconcile
    // queues one owned NICK delta before atomically renaming every token row.
    const desired = [_][]const u8{"#bind"};
    const reconciled = try b.reconcileSessionToken(token, "store-new", &desired);
    try std.testing.expectEqual(@as(usize, 1), reconciled.renamed);
    try std.testing.expectEqual(@as(usize, 0), reconciled.removed);
    try std.testing.expectEqualStrings("store-new", b.channelMembers("#bind")[0].nick);
    const offer_nicks = try b.takeNickChanges();
    defer allocator.free(offer_nicks);
    try std.testing.expectEqual(@as(usize, 1), offer_nicks.len);
    try std.testing.expectEqualStrings("old", offer_nicks[0].old_nick);
    try std.testing.expectEqualStrings("store-new", offer_nicks[0].new_nick);
    for (offer_nicks) |*change| change.deinit(allocator);
    const no_parts = try b.takeMembershipChanges();
    defer allocator.free(no_parts);
    try std.testing.expectEqual(@as(usize, 0), no_parts.len);

    // A stale/malicious peer rename contradicting the Store-selected best nick
    // is rejected before route mutation and emits nothing.
    try a.sendNickChange(a_to_b.sink(), "store-new", "evil", .{ .username = "user", .realname = "Old Real", .host = "old.test", .account = "alice" }, 110);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D2);
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqualStrings("store-new", b.channelMembers("#bind")[0].nick);
    var wire_nicks = try b.takeNickChanges();
    try std.testing.expectEqual(@as(usize, 0), wire_nicks.len);
    allocator.free(wire_nicks);

    // Once Store authority selects the new nick, the same wire transition is
    // authorized and surfaces exactly once.
    authorizer.best_nick = "wire-new";
    try a.sendNickChange(a_to_b.sink(), "store-new", "wire-new", .{ .username = "user", .realname = "New Real", .host = "new.test", .account = "alice" }, 111);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D3);
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqualStrings("wire-new", b.channelMembers("#bind")[0].nick);
    wire_nicks = try b.takeNickChanges();
    try std.testing.expectEqual(@as(usize, 1), wire_nicks.len);
    try std.testing.expectEqualStrings("store-new", wire_nicks[0].old_nick);
    try std.testing.expectEqualStrings("wire-new", wire_nicks[0].new_nick);
    for (wire_nicks) |*change| change.deinit(allocator);
    allocator.free(wire_nicks);
    try std.testing.expectEqual(@as(usize, 2), authorizer.calls);

    // When the authorized destination is held by a lower-priority foreign
    // origin, wire processing publishes the incumbent UID displacement first
    // and the exact winner second, backed by one route-table transaction.
    const collision_token: SessionToken = @splat(0xB7);
    const incumbent_node: NodeId = 0xD00D;
    const incumbent_uid = nick_collision.loserUid(incumbent_node, "collision-target");
    _ = try b.routes.applyMembership("#collision", "collision-old", a_short, 0, 200, true, .{
        .username = "exact-u",
        .session_token = collision_token,
    }, 10);
    _ = try b.routes.applyMembership("#collision", "collision-target", incumbent_node, 0, 100, true, .{
        .username = "inc-u",
    }, 10);
    authorizer.token = collision_token;
    authorizer.best_nick = "collision-target";
    try a.sendNickChange(a_to_b.sink(), "collision-old", "collision-target", .{ .username = "exact-new" }, 201);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D3A);
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expect(b.routes.findMemberOwnedBy("collision-old", a_short) == null);
    const collision_winner = b.routes.findMemberOwnedBy("collision-target", a_short) orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, collision_token, collision_winner.session_token.?));
    try std.testing.expect(b.routes.findMemberOwnedBy(&incumbent_uid, incumbent_node) != null);
    wire_nicks = try b.takeNickChanges();
    try std.testing.expectEqual(@as(usize, 2), wire_nicks.len);
    try std.testing.expectEqualStrings("collision-target", wire_nicks[0].old_nick);
    try std.testing.expectEqualStrings(&incumbent_uid, wire_nicks[0].new_nick);
    try std.testing.expectEqualStrings("collision-old", wire_nicks[1].old_nick);
    try std.testing.expectEqualStrings("collision-target", wire_nicks[1].new_nick);
    for (wire_nicks) |*change| change.deinit(allocator);
    allocator.free(wire_nicks);

    // A Store-selected single authority may authorize an older compatibility
    // row that arrived before token tagging. The callback sees tagged_token=null
    // and returns the retained token from (origin, old nick) itself.
    const single_token: SessionToken = @splat(0xB6);
    _ = try b.routes.applyMembership("#single", "single-old", a_short, 0, 120, true, .{}, 10);
    authorizer.authority = .single;
    authorizer.token = single_token;
    authorizer.best_nick = "single-new";
    try a.sendNickChange(a_to_b.sink(), "single-old", "single-new", .{}, 121);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D4);
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqualStrings("single-new", b.channelMembers("#single")[0].nick);
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, single_token, b.channelMembers("#single")[0].session_token.?));
    wire_nicks = try b.takeNickChanges();
    try std.testing.expectEqual(@as(usize, 1), wire_nicks.len);
    for (wire_nicks) |*change| change.deinit(allocator);
    allocator.free(wire_nicks);

    // Binding is what makes a later authority revoke exact: the renamed legacy
    // row is now removed and surfaces one owned PART instead of becoming a ghost.
    const single_revoked = try b.reconcileSessionToken(single_token, null, &.{});
    try std.testing.expectEqual(@as(usize, 1), single_revoked.removed);
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#single").len);
    const single_parts = try b.takeMembershipChanges();
    defer allocator.free(single_parts);
    try std.testing.expectEqual(@as(usize, 1), single_parts.len);
    try std.testing.expectEqualStrings("#single", single_parts[0].channel);
    try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.parted, single_parts[0].kind);
    for (single_parts) |*change| change.deinit(allocator);
    authorizer.token = token;

    // Two retained tokens for the same origin/old nick are ambiguous. Even an
    // untagged compatibility row must remain unchanged and emit no NICK.
    _ = try b.routes.applyMembership("#ambiguous", "amb-old", a_short, 0, 130, true, .{}, 10);
    authorizer.authority = .ambiguous;
    authorizer.best_nick = "amb-evil";
    try a.sendNickChange(a_to_b.sink(), "amb-old", "amb-evil", .{}, 131);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D5);
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqualStrings("amb-old", b.channelMembers("#ambiguous")[0].nick);
    wire_nicks = try b.takeNickChanges();
    try std.testing.expectEqual(@as(usize, 0), wire_nicks.len);
    allocator.free(wire_nicks);

    // Contradictory receiver tags are fail-closed even if a Store callback
    // would otherwise accept the requested spelling. The callback still runs
    // exactly once, preserving the v2 receiver-authorization invariant.
    const other_token: SessionToken = @splat(0xB4);
    _ = try b.routes.applyMembership("#tag-a", "tag-amb", a_short, 0, 135, true, .{ .session_token = token }, 10);
    _ = try b.routes.applyMembership("#tag-b", "tag-amb", a_short, 0, 135, true, .{ .session_token = other_token }, 10);
    authorizer.authority = .single;
    authorizer.best_nick = "tag-new";
    try a.sendNickChange(a_to_b.sink(), "tag-amb", "tag-new", .{}, 136);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D5A);
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqualStrings("tag-amb", b.channelMembers("#tag-a")[0].nick);
    try std.testing.expectEqualStrings("tag-amb", b.channelMembers("#tag-b")[0].nick);
    wire_nicks = try b.takeNickChanges();
    try std.testing.expectEqual(@as(usize, 0), wire_nicks.len);
    allocator.free(wire_nicks);

    // With no retained Store authority and no token tag, the daemon explicitly
    // classifies the identity as true legacy and preserves NICK compatibility.
    _ = try b.routes.applyMembership("#legacy", "legacy-old", a_short, 0, 140, true, .{}, 10);
    authorizer.authority = .none;
    authorizer.best_nick = "";
    try a.sendNickChange(a_to_b.sink(), "legacy-old", "legacy-new", .{}, 141);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7D6);
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqualStrings("legacy-new", b.channelMembers("#legacy")[0].nick);
    wire_nicks = try b.takeNickChanges();
    try std.testing.expectEqual(@as(usize, 1), wire_nicks.len);
    for (wire_nicks) |*change| change.deinit(allocator);
    allocator.free(wire_nicks);
    try std.testing.expectEqual(@as(usize, 7), authorizer.calls);
}

test "session token reconcile allocation failure retains old identity for retry" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var tc = TestClock{ .now_ms = 10 };
            var state = ChannelCrdt.init(allocator, 1);
            defer state.deinit();
            var peer = try newPeer(allocator, &state, &tc, 1, 2, 1000, "test");
            defer peer.deinit();

            const token: SessionToken = @splat(0xB3);
            _ = try peer.routes.applyMembership("#room", "old", 2, 0, 10, true, .{
                .username = "u",
                .realname = "r",
                .host = "h",
                .account = "a",
                .session_token = token,
            }, 10);
            const desired = [_][]const u8{"#room"};
            const retried = peer.reconcileSessionToken(token, "new", &desired) catch |err| {
                // This assertion runs for every rename-plan and NickDelta queue
                // allocation site. Partial owned deltas unwind and the old row
                // remains the retry source of truth.
                try std.testing.expectEqualStrings("old", peer.channelMembers("#room")[0].nick);
                try std.testing.expectEqual(@as(usize, 0), peer.nick_changes.items.len);
                return err;
            };
            try std.testing.expectEqual(@as(usize, 1), retried.renamed);
            try std.testing.expectEqualStrings("new", peer.channelMembers("#room")[0].nick);
            const changes = try peer.takeNickChanges();
            defer allocator.free(changes);
            try std.testing.expectEqual(@as(usize, 1), changes.len);
            for (changes) |*change| change.deinit(allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "exact-token collision rename is atomic across both identities and deltas on allocation failure" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var tc = TestClock{ .now_ms = 10 };
            var state = ChannelCrdt.init(allocator, 1);
            defer state.deinit();
            var peer = try newPeer(allocator, &state, &tc, 1, 2, 1000, "test");
            defer peer.deinit();

            const exact_node: NodeId = 2;
            const incumbent_node: NodeId = 3;
            const token: SessionToken = @splat(0xBC);
            const uid = nick_collision.loserUid(incumbent_node, "target");
            for ([_][]const u8{ "#one", "#two" }) |channel| {
                _ = try peer.routes.applyMembership(channel, "old", exact_node, 0, 20, true, .{
                    .username = "exact-u",
                    .realname = "Exact User",
                    .host = "exact.test",
                }, 10);
                _ = try peer.routes.applyMembership(channel, "target", incumbent_node, 0, 10, true, .{
                    .username = "inc-u",
                    .realname = "Incumbent User",
                    .host = "inc.test",
                }, 10);
            }

            const renamed = peer.applyAuthorizedSessionTokenCollisionRename(
                exact_node,
                "old",
                "target",
                token,
                .{ .username = "exact-new", .realname = "Exact New", .host = "new.test" },
                incumbent_node,
                &uid,
            ) catch |err| {
                const exact = peer.routes.findMemberOwnedBy("old", exact_node) orelse return error.TestUnexpectedResult;
                const incumbent = peer.routes.findMemberOwnedBy("target", incumbent_node) orelse return error.TestUnexpectedResult;
                try std.testing.expect(exact.session_token == null);
                try std.testing.expectEqualStrings("exact-u", exact.username);
                try std.testing.expectEqualStrings("inc-u", incumbent.username);
                try std.testing.expectEqual(exact_node, peer.routes.nickNode("old").?);
                try std.testing.expectEqual(incumbent_node, peer.routes.nickNode("target").?);
                try std.testing.expect(peer.routes.nickNode(&uid) == null);
                try std.testing.expectEqual(@as(usize, 0), peer.nick_changes.items.len);
                return err;
            };

            try std.testing.expect(renamed);
            const exact = peer.routes.findMemberOwnedBy("target", exact_node) orelse return error.TestUnexpectedResult;
            const incumbent = peer.routes.findMemberOwnedBy(&uid, incumbent_node) orelse return error.TestUnexpectedResult;
            try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, token, exact.session_token.?));
            try std.testing.expectEqualStrings("exact-new", exact.username);
            try std.testing.expectEqualStrings("inc-u", incumbent.username);
            try std.testing.expect(peer.routes.nickNode("old") == null);
            try std.testing.expectEqual(exact_node, peer.routes.nickNode("target").?);
            try std.testing.expectEqual(incumbent_node, peer.routes.nickNode(&uid).?);
            try std.testing.expectEqual(@as(usize, 2), peer.nick_changes.items.len);
            try std.testing.expectEqualStrings("target", peer.nick_changes.items[0].old_nick);
            try std.testing.expectEqualStrings(&uid, peer.nick_changes.items[0].new_nick);
            try std.testing.expectEqualStrings("old", peer.nick_changes.items[1].old_nick);
            try std.testing.expectEqualStrings("target", peer.nick_changes.items[1].new_nick);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "session token revoke allocation failure retains membership for retry" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var tc = TestClock{ .now_ms = 10 };
            var state = ChannelCrdt.init(allocator, 1);
            defer state.deinit();
            var peer = try newPeer(allocator, &state, &tc, 1, 2, 1000, "test");
            defer peer.deinit();

            const token: SessionToken = @splat(0xB5);
            _ = try peer.routes.applyMembership("#room", "old", 2, 0, 10, true, .{
                .username = "u",
                .realname = "r",
                .host = "h",
                .account = "a",
                .session_token = token,
            }, 10);
            const revoked = peer.reconcileSessionToken(token, null, &.{}) catch |err| {
                // Every MembershipDelta string/list allocation precedes route
                // deletion. Any OOM therefore leaves the exact row available
                // as the retry source and cannot expose a partial PART delta.
                try std.testing.expectEqual(@as(usize, 1), peer.channelMembers("#room").len);
                try std.testing.expectEqualStrings("old", peer.channelMembers("#room")[0].nick);
                try std.testing.expectEqual(@as(usize, 0), peer.membership_changes.items.len);
                return err;
            };
            try std.testing.expectEqual(@as(usize, 1), revoked.removed);
            try std.testing.expectEqual(@as(usize, 0), peer.channelMembers("#room").len);
            const changes = try peer.takeMembershipChanges();
            defer allocator.free(changes);
            try std.testing.expectEqual(@as(usize, 1), changes.len);
            try std.testing.expectEqual(S2sPeer.MembershipDelta.Kind.parted, changes[0].kind);
            for (changes) |*change| change.deinit(allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "rejected downgraded MEMBERSHIP creates no UID route delta or roster entry" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x73);
    const kp_b = try signingKeyFor(0x74);
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
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x73E);
    try std.testing.expect(!b.supportsSessionReplicaV2());
    var reject_stub = RejectVerifierStub{};
    b.setResidenceVerifier(reject_stub.verifier());

    try a.sendMembership(a_to_b.sink(), "#room", "Nova", 0, 200, true, .{
        .username = "u",
        .realname = "r",
        .host = "h",
        .account = "nova-acct",
    }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x73F);

    const changes = try b.takeMembershipChanges();
    defer allocator.free(changes);
    try std.testing.expectEqual(@as(usize, 0), changes.len);
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#room").len);
}

test "negotiated-v2 rowless untrusted MEMBERSHIP keeps its route delta and roster entry" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x75);
    const kp_b = try signingKeyFor(0x76);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    // Model the secured adapter's v2 enablement before the capability handshake.
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x75E);
    try std.testing.expect(b.supportsSessionReplicaV2());

    // No local token owner exists, so the daemon's exact Store verifier returns
    // untrusted. On a negotiated-v2 link that is a compatibility sidecar, not a
    // downgrade rejection: routing/NAMES still need this remote participant.
    try a.sendMembership(a_to_b.sink(), "#room", "Nova", 0, 200, true, .{
        .username = "u",
        .realname = "r",
        .host = "h",
        .account = "nova-acct",
    }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x75F);
    b.processDeferredResidenceFrames(tc.now_ms);

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*change| change.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("Nova", changes[0].nick);
    const members = b.channelMembers("#room");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("Nova", members[0].nick);
}

test "v2 residence barrier applies OFFER-visible trust before wire-ordered NICK and MEMBERSHIP" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x77);
    const kp_b = try signingKeyFor(0x78);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x770);
    try std.testing.expect(b.supportsSessionReplicaV2());

    // The pre-resume nick is route-only. Nova is held locally by the exact
    // logical session, but its new-origin Store authority becomes visible only
    // after feed returns (modelled by toggling this verifier before processing).
    _ = try b.routes.applyMembership("#presence", "DeviceB", a_short, 0, 100, true, .{
        .account = "nova-acct",
    }, 10);
    var local = ReclaimResolverStub{ .held_nick = "Nova", .acct = "nova-acct", .hlc = 0 };
    b.setLocalNickResolver(local.resolver());
    var trust = MutableTrustVerifierStub{ .account = "nova-acct", .origin_node = a_short };
    b.setResidenceVerifier(trust.verifier());
    var nick_authority = SessionTokenNickAuthorizerStub{
        .origin_node = a_short,
        .token = @splat(0x77),
        .best_nick = "Nova",
    };
    b.setSessionTokenNickAuthorizer(nick_authority.authorizer());

    try a.sendNickChange(a_to_b.sink(), "DeviceB", "Nova", .{
        .username = "u",
        .realname = "r",
        .host = "h",
        .account = "nova-acct",
    }, 200);
    try a.sendMembership(a_to_b.sink(), "#room", "Nova", 0, 201, true, .{
        .username = "u",
        .realname = "r",
        .host = "h",
        .account = "nova-acct",
    }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x771);

    try std.testing.expectEqual(@as(usize, 2), b.deferred_residence_frames.items.len);
    try std.testing.expectEqual(@as(usize, 0), b.membership_changes.items.len);
    try std.testing.expectEqual(@as(usize, 0), b.nick_changes.items.len);
    try std.testing.expectEqualStrings("DeviceB", b.channelMembers("#presence")[0].nick);

    // The daemon applies the earlier signed OFFER before releasing this queue.
    // Both sidecars then see trusted exact-origin authority and retain Nova;
    // processing pre-authority would have minted a collision UID here.
    trust.trusted = true;
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqual(@as(usize, 0), b.deferred_residence_frames.items.len);
    const nicks = try b.takeNickChanges();
    defer {
        for (nicks) |*change| change.deinit(allocator);
        allocator.free(nicks);
    }
    try std.testing.expectEqual(@as(usize, 1), nicks.len);
    try std.testing.expectEqualStrings("DeviceB", nicks[0].old_nick);
    try std.testing.expectEqualStrings("Nova", nicks[0].new_nick);
    try std.testing.expectEqual(@as(usize, 1), nick_authority.calls);
    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*change| change.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("Nova", changes[0].nick);
    try std.testing.expectEqualStrings("Nova", b.channelMembers("#room")[0].nick);
}

test "v2 residence barrier overflow discards the correlated sidecar batch" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x79);
    const kp_b = try signingKeyFor(0x7A);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);
    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    a.session_replica_transport_enabled = true;
    b.session_replica_transport_enabled = true;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x790);
    b.config.max_session_replica_frames = 1;

    try a.sendMembership(a_to_b.sink(), "#one", "Nova", 0, 300, true, .{ .account = "nova-acct" }, "");
    try a.sendMembership(a_to_b.sink(), "#two", "Nova", 0, 301, true, .{ .account = "nova-acct" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x791);
    try std.testing.expectEqual(@as(u64, 1), b.takeDroppedSessionReplicaFrames());
    try std.testing.expectEqual(@as(usize, 1), b.deferred_residence_frames.items.len);

    // This is the daemon's incomplete-authority branch: no partial sidecar may
    // mutate routing or surface a delta before the requested replay.
    b.discardDeferredResidenceFrames();
    b.processDeferredResidenceFrames(tc.now_ms);
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#one").len);
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#two").len);
    const changes = try b.takeMembershipChanges();
    defer allocator.free(changes);
    try std.testing.expectEqual(@as(usize, 0), changes.len);
}

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

test "P2 (F1): an UNTRUSTED MEMBERSHIP is STORED account-less (no verifier ⇒ blanked)" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x81);
    const kp_b = try signingKeyFor(0x82);
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
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x8EE);

    // No residence verifier ⇒ the wire account is untrusted. It must be blanked in
    // the STORE, not just at resolve time: a forged incumbent persisted account-less
    // can never let a later TRUSTED newcomer remote_same_account-merge with it.
    try a.sendMembership(a_to_b.sink(), "#room", "kain", 0, 200, true, .{ .username = "u", .realname = "r", .host = "h", .account = "kain" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x8EF);

    const members = b.channelMembers("#room");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("kain", members[0].nick);
    try std.testing.expectEqualStrings("", members[0].account); // blanked, NOT the wire "kain"

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
}

test "P2 (F1): a TRUSTED MEMBERSHIP is STORED with the real account (verified ⇒ preserved)" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x83);
    const kp_b = try signingKeyFor(0x84);
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
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x9EE);

    // a's kain carries a VERIFIED residence proof (Design C) — the receiver trusts
    // the account, so the real account is preserved in the store (multi-device).
    var vstub = TrustVerifierStub{ .account = "kain", .origin_node = a_short };
    b.setResidenceVerifier(vstub.verifier());

    try a.sendMembership(a_to_b.sink(), "#room", "kain", 0, 200, true, .{ .username = "u", .realname = "r", .host = "h", .account = "kain" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x9EF);

    const members = b.channelMembers("#room");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("kain", members[0].nick);
    try std.testing.expectEqualStrings("kain", members[0].account); // real account preserved

    const changes = try b.takeMembershipChanges();
    defer {
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }
}

test "P2 (F1): a forged UNTRUSTED incumbent grants NO coexistence to a later TRUSTED newcomer" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x85);
    const kp_b = try signingKeyFor(0x86);
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
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xAEE);

    // Node a forges an UNTRUSTED account=kain (no verifier yet) — stored blanked.
    try a.sendMembership(a_to_b.sink(), "#room", "kain", 0, 100, true, .{ .username = "u", .realname = "r", .host = "h", .account = "kain" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xAEF);
    {
        const members = b.channelMembers("#room");
        try std.testing.expectEqual(@as(usize, 1), members.len);
        try std.testing.expectEqualStrings("", members[0].account); // forged incumbent is account-less
    }
    {
        const changes = try b.takeMembershipChanges();
        for (changes) |*c| c.deinit(allocator);
        allocator.free(changes);
    }

    // The forged incumbent (a, account="") must grant NO same-account coexistence
    // to a genuinely TRUSTED newcomer from a different node — because the stored
    // incumbent account is blank, `remote_same_account` cannot fire. The newcomer
    // is contested on the deterministic (hlc,node) tiebreak, never merged.
    const decision = b.routes.resolveIncomingNick("kain", b_short ^ 0x1, 200, "kain", true);
    try std.testing.expect(decision != .remote_same_account);
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

test "signing peers round-trip a signed MEMO_PUSH frame" {
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

    try a.sendMemoPush(a_to_b.sink(), "alice", "bob", "offline dm preview");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x6EF);

    const pushes = try b.takeMemoPushes();
    defer {
        for (pushes) |p| allocator.free(p);
        allocator.free(pushes);
    }
    try std.testing.expectEqual(@as(usize, 1), pushes.len);
    const ev = try memo_push_relay.decode(pushes[0]);
    try std.testing.expectEqualStrings("alice", ev.account);
    try std.testing.expectEqualStrings("bob", ev.from);
    try std.testing.expectEqualStrings("offline dm preview", ev.text);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "signing peers round-trip a signed MEDIA_WS_DATAGRAM frame" {
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

    const opaque_dg = "e2ee-cadence-ws-datagram-bytes";
    try a.sendMediaWsDatagram(a_to_b.sink(), "#voice", opaque_dg);
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7EF);

    const frames = try b.takeMediaWsDatagrams();
    defer {
        for (frames) |p| allocator.free(p);
        allocator.free(frames);
    }
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    const ev = try media_ws_relay.decode(frames[0]);
    try std.testing.expectEqualStrings("#voice", ev.channel);
    try std.testing.expectEqualStrings(opaque_dg, ev.datagram);
    try std.testing.expectEqual(@as(u64, 0), b.takeRejectedOriginFrames());
}

test "MEDIA_WS_DATAGRAM queue is fail-closed at max_media_ws_datagrams" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    const kp_a = try signingKeyFor(0x73);
    const kp_b = try signingKeyFor(0x74);
    const a_short = signed_frame.originShortId(kp_a.public_key);
    const b_short = signed_frame.originShortId(kp_b.public_key);

    var a = try newSigningPeer(allocator, &a_state, &tc, kp_a, b_short, 1000, "a.test");
    defer a.deinit();
    var b = try newSigningPeer(allocator, &b_state, &tc, kp_b, a_short, 2000, "b.test");
    defer b.deinit();
    b.config.max_media_ws_datagrams = 1;
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7F0);

    try a.sendMediaWsDatagram(a_to_b.sink(), "#c", "first");
    try a.sendMediaWsDatagram(a_to_b.sink(), "#c", "second");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x7F1);

    const frames = try b.takeMediaWsDatagrams();
    defer {
        for (frames) |p| allocator.free(p);
        allocator.free(frames);
    }
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    const ev = try media_ws_relay.decode(frames[0]);
    try std.testing.expectEqualStrings("first", ev.datagram);
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

test "exploit: Byzantine MEMBERSHIP with spoofed origin_node is rejected (no NAMES entry)" {
    // CWE-290: a MEMBERSHIP frame whose origin_node is not the link shortId must
    // never mutate the route table. Assert the REJECT (empty roster + reject
    // counter), never that a forgery "works".
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    // Plaintext peers with require_signed_frames=false so we exercise the
    // acceptsDirectOrigin gate (not the signed-frame origin check).
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    // newPeer leaves require_signed_frames at its default (true). For a
    // non-signing pair that would reject every unsigned in-scope frame; the
    // origin-spoof test needs the frame to reach applyMembershipPayload.
    a.config.require_signed_frames = false;
    b.config.require_signed_frames = false;

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xB01);

    // Legitimate membership from A lands.
    try a.sendMembership(a_to_b.sink(), "#room", "alice", 0, 50, true, .{ .username = "u", .host = "h" }, "");
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xB02);
    try std.testing.expectEqual(@as(usize, 1), b.channelMembers("#room").len);

    // Byzantine payload: claims origin_node=99 (not link peer 1), tries to PART
    // alice and JOIN mallory. Both must be dropped by acceptsDirectOrigin.
    var ev_buf: [membership_event.max_encoded_len]u8 = undefined;
    const forged_part = membership_event.MembershipEvent{
        .present = false,
        .status = 0,
        .origin_node = 99,
        .hlc = 999,
        .channel = "#room",
        .nick = "alice",
    };
    const part_wire = try membership_event.encode(forged_part, &ev_buf);
    var fbuf: [2048]u8 = undefined;
    const part_frame = try s2s_frame.encode(.MEMBERSHIP, part_wire, &fbuf);
    var sink = BufferSink{};
    defer sink.deinit(allocator);
    try b.feed(part_frame, sink.sink(), tc.now_ms, 1);

    const forged_join = membership_event.MembershipEvent{
        .present = true,
        .status = 0b0100,
        .origin_node = 99,
        .hlc = 1000,
        .channel = "#room",
        .nick = "mallory",
        .username = "evil",
        .host = "evil.example",
    };
    const join_wire = try membership_event.encode(forged_join, &ev_buf);
    const join_frame = try s2s_frame.encode(.MEMBERSHIP, join_wire, &fbuf);
    try b.feed(join_frame, sink.sink(), tc.now_ms, 2);

    // alice still present; mallory never appeared; rejects counted.
    try std.testing.expectEqual(@as(usize, 1), b.channelMembers("#room").len);
    try std.testing.expectEqualStrings("alice", b.channelMembers("#room")[0].nick);
    try std.testing.expect(b.findRemoteMember("mallory") == null);
    try std.testing.expect(b.takeRejectedOriginFrames() >= 2);
}

test "exploit: reordered MEMBERSHIP frames over the link converge to the same roster" {
    // Deliver JOIN/PART/re-JOIN out of HLC order across an established link and
    // assert the receiver's live roster matches the canonical in-order apply.
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
    a.config.require_signed_frames = false;
    b.config.require_signed_frames = false;

    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);
    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xC01);

    // Build three MEMBERSHIP frames offline, then feed B in reverse HLC order.
    const events = [_]membership_event.MembershipEvent{
        .{ .present = true, .status = 0b0100, .origin_node = 1, .hlc = 10, .channel = "#room", .nick = "alice", .username = "alice", .host = "a.host" },
        .{ .present = false, .status = 0, .origin_node = 1, .hlc = 20, .channel = "#room", .nick = "alice" },
        .{ .present = true, .status = 0b0010, .origin_node = 1, .hlc = 30, .channel = "#room", .nick = "alice", .username = "alice", .host = "a.host" },
    };
    var frames: [3][]u8 = undefined;
    var frame_bufs: [3][512]u8 = undefined;
    var enc_bufs: [3][membership_event.max_encoded_len]u8 = undefined;
    for (events, 0..) |ev, i| {
        const inner = try membership_event.encode(ev, &enc_bufs[i]);
        const wire = try s2s_frame.encode(.MEMBERSHIP, inner, &frame_bufs[i]);
        frames[i] = try allocator.dupe(u8, wire);
    }
    defer for (frames) |f| allocator.free(f);

    var sink = BufferSink{};
    defer sink.deinit(allocator);
    // Reverse order: re-JOIN, PART, JOIN — PART tombstone + LWW must converge.
    try b.feed(frames[2], sink.sink(), tc.now_ms, 1);
    try b.feed(frames[1], sink.sink(), tc.now_ms, 2);
    try b.feed(frames[0], sink.sink(), tc.now_ms, 3);

    const members = b.channelMembers("#room");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("alice", members[0].nick);
    try std.testing.expectEqual(@as(u4, 0b0010), members[0].status);
    try std.testing.expectEqual(@as(u64, 30), members[0].hlc);
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
        .HANDSHAKE,           .BURST,                  .DELTA,                    .GOSSIP,                           .PING,
        .PONG,                .QUIT,                   .MEMBERSHIP,               .MESSAGE,                          .OPER_GRANT,
        .CHANNEL_MODE_FLAGS,  .CHANNEL_LIST,           .CHANNEL_PROP,             .TOPIC,                            .NICKCHANGE,
        .CHANNEL_MODE_STATE,  .SESSION_MIGRATE,        .SESSION_MIGRATE_CONSUMED, .ENTITY_PROP,                      .CLONE_COUNT,
        .OPER_EVENT,          .OBSERVE_EVENT,          .KILL,                     .WARD,                             .RESYNC,
        .REPAIR_SUMMARY,      .REPAIR_REQUEST,         .REPAIR_RESPONSE,          .MEMO_PUSH,                        .SESSION_REPLICA_OFFER,
        .SESSION_REPLICA_ACK, .SESSION_REPLICA_REVOKE, .MESSAGE_V2,               .SESSION_REPLICA_ATTACHMENT_LEASE, .OPER_EVENT_V2,
        .MESSAGE_V2_ACK,      .MEDIA_WS_DATAGRAM,      .E2EE_GROUP,               .E2EE_GROUP_ACK,
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
