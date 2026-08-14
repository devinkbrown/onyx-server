// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded cross-node route table for UNDERTOW message fan-out.
//!
//! The table is pure state: callers own all I/O decisions and pass allocator
//! ownership in at init. String keys are copied into managed StringHashMaps and
//! released on removal/deinit.
const std = @import("std");
const toml = @import("../../proto/toml.zig");
const channel_list_event = @import("../../proto/channel_list_event.zig");
const membership_event = @import("../../proto/membership_event.zig");
const nick_collision = @import("nick_collision.zig");
const uid_alloc = @import("uid_alloc.zig");

pub const NodeId = u64;
/// Receiver-owned reusable-session identity. MEMBERSHIP never carries this on
/// the wire: the daemon resolves it from a unique live signed SESSION_REPLICA
/// fact and hands it to the route table as trusted local metadata.
pub const SessionToken = [16]u8;

/// Value-only projection of the best roster-backed claim for a nick. Account is
/// intentionally excluded so routing priority cannot become identity-dependent
/// and callers never retain a borrowed roster slice.
pub const NickClaim = struct {
    node_id: NodeId,
    hlc: u64,

    pub fn higherPriorityThan(candidate: NickClaim, incumbent: NickClaim) bool {
        return nick_collision.higherPriority(
            .{ .node_id = candidate.node_id, .hlc = candidate.hlc },
            .{ .node_id = incumbent.node_id, .hlc = incumbent.hlc },
        );
    }
};

/// Allocation-free, owned key for the S2S protocol's bounded nick namespace.
/// Every byte is initialized so AutoHashMap equality/hash never observes padding
/// or stale stack contents. Route-table-only names beyond the wire bound bypass
/// the optional index and use the authoritative roster scan.
const NickKey = struct {
    bytes: [membership_event.max_nick_len]u8 = @splat(0),
    len: u8 = 0,

    fn init(nick: []const u8) ?NickKey {
        if (nick.len == 0 or nick.len > membership_event.max_nick_len) return null;
        var key = NickKey{ .len = @intCast(nick.len) };
        _ = std.ascii.lowerString(key.bytes[0..nick.len], nick);
        return key;
    }
};

/// Borrowed predicate the daemon installs so the route table can ask "is `nick`
/// currently held in the LOCAL world?" without depending on the daemon. Local
/// nicks are authoritative on a cross-namespace collision: an incoming REMOTE
/// nick that matches a local one loses and is renamed to its mesh UID. The
/// `ctx` pointer is opaque to the route table; the daemon owns its lifetime and
/// MUST outlive the table (it is cleared on peer drop / deinit anyway).
pub const LocalNickResolver = struct {
    ctx: *anyopaque,
    /// Case-insensitive (the daemon's world is RFC-1459 case-folded); returns
    /// true iff a LOCAL client currently holds `nick`.
    held_fn: *const fn (*anyopaque, []const u8) bool,
    /// The authenticated ACCOUNT of the LOCAL client holding `nick`, or null when
    /// no local client holds it or the holder is not logged in. Borrowed for the
    /// duration of the synchronous resolve call. Optional: when absent, collision
    /// resolution falls back to the account-blind path (no same-identity reconcile).
    account_fn: ?*const fn (*anyopaque, []const u8) ?[]const u8 = null,
    /// The mesh HLC at which the LOCAL holder of `nick` last asserted its claim, or
    /// 0 when unknown/not held. Lets the resolver decide which of two same-account
    /// sessions is the stale one. Optional: when absent, a same-account local
    /// collision is never escalated to a reclaim (the holder is always kept).
    hlc_fn: ?*const fn (*anyopaque, []const u8) u64 = null,
    /// Exact reusable-session token of the LOCAL holder, when one exists. This
    /// lets signed-session reconciliation distinguish a duplicate projection of
    /// the same attachment from a genuine local-nick collision.
    session_token_fn: ?*const fn (*anyopaque, []const u8) ?SessionToken = null,

    pub fn held(self: LocalNickResolver, nick: []const u8) bool {
        return self.held_fn(self.ctx, nick);
    }

    /// The local holder's authenticated account, or null (not held / not logged in).
    pub fn account(self: LocalNickResolver, nick: []const u8) ?[]const u8 {
        const f = self.account_fn orelse return null;
        return f(self.ctx, nick);
    }

    /// The local holder's last mesh-claim HLC (0 = unknown / never asserted).
    pub fn holderHlc(self: LocalNickResolver, nick: []const u8) u64 {
        const f = self.hlc_fn orelse return 0;
        return f(self.ctx, nick);
    }

    pub fn sessionToken(self: LocalNickResolver, nick: []const u8) ?SessionToken {
        const f = self.session_token_fn orelse return null;
        return f(self.ctx, nick);
    }
};

/// Outcome of `resolveIncomingNick`: either keep the wire nick verbatim, or
/// rename the incoming remote member to `uid` because it lost a cross-namespace
/// (local) or cross-node (remote) collision. We NEVER signal a kill — a loser is
/// always renamed to its stable mesh UID.
pub const NickDecision = union(enum) {
    keep,
    rename_to_uid: nick_collision.Uid,
    /// An incoming REMOTE claim matches a nick a LOCAL client holds AND both bear
    /// the SAME authenticated account, but the LOCAL holder's mesh claim is NOT
    /// strictly older — keep the live local session and drop the remote duplicate.
    /// Never mints a UID for a logged-in user.
    local_same_account,
    /// Same as `local_same_account`, but the LOCAL holder's mesh claim is strictly
    /// OLDER than the incoming one (a known, non-zero holder HLC) — the local
    /// session is the stale ghost and the remote is the live one. The daemon should
    /// retire (ghost-kill) the local session in favour of the remote.
    reclaim_local,
    /// An incoming REMOTE claim matches a REMOTE incumbent on a DIFFERENT node, but
    /// both bear the SAME authenticated account — the same identity duplicated
    /// across the mesh. Accept the wire nick and let `applyMembership`'s hlc LWW
    /// collapse the two claims onto the newer one; the caller must NOT displace the
    /// incumbent to a UID (that would mint a phantom for a real logged-in user).
    remote_same_account,
};

pub const Error = std.mem.Allocator.Error || error{
    BufferTooSmall,
    ChannelFanoutFull,
    InvalidConfig,
    InvalidName,
    InvalidNode,
    MemberCountOverflow,
    RouteTableFull,
};

pub const Config = struct {
    max_nicks: usize = 4096,
    max_channels: usize = 1024,
    max_nodes_per_channel: usize = 64,
    max_name_len: usize = 64,

    pub fn validate(self: Config) Error!void {
        if (self.max_nicks == 0) return error.InvalidConfig;
        if (self.max_channels == 0) return error.InvalidConfig;
        if (self.max_nodes_per_channel == 0) return error.InvalidConfig;
        if (self.max_name_len == 0) return error.InvalidConfig;
    }

    /// Overlay `[mesh.routing]` route-table keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.routing.max_nicks")) |v| cfg.max_nicks = @intCast(v);
        if (doc.getUint("mesh.routing.max_channels")) |v| cfg.max_channels = @intCast(v);
        if (doc.getUint("mesh.routing.max_nodes_per_channel")) |v| cfg.max_nodes_per_channel = @intCast(v);
        if (doc.getUint("mesh.routing.max_name_len")) |v| cfg.max_name_len = @intCast(v);
    }
};

pub const MembershipChange = enum {
    join,
    part,
};

const NodeRef = struct {
    id: NodeId,
    members: u32 = 1,
};

const ChannelState = struct {
    nodes: []NodeRef,
    len: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) Error!ChannelState {
        return .{ .nodes = try allocator.alloc(NodeRef, capacity) };
    }

    fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
        allocator.free(self.nodes);
        self.* = undefined;
    }

    fn addMember(self: *ChannelState, node: NodeId) Error!void {
        if (self.find(node)) |idx| {
            if (self.nodes[idx].members == std.math.maxInt(u32)) {
                return error.MemberCountOverflow;
            }
            self.nodes[idx].members += 1;
            return;
        }

        if (self.len == self.nodes.len) return error.ChannelFanoutFull;
        self.nodes[self.len] = .{ .id = node };
        self.len += 1;
    }

    fn removeMember(self: *ChannelState, node: NodeId) void {
        const idx = self.find(node) orelse return;
        if (self.nodes[idx].members > 1) {
            self.nodes[idx].members -= 1;
            return;
        }
        self.swapRemove(idx);
    }

    fn removeNode(self: *ChannelState, node: NodeId) void {
        const idx = self.find(node) orelse return;
        self.swapRemove(idx);
    }

    fn copyNodes(self: *const ChannelState, out: []NodeId) Error!usize {
        if (out.len < self.len) return error.BufferTooSmall;
        for (self.nodes[0..self.len], 0..) |entry, idx| out[idx] = entry.id;
        return self.len;
    }

    fn find(self: *const ChannelState, node: NodeId) ?usize {
        for (self.nodes[0..self.len], 0..) |entry, idx| {
            if (entry.id == node) return idx;
        }
        return null;
    }

    fn swapRemove(self: *ChannelState, idx: usize) void {
        self.len -= 1;
        if (idx != self.len) self.nodes[idx] = self.nodes[self.len];
    }
};

/// One remote channel member's identity, for projecting NAMES/WHO. `nick`,
/// `username`, `realname`, and `host` are owned by the route table; `status`
/// reuses the MemberStatus bit layout (founder/owner/op/voice) so prefixes
/// render; `hlc` drives last-writer-wins. Identity strings may be empty when
/// the origin did not propagate them (consumers substitute placeholders).
pub const Member = struct {
    nick: []u8,
    /// The member's username (USER ident) on its home node ("" = unknown).
    username: []u8,
    /// The member's realname/GECOS ("" = unknown).
    realname: []u8,
    /// The member's VISIBLE (cloaked) host ("" = unknown).
    host: []u8,
    /// The member's authenticated ACCOUNT ("" = not logged in / unknown). Drives
    /// account-aware collision reconcile (see resolveIncomingNick).
    account: []u8,
    /// The member's REAL (uncloaked) host/IP ("" = unknown/withheld). SENSITIVE:
    /// only ever populated from an oper-info-capable SECURED link, and surfaced
    /// only to operators (remote WHOIS 338/320). See [proto/membership_event].
    real_host: []u8,
    /// The member's TLS client-cert fingerprint ("" = none). Same sensitivity and
    /// gating as `real_host` (remote WHOIS 276).
    certfp: []u8,
    /// Exact signed logical-session token resolved by this receiver, or null
    /// when no unique authority exists. Never populated from peer-controlled
    /// MEMBERSHIP bytes; null keeps legacy/ambiguous rows fail-closed.
    session_token: ?SessionToken = null,
    node: NodeId,
    status: u4,
    hlc: u64,
    /// The RECEIVER's local monotonic clock (ms) at the most recent PRESENT apply
    /// for this member. Distinct from `hlc`, which is the *announcing* node's
    /// monotonic clock and is comparable across hosts ONLY for last-writer-wins
    /// ordering — never against this node's clock. `pruneStale` ages a member out
    /// against THIS field so the staleness window is measured entirely in the
    /// receiver's clock domain (see pruneStale).
    last_refreshed_ms: i64 = 0,

    fn freeStrings(self: *const Member, allocator: std.mem.Allocator) void {
        allocator.free(self.nick);
        allocator.free(self.username);
        allocator.free(self.realname);
        allocator.free(self.host);
        allocator.free(self.account);
        allocator.free(self.real_host);
        allocator.free(self.certfp);
    }
};

/// A remote member's propagated identity, as `applyMembership` accepts it
/// (borrowed; duped into owned `Member` strings on store).
pub const MemberIdentity = struct {
    username: []const u8 = "",
    realname: []const u8 = "",
    host: []const u8 = "",
    account: []const u8 = "",
    /// REAL (uncloaked) host/IP — sensitive; only set/propagated over a secured,
    /// oper-info-capable link and only ever shown to operators. "" = unknown.
    real_host: []const u8 = "",
    /// TLS client-cert fingerprint — same sensitivity/gating as real_host. "" = none.
    certfp: []const u8 = "",
    /// Receiver-derived exact token metadata. See `Member.session_token`.
    session_token: ?SessionToken = null,
};

/// Receiver-visible effects that must be made durable by the caller before an
/// exact-token reconciliation mutates the authoritative compatibility roster.
/// All slices and `member` fields are borrowed from the RouteTable for the
/// duration of the callback only.
pub const SessionTokenReconcileObserver = struct {
    ctx: *anyopaque,
    part_fn: *const fn (ctx: *anyopaque, channel: []const u8, member: *const Member) std.mem.Allocator.Error!void,
    rename_fn: *const fn (ctx: *anyopaque, old_nick: []const u8, new_nick: []const u8, member: *const Member) std.mem.Allocator.Error!void,

    fn part(self: SessionTokenReconcileObserver, channel: []const u8, member: *const Member) std.mem.Allocator.Error!void {
        return self.part_fn(self.ctx, channel, member);
    }

    fn rename(self: SessionTokenReconcileObserver, old_nick: []const u8, new_nick: []const u8, member: *const Member) std.mem.Allocator.Error!void {
        return self.rename_fn(self.ctx, old_nick, new_nick, member);
    }
};

pub const SessionTokenReconcileResult = struct {
    removed: usize = 0,
    renamed: usize = 0,
};

pub const SessionTokenNickMatch = union(enum) {
    none,
    unique: SessionToken,
    ambiguous,
};

/// Two accounts identify the SAME authenticated user iff both are present and
/// byte-equal. Account names are canonical (the daemon emits each account in one
/// fixed spelling), so an exact compare avoids false-positive merges between
/// distinct accounts a looser casemap might conflate. An empty/absent account on
/// either side is "unknown" and never matches — which preserves the prior
/// account-blind collision behaviour for legacy peers that carry no account.
fn sameAccount(incoming: []const u8, holder: ?[]const u8) bool {
    const h = holder orelse return false;
    if (incoming.len == 0 or h.len == 0) return false;
    return std.mem.eql(u8, incoming, h);
}

fn optionalSessionTokenEql(a: ?SessionToken, b: ?SessionToken) bool {
    const left = a orelse return b == null;
    const right = b orelse return false;
    return std.crypto.timing_safe.eql(SessionToken, left, right);
}

fn channelInSet(channel: []const u8, channels: []const []const u8) bool {
    for (channels) |candidate| {
        if (std.ascii.eqlIgnoreCase(channel, candidate)) return true;
    }
    return false;
}

pub const ChannelListKind = channel_list_event.ListKind;

pub const ChannelListEntry = struct {
    kind: ChannelListKind,
    mask: []u8,
    setter: []u8,
    set_at: i64,
    origin_node: NodeId,
    hlc: u64,
    present: bool,
};

const ChannelListState = struct {
    entries: std.ArrayListUnmanaged(ChannelListEntry) = .empty,

    fn deinit(self: *ChannelListState, allocator: std.mem.Allocator) void {
        for (self.entries.items) |*entry| {
            allocator.free(entry.mask);
            allocator.free(entry.setter);
        }
        self.entries.deinit(allocator);
    }

    fn find(self: *const ChannelListState, kind: ChannelListKind, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (entry.kind == kind and std.mem.eql(u8, entry.mask, mask)) return i;
        }
        return null;
    }
};

/// Per-channel member roster (flat list — channels are bounded, and a flat list
/// keeps ownership trivial: owned nick + identity strings per entry).
const MemberList = struct {
    entries: std.ArrayListUnmanaged(Member) = .empty,

    fn deinit(self: *MemberList, allocator: std.mem.Allocator) void {
        for (self.entries.items) |m| m.freeStrings(allocator);
        self.entries.deinit(allocator);
    }

    fn find(self: *const MemberList, nick: []const u8) ?usize {
        for (self.entries.items, 0..) |m, i| {
            if (std.mem.eql(u8, m.nick, nick)) return i;
        }
        return null;
    }
};

/// LWW PART tombstone for one (channel, nick, origin-node) triple.
///
/// Without these, a PART that arrives *before* a lower-HLC JOIN is discarded as
/// "unknown member", and the later JOIN resurrects a member the origin already
/// retracted — classic LWW-without-tombstone divergence under reordering. Channel
/// list masks already keep tombstones for the same reason (`ChannelListEntry.present`);
/// membership needs the same lattice so out-of-order gossip converges.
const PartTombstone = struct {
    nick: []u8,
    node: NodeId,
    hlc: u64,
    /// Receiver-local stamp for `pruneStale` GC (same clock domain as Member.last_refreshed_ms).
    stamped_ms: i64,

    fn free(self: *const PartTombstone, allocator: std.mem.Allocator) void {
        allocator.free(self.nick);
    }
};

const PartTombList = struct {
    entries: std.ArrayListUnmanaged(PartTombstone) = .empty,

    fn deinit(self: *PartTombList, allocator: std.mem.Allocator) void {
        for (self.entries.items) |t| t.free(allocator);
        self.entries.deinit(allocator);
    }

    fn find(self: *const PartTombList, nick: []const u8, node: NodeId) ?usize {
        for (self.entries.items, 0..) |t, i| {
            if (t.node == node and std.mem.eql(u8, t.nick, nick)) return i;
        }
        return null;
    }
};

/// One remote channel MODE-flag aggregate, tracked last-writer-wins by HLC.
pub const ChannelModeFlags = struct {
    flags: u16,
    origin_node: NodeId,
    hlc: u64,
};

/// LWW clock for a channel's topic. The topic TEXT lives in the daemon's world;
/// the route table only orders writes so a stale/re-burst TOPIC never clobbers a
/// newer one. `hlc` is the sole ordering key.
pub const TopicClock = struct {
    origin_node: NodeId,
    hlc: u64,
};

pub const RouteTable = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    cfg: Config,
    nick_to_node: std.StringHashMap(NodeId),
    /// Optional ASCII-case-folded nick -> deterministic best roster claim. The
    /// roster remains authoritative: when an insert/rebuild cannot complete, the
    /// dirty flag makes every query scan until a later one-pass rebuild succeeds.
    best_nick_claims: std.AutoHashMap(NickKey, NickClaim),
    claim_index_dirty: bool = false,
    channels: std.StringHashMap(ChannelState),
    /// channel name -> roster of remote members (nick + status), populated by
    /// MEMBERSHIP propagation (see docs/planning/16). Independent of `channels`
    /// (which is node-level routing) so identity churn never disturbs routing.
    channel_members: std.StringHashMap(MemberList),
    /// channel name -> LWW PART tombstones for (nick, origin-node). Prevents a
    /// reordered lower-HLC JOIN from resurrecting a member after its PART. Never
    /// projected into NAMES (live roster is `channel_members` only).
    channel_part_tombs: std.StringHashMap(PartTombList),
    /// channel name -> last remote aggregate boolean MODE flags, populated by
    /// CHANNEL_MODE_FLAGS propagation. This is independent of route fanout and
    /// rosters; it is only an LWW cache that drives daemon-side world updates.
    channel_mode_flags: std.StringHashMap(ChannelModeFlags),
    /// channel name -> LWW list-mode facts (+b/+e/+I). Tombstones are retained so
    /// stale add frames cannot resurrect a mask after a newer remove.
    channel_lists: std.StringHashMap(ChannelListState),
    /// channel name -> LWW clock for the channel topic (text lives in the daemon
    /// world; this only orders writes so a re-burst never clobbers a newer topic).
    channel_topics: std.StringHashMap(TopicClock),
    /// Borrowed local-world nick predicate for cross-namespace collision checks
    /// (null until the daemon installs it; null behaves like "no local nicks",
    /// preserving the substrate-pure unit-test path). See `setLocalNickResolver`.
    local_nicks: ?LocalNickResolver = null,
    nick_count: usize = 0,
    channel_count: usize = 0,
    list_channel_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Error!Self {
        try cfg.validate();
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .nick_to_node = std.StringHashMap(NodeId).init(allocator),
            .best_nick_claims = std.AutoHashMap(NickKey, NickClaim).init(allocator),
            .channels = std.StringHashMap(ChannelState).init(allocator),
            .channel_members = std.StringHashMap(MemberList).init(allocator),
            .channel_part_tombs = std.StringHashMap(PartTombList).init(allocator),
            .channel_mode_flags = std.StringHashMap(ChannelModeFlags).init(allocator),
            .channel_lists = std.StringHashMap(ChannelListState).init(allocator),
            .channel_topics = std.StringHashMap(TopicClock).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.clear();
        self.nick_to_node.deinit();
        self.best_nick_claims.deinit();
        self.channels.deinit();
        self.channel_members.deinit();
        self.channel_part_tombs.deinit();
        self.channel_mode_flags.deinit();
        self.channel_lists.deinit();
        self.channel_topics.deinit();
        self.* = undefined;
    }

    pub fn clear(self: *Self) void {
        var nicks = self.nick_to_node.iterator();
        while (nicks.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.nick_to_node.clearRetainingCapacity();

        self.best_nick_claims.clearRetainingCapacity();
        self.claim_index_dirty = false;

        var channels = self.channels.iterator();
        while (channels.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.clearRetainingCapacity();

        var members = self.channel_members.iterator();
        while (members.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channel_members.clearRetainingCapacity();

        var tombs = self.channel_part_tombs.iterator();
        while (tombs.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channel_part_tombs.clearRetainingCapacity();

        var mode_flags = self.channel_mode_flags.iterator();
        while (mode_flags.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.channel_mode_flags.clearRetainingCapacity();

        var lists = self.channel_lists.iterator();
        while (lists.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channel_lists.clearRetainingCapacity();

        var topics = self.channel_topics.iterator();
        while (topics.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.channel_topics.clearRetainingCapacity();

        self.nick_count = 0;
        self.channel_count = 0;
        self.list_channel_count = 0;
    }

    pub fn setNickLocation(self: *Self, nick: []const u8, node: NodeId) Error!void {
        try self.validateName(nick);
        try validateNode(node);

        if (self.nick_to_node.getPtr(nick)) |slot| {
            slot.* = node;
            return;
        }

        if (self.nick_count == self.cfg.max_nicks) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned);
        try self.nick_to_node.putNoClobber(owned, node);
        self.nick_count += 1;
    }

    pub fn removeNick(self: *Self, nick: []const u8) bool {
        const removed = self.nick_to_node.fetchRemove(nick) orelse return false;
        self.allocator.free(removed.key);
        self.nick_count -= 1;
        return true;
    }

    pub fn nickNode(self: *const Self, nick: []const u8) ?NodeId {
        return self.nick_to_node.get(nick);
    }

    /// Install (or clear) the borrowed local-world nick predicate. The daemon
    /// calls this once per link so cross-namespace collisions (a remote nick
    /// matching a LOCAL one) resolve in the local nick's favor.
    pub fn setLocalNickResolver(self: *Self, resolver: ?LocalNickResolver) void {
        self.local_nicks = resolver;
    }

    /// The current best (highest-priority) claim the table holds for `nick`
    /// across all channel rosters (ASCII case-insensitive), or null when no
    /// remote member holds it. "Best" uses the same `(hlc, node)` ordering the
    /// collision resolver does, so the incumbent we compare against is the one
    /// that actually won the nick on prior applies.
    fn identityNickClaim(self: *const Self, nick: []const u8) ?nick_collision.Claim {
        var best: ?nick_collision.Claim = null;
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.entries.items) |m| {
                if (!std.ascii.eqlIgnoreCase(m.nick, nick)) continue;
                const cand = nick_collision.Claim{ .node_id = m.node, .hlc = m.hlc, .account = m.account };
                if (best == null or nick_collision.higherPriority(cand, best.?)) best = cand;
            }
        }
        return best;
    }

    fn projectedIdentityNickClaim(self: *const Self, nick: []const u8) ?NickClaim {
        const claim = self.identityNickClaim(nick) orelse return null;
        return .{ .node_id = claim.node_id, .hlc = claim.hlc };
    }

    /// Authoritative value-only scan for an already-normalized protocol nick.
    /// This deliberately stores no Member pointer or borrowed account slice:
    /// roster ArrayLists move on growth/swapRemove and identity strings are
    /// replaced independently of routing priority.
    fn scannedBestNickKey(self: *const Self, key: NickKey) ?NickClaim {
        var best: ?NickClaim = null;
        var channels = self.channel_members.iterator();
        while (channels.next()) |entry| {
            for (entry.value_ptr.entries.items) |member| {
                const member_key = NickKey.init(member.nick) orelse continue;
                if (!std.meta.eql(member_key, key)) continue;
                const candidate = NickClaim{ .node_id = member.node, .hlc = member.hlc };
                if (best == null or candidate.higherPriorityThan(best.?)) best = candidate;
            }
        }
        return best;
    }

    /// Add or raise one claim without rescanning. Existing-value updates never
    /// allocate. A new-key OOM or the configured global index bound makes the
    /// whole optional index dirty, so no partial map can be mistaken for truth.
    fn noteBestNickClaim(self: *Self, nick: []const u8, claim: NickClaim) void {
        const key = NickKey.init(nick) orelse return;
        if (self.claim_index_dirty) return;
        if (self.best_nick_claims.getPtr(key)) |current| {
            if (claim.higherPriorityThan(current.*)) current.* = claim;
            return;
        }
        if (self.best_nick_claims.count() >= self.cfg.max_nicks) {
            self.claim_index_dirty = true;
            return;
        }
        self.best_nick_claims.putNoClobber(key, claim) catch {
            self.claim_index_dirty = true;
        };
    }

    /// Re-select one key after a destructive mutation. The roster is scanned
    /// before touching the cached value, so an existing winner is never removed
    /// merely because allocating a previously-missing map slot fails.
    fn reselectBestNickKey(self: *Self, key: NickKey) void {
        if (self.claim_index_dirty) return;
        const best = self.scannedBestNickKey(key);
        if (best) |claim| {
            if (self.best_nick_claims.getPtr(key)) |current| {
                current.* = claim;
                return;
            }
            if (self.best_nick_claims.count() >= self.cfg.max_nicks) {
                self.claim_index_dirty = true;
                return;
            }
            self.best_nick_claims.putNoClobber(key, claim) catch {
                self.claim_index_dirty = true;
            };
        } else {
            _ = self.best_nick_claims.remove(key);
        }
    }

    /// Rebuild the complete bounded index in one roster pass. The dirty flag is
    /// set before clearing and reset only after every indexable roster claim was
    /// folded successfully. On OOM/overflow the partial map remains ignored.
    fn rebuildAllBestNickClaims(self: *Self) bool {
        self.claim_index_dirty = true;
        self.best_nick_claims.clearRetainingCapacity();

        var channels = self.channel_members.iterator();
        while (channels.next()) |entry| {
            for (entry.value_ptr.entries.items) |member| {
                const key = NickKey.init(member.nick) orelse continue;
                const candidate = NickClaim{ .node_id = member.node, .hlc = member.hlc };
                if (self.best_nick_claims.getPtr(key)) |current| {
                    if (candidate.higherPriorityThan(current.*)) current.* = candidate;
                    continue;
                }
                if (self.best_nick_claims.count() >= self.cfg.max_nicks) return false;
                self.best_nick_claims.putNoClobber(key, candidate) catch return false;
            }
        }

        self.claim_index_dirty = false;
        return true;
    }

    /// Deterministic, ASCII-case-insensitive best claim across every roster. The
    /// healthy path is an allocation-free O(1) lookup. Oversized route-table-only
    /// names and any dirty/partial index fall back to the authoritative scan.
    pub fn bestNickClaim(self: *const Self, nick: []const u8) ?NickClaim {
        const key = NickKey.init(nick) orelse return self.projectedIdentityNickClaim(nick);
        if (self.claim_index_dirty) return self.scannedBestNickKey(key);
        return self.best_nick_claims.get(key);
    }

    /// Decide how to apply an incoming REMOTE nick claim `(nick, node, hlc,
    /// account)`, resolving collisions deterministically and never killing:
    ///   * a LOCAL nick of the same name (per `local_nicks`) is authoritative —
    ///     the incoming remote member loses and is renamed to its mesh UID,
    ///     UNLESS both bear the same authenticated account, in which case they are
    ///     the SAME identity and we return `.local_same_account` so the daemon
    ///     reconciles by liveness instead of UID-renaming a logged-in user;
    ///   * an existing REMOTE nick owned by a DIFFERENT node is contested by the
    ///     CRDT-identical `(hlc, node)` tiebreak — the loser (which may be the
    ///     incumbent, handled by the caller's re-apply, or the newcomer) renames
    ///     to its UID; EXCEPT when both bear the same account, where we `.keep`
    ///     and let the `hlc` LWW in `applyMembership` collapse them to one entry;
    ///   * otherwise the wire nick is kept verbatim.
    /// `account` is the incoming claim's authenticated account ("" = none/unknown,
    /// which disables every same-identity short-circuit and preserves the prior
    /// account-blind behaviour for legacy peers).
    /// `account_trusted` is the PER-CLAIM verified bool (Design C): true only when
    /// the caller VERIFIED the claim's residence proof against the receiver-owned
    /// replicated account pubkey (`server.verifyResidenceTrust`) on an
    /// origin-authenticated frame. When false the wire account is untrusted — it is
    /// blanked HERE, centrally, so no same-identity short-circuit can honor a
    /// forged plaintext `account` (F1): unproven claims take the conservative UID
    /// path, exactly the account-blind legacy behaviour.
    pub fn resolveIncomingNick(self: *const Self, nick: []const u8, node: NodeId, hlc: u64, account: []const u8, account_trusted: bool) NickDecision {
        const acct = if (account_trusted) account else "";

        // STICKY TRUST (R1, the liveness/value split): an ESTABLISHED member
        // re-affirming from ITS OWN node is `.keep` — FIRST, and independent of
        // `account_trusted`. The residence proof gates the INITIAL same-account
        // coexist admission only; it must never continuously gate an
        // already-established member, so a re-burst arriving after a proof
        // expired (partition / USR2 / loss delaying the refresh) cannot
        // UID-rename a live member mid-session. Departure stays the local-clock
        // staleness GC (`pruneStale`), which is orthogonal to this decision.
        const incumbent = self.identityNickClaim(nick);
        if (incumbent) |inc| {
            if (inc.node_id == node) return .keep;
        }

        // Cross-namespace: local world wins. A remote member can never take a nick
        // a local client currently holds — but if the remote bears the SAME
        // authenticated account as the local holder, it is the same logged-in
        // identity (a duplicate session across the mesh), not a stranger. Defer to
        // the daemon rather than minting a UID for a real user.
        if (self.local_nicks) |resolver| {
            if (resolver.held(nick)) {
                if (sameAccount(acct, resolver.account(nick))) {
                    // Same identity. If the local holder's claim is KNOWN and
                    // strictly older than this one, the local session is the stale
                    // ghost → ask the daemon to retire it. Otherwise (newer, equal,
                    // or unknown=0) keep the live local session and drop the remote.
                    const local_hlc = resolver.holderHlc(nick);
                    if (local_hlc != 0 and hlc > local_hlc) return .reclaim_local;
                    return .local_same_account;
                }
                return .{ .rename_to_uid = nick_collision.loserUid(node, nick) };
            }
        }

        // Cross-node remote contest: a different node only displaces the
        // newcomer when the newcomer does NOT win the deterministic tiebreak.
        // (A same-node incumbent already returned `.keep` above.)
        if (incumbent) |inc| {
            // Same authenticated account on a different node = the SAME identity
            // moved/duplicated across the mesh, not two strangers. Accept the wire
            // nick and let `applyMembership`'s hlc LWW collapse the two claims onto
            // the newer one — and signal the caller NOT to displace the incumbent
            // (a UID phantom for a logged-in user is exactly what we avoid).
            if (sameAccount(acct, if (inc.account.len != 0) inc.account else null)) return .remote_same_account;
            const newcomer = nick_collision.Claim{ .node_id = node, .hlc = hlc, .account = acct };
            if (!nick_collision.candidateWins(newcomer, inc)) {
                return .{ .rename_to_uid = nick_collision.loserUid(node, nick) };
            }
            // Newcomer wins: the incumbent is the loser. The caller renames the
            // incumbent (see s2s_peer.displaceIncumbent) so it converges to ITS
            // own UID; the newcomer keeps the contested nick.
        }
        return .keep;
    }

    /// The stable mesh UID the EXISTING holder of `nick` (an incumbent that just
    /// lost a contest to a higher-priority newcomer) must be renamed to. Derived
    /// from the incumbent's owning node, so every node computes the same loser
    /// name. Returns null when no remote member currently holds `nick`.
    pub fn incumbentLoserUid(self: *const Self, nick: []const u8) ?nick_collision.Uid {
        const incumbent = self.identityNickClaim(nick) orelse return null;
        return nick_collision.loserUid(incumbent.node_id, nick);
    }

    /// Resolve the stable UID under which this origin's earlier wire nick was
    /// actually stored after losing a collision. PART is channel-scoped, so only
    /// accept an alias row owned by the same origin in the requested channel.
    pub fn channelLoserUid(self: *const Self, channel: []const u8, node: NodeId, wire_nick: []const u8) ?nick_collision.Uid {
        const uid = nick_collision.loserUid(node, wire_nick);
        const members = self.channelMembers(channel);
        for (members) |member| {
            if (member.node == node and std.ascii.eqlIgnoreCase(member.nick, &uid)) return uid;
        }
        return null;
    }

    /// Resolve a prior loser UID for a same-origin NICK change across any roster.
    /// Checking the stored row prevents a peer from manufacturing an arbitrary UID
    /// alias and prevents one origin from renaming another origin's collision row.
    pub fn storedLoserUid(self: *const Self, node: NodeId, wire_nick: []const u8) ?nick_collision.Uid {
        const uid = nick_collision.loserUid(node, wire_nick);
        var it = @constCast(&self.channel_members).valueIterator();
        while (it.next()) |list| {
            for (list.entries.items) |member| {
                if (member.node == node and std.ascii.eqlIgnoreCase(member.nick, &uid)) return uid;
            }
        }
        return null;
    }

    /// Bind (or clear) receiver-owned exact-token metadata on every roster row
    /// that represents `wire_nick` from `node`. Collision losers are stored under
    /// a deterministic UID, so match that receiver-derived alias as well. This is
    /// deliberately separate from `applyMembership`: an OFFER may arrive after a
    /// compatibility roster row and must be able to tag it retroactively.
    pub fn rebindSessionToken(
        self: *Self,
        node: NodeId,
        wire_nick: []const u8,
        token: ?SessionToken,
    ) Error!usize {
        try self.validateName(wire_nick);
        try validateNode(node);
        const uid = nick_collision.loserUid(node, wire_nick);
        var changed: usize = 0;
        var it = self.channel_members.valueIterator();
        while (it.next()) |list| {
            for (list.entries.items) |*member| {
                if (member.node != node) continue;
                if (!std.ascii.eqlIgnoreCase(member.nick, wire_nick) and
                    !std.ascii.eqlIgnoreCase(member.nick, &uid)) continue;
                if (optionalSessionTokenEql(member.session_token, token)) continue;
                member.session_token = token;
                changed += 1;
            }
        }
        return changed;
    }

    /// Apply a Store-authorized wire rename to an identity that may have arrived
    /// before receiver token tagging. All roster/route strings and the owned
    /// observer delta are allocated first; binding and rename then commit
    /// together. OOM therefore leaves both the old spelling and token tags intact.
    pub fn renameNickBindingSessionToken(
        self: *Self,
        node: NodeId,
        old_nick: []const u8,
        new_nick: []const u8,
        token: SessionToken,
        ident: MemberIdentity,
        observer: ?SessionTokenReconcileObserver,
    ) Error!bool {
        return self.renameSessionTokenRows(token, node, old_nick, new_nick, observer, ident, true);
    }

    /// Atomically move a Store-authorized exact identity onto `new_nick` while
    /// displacing that nick's foreign incumbent to its deterministic UID. Every
    /// roster string and route key is staged before mutation; token binding is
    /// part of the same no-fail commit. A collision, bound mismatch, route-table
    /// limit, or OOM therefore leaves both identities and all routes unchanged.
    /// Client-visible deltas are intentionally owned by the caller, which must
    /// stage them before invoking this transaction and publish them only after a
    /// true result.
    pub fn renameNickBindingSessionTokenDisplacing(
        self: *Self,
        node: NodeId,
        old_nick: []const u8,
        new_nick: []const u8,
        token: SessionToken,
        ident: MemberIdentity,
        incumbent_node: NodeId,
        incumbent_uid: []const u8,
    ) Error!bool {
        try self.validateName(new_nick);
        try self.validateName(incumbent_uid);
        try validateNode(node);
        try validateNode(incumbent_node);
        if (node == incumbent_node) return false;

        const old_home = self.nick_to_node.get(old_nick);
        if (old_home) |home| if (home != node) return false;
        const target_home = self.nick_to_node.get(new_nick) orelse return false;
        if (target_home != incumbent_node) return false;
        const uid_home = self.nick_to_node.get(incumbent_uid);
        if (uid_home) |home| if (home != incumbent_node) return false;

        var exact_count: usize = 0;
        var incumbent_count: usize = 0;
        var lists = self.channel_members.valueIterator();
        while (lists.next()) |list| {
            for (list.entries.items) |*member| {
                const is_exact_old = member.node == node and std.ascii.eqlIgnoreCase(member.nick, old_nick);
                const is_incumbent = member.node == incumbent_node and std.ascii.eqlIgnoreCase(member.nick, new_nick);

                if (is_exact_old) {
                    if (member.session_token) |stored| {
                        if (!std.crypto.timing_safe.eql(SessionToken, stored, token)) return false;
                    }
                    exact_count += 1;
                    continue;
                }
                if (is_incumbent) {
                    incumbent_count += 1;
                    continue;
                }

                // Both destinations must be vacant after removing precisely the
                // two planned source identities. Never fold an unrelated alias
                // or a contradictory same-node row into the transaction.
                if (std.ascii.eqlIgnoreCase(member.nick, new_nick) or
                    std.ascii.eqlIgnoreCase(member.nick, incumbent_uid)) return false;
            }
        }
        if (exact_count == 0 or incumbent_count == 0) return false;

        var exact_nicks: std.ArrayListUnmanaged([]u8) = .empty;
        var exact_transferred: usize = 0;
        defer {
            for (exact_nicks.items[exact_transferred..]) |owned| self.allocator.free(owned);
            exact_nicks.deinit(self.allocator);
        }
        try exact_nicks.ensureTotalCapacity(self.allocator, exact_count);
        for (0..exact_count) |_| exact_nicks.appendAssumeCapacity(try self.allocator.dupe(u8, new_nick));

        const OwnedIdentity = struct {
            username: []u8,
            realname: []u8,
            host: []u8,
            account: []u8,

            fn init(allocator: std.mem.Allocator, identity: MemberIdentity) std.mem.Allocator.Error!@This() {
                const username = try allocator.dupe(u8, identity.username);
                errdefer allocator.free(username);
                const realname = try allocator.dupe(u8, identity.realname);
                errdefer allocator.free(realname);
                const host = try allocator.dupe(u8, identity.host);
                errdefer allocator.free(host);
                const account = try allocator.dupe(u8, identity.account);
                return .{ .username = username, .realname = realname, .host = host, .account = account };
            }

            fn deinit(owned: *@This(), allocator: std.mem.Allocator) void {
                allocator.free(owned.username);
                allocator.free(owned.realname);
                allocator.free(owned.host);
                allocator.free(owned.account);
                owned.* = undefined;
            }
        };
        var exact_identities: std.ArrayListUnmanaged(OwnedIdentity) = .empty;
        var identities_transferred: usize = 0;
        defer {
            for (exact_identities.items[identities_transferred..]) |*owned| owned.deinit(self.allocator);
            exact_identities.deinit(self.allocator);
        }
        try exact_identities.ensureTotalCapacity(self.allocator, exact_count);
        for (0..exact_count) |_| exact_identities.appendAssumeCapacity(try OwnedIdentity.init(self.allocator, ident));

        var incumbent_nicks: std.ArrayListUnmanaged([]u8) = .empty;
        var incumbent_transferred: usize = 0;
        defer {
            for (incumbent_nicks.items[incumbent_transferred..]) |owned| self.allocator.free(owned);
            incumbent_nicks.deinit(self.allocator);
        }
        try incumbent_nicks.ensureTotalCapacity(self.allocator, incumbent_count);
        for (0..incumbent_count) |_| incumbent_nicks.appendAssumeCapacity(try self.allocator.dupe(u8, incumbent_uid));

        const remove_old_route = old_home != null;
        const install_uid_route = uid_home == null;
        const projected_count = self.nick_count - @as(usize, @intFromBool(remove_old_route)) - 1 + 1 + @as(usize, @intFromBool(install_uid_route));
        if (projected_count > self.cfg.max_nicks) return error.RouteTableFull;

        // Reserve for both no-clobber inserts while the old keys are still
        // present. This may over-reserve, but guarantees the commit cannot OOM.
        try self.nick_to_node.ensureUnusedCapacity(2);
        if (!self.claim_index_dirty) try self.best_nick_claims.ensureUnusedCapacity(3);
        const owned_target_key = try self.allocator.dupe(u8, new_nick);
        var target_key_transferred = false;
        defer if (!target_key_transferred) self.allocator.free(owned_target_key);
        var owned_uid_key: ?[]u8 = null;
        if (install_uid_route) owned_uid_key = try self.allocator.dupe(u8, incumbent_uid);
        var uid_key_transferred = false;
        defer if (owned_uid_key) |owned| if (!uid_key_transferred) self.allocator.free(owned);

        var next_exact: usize = 0;
        var next_incumbent: usize = 0;
        lists = self.channel_members.valueIterator();
        while (lists.next()) |list| {
            for (list.entries.items) |*member| {
                if (member.node == node and std.ascii.eqlIgnoreCase(member.nick, old_nick)) {
                    self.allocator.free(member.nick);
                    member.nick = exact_nicks.items[next_exact];
                    next_exact += 1;
                    exact_transferred = next_exact;
                    member.session_token = token;
                    self.allocator.free(member.username);
                    self.allocator.free(member.realname);
                    self.allocator.free(member.host);
                    self.allocator.free(member.account);
                    const owned_ident = exact_identities.items[next_exact - 1];
                    member.username = owned_ident.username;
                    member.realname = owned_ident.realname;
                    member.host = owned_ident.host;
                    member.account = owned_ident.account;
                    identities_transferred = next_exact;
                } else if (member.node == incumbent_node and std.ascii.eqlIgnoreCase(member.nick, new_nick)) {
                    self.allocator.free(member.nick);
                    member.nick = incumbent_nicks.items[next_incumbent];
                    next_incumbent += 1;
                    incumbent_transferred = next_incumbent;
                }
            }
        }
        std.debug.assert(next_exact == exact_count);
        std.debug.assert(next_incumbent == incumbent_count);

        if (remove_old_route) {
            const removed = self.nick_to_node.fetchRemove(old_nick).?;
            self.allocator.free(removed.key);
        }
        const removed_target = self.nick_to_node.fetchRemove(new_nick).?;
        self.allocator.free(removed_target.key);
        self.nick_to_node.putNoClobber(owned_target_key, node) catch unreachable;
        target_key_transferred = true;
        if (install_uid_route) {
            self.nick_to_node.putNoClobber(owned_uid_key.?, incumbent_node) catch unreachable;
            uid_key_transferred = true;
        }
        self.nick_count = projected_count;

        const old_key = NickKey.init(old_nick);
        const target_key = NickKey.init(new_nick);
        const uid_key = NickKey.init(incumbent_uid);
        if (old_key) |key| self.reselectBestNickKey(key);
        if (!self.claim_index_dirty) if (target_key) |key| self.reselectBestNickKey(key);
        if (!self.claim_index_dirty) if (uid_key) |key| self.reselectBestNickKey(key);
        return true;
    }

    /// Resolve the receiver-owned exact token attached to one origin/nick
    /// identity. Collision aliases derived from `wire_nick` are included. A
    /// contradictory set of token tags is explicit ambiguity and must be denied
    /// by callers before applying a peer-controlled NICKCHANGE.
    pub fn sessionTokenForOriginNick(self: *const Self, node: NodeId, wire_nick: []const u8) SessionTokenNickMatch {
        const uid = nick_collision.loserUid(node, wire_nick);
        var found: ?SessionToken = null;
        var it = @constCast(&self.channel_members).valueIterator();
        while (it.next()) |list| {
            for (list.entries.items) |member| {
                if (member.node != node) continue;
                if (!std.ascii.eqlIgnoreCase(member.nick, wire_nick) and
                    !std.ascii.eqlIgnoreCase(member.nick, &uid)) continue;
                const token = member.session_token orelse continue;
                if (found) |existing| {
                    if (!std.crypto.timing_safe.eql(SessionToken, existing, token)) return .ambiguous;
                } else {
                    found = token;
                }
            }
        }
        return if (found) |token| .{ .unique = token } else .none;
    }

    /// Reconcile compatibility-roster rows for exactly one signed logical
    /// session. Desired-channel rows with an obsolete identity are renamed first
    /// (one observer event per origin/old-nick identity); rows outside the desired
    /// channels are then removed (one observer event per row).
    /// `desired_nick=null` means no live Store projection (REVOKE/quarantine) and
    /// therefore removes every row carrying the exact token. Rows without a
    /// receiver-derived token, or bearing any other token, are never touched.
    ///
    /// Every observer callback runs before its corresponding mutation. A callback
    /// or rename-plan allocation failure returns an error with that row/identity
    /// still present, so callers can retry without losing the client-visible
    /// PART/NICK event. Earlier successful mutations remain valid progress and
    /// cannot be emitted twice on the retry.
    pub fn reconcileSessionToken(
        self: *Self,
        token: SessionToken,
        desired_nick: ?[]const u8,
        desired_channels: []const []const u8,
    ) Error!SessionTokenReconcileResult {
        return self.reconcileSessionTokenObserved(token, desired_nick, desired_channels, null);
    }

    pub fn reconcileSessionTokenObserved(
        self: *Self,
        token: SessionToken,
        desired_nick: ?[]const u8,
        desired_channels: []const []const u8,
        observer: ?SessionTokenReconcileObserver,
    ) Error!SessionTokenReconcileResult {
        var result = SessionTokenReconcileResult{};
        var local_canonical_exact = false;
        if (desired_nick) |nick| {
            try self.validateName(nick);
            if (self.local_nicks) |resolver| {
                if (resolver.held(nick)) {
                    if (resolver.sessionToken(nick)) |local_token| {
                        local_canonical_exact = std.crypto.timing_safe.eql(SessionToken, local_token, token);
                    }
                }
            }
        }

        // Rename every obsolete identity before removing stale channels. This
        // preserves IRC ordering: clients see one global NICK, followed by any
        // PARTs for channels absent from the new signed snapshot. When the exact
        // canonical session is already LOCAL, every remote row is a compatibility
        // duplicate and is merged by observed removal below. Renaming it would
        // produce a NICK the daemon must suppress because the target is occupied,
        // leaving incremental clients with the UID zombie.
        if (desired_nick) |nick| if (!local_canonical_exact) {
            while (true) {
                var candidate_node: ?NodeId = null;
                var candidate_old: ?[]const u8 = null;
                var channels = self.channel_members.iterator();
                find_candidate: while (channels.next()) |entry| {
                    if (!channelInSet(entry.key_ptr.*, desired_channels)) continue;
                    for (entry.value_ptr.entries.items) |*member| {
                        const stored = member.session_token orelse continue;
                        if (!std.crypto.timing_safe.eql(SessionToken, stored, token)) continue;
                        const uid = nick_collision.loserUid(member.node, nick);
                        if (std.ascii.eqlIgnoreCase(member.nick, nick)) continue;
                        if (std.ascii.eqlIgnoreCase(member.nick, &uid)) {
                            var target_uid: nick_collision.Uid = undefined;
                            const target = self.reconciledNickTarget(token, member.node, nick, &target_uid);
                            // A genuinely contested alias remains the safe wire
                            // identity. If the canonical row carries this same
                            // exact token, the removal pass below collapses the
                            // duplicate instead of issuing an impossible NICK.
                            if (std.ascii.eqlIgnoreCase(target, &uid)) continue;
                        }
                        candidate_node = member.node;
                        candidate_old = member.nick;
                        break :find_candidate;
                    }
                }
                const node = candidate_node orelse break;
                const old_nick = candidate_old.?;
                var target_uid: nick_collision.Uid = undefined;
                const target = self.reconciledNickTarget(token, node, nick, &target_uid);
                if (try self.renameSessionTokenRows(token, node, old_nick, target, observer, null, false)) {
                    result.renamed += 1;
                } else {
                    // A target collision that cannot be represented safely is an
                    // incomplete reconcile, never permission to delete the row.
                    return error.RouteTableFull;
                }
            }
        };

        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            const list = entry.value_ptr;
            var i: usize = 0;
            while (i < list.entries.items.len) {
                const member = &list.entries.items[i];
                const stored = member.session_token orelse {
                    i += 1;
                    continue;
                };
                if (!std.crypto.timing_safe.eql(SessionToken, stored, token)) {
                    i += 1;
                    continue;
                }
                const nick_matches = if (desired_nick) |nick| matches: {
                    if (local_canonical_exact) break :matches false;
                    if (std.ascii.eqlIgnoreCase(member.nick, nick)) break :matches true;
                    // Collision losers are stored under a deterministic alias
                    // derived by this receiver from the authoritative real nick
                    // and origin. Retain it only while the canonical spelling is
                    // genuinely unavailable. If this channel already has the
                    // same exact token under the canonical nick, the UID is a
                    // duplicate projection and must be retired with an observed
                    // PART so incremental clients converge with NAMES.
                    const uid = nick_collision.loserUid(member.node, nick);
                    if (!std.ascii.eqlIgnoreCase(member.nick, &uid)) break :matches false;
                    if (list.find(nick)) |canonical_idx| {
                        const canonical_token = list.entries.items[canonical_idx].session_token;
                        if (canonical_token) |other| {
                            if (std.crypto.timing_safe.eql(SessionToken, other, token)) break :matches false;
                        }
                    }
                    break :matches true;
                } else false;
                if (nick_matches and channelInSet(entry.key_ptr.*, desired_channels)) {
                    i += 1;
                    continue;
                }

                if (observer) |sink| try sink.part(entry.key_ptr.*, member);

                const claim_key = NickKey.init(member.nick);
                const route_points_at_removed = self.nickNode(member.nick) == member.node;
                const last_occurrence = self.memberNickOccurrences(member.nick) == 1;
                // If this is the last roster occurrence, retire its best-effort
                // nick route before freeing the only remaining spelling. If the
                // route points at this row but another exact nick survives, clear
                // the stale home now and re-home it to the best survivor below.
                if (last_occurrence or route_points_at_removed) _ = self.removeNick(member.nick);
                member.freeStrings(self.allocator);
                _ = list.entries.swapRemove(i);
                result.removed += 1;
                if (claim_key) |key| {
                    self.reselectBestNickKey(key);
                    if (!last_occurrence and route_points_at_removed) {
                        if (self.bestMemberForNickKey(key)) |survivor|
                            self.setNickLocation(survivor.nick, survivor.node) catch {};
                    }
                }
            }
        }

        // Map mutation cannot occur during the iterator above. Prune empty
        // rosters afterward, one at a time, using the existing ownership helper.
        while (true) {
            var empty: ?[]const u8 = null;
            var empties = self.channel_members.iterator();
            while (empties.next()) |entry| {
                if (entry.value_ptr.entries.items.len == 0) {
                    empty = entry.key_ptr.*;
                    break;
                }
            }
            if (empty) |channel| self.pruneIfEmpty(channel) else break;
        }
        return result;
    }

    /// Choose the collision-safe stored spelling for an authoritative real nick.
    /// An already-stored UID alias is accepted by the caller before this helper;
    /// this path is for an obsolete old identity moving to the new authority.
    fn reconciledNickTarget(self: *const Self, token: SessionToken, node: NodeId, desired_nick: []const u8, uid_out: *nick_collision.Uid) []const u8 {
        var contested = if (self.nick_to_node.get(desired_nick)) |home| home != node else false;
        if (!contested) {
            var it = @constCast(&self.channel_members).valueIterator();
            outer: while (it.next()) |list| {
                for (list.entries.items) |member| {
                    if (member.node != node and std.ascii.eqlIgnoreCase(member.nick, desired_nick)) {
                        contested = true;
                        break :outer;
                    }
                }
            }
        }
        if (!contested) {
            if (self.local_nicks) |resolver| {
                contested = resolver.held(desired_nick);
                if (contested) {
                    if (resolver.sessionToken(desired_nick)) |local_token| {
                        if (std.crypto.timing_safe.eql(SessionToken, local_token, token)) contested = false;
                    }
                }
            }
        }
        if (!contested) return desired_nick;
        uid_out.* = nick_collision.loserUid(node, desired_nick);
        return uid_out;
    }

    /// Transactionally rename every exact-token row for one stored identity.
    /// All route/roster strings and observer-owned delta state are allocated
    /// before any RouteTable mutation; the commit phase itself cannot fail.
    fn renameSessionTokenRows(
        self: *Self,
        token: SessionToken,
        node: NodeId,
        old_nick: []const u8,
        new_nick: []const u8,
        observer: ?SessionTokenReconcileObserver,
        ident: ?MemberIdentity,
        bind_untagged: bool,
    ) Error!bool {
        try self.validateName(new_nick);
        const stable_old_nick = try self.allocator.dupe(u8, old_nick);
        defer self.allocator.free(stable_old_nick);
        var count: usize = 0;
        var representative: ?*const Member = null;
        var lists = self.channel_members.valueIterator();
        while (lists.next()) |list| {
            for (list.entries.items) |*member| {
                if (member.node != node or !std.ascii.eqlIgnoreCase(member.nick, stable_old_nick)) continue;
                if (member.session_token) |stored| {
                    if (!std.crypto.timing_safe.eql(SessionToken, stored, token)) {
                        if (bind_untagged) return false;
                        continue;
                    }
                } else if (!bind_untagged) continue;
                // Never create two same-spelling rows in one channel. Target
                // selection normally prevents this; retain old state if a
                // contradictory roster already occupies the destination.
                if (list.find(new_nick)) |idx| {
                    if (&list.entries.items[idx] != member) return false;
                }
                representative = representative orelse member;
                count += 1;
            }
        }
        if (count == 0) return false;

        var owned_nicks: std.ArrayListUnmanaged([]u8) = .empty;
        var transferred_nicks: usize = 0;
        defer {
            for (owned_nicks.items[transferred_nicks..]) |owned| self.allocator.free(owned);
            owned_nicks.deinit(self.allocator);
        }
        try owned_nicks.ensureTotalCapacity(self.allocator, count);
        for (0..count) |_| owned_nicks.appendAssumeCapacity(try self.allocator.dupe(u8, new_nick));

        const old_route_home = self.nick_to_node.get(stable_old_nick);
        const remove_old_route = old_route_home != null and old_route_home.? == node;
        const new_route_home = self.nick_to_node.get(new_nick);
        if (new_route_home != null and new_route_home.? != node) return false;
        const install_new_route = new_route_home == null and (remove_old_route or self.nick_count < self.cfg.max_nicks);
        var owned_route_key: ?[]u8 = null;
        if (install_new_route) {
            try self.nick_to_node.ensureUnusedCapacity(1);
            owned_route_key = try self.allocator.dupe(u8, new_nick);
        }
        defer if (owned_route_key) |owned| self.allocator.free(owned);

        const member = representative.?;
        if (observer) |sink| try sink.rename(stable_old_nick, new_nick, member);

        var next_owned: usize = 0;
        lists = self.channel_members.valueIterator();
        while (lists.next()) |list| {
            for (list.entries.items) |*row| {
                if (row.node != node or !std.ascii.eqlIgnoreCase(row.nick, stable_old_nick)) continue;
                if (row.session_token) |stored| {
                    if (!std.crypto.timing_safe.eql(SessionToken, stored, token)) continue;
                } else if (!bind_untagged) continue;
                self.allocator.free(row.nick);
                row.nick = owned_nicks.items[next_owned];
                next_owned += 1;
                transferred_nicks = next_owned;
                if (bind_untagged) row.session_token = token;
                if (ident) |identity| {
                    // Token installation and the spelling change are the
                    // authoritative atomic state. Identity refresh retains the
                    // established best-effort semantics of wire NICKCHANGE.
                    replaceOwned(self.allocator, &row.username, identity.username) catch {};
                    replaceOwned(self.allocator, &row.realname, identity.realname) catch {};
                    replaceOwned(self.allocator, &row.host, identity.host) catch {};
                    replaceOwned(self.allocator, &row.account, identity.account) catch {};
                }
            }
        }
        std.debug.assert(next_owned == count);

        var old_route_removed = false;
        if (remove_old_route) {
            const removed = self.nick_to_node.fetchRemove(stable_old_nick).?;
            self.allocator.free(removed.key);
            old_route_removed = true;
        }
        if (install_new_route) {
            const key = owned_route_key.?;
            self.nick_to_node.putNoClobber(key, node) catch unreachable;
            owned_route_key = null;
        }
        if (old_route_removed and !install_new_route) self.nick_count -= 1;
        if (!old_route_removed and install_new_route) self.nick_count += 1;

        const old_key = NickKey.init(stable_old_nick);
        const new_key = NickKey.init(new_nick);
        if (old_key) |key| self.reselectBestNickKey(key);
        if (!self.claim_index_dirty) {
            if (new_key) |key| {
                if (old_key == null or !std.meta.eql(old_key.?, key)) self.reselectBestNickKey(key);
            }
        }
        return true;
    }

    fn memberNickOccurrences(self: *const Self, nick: []const u8) usize {
        var count: usize = 0;
        var it = @constCast(&self.channel_members).valueIterator();
        while (it.next()) |list| {
            for (list.entries.items) |member| {
                if (!std.ascii.eqlIgnoreCase(member.nick, nick)) continue;
                count += 1;
            }
        }
        return count;
    }

    fn bestMemberForNickKey(self: *const Self, key: NickKey) ?Member {
        const best = self.scannedBestNickKey(key) orelse return null;
        var it = @constCast(&self.channel_members).valueIterator();
        while (it.next()) |list| {
            for (list.entries.items) |member| {
                const member_key = NickKey.init(member.nick) orelse continue;
                if (!std.meta.eql(member_key, key)) continue;
                if (member.node == best.node_id and member.hlc == best.hlc) return member;
            }
        }
        return null;
    }

    pub fn channelNodes(self: *const Self, chan: []const u8, out: []NodeId) Error!usize {
        try self.validateName(chan);
        const state = self.channels.getPtr(chan) orelse return 0;
        return state.copyNodes(out);
    }

    pub fn updateOnMembershipChange(
        self: *Self,
        chan: []const u8,
        node: NodeId,
        change: MembershipChange,
    ) Error!void {
        switch (change) {
            .join => try self.addChannelMember(chan, node),
            .part => self.removeChannelMember(chan, node),
        }
    }

    pub fn addChannelMember(self: *Self, chan: []const u8, node: NodeId) Error!void {
        try self.validateName(chan);
        try validateNode(node);

        if (self.channels.getPtr(chan)) |state| {
            try state.addMember(node);
            return;
        }

        if (self.channel_count == self.cfg.max_channels) return error.RouteTableFull;

        var state = try ChannelState.init(self.allocator, self.cfg.max_nodes_per_channel);
        errdefer state.deinit(self.allocator);
        try state.addMember(node);

        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, state);
        self.channel_count += 1;
    }

    pub fn removeChannelMember(self: *Self, chan: []const u8, node: NodeId) void {
        const entry = self.channels.getEntry(chan) orelse return;
        entry.value_ptr.removeMember(node);
        if (entry.value_ptr.len != 0) return;

        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
        self.channel_count -= 1;
    }

    /// Idempotently set whether `node` appears in `chan`'s node-set, INDEPENDENT
    /// of the join/part refcount that `addChannelMember`/`removeChannelMember`
    /// track. A caller that recomputes presence from scratch on every event
    /// (anti-entropy route refresh) needs "present exactly once" / "absent"
    /// convergence, not an accumulating refcount — and, critically, it must
    /// touch ONLY this per-channel node-set, never the authoritative
    /// `channel_members`/`nick_to_node` maps that `removeNode` also clears.
    pub fn setChannelNodePresence(self: *Self, chan: []const u8, node: NodeId, present: bool) Error!void {
        try self.validateName(chan);
        try validateNode(node);

        if (present) {
            // Add only when absent, so repeated refreshes never inflate the
            // node's refcount past one (which a later single clear could not undo).
            if (self.channels.getPtr(chan)) |state| {
                if (state.find(node) != null) return;
            }
            try self.addChannelMember(chan, node);
            return;
        }

        // Full, refcount-agnostic removal: the refresh recomputed this node as
        // no-longer-live, so it leaves the set regardless of any prior count.
        const entry = self.channels.getEntry(chan) orelse return;
        entry.value_ptr.removeNode(node);
        if (entry.value_ptr.len != 0) return;

        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
        self.channel_count -= 1;
    }

    /// Outcome of `applyMembership`, so the caller can emit the matching live IRC
    /// surface (a remote `JOIN`/`PART` to local channel members). `unchanged`
    /// covers stale events and re-affirmations of an existing member (so the
    /// periodic anti-entropy re-burst never produces a duplicate JOIN).
    pub const ApplyOutcome = enum { joined, parted, status_changed, unchanged };

    /// Outcome plus the member's previous status bits, so the caller can emit a
    /// precise MODE diff (which prefixes were added/removed) for a status change.
    pub const ApplyResult = struct {
        outcome: ApplyOutcome,
        prev_status: u4 = 0,
    };

    pub const ApplyListOutcome = enum { added, removed, unchanged };

    pub const ApplyListResult = struct {
        outcome: ApplyListOutcome,
    };

    /// Apply a MEMBERSHIP event for a remote member, last-writer-wins by `hlc`.
    /// `present` true = join/status upsert; false = part. Stale events (hlc <= the
    /// stored one for this nick) are ignored, so out-of-order gossip converges.
    /// PART events also stamp an origin-scoped LWW tombstone so a reordered older
    /// JOIN cannot resurrect a member after its PART (see `channel_part_tombs`).
    /// `ident` carries the member's propagated username/realname/visible-host;
    /// on a newer event the stored identity is replaced (LWW, like the status).
    /// Also maintains the `nick_to_node` routing index (so `nickNode` resolves the
    /// remote nick for PRIVMSG relay): a present apply upserts the location, a part
    /// drops it once the nick is absent from every channel roster.
    /// `now_ms` is the RECEIVER's local monotonic clock at apply time; on every
    /// PRESENT apply (join/status/re-affirm) it stamps the member's
    /// `last_refreshed_ms` so `pruneStale` can age the member out against this
    /// node's own clock. It does NOT participate in LWW ordering (that stays `hlc`).
    pub fn applyMembership(
        self: *Self,
        chan: []const u8,
        nick: []const u8,
        node: NodeId,
        status: u4,
        hlc: u64,
        present: bool,
        ident: MemberIdentity,
        now_ms: i64,
    ) Error!ApplyResult {
        try self.validateName(chan);
        try self.validateName(nick);
        try validateNode(node);

        const list = try self.ensureMemberList(chan);
        // A PART is origin-owned. If the wire nick currently names another
        // node's row, never delete it; only follow this origin's deterministic
        // loser UID in the same channel. This closes the authenticated
        // cross-origin deletion path while preserving collision cleanup.
        if (!present) {
            if (list.find(nick)) |idx| {
                if (list.entries.items[idx].node != node) {
                    const uid = nick_collision.loserUid(node, nick);
                    if (list.find(&uid)) |uid_idx| {
                        if (list.entries.items[uid_idx].node == node)
                            return self.applyMembership(chan, &uid, node, status, hlc, false, ident, now_ms);
                    }
                    // Still record an origin-scoped PART tombstone under the wire
                    // nick so a reordered older JOIN from THIS origin cannot land
                    // later under the real nick after the UID path is gone.
                    try self.notePartTombstone(chan, nick, node, hlc, now_ms);
                    return .{ .outcome = .unchanged };
                }
            }
        }
        if (list.find(nick)) |idx| {
            const cur = &list.entries.items[idx];
            const prev = cur.status;
            // A PRESENT event for an already-known member is itself the liveness
            // signal we prune against, so refresh the local last-seen stamp
            // unconditionally — even for a stale-hlc re-affirmation that the LWW
            // guard below collapses to `unchanged`. This is the anti-entropy
            // re-burst keeping a still-present member alive; it must not depend on
            // the hlc advancing. Stamped before the LWW early-return; never touched
            // for a part (present=false), whose retraction is what we want to age.
            if (present) cur.last_refreshed_ms = now_ms;
            if (hlc <= cur.hlc) return .{ .outcome = .unchanged, .prev_status = prev }; // stale
            if (present) {
                const changed = cur.status != status or cur.node != node;
                try replaceOwned(self.allocator, &cur.username, ident.username);
                try replaceOwned(self.allocator, &cur.realname, ident.realname);
                try replaceOwned(self.allocator, &cur.host, ident.host);
                try replaceOwned(self.allocator, &cur.account, ident.account);
                try replaceOwned(self.allocator, &cur.real_host, ident.real_host);
                try replaceOwned(self.allocator, &cur.certfp, ident.certfp);
                cur.session_token = ident.session_token;
                cur.node = node;
                cur.status = status;
                cur.hlc = hlc;
                // A newer JOIN supersedes any PART tombstone for this origin/nick.
                self.clearPartTombstone(chan, nick, node);
                // Keep the nick->node routing index in sync so PRIVMSG relay can
                // resolve this remote nick (best-effort: a full index degrades to
                // NAMES/WHOIS-only, never breaks membership). Re-run even on a
                // re-affirmation so entries predating this wiring self-heal.
                self.setNickLocation(nick, node) catch {};
                self.noteBestNickClaim(nick, .{ .node_id = node, .hlc = hlc });
                return .{ .outcome = if (changed) .status_changed else .unchanged, .prev_status = prev };
            } else {
                const claim_key = NickKey.init(cur.nick);
                // Tombstone BEFORE free/remove so a reordered older JOIN cannot
                // re-insert once the live row is gone.
                try self.notePartTombstone(chan, nick, node, hlc, now_ms);
                cur.freeStrings(self.allocator);
                _ = list.entries.swapRemove(idx);
                self.pruneIfEmpty(chan);
                // Drop the nick->node route only when the member is gone from EVERY
                // known channel; channel membership is the only mesh-wide nick
                // replication, so a still-present membership keeps the route alive.
                if (self.findMember(nick) == null) _ = self.removeNick(nick);
                if (claim_key) |key| self.reselectBestNickKey(key);
                return .{ .outcome = .parted, .prev_status = prev };
            }
        }
        if (!present) {
            // If the JOIN side of this remote member lost a local/cross-node nick
            // contest, it was stored under its deterministic loser UID. The peer's
            // later PART still names the user's real nick, so remove the UID entry
            // too; otherwise identified/duplicate-session cleanup leaves a phantom
            // UID nick in NAMES until stale GC runs.
            const uid = nick_collision.loserUid(node, nick);
            if (list.find(uid[0..])) |idx| {
                const cur = &list.entries.items[idx];
                if (cur.node == node) {
                    const prev = cur.status;
                    if (hlc <= cur.hlc) return .{ .outcome = .unchanged, .prev_status = prev };
                    const claim_key = NickKey.init(cur.nick);
                    // Tombstone both the wire nick and the UID alias so either
                    // spelling of a reordered older JOIN is blocked.
                    try self.notePartTombstone(chan, nick, node, hlc, now_ms);
                    try self.notePartTombstone(chan, uid[0..], node, hlc, now_ms);
                    cur.freeStrings(self.allocator);
                    _ = list.entries.swapRemove(idx);
                    self.pruneIfEmpty(chan);
                    if (self.findMember(uid[0..]) == null) _ = self.removeNick(uid[0..]);
                    if (claim_key) |key| self.reselectBestNickKey(key);
                    return .{ .outcome = .parted, .prev_status = prev };
                }
            }
            // Unknown member PART: still stamp the origin-scoped tombstone so a
            // reordered older JOIN for the same origin cannot resurrect later.
            try self.notePartTombstone(chan, nick, node, hlc, now_ms);
            // ensureMemberList may have created an empty roster solely for this
            // lookup — drop it so channelNames does not accumulate hollow keys.
            self.pruneIfEmpty(chan);
            return .{ .outcome = .unchanged };
        }
        // Fresh JOIN: a PART tombstone with equal-or-newer hlc blocks resurrection.
        if (self.partTombstoneBlocks(chan, nick, node, hlc)) {
            return .{ .outcome = .unchanged };
        }
        if (list.entries.items.len >= self.cfg.max_nicks) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned);
        const owned_user = try self.allocator.dupe(u8, ident.username);
        errdefer self.allocator.free(owned_user);
        const owned_real = try self.allocator.dupe(u8, ident.realname);
        errdefer self.allocator.free(owned_real);
        const owned_host = try self.allocator.dupe(u8, ident.host);
        errdefer self.allocator.free(owned_host);
        const owned_account = try self.allocator.dupe(u8, ident.account);
        errdefer self.allocator.free(owned_account);
        const owned_real_host = try self.allocator.dupe(u8, ident.real_host);
        errdefer self.allocator.free(owned_real_host);
        const owned_certfp = try self.allocator.dupe(u8, ident.certfp);
        errdefer self.allocator.free(owned_certfp);
        try list.entries.append(self.allocator, .{
            .nick = owned,
            .username = owned_user,
            .realname = owned_real,
            .host = owned_host,
            .account = owned_account,
            .real_host = owned_real_host,
            .certfp = owned_certfp,
            .session_token = ident.session_token,
            .node = node,
            .status = status,
            .hlc = hlc,
            .last_refreshed_ms = now_ms,
        });
        self.clearPartTombstone(chan, nick, node);
        // Index this newly-learned remote nick for PRIVMSG relay routing
        // (best-effort, see the upsert branch above).
        self.setNickLocation(nick, node) catch {};
        self.noteBestNickClaim(nick, .{ .node_id = node, .hlc = hlc });
        return .{ .outcome = .joined };
    }

    /// Staleness-GC reconciliation: drop every remote member whose local last-seen
    /// stamp (`last_refreshed_ms`) was not refreshed within `window_ms` of `now_ms`
    /// (i.e. `now_ms - last_refreshed_ms > window_ms`), returning the total count
    /// pruned. The mesh anti-entropy re-burst refreshes each PRESENT member's
    /// `last_refreshed_ms` to ~`now` on its cadence, so a member whose stamp is
    /// older than the window is one whose departure (PART/QUIT) never cleanly
    /// propagated — a stale "zombie" projection. This reaps it.
    ///
    /// CLOCK DOMAIN: both `now_ms` and `last_refreshed_ms` are the SAME receiver's
    /// local monotonic clock (server `nowMs()`), so the difference is meaningful.
    /// The member's `hlc` is deliberately NOT used here: it is the *announcing*
    /// node's monotonic clock (time-since-boot, per-machine) and is comparable
    /// across hosts only for last-writer-wins ordering — never against this node's
    /// clock. Comparing the two clock domains would, on a real multi-host mesh with
    /// differing uptimes, either reap every live remote member every cadence or
    /// never reap at all. Stamp and prune both live in the local domain instead.
    ///
    /// Each removed member mirrors the `present=false` (part) branch of
    /// `applyMembership` exactly: free its strings, swapRemove it from the roster,
    /// prune the channel if it emptied, and drop the nick→node route once the nick
    /// is absent from every channel. Removal happens in two passes so the route
    /// drop and channel prune see fully-swept rosters and never invalidate the
    /// channel iterator mid-walk (mirrors `removeNodeMembers`).
    pub fn pruneStale(self: *Self, now_ms: i64, window_ms: i64) usize {
        return self.pruneStaleObserved(now_ms, window_ms, null) catch unreachable;
    }

    /// Observer-aware stale-member repair. Every client-visible PART is queued
    /// before its authoritative roster row is removed, matching the ordering
    /// guarantee of exact-token reconciliation. If the observer cannot retain
    /// the delta, that row remains present for the next maintenance retry.
    pub fn pruneStaleObserved(
        self: *Self,
        now_ms: i64,
        window_ms: i64,
        observer: ?SessionTokenReconcileObserver,
    ) Error!usize {
        // Pass 1: strip stale members from every roster in place (no map mutation),
        // collecting emptied channel keys to prune and the nicks whose routes may
        // now be orphaned. Removed nicks are duped because their owned strings are
        // freed here but the route-drop check in pass 2 still needs the name.
        var pruned: usize = 0;
        var observer_error: ?Error = null;
        var it = self.channel_members.iterator();
        outer: while (it.next()) |entry| {
            const list = entry.value_ptr;
            var i: usize = 0;
            while (i < list.entries.items.len) {
                const m = &list.entries.items[i];
                // Local-clock staleness: a member refreshed within the window (or
                // stamped in the future relative to now) survives; only a frozen,
                // aged local stamp ages out. Both operands are this node's monotonic
                // clock (see the clock-domain note above), so a plain signed
                // difference is correct and overflow-safe for realistic ms values.
                if (now_ms - m.last_refreshed_ms > window_ms) {
                    if (observer) |obs| obs.part(entry.key_ptr.*, m) catch |err| {
                        observer_error = err;
                        break :outer;
                    };
                    // The cached winner may be this row. Mark the optional map
                    // unusable before freeing anything; one authoritative rebuild
                    // after the complete sweep will either restore it atomically
                    // (via the clean flag) or leave scan fallback active.
                    self.claim_index_dirty = true;
                    // Complete this row's transaction before advancing to the
                    // next observer callback. In particular, remove the derived
                    // route while the nick spelling is still borrowed and valid.
                    if (self.memberNickOccurrences(m.nick) == 1) _ = self.removeNick(m.nick);
                    m.freeStrings(self.allocator);
                    _ = list.entries.swapRemove(i);
                    pruned += 1;
                } else i += 1;
            }
        }

        // Prune empty maps after ending the iterator. This cleanup runs even when
        // a later observer callback failed, so every earlier queued departure is
        // paired with a complete authoritative mutation and cannot strand an
        // empty channel or nick route.
        while (true) {
            var empty: ?[]const u8 = null;
            var empties = self.channel_members.iterator();
            while (empties.next()) |entry| {
                if (entry.value_ptr.entries.items.len == 0) {
                    empty = entry.key_ptr.*;
                    break;
                }
            }
            if (empty) |channel| self.pruneIfEmpty(channel) else break;
        }

        if (self.claim_index_dirty) _ = self.rebuildAllBestNickClaims();
        if (observer_error) |err| return err;

        // Pass 2: age origin-scoped PART tombstones in the same receiver-local
        // window. Once the window elapses a re-burst would have re-affirmed any
        // still-present member, so the tombstone is no longer needed to block a
        // reordered older JOIN — and retaining it forever would unbounded-grow
        // under PART churn (CWE-400).
        var tomb_empties: std.ArrayListUnmanaged([]const u8) = .empty;
        defer tomb_empties.deinit(self.allocator);
        var tomb_it = self.channel_part_tombs.iterator();
        while (tomb_it.next()) |entry| {
            const list = entry.value_ptr;
            var i: usize = 0;
            while (i < list.entries.items.len) {
                if (now_ms - list.entries.items[i].stamped_ms > window_ms) {
                    list.entries.items[i].free(self.allocator);
                    _ = list.entries.swapRemove(i);
                    pruned += 1;
                } else i += 1;
            }
            if (list.entries.items.len == 0) {
                tomb_empties.append(self.allocator, entry.key_ptr.*) catch {};
            }
        }
        for (tomb_empties.items) |chan| {
            const e = self.channel_part_tombs.getEntry(chan) orelse continue;
            const owned_key = e.key_ptr.*;
            e.value_ptr.deinit(self.allocator);
            self.channel_part_tombs.removeByPtr(e.key_ptr);
            self.allocator.free(owned_key);
        }

        // `pruneStale` is the bounded periodic repair point as well as a bulk
        // mutation: retry a prior transient-OOM rebuild even when nothing aged
        // out on this particular pass.
        if (self.claim_index_dirty) _ = self.rebuildAllBestNickClaims();

        return pruned;
    }

    /// Borrowed roster of remote members for `chan` (empty if none). Valid until
    /// the next `applyMembership`/eviction touching this channel.
    pub fn channelMembers(self: *const Self, chan: []const u8) []const Member {
        const list = self.channel_members.getPtr(chan) orelse return &.{};
        return list.entries.items;
    }

    /// Iterator over every channel name for which this table currently holds a
    /// remote member roster — the mesh-wide channel-name enumeration used by
    /// LIST/LISTX to surface channels whose members are all remote. Names are
    /// borrowed from the table and stay valid until the next
    /// `applyMembership`/eviction mutates the roster map.
    pub const ChannelNameIterator = struct {
        inner: std.StringHashMap(MemberList).Iterator,

        pub fn next(self: *ChannelNameIterator) ?[]const u8 {
            if (self.inner.next()) |entry| return entry.key_ptr.*;
            return null;
        }
    };

    /// Enumerate the channel names with a live remote roster (see
    /// `ChannelNameIterator`). Includes internal routing pseudo-channels such as
    /// the presence roster; callers filter to real channel names.
    pub fn channelNames(self: *const Self) ChannelNameIterator {
        return .{ .inner = self.channel_members.iterator() };
    }

    /// Apply a CHANNEL_LIST event for +b/+e/+I state, last-writer-wins by `hlc`
    /// for the tuple (channel, kind, mask). Newer tombstones are retained so an
    /// older add frame cannot resurrect a removed mask.
    pub fn applyChannelList(
        self: *Self,
        chan: []const u8,
        kind: ChannelListKind,
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
        origin_node: NodeId,
        hlc: u64,
        present: bool,
    ) Error!ApplyListResult {
        try self.validateName(chan);
        try validateNode(origin_node);
        if (mask.len == 0 or mask.len > channel_list_event.max_mask_len) return error.InvalidName;
        if (setter.len > channel_list_event.max_setter_len) return error.InvalidName;

        const list = try self.ensureChannelList(chan);
        if (list.find(kind, mask)) |idx| {
            const cur = &list.entries.items[idx];
            if (hlc <= cur.hlc) return .{ .outcome = .unchanged };

            const was_present = cur.present;
            const owned_setter = try self.allocator.dupe(u8, setter);
            self.allocator.free(cur.setter);
            cur.setter = owned_setter;
            cur.set_at = set_at;
            cur.origin_node = origin_node;
            cur.hlc = hlc;
            cur.present = present;
            return .{ .outcome = if (present == was_present) .unchanged else if (present) .added else .removed };
        }

        if (list.entries.items.len >= self.cfg.max_nicks) return error.RouteTableFull;
        const owned_mask = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(owned_mask);
        const owned_setter = try self.allocator.dupe(u8, setter);
        errdefer self.allocator.free(owned_setter);
        try list.entries.append(self.allocator, .{
            .kind = kind,
            .mask = owned_mask,
            .setter = owned_setter,
            .set_at = set_at,
            .origin_node = origin_node,
            .hlc = hlc,
            .present = present,
        });
        return .{ .outcome = if (present) .added else .unchanged };
    }

    /// Scan every channel roster for `nick` (ASCII case-insensitive, matching
    /// the daemon's nick comparison) and return the first match by value. The
    /// returned `nick` slice is borrowed from the table — valid until the next
    /// `applyMembership`/eviction. Channel membership is the only mesh-wide
    /// nick replication, so a remote user in no channels is not findable here.
    pub fn findMember(self: *const Self, nick: []const u8) ?Member {
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.entries.items) |m| {
                if (std.ascii.eqlIgnoreCase(m.nick, nick)) return m;
            }
        }
        return null;
    }

    /// Return one roster row for the exact mesh owner of `nick`. This is used by
    /// callers staging a collision displacement delta before the route-table
    /// transaction; the returned strings remain borrowed until mutation.
    pub fn findMemberOwnedBy(self: *const Self, nick: []const u8, node: NodeId) ?Member {
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.entries.items) |member| {
                if (member.node == node and std.ascii.eqlIgnoreCase(member.nick, nick)) return member;
            }
        }
        return null;
    }

    pub const ApplyChannelModeFlagsOutcome = enum { changed, unchanged };

    /// Apply a CHANNEL_MODE_FLAGS event for a remote channel, last-writer-wins by
    /// `hlc`. Stale events (hlc <= stored) are ignored. The daemon handles the
    /// actual local world mutation after draining a changed aggregate.
    pub fn applyChannelModeFlags(
        self: *Self,
        chan: []const u8,
        node: NodeId,
        flags: u16,
        hlc: u64,
    ) Error!ApplyChannelModeFlagsOutcome {
        try self.validateName(chan);
        try validateNode(node);

        if (self.channel_mode_flags.getPtr(chan)) |cur| {
            if (hlc <= cur.hlc) return .unchanged;
            const changed = cur.flags != flags;
            cur.flags = flags;
            cur.origin_node = node;
            cur.hlc = hlc;
            return if (changed) .changed else .unchanged;
        }

        if (self.channel_mode_flags.count() >= self.cfg.max_channels) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channel_mode_flags.putNoClobber(owned, .{
            .flags = flags,
            .origin_node = node,
            .hlc = hlc,
        });
        return .changed;
    }

    pub fn channelModeFlags(self: *const Self, chan: []const u8) ?ChannelModeFlags {
        return self.channel_mode_flags.get(chan);
    }

    pub const ApplyTopicOutcome = enum { changed, unchanged };

    /// Apply a TOPIC event for a remote channel, last-writer-wins by `hlc`. Stale
    /// events (hlc <= stored) are ignored. The topic TEXT mutation happens in the
    /// daemon's world after draining a `changed` outcome.
    pub fn applyTopic(self: *Self, chan: []const u8, node: NodeId, hlc: u64) Error!ApplyTopicOutcome {
        try self.validateName(chan);
        try validateNode(node);

        if (self.channel_topics.getPtr(chan)) |cur| {
            if (hlc <= cur.hlc) return .unchanged;
            cur.origin_node = node;
            cur.hlc = hlc;
            return .changed;
        }

        if (self.channel_topics.count() >= self.cfg.max_channels) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channel_topics.putNoClobber(owned, .{ .origin_node = node, .hlc = hlc });
        return .changed;
    }

    /// Rename a remote user across the nick→node map and every channel roster it
    /// appears in, refreshing its propagated identity. Returns true if `old_nick`
    /// existed anywhere (so the daemon should surface a live NICK line). ASCII
    /// case-sensitive match (nicks are stored verbatim). Best-effort on OOM: a
    /// failed roster rename leaves that roster untouched but still reports the
    /// rename if the nick→node entry moved.
    pub fn renameNick(
        self: *Self,
        old_nick: []const u8,
        new_nick: []const u8,
        node: NodeId,
        ident: MemberIdentity,
    ) Error!bool {
        try self.validateName(new_nick);
        // Capture copied normalized keys before any route/roster owned string can
        // be freed, so post-mutation claim reselection never dereferences one of
        // the strings the roster loop just replaced.
        const old_claim_key = NickKey.init(old_nick);
        const new_claim_key = NickKey.init(new_nick);

        // Ownership guard (mesh identity == home node): a caller may only rename an
        // entry HOMED on `node`. `renameNick` is reached from the wire
        // (recvNickChange) with a PEER-CONTROLLED `old_nick` whose `node` is the
        // sending peer's own id (pinned by acceptsDirectOrigin + the signed-frame
        // origin check) — but that peer does not necessarily OWN `old_nick`. If
        // old_nick currently routes to a DIFFERENT node, this is a cross-node
        // hijack (a Byzantine admitted peer moving another node's nick onto
        // itself); drop it wholesale and mutate nothing. The legitimate same-node
        // rename and the collision-displacement path (which passes
        // node = nickNode(nick)) both satisfy home == node and proceed. A nick with
        // no route entry falls through — the roster loop below only ever renames
        // entries it also owns (`m.node == node`).
        if (self.nick_to_node.get(old_nick)) |home| {
            if (home != node) return false;
        }

        // Collision resolution must move/disambiguate a foreign target before
        // rename reaches this mutation layer. Never overwrite another origin's
        // route or roster row (including a generated UID target).
        if (self.nick_to_node.get(new_nick)) |home| {
            if (home != node) return false;
        }
        var target_it = self.channel_members.valueIterator();
        while (target_it.next()) |list| {
            for (list.entries.items) |member| {
                if (member.node != node and std.ascii.eqlIgnoreCase(member.nick, new_nick)) return false;
            }
        }

        var existed = false;

        // nick_to_node: move old -> new (preserving the node mapping).
        if (self.nick_to_node.fetchRemove(old_nick)) |kv| {
            self.allocator.free(kv.key);
            const owned = self.allocator.dupe(u8, new_nick) catch {
                // Couldn't re-key; drop the stale mapping rather than corrupt it.
                return error.OutOfMemory;
            };
            errdefer self.allocator.free(owned);
            // If new_nick already maps (collision), overwrite the owned key it has.
            // That displaces a distinct pre-existing entry, so the map net-loses one
            // slot (old removed, new displaced, new re-added); decrement `nick_count`
            // to match or it leaks upward on every rename-into-an-existing-nick and
            // eventually wedges `setNickLocation` against `max_nicks` with a false
            // RouteTableFull.
            if (self.nick_to_node.fetchRemove(new_nick)) |old_new| {
                self.allocator.free(old_new.key);
                self.nick_count -= 1;
            }
            try self.nick_to_node.putNoClobber(owned, node);
            existed = true;
        }

        // Every channel roster: rename the matching member + refresh identity.
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            const list = entry.value_ptr;
            const idx = list.find(old_nick) orelse continue;
            const m = &list.entries.items[idx];
            // Never re-home a roster entry owned by a DIFFERENT node — defends the
            // cross-node hijack even if the route index (nick_to_node) has diverged
            // from a roster row (degraded index; see applyMembership).
            if (m.node != node) continue;
            const new_owned = self.allocator.dupe(u8, new_nick) catch continue;
            self.allocator.free(m.nick);
            m.nick = new_owned;
            m.node = node;
            // Identity refresh is best-effort: a failed realloc keeps the old copy.
            replaceOwned(self.allocator, &m.username, ident.username) catch {};
            replaceOwned(self.allocator, &m.realname, ident.realname) catch {};
            replaceOwned(self.allocator, &m.host, ident.host) catch {};
            existed = true;
        }
        // Roster renames are intentionally best-effort per channel, so derive both
        // keys from the actual post-loop state rather than moving a cached winner.
        // A case-only rename has one normalized key and needs one scan.
        if (old_claim_key) |old_key| self.reselectBestNickKey(old_key);
        if (!self.claim_index_dirty) {
            if (new_claim_key) |new_key| {
                if (old_claim_key == null or !std.meta.eql(old_claim_key.?, new_key)) {
                    self.reselectBestNickKey(new_key);
                }
            }
        }
        return existed;
    }

    fn ensureMemberList(self: *Self, chan: []const u8) Error!*MemberList {
        if (self.channel_members.getPtr(chan)) |list| return list;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channel_members.putNoClobber(owned, .{});
        return self.channel_members.getPtr(chan).?;
    }

    fn ensurePartTombList(self: *Self, chan: []const u8) Error!*PartTombList {
        if (self.channel_part_tombs.getPtr(chan)) |list| return list;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channel_part_tombs.putNoClobber(owned, .{});
        return self.channel_part_tombs.getPtr(chan).?;
    }

    /// Record (or LWW-advance) an origin-scoped PART tombstone. Bounded by
    /// `max_nicks` per channel — when full, the oldest stamp is evicted so a
    /// hostile PART flood cannot grow the map without bound (CWE-400).
    fn notePartTombstone(
        self: *Self,
        chan: []const u8,
        nick: []const u8,
        node: NodeId,
        hlc: u64,
        now_ms: i64,
    ) Error!void {
        const list = try self.ensurePartTombList(chan);
        if (list.find(nick, node)) |idx| {
            const cur = &list.entries.items[idx];
            // Always refresh the receiver stamp so a still-relevant tombstone
            // is not aged out while the origin keeps re-announcing the PART.
            cur.stamped_ms = now_ms;
            if (hlc > cur.hlc) cur.hlc = hlc;
            return;
        }
        if (list.entries.items.len >= self.cfg.max_nicks) {
            // Evict the oldest stamp (fail-toward-bound, not fail-open growth).
            var oldest_i: usize = 0;
            var oldest_ms = list.entries.items[0].stamped_ms;
            for (list.entries.items, 0..) |t, i| {
                if (t.stamped_ms < oldest_ms) {
                    oldest_ms = t.stamped_ms;
                    oldest_i = i;
                }
            }
            list.entries.items[oldest_i].free(self.allocator);
            _ = list.entries.swapRemove(oldest_i);
        }
        const owned_nick = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned_nick);
        try list.entries.append(self.allocator, .{
            .nick = owned_nick,
            .node = node,
            .hlc = hlc,
            .stamped_ms = now_ms,
        });
    }

    fn partTombstoneBlocks(self: *const Self, chan: []const u8, nick: []const u8, node: NodeId, hlc: u64) bool {
        const list = self.channel_part_tombs.getPtr(chan) orelse return false;
        const idx = list.find(nick, node) orelse return false;
        return hlc <= list.entries.items[idx].hlc;
    }

    fn clearPartTombstone(self: *Self, chan: []const u8, nick: []const u8, node: NodeId) void {
        const entry = self.channel_part_tombs.getEntry(chan) orelse return;
        const list = entry.value_ptr;
        const idx = list.find(nick, node) orelse return;
        list.entries.items[idx].free(self.allocator);
        _ = list.entries.swapRemove(idx);
        if (list.entries.items.len == 0) {
            const owned_key = entry.key_ptr.*;
            list.deinit(self.allocator);
            self.channel_part_tombs.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
        }
    }

    fn ensureChannelList(self: *Self, chan: []const u8) Error!*ChannelListState {
        if (self.channel_lists.getPtr(chan)) |list| return list;
        if (self.list_channel_count == self.cfg.max_channels) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channel_lists.putNoClobber(owned, .{});
        self.list_channel_count += 1;
        return self.channel_lists.getPtr(chan).?;
    }

    fn pruneIfEmpty(self: *Self, chan: []const u8) void {
        const entry = self.channel_members.getEntry(chan) orelse return;
        if (entry.value_ptr.entries.items.len != 0) return;
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channel_members.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    pub fn removeNode(self: *Self, node: NodeId) void {
        self.claim_index_dirty = true;
        self.removeNodeNicks(node);
        self.removeNodeChannels(node);
        self.removeNodeMembers(node);
        self.removeNodePartTombs(node);
        _ = self.rebuildAllBestNickClaims();
    }

    /// Alias used by daemon peer-drop cleanup: remove every route/member whose
    /// origin is `node`.
    pub fn removeByNode(self: *Self, node: NodeId) void {
        self.removeNode(node);
    }

    pub fn clearOrigin(self: *Self, node: NodeId) void {
        self.removeByNode(node);
    }

    /// Drop every remote member homed on a departed node (netsplit hygiene), and
    /// remove any channel left with no remaining members.
    fn removeNodeMembers(self: *Self, node: NodeId) void {
        var empties: std.ArrayListUnmanaged([]const u8) = .empty;
        defer empties.deinit(self.allocator);
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            const list = entry.value_ptr;
            var i: usize = 0;
            while (i < list.entries.items.len) {
                if (list.entries.items[i].node == node) {
                    list.entries.items[i].freeStrings(self.allocator);
                    _ = list.entries.swapRemove(i);
                } else i += 1;
            }
            if (list.entries.items.len == 0) empties.append(self.allocator, entry.key_ptr.*) catch {};
        }
        for (empties.items) |chan| self.pruneIfEmpty(chan);
    }

    /// Drop every PART tombstone homed on a departed node. A dead origin can no
    /// longer re-JOIN, so retaining its tombstones only wastes the bound.
    fn removeNodePartTombs(self: *Self, node: NodeId) void {
        var empties: std.ArrayListUnmanaged([]const u8) = .empty;
        defer empties.deinit(self.allocator);
        var it = self.channel_part_tombs.iterator();
        while (it.next()) |entry| {
            const list = entry.value_ptr;
            var i: usize = 0;
            while (i < list.entries.items.len) {
                if (list.entries.items[i].node == node) {
                    list.entries.items[i].free(self.allocator);
                    _ = list.entries.swapRemove(i);
                } else i += 1;
            }
            if (list.entries.items.len == 0) empties.append(self.allocator, entry.key_ptr.*) catch {};
        }
        for (empties.items) |chan| {
            const e = self.channel_part_tombs.getEntry(chan) orelse continue;
            const owned_key = e.key_ptr.*;
            e.value_ptr.deinit(self.allocator);
            self.channel_part_tombs.removeByPtr(e.key_ptr);
            self.allocator.free(owned_key);
        }
    }

    pub fn nickCount(self: *const Self) usize {
        return self.nick_count;
    }

    pub fn channelCount(self: *const Self) usize {
        return self.channel_count;
    }

    fn removeNodeNicks(self: *Self, node: NodeId) void {
        while (true) {
            var it = self.nick_to_node.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* != node) continue;
                const owned_key = entry.key_ptr.*;
                self.nick_to_node.removeByPtr(entry.key_ptr);
                self.allocator.free(owned_key);
                self.nick_count -= 1;
                break;
            } else {
                return;
            }
        }
    }

    fn removeNodeChannels(self: *Self, node: NodeId) void {
        while (true) {
            var it = self.channels.iterator();
            var removed_empty = false;
            while (it.next()) |entry| {
                entry.value_ptr.removeNode(node);
                if (entry.value_ptr.len != 0) continue;

                const owned_key = entry.key_ptr.*;
                entry.value_ptr.deinit(self.allocator);
                self.channels.removeByPtr(entry.key_ptr);
                self.allocator.free(owned_key);
                self.channel_count -= 1;
                removed_empty = true;
                break;
            }
            if (!removed_empty) return;
        }
    }

    fn validateName(self: *const Self, name: []const u8) Error!void {
        if (name.len == 0 or name.len > self.cfg.max_name_len) return error.InvalidName;
    }
};

fn validateNode(node: NodeId) Error!void {
    if (node == 0) return error.InvalidNode;
}

/// Replace an owned string with a copy of `incoming` (no-op when equal). The
/// new copy is allocated BEFORE the old one is freed, so an allocation failure
/// leaves the previous owned value intact (never a dangling slot).
fn replaceOwned(allocator: std.mem.Allocator, slot: *[]u8, incoming: []const u8) std.mem.Allocator.Error!void {
    if (std.mem.eql(u8, slot.*, incoming)) return;
    const fresh = try allocator.dupe(u8, incoming);
    allocator.free(slot.*);
    slot.* = fresh;
}

fn containsNode(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |candidate| {
        if (candidate == node) return true;
    }
    return false;
}

test "nick routing" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();

    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
    try table.setNickLocation("alice", 10);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));

    try table.setNickLocation("alice", 20);
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode("alice"));
    try std.testing.expectEqual(@as(usize, 1), table.nickCount());

    try std.testing.expect(table.removeNick("alice"));
    try std.testing.expect(!table.removeNick("alice"));
    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
}

test "mesh route_table renameNick keeps nick_count consistent and never clobbers a foreign target" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // Non-collision rename: the target nick is free, so the count is unchanged
    // (one nick keeps existing, just re-keyed).
    try table.setNickLocation("alice", 10);
    try std.testing.expectEqual(@as(usize, 1), table.nickCount());
    try std.testing.expect(try table.renameNick("alice", "carol", 10, .{}));
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("carol"));
    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
    try std.testing.expectEqual(@as(usize, 1), table.nickCount());

    // A target homed on another node is never overwritten. Collision resolution
    // must displace it first or select the caller's loser UID.
    try table.setNickLocation("bob", 20);
    try std.testing.expectEqual(@as(usize, 2), table.nickCount());
    try std.testing.expect(!(try table.renameNick("carol", "bob", 10, .{})));
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode("bob"));
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("carol"));
    try std.testing.expectEqual(@as(usize, 2), table.nickCount());

    // The leaked counter must not wedge future inserts against max_nicks: with a
    // consistent count of 2 there is room for more nicks up to the cap.
    try table.setNickLocation("dave", 30);
    try std.testing.expectEqual(@as(usize, 3), table.nickCount());
}

test "mesh route_table renameNick rejects hijacking a nick homed on another node" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // "victim" is homed on node 10. A Byzantine peer on node 20 sends a rename
    // for a nick it does NOT own (origin_node is pinned to the peer, but old_nick
    // is peer-controlled). The ownership guard MUST drop it wholesale.
    try table.setNickLocation("victim", 10);
    try std.testing.expectEqual(@as(usize, 1), table.nickCount());

    try std.testing.expect(!(try table.renameNick("victim", "pwned", 20, .{})));

    // Nothing moved: victim stays homed on 10, the attacker's target never
    // materialised, and the count is untouched.
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("victim"));
    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("pwned"));
    try std.testing.expectEqual(@as(usize, 1), table.nickCount());
}

test "mesh route_table PART cannot delete another origin's exact nick" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#safe", "trev", 10, 0, 10, true, .{}, 0);

    const result = try table.applyMembership("#safe", "trev", 20, 0, 999, false, .{}, 0);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, result.outcome);
    const member = table.findMember("trev") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(NodeId, 10), member.node);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("trev"));
}

test "mesh route_table rename refuses an occupied generated UID target" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    const uid = nick_collision.loserUid(10, "taken");
    _ = try table.applyMembership("#old", "old", 10, 0, 1, true, .{}, 0);
    _ = try table.applyMembership("#foreign", &uid, 20, 0, 1, true, .{}, 0);

    try std.testing.expect(!(try table.renameNick("old", &uid, 10, .{})));
    try std.testing.expectEqual(@as(NodeId, 10), table.findMember("old").?.node);
    try std.testing.expectEqual(@as(NodeId, 20), table.findMember(&uid).?.node);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("old"));
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode(&uid));
}

test "mesh route_table renameNick allows same-node rename but not cross-node roster hijack" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // "alice" homed on node 10, present in #chan on node 10 (route + roster).
    _ = try table.applyMembership("#chan", "alice", 10, 0, 1, true, .{}, 0);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));

    // Legitimate same-node rename (node 10 renames ITS OWN alice) still works and
    // moves both the route and the roster entry.
    try std.testing.expect(try table.renameNick("alice", "allie", 10, .{}));
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("allie"));
    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
    try std.testing.expect(table.findMember("allie") != null);
    try std.testing.expect(table.findMember("alice") == null);
    try std.testing.expectEqual(@as(NodeId, 10), table.bestNickClaim("ALLIE").?.node_id);
    try std.testing.expect(table.bestNickClaim("alice") == null);

    // Cross-node attempt: node 20 tries to rename node 10's live user. Rejected —
    // route and roster stay homed on 10 under the original nick.
    try std.testing.expect(!(try table.renameNick("allie", "gotcha", 20, .{})));
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("allie"));
    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("gotcha"));
    if (table.findMember("allie")) |m| {
        try std.testing.expectEqual(@as(NodeId, 10), m.node);
    } else return error.TestUnexpectedResult;
    try std.testing.expect(table.findMember("gotcha") == null);
    try std.testing.expectEqual(@as(NodeId, 10), table.bestNickClaim("allie").?.node_id);
    try std.testing.expect(table.bestNickClaim("gotcha") == null);
}

test "channel fan-out node set" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nodes_per_channel = 3 });
    defer table.deinit();

    try table.updateOnMembershipChange("#zig", 10, .join);
    try table.updateOnMembershipChange("#zig", 20, .join);
    try table.updateOnMembershipChange("#zig", 10, .join);

    var out: [3]NodeId = undefined;
    var len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expect(containsNode(out[0..len], 10));
    try std.testing.expect(containsNode(out[0..len], 20));

    try table.updateOnMembershipChange("#zig", 10, .part);
    len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expect(containsNode(out[0..len], 10));

    try table.updateOnMembershipChange("#zig", 10, .part);
    len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expect(!containsNode(out[0..len], 10));
    try std.testing.expect(containsNode(out[0..len], 20));
}

test "node removal purges its nicks" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();

    try table.setNickLocation("alice", 10);
    try table.setNickLocation("bob", 20);
    try table.updateOnMembershipChange("#zig", 10, .join);
    try table.updateOnMembershipChange("#zig", 20, .join);
    try table.updateOnMembershipChange("#empty-after-purge", 10, .join);

    table.removeByNode(10);

    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode("bob"));

    var out: [2]NodeId = undefined;
    const len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expect(containsNode(out[0..len], 20));
    try std.testing.expectEqual(@as(usize, 0), try table.channelNodes("#empty-after-purge", &out));
}

test "setChannelNodePresence is idempotent by liveness and refcount-agnostic" {
    var table = try RouteTable.init(std.testing.allocator, .{
        .max_nicks = 8,
        .max_channels = 8,
        .max_nodes_per_channel = 8,
    });
    defer table.deinit();

    var out: [4]NodeId = undefined;

    // Absent -> present adds exactly one node-set entry.
    try table.setChannelNodePresence("#undertow", 7, true);
    try std.testing.expectEqual(@as(usize, 1), try table.channelNodes("#undertow", &out));
    try std.testing.expectEqual(@as(NodeId, 7), out[0]);

    // Repeated "present" refreshes never inflate the set (idempotent) — a single
    // "absent" must fully clear it, which it could not if a refcount accumulated.
    try table.setChannelNodePresence("#undertow", 7, true);
    try table.setChannelNodePresence("#undertow", 7, true);
    try std.testing.expectEqual(@as(usize, 1), try table.channelNodes("#undertow", &out));

    try table.setChannelNodePresence("#undertow", 7, false);
    try std.testing.expectEqual(@as(usize, 0), try table.channelNodes("#undertow", &out));

    // Clearing an absent node / empty channel is a no-op, never an error.
    try table.setChannelNodePresence("#undertow", 7, false);
    try table.setChannelNodePresence("#never-seen", 9, false);
}

test "no leak across clear, remove, and deinit paths" {
    var table = try RouteTable.init(std.testing.allocator, .{
        .max_nicks = 4,
        .max_channels = 4,
        .max_nodes_per_channel = 4,
    });
    defer table.deinit();

    try table.setNickLocation("alice", 1);
    try table.setNickLocation("bob", 2);
    try table.updateOnMembershipChange("#a", 1, .join);
    try table.updateOnMembershipChange("#a", 2, .join);
    try table.updateOnMembershipChange("#b", 2, .join);

    try std.testing.expect(table.removeNick("alice"));
    table.removeNode(2);
    table.clear();

    try std.testing.expectEqual(@as(usize, 0), table.nickCount());
    try std.testing.expectEqual(@as(usize, 0), table.channelCount());
}

test "applyMembership tracks remote channel members with last-writer-wins" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "alice", 10, 0b0100, 1, true, .{}, 0); // op
    _ = try table.applyMembership("#chat", "bob", 20, 0b0000, 1, true, .{}, 0);
    try std.testing.expectEqual(@as(usize, 2), table.channelMembers("#chat").len);

    // A stale event (lower hlc) is ignored; a newer one updates status.
    _ = try table.applyMembership("#chat", "alice", 10, 0b0000, 0, true, .{}, 0);
    _ = try table.applyMembership("#chat", "alice", 10, 0b0010, 5, true, .{}, 0); // now voice
    var alice_status: ?u4 = null;
    for (table.channelMembers("#chat")) |m| {
        if (std.mem.eql(u8, m.nick, "alice")) alice_status = m.status;
    }
    try std.testing.expectEqual(@as(u4, 0b0010), alice_status.?);
}

test "applyMembership stores and LWW-updates the propagated identity" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{
        .username = "alice",
        .realname = "Alice Liddell",
        .host = "cloak-1a2b.users",
    }, 0);
    var alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("alice", alice.username);
    try std.testing.expectEqualStrings("Alice Liddell", alice.realname);
    try std.testing.expectEqualStrings("cloak-1a2b.users", alice.host);

    // A stale event must NOT clobber the stored identity.
    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{ .username = "stale" }, 0);
    alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("alice", alice.username);

    // A newer event replaces it (e.g. a vhost change re-announced).
    _ = try table.applyMembership("#chat", "alice", 10, 0, 9, true, .{
        .username = "alice",
        .realname = "Alice Liddell",
        .host = "vanity.example",
    }, 0);
    alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("vanity.example", alice.host);

    // Part frees the identity strings (leak-checked by testing.allocator).
    _ = try table.applyMembership("#chat", "alice", 10, 0, 10, false, .{}, 0);
    try std.testing.expect(table.findMember("alice") == null);
}

test "session token metadata is receiver-owned, LWW copied, and explicitly rebound" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    var first: SessionToken = @splat(0x11);
    first[15] = 0xA1;
    var second: SessionToken = @splat(0x22);
    second[15] = 0xB2;

    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{ .session_token = first }, 0);
    var member = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, first, member.session_token.?));

    // A stale wire re-affirmation cannot overwrite receiver metadata through the
    // LWW identity path. Token authority changes use the explicit rebind API.
    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{ .session_token = second }, 1);
    member = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, first, member.session_token.?));
    try std.testing.expectEqual(@as(usize, 1), try table.rebindSessionToken(10, "ALICE", second));
    member = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, second, member.session_token.?));
    try std.testing.expectEqual(@as(usize, 0), try table.rebindSessionToken(10, "alice", second));
    try std.testing.expectEqual(@as(usize, 1), try table.rebindSessionToken(10, "alice", null));
    try std.testing.expect((table.findMember("alice") orelse return error.TestUnexpectedResult).session_token == null);
}

test "rebindSessionToken follows receiver-derived collision UID aliases" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const token: SessionToken = @splat(0xC3);
    const uid = nick_collision.loserUid(10, "alice");
    _ = try table.applyMembership("#chat", &uid, 10, 0, 1, true, .{}, 0);

    try std.testing.expectEqual(@as(usize, 1), try table.rebindSessionToken(10, "alice", token));
    const member = table.findMember(&uid) orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, token, member.session_token.?));
}

test "Store-authorized untagged rename binds every row and is retry-safe" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const token: SessionToken = @splat(0xC4);
    _ = try table.applyMembership("#one", "old", 10, 0, 1, true, .{}, 0);
    _ = try table.applyMembership("#two", "old", 10, 0, 1, true, .{}, 0);

    const FailingObserver = struct {
        calls: usize = 0,

        fn part(_: *anyopaque, _: []const u8, _: *const Member) std.mem.Allocator.Error!void {
            unreachable;
        }

        fn rename(ctx: *anyopaque, _: []const u8, _: []const u8, _: *const Member) std.mem.Allocator.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            return error.OutOfMemory;
        }
    };
    var failing = FailingObserver{};
    try std.testing.expectError(error.OutOfMemory, table.renameNickBindingSessionToken(10, "old", "new", token, .{}, .{
        .ctx = &failing,
        .part_fn = FailingObserver.part,
        .rename_fn = FailingObserver.rename,
    }));
    try std.testing.expectEqual(@as(usize, 1), failing.calls);
    for ([_][]const u8{ "#one", "#two" }) |channel| {
        const member = table.channelMembers(channel)[0];
        try std.testing.expectEqualStrings("old", member.nick);
        try std.testing.expect(member.session_token == null);
    }
    try std.testing.expect(table.nickNode("old") != null);
    try std.testing.expect(table.nickNode("new") == null);

    // Retrying the same Store-authorized transaction binds and renames together;
    // the failed attempt left no partial receiver metadata behind.
    try std.testing.expect(try table.renameNickBindingSessionToken(10, "old", "new", token, .{}, null));
    for ([_][]const u8{ "#one", "#two" }) |channel| {
        const member = table.channelMembers(channel)[0];
        try std.testing.expectEqualStrings("new", member.nick);
        try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, token, member.session_token.?));
    }
    try std.testing.expect(table.nickNode("old") == null);
    try std.testing.expect(table.nickNode("new") != null);
}

test "reconcileSessionToken replaces stale nick rows within desired channels without touching decoys" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 16, .max_channels = 16, .max_nodes_per_channel = 16 });
    defer table.deinit();

    const exact: SessionToken = @splat(0x31);
    const other: SessionToken = @splat(0x32);
    _ = try table.applyMembership("#keep", "old-alice", 10, 0, 2, true, .{ .session_token = exact }, 0);
    _ = try table.applyMembership("#gone", "old-alice", 10, 0, 2, true, .{ .session_token = exact }, 0);
    _ = try table.applyMembership("#other", "bob", 10, 0, 1, true, .{ .session_token = other }, 0);
    _ = try table.applyMembership("#unbound", "carol", 10, 0, 1, true, .{}, 0);

    const desired = [_][]const u8{"#KEEP"};
    const reconciled = try table.reconcileSessionToken(exact, "alice", &desired);
    try std.testing.expectEqual(@as(usize, 1), reconciled.renamed);
    try std.testing.expectEqual(@as(usize, 1), reconciled.removed);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#keep").len);
    try std.testing.expectEqualStrings("alice", table.channelMembers("#keep")[0].nick);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#gone").len);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#other").len);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#unbound").len);
    try std.testing.expect(table.nickNode("alice") != null);
    try std.testing.expect(table.nickNode("old-alice") == null);
    const unchanged = try table.reconcileSessionToken(exact, "alice", &desired);
    try std.testing.expectEqual(@as(usize, 0), unchanged.renamed);
    try std.testing.expectEqual(@as(usize, 0), unchanged.removed);

    // A missing Store projection retracts the final exact-token row without
    // disturbing the distinct or deliberately-unbound compatibility rows.
    const revoked = try table.reconcileSessionToken(exact, null, &desired);
    try std.testing.expectEqual(@as(usize, 1), revoked.removed);
    try std.testing.expect(table.nickNode("alice") == null);
    const bob = table.findMember("bob") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, other, bob.session_token.?));
    try std.testing.expect(table.findMember("carol") != null);
}

test "reconcileSessionToken rehomes a shared nick route to the best surviving claim" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const survivor_token: SessionToken = @splat(0x41);
    const removed_token: SessionToken = @splat(0x42);
    _ = try table.applyMembership("#survives", "shared", 10, 0, 10, true, .{ .session_token = survivor_token }, 0);
    _ = try table.applyMembership("#removed", "shared", 20, 0, 20, true, .{ .session_token = removed_token }, 0);
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode("shared"));

    const reconciled = try table.reconcileSessionToken(removed_token, null, &.{});
    try std.testing.expectEqual(@as(usize, 1), reconciled.removed);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("shared"));
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#survives").len);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#removed").len);
    const survivor = table.findMember("shared") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.crypto.timing_safe.eql(SessionToken, survivor_token, survivor.session_token.?));
}

test "reconcileSessionToken canonicalizes an uncontested receiver-derived collision alias" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const token: SessionToken = @splat(0x51);
    const origin: NodeId = 42;
    const uid = nick_collision.loserUid(origin, "alice");
    _ = try table.applyMembership("#room", &uid, origin, 0, 10, true, .{ .session_token = token }, 0);

    const desired = [_][]const u8{"#ROOM"};
    const canonicalized = try table.reconcileSessionToken(token, "ALICE", &desired);
    try std.testing.expectEqual(@as(usize, 0), canonicalized.removed);
    try std.testing.expectEqual(@as(usize, 1), canonicalized.renamed);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#room").len);
    try std.testing.expectEqualStrings("ALICE", table.channelMembers("#room")[0].nick);
    try std.testing.expect(table.nickNode(&uid) == null);
    try std.testing.expectEqual(@as(?NodeId, origin), table.nickNode("ALICE"));

    // Once signed authority changes the real nick, the old collision alias is
    // no longer derivable from the desired identity and must be retracted.
    const renamed = try table.reconcileSessionToken(token, "alice-new", &desired);
    try std.testing.expectEqual(@as(usize, 1), renamed.renamed);
    try std.testing.expectEqual(@as(usize, 0), renamed.removed);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#room").len);
    try std.testing.expect(table.nickNode(&uid) == null);
    try std.testing.expectEqualStrings("alice-new", table.channelMembers("#room")[0].nick);
}

test "reconcileSessionToken removes remote UID beside exact-token local canonical nick with observed PART" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const token: SessionToken = @splat(0x53);
    const origin: NodeId = 42;
    const uid = nick_collision.loserUid(origin, "kain");
    var local = LocalNickStub{ .held = "kain", .acct = "kain", .token = token };
    table.setLocalNickResolver(local.resolver());
    _ = try table.applyMembership("#root", &uid, origin, 0, 10, true, .{
        .account = "kain",
        .session_token = token,
    }, 0);

    const Observer = struct {
        parts: usize = 0,

        fn part(ctx: *anyopaque, channel: []const u8, member: *const Member) std.mem.Allocator.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            std.debug.assert(std.mem.eql(u8, channel, "#root"));
            std.debug.assert(uid_alloc.validate(member.nick));
            self.parts += 1;
        }
        fn rename(_: *anyopaque, _: []const u8, _: []const u8, _: *const Member) std.mem.Allocator.Error!void {
            unreachable;
        }
    };
    var observer = Observer{};
    const desired = [_][]const u8{"#root"};
    const reconciled = try table.reconcileSessionTokenObserved(token, "kain", &desired, .{
        .ctx = &observer,
        .part_fn = Observer.part,
        .rename_fn = Observer.rename,
    });
    try std.testing.expectEqual(@as(usize, 0), reconciled.renamed);
    try std.testing.expectEqual(@as(usize, 1), reconciled.removed);
    try std.testing.expectEqual(@as(usize, 1), observer.parts);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#root").len);
    try std.testing.expect(table.nickNode(&uid) == null);
}

test "reconcileSessionToken retains remote UID when local canonical nick has a different token" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const remote_token: SessionToken = @splat(0x54);
    const local_token: SessionToken = @splat(0x55);
    const origin: NodeId = 42;
    const uid = nick_collision.loserUid(origin, "kain");
    var local = LocalNickStub{ .held = "kain", .acct = "kain", .token = local_token };
    table.setLocalNickResolver(local.resolver());
    _ = try table.applyMembership("#root", &uid, origin, 0, 10, true, .{
        .account = "kain",
        .session_token = remote_token,
    }, 0);

    const desired = [_][]const u8{"#root"};
    const reconciled = try table.reconcileSessionToken(remote_token, "kain", &desired);
    try std.testing.expectEqual(@as(usize, 0), reconciled.renamed);
    try std.testing.expectEqual(@as(usize, 0), reconciled.removed);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#root").len);
    try std.testing.expectEqualStrings(&uid, table.channelMembers("#root")[0].nick);
    try std.testing.expectEqual(@as(?NodeId, origin), table.nickNode(&uid));
}

test "reconcileSessionToken removes a UID duplicate when canonical row has the same token" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const token: SessionToken = @splat(0x52);
    const uid = nick_collision.loserUid(42, "alice");
    _ = try table.applyMembership("#room", "alice", 7, 0, 10, true, .{ .session_token = token }, 0);
    _ = try table.applyMembership("#room", &uid, 42, 0, 11, true, .{ .session_token = token }, 0);

    const desired = [_][]const u8{"#room"};
    const reconciled = try table.reconcileSessionToken(token, "alice", &desired);
    try std.testing.expectEqual(@as(usize, 1), reconciled.removed);
    try std.testing.expectEqual(@as(usize, 0), reconciled.renamed);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#room").len);
    try std.testing.expectEqualStrings("alice", table.channelMembers("#room")[0].nick);
    try std.testing.expect(table.nickNode(&uid) == null);
}

test "applyMembership stores the oper-info real_host + certfp (remote WHOIS 338/276/320)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // A secured oper-info link propagates the real IP + certfp; they must reach the
    // roster Member so the receiver's remote WHOIS can surface them to operators.
    _ = try table.applyMembership("#root", "trev", 20, 0, 1, true, .{
        .host = "cloak.users",
        .account = "trev",
        .real_host = "203.0.113.42",
        .certfp = "409db4958a2bb069fe4f2f7541bb25918bd0dd1b25612baae430ec761365732e",
    }, 0);
    var m = table.findMember("trev") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("203.0.113.42", m.real_host);
    try std.testing.expectEqualStrings("409db4958a2bb069fe4f2f7541bb25918bd0dd1b25612baae430ec761365732e", m.certfp);

    // A newer event LWW-replaces them (re-announce from a new connection/IP).
    _ = try table.applyMembership("#root", "trev", 20, 0, 9, true, .{
        .account = "trev",
        .real_host = "198.51.100.7",
        .certfp = "",
    }, 0);
    m = table.findMember("trev") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("198.51.100.7", m.real_host);
    try std.testing.expectEqualStrings("", m.certfp);

    // Part frees the oper-info strings too (leak-checked by testing.allocator).
    _ = try table.applyMembership("#root", "trev", 20, 0, 10, false, .{}, 0);
    try std.testing.expect(table.findMember("trev") == null);
}

test "findMember locates a roster member case-insensitively with its node" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "Alice", 10, 0b0100, 1, true, .{}, 0);
    _ = try table.applyMembership("#ops", "bob", 20, 0, 1, true, .{}, 0);

    const alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Alice", alice.nick);
    try std.testing.expectEqual(@as(NodeId, 10), alice.node);

    const bob = table.findMember("BOB") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(NodeId, 20), bob.node);

    try std.testing.expect(table.findMember("carol") == null);
}

test "applyMembership part removes a member and prunes an empty channel" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#x", "alice", 10, 0, 1, true, .{}, 0);
    // Stale part (hlc <= current) does not remove.
    _ = try table.applyMembership("#x", "alice", 10, 0, 1, false, .{}, 0);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#x").len);
    // Newer part removes; the now-empty channel is pruned.
    _ = try table.applyMembership("#x", "alice", 10, 0, 2, false, .{}, 0);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#x").len);
}

test "applyMembership part removes a collision-renamed UID member" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const uid = nick_collision.loserUid(10, "trev");
    _ = try table.applyMembership("#root", uid[0..], 10, 0, 1, true, .{
        .username = "trev",
        .host = "trev.users.ircxnet",
        .account = "trev",
    }, 0);
    try std.testing.expect(table.findMember(uid[0..]) != null);
    try std.testing.expectEqual(@as(NodeId, 10), table.bestNickClaim(uid[0..]).?.node_id);

    // The PART wire event carries the user's real nick, not the fallback UID
    // assigned by the receiver during collision resolution. It must still remove
    // the UID roster entry so NAMES does not retain a phantom generated nick.
    const res = try table.applyMembership("#root", "trev", 10, 0, 2, false, .{}, 0);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.parted, res.outcome);
    try std.testing.expect(table.findMember(uid[0..]) == null);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#root").len);
    try std.testing.expect(table.bestNickClaim(uid[0..]) == null);
}

test "channelNames enumerates channels with a live remote roster (LIST union input)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#alpha", "alice", 10, 0, 1, true, .{}, 0);
    _ = try table.applyMembership("#beta", "bob", 10, 0, 1, true, .{}, 0);
    _ = try table.applyMembership("#beta", "carol", 10, 0, 2, true, .{}, 0);

    var saw_alpha = false;
    var saw_beta = false;
    var count: usize = 0;
    var it = table.channelNames();
    while (it.next()) |name| {
        count += 1;
        if (std.mem.eql(u8, name, "#alpha")) saw_alpha = true;
        if (std.mem.eql(u8, name, "#beta")) saw_beta = true;
    }
    try std.testing.expect(saw_alpha);
    try std.testing.expect(saw_beta);
    // Each channel appears exactly once regardless of member count.
    try std.testing.expectEqual(@as(usize, 2), count);

    // Parting the last member prunes the channel, so it drops out of enumeration.
    _ = try table.applyMembership("#alpha", "alice", 10, 0, 2, false, .{}, 0);
    var remaining: usize = 0;
    var it2 = table.channelNames();
    while (it2.next()) |name| {
        remaining += 1;
        try std.testing.expect(!std.mem.eql(u8, name, "#alpha"));
    }
    try std.testing.expectEqual(@as(usize, 1), remaining);
}

test "applyMembership maintains the nick->node routing index for PRIVMSG relay" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // A join makes the remote nick resolvable to its owning node — this is the
    // index the cross-node PRIVMSG relay consults (`nickNode`). Before the fix it
    // stayed empty (only NAMES/WHOIS, which scan the roster, worked) so every
    // cross-node PM fell through to ERR_NOSUCHNICK.
    _ = try table.applyMembership("#a", "alice", 10, 0, 1, true, .{}, 0);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));

    // The same nick in a second channel must keep one location; parting ONE
    // channel must NOT drop the route while another membership remains.
    _ = try table.applyMembership("#b", "alice", 10, 0, 1, true, .{}, 0);
    _ = try table.applyMembership("#a", "alice", 10, 0, 2, false, .{}, 0); // part #a
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));

    // Parting the LAST channel drops the route (channel membership is the only
    // mesh-wide nick replication, so a no-channel remote user is unroutable).
    _ = try table.applyMembership("#b", "alice", 10, 0, 3, false, .{}, 0); // part #b
    try std.testing.expect(table.nickNode("alice") == null);
}

test "pruneStale reaps members whose local last-seen aged past the window" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const T: i64 = 1_000_000;
    const window: i64 = 90_000;

    // A member last refreshed at LOCAL T is still within the window at T+50_000 and
    // must survive; the same member ages out once now passes T+window. The wire hlc
    // is deliberately a different magnitude (5) to prove pruning keys off the local
    // stamp (now_ms=T), not the announcer's hlc.
    _ = try table.applyMembership("#chat", "alice", 10, 0, 5, true, .{ .username = "alice" }, T);
    try std.testing.expectEqual(@as(usize, 0), table.pruneStale(T + 50_000, window));
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#chat").len);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));
    try std.testing.expectEqual(@as(NodeId, 10), table.bestNickClaim("ALICE").?.node_id);

    // Now strictly past the window: the member is reaped, its emptied channel is
    // pruned, and its nick→node route is dropped (last channel gone).
    try std.testing.expectEqual(@as(usize, 1), table.pruneStale(T + 100_000, window));
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#chat").len);
    try std.testing.expect(table.nickNode("alice") == null);
    try std.testing.expect(table.findMember("alice") == null);
    try std.testing.expect(table.bestNickClaim("alice") == null);
    try std.testing.expect(!table.claim_index_dirty);
}

test "pruneStaleObserved queues each client-visible departure before mutation" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#old", "alice", 10, 0, 1, true, .{ .username = "user", .host = "cloak" }, 1);

    const Observer = struct {
        table: *RouteTable,
        calls: usize = 0,

        fn part(ctx: *anyopaque, channel: []const u8, member: *const Member) std.mem.Allocator.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            // The observer owns the delta before authoritative removal, so all
            // borrowed identity fields and the route row are still available.
            std.debug.assert(std.mem.eql(u8, "#old", channel));
            std.debug.assert(std.mem.eql(u8, "alice", member.nick));
            std.debug.assert(std.mem.eql(u8, "user", member.username));
            std.debug.assert(std.mem.eql(u8, "cloak", member.host));
            std.debug.assert(self.table.findMember("alice") != null);
            self.calls += 1;
        }

        fn rename(_: *anyopaque, _: []const u8, _: []const u8, _: *const Member) std.mem.Allocator.Error!void {
            unreachable;
        }
    };
    var observer = Observer{ .table = &table };
    const pruned = try table.pruneStaleObserved(100_000, 90_000, .{
        .ctx = &observer,
        .part_fn = Observer.part,
        .rename_fn = Observer.rename,
    });
    try std.testing.expectEqual(@as(usize, 1), pruned);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expect(table.findMember("alice") == null);
}

test "pruneStaleObserved preserves a row when its departure cannot be retained" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#old", "alice", 10, 0, 1, true, .{}, 1);

    const Observer = struct {
        fn part(_: *anyopaque, _: []const u8, _: *const Member) std.mem.Allocator.Error!void {
            return error.OutOfMemory;
        }
        fn rename(_: *anyopaque, _: []const u8, _: []const u8, _: *const Member) std.mem.Allocator.Error!void {
            unreachable;
        }
    };
    var ctx: u8 = 0;
    try std.testing.expectError(error.OutOfMemory, table.pruneStaleObserved(100_000, 90_000, .{
        .ctx = &ctx,
        .part_fn = Observer.part,
        .rename_fn = Observer.rename,
    }));
    try std.testing.expect(table.findMember("alice") != null);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));
}

test "pruneStaleObserved completes earlier rows when a later observer allocation fails" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#first", "alice", 10, 0, 1, true, .{}, 1);
    _ = try table.applyMembership("#second", "bob", 20, 0, 1, true, .{}, 1);

    const Observer = struct {
        calls: usize = 0,
        accepted_was_alice: ?bool = null,

        fn part(ctx: *anyopaque, _: []const u8, member: *const Member) std.mem.Allocator.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            if (self.calls == 2) return error.OutOfMemory;
            self.accepted_was_alice = std.mem.eql(u8, member.nick, "alice");
        }
        fn rename(_: *anyopaque, _: []const u8, _: []const u8, _: *const Member) std.mem.Allocator.Error!void {
            unreachable;
        }
    };
    var observer = Observer{};
    try std.testing.expectError(error.OutOfMemory, table.pruneStaleObserved(100_000, 90_000, .{
        .ctx = &observer,
        .part_fn = Observer.part,
        .rename_fn = Observer.rename,
    }));
    try std.testing.expectEqual(@as(usize, 2), observer.calls);

    // Hash-map iteration order is intentionally unspecified. Whichever row was
    // accepted first is completely gone (route and empty channel); the row whose
    // observer failed remains authoritative for a later retry.
    const accepted_was_alice = observer.accepted_was_alice orelse return error.TestUnexpectedResult;
    const accepted = if (accepted_was_alice) "alice" else "bob";
    const retained = if (accepted_was_alice) "bob" else "alice";
    const accepted_channel = if (accepted_was_alice) "#first" else "#second";
    const retained_channel = if (accepted_was_alice) "#second" else "#first";
    try std.testing.expect(table.findMember(accepted) == null);
    try std.testing.expect(table.nickNode(accepted) == null);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers(accepted_channel).len);
    try std.testing.expect(table.findMember(retained) != null);
    try std.testing.expect(table.nickNode(retained) != null);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers(retained_channel).len);
}

test "pruneStale keeps a route while the nick remains fresh in another channel" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const window: i64 = 90_000;

    // "alice" was last refreshed long ago in #old (local now=1) but recently in
    // #new (local now=1_000_000); "bob" is fresh in #new only. Each channel holds a
    // SEPARATE Member entry, so they carry independent last-seen stamps. Pruning at
    // now=1_050_000 reaps only the stale #old projection, keeps #new untouched, and
    // RETAINS alice's route because she is still present in #new.
    _ = try table.applyMembership("#old", "alice", 10, 0, 1, true, .{}, 1);
    _ = try table.applyMembership("#new", "alice", 10, 0, 1_000_000, true, .{}, 1_000_000);
    _ = try table.applyMembership("#new", "bob", 20, 0, 1_000_000, true, .{}, 1_000_000);

    try std.testing.expectEqual(@as(usize, 1), table.pruneStale(1_050_000, window));
    // #old emptied and pruned; #new intact with both members.
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#old").len);
    try std.testing.expectEqual(@as(usize, 2), table.channelMembers("#new").len);
    // alice's route survives (still in #new); bob untouched.
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));
    try std.testing.expectEqual(@as(NodeId, 10), table.bestNickClaim("ALICE").?.node_id);
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode("bob"));
    try std.testing.expect(table.findMember("alice") != null);

    // A second prune well past every stamp reaps both, empties #new, drops routes.
    try std.testing.expectEqual(@as(usize, 2), table.pruneStale(2_000_000, window));
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#new").len);
    try std.testing.expect(table.nickNode("alice") == null);
    try std.testing.expect(table.nickNode("bob") == null);
}

test "pruneStale uses the local last-seen stamp, not the announcer's wire hlc (cross-skew regression)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // Simulate a peer with a wildly different uptime: its monotonic clock (the wire
    // hlc) reads 5 while THIS node's local clock reads 1_000_000 at apply time. The
    // two are different clock domains and must never be compared. Apply the member
    // with hlc=5 but stamp it with local now_ms=1_000_000.
    _ = try table.applyMembership("#chat", "alice", 10, 0, 5, true, .{ .username = "alice" }, 1_000_000);

    // Prune 10_000ms later in the LOCAL domain, well inside the 90s window. The
    // member SURVIVES because last_refreshed_ms (1_000_000) is fresh. Under the old
    // hlc-based logic this would compute 1_010_000 - 5 = 1_009_995 > 90_000 and
    // wrongly reap a live remote member — exactly the cross-host flapping bug.
    try std.testing.expectEqual(@as(usize, 0), table.pruneStale(1_010_000, 90_000));
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#chat").len);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));
}

test "mesh route_table re-affirming a present member refreshes local last-seen so pruneStale never reaps a live member (roster-decay regression)" {
    // Federation roster-decay bug: on a 2-node mesh, the 30s anti-entropy re-burst
    // re-affirms every PRESENT remote member, but the receive path must refresh that
    // member's RECEIVER-LOCAL last-seen stamp on EVERY present apply — otherwise the
    // stamp freezes at first-join and pruneStale reaps a still-live member after the
    // TTL, leaving NAMES showing only local members ("eventually shows everyone, then
    // decays"). The liveness touch must be ORTHOGONAL to CRDT/LWW value convergence:
    // it must fire even when the re-affirmation carries a NON-advancing hlc that the
    // LWW guard collapses to `unchanged`, because a "still here" signal is not a value
    // change. This models one receiver's clock domain (the same nowMs pruneStale uses).
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const T0: i64 = 1_000_000;
    const window: i64 = 90_000; // stale_member_ttl_ms
    const hlc: u64 = 42; // the announcer's wire hlc — held CONSTANT across re-affirms

    // T0: member M learned from remote node 10 in #root.
    _ = try table.applyMembership("#root", "mallory", 10, 0, hlc, true, .{ .username = "mallory" }, T0);

    // 30s re-burst: SAME hlc (idempotent CRDT no-op) → LWW collapses to `unchanged`,
    // but the local last-seen MUST advance to T0+30k anyway.
    const r1 = try table.applyMembership("#root", "mallory", 10, 0, hlc, true, .{ .username = "mallory" }, T0 + 30_000);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, r1.outcome);

    // 60s re-burst: same again → stamp advances to T0+60k.
    const r2 = try table.applyMembership("#root", "mallory", 10, 0, hlc, true, .{ .username = "mallory" }, T0 + 60_000);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, r2.outcome);

    // Prune at T0+95k: 95k since T0 (> window) but only 35k since the last re-affirm
    // at T0+60k (< window). A LIVE re-affirmed member must SURVIVE. Under the frozen-
    // stamp regression this reaps her — the live NAMES-decay bug.
    try std.testing.expectEqual(@as(usize, 0), table.pruneStale(T0 + 95_000, window));
    // Still visible in the peer's roster (NAMES shows her).
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#root").len);
    // Still ROUTABLE: the member and its nick->node route are the SAME RouteTable
    // entry, so a spurious prune also drops the route and breaks cross-node PRIVMSG
    // (the live "401 No such nick" symptom). Assert the route survives too.
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("mallory"));
    try std.testing.expect(table.findMember("mallory") != null);
}

test "mesh route_table pruneStale still reaps a member whose re-affirmation genuinely stopped (zombie-reap intent preserved)" {
    // The dual of the regression above: the liveness touch must NOT defeat the
    // zombie reaper. A member whose PART/QUIT was lost stops being re-affirmed by the
    // sender, so its local stamp stops advancing and it MUST age out after the TTL.
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const T0: i64 = 1_000_000;
    const window: i64 = 90_000;
    const hlc: u64 = 7;

    _ = try table.applyMembership("#root", "ghost", 10, 0, hlc, true, .{ .username = "ghost" }, T0);
    // One re-affirm at +30k, then the sender stops listing her (lost PART).
    _ = try table.applyMembership("#root", "ghost", 10, 0, hlc, true, .{ .username = "ghost" }, T0 + 30_000);

    // +100k since the last stamp (T0+30k) is 70k — still inside the window, survives.
    try std.testing.expectEqual(@as(usize, 0), table.pruneStale(T0 + 100_000, window));
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#root").len);

    // +125k: now 95k past the frozen T0+30k stamp (> window) → the zombie is reaped.
    try std.testing.expectEqual(@as(usize, 1), table.pruneStale(T0 + 125_000, window));
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#root").len);
    try std.testing.expect(table.nickNode("ghost") == null);
    try std.testing.expect(table.findMember("ghost") == null);
}

test "applyChannelList tracks list masks with last-writer-wins tombstones" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    var res = try table.applyChannelList("#ops", .ban, "*!*@bad", "oper!u@h", 10, 2, 100, true);
    try std.testing.expectEqual(RouteTable.ApplyListOutcome.added, res.outcome);

    // Stale remove is ignored.
    res = try table.applyChannelList("#ops", .ban, "*!*@bad", "oper!u@h", 11, 2, 99, false);
    try std.testing.expectEqual(RouteTable.ApplyListOutcome.unchanged, res.outcome);

    // Newer remove becomes a tombstone.
    res = try table.applyChannelList("#ops", .ban, "*!*@bad", "oper!u@h", 12, 2, 101, false);
    try std.testing.expectEqual(RouteTable.ApplyListOutcome.removed, res.outcome);

    // Older add cannot resurrect.
    res = try table.applyChannelList("#ops", .ban, "*!*@bad", "oper!u@h", 13, 2, 100, true);
    try std.testing.expectEqual(RouteTable.ApplyListOutcome.unchanged, res.outcome);

    // Newer add can.
    res = try table.applyChannelList("#ops", .ban, "*!*@bad", "oper2!u@h", 14, 2, 102, true);
    try std.testing.expectEqual(RouteTable.ApplyListOutcome.added, res.outcome);
}

test "removeNode evicts that node's remote members (netsplit hygiene)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{}, 0);
    _ = try table.applyMembership("#chat", "bob", 20, 0, 1, true, .{}, 0);
    table.removeNode(10);
    const members = table.channelMembers("#chat");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("bob", members[0].nick);

    table.removeNode(20); // last member gone -> channel pruned
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#chat").len);
}

test "applyChannelModeFlags tracks aggregate flags with last-writer-wins" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    try std.testing.expectEqual(RouteTable.ApplyChannelModeFlagsOutcome.changed, try table.applyChannelModeFlags("#chat", 10, 0b0011, 5));
    try std.testing.expectEqual(RouteTable.ApplyChannelModeFlagsOutcome.unchanged, try table.applyChannelModeFlags("#chat", 10, 0b0101, 4));
    try std.testing.expectEqual(@as(u16, 0b0011), table.channelModeFlags("#chat").?.flags);

    try std.testing.expectEqual(RouteTable.ApplyChannelModeFlagsOutcome.changed, try table.applyChannelModeFlags("#chat", 20, 0b0101, 6));
    const got = table.channelModeFlags("#chat").?;
    try std.testing.expectEqual(@as(u16, 0b0101), got.flags);
    try std.testing.expectEqual(@as(NodeId, 20), got.origin_node);
    try std.testing.expectEqual(@as(u64, 6), got.hlc);
}

test "Config.applyToml overlays mesh.routing route-table keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.routing]
        \\max_nicks = 8192
        \\max_nodes_per_channel = 128
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 8192), cfg.max_nicks);
    try std.testing.expectEqual(@as(usize, 128), cfg.max_nodes_per_channel);
    try std.testing.expectEqual(@as(usize, 1024), cfg.max_channels); // default
}

// --- Cross-node / cross-namespace NICK collision resolution --------------

fn expectRename(decision: NickDecision) !nick_collision.Uid {
    return switch (decision) {
        .keep, .local_same_account, .remote_same_account, .reclaim_local => error.TestUnexpectedResult,
        .rename_to_uid => |uid| uid,
    };
}

const LocalNickStub = struct {
    held: []const u8,
    /// The local holder's authenticated account ("" = not logged in).
    acct: []const u8 = "",
    /// The local holder's last mesh-claim HLC (0 = unknown).
    hlc: u64 = 0,
    token: ?SessionToken = null,
    fn isHeld(ctx: *anyopaque, nick: []const u8) bool {
        const self: *LocalNickStub = @ptrCast(@alignCast(ctx));
        return std.ascii.eqlIgnoreCase(self.held, nick);
    }
    fn accountOf(ctx: *anyopaque, nick: []const u8) ?[]const u8 {
        const self: *LocalNickStub = @ptrCast(@alignCast(ctx));
        if (!std.ascii.eqlIgnoreCase(self.held, nick)) return null;
        return if (self.acct.len != 0) self.acct else null;
    }
    fn hlcOf(ctx: *anyopaque, nick: []const u8) u64 {
        const self: *LocalNickStub = @ptrCast(@alignCast(ctx));
        if (!std.ascii.eqlIgnoreCase(self.held, nick)) return 0;
        return self.hlc;
    }
    fn tokenOf(ctx: *anyopaque, nick: []const u8) ?SessionToken {
        const self: *LocalNickStub = @ptrCast(@alignCast(ctx));
        if (!std.ascii.eqlIgnoreCase(self.held, nick)) return null;
        return self.token;
    }
    fn resolver(self: *LocalNickStub) LocalNickResolver {
        return .{
            .ctx = self,
            .held_fn = isHeld,
            .account_fn = accountOf,
            .hlc_fn = hlcOf,
            .session_token_fn = tokenOf,
        };
    }
};

test "resolveIncomingNick keeps an uncontested nick" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("alice", 10, 100, "", true));
}

test "bestNickClaim is case-insensitive and independent of roster iteration order" {
    const ClaimInput = struct { nick: []const u8, node: NodeId, hlc: u64 };
    const claims = [_]ClaimInput{
        .{ .nick = "RICKY", .node = 1, .hlc = 10 },
        .{ .nick = "ricky", .node = 1, .hlc = 20 },
        .{ .nick = "RiCkY", .node = 2, .hlc = 15 },
    };
    const permutations = [_][3]usize{
        .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 },
        .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 },
    };

    for (permutations) |permutation| {
        var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
        defer table.deinit();
        for (permutation, 0..) |claim_idx, channel_idx| {
            var channel_buf: [8]u8 = undefined;
            const channel = try std.fmt.bufPrint(&channel_buf, "#c{d}", .{channel_idx});
            const claim = claims[claim_idx];
            _ = try table.applyMembership(channel, claim.nick, claim.node, 0, claim.hlc, true, .{}, 0);
        }
        const best = table.bestNickClaim("rIcKy") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(NodeId, 1), best.node_id);
        try std.testing.expectEqual(@as(u64, 20), best.hlc);
        try std.testing.expect(!table.claim_index_dirty);
        try std.testing.expectEqual(@as(usize, 1), table.best_nick_claims.count());
    }
}

test "bestNickClaim incrementally raises a claim and ignores stale reaffirmation" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#a", "RICKY", 1, 0, 10, true, .{}, 1);
    _ = try table.applyMembership("#b", "ricky", 2, 0, 20, true, .{}, 1);

    // Stale HLC only refreshes liveness; it cannot change the indexed winner.
    _ = try table.applyMembership("#a", "RICKY", 3, 0, 10, true, .{}, 2);
    var best = table.bestNickClaim("ricky").?;
    try std.testing.expectEqual(@as(NodeId, 2), best.node_id);
    try std.testing.expectEqual(@as(u64, 20), best.hlc);

    // A newer update to the lower row stays below the incumbent, then overtakes.
    _ = try table.applyMembership("#a", "RICKY", 3, 0, 15, true, .{}, 3);
    best = table.bestNickClaim("RICKY").?;
    try std.testing.expectEqual(@as(NodeId, 2), best.node_id);
    _ = try table.applyMembership("#a", "RICKY", 3, 0, 25, true, .{}, 4);
    best = table.bestNickClaim("rIcKy").?;
    try std.testing.expectEqual(@as(NodeId, 3), best.node_id);
    try std.testing.expectEqual(@as(u64, 25), best.hlc);

    // Equal HLC resolves by the same higher-node tiebreak as collision handling.
    _ = try table.applyMembership("#c", "RiCkY", 4, 0, 25, true, .{}, 5);
    best = table.bestNickClaim("ricky").?;
    try std.testing.expectEqual(@as(NodeId, 4), best.node_id);
    _ = try table.applyMembership("#c", "RiCkY", 4, 0, 26, false, .{}, 6);
    best = table.bestNickClaim("ricky").?;
    try std.testing.expectEqual(@as(NodeId, 3), best.node_id);
    try std.testing.expect(!table.claim_index_dirty);
}

test "bestNickClaim falls back deterministically as claims part" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#a", "RICKY", 1, 0, 10, true, .{}, 0);
    _ = try table.applyMembership("#b", "ricky", 1, 0, 20, true, .{}, 0);
    _ = try table.applyMembership("#c", "RiCkY", 2, 0, 15, true, .{}, 0);

    // The roster-backed query is authoritative even if the best-effort exact-key
    // route index is absent.
    _ = table.removeNick("ricky");
    try std.testing.expectEqual(@as(u64, 20), table.bestNickClaim("RICKY").?.hlc);
    _ = try table.applyMembership("#b", "ricky", 1, 0, 21, false, .{}, 0);
    var best = table.bestNickClaim("ricky").?;
    try std.testing.expectEqual(@as(NodeId, 2), best.node_id);
    try std.testing.expectEqual(@as(u64, 15), best.hlc);
    _ = try table.applyMembership("#c", "RiCkY", 2, 0, 16, false, .{}, 0);
    best = table.bestNickClaim("ricky").?;
    try std.testing.expectEqual(@as(NodeId, 1), best.node_id);
    try std.testing.expectEqual(@as(u64, 10), best.hlc);
    _ = try table.applyMembership("#a", "RICKY", 1, 0, 11, false, .{}, 0);
    try std.testing.expect(table.bestNickClaim("ricky") == null);
}

test "bestNickClaim bounded overflow degrades to scans and a rebuild recovers" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 1, .max_channels = 4, .max_nodes_per_channel = 4 });
    defer table.deinit();
    _ = try table.applyMembership("#a", "alpha", 1, 0, 10, true, .{}, 0);
    _ = try table.applyMembership("#b", "beta", 2, 0, 20, true, .{}, 0);

    try std.testing.expect(table.claim_index_dirty);
    try std.testing.expectEqual(@as(NodeId, 1), table.bestNickClaim("ALPHA").?.node_id);
    try std.testing.expectEqual(@as(NodeId, 2), table.bestNickClaim("BETA").?.node_id);

    _ = try table.applyMembership("#b", "beta", 2, 0, 21, false, .{}, 0);
    try std.testing.expect(table.rebuildAllBestNickClaims());
    try std.testing.expect(!table.claim_index_dirty);
    try std.testing.expectEqual(@as(usize, 1), table.best_nick_claims.count());
    try std.testing.expectEqual(@as(NodeId, 1), table.bestNickClaim("alpha").?.node_id);
    try std.testing.expect(table.bestNickClaim("beta") == null);
}

test "bestNickClaim scans route-table-only nicks beyond the S2S wire bound" {
    const long_nick = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789xyz";
    try std.testing.expect(long_nick.len > membership_event.max_nick_len);
    var table = try RouteTable.init(std.testing.allocator, .{
        .max_nicks = 4,
        .max_channels = 4,
        .max_nodes_per_channel = 4,
        .max_name_len = long_nick.len,
    });
    defer table.deinit();
    _ = try table.applyMembership("#long", long_nick, 7, 0, 77, true, .{}, 0);

    const best = table.bestNickClaim(long_nick).?;
    try std.testing.expectEqual(@as(NodeId, 7), best.node_id);
    try std.testing.expectEqual(@as(u64, 77), best.hlc);
    try std.testing.expect(!table.claim_index_dirty);
    try std.testing.expectEqual(@as(usize, 0), table.best_nick_claims.count());
}

test "bestNickClaim rename reselects old and contested new normalized keys" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#a", "old", 1, 0, 10, true, .{}, 0);
    _ = try table.applyMembership("#b", "old", 1, 0, 20, true, .{}, 0);
    // A same-origin target spelling is a legitimate multi-roster contest. A
    // foreign-origin target is deliberately rejected by renameNick's ownership
    // guard and belongs in the collision/UID fixtures instead.
    _ = try table.applyMembership("#c", "new", 1, 0, 15, true, .{}, 0);

    try std.testing.expect(try table.renameNick("old", "new", 1, .{}));
    try std.testing.expect(table.bestNickClaim("old") == null);
    var best = table.bestNickClaim("NEW").?;
    try std.testing.expectEqual(@as(NodeId, 1), best.node_id);
    try std.testing.expectEqual(@as(u64, 20), best.hlc);

    // A case-only rename is one normalized-key reselect and must retain the
    // unrelated roster's contested spelling in the same winner set.
    try std.testing.expect(try table.renameNick("new", "NeW", 1, .{}));
    best = table.bestNickClaim("new").?;
    try std.testing.expectEqual(@as(NodeId, 1), best.node_id);
    try std.testing.expectEqual(@as(usize, 1), table.best_nick_claims.count());
    try std.testing.expect(!table.claim_index_dirty);
}

test "bestNickClaim partial rename OOM reflects both actual roster names" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var table = try RouteTable.init(failing.allocator(), .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#a", "old", 1, 0, 10, true, .{}, 0);
    _ = try table.applyMembership("#b", "old", 1, 0, 10, true, .{}, 0);

    // Allow the exact-route re-key and one roster nick copy, then fail every
    // subsequent allocation. renameNick deliberately leaves the second roster
    // untouched; claim lookup must describe that real partial state.
    failing.fail_index = failing.alloc_index + 2;
    try std.testing.expect(try table.renameNick("old", "new", 1, .{}));
    try std.testing.expect(failing.has_induced_failure);

    var old_rows: usize = 0;
    var new_rows: usize = 0;
    var channels = table.channel_members.iterator();
    while (channels.next()) |entry| {
        for (entry.value_ptr.entries.items) |member| {
            if (std.mem.eql(u8, member.nick, "old")) old_rows += 1;
            if (std.mem.eql(u8, member.nick, "new")) new_rows += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), old_rows);
    try std.testing.expectEqual(@as(usize, 1), new_rows);
    try std.testing.expect(table.bestNickClaim("old") != null);
    try std.testing.expect(table.bestNickClaim("new") != null);
}

test "bestNickClaim prune survives claim-index rebuild OOM" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var table = try RouteTable.init(failing.allocator(), .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#stale", "ghost", 1, 0, 30, true, .{}, 0);
    _ = try table.applyMembership("#fresh", "GHOST", 2, 0, 20, true, .{}, 100);
    try std.testing.expectEqual(@as(NodeId, 1), table.bestNickClaim("ghost").?.node_id);

    // Reset only the optional index so prune's post-mutation rebuild must
    // allocate. The obsolete orphan-name capture no longer exists: stale-row
    // removal is now a per-row complete transaction with no allocation between
    // its observed departure and authoritative mutation. Failing the current
    // relevant allocation must leave scan fallback active, never expose node 1
    // after its roster row was freed.
    table.best_nick_claims.deinit();
    table.best_nick_claims = std.AutoHashMap(NickKey, NickClaim).init(failing.allocator());
    table.claim_index_dirty = true;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectEqual(@as(usize, 1), table.pruneStale(101, 50));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(table.claim_index_dirty);
    const best = table.bestNickClaim("ghost").?;
    try std.testing.expectEqual(@as(NodeId, 2), best.node_id);
    try std.testing.expectEqual(@as(u64, 20), best.hlc);

    // A later maintenance pass retries the optional rebuild even with nothing
    // else to prune and restores the fast index from authoritative roster state.
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(@as(usize, 0), table.pruneStale(101, 50));
    try std.testing.expect(!table.claim_index_dirty);
    try std.testing.expectEqual(@as(NodeId, 2), table.best_nick_claims.get(NickKey.init("ghost").?).?.node_id);
}

test "bestNickClaim removeNode reselects a surviving claimant" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#a", "same", 1, 0, 30, true, .{}, 0);
    _ = try table.applyMembership("#b", "SAME", 2, 0, 20, true, .{}, 0);
    _ = try table.applyMembership("#c", "same", 1, 0, 10, true, .{}, 0);

    table.removeNode(1);
    const best = table.bestNickClaim("same").?;
    try std.testing.expectEqual(@as(NodeId, 2), best.node_id);
    try std.testing.expectEqual(@as(u64, 20), best.hlc);
    try std.testing.expect(!table.claim_index_dirty);
    table.clearOrigin(2);
    try std.testing.expect(table.bestNickClaim("same") == null);
    try std.testing.expect(!table.claim_index_dirty);
}

test "bestNickClaim OOM dirties incremental insert and rebuild then recovers" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var table = try RouteTable.init(failing.allocator(), .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();
    _ = try table.applyMembership("#a", "alpha", 1, 0, 10, true, .{}, 0);
    _ = try table.applyMembership("#b", "beta", 2, 0, 20, true, .{}, 0);

    // Reset only the optional cache so the allocator-backed roster remains a
    // valid oracle. Force the next map allocation to fail first through the
    // incremental helper, then through the one-pass rebuild.
    table.best_nick_claims.deinit();
    table.best_nick_claims = std.AutoHashMap(NickKey, NickClaim).init(failing.allocator());
    table.claim_index_dirty = false;
    failing.fail_index = failing.alloc_index;
    table.noteBestNickClaim("alpha", .{ .node_id = 1, .hlc = 10 });
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(table.claim_index_dirty);
    try std.testing.expectEqual(@as(NodeId, 1), table.bestNickClaim("ALPHA").?.node_id);
    try std.testing.expectEqual(@as(NodeId, 2), table.bestNickClaim("beta").?.node_id);
    try std.testing.expect(!table.rebuildAllBestNickClaims());
    try std.testing.expect(table.claim_index_dirty);

    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expect(table.rebuildAllBestNickClaims());
    try std.testing.expect(!table.claim_index_dirty);
    try std.testing.expectEqual(@as(usize, 2), table.best_nick_claims.count());
    try std.testing.expectEqual(@as(NodeId, 1), table.bestNickClaim("alpha").?.node_id);
    try std.testing.expectEqual(@as(NodeId, 2), table.bestNickClaim("BETA").?.node_id);

    table.clear();
    try std.testing.expect(!table.claim_index_dirty);
    try std.testing.expectEqual(@as(usize, 0), table.best_nick_claims.count());
    _ = try table.applyMembership("#again", "gamma", 3, 0, 30, true, .{}, 0);
    try std.testing.expectEqual(@as(NodeId, 3), table.bestNickClaim("GAMMA").?.node_id);
}

test "resolveIncomingNick renames a remote nick that collides with a LOCAL one" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();
    var stub = LocalNickStub{ .held = "Alice" };
    table.setLocalNickResolver(stub.resolver());

    // Local world is authoritative (case-insensitive) — the incoming remote
    // member loses and is forced to its mesh UID.
    const uid = try expectRename(table.resolveIncomingNick("alice", 10, 100, "", true));
    try std.testing.expect(uid_alloc.validate(uid[0..]));
    const parts = try uid_alloc.parse(uid[0..]);
    try std.testing.expectEqual(@as(u16, 10), parts.node); // owner-node scoped

    // Clearing the resolver removes the cross-namespace contest.
    table.setLocalNickResolver(null);
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("alice", 10, 100, "", true));
}

test "resolveIncomingNick reconciles a same-account remote collision with a LOCAL holder" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();
    // The local holder of "kain" is logged in to account "kain". An incoming
    // remote claim for "kain" bearing the SAME account is the same identity, not a
    // stranger: the table must NOT mint a UID — it defers to the daemon.
    var stub = LocalNickStub{ .held = "kain", .acct = "kain" };
    table.setLocalNickResolver(stub.resolver());
    // Unknown local holder HLC (0) → fail-safe: keep local, never reclaim.
    try std.testing.expectEqual(NickDecision.local_same_account, table.resolveIncomingNick("kain", 10, 100, "kain", true));

    // A DIFFERENT account on the incoming claim is a genuine collision → UID.
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "mallory", true));
    // An empty incoming account falls back to the account-blind path → UID.
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "", true));
}

test "resolveIncomingNick retires a STALE local session for a strictly-newer same-account claim" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();
    // Local "kain" asserted its claim at HLC 100. A same-account remote claim at a
    // strictly-newer HLC means the local session is the stale ghost → reclaim it.
    var stub = LocalNickStub{ .held = "kain", .acct = "kain", .hlc = 100 };
    table.setLocalNickResolver(stub.resolver());
    try std.testing.expectEqual(NickDecision.reclaim_local, table.resolveIncomingNick("kain", 10, 200, "kain", true));
    // An EQUAL or OLDER incoming HLC keeps the live local session (no reclaim).
    try std.testing.expectEqual(NickDecision.local_same_account, table.resolveIncomingNick("kain", 10, 100, "kain", true));
    try std.testing.expectEqual(NickDecision.local_same_account, table.resolveIncomingNick("kain", 10, 50, "kain", true));
    // A different account is still a genuine collision regardless of HLC → UID.
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 999, "mallory", true));
}

test "resolveIncomingNick renames a newcomer that loses a cross-node remote contest" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // Node 20 holds "kain" with a high HLC. A newcomer from node 10 with a lower
    // HLC must lose and rename to its UID; the SAME node re-asserting keeps it.
    _ = try table.applyMembership("#chat", "kain", 20, 0, 500, true, .{}, 0);
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "", true));
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("kain", 20, 999, "", true));

    // A higher-HLC newcomer from node 10 WINS: the table reports keep (the caller
    // then displaces the incumbent to its UID).
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("kain", 10, 600, "", true));
}

test "resolveIncomingNick collapses a same-account cross-node collision via keep (no UID)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // Node 20 holds "kain" logged in to account "kain". A LOWER-hlc newcomer from
    // node 10 on the SAME account would normally lose and get a UID — but because
    // it is the same identity, the table reports `remote_same_account` (no UID, no
    // incumbent displacement) and lets hlc LWW in applyMembership converge.
    _ = try table.applyMembership("#chat", "kain", 20, 0, 500, true, .{ .account = "kain" }, 0);
    try std.testing.expectEqual(NickDecision.remote_same_account, table.resolveIncomingNick("kain", 10, 100, "kain", true));
    // A different account still contests normally (lower hlc loser → UID).
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "mallory", true));
}

test "resolveIncomingNick: an UNTRUSTED account never unlocks a same-identity short-circuit (mesh F1)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // Local collision: a forged `account=kain` on an unverified claim must NOT
    // coexist with (or reclaim) the real local kain — conservative UID path.
    var stub = LocalNickStub{ .held = "kain", .acct = "kain", .hlc = 100 };
    table.setLocalNickResolver(stub.resolver());
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "kain", false));
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 999, "kain", false)); // no reclaim either
    // The SAME claim verified is the same identity again.
    try std.testing.expectEqual(NickDecision.reclaim_local, table.resolveIncomingNick("kain", 10, 999, "kain", true));
    table.setLocalNickResolver(null);

    // Cross-node collision: an unverified same-account claim contests like a
    // stranger (deterministic tiebreak → UID for the lower claim), never
    // `remote_same_account` coexistence.
    _ = try table.applyMembership("#chat", "kain", 20, 0, 500, true, .{ .account = "kain" }, 0);
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "kain", false));
    try std.testing.expectEqual(NickDecision.remote_same_account, table.resolveIncomingNick("kain", 10, 100, "kain", true));
}

test "resolveIncomingNick sticky trust: an ESTABLISHED member's re-affirm is keep, independent of account trust (mesh R1)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // kain@A (node 20) was admitted into coexistence with a LOCAL kain while its
    // residence proof verified (the initial same-account admission).
    var stub = LocalNickStub{ .held = "kain", .acct = "kain", .hlc = 100 };
    table.setLocalNickResolver(stub.resolver());
    try std.testing.expectEqual(NickDecision.local_same_account, table.resolveIncomingNick("kain", 20, 100, "kain", true));
    _ = try table.applyMembership("#chat", "kain", 20, 0, 100, true, .{ .account = "kain" }, 0);

    // A later re-affirm from the SAME node whose proof has EXPIRED (trusted=false
    // now) must NOT re-run the account gate and UID-flip the live member: the
    // proof gates the INITIAL admission only. This covers re-bursts, status
    // changes, and reclaim edges alike — every same-node re-affirm is `.keep`.
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("kain", 20, 200, "kain", false));
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("kain", 20, 200, "", false));
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("kain", 20, 50, "kain", false)); // even stale hlc
    // And with the local holder gone (user logged off locally) it still keeps.
    table.setLocalNickResolver(null);
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("kain", 20, 300, "kain", false));

    // A DIFFERENT node claiming the same nick with an unproven account is still
    // a stranger: the established member is never displaced by it (the lower
    // claim loses), and no coexistence is granted.
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "kain", false));
}

test "resolveIncomingNick breaks an HLC tie by higher node id" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "kain", 20, 0, 300, true, .{}, 0);
    // Same HLC, lower node id => newcomer loses.
    _ = try expectRename(table.resolveIncomingNick("kain", 5, 300, "", true));
    // Same HLC, higher node id => newcomer wins (keep; caller displaces).
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("kain", 99, 300, "", true));
}

test "incumbentLoserUid derives a stable, owner-scoped fallback" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    try std.testing.expect(table.incumbentLoserUid("ghost") == null);
    _ = try table.applyMembership("#chat", "kain", 42, 0, 1, true, .{}, 0);
    const uid = table.incumbentLoserUid("kain").?;
    try std.testing.expect(uid_alloc.validate(uid[0..]));
    try std.testing.expectEqual(@as(u16, 42), (try uid_alloc.parse(uid[0..])).node);
    // Stable across calls.
    try std.testing.expectEqualSlices(u8, uid[0..], table.incumbentLoserUid("kain").?[0..]);
}

// ---------------------------------------------------------------------------
// exploit: hostile NAMES/membership — reorder convergence + Byzantine PART
// ---------------------------------------------------------------------------

/// Snapshot the live (channel, nick, node, status, hlc) roster for convergence
/// compares. Order-independent: sorted by (channel, nick).
fn rosterFingerprint(table: *const RouteTable, allocator: std.mem.Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(allocator);
    var it = table.channelNames();
    while (it.next()) |chan| try names.append(allocator, chan);
    std.mem.sort([]const u8, names.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);
    for (names.items) |chan| {
        const members = table.channelMembers(chan);
        // Copy + sort by nick so fingerprint is order-independent.
        const idxs = try allocator.alloc(usize, members.len);
        defer allocator.free(idxs);
        for (idxs, 0..) |*slot, i| slot.* = i;
        std.mem.sort(usize, idxs, members, struct {
            fn less(ms: []const Member, a: usize, b: usize) bool {
                return std.mem.order(u8, ms[a].nick, ms[b].nick) == .lt;
            }
        }.less);
        for (idxs) |i| {
            const m = members[i];
            var line_buf: [256]u8 = undefined;
            const line = try std.fmt.bufPrint(&line_buf, "{s}|{s}|{d}|{d}|{d};", .{ chan, m.nick, m.node, m.status, m.hlc });
            try out.appendSlice(allocator, line);
        }
    }
    return out.toOwnedSlice(allocator);
}

test "exploit: membership reorder converges (PART-before-JOIN cannot resurrect)" {
    // CWE-362 / convergence: a PART that races ahead of its matching lower-HLC
    // JOIN must still win LWW. Without a PART tombstone the early PART is
    // discarded as "unknown member" and the late JOIN resurrects a departed user
    // into NAMES — Byzantine-adjacent phantom membership under reordering.
    const allocator = std.testing.allocator;
    const seed: u64 = 0xA11CE_5EED;
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();

    const Event = struct {
        present: bool,
        status: u4,
        hlc: u64,
        nick: []const u8,
        node: NodeId,
    };
    // Canonical history for alice@10 on #chat:
    //   JOIN hlc=10 status=op → PART hlc=20 → JOIN hlc=30 status=voice
    // Final: alice present, voice, hlc=30.
    const canon = [_]Event{
        .{ .present = true, .status = 0b0100, .hlc = 10, .nick = "alice", .node = 10 },
        .{ .present = false, .status = 0, .hlc = 20, .nick = "alice", .node = 10 },
        .{ .present = true, .status = 0b0010, .hlc = 30, .nick = "alice", .node = 10 },
        .{ .present = true, .status = 0, .hlc = 15, .nick = "bob", .node = 20 },
        .{ .present = false, .status = 0, .hlc = 25, .nick = "bob", .node = 20 },
    };

    var reference = try RouteTable.init(allocator, .{ .max_nicks = 16, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer reference.deinit();
    for (canon) |ev| {
        _ = try reference.applyMembership("#chat", ev.nick, ev.node, ev.status, ev.hlc, ev.present, .{}, 0);
    }
    const expected = try rosterFingerprint(&reference, allocator);
    defer allocator.free(expected);
    // Sanity: alice present voice, bob gone.
    try std.testing.expect(reference.findMember("alice") != null);
    try std.testing.expectEqual(@as(u4, 0b0010), reference.findMember("alice").?.status);
    try std.testing.expect(reference.findMember("bob") == null);

    // Apply the same multiset under many shuffles; every order must converge.
    const order = try allocator.alloc(usize, canon.len);
    defer allocator.free(order);
    var trial: usize = 0;
    while (trial < 64) : (trial += 1) {
        for (order, 0..) |*slot, i| slot.* = i;
        rng.shuffle(usize, order);

        var table = try RouteTable.init(allocator, .{ .max_nicks = 16, .max_channels = 8, .max_nodes_per_channel = 8 });
        defer table.deinit();
        for (order) |i| {
            const ev = canon[i];
            _ = try table.applyMembership("#chat", ev.nick, ev.node, ev.status, ev.hlc, ev.present, .{}, 0);
        }
        const got = try rosterFingerprint(&table, allocator);
        defer allocator.free(got);
        if (!std.mem.eql(u8, expected, got)) {
            std.debug.print("membership reorder divergence seed={d} trial={d} order={any}\nexpected={s}\ngot={s}\n", .{ seed, trial, order, expected, got });
            return error.TestExpectedEqual;
        }
    }
}

test "exploit: Byzantine cross-origin PART cannot delete another node's member" {
    // CWE-290: an admitted peer (or a forged MEMBERSHIP that slipped past a
    // weaker gate) must never PART a nick owned by a different origin. The
    // route table is origin-owned: wrong-node PART is a no-op and the victim
    // stays in the NAMES projection.
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#ops", "trev", 10, 0b0100, 5, true, .{
        .username = "trev",
        .host = "trev.users",
    }, 0);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#ops").len);

    // Byzantine node 99 tries to PART trev with a *newer* hlc — still rejected.
    const res = try table.applyMembership("#ops", "trev", 99, 0, 99, false, .{}, 0);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, res.outcome);
    const victim = table.findMember("trev") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(NodeId, 10), victim.node);
    try std.testing.expectEqual(@as(u4, 0b0100), victim.status);
    try std.testing.expectEqual(@as(u64, 5), victim.hlc);
    try std.testing.expectEqualStrings("trev", victim.username);
}

test "exploit: stale JOIN after PART tombstone cannot resurrect into NAMES" {
    // Direct counterexample for the pre-tombstone hole: PART hlc=20 first, then
    // JOIN hlc=10. Fail-closed final state is ABSENT (PART wins LWW).
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    const part = try table.applyMembership("#chat", "alice", 10, 0, 20, false, .{}, 100);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, part.outcome); // unknown → tombstone only
    const join = try table.applyMembership("#chat", "alice", 10, 0b0100, 10, true, .{ .username = "alice" }, 101);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, join.outcome);
    try std.testing.expect(table.findMember("alice") == null);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#chat").len);

    // A *newer* JOIN after the PART still lands (legitimate rejoin).
    const rejoin = try table.applyMembership("#chat", "alice", 10, 0, 30, true, .{ .username = "alice" }, 102);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.joined, rejoin.outcome);
    try std.testing.expect(table.findMember("alice") != null);
}

test "mesh NAMES projection converges after late partial membership burst + catch-up" {
    // Regression for the live nicklist desync: each mesh node projects NAMES from
    // its RouteTable.channelMembers. A late *partial* burst (only a subset of the
    // peer's locals) must not permanently pin a divergent roster — the subsequent
    // anti-entropy re-burst / individual MEMBERSHIP catch-up has to converge both
    // sides to the same (channel, nick, node, status) set regardless of delivery
    // order. Models two receivers applying the same multiset of facts under
    // opposite orders and asserts channelMembers fingerprints match.
    const allocator = std.testing.allocator;
    const Event = struct {
        chan: []const u8,
        nick: []const u8,
        node: NodeId,
        status: u4,
        hlc: u64,
        present: bool,
    };
    // Canonical mesh history for #root across two origin nodes:
    //   node 10: alice (op) joins, bob joins, alice parts, alice rejoins (voice)
    //   node 20: carol joins (op) and stays
    // Final NAMES projection: alice(voice)@10, bob@10, carol(op)@20.
    const canon = [_]Event{
        .{ .chan = "#root", .nick = "alice", .node = 10, .status = 0b0100, .hlc = 10, .present = true },
        .{ .chan = "#root", .nick = "bob", .node = 10, .status = 0, .hlc = 11, .present = true },
        .{ .chan = "#root", .nick = "carol", .node = 20, .status = 0b0100, .hlc = 12, .present = true },
        .{ .chan = "#root", .nick = "alice", .node = 10, .status = 0, .hlc = 20, .present = false },
        .{ .chan = "#root", .nick = "alice", .node = 10, .status = 0b0010, .hlc = 30, .present = true },
    };

    // "Partial burst first" order: only bob+carol land early (alice's first JOIN
    // delayed), then the rest catch up — the shape of a truncated membership
    // burst followed by individual events / re-burst.
    const partial_first = [_]usize{ 1, 2, 0, 3, 4 };
    // "Full history reversed" order — stresses PART-before-JOIN tombstones.
    const reversed = [_]usize{ 4, 3, 2, 1, 0 };

    var ref = try RouteTable.init(allocator, .{ .max_nicks = 16, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer ref.deinit();
    for (canon) |ev| {
        _ = try ref.applyMembership(ev.chan, ev.nick, ev.node, ev.status, ev.hlc, ev.present, .{}, 0);
    }
    const expected = try rosterFingerprint(&ref, allocator);
    defer allocator.free(expected);

    // Sanity on the reference final NAMES set.
    try std.testing.expectEqual(@as(usize, 3), ref.channelMembers("#root").len);
    try std.testing.expectEqual(@as(u4, 0b0010), ref.findMember("alice").?.status);
    try std.testing.expect(ref.findMember("bob") != null);
    try std.testing.expectEqual(@as(u4, 0b0100), ref.findMember("carol").?.status);

    for ([_][]const usize{ &partial_first, &reversed }) |order| {
        var table = try RouteTable.init(allocator, .{ .max_nicks = 16, .max_channels = 8, .max_nodes_per_channel = 8 });
        defer table.deinit();
        for (order) |i| {
            const ev = canon[i];
            _ = try table.applyMembership(ev.chan, ev.nick, ev.node, ev.status, ev.hlc, ev.present, .{}, 0);
        }
        const got = try rosterFingerprint(&table, allocator);
        defer allocator.free(got);
        if (!std.mem.eql(u8, expected, got)) {
            std.debug.print("NAMES membership divergence\nexpected={s}\ngot={s}\n", .{ expected, got });
            return error.TestExpectedEqual;
        }
        // Explicit NAMES-shaped assertions (not just the fingerprint).
        try std.testing.expectEqual(@as(usize, 3), table.channelMembers("#root").len);
        try std.testing.expectEqual(@as(u4, 0b0010), table.findMember("alice").?.status);
        try std.testing.expectEqual(@as(NodeId, 10), table.findMember("bob").?.node);
        try std.testing.expectEqual(@as(NodeId, 20), table.findMember("carol").?.node);
    }
}

test "same-HLC re-burst after PART tombstone does not resurrect a departed member into NAMES" {
    // sendMembershipBurstTo historically stamped ONE hlc across every present
    // member. A PART and a later re-burst that somehow share an hlc (or the
    // re-burst is older) must not undo the PART: the tombstone is equal-or-newer
    // fail-closed so NAMES on the peer never re-grows a user who left.
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#root", "ghost", 10, 0, 50, true, .{ .username = "ghost" }, 1_000);
    _ = try table.applyMembership("#root", "ghost", 10, 0, 60, false, .{}, 1_001);
    try std.testing.expect(table.findMember("ghost") == null);

    // Re-burst with the SAME hlc as the PART (equal → blocked).
    const same = try table.applyMembership("#root", "ghost", 10, 0, 60, true, .{ .username = "ghost" }, 1_002);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, same.outcome);
    try std.testing.expect(table.findMember("ghost") == null);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#root").len);

    // Re-burst with a strictly older hlc (partial/late) — still blocked.
    const older = try table.applyMembership("#root", "ghost", 10, 0, 55, true, .{ .username = "ghost" }, 1_003);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.unchanged, older.outcome);
    try std.testing.expect(table.findMember("ghost") == null);

    // Only a strictly newer JOIN (genuine rejoin) repopulates NAMES.
    const newer = try table.applyMembership("#root", "ghost", 10, 0, 70, true, .{ .username = "ghost" }, 1_004);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.joined, newer.outcome);
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#root").len);
}
