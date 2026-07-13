// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded cross-node route table for SUIMYAKU message fan-out.
//!
//! The table is pure state: callers own all I/O decisions and pass allocator
//! ownership in at init. String keys are copied into managed StringHashMaps and
//! released on removal/deinit.
const std = @import("std");
const toml = @import("../../proto/toml.zig");
const channel_list_event = @import("../../proto/channel_list_event.zig");
const nick_collision = @import("nick_collision.zig");
const uid_alloc = @import("uid_alloc.zig");

pub const NodeId = u64;

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
    channels: std.StringHashMap(ChannelState),
    /// channel name -> roster of remote members (nick + status), populated by
    /// MEMBERSHIP propagation (see docs/planning/16). Independent of `channels`
    /// (which is node-level routing) so identity churn never disturbs routing.
    channel_members: std.StringHashMap(MemberList),
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
            .channels = std.StringHashMap(ChannelState).init(allocator),
            .channel_members = std.StringHashMap(MemberList).init(allocator),
            .channel_mode_flags = std.StringHashMap(ChannelModeFlags).init(allocator),
            .channel_lists = std.StringHashMap(ChannelListState).init(allocator),
            .channel_topics = std.StringHashMap(TopicClock).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.clear();
        self.nick_to_node.deinit();
        self.channels.deinit();
        self.channel_members.deinit();
        self.channel_mode_flags.deinit();
        self.channel_lists.deinit();
        self.channel_topics.deinit();
        self.* = undefined;
    }

    pub fn clear(self: *Self) void {
        var nicks = self.nick_to_node.iterator();
        while (nicks.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.nick_to_node.clearRetainingCapacity();

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
    fn nickClaim(self: *const Self, nick: []const u8) ?nick_collision.Claim {
        var best: ?nick_collision.Claim = null;
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.entries.items) |m| {
                if (!std.ascii.eqlIgnoreCase(m.nick, nick)) continue;
                const cand = nick_collision.Claim{ .node_id = m.node, .hlc = m.hlc, .account = m.account };
                if (best == null or nick_collision.candidateWins(cand, best.?)) best = cand;
            }
        }
        return best;
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
        const incumbent = self.nickClaim(nick);
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
        const incumbent = self.nickClaim(nick) orelse return null;
        return nick_collision.loserUid(incumbent.node_id, nick);
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
                cur.node = node;
                cur.status = status;
                cur.hlc = hlc;
                // Keep the nick->node routing index in sync so PRIVMSG relay can
                // resolve this remote nick (best-effort: a full index degrades to
                // NAMES/WHOIS-only, never breaks membership). Re-run even on a
                // re-affirmation so entries predating this wiring self-heal.
                self.setNickLocation(nick, node) catch {};
                return .{ .outcome = if (changed) .status_changed else .unchanged, .prev_status = prev };
            } else {
                cur.freeStrings(self.allocator);
                _ = list.entries.swapRemove(idx);
                self.pruneIfEmpty(chan);
                // Drop the nick->node route only when the member is gone from EVERY
                // known channel; channel membership is the only mesh-wide nick
                // replication, so a still-present membership keeps the route alive.
                if (self.findMember(nick) == null) _ = self.removeNick(nick);
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
                    cur.freeStrings(self.allocator);
                    _ = list.entries.swapRemove(idx);
                    self.pruneIfEmpty(chan);
                    if (self.findMember(uid[0..]) == null) _ = self.removeNick(uid[0..]);
                    return .{ .outcome = .parted, .prev_status = prev };
                }
            }
            return .{ .outcome = .unchanged }; // part for an unknown member
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
            .node = node,
            .status = status,
            .hlc = hlc,
            .last_refreshed_ms = now_ms,
        });
        // Index this newly-learned remote nick for PRIVMSG relay routing
        // (best-effort, see the upsert branch above).
        self.setNickLocation(nick, node) catch {};
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
        // Pass 1: strip stale members from every roster in place (no map mutation),
        // collecting emptied channel keys to prune and the nicks whose routes may
        // now be orphaned. Removed nicks are duped because their owned strings are
        // freed here but the route-drop check in pass 2 still needs the name.
        var empties: std.ArrayListUnmanaged([]const u8) = .empty;
        defer empties.deinit(self.allocator);
        var orphan_nicks: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (orphan_nicks.items) |n| self.allocator.free(n);
            orphan_nicks.deinit(self.allocator);
        }

        var pruned: usize = 0;
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
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
                    // Capture the nick before freeStrings invalidates the slice.
                    if (self.allocator.dupe(u8, m.nick)) |owned| {
                        orphan_nicks.append(self.allocator, owned) catch self.allocator.free(owned);
                    } else |_| {}
                    m.freeStrings(self.allocator);
                    _ = list.entries.swapRemove(i);
                    pruned += 1;
                } else i += 1;
            }
            if (list.entries.items.len == 0) empties.append(self.allocator, entry.key_ptr.*) catch {};
        }

        // Pass 2: drop the nick→node route for any orphaned nick now absent from
        // EVERY channel roster (the only mesh-wide nick replication), exactly like
        // the part branch. `findMember` reflects the fully-swept rosters here.
        for (orphan_nicks.items) |nick| {
            if (self.findMember(nick) == null) _ = self.removeNick(nick);
        }

        // Pass 3: prune channels emptied by the sweep (mutates the channels map, so
        // it runs after the outer iteration completes).
        for (empties.items) |chan| self.pruneIfEmpty(chan);

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

        return existed;
    }

    fn ensureMemberList(self: *Self, chan: []const u8) Error!*MemberList {
        if (self.channel_members.getPtr(chan)) |list| return list;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channel_members.putNoClobber(owned, .{});
        return self.channel_members.getPtr(chan).?;
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
        self.removeNodeNicks(node);
        self.removeNodeChannels(node);
        self.removeNodeMembers(node);
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

test "mesh route_table renameNick keeps nick_count consistent across the collision path" {
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

    // Collision rename: "carol" renames onto "bob", which ALREADY routes to
    // another node. The old "carol" mapping is removed and the pre-existing
    // "bob" mapping is displaced, so exactly one nick_to_node entry disappears —
    // nick_count MUST drop from 2 to 1, not stay at 2.
    try table.setNickLocation("bob", 20);
    try std.testing.expectEqual(@as(usize, 2), table.nickCount());
    try std.testing.expect(try table.renameNick("carol", "bob", 10, .{}));
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("bob"));
    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("carol"));
    try std.testing.expectEqual(@as(usize, 1), table.nickCount());

    // The leaked counter must not wedge future inserts against max_nicks: with a
    // consistent count of 1 there is room for more nicks up to the cap.
    try table.setNickLocation("dave", 30);
    try std.testing.expectEqual(@as(usize, 2), table.nickCount());
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

    // The PART wire event carries the user's real nick, not the fallback UID
    // assigned by the receiver during collision resolution. It must still remove
    // the UID roster entry so NAMES does not retain a phantom generated nick.
    const res = try table.applyMembership("#root", "trev", 10, 0, 2, false, .{}, 0);
    try std.testing.expectEqual(RouteTable.ApplyOutcome.parted, res.outcome);
    try std.testing.expect(table.findMember(uid[0..]) == null);
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#root").len);
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

    // Now strictly past the window: the member is reaped, its emptied channel is
    // pruned, and its nick→node route is dropped (last channel gone).
    try std.testing.expectEqual(@as(usize, 1), table.pruneStale(T + 100_000, window));
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#chat").len);
    try std.testing.expect(table.nickNode("alice") == null);
    try std.testing.expect(table.findMember("alice") == null);
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
    fn resolver(self: *LocalNickStub) LocalNickResolver {
        return .{ .ctx = self, .held_fn = isHeld, .account_fn = accountOf, .hlc_fn = hlcOf };
    }
};

test "resolveIncomingNick keeps an uncontested nick" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();
    try std.testing.expectEqual(NickDecision.keep, table.resolveIncomingNick("alice", 10, 100, "", true));
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
