// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable public contracts for the UNDERTOW route table.
const std = @import("std");
const toml = @import("../../../proto/toml.zig");
const channel_list_event = @import("../../../proto/channel_list_event.zig");
const nick_collision = @import("../nick_collision.zig");

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
    /// Display account ("" = unknown). Used for WHOIS 330 / oper-prefix grant→nick
    /// mapping. Collision short-circuits consult this only when `account_trusted`.
    account: []u8,
    /// True only when a residence proof verified this account on an
    /// origin-authenticated claim (Design C / F1). Display may keep `account`
    /// without this bit; `resolveIncomingNick` must not.
    account_trusted: bool = false,
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

    pub fn freeStrings(self: *const Member, allocator: std.mem.Allocator) void {
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
    /// See `Member.account_trusted`. Default false keeps collision fail-closed.
    account_trusted: bool = false,
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

    pub fn part(self: SessionTokenReconcileObserver, channel: []const u8, member: *const Member) std.mem.Allocator.Error!void {
        return self.part_fn(self.ctx, channel, member);
    }

    pub fn rename(self: SessionTokenReconcileObserver, old_nick: []const u8, new_nick: []const u8, member: *const Member) std.mem.Allocator.Error!void {
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

/// One remote channel MODE-flag aggregate, tracked last-writer-wins by HLC.
pub const ChannelModeFlags = struct {
    flags: u16,
    origin_node: NodeId,
    hlc: u64,
};

/// LWW record for a channel's topic. `hlc` is the sole ordering key. The text is
/// kept here because a channel that exists only on the peer has no local world
/// row for LIST/LISTX to read. Strings are allocator-owned; empty text is a
/// zero-length slice and is not freed.
pub const TopicClock = struct {
    origin_node: NodeId,
    hlc: u64,
    topic: []u8 = &.{},
    setter: []u8 = &.{},
    set_at: i64 = 0,
    present: bool = false,
};

/// Borrowed topic published by one peer. Valid until that peer's route table
/// replaces or clears the channel.
pub const TopicView = struct {
    topic: []const u8,
    setter: []const u8,
    set_at: i64,
    present: bool,
    hlc: u64,
    origin_node: NodeId,
};
