// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded cross-node route table for UNDERTOW message fan-out.
//!
//! The table is pure state: callers own all I/O decisions and pass allocator
//! ownership in at init. String keys are copied into managed StringHashMaps and
//! released on removal/deinit.
const std = @import("std");
const nick_collision = @import("../nick_collision.zig");
const uid_alloc = @import("../uid_alloc.zig");
const contracts = @import("contracts.zig");
const storage = @import("storage.zig");
const channel_list_event = @import("../../../proto/channel_list_event.zig");

pub const NodeId = contracts.NodeId;
pub const SessionToken = contracts.SessionToken;
pub const NickClaim = contracts.NickClaim;
pub const LocalNickResolver = contracts.LocalNickResolver;
pub const NickDecision = contracts.NickDecision;
pub const Error = contracts.Error;
pub const Config = contracts.Config;
pub const MembershipChange = contracts.MembershipChange;
pub const Member = contracts.Member;
pub const MemberIdentity = contracts.MemberIdentity;
pub const SessionTokenReconcileObserver = contracts.SessionTokenReconcileObserver;
pub const SessionTokenReconcileResult = contracts.SessionTokenReconcileResult;
pub const SessionTokenNickMatch = contracts.SessionTokenNickMatch;
pub const ChannelListKind = contracts.ChannelListKind;
pub const ChannelListEntry = contracts.ChannelListEntry;
pub const ChannelModeFlags = contracts.ChannelModeFlags;
pub const TopicClock = contracts.TopicClock;
pub const TopicView = contracts.TopicView;

pub const NickKey = storage.NickKey;
const NodeRef = storage.NodeRef;
const ChannelState = storage.ChannelState;
const ChannelListState = storage.ChannelListState;
const MemberList = storage.MemberList;
const PartTombstone = storage.PartTombstone;
const PartTombList = storage.PartTombList;

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

fn dupeOwnedBytes(allocator: std.mem.Allocator, text: []const u8) Error![]u8 {
    if (text.len == 0) return &.{};
    return allocator.dupe(u8, text);
}

fn freeOwnedBytes(allocator: std.mem.Allocator, text: []u8) void {
    if (text.len == 0) return;
    allocator.free(text);
}

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
        while (topics.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeOwnedBytes(self.allocator, entry.value_ptr.topic);
            freeOwnedBytes(self.allocator, entry.value_ptr.setter);
        }
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
                // Collision identity ignores display-only accounts (F1).
                const cand = nick_collision.Claim{
                    .node_id = m.node,
                    .hlc = m.hlc,
                    .account = if (m.account_trusted) m.account else "",
                };
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
    pub fn noteBestNickClaim(self: *Self, nick: []const u8, claim: NickClaim) void {
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
    pub fn rebuildAllBestNickClaims(self: *Self) bool {
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
            // An unproven newcomer does not take the nick from a residence-trusted
            // holder, including when its HLC is higher. HLC remains the tiebreak
            // between two untrusted claims.
            if (inc.account.len != 0 and acct.len == 0) {
                return .{ .rename_to_uid = nick_collision.loserUid(node, nick) };
            }
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
                    member.account_trusted = ident.account_trusted;
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
                    row.account_trusted = identity.account_trusted;
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
                cur.account_trusted = ident.account_trusted;
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
            .account_trusted = ident.account_trusted,
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
    /// events (hlc <= stored) are ignored. The accepted text stays in this table
    /// so a remote-only channel can still answer LIST/LISTX after the daemon
    /// drains the change queue. A failed copy leaves the previous record in place.
    pub fn applyTopic(
        self: *Self,
        chan: []const u8,
        node: NodeId,
        hlc: u64,
        text: []const u8,
        setter: []const u8,
        set_at: i64,
        present: bool,
    ) Error!ApplyTopicOutcome {
        try self.validateName(chan);
        try validateNode(node);

        if (self.channel_topics.getPtr(chan)) |cur| {
            if (hlc <= cur.hlc) return .unchanged;
            const owned_topic = try dupeOwnedBytes(self.allocator, text);
            errdefer freeOwnedBytes(self.allocator, owned_topic);
            const owned_setter = try dupeOwnedBytes(self.allocator, setter);
            freeOwnedBytes(self.allocator, cur.topic);
            freeOwnedBytes(self.allocator, cur.setter);
            cur.topic = owned_topic;
            cur.setter = owned_setter;
            cur.set_at = set_at;
            cur.present = present;
            cur.origin_node = node;
            cur.hlc = hlc;
            return .changed;
        }

        if (self.channel_topics.count() >= self.cfg.max_channels) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        const owned_topic = try dupeOwnedBytes(self.allocator, text);
        errdefer freeOwnedBytes(self.allocator, owned_topic);
        const owned_setter = try dupeOwnedBytes(self.allocator, setter);
        errdefer freeOwnedBytes(self.allocator, owned_setter);
        try self.channel_topics.putNoClobber(owned, .{
            .origin_node = node,
            .hlc = hlc,
            .topic = owned_topic,
            .setter = owned_setter,
            .set_at = set_at,
            .present = present,
        });
        return .changed;
    }

    /// Topic text last accepted for `chan`, or null when this peer has not
    /// published one. The slices borrow the route table.
    pub fn channelTopic(self: *const Self, chan: []const u8) ?TopicView {
        const cur = self.channel_topics.get(chan) orelse return null;
        return .{
            .topic = if (cur.present) cur.topic else "",
            .setter = cur.setter,
            .set_at = cur.set_at,
            .present = cur.present,
            .hlc = cur.hlc,
            .origin_node = cur.origin_node,
        };
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
