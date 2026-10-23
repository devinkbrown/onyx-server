// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Split test leaf for the UNDERTOW route-table contract.
const std = @import("std");
const core = @import("core.zig");
const RouteTable = core.RouteTable;
const NodeId = core.NodeId;
const SessionToken = core.SessionToken;
const NickClaim = core.NickClaim;
const NickKey = core.NickKey;
const LocalNickResolver = core.LocalNickResolver;
const NickDecision = core.NickDecision;
const Error = core.Error;
const Config = core.Config;
const MembershipChange = core.MembershipChange;
const Member = core.Member;
const MemberIdentity = core.MemberIdentity;
const SessionTokenReconcileObserver = core.SessionTokenReconcileObserver;
const SessionTokenReconcileResult = core.SessionTokenReconcileResult;
const SessionTokenNickMatch = core.SessionTokenNickMatch;
const ChannelListKind = core.ChannelListKind;
const ChannelListEntry = core.ChannelListEntry;
const ChannelModeFlags = core.ChannelModeFlags;
const TopicClock = core.TopicClock;
const TopicView = core.TopicView;
const nick_collision = @import("../nick_collision.zig");
const uid_alloc = @import("../uid_alloc.zig");
const membership_event = @import("../../../proto/membership_event.zig");
const channel_list_event = @import("../../../proto/channel_list_event.zig");

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
    _ = try table.applyMembership("#chat", "kain", 20, 0, 500, true, .{ .account = "kain", .account_trusted = true }, 0);
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
    _ = try table.applyMembership("#chat", "kain", 20, 0, 500, true, .{ .account = "kain", .account_trusted = true }, 0);
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 100, "kain", false));
    _ = try expectRename(table.resolveIncomingNick("kain", 10, 900, "kain", false));
    try std.testing.expectEqual(NickDecision.remote_same_account, table.resolveIncomingNick("kain", 10, 100, "kain", true));

    // Display-only incumbent (signed peer, no residence) also grants no coexistence.
    var display_only = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer display_only.deinit();
    _ = try display_only.applyMembership("#chat", "kain", 20, 0, 500, true, .{ .account = "kain", .account_trusted = false }, 0);
    _ = try expectRename(display_only.resolveIncomingNick("kain", 10, 100, "kain", true));
}

test "resolveIncomingNick sticky trust: an ESTABLISHED member's re-affirm is keep, independent of account trust (mesh R1)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // kain@A (node 20) was admitted into coexistence with a LOCAL kain while its
    // residence proof verified (the initial same-account admission).
    var stub = LocalNickStub{ .held = "kain", .acct = "kain", .hlc = 100 };
    table.setLocalNickResolver(stub.resolver());
    try std.testing.expectEqual(NickDecision.local_same_account, table.resolveIncomingNick("kain", 20, 100, "kain", true));
    _ = try table.applyMembership("#chat", "kain", 20, 0, 100, true, .{ .account = "kain", .account_trusted = true }, 0);

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
