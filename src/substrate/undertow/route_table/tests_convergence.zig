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

fn containsNode(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |candidate| {
        if (candidate == node) return true;
    }
    return false;
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

test "GAP-M2 a raised channel ceiling stores the 65th node" {
    const alloc = std.testing.allocator;
    var bounded = try RouteTable.init(alloc, .{ .max_nodes_per_channel = 64 });
    defer bounded.deinit();
    var n: NodeId = 1;
    while (n <= 64) : (n += 1) try bounded.updateOnMembershipChange("#m2", n, .join);
    try std.testing.expectError(error.ChannelFanoutFull, bounded.updateOnMembershipChange("#m2", 65, .join));

    var wide = try RouteTable.init(alloc, .{ .max_nodes_per_channel = 128 });
    defer wide.deinit();
    n = 1;
    while (n <= 65) : (n += 1) try wide.updateOnMembershipChange("#m2", n, .join);
    var out: [128]NodeId = undefined;
    const stored = try wide.channelNodes("#m2", &out);
    try std.testing.expectEqual(@as(usize, 65), stored);
    try std.testing.expect(containsNode(out[0..stored], 1));
    try std.testing.expect(containsNode(out[0..stored], 65));

    while (n <= 128) : (n += 1) try wide.updateOnMembershipChange("#m2", n, .join);
    try std.testing.expectError(error.ChannelFanoutFull, wide.updateOnMembershipChange("#m2", 129, .join));
    std.debug.print("GAP-M2 branch=raised ceilings store the 65th node and still evict only when full\n", .{});
}
