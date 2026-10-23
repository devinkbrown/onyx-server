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
