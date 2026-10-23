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

const toml = @import("../../../proto/toml.zig");

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
