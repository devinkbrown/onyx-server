// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for the UNDERTOW network-state CRDT store.
const std = @import("std");

const state = @import("state.zig");

const NetworkState = state.NetworkState;
const MembershipSet = state.OrSet(state.MembershipKey);
const BanSet = state.OrSet(state.BanKey);

const max_recorded_deltas = 96;

const RecordedDelta = union(enum) {
    sparse_state: NetworkState,
    membership: MembershipSet,
    ban: BanSet,

    fn deinit(self: *RecordedDelta) void {
        switch (self.*) {
            .sparse_state => |*ns| ns.deinit(),
            .membership => |*delta| delta.deinit(),
            .ban => |*delta| delta.deinit(),
        }
    }

    fn apply(self: *const RecordedDelta, target: *NetworkState) !void {
        switch (self.*) {
            .sparse_state => |*ns| try target.merge(ns),
            .membership => |delta| try target.memberships.mergeDelta(delta),
            .ban => |delta| try target.bans.mergeDelta(delta),
        }
    }
};

fn makeHlc(wall_ms: u64, logical: u16) !state.Hlc {
    return state.Hlc.init(wall_ms, logical);
}

fn uidAt(idx: usize) !state.Uid {
    return switch (idx % 6) {
        0 => state.Uid.init("001AAAAAA"),
        1 => state.Uid.init("002BBBBBB"),
        2 => state.Uid.init("003CCCCCC"),
        3 => state.Uid.init("004DDDDDD"),
        4 => state.Uid.init("005EEEEEE"),
        else => state.Uid.init("006FFFFFF"),
    };
}

fn nickAt(idx: usize) !state.Nick {
    return switch (idx % 6) {
        0 => state.Nick.init("alice"),
        1 => state.Nick.init("bob"),
        2 => state.Nick.init("carol"),
        3 => state.Nick.init("dave"),
        4 => state.Nick.init("erin"),
        else => state.Nick.init("frank"),
    };
}

fn channelAt(idx: usize) !state.ChannelName {
    return switch (idx % 4) {
        0 => state.ChannelName.init("#onyx"),
        1 => state.ChannelName.init("#undertow"),
        2 => state.ChannelName.init("#crdt"),
        else => state.ChannelName.init("#mesh"),
    };
}

fn shortTextAt(idx: usize) !state.ShortText {
    return switch (idx % 6) {
        0 => state.ShortText.init("alpha"),
        1 => state.ShortText.init("bravo"),
        2 => state.ShortText.init("charlie"),
        3 => state.ShortText.init("delta"),
        4 => state.ShortText.init("echo"),
        else => state.ShortText.init("foxtrot"),
    };
}

fn topicAt(idx: usize) !state.TopicText {
    return switch (idx % 5) {
        0 => state.TopicText.init("mesh state"),
        1 => state.TopicText.init("deterministic ocean"),
        2 => state.TopicText.init("bounded property test"),
        3 => state.TopicText.init("causal repair"),
        else => state.TopicText.init("ircx crdt"),
    };
}

fn modeParamAt(idx: usize) !state.ModeParam {
    return switch (idx % 5) {
        0 => state.ModeParam.init("10"),
        1 => state.ModeParam.init("25"),
        2 => state.ModeParam.init("50"),
        3 => state.ModeParam.init("secret"),
        else => state.ModeParam.init("mesh-key"),
    };
}

fn maskAt(idx: usize) []const u8 {
    return switch (idx % 5) {
        0 => "*!*@example.test",
        1 => "*!*@mesh.test",
        2 => "bad!*@host.test",
        3 => "*!*@Example.TEST",
        else => "quiet!*@undertow.test",
    };
}

fn cloneState(allocator: std.mem.Allocator, source: *const NetworkState) !NetworkState {
    var out = NetworkState.init(allocator, source.replica_id, source.node_id);
    errdefer out.deinit();
    try out.merge(source);
    return out;
}

fn expectMergeLaws(allocator: std.mem.Allocator, a: *const NetworkState, b: *const NetworkState, c: *const NetworkState) !void {
    var ab = try cloneState(allocator, a);
    defer ab.deinit();
    try ab.merge(b);

    var ba = try cloneState(allocator, b);
    defer ba.deinit();
    try ba.merge(a);
    try std.testing.expect(NetworkState.eql(&ab, &ba));

    var left = try cloneState(allocator, a);
    defer left.deinit();
    try left.merge(b);
    try left.merge(c);

    var bc = try cloneState(allocator, b);
    defer bc.deinit();
    try bc.merge(c);

    var right = try cloneState(allocator, a);
    defer right.deinit();
    try right.merge(&bc);
    try std.testing.expect(NetworkState.eql(&left, &right));

    var idem = try cloneState(allocator, a);
    defer idem.deinit();
    try idem.merge(a);
    try std.testing.expect(NetworkState.eql(&idem, a));
}

fn randomReplicaIndex(random: std.Random, replica_count: usize) usize {
    return random.uintLessThan(usize, replica_count);
}

fn randomSession(random: std.Random) u64 {
    return 1 + random.uintLessThan(u64, 3);
}

fn policyForBooleanMode(mode: u8) state.BooleanModePolicy {
    return switch (mode) {
        'm' => .add_wins,
        else => .remove_wins,
    };
}

fn randomBanKind(random: std.Random) state.BanKind {
    return switch (random.uintLessThan(u8, 3)) {
        0 => .ban,
        1 => .except,
        else => .invex,
    };
}

fn applyRandomStateOp(ns: *NetworkState, random: std.Random, step: u64) !void {
    const uid = try uidAt(random.uintLessThan(usize, 6));
    const nick = try nickAt(random.uintLessThan(usize, 6));
    const chan = try channelAt(random.uintLessThan(usize, 4));
    const hlc = try makeHlc(10_000 + step, @intCast(step % 17));

    switch (random.uintLessThan(u8, 10)) {
        0 => try ns.upsertUser(uid, .{
            .nick = nick,
            .account = try shortTextAt(step),
            .realname = try shortTextAt(step + 1),
        }, hlc, @intCast(1 + random.uintLessThan(u16, 64))),
        1 => try ns.setPresence(uid, .{
            .expires_at_ms = 50_000 + step,
            .tombstoned = random.boolean(),
        }, hlc),
        2 => try ns.claimNick(nick, uid, @intCast(1 + random.uintLessThan(u16, 64)), hlc),
        3 => try ns.createChannel(chan, hlc, @intCast(1 + random.uintLessThan(u16, 64))),
        4 => try ns.join(chan, uid, randomSession(random)),
        5 => try ns.part(chan, uid, randomSession(random)),
        6 => try ns.setPrefixMode(.{ .channel = chan, .uid = uid, .mode = if (random.boolean()) 'o' else 'v' }, random.boolean(), @intCast(1 + random.uintLessThan(u16, 64)), hlc),
        7 => {
            const mode: u8 = if (random.boolean()) 'm' else 'i';
            try ns.setBooleanMode(.{ .channel = chan, .mode = mode }, policyForBooleanMode(mode), random.boolean(), hlc);
        },
        8 => try ns.setParamMode(.{ .channel = chan, .mode = if (random.boolean()) 'l' else 'k' }, try modeParamAt(step), @intCast(1 + random.uintLessThan(u16, 64)), hlc),
        else => try ns.setTopic(chan, try topicAt(step), uid, hlc),
    }
}

fn populateRandomState(ns: *NetworkState, random: std.Random, steps: usize, base_step: u64) !void {
    var step: usize = 0;
    while (step < steps) : (step += 1) {
        try applyRandomStateOp(ns, random, base_step + step);
    }
}

fn appendDelta(allocator: std.mem.Allocator, deltas: *std.ArrayList(RecordedDelta), delta: RecordedDelta) !void {
    var owned = delta;
    errdefer owned.deinit();
    try deltas.append(allocator, owned);
}

fn deinitRecordedDeltas(allocator: std.mem.Allocator, deltas: *std.ArrayList(RecordedDelta)) void {
    for (deltas.items) |*delta| delta.deinit();
    deltas.deinit(allocator);
}

fn recordSparseOp(allocator: std.mem.Allocator, origin: *NetworkState, deltas: *std.ArrayList(RecordedDelta), random: std.Random, step: u64) !void {
    const uid = try uidAt(random.uintLessThan(usize, 6));
    const nick = try nickAt(random.uintLessThan(usize, 6));
    const chan = try channelAt(random.uintLessThan(usize, 4));
    const hlc = try makeHlc(20_000 + step, @intCast(step % 23));
    const action = random.uintLessThan(u8, 9);

    switch (action) {
        0 => {
            const profile = state.UserProfile{
                .nick = nick,
                .account = try shortTextAt(step),
                .realname = try shortTextAt(step + 2),
            };
            try origin.upsertUser(uid, profile, hlc, 10);
            var sparse = NetworkState.init(allocator, origin.replica_id, origin.node_id);
            errdefer sparse.deinit();
            try sparse.upsertUser(uid, profile, hlc, 10);
            try appendDelta(allocator, deltas, .{ .sparse_state = sparse });
        },
        1 => {
            try origin.claimNick(nick, uid, 10 + @as(state.Authority, @intCast(step % 5)), hlc);
            var sparse = NetworkState.init(allocator, origin.replica_id, origin.node_id);
            errdefer sparse.deinit();
            try sparse.claimNick(nick, uid, 10 + @as(state.Authority, @intCast(step % 5)), hlc);
            try appendDelta(allocator, deltas, .{ .sparse_state = sparse });
        },
        2 => {
            try origin.createChannel(chan, hlc, 10);
            var sparse = NetworkState.init(allocator, origin.replica_id, origin.node_id);
            errdefer sparse.deinit();
            try sparse.createChannel(chan, hlc, 10);
            try appendDelta(allocator, deltas, .{ .sparse_state = sparse });
        },
        3 => {
            const key = state.MembershipKey{ .channel = chan, .uid = uid, .session = randomSession(random) };
            var delta = try origin.memberships.add(key);
            errdefer delta.deinit();
            try appendDelta(allocator, deltas, .{ .membership = delta });
        },
        4 => {
            const key = state.MembershipKey{ .channel = chan, .uid = uid, .session = randomSession(random) };
            var delta = try origin.memberships.remove(key);
            errdefer delta.deinit();
            try appendDelta(allocator, deltas, .{ .membership = delta });
        },
        5 => {
            const mode: u8 = if (random.boolean()) 'm' else 'i';
            const key = state.BooleanModeKey{ .channel = chan, .mode = mode };
            const policy = policyForBooleanMode(mode);
            const enabled = random.boolean();
            try origin.setBooleanMode(key, policy, enabled, hlc);
            var sparse = NetworkState.init(allocator, origin.replica_id, origin.node_id);
            errdefer sparse.deinit();
            try sparse.setBooleanMode(key, policy, enabled, hlc);
            try appendDelta(allocator, deltas, .{ .sparse_state = sparse });
        },
        6 => {
            const key = state.BanKey{ .channel = chan, .kind = randomBanKind(random), .mask = try state.Mask.initLower(maskAt(step)) };
            var delta = try origin.bans.add(key);
            errdefer delta.deinit();
            try appendDelta(allocator, deltas, .{ .ban = delta });
        },
        7 => {
            const key = state.BanKey{ .channel = chan, .kind = randomBanKind(random), .mask = try state.Mask.initLower(maskAt(step)) };
            var delta = try origin.bans.remove(key);
            errdefer delta.deinit();
            try appendDelta(allocator, deltas, .{ .ban = delta });
        },
        else => {
            try origin.setTopic(chan, try topicAt(step), uid, hlc);
            var sparse = NetworkState.init(allocator, origin.replica_id, origin.node_id);
            errdefer sparse.deinit();
            try sparse.setTopic(chan, try topicAt(step), uid, hlc);
            try appendDelta(allocator, deltas, .{ .sparse_state = sparse });
        },
    }
}

fn feedU64(hasher: *std.hash.Wyhash, value: u64) void {
    hasher.update(std.mem.asBytes(&value));
}

fn feedBytes(hasher: *std.hash.Wyhash, bytes: []const u8) void {
    feedU64(hasher, bytes.len);
    hasher.update(bytes);
}

fn observableFingerprint(ns: *const NetworkState) !u64 {
    var hasher = std.hash.Wyhash.init(0x5791_3d4f_8abc_e002);

    var chan_idx: usize = 0;
    while (chan_idx < 4) : (chan_idx += 1) {
        const chan = try channelAt(chan_idx);
        feedBytes(&hasher, chan.asSlice());
        if (ns.channelBirth(chan)) |birth| {
            feedU64(&hasher, 1);
            feedU64(&hasher, @intCast(birth.wall_ms));
            feedU64(&hasher, birth.logical);
        } else {
            feedU64(&hasher, 0);
        }

        var uid_idx: usize = 0;
        while (uid_idx < 6) : (uid_idx += 1) {
            const uid = try uidAt(uid_idx);
            var session: u64 = 1;
            while (session <= 3) : (session += 1) {
                feedU64(&hasher, if (ns.hasMember(chan, uid, session)) 1 else 0);
            }
        }

        var mask_idx: usize = 0;
        while (mask_idx < 5) : (mask_idx += 1) {
            feedU64(&hasher, if (try ns.hasBan(chan, .ban, maskAt(mask_idx))) 1 else 0);
        }
    }

    var nick_idx: usize = 0;
    while (nick_idx < 6) : (nick_idx += 1) {
        const nick = try nickAt(nick_idx);
        var uid_idx: usize = 0;
        while (uid_idx < 6) : (uid_idx += 1) {
            const resolution = ns.resolveNick(nick, try uidAt(uid_idx));
            feedU64(&hasher, @backingInt(resolution.outcome));
            feedBytes(&hasher, resolution.display.asSlice());
            if (resolution.winner_uid) |winner| feedBytes(&hasher, winner.asSlice()) else feedU64(&hasher, 0);
        }
    }

    return hasher.final();
}

test "network state randomized full-state merge laws" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7374_6174_655f_6c31);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 32) : (iter += 1) {
        var a = NetworkState.init(allocator, 1, 11);
        defer a.deinit();
        var b = NetworkState.init(allocator, 2, 22);
        defer b.deinit();
        var c = NetworkState.init(allocator, 3, 33);
        defer c.deinit();

        try populateRandomState(&a, random, 24, iter * 1000);
        try populateRandomState(&b, random, 24, iter * 1000 + 100);
        try populateRandomState(&c, random, 24, iter * 1000 + 200);

        try expectMergeLaws(allocator, &a, &b, &c);
    }
}

test "network state sparse deltas converge in randomized exchange order" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6465_6c74_615f_6f31);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 24) : (iter += 1) {
        const replica_count = 2 + random.uintLessThan(usize, 2);
        var replicas = [_]NetworkState{
            NetworkState.init(allocator, 1, 11),
            NetworkState.init(allocator, 2, 22),
            NetworkState.init(allocator, 3, 33),
        };
        defer for (&replicas) |*replica| replica.deinit();

        var deltas: std.ArrayList(RecordedDelta) = .empty;
        defer deinitRecordedDeltas(allocator, &deltas);

        var step: usize = 0;
        while (step < 36) : (step += 1) {
            const origin_idx = randomReplicaIndex(random, replica_count);
            try recordSparseOp(allocator, &replicas[origin_idx], &deltas, random, iter * 1000 + step);
        }
        try std.testing.expect(deltas.items.len <= max_recorded_deltas);

        var order: [max_recorded_deltas]usize = undefined;
        for (order[0..deltas.items.len], 0..) |*slot, idx| slot.* = idx;

        for (replicas[0..replica_count]) |*replica| {
            random.shuffle(usize, order[0..deltas.items.len]);
            for (order[0..deltas.items.len]) |delta_idx| {
                try deltas.items[delta_idx].apply(replica);
            }
        }

        for (replicas[1..replica_count]) |*replica| {
            try std.testing.expect(NetworkState.eql(&replicas[0], replica));
        }
    }
}

test "membership tombstones suppress observed adds but not causal re-adds" {
    const allocator = std.testing.allocator;
    const chan = try state.ChannelName.init("#tomb");
    const uid = try state.Uid.init("001TOMB");
    const key = state.MembershipKey{ .channel = chan, .uid = uid, .session = 1 };

    var a = NetworkState.init(allocator, 1, 11);
    defer a.deinit();
    var b = NetworkState.init(allocator, 2, 22);
    defer b.deinit();

    var add_seen = try a.memberships.add(key);
    defer add_seen.deinit();
    try b.memberships.mergeDelta(add_seen);

    var observed_remove = try b.memberships.remove(key);
    defer observed_remove.deinit();

    var late_target = NetworkState.init(allocator, 9, 99);
    defer late_target.deinit();
    try late_target.memberships.mergeDelta(observed_remove);
    try late_target.memberships.mergeDelta(add_seen);
    try std.testing.expect(!late_target.hasMember(chan, uid, 1));

    var readd_after_remove = try b.memberships.add(key);
    defer readd_after_remove.deinit();

    var left = NetworkState.init(allocator, 10, 100);
    defer left.deinit();
    try left.memberships.mergeDelta(observed_remove);
    try left.memberships.mergeDelta(add_seen);
    try left.memberships.mergeDelta(readd_after_remove);

    var right = NetworkState.init(allocator, 11, 110);
    defer right.deinit();
    try right.memberships.mergeDelta(readd_after_remove);
    try right.memberships.mergeDelta(add_seen);
    try right.memberships.mergeDelta(observed_remove);

    try std.testing.expect(left.hasMember(chan, uid, 1));
    try std.testing.expect(right.hasMember(chan, uid, 1));
    try std.testing.expect(NetworkState.eql(&left, &right));
}

test "observable fingerprint changes for same-cardinality differing content" {
    const allocator = std.testing.allocator;
    const chan = try state.ChannelName.init("#onyx");

    var a = NetworkState.init(allocator, 1, 11);
    defer a.deinit();
    var b = NetworkState.init(allocator, 2, 22);
    defer b.deinit();

    try a.createChannel(chan, try makeHlc(1000, 0), 10);
    try b.createChannel(chan, try makeHlc(2000, 0), 10);
    try std.testing.expectEqual(@as(usize, 1), a.channels.items.len);
    try std.testing.expectEqual(@as(usize, 1), b.channels.items.len);
    try std.testing.expect(!NetworkState.eql(&a, &b));
    try std.testing.expect((try observableFingerprint(&a)) != (try observableFingerprint(&b)));

    var c = NetworkState.init(allocator, 3, 33);
    defer c.deinit();
    var d = NetworkState.init(allocator, 4, 44);
    defer d.deinit();

    const nick = try state.Nick.init("alice");
    try c.claimNick(nick, try state.Uid.init("001AAAAAA"), 10, try makeHlc(3000, 0));
    try d.claimNick(nick, try state.Uid.init("002BBBBBB"), 10, try makeHlc(3000, 0));
    try std.testing.expectEqual(c.nick_claims.items.len, d.nick_claims.items.len);
    try std.testing.expect((try observableFingerprint(&c)) != (try observableFingerprint(&d)));
}

test "adversarial generated deltas do not panic or leak" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xadad_6576_6572_7365);
    const random = prng.random();

    var target = NetworkState.init(allocator, 50, 500);
    defer target.deinit();

    var step: usize = 0;
    while (step < 192) : (step += 1) {
        const replica_id: u64 = 100 + random.uintLessThan(u64, 8);
        var source = NetworkState.init(allocator, replica_id, replica_id * 10);
        defer source.deinit();

        const uid = try uidAt(random.uintLessThan(usize, 6));
        const chan = try channelAt(random.uintLessThan(usize, 4));
        const member_key = state.MembershipKey{ .channel = chan, .uid = uid, .session = randomSession(random) };

        switch (random.uintLessThan(u8, 6)) {
            0 => {
                var delta = try source.memberships.remove(member_key);
                defer delta.deinit();
                try target.memberships.mergeDelta(delta);
            },
            1 => {
                var add = try source.memberships.add(member_key);
                defer add.deinit();
                var remove = try source.memberships.remove(member_key);
                defer remove.deinit();
                if (random.boolean()) try target.memberships.mergeDelta(remove);
                try target.memberships.mergeDelta(add);
                try target.memberships.mergeDelta(remove);
            },
            2 => {
                const key = state.BanKey{ .channel = chan, .kind = randomBanKind(random), .mask = try state.Mask.initLower(maskAt(step)) };
                var delta = try source.bans.remove(key);
                defer delta.deinit();
                try target.bans.mergeDelta(delta);
            },
            3 => {
                const key = state.BanKey{ .channel = chan, .kind = randomBanKind(random), .mask = try state.Mask.initLower(maskAt(step)) };
                var add = try source.bans.add(key);
                defer add.deinit();
                try target.bans.mergeDelta(add);
                try target.bans.mergeDelta(add);
            },
            4 => try applyRandomStateOp(&target, random, 90_000 + step),
            else => {
                var sparse = NetworkState.init(allocator, replica_id, replica_id * 10);
                defer sparse.deinit();
                try applyRandomStateOp(&sparse, random, 100_000 + step);
                try target.merge(&sparse);
                try target.merge(&sparse);
            },
        }
    }
}
