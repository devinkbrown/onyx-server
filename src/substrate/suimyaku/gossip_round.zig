// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure SUIMYAKU gossip round driver: no sockets, timers, or daemon coupling.
const std = @import("std");

const membership_view = @import("membership_view.zig");
const goryu = @import("goryu.zig");
const toml = @import("../../proto/toml.zig");

pub const NodeId = membership_view.NodeId;
pub const MemberState = enum { alive, suspect, dead, left };
pub const Incarnation = u64;
pub const DeltaDot = goryu.Dot;
const max_tracked_witnesses = 16;

pub const SazanamiConfig = struct {
    suspicion_timeout_ms: i64 = 3_000,
    witness_quorum: u8 = 2,

    fn sanitized(self: SazanamiConfig) SazanamiConfig {
        var c = self;
        if (c.suspicion_timeout_ms < 0) c.suspicion_timeout_ms = 0;
        // A single accuser must never bury a peer: require at least two distinct
        // witnesses before a node can be declared dead. This closes a
        // config-reachable solo-DEAD on the live S2S path (e.g. a link-flap on a
        // 2-node mesh where the sole peer is the accuser).
        if (c.witness_quorum < 2) c.witness_quorum = 2;
        return c;
    }

    /// Overlay `[mesh.sazanami]` keys onto this config.
    pub fn applyToml(cfg: *SazanamiConfig, doc: *const toml.Document) void {
        if (doc.getInt("mesh.sazanami.suspicion_timeout_ms")) |v| cfg.suspicion_timeout_ms = v;
        if (doc.getUint("mesh.sazanami.witness_quorum")) |v| cfg.witness_quorum = @intCast(v);
    }
};

pub const Reaped = struct { id: NodeId, incarnation: Incarnation };

pub const Member = struct {
    id: NodeId,
    state: MemberState,
    incarnation: Incarnation,
    suspect_since_ms: i64 = 0,
    witnesses: WitnessSet = .{},
};

const WitnessSet = struct {
    ids: [max_tracked_witnesses]NodeId = undefined,
    len: u8 = 0,

    fn clear(self: *WitnessSet) void {
        self.len = 0;
    }

    fn add(self: *WitnessSet, id: NodeId) bool {
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            if (self.ids[i] == id) return false;
        }
        if (self.len >= max_tracked_witnesses) return false;
        self.ids[self.len] = id;
        self.len += 1;
        return true;
    }
};

pub const Membership = struct {
    allocator: std.mem.Allocator,
    cfg: SazanamiConfig,
    self_id: NodeId,
    self_incarnation: Incarnation = 0,
    members: std.AutoHashMap(NodeId, Member),

    fn init(allocator: std.mem.Allocator, self_id: NodeId, cfg: SazanamiConfig) Membership {
        return .{
            .allocator = allocator,
            .cfg = cfg.sanitized(),
            .self_id = self_id,
            .members = std.AutoHashMap(NodeId, Member).init(allocator),
        };
    }

    fn deinit(self: *Membership) void {
        self.members.deinit();
    }

    pub fn get(self: *const Membership, id: NodeId) ?Member {
        return self.members.get(id);
    }

    fn applyAlive(self: *Membership, node: NodeId, incarnation: Incarnation) !bool {
        if (node == self.self_id) {
            if (incarnation > self.self_incarnation) {
                self.self_incarnation = incarnation;
                return true;
            }
            return false;
        }

        const gop = try self.members.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .id = node, .state = .alive, .incarnation = incarnation };
            return true;
        }

        const m = gop.value_ptr;
        if ((m.state == .left or m.state == .dead) and incarnation <= m.incarnation) return false;
        if (incarnation > m.incarnation) {
            m.incarnation = incarnation;
            return toAlive(m);
        }
        if (incarnation == m.incarnation and m.state == .suspect) return toAlive(m);
        return false;
    }

    fn applySuspect(
        self: *Membership,
        node: NodeId,
        incarnation: Incarnation,
        witness: NodeId,
        now_ms: i64,
    ) !bool {
        if (node == self.self_id) {
            if (incarnation >= self.self_incarnation) {
                self.self_incarnation = incarnation + 1;
                return true;
            }
            return false;
        }

        const gop = try self.members.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .id = node,
                .state = .suspect,
                .incarnation = incarnation,
                .suspect_since_ms = now_ms,
            };
            _ = gop.value_ptr.witnesses.add(witness);
            return true;
        }

        const m = gop.value_ptr;
        if (incarnation < m.incarnation) return false;
        if (m.state == .left or m.state == .dead) return false;
        if (incarnation > m.incarnation or m.state == .alive) {
            m.incarnation = incarnation;
            m.state = .suspect;
            m.suspect_since_ms = now_ms;
            m.witnesses.clear();
            _ = m.witnesses.add(witness);
            return true;
        }
        return m.witnesses.add(witness);
    }

    fn applyDead(
        self: *Membership,
        node: NodeId,
        incarnation: Incarnation,
        witness: NodeId,
        now_ms: i64,
    ) !bool {
        var changed = try self.applySuspect(node, incarnation, witness, now_ms);
        if (node == self.self_id) return changed;
        if (self.members.getPtr(node)) |m| {
            if (self.maybeBury(m, now_ms)) changed = true;
        }
        return changed;
    }

    fn applyLeft(self: *Membership, node: NodeId, incarnation: Incarnation) !bool {
        if (node == self.self_id) return false;
        const gop = try self.members.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .id = node, .state = .left, .incarnation = incarnation };
            return true;
        }
        const m = gop.value_ptr;
        if (m.state == .left and incarnation <= m.incarnation) return false;
        if (incarnation < m.incarnation) return false;
        m.state = .left;
        m.incarnation = incarnation;
        m.witnesses.clear();
        return true;
    }

    fn tick(self: *Membership, now_ms: i64, reaped: *std.ArrayList(Reaped)) !void {
        var it = self.members.iterator();
        while (it.next()) |entry| {
            const m = entry.value_ptr;
            if (m.state != .suspect) continue;
            if (m.witnesses.len < self.cfg.witness_quorum) continue;
            if (now_ms - m.suspect_since_ms < self.cfg.suspicion_timeout_ms) continue;
            m.state = .dead;
            m.witnesses.clear();
            try reaped.append(self.allocator, .{ .id = m.id, .incarnation = m.incarnation });
        }
    }

    fn maybeBury(self: *Membership, m: *Member, now_ms: i64) bool {
        _ = now_ms;
        if (m.state != .suspect) return false;
        if (m.witnesses.len < self.cfg.witness_quorum) return false;
        if (self.cfg.suspicion_timeout_ms != 0) return false;
        m.state = .dead;
        m.witnesses.clear();
        return true;
    }

    fn toAlive(m: *Member) bool {
        const changed = m.state != .alive;
        m.state = .alive;
        m.suspect_since_ms = 0;
        m.witnesses.clear();
        return changed;
    }
};

pub const Config = struct {
    fanout: usize = 3,
    max_member_deltas: usize = 64,
    max_suspicions: usize = 64,

    pub fn sanitized(self: Config) Config {
        var c = self;
        if (c.fanout == 0) c.fanout = 1;
        if (c.max_member_deltas == 0) c.max_member_deltas = 1;
        return c;
    }

    /// Overlay `[mesh.gossip]` gossip-round keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.gossip.round_fanout")) |v| cfg.fanout = @intCast(v);
        if (doc.getUint("mesh.gossip.max_member_deltas")) |v| cfg.max_member_deltas = @intCast(v);
        if (doc.getUint("mesh.gossip.max_suspicions")) |v| cfg.max_suspicions = @intCast(v);
    }
};

pub const MemberDelta = struct {
    id: NodeId,
    state: MemberState,
    incarnation: Incarnation,
};

pub const Suspicion = struct { node: NodeId, incarnation: Incarnation, witness: NodeId };

pub const GossipPayload = struct {
    origin: NodeId,
    origin_incarnation: Incarnation,
    member_deltas: std.ArrayList(MemberDelta) = .empty,
    suspicions: std.ArrayList(Suspicion) = .empty,

    pub fn deinit(self: *GossipPayload, allocator: std.mem.Allocator) void {
        self.member_deltas.deinit(allocator);
        self.suspicions.deinit(allocator);
        self.* = .{
            .origin = self.origin,
            .origin_incarnation = self.origin_incarnation,
        };
    }
};

pub const RoundResult = struct {
    peers: std.ArrayList(NodeId) = .empty,
    payload: GossipPayload,

    pub fn deinit(self: *RoundResult, allocator: std.mem.Allocator) void {
        self.peers.deinit(allocator);
        self.payload.deinit(allocator);
    }
};

pub const GossipRound = struct {
    allocator: std.mem.Allocator,
    self_id: NodeId,
    view: membership_view.MembershipView,
    membership: Membership,

    pub fn init(
        allocator: std.mem.Allocator,
        self_id: NodeId,
        view_cfg: membership_view.Config,
        sazanami_cfg: SazanamiConfig,
    ) !GossipRound {
        var view = try membership_view.MembershipView.init(allocator, self_id, view_cfg);
        errdefer view.deinit();

        return .{
            .allocator = allocator,
            .self_id = self_id,
            .view = view,
            .membership = Membership.init(allocator, self_id, sazanami_cfg),
        };
    }

    pub fn deinit(self: *GossipRound) void {
        self.view.deinit();
        self.membership.deinit();
    }

    pub fn observeJoin(self: *GossipRound, peer: NodeId, now_ms: i64, rng_seed: u64) !void {
        if (peer == self.self_id or peer == 0) return;
        var rng = membership_view.Rng.init(mixSeed(rng_seed, self.self_id, peer));
        _ = try self.view.join(peer, now_ms, &rng);
        _ = try self.membership.applyAlive(peer, 0);
    }

    pub fn suspect(self: *GossipRound, peer: NodeId, incarnation: Incarnation, now_ms: i64) !void {
        _ = try self.membership.applySuspect(peer, incarnation, self.self_id, now_ms);
    }

    /// Merge inbound payloads, reap suspects, select peers, and build payload.
    pub fn run(
        self: *GossipRound,
        now_ms: i64,
        rng_seed: u64,
        peer_list: []const NodeId,
        received: []const GossipPayload,
        cfg_arg: Config,
    ) !RoundResult {
        const cfg = cfg_arg.sanitized();
        var rng = membership_view.Rng.init(mixSeed(rng_seed, self.self_id, @bitCast(now_ms)));

        for (received) |*payload| {
            try self.applyPayload(payload, now_ms, &rng);
        }

        var reaped: std.ArrayList(Reaped) = .empty;
        defer reaped.deinit(self.allocator);
        try self.membership.tick(now_ms, &reaped);
        for (reaped.items) |dead| {
            _ = try self.view.activeFailed(dead.id, now_ms, &rng);
        }

        var result = RoundResult{
            .payload = try self.buildPayload(now_ms, cfg),
        };
        errdefer result.deinit(self.allocator);
        result.peers = try selectPeers(self.allocator, self.self_id, peer_list, cfg.fanout, rng_seed);
        return result;
    }

    pub fn applyPayload(
        self: *GossipRound,
        payload: *const GossipPayload,
        now_ms: i64,
        rng: *membership_view.Rng,
    ) !void {
        if (payload.origin != 0 and payload.origin != self.self_id) {
            _ = try self.membership.applyAlive(payload.origin, payload.origin_incarnation);
            _ = try self.view.join(payload.origin, now_ms, rng);
        }

        for (payload.member_deltas.items) |delta| {
            if (delta.id == 0) continue;
            switch (delta.state) {
                .alive => {
                    _ = try self.membership.applyAlive(delta.id, delta.incarnation);
                    try self.learnAlive(delta.id, now_ms, rng);
                },
                .suspect => {
                    _ = try self.membership.applySuspect(
                        delta.id,
                        delta.incarnation,
                        payload.origin,
                        now_ms,
                    );
                },
                .dead => {
                    _ = try self.membership.applyDead(
                        delta.id,
                        delta.incarnation,
                        payload.origin,
                        now_ms,
                    );
                    if (self.membership.get(delta.id)) |member| {
                        if (member.state == .dead) try self.markFailed(delta.id, now_ms, rng);
                    }
                },
                .left => {
                    _ = try self.membership.applyLeft(delta.id, delta.incarnation);
                    if (delta.id != self.self_id) _ = try self.view.leave(delta.id);
                },
            }
        }

        for (payload.suspicions.items) |s| {
            if (s.node == 0) continue;
            _ = try self.membership.applySuspect(s.node, s.incarnation, s.witness, now_ms);
        }
    }

    pub fn buildPayload(self: *GossipRound, now_ms: i64, cfg_arg: Config) !GossipPayload {
        _ = now_ms;
        const cfg = cfg_arg.sanitized();
        var payload = GossipPayload{
            .origin = self.self_id,
            .origin_incarnation = self.membership.self_incarnation,
        };
        errdefer payload.deinit(self.allocator);

        try self.appendDelta(&payload, .{
            .id = self.self_id,
            .state = .alive,
            .incarnation = self.membership.self_incarnation,
        }, cfg.max_member_deltas);

        for (self.view.activeEntries()) |entry| {
            try self.appendKnownAlive(&payload, entry.id, cfg.max_member_deltas);
        }
        for (self.view.passiveEntries()) |entry| {
            try self.appendKnownAlive(&payload, entry.id, cfg.max_member_deltas);
        }

        var it = self.membership.members.iterator();
        while (it.next()) |entry| {
            const member = entry.value_ptr.*;
            switch (member.state) {
                .suspect => {
                    if (payload.suspicions.items.len < cfg.max_suspicions) {
                        try payload.suspicions.append(self.allocator, .{
                            .node = member.id,
                            .incarnation = member.incarnation,
                            .witness = self.self_id,
                        });
                    }
                },
                else => try self.appendDelta(&payload, .{
                    .id = member.id,
                    .state = member.state,
                    .incarnation = member.incarnation,
                }, cfg.max_member_deltas),
            }
        }

        sortPayload(&payload);
        return payload;
    }

    fn appendKnownAlive(
        self: *GossipRound,
        payload: *GossipPayload,
        id: NodeId,
        max_deltas: usize,
    ) !void {
        if (id == 0 or id == self.self_id) return;
        if (self.membership.get(id)) |member| {
            if (member.state != .alive) return;
            try self.appendDelta(payload, .{
                .id = id,
                .state = .alive,
                .incarnation = member.incarnation,
            }, max_deltas);
            return;
        }
        try self.appendDelta(payload, .{
            .id = id,
            .state = .alive,
            .incarnation = 0,
        }, max_deltas);
    }

    fn appendDelta(
        self: *GossipRound,
        payload: *GossipPayload,
        delta: MemberDelta,
        max_deltas: usize,
    ) !void {
        if (delta.id == 0) return;
        if (findDelta(payload.member_deltas.items, delta.id)) |idx| {
            if (deltaWins(delta, payload.member_deltas.items[idx])) {
                payload.member_deltas.items[idx] = delta;
            }
            return;
        }
        if (payload.member_deltas.items.len >= max_deltas) return;
        try payload.member_deltas.append(self.allocator, delta);
    }

    fn learnAlive(
        self: *GossipRound,
        id: NodeId,
        now_ms: i64,
        rng: *membership_view.Rng,
    ) !void {
        if (id == self.self_id) return;
        if (self.view.isActive(id)) {
            _ = try self.view.markActiveAlive(id, now_ms);
        } else {
            _ = try self.view.learnPassive(id, now_ms, rng);
        }
    }

    fn markFailed(
        self: *GossipRound,
        id: NodeId,
        now_ms: i64,
        rng: *membership_view.Rng,
    ) !void {
        if (id == self.self_id) return;
        _ = try self.view.activeFailed(id, now_ms, rng);
    }
};

pub fn selectPeers(
    allocator: std.mem.Allocator,
    self_id: NodeId,
    peer_list: []const NodeId,
    fanout_arg: usize,
    rng_seed: u64,
) !std.ArrayList(NodeId) {
    const fanout = if (fanout_arg == 0) 1 else fanout_arg;
    var candidates: std.ArrayList(NodeId) = .empty;
    defer candidates.deinit(allocator);

    for (peer_list) |peer| {
        if (peer == 0 or peer == self_id or containsNode(candidates.items, peer)) continue;
        try candidates.append(allocator, peer);
    }
    std.mem.sort(NodeId, candidates.items, {}, lessNode);

    var out: std.ArrayList(NodeId) = .empty;
    errdefer out.deinit(allocator);
    if (candidates.items.len == 0) return out;

    const want = @min(fanout, candidates.items.len);
    var prng = std.Random.DefaultPrng.init(mixSeed(rng_seed, self_id, @intCast(candidates.items.len)));
    const random = prng.random();
    var i: usize = 0;
    while (i < want) : (i += 1) {
        const j = i + random.uintLessThan(usize, candidates.items.len - i);
        std.mem.swap(NodeId, &candidates.items[i], &candidates.items[j]);
        try out.append(allocator, candidates.items[i]);
    }
    std.mem.sort(NodeId, out.items, {}, lessNode);
    return out;
}

fn findDelta(items: []const MemberDelta, id: NodeId) ?usize {
    for (items, 0..) |item, idx| {
        if (item.id == id) return idx;
    }
    return null;
}

fn deltaWins(candidate: MemberDelta, current: MemberDelta) bool {
    if (candidate.incarnation != current.incarnation) {
        return candidate.incarnation > current.incarnation;
    }
    return stateRank(candidate.state) > stateRank(current.state);
}

fn stateRank(state: MemberState) u8 {
    return switch (state) {
        .alive => 0,
        .suspect => 1,
        .dead => 2,
        .left => 3,
    };
}

fn sortPayload(payload: *GossipPayload) void {
    std.mem.sort(MemberDelta, payload.member_deltas.items, {}, lessDelta);
    std.mem.sort(Suspicion, payload.suspicions.items, {}, lessSuspicion);
}

fn lessNode(_: void, a: NodeId, b: NodeId) bool {
    return a < b;
}

fn lessDelta(_: void, a: MemberDelta, b: MemberDelta) bool {
    if (a.id != b.id) return a.id < b.id;
    if (a.incarnation != b.incarnation) return a.incarnation < b.incarnation;
    return stateRank(a.state) < stateRank(b.state);
}

fn lessSuspicion(_: void, a: Suspicion, b: Suspicion) bool {
    if (a.node != b.node) return a.node < b.node;
    if (a.incarnation != b.incarnation) return a.incarnation < b.incarnation;
    return a.witness < b.witness;
}

fn containsNode(nodes: []const NodeId, peer: NodeId) bool {
    for (nodes) |node| {
        if (node == peer) return true;
    }
    return false;
}

fn mixSeed(a: u64, b: u64, c: u64) u64 {
    var x = a ^ (b *% 0x9e3779b97f4a7c15) ^ (c *% 0xbf58476d1ce4e5b9);
    x ^= x >> 30;
    x *%= 0xbf58476d1ce4e5b9;
    x ^= x >> 27;
    x *%= 0x94d049bb133111eb;
    return x ^ (x >> 31);
}

const testing = std.testing;

fn newRound(id: NodeId, n: usize) !GossipRound {
    return GossipRound.init(testing.allocator, id, .{
        .active_capacity = n,
        .passive_capacity = n * 2 + 1,
    }, .{
        .suspicion_timeout_ms = 1_000,
        .witness_quorum = 2,
    });
}

test "a round propagates a join to all nodes within log(n) rounds" {
    const n: usize = 16;
    const fanout: usize = 6;
    const cfg = Config{ .fanout = fanout };
    var nodes: std.ArrayList(GossipRound) = .empty;
    defer {
        for (nodes.items) |*node| node.deinit();
        nodes.deinit(testing.allocator);
    }

    var peers: [n]NodeId = undefined;
    for (&peers, 0..) |*peer, idx| peer.* = @intCast(idx + 1);
    for (peers) |peer| {
        try nodes.append(testing.allocator, try newRound(peer, n));
    }

    const joiner = peers[0];
    var round: usize = 0;
    while (round < 4) : (round += 1) {
        var results: std.ArrayList(RoundResult) = .empty;
        defer {
            for (results.items) |*result| result.deinit(testing.allocator);
            results.deinit(testing.allocator);
        }

        for (nodes.items) |*node| {
            const result = try node.run(
                @intCast(round * 1000),
                0xC0FFEE +% @as(u64, @intCast(round)),
                &peers,
                &.{},
                cfg,
            );
            try results.append(testing.allocator, result);
        }

        for (results.items) |*result| {
            for (result.peers.items) |peer| {
                var rng = membership_view.Rng.init(mixSeed(@intCast(round), result.payload.origin, peer));
                try nodes.items[@as(usize, @intCast(peer - 1))].applyPayload(
                    &result.payload,
                    @intCast(round * 1000),
                    &rng,
                );
            }
        }
    }

    for (nodes.items) |*node| {
        if (node.self_id == joiner) continue;
        const member = node.membership.get(joiner) orelse return error.TestExpectedEqual;
        try testing.expectEqual(MemberState.alive, member.state);
    }
}

test "suspicion reports transition to confirmed dead deterministically" {
    var a = try newRound(1, 4);
    defer a.deinit();
    var b = try newRound(2, 4);
    defer b.deinit();
    var c = try newRound(3, 4);
    defer c.deinit();

    try a.observeJoin(4, 0, 1);
    try b.observeJoin(4, 0, 2);
    try a.suspect(4, 0, 0);
    try b.suspect(4, 0, 0);

    var pa = try a.buildPayload(0, .{});
    defer pa.deinit(testing.allocator);
    var pb = try b.buildPayload(0, .{});
    defer pb.deinit(testing.allocator);

    var rng = membership_view.Rng.init(9);
    try c.applyPayload(&pa, 0, &rng);
    try c.applyPayload(&pb, 0, &rng);
    try testing.expectEqual(MemberState.suspect, c.membership.get(4).?.state);

    var reaped: std.ArrayList(Reaped) = .empty;
    defer reaped.deinit(testing.allocator);
    try c.membership.tick(2_000, &reaped);
    try testing.expectEqual(MemberState.dead, c.membership.get(4).?.state);
    try testing.expectEqual(@as(usize, 1), reaped.items.len);
}

test "single dead witness does not evict active peer before quorum" {
    var c = try newRound(3, 4);
    defer c.deinit();

    try c.observeJoin(4, 0, 1);
    try testing.expect(c.view.isActive(4));

    var payload = GossipPayload{
        .origin = 1,
        .origin_incarnation = 0,
    };
    defer payload.deinit(testing.allocator);
    try payload.member_deltas.append(testing.allocator, .{
        .id = 4,
        .state = .dead,
        .incarnation = 0,
    });

    var rng = membership_view.Rng.init(9);
    try c.applyPayload(&payload, 0, &rng);

    const member = c.membership.get(4) orelse return error.TestExpectedEqual;
    try testing.expectEqual(MemberState.suspect, member.state);
    try testing.expect(c.view.isActive(4));

    var reaped: std.ArrayList(Reaped) = .empty;
    defer reaped.deinit(testing.allocator);
    try c.membership.tick(2_000, &reaped);
    try testing.expectEqual(@as(usize, 0), reaped.items.len);
    try testing.expect(c.view.isActive(4));
}

test "rounds are deterministic with the same seed" {
    var a = try newRound(1, 8);
    defer a.deinit();
    var b = try newRound(1, 8);
    defer b.deinit();

    const peers = [_]NodeId{ 1, 2, 3, 4, 5, 6, 7, 8 };
    for (peers[1..]) |peer| {
        try a.observeJoin(peer, @intCast(peer * 10), 11);
        try b.observeJoin(peer, @intCast(peer * 10), 11);
    }
    try a.suspect(7, 0, 500);
    try b.suspect(7, 0, 500);

    var ra = try a.run(1_000, 0x12345678, &peers, &.{}, .{ .fanout = 3 });
    defer ra.deinit(testing.allocator);
    var rb = try b.run(1_000, 0x12345678, &peers, &.{}, .{ .fanout = 3 });
    defer rb.deinit(testing.allocator);

    try testing.expectEqualSlices(NodeId, ra.peers.items, rb.peers.items);
    try testing.expectEqualSlices(MemberDelta, ra.payload.member_deltas.items, rb.payload.member_deltas.items);
    try testing.expectEqualSlices(Suspicion, ra.payload.suspicions.items, rb.payload.suspicions.items);
}

test "Config/SazanamiConfig applyToml overlay mesh.gossip + mesh.sazanami keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.gossip]
        \\round_fanout = 7
        \\max_suspicions = 99
        \\[mesh.sazanami]
        \\suspicion_timeout_ms = 4000
        \\witness_quorum = 5
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try testing.expectEqual(@as(usize, 7), cfg.fanout);
    try testing.expectEqual(@as(usize, 99), cfg.max_suspicions);
    try testing.expectEqual(@as(usize, 64), cfg.max_member_deltas); // default kept

    var sz = SazanamiConfig{};
    sz.applyToml(&doc);
    try testing.expectEqual(@as(i64, 4000), sz.suspicion_timeout_ms);
    try testing.expectEqual(@as(u8, 5), sz.witness_quorum);
}

test "witness_quorum floors to 2 so a single witness never buries a peer" {
    // A config asking for quorum 1 must be clamped to 2 (no solo accuser).
    try testing.expectEqual(@as(u8, 2), (SazanamiConfig{ .witness_quorum = 1 }).sanitized().witness_quorum);
    try testing.expectEqual(@as(u8, 2), (SazanamiConfig{ .witness_quorum = 0 }).sanitized().witness_quorum);

    // Behaviorally: even with a requested quorum of 1 and immediate burial
    // (suspicion_timeout_ms == 0), one witness must leave the peer merely
    // suspect; the second distinct witness reaches quorum and buries it.
    var m = Membership.init(testing.allocator, 3, .{ .witness_quorum = 1, .suspicion_timeout_ms = 0 });
    defer m.deinit();
    try testing.expectEqual(@as(u8, 2), m.cfg.witness_quorum);

    _ = try m.applyDead(4, 0, 1, 0); // witness 1 accuses node 4
    try testing.expectEqual(MemberState.suspect, (m.get(4) orelse return error.TestExpectedEqual).state);

    _ = try m.applyDead(4, 0, 2, 0); // second distinct witness reaches quorum
    try testing.expectEqual(MemberState.dead, (m.get(4) orelse return error.TestExpectedEqual).state);
}
