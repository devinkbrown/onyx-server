// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic multi-node convergence harness for the Undertow CRDT mesh.
//!
//! The harness deliberately keeps I/O, wall time, and sockets out of the loop:
//! one master seed drives node clocks, node PRNGs, random workload selection,
//! network delay/drop/reorder, partitions, and anti-entropy replay.
const std = @import("std");

const anti_entropy = @import("anti_entropy.zig");
const clock = @import("clock.zig");
const state_mod = @import("state.zig");

const Allocator = std.mem.Allocator;
const Hlc = clock.Hlc;
const NetworkState = state_mod.NetworkState;

const NodeHandle = struct {
    id: u32,
};

const Delivery = struct {
    from: NodeHandle,
    to: NodeHandle,
    payload: u64,
};

const LinkConfig = struct {
    latency_ms: i64 = 1,
    jitter_ms: i64 = 0,
    drop_probability: f64 = 0.0,
    reorder_probability: f64 = 0.0,
    reorder_extra_ms: i64 = 0,
};

const LinkKey = struct {
    from: u32,
    to: u32,
};

const NetworkEvent = struct {
    due_ms: i64,
    seq: u64,
    from: NodeHandle,
    to: NodeHandle,
    payload: u64,
};

fn compareNetworkEvents(_: void, a: NetworkEvent, b: NetworkEvent) std.math.Order {
    const due_order = std.math.order(a.due_ms, b.due_ms);
    if (due_order != .eq) return due_order;
    return std.math.order(a.seq, b.seq);
}

const NetworkQueue = std.PriorityQueue(NetworkEvent, void, compareNetworkEvents);

const Network = struct {
    allocator: Allocator,
    clock_ms: i64 = 0,
    next_seq: u64 = 0,
    prng: std.Random.Pcg,
    events: NetworkQueue,
    partitioned: std.ArrayList(bool) = .empty,
    links: std.AutoHashMap(LinkKey, LinkConfig),
    delivery_log: std.ArrayList(Delivery) = .empty,

    fn init(allocator: Allocator, seed: u64) Network {
        return .{
            .allocator = allocator,
            .prng = std.Random.Pcg.init(seed),
            .events = NetworkQueue.initContext({}),
            .links = std.AutoHashMap(LinkKey, LinkConfig).init(allocator),
        };
    }

    fn deinit(self: *Network) void {
        self.delivery_log.deinit(self.allocator);
        self.links.deinit();
        self.partitioned.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    fn registerNodes(self: *Network, count: usize) !void {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            try self.partitioned.append(self.allocator, false);
        }
    }

    fn setLinkConfig(self: *Network, from: NodeHandle, to: NodeHandle, config: LinkConfig) !void {
        try self.links.put(.{ .from = from.id, .to = to.id }, config);
    }

    fn send(self: *Network, from: NodeHandle, to: NodeHandle, payload: u64) !void {
        const config = self.links.get(.{ .from = from.id, .to = to.id }) orelse LinkConfig{};
        const random = self.prng.random();
        if (random.float(f64) < config.drop_probability) return;

        var delay_ms = config.latency_ms;
        if (config.jitter_ms > 0) {
            delay_ms += random.intRangeAtMost(i64, 0, config.jitter_ms);
        }
        if (config.reorder_probability > 0 and random.float(f64) < config.reorder_probability) {
            const extra = if (config.reorder_extra_ms > 0) config.reorder_extra_ms else config.latency_ms;
            if (extra > 0) delay_ms += random.intRangeAtMost(i64, 1, extra);
        }

        const seq = self.next_seq;
        self.next_seq += 1;
        try self.events.push(self.allocator, .{
            .due_ms = self.clock_ms + delay_ms,
            .seq = seq,
            .from = from,
            .to = to,
            .payload = payload,
        });
    }

    fn partition(self: *Network, set: []const NodeHandle) void {
        @memset(self.partitioned.items, false);
        for (set) |node| self.partitioned.items[node.id] = true;
    }

    fn heal(self: *Network) void {
        @memset(self.partitioned.items, false);
    }

    fn run(self: *Network, max_ticks: usize) !usize {
        var ticks: usize = 0;
        while (ticks < max_ticks) : (ticks += 1) {
            const event = self.events.pop() orelse return ticks;
            if (event.due_ms > self.clock_ms) self.clock_ms = event.due_ms;
            if (self.partitioned.items[event.from.id] == self.partitioned.items[event.to.id]) {
                try self.delivery_log.append(self.allocator, .{
                    .from = event.from,
                    .to = event.to,
                    .payload = event.payload,
                });
            }
        }
        return ticks;
    }

    fn deliveries(self: *const Network) []const Delivery {
        return self.delivery_log.items;
    }
};

const uid_pool = [_][]const u8{
    "001ALPHA",
    "002BRAVO",
    "003CHARLIE",
    "004DELTA",
    "005ECHO",
    "006FOXTROT",
};

const nick_pool = [_][]const u8{
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
};

const channel_pool = [_][]const u8{
    "#ops",
    "#dev",
    "#mesh",
    "#zig",
};

const mask_pool = [_][]const u8{
    "*!*@a.test",
    "*!*@b.test",
    "*!*@c.test",
    "*!*@d.test",
};

const topic_pool = [_][]const u8{
    "mesh-green",
    "mesh-blue",
    "mesh-red",
    "mesh-gold",
};

const Node = struct {
    handle: NodeHandle,
    state: NetworkState,
    hlc: Hlc = .{},
    prng: std.Random.Pcg,

    fn init(allocator: Allocator, handle: NodeHandle, master_seed: u64) Node {
        const replica_id = @as(u64, handle.id) + 1;
        const node_id = 1000 + replica_id;
        return .{
            .handle = handle,
            .state = NetworkState.init(allocator, replica_id, node_id),
            .prng = std.Random.Pcg.init(deriveSeed(master_seed, replica_id)),
        };
    }

    fn deinit(self: *Node) void {
        self.state.deinit();
        self.* = undefined;
    }
};

const Delta = struct {
    from: u32,
    hlc: Hlc,
    state: NetworkState,

    fn deinit(self: *Delta) void {
        self.state.deinit();
        self.* = undefined;
    }
};

/// Seed-replayable CRDT mesh simulator.
pub const Mesh = struct {
    allocator: Allocator,
    seed: u64,
    network: Network,
    prng: std.Random.Pcg,
    nodes: std.ArrayList(Node) = .empty,
    deltas: std.ArrayList(Delta) = .empty,
    processed_deliveries: usize = 0,
    logical_ms: u64 = 0,

    pub fn init(allocator: Allocator, seed: u64, node_count: usize) !Mesh {
        var mesh = Mesh{
            .allocator = allocator,
            .seed = seed,
            .network = Network.init(allocator, deriveSeed(seed, 0x51d)),
            .prng = std.Random.Pcg.init(deriveSeed(seed, 0xa11ce)),
        };
        errdefer mesh.deinit();

        try mesh.network.registerNodes(node_count);
        var i: usize = 0;
        while (i < node_count) : (i += 1) {
            const handle = NodeHandle{ .id = @intCast(i) };
            try mesh.nodes.append(allocator, Node.init(allocator, handle, seed));
        }

        try mesh.configureLinks();
        return mesh;
    }

    pub fn deinit(self: *Mesh) void {
        for (self.deltas.items) |*delta| delta.deinit();
        self.deltas.deinit(self.allocator);
        for (self.nodes.items) |*node| node.deinit();
        self.nodes.deinit(self.allocator);
        self.network.deinit();
        self.* = undefined;
    }

    pub fn runRandomWorkload(self: *Mesh, steps: usize) !void {
        var step: usize = 0;
        while (step < steps) : (step += 1) {
            const node_idx = self.randomNodeIndex();
            try self.applyRandomOperation(node_idx);
            try self.broadcastSnapshot(node_idx);
            _ = try self.network.run(self.randomSmallTicks());
            try self.drainNetwork();
        }
    }

    pub fn partitionFirstHalf(self: *Mesh) !void {
        var handles: [16]NodeHandle = undefined;
        const count = @min(handles.len, @max(@as(usize, 1), self.nodes.items.len / 2));
        var i: usize = 0;
        while (i < count) : (i += 1) handles[i] = self.nodes.items[i].handle;
        self.network.partition(handles[0..count]);
    }

    pub fn heal(self: *Mesh) void {
        self.network.heal();
    }

    pub fn reconcile(self: *Mesh) !void {
        _ = try self.network.run(100_000);
        try self.drainNetwork();

        try self.replayAllDeltas();
        try self.replayAllDeltas();

        var rounds: usize = 0;
        while (rounds < 16) : (rounds += 1) {
            if (self.allEqual()) return;
            try self.repairRound(.{});
        }
        return error.DidNotConverge;
    }

    pub fn expectConverged(self: *Mesh) !void {
        if (self.nodes.items.len == 0) return;
        const first = &self.nodes.items[0].state;
        for (self.nodes.items[1..]) |*node| {
            if (!NetworkState.eql(first, &node.state)) {
                std.debug.print("Undertow convergence mismatch seed=0x{x}\n", .{self.seed});
                return error.DidNotConverge;
            }
        }
    }

    fn configureLinks(self: *Mesh) !void {
        for (self.nodes.items) |from| {
            for (self.nodes.items) |to| {
                if (from.handle.id == to.handle.id) continue;
                const r = self.prng.random();
                try self.network.setLinkConfig(from.handle, to.handle, .{
                    .latency_ms = r.intRangeAtMost(i64, 1, 8),
                    .jitter_ms = r.intRangeAtMost(i64, 0, 6),
                    .drop_probability = 0.12,
                    .reorder_probability = 0.35,
                    .reorder_extra_ms = 12,
                });
            }
        }
    }

    fn randomNodeIndex(self: *Mesh) usize {
        return self.prng.random().intRangeLessThan(usize, 0, self.nodes.items.len);
    }

    fn randomSmallTicks(self: *Mesh) usize {
        return self.prng.random().intRangeAtMost(usize, 0, 4);
    }

    fn nextHlc(self: *Mesh, node_idx: usize) !Hlc {
        self.logical_ms += 1;
        return self.nodes.items[node_idx].hlc.now(self.logical_ms);
    }

    fn applyRandomOperation(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        switch (r.intRangeLessThan(u8, 0, 6)) {
            0 => try self.opNickClaim(node_idx),
            1 => try self.opJoin(node_idx),
            2 => try self.opPart(node_idx),
            3 => try self.opTopic(node_idx),
            4 => try self.opBan(node_idx),
            5 => try self.opPrefixGrant(node_idx),
            else => unreachable,
        }
    }

    fn opNickClaim(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const nick = try state_mod.Nick.init(pick(&nick_pool, r));
        const hlc = try self.nextHlc(node_idx);
        const authority: state_mod.Authority = @intCast(10 + r.intRangeLessThan(u16, 0, 5));
        try node.state.upsertUser(uid, .{
            .nick = nick,
            .realname = try state_mod.ShortText.init("mesh user"),
        }, hlc, authority);
        try node.state.claimNick(nick, uid, authority, hlc);
    }

    fn opJoin(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const hlc = try self.nextHlc(node_idx);
        try node.state.createChannel(chan, hlc, 10);
        try node.state.join(chan, uid, 1);
    }

    fn opPart(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        try node.state.part(chan, uid, 1);
    }

    fn opTopic(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const topic = try state_mod.TopicText.init(pick(&topic_pool, r));
        const hlc = try self.nextHlc(node_idx);
        try node.state.createChannel(chan, hlc, 10);
        try node.state.setTopic(chan, topic, uid, hlc);
    }

    fn opBan(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const mask = pick(&mask_pool, r);
        if (r.intRangeLessThan(u8, 0, 2) == 0) {
            const hlc = try self.nextHlc(node_idx);
            try node.state.createChannel(chan, hlc, 10);
            try node.state.addBan(chan, .ban, mask, .{
                .setter = uid,
                .reason = try state_mod.ShortText.init("seeded"),
            }, hlc);
        } else {
            try node.state.removeBan(chan, .ban, mask);
        }
    }

    fn opPrefixGrant(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const mode: u8 = if (r.intRangeLessThan(u8, 0, 2) == 0) 'o' else 'v';
        const hlc = try self.nextHlc(node_idx);
        try node.state.createChannel(chan, hlc, 10);
        try node.state.join(chan, uid, 1);
        try node.state.setPrefixMode(.{ .channel = chan, .uid = uid, .mode = mode }, true, 10, hlc);
    }

    fn broadcastSnapshot(self: *Mesh, from_idx: usize) !void {
        var snapshot = try cloneNetworkState(&self.nodes.items[from_idx].state);
        var moved = false;
        errdefer if (!moved) snapshot.deinit();

        const payload: u64 = @intCast(self.deltas.items.len);
        try self.deltas.append(self.allocator, .{
            .from = @intCast(from_idx),
            .hlc = self.nodes.items[from_idx].hlc,
            .state = snapshot,
        });
        moved = true;
        for (self.nodes.items, 0..) |node, to_idx| {
            if (to_idx == from_idx) continue;
            try self.network.send(self.nodes.items[from_idx].handle, node.handle, payload);
        }
    }

    fn drainNetwork(self: *Mesh) !void {
        const deliveries = self.network.deliveries();
        while (self.processed_deliveries < deliveries.len) : (self.processed_deliveries += 1) {
            const delivery = deliveries[self.processed_deliveries];
            const payload: usize = @intCast(delivery.payload);
            try self.applyDeltaToNode(payload, delivery.to.id);
        }
    }

    fn replayAllDeltas(self: *Mesh) !void {
        for (self.deltas.items, 0..) |_, payload| {
            for (self.nodes.items, 0..) |_, node_idx| {
                try self.applyDeltaToNode(payload, @intCast(node_idx));
            }
        }
    }

    fn applyDeltaToNode(self: *Mesh, payload: usize, to_id: u32) !void {
        if (payload >= self.deltas.items.len or to_id >= self.nodes.items.len) return error.InvalidDelta;
        const delta = &self.deltas.items[payload];
        const to = &self.nodes.items[to_id];
        _ = try to.hlc.recv(self.logical_ms, delta.hlc);
        try to.state.merge(&delta.state);
    }

    fn repairRound(self: *Mesh, strategy_config: anti_entropy.StrategyConfig) !void {
        var i: usize = 0;
        while (i < self.nodes.items.len) : (i += 1) {
            var j: usize = 0;
            while (j < self.nodes.items.len) : (j += 1) {
                if (i == j) continue;
                _ = try self.repairPair(i, j, strategy_config);
            }
        }
    }

    const RepairResult = struct {
        strategy: anti_entropy.RepairStrategy,
        pull_count: usize,
        push_count: usize,
    };

    fn repairPair(self: *Mesh, local_idx: usize, remote_idx: usize, strategy_config: anti_entropy.StrategyConfig) !RepairResult {
        var local = anti_entropy.Lane.init(self.allocator, .memberships);
        defer local.deinit();
        var remote = anti_entropy.Lane.init(self.allocator, .memberships);
        defer remote.deinit();
        try populateStateLane(&local, &self.nodes.items[local_idx].state);
        try populateStateLane(&remote, &self.nodes.items[remote_idx].state);

        const planner = anti_entropy.Planner.init(self.allocator, strategy_config);
        var plan = try planner.plan(&local, &remote);
        defer plan.deinit();

        switch (plan.strategy) {
            .delta_replay, .merkle_range_diff => {
                try repairSelectedKeys(&self.nodes.items[local_idx].state, &self.nodes.items[remote_idx].state, plan.pull_keys);
                try repairSelectedKeys(&self.nodes.items[remote_idx].state, &self.nodes.items[local_idx].state, plan.push_keys);
            },
            .full_resync => {
                if (plan.pull_keys.len != 0) {
                    try self.nodes.items[local_idx].state.merge(&self.nodes.items[remote_idx].state);
                }
                if (plan.push_keys.len != 0) {
                    try self.nodes.items[remote_idx].state.merge(&self.nodes.items[local_idx].state);
                }
            },
        }

        return .{
            .strategy = plan.strategy,
            .pull_count = plan.pull_keys.len,
            .push_count = plan.push_keys.len,
        };
    }

    fn allEqual(self: *Mesh) bool {
        if (self.nodes.items.len == 0) return true;
        const first = &self.nodes.items[0].state;
        for (self.nodes.items[1..]) |*node| {
            if (!NetworkState.eql(first, &node.state)) return false;
        }
        return true;
    }
};

fn cloneNetworkState(src: *const NetworkState) !NetworkState {
    var out = NetworkState.init(src.allocator, src.replica_id, src.node_id);
    errdefer out.deinit();

    try out.users.appendSlice(out.allocator, src.users.items);
    try out.nick_claims.appendSlice(out.allocator, src.nick_claims.items);
    try out.channels.appendSlice(out.allocator, src.channels.items);
    try out.prefix_modes.appendSlice(out.allocator, src.prefix_modes.items);
    try out.boolean_modes.appendSlice(out.allocator, src.boolean_modes.items);
    try out.param_modes.appendSlice(out.allocator, src.param_modes.items);
    try out.ban_metadata.appendSlice(out.allocator, src.ban_metadata.items);
    try out.topics.appendSlice(out.allocator, src.topics.items);

    var memberships = try src.memberships.clone();
    errdefer memberships.deinit();
    var bans = try src.bans.clone();
    errdefer bans.deinit();

    out.memberships.deinit();
    out.memberships = memberships;
    out.bans.deinit();
    out.bans = bans;
    return out;
}

fn populateStateLane(lane: *anti_entropy.Lane, ns: *const NetworkState) !void {
    var key_buf: [512]u8 = undefined;

    for (ns.users.items) |entry| {
        const key = try userKey(&key_buf, entry.uid);
        try lane.putHash(key, hashUserEntry(entry));
    }
    for (ns.nick_claims.items) |claim| {
        const key = try nickClaimKey(&key_buf, claim.nick, claim.uid);
        try lane.putHash(key, hashNickClaim(claim));
    }
    for (ns.channels.items) |channel| {
        const key = try channelKey(&key_buf, channel.name);
        try lane.putHash(key, hashChannelRoot(channel));
    }
    for (ns.memberships.entries.items) |entry| {
        const key = try membershipKey(&key_buf, entry.value);
        try lane.putHash(key, hashMembershipEntry(entry));
    }
    try lane.putHash("memberships:cc", hashCausalContext(ns.memberships.cc));
    for (ns.prefix_modes.items) |entry| {
        const key = try prefixModeKey(&key_buf, entry.key);
        try lane.putHash(key, hashPrefixModeEntry(entry));
    }
    for (ns.boolean_modes.items) |entry| {
        const key = try booleanModeKey(&key_buf, entry.key);
        try lane.putHash(key, hashBooleanModeEntry(entry));
    }
    for (ns.param_modes.items) |entry| {
        const key = try paramModeKey(&key_buf, entry.key);
        try lane.putHash(key, hashParamModeEntry(entry));
    }
    for (ns.bans.entries.items) |entry| {
        const key = try banKey(&key_buf, entry.value);
        try lane.putHash(key, hashBanSetEntry(entry));
    }
    try lane.putHash("bans:cc", hashCausalContext(ns.bans.cc));
    for (ns.ban_metadata.items) |entry| {
        const key = try banMetadataKey(&key_buf, entry.key);
        try lane.putHash(key, hashBanMetadataEntry(entry));
    }
    for (ns.topics.items) |entry| {
        const key = try topicKey(&key_buf, entry.channel);
        try lane.putHash(key, hashTopicEntry(entry));
    }
}

fn repairSelectedKeys(target: *NetworkState, source: *const NetworkState, keys: []const []const u8) !void {
    if (keys.len == 0) return;

    var sparse = NetworkState.init(target.allocator, source.replica_id, source.node_id);
    defer sparse.deinit();

    var key_buf: [512]u8 = undefined;

    for (source.users.items) |entry| {
        const key = try userKey(&key_buf, entry.uid);
        if (containsKey(keys, key)) try sparse.users.append(sparse.allocator, entry);
    }
    for (source.nick_claims.items) |claim| {
        const key = try nickClaimKey(&key_buf, claim.nick, claim.uid);
        if (containsKey(keys, key)) try sparse.nick_claims.append(sparse.allocator, claim);
    }
    for (source.channels.items) |channel| {
        const key = try channelKey(&key_buf, channel.name);
        if (containsKey(keys, key)) try sparse.channels.append(sparse.allocator, channel);
    }
    if (hasKeyPrefix(keys, "memberships:")) {
        var memberships = try source.memberships.clone();
        errdefer memberships.deinit();
        sparse.memberships.deinit();
        sparse.memberships = memberships;
    }
    for (source.prefix_modes.items) |entry| {
        const key = try prefixModeKey(&key_buf, entry.key);
        if (containsKey(keys, key)) try sparse.prefix_modes.append(sparse.allocator, entry);
    }
    for (source.boolean_modes.items) |entry| {
        const key = try booleanModeKey(&key_buf, entry.key);
        if (containsKey(keys, key)) try sparse.boolean_modes.append(sparse.allocator, entry);
    }
    for (source.param_modes.items) |entry| {
        const key = try paramModeKey(&key_buf, entry.key);
        if (containsKey(keys, key)) try sparse.param_modes.append(sparse.allocator, entry);
    }
    if (hasKeyPrefix(keys, "bans:")) {
        var bans = try source.bans.clone();
        errdefer bans.deinit();
        sparse.bans.deinit();
        sparse.bans = bans;
    }
    for (source.ban_metadata.items) |entry| {
        const key = try banMetadataKey(&key_buf, entry.key);
        if (containsKey(keys, key)) try sparse.ban_metadata.append(sparse.allocator, entry);
    }
    for (source.topics.items) |entry| {
        const key = try topicKey(&key_buf, entry.channel);
        if (containsKey(keys, key)) try sparse.topics.append(sparse.allocator, entry);
    }

    try target.merge(&sparse);
}

fn containsKey(keys: []const []const u8, needle: []const u8) bool {
    for (keys) |key| {
        if (std.mem.eql(u8, key, needle)) return true;
    }
    return false;
}

fn hasKeyPrefix(keys: []const []const u8, prefix: []const u8) bool {
    for (keys) |key| {
        if (std.mem.startsWith(u8, key, prefix)) return true;
    }
    return false;
}

fn stateHash(ns: *const NetworkState) anti_entropy.Hash {
    var fold = StateHashFold.init();

    for (ns.users.items) |entry| fold.add(hashUserEntry(entry));
    for (ns.nick_claims.items) |claim| fold.add(hashNickClaim(claim));
    for (ns.channels.items) |channel| fold.add(hashChannelRoot(channel));
    for (ns.memberships.entries.items) |entry| fold.add(hashMembershipEntry(entry));
    fold.add(hashCausalContext(ns.memberships.cc));
    for (ns.prefix_modes.items) |entry| fold.add(hashPrefixModeEntry(entry));
    for (ns.boolean_modes.items) |entry| fold.add(hashBooleanModeEntry(entry));
    for (ns.param_modes.items) |entry| fold.add(hashParamModeEntry(entry));
    for (ns.bans.entries.items) |entry| fold.add(hashBanSetEntry(entry));
    fold.add(hashCausalContext(ns.bans.cc));
    for (ns.ban_metadata.items) |entry| fold.add(hashBanMetadataEntry(entry));
    for (ns.topics.items) |entry| fold.add(hashTopicEntry(entry));

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.network-state.v1");
    updateU64(&h, ns.users.items.len);
    updateU64(&h, ns.nick_claims.items.len);
    updateU64(&h, ns.channels.items.len);
    updateU64(&h, ns.memberships.entries.items.len);
    updateU64(&h, ns.prefix_modes.items.len);
    updateU64(&h, ns.boolean_modes.items.len);
    updateU64(&h, ns.param_modes.items.len);
    updateU64(&h, ns.bans.entries.items.len);
    updateU64(&h, ns.ban_metadata.items.len);
    updateU64(&h, ns.topics.items.len);
    h.update(&fold.acc);
    var out: anti_entropy.Hash = undefined;
    h.final(&out);
    return out;
}

const StateHashFold = struct {
    acc: anti_entropy.Hash = @splat(0),

    fn init() StateHashFold {
        return .{};
    }

    fn add(self: *StateHashFold, hash: anti_entropy.Hash) void {
        for (&self.acc, hash) |*dst, byte| dst.* ^= byte;
    }
};

fn userKey(buf: []u8, uid: state_mod.Uid) ![]const u8 {
    return std.fmt.bufPrint(buf, "users:{s}", .{uid.asSlice()});
}

fn nickClaimKey(buf: []u8, nick: state_mod.Nick, uid: state_mod.Uid) ![]const u8 {
    return std.fmt.bufPrint(buf, "nicks:{s}:{s}", .{ nick.asSlice(), uid.asSlice() });
}

fn channelKey(buf: []u8, channel: state_mod.ChannelName) ![]const u8 {
    return std.fmt.bufPrint(buf, "channels:{s}", .{channel.asSlice()});
}

fn membershipKey(buf: []u8, key: state_mod.MembershipKey) ![]const u8 {
    return std.fmt.bufPrint(buf, "memberships:{s}:{s}:{}", .{ key.channel.asSlice(), key.uid.asSlice(), key.session });
}

fn prefixModeKey(buf: []u8, key: state_mod.PrefixModeKey) ![]const u8 {
    return std.fmt.bufPrint(buf, "prefix_modes:{s}:{s}:{c}", .{ key.channel.asSlice(), key.uid.asSlice(), key.mode });
}

fn booleanModeKey(buf: []u8, key: state_mod.BooleanModeKey) ![]const u8 {
    return std.fmt.bufPrint(buf, "boolean_modes:{s}:{c}", .{ key.channel.asSlice(), key.mode });
}

fn paramModeKey(buf: []u8, key: state_mod.ParamModeKey) ![]const u8 {
    return std.fmt.bufPrint(buf, "param_modes:{s}:{c}", .{ key.channel.asSlice(), key.mode });
}

fn banKey(buf: []u8, key: state_mod.BanKey) ![]const u8 {
    return std.fmt.bufPrint(buf, "bans:{s}:{}:{s}", .{ key.channel.asSlice(), @backingInt(key.kind), key.mask.asSlice() });
}

fn banMetadataKey(buf: []u8, key: state_mod.BanKey) ![]const u8 {
    return std.fmt.bufPrint(buf, "ban_metadata:{s}:{}:{s}", .{ key.channel.asSlice(), @backingInt(key.kind), key.mask.asSlice() });
}

fn topicKey(buf: []u8, channel: state_mod.ChannelName) ![]const u8 {
    return std.fmt.bufPrint(buf, "topics:{s}", .{channel.asSlice()});
}

fn hashUserEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.user.v1");
    updateInline(&h, entry.uid);
    updateUserProfileRegister(&h, entry.profile);
    updatePresenceRegister(&h, entry.presence);
    return finalHash(&h);
}

fn hashNickClaim(claim: state_mod.NickClaim) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.nick.v1");
    updateInline(&h, claim.nick);
    updateInline(&h, claim.uid);
    updateU64(&h, claim.authority);
    updateHlc(&h, claim.hlc);
    updateU64(&h, claim.node_id);
    return finalHash(&h);
}

fn hashChannelRoot(channel: state_mod.ChannelRoot) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.channel.v1");
    updateInline(&h, channel.name);
    updateHlc(&h, channel.birth_hlc);
    updateBool(&h, channel.has_birth);
    updateU64(&h, channel.authority);
    updateU64(&h, channel.node_id);
    return finalHash(&h);
}

fn hashMembershipEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.membership.v1");
    updateMembershipKey(&h, entry.value);
    updateDotList(&h, entry.dots.items);
    return finalHash(&h);
}

fn hashPrefixModeEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.prefix-mode.v1");
    updatePrefixModeKey(&h, entry.key);
    updateAuthToggle(&h, entry.toggle);
    return finalHash(&h);
}

fn hashBooleanModeEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.boolean-mode.v1");
    updateBooleanModeKey(&h, entry.key);
    updateU8(&h, @backingInt(entry.toggle.policy));
    updateBool(&h, entry.toggle.enabled);
    updateHlc(&h, entry.toggle.hlc);
    updateU64(&h, entry.toggle.node_id);
    return finalHash(&h);
}

fn hashParamModeEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.param-mode.v1");
    updateParamModeKey(&h, entry.key);
    updateParamModeRegister(&h, entry.register);
    return finalHash(&h);
}

fn hashBanSetEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.ban.v1");
    updateBanKey(&h, entry.value);
    updateDotList(&h, entry.dots.items);
    return finalHash(&h);
}

fn hashBanMetadataEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.ban-metadata.v1");
    updateBanKey(&h, entry.key);
    updateBanMetadataRegister(&h, entry.register);
    return finalHash(&h);
}

fn hashTopicEntry(entry: anytype) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.topic.v1");
    updateInline(&h, entry.channel);
    updateTopicRegister(&h, entry.register);
    return finalHash(&h);
}

fn hashCausalContext(cc: anytype) anti_entropy.Hash {
    var fold = StateHashFold.init();
    var count: usize = 0;
    var it = cc.dots.iterator();
    while (it.next()) |entry| {
        fold.add(hashDot(entry.key_ptr.*));
        count += 1;
    }

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.causal-context.v1");
    updateU64(&h, count);
    h.update(&fold.acc);
    return finalHash(&h);
}

fn hashDot(dot: state_mod.Dot) anti_entropy.Hash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("onyx_server.suimyaku.state.dot.v1");
    updateU64(&h, dot.replica);
    updateU64(&h, dot.counter);
    return finalHash(&h);
}

fn updateUserProfileRegister(h: *std.crypto.hash.sha2.Sha256, register: anytype) void {
    updateRegisterHeader(h, register);
    if (register.value) |value| {
        updateInline(h, value.nick);
        updateInline(h, value.account);
        updateInline(h, value.realname);
    }
}

fn updatePresenceRegister(h: *std.crypto.hash.sha2.Sha256, register: anytype) void {
    updateRegisterHeader(h, register);
    if (register.value) |value| {
        updateU64(h, value.expires_at_ms);
        updateBool(h, value.tombstoned);
    }
}

fn updateParamModeRegister(h: *std.crypto.hash.sha2.Sha256, register: anytype) void {
    updateRegisterHeader(h, register);
    if (register.value) |value| {
        updateInline(h, value.value);
        updateU64(h, value.authority);
    }
}

fn updateBanMetadataRegister(h: *std.crypto.hash.sha2.Sha256, register: anytype) void {
    updateRegisterHeader(h, register);
    if (register.value) |value| {
        updateInline(h, value.setter);
        updateInline(h, value.reason);
    }
}

fn updateTopicRegister(h: *std.crypto.hash.sha2.Sha256, register: anytype) void {
    updateRegisterHeader(h, register);
    if (register.value) |value| {
        updateInline(h, value.text);
        updateInline(h, value.setter);
        updateHlc(h, value.hlc);
    }
}

fn updateRegisterHeader(h: *std.crypto.hash.sha2.Sha256, register: anytype) void {
    updateBool(h, register.value != null);
    updateU64(h, register.timestamp);
    updateU64(h, register.replica_id);
}

fn updateMembershipKey(h: *std.crypto.hash.sha2.Sha256, key: state_mod.MembershipKey) void {
    updateInline(h, key.channel);
    updateInline(h, key.uid);
    updateU64(h, key.session);
}

fn updatePrefixModeKey(h: *std.crypto.hash.sha2.Sha256, key: state_mod.PrefixModeKey) void {
    updateInline(h, key.channel);
    updateInline(h, key.uid);
    updateU8(h, key.mode);
}

fn updateBooleanModeKey(h: *std.crypto.hash.sha2.Sha256, key: state_mod.BooleanModeKey) void {
    updateInline(h, key.channel);
    updateU8(h, key.mode);
}

fn updateParamModeKey(h: *std.crypto.hash.sha2.Sha256, key: state_mod.ParamModeKey) void {
    updateInline(h, key.channel);
    updateU8(h, key.mode);
}

fn updateBanKey(h: *std.crypto.hash.sha2.Sha256, key: state_mod.BanKey) void {
    updateInline(h, key.channel);
    updateU8(h, @backingInt(key.kind));
    updateInline(h, key.mask);
}

fn updateAuthToggle(h: *std.crypto.hash.sha2.Sha256, toggle: state_mod.AuthToggle) void {
    updateBool(h, toggle.enabled);
    updateU64(h, toggle.authority);
    updateHlc(h, toggle.hlc);
    updateU64(h, toggle.node_id);
}

fn updateDotList(h: *std.crypto.hash.sha2.Sha256, dots: []const state_mod.Dot) void {
    var fold = StateHashFold.init();
    for (dots) |dot| fold.add(hashDot(dot));
    updateU64(h, dots.len);
    h.update(&fold.acc);
}

fn updateInline(h: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    updateU64(h, value.len);
    h.update(value.asSlice());
}

fn updateHlc(h: *std.crypto.hash.sha2.Sha256, value: Hlc) void {
    updateU64(h, value.wall_ms);
    updateU64(h, value.logical);
}

fn updateBool(h: *std.crypto.hash.sha2.Sha256, value: bool) void {
    updateU8(h, if (value) 1 else 0);
}

fn updateU8(h: *std.crypto.hash.sha2.Sha256, value: u8) void {
    h.update(&[_]u8{value});
}

fn updateU64(h: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    h.update(&buf);
}

fn finalHash(h: *std.crypto.hash.sha2.Sha256) anti_entropy.Hash {
    var out: anti_entropy.Hash = undefined;
    h.final(&out);
    return out;
}

fn pick(comptime pool: []const []const u8, random: std.Random) []const u8 {
    return pool[random.intRangeLessThan(usize, 0, pool.len)];
}

fn deriveSeed(master_seed: u64, stream: u64) u64 {
    var x = master_seed +% 0x9e37_79b9_7f4a_7c15 +% (stream << 1);
    x = (x ^ (x >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    x = (x ^ (x >> 27)) *% 0x94d0_49bb_1331_11eb;
    return x ^ (x >> 31);
}

fn runConvergenceSeed(seed: u64, partitioned: bool) !void {
    var mesh = try Mesh.init(std.testing.allocator, seed, 4);
    defer mesh.deinit();

    if (partitioned) {
        try mesh.partitionFirstHalf();
        try mesh.runRandomWorkload(80);
        mesh.heal();
        try std.testing.expect(!mesh.allEqual());
        try mesh.runRandomWorkload(40);
    } else {
        try mesh.runRandomWorkload(120);
    }

    try mesh.reconcile();
    try mesh.expectConverged();
}

test "convergence with no partition over random workloads" {
    var i: u64 = 0;
    while (i < 50) : (i += 1) {
        try runConvergenceSeed(0x0160_0000 + i, false);
    }
}

test "convergence after partition and heal over random workloads" {
    var i: u64 = 0;
    while (i < 50) : (i += 1) {
        try runConvergenceSeed(0x0160_1000 + i, true);
    }
}

test "nick collision across partitions converges by rename to UID" {
    var mesh = try Mesh.init(std.testing.allocator, 0x0160_c0111510, 2);
    defer mesh.deinit();

    try mesh.partitionFirstHalf();
    const nick = try state_mod.Nick.init("same");
    const loser_uid = try state_mod.Uid.init("001LOSER");
    const winner_uid = try state_mod.Uid.init("002WINNER");

    const loser_hlc = try mesh.nextHlc(0);
    try mesh.nodes.items[0].state.claimNick(nick, loser_uid, 10, loser_hlc);
    try mesh.broadcastSnapshot(0);

    const winner_hlc = try mesh.nextHlc(1);
    try mesh.nodes.items[1].state.claimNick(nick, winner_uid, 20, winner_hlc);
    try mesh.broadcastSnapshot(1);

    _ = try mesh.network.run(100);
    try mesh.drainNetwork();
    mesh.heal();
    try mesh.reconcile();
    try mesh.expectConverged();

    for (mesh.nodes.items) |*node| {
        const winner = node.state.resolveNick(nick, winner_uid);
        try std.testing.expectEqual(state_mod.NickOutcome.keep_nick, winner.outcome);
        try std.testing.expectEqual(winner_uid, winner.winner_uid.?);

        const loser = node.state.resolveNick(nick, loser_uid);
        try std.testing.expectEqual(state_mod.NickOutcome.rename_to_uid, loser.outcome);
        try std.testing.expectEqual(winner_uid, loser.winner_uid.?);
        try std.testing.expect(std.mem.eql(u8, loser_uid.asSlice(), loser.display.asSlice()));
    }
}

test "redelivering the same delta set twice is idempotent" {
    var mesh = try Mesh.init(std.testing.allocator, 0x0160_1de0, 3);
    defer mesh.deinit();

    try mesh.runRandomWorkload(40);
    try mesh.replayAllDeltas();

    var snapshots = std.ArrayList(NetworkState).empty;
    defer {
        for (snapshots.items) |*snapshot| snapshot.deinit();
        snapshots.deinit(std.testing.allocator);
    }

    for (mesh.nodes.items) |*node| {
        try snapshots.append(std.testing.allocator, try cloneNetworkState(&node.state));
    }

    try mesh.replayAllDeltas();

    for (mesh.nodes.items, snapshots.items) |*node, *snapshot| {
        try std.testing.expect(NetworkState.eql(&node.state, snapshot));
    }
}

test "state hash includes equal-cardinality key value content" {
    const allocator = std.testing.allocator;
    const uid = try state_mod.Uid.init("001HASH");
    const nick = try state_mod.Nick.init("hashnick");
    const hlc = try Hlc.init(10, 0);

    var a = NetworkState.init(allocator, 1, 100);
    defer a.deinit();
    var b = NetworkState.init(allocator, 1, 100);
    defer b.deinit();

    try a.upsertUser(uid, .{
        .nick = nick,
        .realname = try state_mod.ShortText.init("left"),
    }, hlc, 10);
    try b.upsertUser(uid, .{
        .nick = nick,
        .realname = try state_mod.ShortText.init("right"),
    }, hlc, 10);

    try std.testing.expect(!std.mem.eql(u8, &stateHash(&a), &stateHash(&b)));
}

test "anti-entropy repair uses delta replay pull and push keys" {
    var mesh = try Mesh.init(std.testing.allocator, 0x0160_aed1, 2);
    defer mesh.deinit();
    try seedPlannerRepairPair(&mesh, 24, 1);

    const result = try mesh.repairPair(0, 1, .{
        .delta_replay_limit = 8,
        .full_resync_threshold = 1024,
    });

    try std.testing.expectEqual(anti_entropy.RepairStrategy.delta_replay, result.strategy);
    try std.testing.expect(result.pull_count != 0);
    try std.testing.expect(result.push_count != 0);
    try std.testing.expect(NetworkState.eql(&mesh.nodes.items[0].state, &mesh.nodes.items[1].state));
}

test "anti-entropy repair uses merkle range diff key sets" {
    var mesh = try Mesh.init(std.testing.allocator, 0x0160_aed2, 2);
    defer mesh.deinit();
    try seedPlannerRepairPair(&mesh, 80, 12);

    const result = try mesh.repairPair(0, 1, .{
        .delta_replay_limit = 4,
        .full_resync_threshold = 1024,
    });

    try std.testing.expectEqual(anti_entropy.RepairStrategy.merkle_range_diff, result.strategy);
    try std.testing.expect(result.pull_count != 0);
    try std.testing.expect(result.push_count != 0);
    try std.testing.expect(NetworkState.eql(&mesh.nodes.items[0].state, &mesh.nodes.items[1].state));
}

test "anti-entropy repair uses full resync only when planned" {
    var mesh = try Mesh.init(std.testing.allocator, 0x0160_aed3, 2);
    defer mesh.deinit();
    try seedPlannerRepairPair(&mesh, 4, 1);

    const result = try mesh.repairPair(0, 1, .{
        .delta_replay_limit = 8,
        .full_resync_threshold = 1,
    });

    try std.testing.expectEqual(anti_entropy.RepairStrategy.full_resync, result.strategy);
    try std.testing.expect(result.pull_count != 0);
    try std.testing.expect(result.push_count != 0);
    try std.testing.expect(NetworkState.eql(&mesh.nodes.items[0].state, &mesh.nodes.items[1].state));
}

test "Undertow mesh converges after partition heal across a seed campaign" {
    // Deterministic Ocean deliverable: split the mesh, mutate CRDT state on both
    // sides of the partition, heal, and require every replica to converge to a
    // byte-identical state. `expectConverged` prints the failing seed so any red
    // run replays verbatim.
    var s: u64 = 0;
    while (s < 64) : (s += 1) {
        const seed = 0x0160_5a20 +% s;
        var mesh = try Mesh.init(std.testing.allocator, seed, 4);
        defer mesh.deinit();

        try mesh.partitionFirstHalf();
        try mesh.runRandomWorkload(60); // both sides mutate while split
        mesh.heal();

        try mesh.reconcile();
        try mesh.expectConverged();
    }
}

test "Undertow mesh merge is order-independent and idempotent across a seed campaign" {
    // The convergence guarantee rests on the merge being commutative, associative
    // and idempotent. Feed the exact same delta snapshots to two fresh replicas in
    // opposite orders: a commutative/associative merge must land them on identical
    // state regardless of ordering, and re-applying the whole set must be a no-op.
    var s: u64 = 0;
    while (s < 32) : (s += 1) {
        const seed = 0x0160_9a70 +% s;
        var mesh = try Mesh.init(std.testing.allocator, seed, 4);
        defer mesh.deinit();
        try mesh.runRandomWorkload(60);

        const deltas = mesh.deltas.items;

        var forward = NetworkState.init(std.testing.allocator, 7, 700);
        defer forward.deinit();
        var backward = NetworkState.init(std.testing.allocator, 7, 700);
        defer backward.deinit();

        for (deltas) |*d| try forward.merge(&d.state);
        var i: usize = deltas.len;
        while (i > 0) : (i -= 1) try backward.merge(&deltas[i - 1].state);

        if (!NetworkState.eql(&forward, &backward)) {
            std.debug.print("Undertow merge order-dependence seed=0x{x}\n", .{seed});
            return error.MergeOrderDependent;
        }

        // Idempotence: re-merging the full delta set changes nothing.
        var snapshot = try cloneNetworkState(&forward);
        defer snapshot.deinit();
        for (deltas) |*d| try forward.merge(&d.state);
        if (!NetworkState.eql(&forward, &snapshot)) {
            std.debug.print("Undertow merge non-idempotent seed=0x{x}\n", .{seed});
            return error.MergeNonIdempotent;
        }
    }
}

test "Undertow mesh partition-heal convergence replays byte-for-byte from its seed" {
    // A DST test must replay identically from its seed. Drive the same partition /
    // mutate / heal / reconcile program twice under one seed and require the final
    // converged state hashes to match.
    const seed = 0x0160_5eed_d57;

    var first = try Mesh.init(std.testing.allocator, seed, 4);
    defer first.deinit();
    try first.partitionFirstHalf();
    try first.runRandomWorkload(60);
    first.heal();
    try first.reconcile();
    try first.expectConverged();

    var second = try Mesh.init(std.testing.allocator, seed, 4);
    defer second.deinit();
    try second.partitionFirstHalf();
    try second.runRandomWorkload(60);
    second.heal();
    try second.reconcile();
    try second.expectConverged();

    const first_hash = stateHash(&first.nodes.items[0].state);
    const second_hash = stateHash(&second.nodes.items[0].state);
    if (!std.mem.eql(u8, &first_hash, &second_hash)) {
        std.debug.print("Undertow replay divergence seed=0x{x}\n", .{seed});
        return error.ReplayDiverged;
    }
}

fn seedPlannerRepairPair(mesh: *Mesh, common_count: usize, unique_per_side: usize) !void {
    var i: usize = 0;
    while (i < common_count) : (i += 1) {
        try seedUser(mesh, 0, "C", i, "common");
    }
    try mesh.nodes.items[1].state.merge(&mesh.nodes.items[0].state);

    i = 0;
    while (i < unique_per_side) : (i += 1) {
        try seedUser(mesh, 0, "L", i, "left");
        try seedUser(mesh, 1, "R", i, "right");
    }
    try std.testing.expect(!NetworkState.eql(&mesh.nodes.items[0].state, &mesh.nodes.items[1].state));
}

fn seedUser(mesh: *Mesh, node_idx: usize, comptime prefix: []const u8, idx: usize, comptime realname: []const u8) !void {
    var uid_buf: [32]u8 = undefined;
    var nick_buf: [64]u8 = undefined;
    const uid_text = try std.fmt.bufPrint(&uid_buf, "{s}UID{}", .{ prefix, idx });
    const nick_text = try std.fmt.bufPrint(&nick_buf, "{s}nick{}", .{ prefix, idx });
    const uid = try state_mod.Uid.init(uid_text);
    const nick = try state_mod.Nick.init(nick_text);
    const hlc = try mesh.nextHlc(node_idx);

    try mesh.nodes.items[node_idx].state.upsertUser(uid, .{
        .nick = nick,
        .realname = try state_mod.ShortText.init(realname),
    }, hlc, 10);
    try mesh.nodes.items[node_idx].state.claimNick(nick, uid, 10, hlc);
}
