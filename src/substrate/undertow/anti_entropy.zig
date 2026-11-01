// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UNDERTOW anti-entropy reconciliation planner.
//!
//! UNDERTOW repair is keyed by entity-family lanes: each lane fingerprints one
//! family (`channel`, `ban`, `membership`, etc.) as a Merkle tree of
//! `key -> value_hash`. The committed Merkle primitive exposes a half-diff:
//! `diffProbe(local, remote)` returns keys that are remote-only or changed from
//! `local`'s point of view. The planner therefore runs that walk reciprocally:
//! once to decide what this node should pull, and once to decide what the peer
//! should pull from us. That bidirectional plan is the single CRDT repair
//! mechanism that replaces TS6 MSEQ/HASHCHECK/RESYNC.
const std = @import("std");

const clock = @import("clock.zig");
const concord = @import("concord.zig");
const merkle = @import("merkle.zig");
const toml = @import("../../proto/toml.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Hash = merkle.Hash;

/// Coarse UNDERTOW entity family carried by an anti-entropy lane.
pub const EntityFamily = enum {
    users,
    nicks,
    channels,
    memberships,
    prefix_modes,
    channel_modes,
    bans,
    topics,
    accounts,
    history,
};

/// Per-entity-family Merkle lane over `key -> value_hash`.
pub const Lane = struct {
    family: EntityFamily,
    tree: merkle.MerkleTree,

    pub fn init(allocator: Allocator, family: EntityFamily) Lane {
        return .{
            .family = family,
            .tree = merkle.MerkleTree.init(allocator),
        };
    }

    pub fn deinit(self: *Lane) void {
        self.tree.deinit();
    }

    /// Insert or update a lane key using an already domain-separated value hash.
    pub fn putHash(self: *Lane, key: []const u8, value_hash: Hash) Allocator.Error!void {
        try self.tree.put(key, value_hash);
    }

    /// Remove a lane key. Returns true when the key existed.
    pub fn remove(self: *Lane, key: []const u8) bool {
        return self.tree.remove(key);
    }

    pub fn len(self: *const Lane) usize {
        return self.tree.len();
    }

    pub fn root(self: *const Lane) Hash {
        return self.tree.root();
    }

    pub fn probe(self: *const Lane) merkle.NodeProbe {
        return self.tree.probe();
    }
};

/// MeshLens repair strategy for a lane pair.
pub const RepairStrategy = enum {
    delta_replay,
    merkle_range_diff,
    full_resync,
};

/// Cost thresholds used by the MeshLens planner.
pub const StrategyConfig = struct {
    /// Small drift is cheaper to repair by replaying recent CRDT deltas.
    delta_replay_limit: usize = 8,
    /// At or above this many differing keys, request a full lane snapshot.
    full_resync_threshold: usize = 1024,

    pub fn init(delta_replay_limit: usize, full_resync_threshold: usize) StrategyConfig {
        return .{
            .delta_replay_limit = delta_replay_limit,
            .full_resync_threshold = full_resync_threshold,
        };
    }

    /// Overlay `[mesh.antientropy]` strategy keys onto this config.
    pub fn applyToml(cfg: *StrategyConfig, doc: *const toml.Document) void {
        if (doc.getUint("mesh.antientropy.delta_replay_limit")) |v| cfg.delta_replay_limit = @intCast(v);
        if (doc.getUint("mesh.antientropy.full_resync_threshold")) |v| cfg.full_resync_threshold = @intCast(v);
    }
};

/// Bidirectional repair plan for one entity-family lane.
pub const RepairPlan = struct {
    allocator: Allocator,
    family: EntityFamily,
    strategy: RepairStrategy,
    local_root: Hash,
    remote_root: Hash,
    pull_keys: [][]u8,
    push_keys: [][]u8,

    pub fn deinit(self: *RepairPlan) void {
        freeKeyList(self.allocator, self.pull_keys);
        freeKeyList(self.allocator, self.push_keys);
        self.* = .{
            .allocator = self.allocator,
            .family = self.family,
            .strategy = self.strategy,
            .local_root = self.local_root,
            .remote_root = self.remote_root,
            .pull_keys = &.{},
            .push_keys = &.{},
        };
    }

    pub fn differingKeyEstimate(self: *const RepairPlan) usize {
        return self.pull_keys.len + self.push_keys.len;
    }
};

/// Cost-aware reconciliation planner.
pub const Planner = struct {
    allocator: Allocator,
    strategy_config: StrategyConfig = .{},

    pub const Error = Allocator.Error || error{
        LaneFamilyMismatch,
    };

    pub fn init(allocator: Allocator, strategy_config: StrategyConfig) Planner {
        return .{
            .allocator = allocator,
            .strategy_config = strategy_config,
        };
    }

    /// Build a repair plan for two in-memory lanes.
    ///
    /// `pull_keys` is produced by `diffProbe(local, remote)`: keys this node
    /// should request from the peer. `push_keys` is produced by the reciprocal
    /// walk `diffProbe(remote, local)`: keys the peer should request from us.
    pub fn plan(self: Planner, local: *const Lane, remote: *const Lane) Error!RepairPlan {
        if (local.family != remote.family) return error.LaneFamilyMismatch;

        const local_root = local.root();
        const remote_root = remote.root();

        var pull = try merkle.diffProbe(self.allocator, &local.tree, remote.probe());
        defer pull.deinit();

        var push = try merkle.diffProbe(self.allocator, &remote.tree, local.probe());
        defer push.deinit();

        const estimated_diff = pull.keys.len + push.keys.len;
        const strategy = selectStrategy(self.strategy_config, .{
            .local_key_count = local.len(),
            .remote_key_count = remote.len(),
            .estimated_differing_keys = estimated_diff,
        });

        const pull_keys = pull.keys;
        pull.keys = &.{};
        errdefer freeKeyList(self.allocator, pull_keys);

        const push_keys = push.keys;
        push.keys = &.{};
        errdefer freeKeyList(self.allocator, push_keys);

        return .{
            .allocator = self.allocator,
            .family = local.family,
            .strategy = strategy,
            .local_root = local_root,
            .remote_root = remote_root,
            .pull_keys = pull_keys,
            .push_keys = push_keys,
        };
    }
};

/// Inputs to the MeshLens cost selector.
pub const StrategyInput = struct {
    local_key_count: usize,
    remote_key_count: usize,
    estimated_differing_keys: usize,
};

/// Pick the cheapest lane repair strategy from a differing-key estimate.
pub fn selectStrategy(config: StrategyConfig, input: StrategyInput) RepairStrategy {
    if (input.estimated_differing_keys == 0) return .delta_replay;
    if (input.estimated_differing_keys >= config.full_resync_threshold) return .full_resync;

    const total_keys = input.local_key_count + input.remote_key_count;
    if (total_keys > 0 and input.estimated_differing_keys * 2 >= total_keys) {
        return .full_resync;
    }

    if (input.estimated_differing_keys <= config.delta_replay_limit) return .delta_replay;
    return .merkle_range_diff;
}

/// Minimum anti-entropy repair interval: divergent peers repair this promptly.
pub const min_repair_interval_ms: u64 = 1_000;
/// Maximum anti-entropy repair interval: quiet-peer backoff never exceeds this.
pub const max_repair_interval_ms: u64 = 60_000;
/// Quiet-peer backoff multiplier applied per consecutive quiet repair.
pub const repair_backoff_factor: u64 = 2;

/// Per-peer inputs to the adaptive repair scheduler.
///
/// The caller owns this state: increment `quiet_repairs` after a repair that
/// found no divergence, and reset it to `0` when divergence is observed.
pub const PeerRepairState = struct {
    peer_id: u64,
    /// Last repair time on the caller's monotonic/wall scale, or null if never.
    last_repair_ms: ?u64,
    /// Pending differing-key estimate; any non-zero value forces prompt repair.
    pending_divergence: usize,
    quiet_repairs: u32 = 0,
};

/// Caller-supplied cap on repairs admitted in one scheduling window.
pub const RepairBudget = struct {
    max_per_window: usize,
    /// Deferred peers become due again this long after `now_ms`.
    window_ms: u64 = max_repair_interval_ms,
};

/// One deterministic scheduling decision for a peer.
pub const RepairDecision = struct {
    peer_id: u64,
    interval_ms: u64,
    /// When this peer should next be repaired, after budget deferral.
    effective_due_ms: u64,
    /// The peer's natural due time (before deferral) has been reached.
    due: bool,
    /// Due, but held past `effective_due_ms` by the repair budget.
    deferred: bool,
};

/// Interval until the next repair for one peer.
///
/// Divergent peers (`pending_divergence > 0`) always get the minimum.
/// Quiet peers back off exponentially by `quiet_repairs`, bounded by
/// `[min_repair_interval_ms, max_repair_interval_ms]`. Pure: no clock reads.
pub fn nextRepairIntervalMs(pending_divergence: usize, quiet_repairs: u32) u64 {
    if (pending_divergence > 0) return min_repair_interval_ms;
    var interval = min_repair_interval_ms;
    var i: u32 = 0;
    while (i < quiet_repairs) : (i += 1) {
        if (interval >= max_repair_interval_ms) return max_repair_interval_ms;
        interval = @min(max_repair_interval_ms, interval *| repair_backoff_factor);
    }
    return @min(interval, max_repair_interval_ms);
}

/// Natural due time for a peer, saturating on overflow. Never repaired is due now.
pub fn repairDueAtMs(peer: PeerRepairState, now_ms: u64) u64 {
    const last = peer.last_repair_ms orelse return now_ms;
    return last +| nextRepairIntervalMs(peer.pending_divergence, peer.quiet_repairs);
}

/// Decide repairs for `peers` at `now_ms`, writing at most `out.len` decisions.
///
/// Decisions are emitted in ascending `peer_id` order (input order breaks id
/// ties). At most `budget.max_per_window` due peers are admitted; further due
/// peers are deferred to `now_ms + budget.window_ms` in that same order.
/// Pure and deterministic: `now_ms` is a parameter and no clock is read.
/// Clock regression is safe: all arithmetic saturates and a peer whose
/// `last_repair_ms` lies in the future is simply not due yet.
pub fn scheduleRepairs(peers: []const PeerRepairState, now_ms: u64, budget: RepairBudget, out: []RepairDecision) usize {
    const count = @min(peers.len, out.len);
    var admitted: usize = 0;
    var written: usize = 0;
    // Selection by ascending (peer_id, input index); no allocation.
    var prev_id: u64 = 0;
    var prev_idx: usize = 0;
    var have_prev = false;
    while (written < count) {
        var best: ?usize = null;
        for (peers, 0..) |peer, idx| {
            if (have_prev and (peer.peer_id < prev_id or (peer.peer_id == prev_id and idx <= prev_idx))) continue;
            if (best == null or peer.peer_id < peers[best.?].peer_id) best = idx;
        }
        const idx = best orelse break;
        const peer = peers[idx];
        prev_id = peer.peer_id;
        prev_idx = idx;
        have_prev = true;

        const interval = nextRepairIntervalMs(peer.pending_divergence, peer.quiet_repairs);
        const due_at = repairDueAtMs(peer, now_ms);
        const due = due_at <= now_ms;
        var deferred = false;
        var effective_due = due_at;
        if (due) {
            if (admitted < budget.max_per_window) {
                admitted += 1;
            } else {
                deferred = true;
                effective_due = now_ms +| budget.window_ms;
            }
        }
        out[written] = .{
            .peer_id = peer.peer_id,
            .interval_ms = interval,
            .effective_due_ms = effective_due,
            .due = due,
            .deferred = deferred,
        };
        written += 1;
    }
    return written;
}

/// Version-vector plus HLC frontier advertised by one live peer.
pub const PeerFrontier = struct {
    causal: clock.VersionVector,
    hlc: clock.Hlc,
};

/// Causal-stability watermark across live peers.
pub const StabilityWatermark = struct {
    causal: clock.VersionVector,
    hlc: clock.Hlc,

    /// A dot is stable when every live peer's vector covered it.
    pub fn containsDot(self: *const StabilityWatermark, dot: concord.Dot) bool {
        return self.causal.counter(dot.replica) >= dot.counter;
    }
};

/// Compute the tombstone-GC stability frontier as pointwise minima.
///
/// The caller supplies only live peers. Missing replicas count as counter `0`,
/// so dots from a replica absent on any live peer are not stable.
pub fn causalStabilityWatermark(peers: []const PeerFrontier) clock.VersionVector.Error!StabilityWatermark {
    var watermark = StabilityWatermark{
        .causal = clock.VersionVector.init(),
        .hlc = .{},
    };
    if (peers.len == 0) return watermark;

    watermark.hlc = peers[0].hlc;
    for (peers[1..]) |peer| {
        if (clock.Hlc.compare(peer.hlc, watermark.hlc) == .lt) {
            watermark.hlc = peer.hlc;
        }
    }

    for (peers) |peer| {
        for (peer.causal.entries[0..peer.causal.len]) |entry| {
            if (containsReplica(&watermark.causal, entry.replica)) continue;

            var min_counter = entry.counter;
            for (peers) |candidate| {
                min_counter = @min(min_counter, candidate.causal.counter(entry.replica));
            }
            try putCounter(&watermark.causal, entry.replica, min_counter);
        }
    }

    return watermark;
}

fn freeKeyList(allocator: Allocator, keys: [][]u8) void {
    for (keys) |key| allocator.free(key);
    allocator.free(keys);
}

fn containsReplica(vv: *const clock.VersionVector, replica: u64) bool {
    return vv.counter(replica) != 0;
}

fn putCounter(vv: *clock.VersionVector, replica: u64, counter: u64) clock.VersionVector.Error!void {
    if (counter == 0) return;

    for (vv.entries[0..vv.len], 0..) |entry, idx| {
        if (entry.replica == replica) {
            vv.entries[idx].counter = counter;
            return;
        }
    }

    if (vv.len == clock.VersionVector.max_entries) return error.CapacityExceeded;
    vv.entries[vv.len] = .{ .replica = replica, .counter = counter };
    vv.len += 1;
}

fn valueHash(value: []const u8) Hash {
    var out: Hash = undefined;
    Sha256.hash(value, &out, .{});
    return out;
}

fn expectKeys(actual: []const []u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, 0..) |key, i| {
        try std.testing.expectEqualStrings(key, actual[i]);
    }
}

test "reciprocal planner pulls and pushes exactly the changed keys" {
    const allocator = std.testing.allocator;
    var local = Lane.init(allocator, .channels);
    defer local.deinit();
    var remote = Lane.init(allocator, .channels);
    defer remote.deinit();

    try local.putHash("chan:#ops:topic", valueHash("same"));
    try remote.putHash("chan:#ops:topic", valueHash("same"));

    try local.putHash("chan:#ops:mode", valueHash("+nt"));
    try remote.putHash("chan:#ops:mode", valueHash("+ntk"));
    try local.putHash("chan:#ops:ban:1", valueHash("old-mask"));
    try remote.putHash("chan:#ops:ban:1", valueHash("new-mask"));
    try local.putHash("chan:#ops:ban:2", valueHash("old-meta"));
    try remote.putHash("chan:#ops:ban:2", valueHash("new-meta"));

    const planner = Planner.init(allocator, .{});
    var plan = try planner.plan(&local, &remote);
    defer plan.deinit();

    try expectKeys(plan.pull_keys, &.{
        "chan:#ops:ban:1",
        "chan:#ops:ban:2",
        "chan:#ops:mode",
    });
    try expectKeys(plan.push_keys, &.{
        "chan:#ops:ban:1",
        "chan:#ops:ban:2",
        "chan:#ops:mode",
    });
}

test "planner returns asymmetric pull and push key ownership without leaks" {
    const allocator = std.testing.allocator;
    var local = Lane.init(allocator, .memberships);
    defer local.deinit();
    var remote = Lane.init(allocator, .memberships);
    defer remote.deinit();

    try local.putHash("member:#ops:uid002", valueHash("local-only"));
    try remote.putHash("member:#ops:uid003", valueHash("remote-only"));

    const planner = Planner.init(allocator, .{});
    var plan = try planner.plan(&local, &remote);
    defer plan.deinit();

    try expectKeys(plan.pull_keys, &.{"member:#ops:uid003"});
    try expectKeys(plan.push_keys, &.{"member:#ops:uid002"});
}

test "identical lanes produce an empty plan" {
    const allocator = std.testing.allocator;
    var local = Lane.init(allocator, .bans);
    defer local.deinit();
    var remote = Lane.init(allocator, .bans);
    defer remote.deinit();

    try local.putHash("ban:#ops:*!*@example", valueHash("mask"));
    try remote.putHash("ban:#ops:*!*@example", valueHash("mask"));

    const planner = Planner.init(allocator, .{});
    var plan = try planner.plan(&local, &remote);
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 0), plan.pull_keys.len);
    try std.testing.expectEqual(@as(usize, 0), plan.push_keys.len);
    try std.testing.expectEqual(RepairStrategy.delta_replay, plan.strategy);
}

test "strategy selector picks full resync past threshold" {
    const config = StrategyConfig.init(4, 10);

    try std.testing.expectEqual(RepairStrategy.delta_replay, selectStrategy(config, .{
        .local_key_count = 100,
        .remote_key_count = 100,
        .estimated_differing_keys = 4,
    }));
    try std.testing.expectEqual(RepairStrategy.merkle_range_diff, selectStrategy(config, .{
        .local_key_count = 100,
        .remote_key_count = 100,
        .estimated_differing_keys = 5,
    }));
    try std.testing.expectEqual(RepairStrategy.full_resync, selectStrategy(config, .{
        .local_key_count = 100,
        .remote_key_count = 100,
        .estimated_differing_keys = 10,
    }));
}

test "causal stability watermark is the min across peer frontiers" {
    var a = clock.VersionVector.init();
    try putCounter(&a, 1, 5);
    try putCounter(&a, 2, 9);
    try putCounter(&a, 3, 2);

    var b = clock.VersionVector.init();
    try putCounter(&b, 1, 3);
    try putCounter(&b, 2, 11);
    try putCounter(&b, 3, 8);

    var c = clock.VersionVector.init();
    try putCounter(&c, 1, 7);
    try putCounter(&c, 2, 4);
    try putCounter(&c, 3, 6);

    const peers = [_]PeerFrontier{
        .{ .causal = a, .hlc = try clock.Hlc.init(900, 2) },
        .{ .causal = b, .hlc = try clock.Hlc.init(700, 4) },
        .{ .causal = c, .hlc = try clock.Hlc.init(800, 1) },
    };

    const watermark = try causalStabilityWatermark(&peers);
    try std.testing.expectEqual(@as(u64, 3), watermark.causal.counter(1));
    try std.testing.expectEqual(@as(u64, 4), watermark.causal.counter(2));
    try std.testing.expectEqual(@as(u64, 2), watermark.causal.counter(3));
    try std.testing.expect(watermark.containsDot(.{ .replica = 1, .counter = 3 }));
    try std.testing.expect(!watermark.containsDot(.{ .replica = 1, .counter = 4 }));
    try std.testing.expectEqual(@as(u48, 700), watermark.hlc.wall_ms);
    try std.testing.expectEqual(@as(u16, 4), watermark.hlc.logical);
}

test "anti-entropy quiet peer interval grows to max and stays bounded" {
    try std.testing.expectEqual(min_repair_interval_ms, nextRepairIntervalMs(0, 0));
    try std.testing.expectEqual(min_repair_interval_ms * 2, nextRepairIntervalMs(0, 1));
    try std.testing.expectEqual(min_repair_interval_ms * 4, nextRepairIntervalMs(0, 2));
    try std.testing.expectEqual(max_repair_interval_ms, nextRepairIntervalMs(0, 10));
    try std.testing.expectEqual(max_repair_interval_ms, nextRepairIntervalMs(0, 1_000));
    try std.testing.expectEqual(max_repair_interval_ms, nextRepairIntervalMs(0, std.math.maxInt(u32)));
    try std.testing.expect(min_repair_interval_ms > 0);
    try std.testing.expect(max_repair_interval_ms >= min_repair_interval_ms);
}

test "anti-entropy divergent peer gets min interval" {
    try std.testing.expectEqual(min_repair_interval_ms, nextRepairIntervalMs(1, 0));
    try std.testing.expectEqual(min_repair_interval_ms, nextRepairIntervalMs(999, 10));
    try std.testing.expectEqual(min_repair_interval_ms, nextRepairIntervalMs(std.math.maxInt(usize), std.math.maxInt(u32)));
}

test "anti-entropy budget caps simultaneous due peers deferred by peer id" {
    const now_ms: u64 = 100_000;
    const peers = [_]PeerRepairState{
        .{ .peer_id = 3, .last_repair_ms = null, .pending_divergence = 5 },
        .{ .peer_id = 1, .last_repair_ms = 0, .pending_divergence = 0, .quiet_repairs = 0 },
        .{ .peer_id = 2, .last_repair_ms = null, .pending_divergence = 0 },
    };
    var out: [3]RepairDecision = undefined;
    const n = scheduleRepairs(&peers, now_ms, .{ .max_per_window = 2, .window_ms = 5_000 }, &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    // Deterministic peer-id order regardless of input order.
    try std.testing.expectEqual(@as(u64, 1), out[0].peer_id);
    try std.testing.expectEqual(@as(u64, 2), out[1].peer_id);
    try std.testing.expectEqual(@as(u64, 3), out[2].peer_id);
    try std.testing.expect(out[0].due and !out[0].deferred);
    try std.testing.expect(out[1].due and !out[1].deferred);
    try std.testing.expect(out[2].due and out[2].deferred);
    try std.testing.expectEqual(now_ms + 5_000, out[2].effective_due_ms);
    // Exactly budget admitted.
    var admitted: usize = 0;
    for (out[0..n]) |d| {
        if (d.due and !d.deferred) admitted += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), admitted);
}

test "anti-entropy clock regression is safe" {
    const peers = [_]PeerRepairState{
        .{ .peer_id = 7, .last_repair_ms = 10_000, .pending_divergence = 0, .quiet_repairs = 0 },
    };
    var out: [1]RepairDecision = undefined;
    const n = scheduleRepairs(&peers, 5_000, .{ .max_per_window = 4, .window_ms = 5_000 }, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(min_repair_interval_ms, out[0].interval_ms);
    try std.testing.expectEqual(@as(u64, 10_000 + min_repair_interval_ms), out[0].effective_due_ms);
    try std.testing.expect(!out[0].due);
    try std.testing.expect(!out[0].deferred);
}

test "anti-entropy zero budget defers all due peers" {
    const peers = [_]PeerRepairState{
        .{ .peer_id = 1, .last_repair_ms = null, .pending_divergence = 1 },
    };
    var out: [1]RepairDecision = undefined;
    _ = scheduleRepairs(&peers, 42, .{ .max_per_window = 0, .window_ms = 1_000 }, &out);
    try std.testing.expect(out[0].due and out[0].deferred);
    try std.testing.expectEqual(@as(u64, 1_042), out[0].effective_due_ms);
}

test "StrategyConfig.applyToml overlays mesh.antientropy keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.antientropy]
        \\delta_replay_limit = 16
    );
    defer doc.deinit(allocator);

    var cfg = StrategyConfig{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 16), cfg.delta_replay_limit);
    try std.testing.expectEqual(@as(usize, 1024), cfg.full_resync_threshold); // default
}
