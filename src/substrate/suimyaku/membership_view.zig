// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SUIMYAKU bounded partial membership view.
//!
//! This is the LARGE-mesh companion to SAZANAMI: SAZANAMI tracks liveness
//! evidence, while this module bounds overlay fanout with a partial-view-shaped
//! active view plus a larger passive view. All time and randomness are supplied
//! by the caller, so simulation, replay, and production actors share the same
//! deterministic state machine.
const std = @import("std");
const toml = @import("../../proto/toml.zig");

/// Stable identifier for a mesh node (planning/04: low 64 bits of NodeId).
pub const NodeId = u64;

/// Deterministic, small-state RNG for membership decisions.
///
/// The caller owns the seed and passes this object through operations. It is
/// intentionally not cryptographic; membership shuffling is not a secret-bearing
/// path. Capability tokens and key material must use the crypto substrate.
pub const Rng = struct {
    state: u64,

    pub fn init(seed: u64) Rng {
        return .{ .state = seed };
    }

    pub fn next(self: *Rng) u64 {
        self.state +%= 0x9e3779b97f4a7c15;
        var z = self.state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    pub fn index(self: *Rng, upper: usize) usize {
        if (upper <= 1) return 0;
        return @intCast(self.next() % @as(u64, @intCast(upper)));
    }
};

/// Tuning for the bounded view. Capacities are allocated once at init.
pub const Config = struct {
    /// Connected peers. The active view; every active peer may receive
    /// direct protocol traffic, so this should remain small.
    active_capacity: usize = 8,
    /// Backup candidates. This should be larger than the active view.
    passive_capacity: usize = 64,
    /// Maximum active entries sampled into a shuffle.
    shuffle_active_count: usize = 2,
    /// Maximum passive entries sampled into a shuffle.
    shuffle_passive_count: usize = 4,

    pub fn validate(self: Config) Error!void {
        if (self.active_capacity == 0) return error.InvalidConfig;
        if (self.passive_capacity <= self.active_capacity) return error.InvalidConfig;
        if (self.shuffle_active_count + self.shuffle_passive_count == 0) {
            return error.InvalidConfig;
        }
    }

    /// Overlay `[mesh.gossip]` bounded-view keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.gossip.view_active_capacity")) |v| cfg.active_capacity = @intCast(v);
        if (doc.getUint("mesh.gossip.view_passive_capacity")) |v| cfg.passive_capacity = @intCast(v);
        if (doc.getUint("mesh.gossip.view_shuffle_active")) |v| cfg.shuffle_active_count = @intCast(v);
        if (doc.getUint("mesh.gossip.view_shuffle_passive")) |v| cfg.shuffle_passive_count = @intCast(v);
    }
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidNode,
    BufferTooSmall,
};

/// Public view entry. Timestamps are caller-supplied milliseconds.
pub const Entry = struct {
    id: NodeId,
    joined_ms: i64,
    last_seen_ms: i64,
};

/// Result of adding or promoting a member.
pub const JoinResult = struct {
    active: NodeId,
    demoted: ?NodeId = null,
    passive_dropped: ?NodeId = null,
};

/// Result of marking an active member failed.
pub const FailureResult = struct {
    failed: NodeId,
    promoted: ?NodeId = null,
};

/// Shuffle request planned by `buildShuffle`.
pub const ShufflePlan = struct {
    target: NodeId,
    sample_len: usize,
};

/// Bounded partial membership view (active + passive).
pub const MembershipView = struct {
    allocator: std.mem.Allocator,
    self_id: NodeId,
    cfg: Config,
    active: []Entry,
    passive: []Entry,
    active_len: usize = 0,
    passive_len: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        self_id: NodeId,
        cfg: Config,
    ) Error!MembershipView {
        if (!validNodeId(self_id)) return error.InvalidNode;
        try cfg.validate();

        const active = try allocator.alloc(Entry, cfg.active_capacity);
        errdefer allocator.free(active);
        const passive = try allocator.alloc(Entry, cfg.passive_capacity);
        errdefer allocator.free(passive);

        return .{
            .allocator = allocator,
            .self_id = self_id,
            .cfg = cfg,
            .active = active,
            .passive = passive,
        };
    }

    pub fn deinit(self: *MembershipView) void {
        self.allocator.free(self.active);
        self.allocator.free(self.passive);
        self.* = .{
            .allocator = self.allocator,
            .self_id = self.self_id,
            .cfg = self.cfg,
            .active = &.{},
            .passive = &.{},
        };
    }

    pub fn activeCount(self: *const MembershipView) usize {
        return self.active_len;
    }

    pub fn passiveCount(self: *const MembershipView) usize {
        return self.passive_len;
    }

    pub fn activeEntries(self: *const MembershipView) []const Entry {
        return self.active[0..self.active_len];
    }

    pub fn passiveEntries(self: *const MembershipView) []const Entry {
        return self.passive[0..self.passive_len];
    }

    pub fn isActive(self: *const MembershipView, id: NodeId) bool {
        return self.findActive(id) != null;
    }

    pub fn isPassive(self: *const MembershipView, id: NodeId) bool {
        return self.findPassive(id) != null;
    }

    /// Handle a JOIN/NEIGHBOR-UP event by ensuring `peer` is active.
    ///
    /// If the active view is full, one active peer is deterministically demoted
    /// into the passive view. No allocation occurs on this path.
    pub fn join(
        self: *MembershipView,
        peer: NodeId,
        now_ms: i64,
        rng: *Rng,
    ) Error!JoinResult {
        try self.validatePeer(peer);

        if (self.findActive(peer)) |idx| {
            self.active[idx].last_seen_ms = now_ms;
            return .{ .active = peer };
        }

        self.removePassive(peer);
        const entry = Entry{ .id = peer, .joined_ms = now_ms, .last_seen_ms = now_ms };

        if (self.active_len < self.active.len) {
            self.active[self.active_len] = entry;
            self.active_len += 1;
            return .{ .active = peer };
        }

        const idx = rng.index(self.active_len);
        const demoted = self.active[idx];
        self.active[idx] = entry;
        const dropped = self.addPassiveEntry(demoted, rng);
        return .{ .active = peer, .demoted = demoted.id, .passive_dropped = dropped };
    }

    /// Learn a passive candidate from shuffle, join-forward, or introductions.
    pub fn learnPassive(
        self: *MembershipView,
        peer: NodeId,
        now_ms: i64,
        rng: *Rng,
    ) Error!?NodeId {
        try self.validatePeer(peer);
        if (self.isActive(peer)) return null;

        return self.addPassiveEntry(.{
            .id = peer,
            .joined_ms = now_ms,
            .last_seen_ms = now_ms,
        }, rng);
    }

    /// Mark an active peer as healthy without changing view shape.
    pub fn markActiveAlive(self: *MembershipView, peer: NodeId, now_ms: i64) Error!bool {
        try self.validatePeer(peer);
        const idx = self.findActive(peer) orelse return false;
        self.active[idx].last_seen_ms = now_ms;
        return true;
    }

    /// Remove a failed active member and promote one passive candidate if any.
    ///
    /// The failed member is not placed into passive; SAZANAMI must reintroduce it
    /// through a fresh alive/join observation before it can carry traffic again.
    pub fn activeFailed(
        self: *MembershipView,
        peer: NodeId,
        now_ms: i64,
        rng: *Rng,
    ) Error!?FailureResult {
        try self.validatePeer(peer);
        const idx = self.findActive(peer) orelse return null;

        const failed = self.active[idx].id;
        self.removeActiveAt(idx);

        if (self.passive_len == 0) {
            return .{ .failed = failed };
        }

        const passive_idx = rng.index(self.passive_len);
        var promoted = self.passive[passive_idx];
        promoted.last_seen_ms = now_ms;
        self.removePassiveAt(passive_idx);
        self.active[self.active_len] = promoted;
        self.active_len += 1;
        return .{ .failed = failed, .promoted = promoted.id };
    }

    /// Remove a departed peer from both views.
    pub fn leave(self: *MembershipView, peer: NodeId) Error!bool {
        try self.validatePeer(peer);

        var changed = false;
        if (self.findActive(peer)) |idx| {
            self.removeActiveAt(idx);
            changed = true;
        }
        if (self.findPassive(peer)) |idx| {
            self.removePassiveAt(idx);
            changed = true;
        }
        return changed;
    }

    /// Build a shuffle request into caller-owned `out`.
    ///
    /// The target is selected from the active view. The sample is a bounded,
    /// duplicate-free mix of active and passive members, excluding the target.
    pub fn buildShuffle(
        self: *const MembershipView,
        rng: *Rng,
        out: []NodeId,
    ) Error!?ShufflePlan {
        if (self.active_len == 0) return null;

        const desired = @min(
            out.len,
            self.cfg.shuffle_active_count + self.cfg.shuffle_passive_count,
        );
        if (desired == 0) return error.BufferTooSmall;

        const target = self.active[rng.index(self.active_len)].id;
        var len = self.sampleFromEntries(
            self.active[0..self.active_len],
            target,
            self.cfg.shuffle_active_count,
            rng,
            out[0..desired],
            0,
        );
        len = self.sampleFromEntries(
            self.passive[0..self.passive_len],
            target,
            self.cfg.shuffle_passive_count,
            rng,
            out[0..desired],
            len,
        );

        return .{ .target = target, .sample_len = len };
    }

    /// Merge a shuffle reply/request sample into the passive view.
    ///
    /// Invalid self, sender, zero, active, and duplicate nodes are ignored so an
    /// untrusted peer cannot poison the active set or create duplicate fanout.
    pub fn applyShuffle(
        self: *MembershipView,
        sender: NodeId,
        sample: []const NodeId,
        now_ms: i64,
        rng: *Rng,
    ) Error!usize {
        try self.validatePeer(sender);

        var added_or_refreshed: usize = 0;
        for (sample, 0..) |peer, idx| {
            if (!validNodeId(peer)) continue;
            if (containsNode(sample[0..idx], peer)) continue;
            if (peer == self.self_id or peer == sender) continue;
            if (self.isActive(peer)) continue;
            _ = try self.learnPassive(peer, now_ms, rng);
            added_or_refreshed += 1;
        }
        return added_or_refreshed;
    }

    fn validatePeer(self: *const MembershipView, peer: NodeId) Error!void {
        if (!validNodeId(peer) or peer == self.self_id) return error.InvalidNode;
    }

    fn findActive(self: *const MembershipView, peer: NodeId) ?usize {
        return findEntry(self.active[0..self.active_len], peer);
    }

    fn findPassive(self: *const MembershipView, peer: NodeId) ?usize {
        return findEntry(self.passive[0..self.passive_len], peer);
    }

    fn removeActiveAt(self: *MembershipView, idx: usize) void {
        if (idx + 1 < self.active_len) {
            self.active[idx] = self.active[self.active_len - 1];
        }
        self.active_len -= 1;
    }

    fn removePassive(self: *MembershipView, peer: NodeId) void {
        if (self.findPassive(peer)) |idx| self.removePassiveAt(idx);
    }

    fn removePassiveAt(self: *MembershipView, idx: usize) void {
        if (idx + 1 < self.passive_len) {
            self.passive[idx] = self.passive[self.passive_len - 1];
        }
        self.passive_len -= 1;
    }

    fn addPassiveEntry(self: *MembershipView, entry: Entry, rng: *Rng) ?NodeId {
        if (self.findActive(entry.id) != null) return null;
        if (self.findPassive(entry.id)) |idx| {
            self.passive[idx].last_seen_ms = entry.last_seen_ms;
            return null;
        }

        if (self.passive_len < self.passive.len) {
            self.passive[self.passive_len] = entry;
            self.passive_len += 1;
            return null;
        }

        const idx = rng.index(self.passive_len);
        const dropped = self.passive[idx].id;
        self.passive[idx] = entry;
        return dropped;
    }

    fn sampleFromEntries(
        self: *const MembershipView,
        entries: []const Entry,
        excluded: NodeId,
        limit: usize,
        rng: *Rng,
        out: []NodeId,
        start_len: usize,
    ) usize {
        _ = self;
        var len = start_len;
        var seen: usize = 0;
        while (seen < entries.len and seen < limit and len < out.len) : (seen += 1) {
            const idx = (rng.index(entries.len) + seen) % entries.len;
            const id = entries[idx].id;
            if (id == excluded or containsNode(out[0..len], id)) continue;
            out[len] = id;
            len += 1;
        }
        return len;
    }
};

fn validNodeId(id: NodeId) bool {
    return id != 0;
}

fn findEntry(entries: []const Entry, peer: NodeId) ?usize {
    for (entries, 0..) |entry, idx| {
        if (entry.id == peer) return idx;
    }
    return null;
}

fn containsNode(nodes: []const NodeId, peer: NodeId) bool {
    for (nodes) |node| {
        if (node == peer) return true;
    }
    return false;
}

fn expectNodeIn(entries: []const Entry, peer: NodeId) !void {
    try std.testing.expect(findEntry(entries, peer) != null);
}

fn expectSameView(a: *const MembershipView, b: *const MembershipView) !void {
    try std.testing.expectEqual(a.self_id, b.self_id);
    try std.testing.expectEqual(a.active_len, b.active_len);
    try std.testing.expectEqual(a.passive_len, b.passive_len);
    try std.testing.expectEqualSlices(Entry, a.activeEntries(), b.activeEntries());
    try std.testing.expectEqualSlices(Entry, a.passiveEntries(), b.passiveEntries());
}

test "active view stays bounded and demotes overflow into passive" {
    var rng = Rng.init(7);
    var view = try MembershipView.init(std.testing.allocator, 1, .{
        .active_capacity = 3,
        .passive_capacity = 8,
    });
    defer view.deinit();

    _ = try view.join(10, 100, &rng);
    _ = try view.join(11, 101, &rng);
    _ = try view.join(12, 102, &rng);
    const result = try view.join(13, 103, &rng);

    try std.testing.expectEqual(@as(usize, 3), view.activeCount());
    try std.testing.expect(view.activeCount() <= view.cfg.active_capacity);
    try std.testing.expect(result.demoted != null);
    try expectNodeIn(view.passiveEntries(), result.demoted.?);
    try expectNodeIn(view.activeEntries(), 13);
}

test "passive shuffle learns remote candidates and excludes active peers" {
    var rng = Rng.init(11);
    var view = try MembershipView.init(std.testing.allocator, 1, .{
        .active_capacity = 2,
        .passive_capacity = 6,
        .shuffle_active_count = 1,
        .shuffle_passive_count = 3,
    });
    defer view.deinit();

    _ = try view.join(10, 100, &rng);
    _ = try view.join(11, 101, &rng);
    _ = try view.learnPassive(20, 102, &rng);
    _ = try view.learnPassive(21, 103, &rng);

    var sample: [4]NodeId = undefined;
    const plan = (try view.buildShuffle(&rng, &sample)).?;
    try std.testing.expect(plan.sample_len <= sample.len);
    try std.testing.expect(view.isActive(plan.target));

    const changed = try view.applyShuffle(10, &.{ 11, 22, 23, 1, 0, 22 }, 200, &rng);
    try std.testing.expectEqual(@as(usize, 2), changed);
    try std.testing.expect(!view.isPassive(11));
    try std.testing.expect(!view.isPassive(1));
    try expectNodeIn(view.passiveEntries(), 22);
    try expectNodeIn(view.passiveEntries(), 23);
}

test "active-member failure promotes from passive" {
    var rng = Rng.init(19);
    var view = try MembershipView.init(std.testing.allocator, 1, .{
        .active_capacity = 2,
        .passive_capacity = 6,
    });
    defer view.deinit();

    _ = try view.join(10, 100, &rng);
    _ = try view.join(11, 101, &rng);
    _ = try view.learnPassive(20, 102, &rng);
    _ = try view.learnPassive(21, 103, &rng);

    const result = (try view.activeFailed(10, 200, &rng)).?;
    try std.testing.expectEqual(@as(NodeId, 10), result.failed);
    try std.testing.expect(result.promoted != null);
    try std.testing.expect(!view.isActive(10));
    try std.testing.expectEqual(@as(usize, 2), view.activeCount());
    try std.testing.expectEqual(@as(usize, 1), view.passiveCount());
}

test "membership decisions are deterministic for a seed" {
    var rng_a = Rng.init(0x5eed);
    var rng_b = Rng.init(0x5eed);
    var a = try MembershipView.init(std.testing.allocator, 1, .{
        .active_capacity = 3,
        .passive_capacity = 7,
        .shuffle_active_count = 2,
        .shuffle_passive_count = 3,
    });
    defer a.deinit();
    var b = try MembershipView.init(std.testing.allocator, 1, .{
        .active_capacity = 3,
        .passive_capacity = 7,
        .shuffle_active_count = 2,
        .shuffle_passive_count = 3,
    });
    defer b.deinit();

    for (10..18) |id| {
        _ = try a.join(@intCast(id), @intCast(id * 10), &rng_a);
        _ = try b.join(@intCast(id), @intCast(id * 10), &rng_b);
    }
    _ = try a.applyShuffle(10, &.{ 30, 31, 32, 33, 34 }, 500, &rng_a);
    _ = try b.applyShuffle(10, &.{ 30, 31, 32, 33, 34 }, 500, &rng_b);
    _ = try a.activeFailed(13, 600, &rng_a);
    _ = try b.activeFailed(13, 600, &rng_b);

    var sample_a: [5]NodeId = undefined;
    var sample_b: [5]NodeId = undefined;
    const plan_a = (try a.buildShuffle(&rng_a, &sample_a)).?;
    const plan_b = (try b.buildShuffle(&rng_b, &sample_b)).?;

    try std.testing.expectEqual(plan_a, plan_b);
    try std.testing.expectEqualSlices(NodeId, sample_a[0..plan_a.sample_len], sample_b[0..plan_b.sample_len]);
    try expectSameView(&a, &b);
}

test "invalid input is rejected without changing the view" {
    var rng = Rng.init(23);
    try std.testing.expectError(error.InvalidNode, MembershipView.init(std.testing.allocator, 0, .{}));
    try std.testing.expectError(error.InvalidConfig, MembershipView.init(std.testing.allocator, 1, .{
        .active_capacity = 2,
        .passive_capacity = 2,
    }));

    var view = try MembershipView.init(std.testing.allocator, 1, .{
        .active_capacity = 2,
        .passive_capacity = 5,
    });
    defer view.deinit();

    try std.testing.expectError(error.InvalidNode, view.join(0, 100, &rng));
    try std.testing.expectError(error.InvalidNode, view.join(1, 100, &rng));
    try std.testing.expectEqual(@as(usize, 0), view.activeCount());
    try std.testing.expectEqual(@as(usize, 0), view.passiveCount());
}

test "Config.applyToml overlays mesh.gossip bounded-view keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.gossip]
        \\view_active_capacity = 10
        \\view_passive_capacity = 80
        \\view_shuffle_active = 3
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 10), cfg.active_capacity);
    try std.testing.expectEqual(@as(usize, 80), cfg.passive_capacity);
    try std.testing.expectEqual(@as(usize, 3), cfg.shuffle_active_count);
    try std.testing.expectEqual(@as(usize, 4), cfg.shuffle_passive_count); // default
}
