// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic partial-view membership + eager/lazy broadcast overlay state.
//!
//! The partial view keeps a small active set and a larger passive reserve. The
//! broadcast driver sends full payloads eagerly and repairs gaps lazily with
//! digest/GRAFT.
const std = @import("std");
const membership_view = @import("membership_view.zig");
const toml = @import("../../proto/toml.zig");

pub const NodeId = membership_view.NodeId;
pub const Rng = membership_view.Rng;

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidNode,
};

const max_shuffle_sample = 64;

pub const Config = struct {
    active_max: usize = 8,
    passive_max: usize = 64,
    /// Active random walk length for JOIN forwarding.
    arwl: u8 = 6,
    /// Passive random walk length point; peers are learned passively here.
    prwl: u8 = 3,
    shuffle_active: usize = 2,
    shuffle_passive: usize = 4,

    fn validate(self: Config) Error!void {
        if (self.active_max == 0) return error.InvalidConfig;
        if (self.passive_max <= self.active_max) return error.InvalidConfig;
        if (self.prwl > self.arwl) return error.InvalidConfig;
    }

    /// Overlay `[mesh.gossip]` partial-view keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.gossip.active_view_max")) |v| cfg.active_max = @intCast(v);
        if (doc.getUint("mesh.gossip.passive_view_max")) |v| cfg.passive_max = @intCast(v);
        if (doc.getUint("mesh.gossip.active_walk_len")) |v| cfg.arwl = @intCast(v);
        if (doc.getUint("mesh.gossip.passive_walk_len")) |v| cfg.prwl = @intCast(v);
        if (doc.getUint("mesh.gossip.shuffle_active_count")) |v| cfg.shuffle_active = @intCast(v);
        if (doc.getUint("mesh.gossip.shuffle_passive_count")) |v| cfg.shuffle_passive = @intCast(v);
    }
};

pub const ForwardJoin = struct { to: NodeId, joining: NodeId, ttl: u8 };
pub const Neighbor = struct { to: NodeId, high_priority: bool };
pub const Disconnect = struct { to: NodeId };

pub const ShuffleSample = struct {
    nodes: [max_shuffle_sample]NodeId = undefined,
    len: usize = 0,

    fn append(self: *ShuffleSample, id: NodeId) void {
        if (self.len >= self.nodes.len or containsNode(self.nodes[0..self.len], id)) return;
        self.nodes[self.len] = id;
        self.len += 1;
    }

    pub fn items(self: *const ShuffleSample) []const NodeId {
        return self.nodes[0..self.len];
    }
};

pub const Shuffle = struct { to: NodeId, from: NodeId, ttl: u8, sample: ShuffleSample };

pub const EagerPush = struct { to: NodeId, msg_id: u64, payload: []const u8 };
pub const LazyPush = struct { to: NodeId, msg_id: u64 };
pub const Graft = struct { to: NodeId, msg_id: u64 };
pub const Prune = struct { to: NodeId, msg_id: u64 };

pub const Action = union(enum) {
    ForwardJoin: ForwardJoin,
    Neighbor: Neighbor,
    Disconnect: Disconnect,
    Shuffle: Shuffle,
    ShuffleReply: Shuffle,
    EagerPush: EagerPush,
    LazyPush: LazyPush,
    Graft: Graft,
    Prune: Prune,
};

pub const Views = struct {
    allocator: std.mem.Allocator,
    self_id: NodeId,
    cfg: Config,
    active: []NodeId,
    passive: []NodeId,
    active_len: usize = 0,
    passive_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, self_id: NodeId, cfg: Config) Error!Views {
        if (!validNode(self_id)) return error.InvalidNode;
        try cfg.validate();
        const active = try allocator.alloc(NodeId, cfg.active_max);
        errdefer allocator.free(active);
        const passive = try allocator.alloc(NodeId, cfg.passive_max);
        errdefer allocator.free(passive);
        return .{ .allocator = allocator, .self_id = self_id, .cfg = cfg, .active = active, .passive = passive };
    }

    pub fn deinit(self: *Views) void {
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

    pub fn activeView(self: *const Views) []const NodeId {
        return self.active[0..self.active_len];
    }

    pub fn passiveView(self: *const Views) []const NodeId {
        return self.passive[0..self.passive_len];
    }

    pub fn isActive(self: *const Views, id: NodeId) bool {
        return findNode(self.activeView(), id) != null;
    }

    pub fn isPassive(self: *const Views, id: NodeId) bool {
        return findNode(self.passiveView(), id) != null;
    }

    pub fn onJoin(self: *Views, peer: NodeId, now_ms: i64, rng: *Rng) Error![]Action {
        _ = now_ms;
        try self.validatePeer(peer);
        const old_active = self.activeView();
        _ = self.addActive(peer, rng);

        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        for (old_active) |target| {
            if (target == peer) continue;
            try out.append(self.allocator, .{ .ForwardJoin = .{
                .to = target,
                .joining = peer,
                .ttl = self.cfg.arwl,
            } });
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onForwardJoin(
        self: *Views,
        joining: NodeId,
        ttl: u8,
        from: NodeId,
        now_ms: i64,
        rng: *Rng,
    ) Error![]Action {
        _ = now_ms;
        try self.validatePeer(joining);
        if (validNode(from) and from != self.self_id) _ = self.addActive(from, rng);
        if (ttl == self.cfg.prwl) _ = self.addPassive(joining, rng);

        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        if (ttl == 0 or self.active_len == 0) {
            _ = self.addActive(joining, rng);
            try out.append(self.allocator, .{ .Neighbor = .{ .to = joining, .high_priority = false } });
            return out.toOwnedSlice(self.allocator);
        }

        if (self.randomActiveExcept(from, joining, rng)) |target| {
            try out.append(self.allocator, .{ .ForwardJoin = .{
                .to = target,
                .joining = joining,
                .ttl = ttl - 1,
            } });
        } else {
            _ = self.addActive(joining, rng);
            try out.append(self.allocator, .{ .Neighbor = .{ .to = joining, .high_priority = false } });
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onNeighbor(
        self: *Views,
        peer: NodeId,
        high_priority: bool,
        now_ms: i64,
        rng: *Rng,
    ) Error![]Action {
        _ = now_ms;
        try self.validatePeer(peer);
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);

        if (self.isActive(peer)) return out.toOwnedSlice(self.allocator);
        if (!high_priority and self.active_len >= self.active.len) {
            try out.append(self.allocator, .{ .Disconnect = .{ .to = peer } });
            return out.toOwnedSlice(self.allocator);
        }
        _ = self.addActive(peer, rng);
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onDisconnect(self: *Views, peer: NodeId, now_ms: i64, rng: *Rng) Error![]Action {
        _ = now_ms;
        try self.validatePeer(peer);
        const was_active = self.removeActive(peer);
        _ = self.removePassive(peer);

        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        if (was_active) {
            if (self.promotePassive(rng)) |promoted| {
                try out.append(self.allocator, .{ .Neighbor = .{ .to = promoted, .high_priority = true } });
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn shuffle(self: *Views, rng: *Rng) Error![]Action {
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        if (self.active_len == 0) return out.toOwnedSlice(self.allocator);
        const target = self.active[rng.index(self.active_len)];
        var sample = self.makeShuffleSample(target, rng);
        sample.append(self.self_id);
        try out.append(self.allocator, .{ .Shuffle = .{
            .to = target,
            .from = self.self_id,
            .ttl = self.cfg.arwl,
            .sample = sample,
        } });
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onShuffle(
        self: *Views,
        from: NodeId,
        ttl: u8,
        sample: []const NodeId,
        now_ms: i64,
        rng: *Rng,
    ) Error![]Action {
        _ = now_ms;
        try self.validatePeer(from);
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);

        if (ttl > 0) {
            if (self.randomActiveExcept(from, 0, rng)) |target| {
                try out.append(self.allocator, .{ .Shuffle = .{
                    .to = target,
                    .from = from,
                    .ttl = ttl - 1,
                    .sample = copySample(sample),
                } });
                return out.toOwnedSlice(self.allocator);
            }
        }

        const reply = self.makeShuffleSample(from, rng);
        self.mergePassiveSample(sample, rng);
        try out.append(self.allocator, .{ .ShuffleReply = .{
            .to = from,
            .from = self.self_id,
            .ttl = 0,
            .sample = reply,
        } });
        return out.toOwnedSlice(self.allocator);
    }

    fn validatePeer(self: *const Views, peer: NodeId) Error!void {
        if (!validNode(peer) or peer == self.self_id) return error.InvalidNode;
    }

    fn addActive(self: *Views, peer: NodeId, rng: *Rng) ?NodeId {
        if (!validNode(peer) or peer == self.self_id) return null;
        if (findNode(self.activeView(), peer) != null) return null;
        _ = self.removePassive(peer);
        if (self.active_len < self.active.len) {
            self.active[self.active_len] = peer;
            self.active_len += 1;
            return null;
        }
        const idx = rng.index(self.active_len);
        const demoted = self.active[idx];
        self.active[idx] = peer;
        _ = self.addPassive(demoted, rng);
        return demoted;
    }

    fn addPassive(self: *Views, peer: NodeId, rng: *Rng) ?NodeId {
        if (!validNode(peer) or peer == self.self_id or self.isActive(peer)) return null;
        if (findNode(self.passiveView(), peer) != null) return null;
        if (self.passive_len < self.passive.len) {
            self.passive[self.passive_len] = peer;
            self.passive_len += 1;
            return null;
        }
        const idx = rng.index(self.passive_len);
        const dropped = self.passive[idx];
        self.passive[idx] = peer;
        return dropped;
    }

    fn removeActive(self: *Views, peer: NodeId) bool {
        const idx = findNode(self.activeView(), peer) orelse return false;
        self.active_len -= 1;
        if (idx < self.active_len) self.active[idx] = self.active[self.active_len];
        return true;
    }

    fn removePassive(self: *Views, peer: NodeId) bool {
        const idx = findNode(self.passiveView(), peer) orelse return false;
        self.passive_len -= 1;
        if (idx < self.passive_len) self.passive[idx] = self.passive[self.passive_len];
        return true;
    }

    fn promotePassive(self: *Views, rng: *Rng) ?NodeId {
        if (self.passive_len == 0 or self.active_len >= self.active.len) return null;
        const idx = rng.index(self.passive_len);
        const promoted = self.passive[idx];
        _ = self.removePassive(promoted);
        self.active[self.active_len] = promoted;
        self.active_len += 1;
        return promoted;
    }

    fn randomActiveExcept(self: *const Views, a: NodeId, b: NodeId, rng: *Rng) ?NodeId {
        if (self.active_len == 0) return null;
        var seen: usize = 0;
        while (seen < self.active_len) : (seen += 1) {
            const peer = self.active[(rng.index(self.active_len) + seen) % self.active_len];
            if (peer != a and peer != b) return peer;
        }
        return null;
    }

    fn makeShuffleSample(self: *const Views, excluded: NodeId, rng: *Rng) ShuffleSample {
        var sample = ShuffleSample{};
        var i: usize = 0;
        while (i < self.active_len and i < self.cfg.shuffle_active) : (i += 1) {
            const peer = self.active[(rng.index(self.active_len) + i) % self.active_len];
            if (peer != excluded) sample.append(peer);
        }
        i = 0;
        while (i < self.passive_len and i < self.cfg.shuffle_passive) : (i += 1) {
            const peer = self.passive[(rng.index(self.passive_len) + i) % self.passive_len];
            if (peer != excluded) sample.append(peer);
        }
        return sample;
    }

    fn mergePassiveSample(self: *Views, sample: []const NodeId, rng: *Rng) void {
        for (sample) |peer| {
            if (!validNode(peer) or peer == self.self_id or self.isActive(peer)) continue;
            _ = self.addPassive(peer, rng);
        }
    }
};

pub const BroadcastConfig = struct {
    graft_retry_ms: i64 = 1000,

    /// Overlay `[mesh.gossip]` Broadcast keys onto this config.
    pub fn applyToml(cfg: *BroadcastConfig, doc: *const toml.Document) void {
        if (doc.getInt("mesh.gossip.graft_retry_ms")) |v| cfg.graft_retry_ms = v;
    }
};

const StoredMessage = struct {
    payload: []u8,
};

const Missing = struct {
    msg_id: u64,
    from: NodeId,
    next_graft_ms: i64,
};

pub const Broadcast = struct {
    allocator: std.mem.Allocator,
    views: *const Views,
    cfg: BroadcastConfig,
    messages: std.AutoHashMap(u64, StoredMessage),
    eager: std.AutoHashMap(NodeId, void),
    lazy: std.AutoHashMap(NodeId, void),
    missing: std.ArrayList(Missing) = .empty,

    pub fn init(allocator: std.mem.Allocator, views: *const Views, cfg: BroadcastConfig) Broadcast {
        return .{
            .allocator = allocator,
            .views = views,
            .cfg = cfg,
            .messages = std.AutoHashMap(u64, StoredMessage).init(allocator),
            .eager = std.AutoHashMap(NodeId, void).init(allocator),
            .lazy = std.AutoHashMap(NodeId, void).init(allocator),
        };
    }

    pub fn deinit(self: *Broadcast) void {
        var it = self.messages.valueIterator();
        while (it.next()) |msg| self.allocator.free(msg.payload);
        self.messages.deinit();
        self.eager.deinit();
        self.lazy.deinit();
        self.missing.deinit(self.allocator);
    }

    pub fn broadcast(self: *Broadcast, msg_id: u64, payload: []const u8) ![]Action {
        try self.syncActive();
        const stored = try self.storeMessage(msg_id, payload);
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        try self.appendFanout(&out, msg_id, stored.payload, 0);
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onEager(self: *Broadcast, msg_id: u64, payload: []const u8, from: NodeId) ![]Action {
        try self.syncActive();
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);

        if (self.messages.get(msg_id)) |_| {
            if (self.views.isActive(from)) {
                _ = self.eager.remove(from);
                try self.lazy.put(from, {});
                try out.append(self.allocator, .{ .Prune = .{ .to = from, .msg_id = msg_id } });
            }
            return out.toOwnedSlice(self.allocator);
        }

        const stored = try self.storeMessage(msg_id, payload);
        self.removeMissing(msg_id);
        if (self.views.isActive(from)) {
            try self.eager.put(from, {});
            _ = self.lazy.remove(from);
        }
        try self.appendFanout(&out, msg_id, stored.payload, from);
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onLazy(self: *Broadcast, msg_id: u64, from: NodeId) ![]Action {
        try self.syncActive();
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        if (self.messages.contains(msg_id) or !self.views.isActive(from)) {
            return out.toOwnedSlice(self.allocator);
        }
        try self.lazy.put(from, {});
        _ = self.eager.remove(from);
        if (findMissing(self.missing.items, msg_id) == null) {
            try self.missing.append(self.allocator, .{
                .msg_id = msg_id,
                .from = from,
                .next_graft_ms = 0,
            });
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onGraft(self: *Broadcast, msg_id: u64, from: NodeId) ![]Action {
        try self.syncActive();
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        const stored = self.messages.get(msg_id) orelse return out.toOwnedSlice(self.allocator);
        if (self.views.isActive(from)) {
            try self.eager.put(from, {});
            _ = self.lazy.remove(from);
            try out.append(self.allocator, .{ .EagerPush = .{
                .to = from,
                .msg_id = msg_id,
                .payload = stored.payload,
            } });
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn onPrune(self: *Broadcast, msg_id: u64, from: NodeId) ![]Action {
        _ = msg_id;
        try self.syncActive();
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);
        if (self.views.isActive(from)) {
            _ = self.eager.remove(from);
            try self.lazy.put(from, {});
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn missingTimer(self: *Broadcast, now_ms: i64) ![]Action {
        try self.syncActive();
        var out: std.ArrayList(Action) = .empty;
        errdefer out.deinit(self.allocator);

        var i: usize = 0;
        while (i < self.missing.items.len) {
            var m = &self.missing.items[i];
            if (self.messages.contains(m.msg_id) or !self.views.isActive(m.from)) {
                _ = self.swapRemoveMissingAt(i);
                continue;
            }
            if (now_ms >= m.next_graft_ms) {
                try self.eager.put(m.from, {});
                _ = self.lazy.remove(m.from);
                try out.append(self.allocator, .{ .Graft = .{ .to = m.from, .msg_id = m.msg_id } });
                m.next_graft_ms = now_ms + self.cfg.graft_retry_ms;
            }
            i += 1;
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn hasMessage(self: *const Broadcast, msg_id: u64) bool {
        return self.messages.contains(msg_id);
    }

    pub fn isEager(self: *const Broadcast, peer: NodeId) bool {
        return self.eager.contains(peer);
    }

    pub fn isLazy(self: *const Broadcast, peer: NodeId) bool {
        return self.lazy.contains(peer);
    }

    fn storeMessage(self: *Broadcast, msg_id: u64, payload: []const u8) !StoredMessage {
        if (self.messages.get(msg_id)) |stored| return stored;
        const copy = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(copy);
        const stored = StoredMessage{ .payload = copy };
        try self.messages.put(msg_id, stored);
        return stored;
    }

    fn appendFanout(
        self: *Broadcast,
        out: *std.ArrayList(Action),
        msg_id: u64,
        payload: []const u8,
        from: NodeId,
    ) !void {
        for (self.views.activeView()) |peer| {
            if (peer == from) continue;
            if (self.lazy.contains(peer)) {
                try out.append(self.allocator, .{ .LazyPush = .{ .to = peer, .msg_id = msg_id } });
            } else {
                try self.eager.put(peer, {});
                try out.append(self.allocator, .{ .EagerPush = .{
                    .to = peer,
                    .msg_id = msg_id,
                    .payload = payload,
                } });
            }
        }
    }

    fn syncActive(self: *Broadcast) !void {
        var eager_it = self.eager.keyIterator();
        while (eager_it.next()) |peer| {
            if (!self.views.isActive(peer.*)) _ = self.eager.remove(peer.*);
        }
        var lazy_it = self.lazy.keyIterator();
        while (lazy_it.next()) |peer| {
            if (!self.views.isActive(peer.*)) _ = self.lazy.remove(peer.*);
        }
        for (self.views.activeView()) |peer| {
            if (!self.eager.contains(peer) and !self.lazy.contains(peer)) {
                try self.eager.put(peer, {});
            }
        }
    }

    fn removeMissing(self: *Broadcast, msg_id: u64) void {
        var i: usize = 0;
        while (i < self.missing.items.len) {
            if (self.missing.items[i].msg_id == msg_id) {
                _ = self.swapRemoveMissingAt(i);
            } else {
                i += 1;
            }
        }
    }

    fn swapRemoveMissingAt(self: *Broadcast, idx: usize) Missing {
        const item = self.missing.items[idx];
        _ = self.missing.swapRemove(idx);
        return item;
    }
};

fn validNode(id: NodeId) bool {
    return id != 0;
}

fn findNode(nodes: []const NodeId, id: NodeId) ?usize {
    for (nodes, 0..) |node, idx| {
        if (node == id) return idx;
    }
    return null;
}

fn containsNode(nodes: []const NodeId, id: NodeId) bool {
    return findNode(nodes, id) != null;
}

fn copySample(nodes: []const NodeId) ShuffleSample {
    var out = ShuffleSample{};
    for (nodes) |node| out.append(node);
    return out;
}

fn findMissing(items: []const Missing, msg_id: u64) ?usize {
    for (items, 0..) |item, idx| {
        if (item.msg_id == msg_id) return idx;
    }
    return null;
}

fn freeActions(allocator: std.mem.Allocator, actions: []Action) void {
    allocator.free(actions);
}

fn expectActionTo(actions: []const Action, tag: std.meta.Tag(Action), to: NodeId) !void {
    for (actions) |action| {
        switch (action) {
            .ForwardJoin => |a| if (tag == .ForwardJoin and a.to == to) return,
            .Neighbor => |a| if (tag == .Neighbor and a.to == to) return,
            .Disconnect => |a| if (tag == .Disconnect and a.to == to) return,
            .Shuffle => |a| if (tag == .Shuffle and a.to == to) return,
            .ShuffleReply => |a| if (tag == .ShuffleReply and a.to == to) return,
            .EagerPush => |a| if (tag == .EagerPush and a.to == to) return,
            .LazyPush => |a| if (tag == .LazyPush and a.to == to) return,
            .Graft => |a| if (tag == .Graft and a.to == to) return,
            .Prune => |a| if (tag == .Prune and a.to == to) return,
        }
    }
    return error.TestExpectedEqual;
}

test "active view caps and passive promotion on failure" {
    var rng = Rng.init(7);
    var views = try Views.init(std.testing.allocator, 1, .{ .active_max = 2, .passive_max = 6 });
    defer views.deinit();

    var actions = try views.onNeighbor(10, true, 100, &rng);
    freeActions(std.testing.allocator, actions);
    actions = try views.onNeighbor(11, true, 101, &rng);
    freeActions(std.testing.allocator, actions);
    actions = try views.onNeighbor(12, true, 102, &rng);
    freeActions(std.testing.allocator, actions);

    try std.testing.expectEqual(@as(usize, 2), views.activeView().len);
    try std.testing.expectEqual(@as(usize, 1), views.passiveView().len);

    const failed = views.activeView()[0];
    actions = try views.onDisconnect(failed, 200, &rng);
    defer freeActions(std.testing.allocator, actions);

    try std.testing.expectEqual(@as(usize, 2), views.activeView().len);
    try std.testing.expectEqual(@as(usize, 0), views.passiveView().len);
    try expectActionTo(actions, .Neighbor, views.activeView()[1]);
}

test "broadcast eager builds tree lazy graft recovers and prune sheds duplicate" {
    var rng = Rng.init(13);
    var va = try Views.init(std.testing.allocator, 1, .{ .active_max = 4, .passive_max = 8 });
    var vb = try Views.init(std.testing.allocator, 2, .{ .active_max = 4, .passive_max = 8 });
    var vc = try Views.init(std.testing.allocator, 3, .{ .active_max = 4, .passive_max = 8 });
    defer va.deinit();
    defer vb.deinit();
    defer vc.deinit();

    var actions = try va.onNeighbor(2, true, 0, &rng);
    freeActions(std.testing.allocator, actions);
    actions = try va.onNeighbor(3, true, 0, &rng);
    freeActions(std.testing.allocator, actions);
    actions = try vb.onNeighbor(1, true, 0, &rng);
    freeActions(std.testing.allocator, actions);
    actions = try vb.onNeighbor(3, true, 0, &rng);
    freeActions(std.testing.allocator, actions);
    actions = try vc.onNeighbor(1, true, 0, &rng);
    freeActions(std.testing.allocator, actions);
    actions = try vc.onNeighbor(2, true, 0, &rng);
    freeActions(std.testing.allocator, actions);

    var pa = Broadcast.init(std.testing.allocator, &va, .{ .graft_retry_ms = 10 });
    var pb = Broadcast.init(std.testing.allocator, &vb, .{ .graft_retry_ms = 10 });
    var pc = Broadcast.init(std.testing.allocator, &vc, .{ .graft_retry_ms = 10 });
    defer pa.deinit();
    defer pb.deinit();
    defer pc.deinit();

    const first = try pa.broadcast(100, "one");
    defer freeActions(std.testing.allocator, first);
    var b_to_c: ?EagerPush = null;
    for (first) |action| switch (action) {
        .EagerPush => |push| {
            if (push.to == 2) {
                actions = try pb.onEager(push.msg_id, push.payload, 1);
                for (actions) |a| switch (a) {
                    .EagerPush => |e| {
                        if (e.to == 3) b_to_c = e;
                    },
                    else => {},
                };
                freeActions(std.testing.allocator, actions);
            } else if (push.to == 3) {
                actions = try pc.onEager(push.msg_id, push.payload, 1);
                freeActions(std.testing.allocator, actions);
            }
        },
        else => {},
    };
    try std.testing.expect(pc.hasMessage(100));
    const dup = b_to_c.?;
    actions = try pc.onEager(dup.msg_id, dup.payload, 2);
    try expectActionTo(actions, .Prune, 2);
    freeActions(std.testing.allocator, actions);
    actions = try pb.onPrune(100, 3);
    freeActions(std.testing.allocator, actions);
    try std.testing.expect(pb.isLazy(3));
    try std.testing.expect(!pb.isEager(3));

    const second = try pa.broadcast(101, "two");
    defer freeActions(std.testing.allocator, second);
    for (second) |action| switch (action) {
        .EagerPush => |push| if (push.to == 2) {
            actions = try pb.onEager(push.msg_id, push.payload, 1);
            defer freeActions(std.testing.allocator, actions);
            try expectActionTo(actions, .LazyPush, 3);
            for (actions) |a| switch (a) {
                .LazyPush => |lazy| {
                    if (lazy.to != 3) continue;
                    const lazy_actions = try pc.onLazy(lazy.msg_id, 2);
                    freeActions(std.testing.allocator, lazy_actions);
                },
                else => {},
            };
        },
        else => {},
    };

    actions = try pc.missingTimer(10);
    defer freeActions(std.testing.allocator, actions);
    try expectActionTo(actions, .Graft, 2);
    for (actions) |action| switch (action) {
        .Graft => |graft| {
            const repair = try pb.onGraft(graft.msg_id, 3);
            defer freeActions(std.testing.allocator, repair);
            try expectActionTo(repair, .EagerPush, 3);
            for (repair) |r| switch (r) {
                .EagerPush => |eager| {
                    const done = try pc.onEager(eager.msg_id, eager.payload, 2);
                    freeActions(std.testing.allocator, done);
                },
                else => {},
            };
        },
        else => {},
    };
    try std.testing.expect(pc.hasMessage(101));
}

test "Config/BroadcastConfig applyToml overlay mesh.gossip keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.gossip]
        \\active_view_max = 16
        \\passive_view_max = 128
        \\active_walk_len = 9
        \\graft_retry_ms = 750
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 16), cfg.active_max);
    try std.testing.expectEqual(@as(usize, 128), cfg.passive_max);
    try std.testing.expectEqual(@as(u8, 9), cfg.arwl);
    // Untouched.
    try std.testing.expectEqual(@as(u8, 3), cfg.prwl);

    var pc = BroadcastConfig{};
    pc.applyToml(&doc);
    try std.testing.expectEqual(@as(i64, 750), pc.graft_retry_ms);
}
