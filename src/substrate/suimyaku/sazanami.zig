// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure witnessed Sazanami failure detector.
//!
//! This module has no sockets, timers, or daemon coupling. The caller supplies
//! the clock and deterministic RNG, then transports the returned actions.
const std = @import("std");

const membership_view = @import("membership_view.zig");
const toml = @import("../../proto/toml.zig");

pub const NodeId = membership_view.NodeId;
pub const Rng = membership_view.Rng;
pub const Incarnation = u64;
pub const max_witnesses = 32;

pub const State = enum { alive, suspect, dead };

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidNode,
};

pub const Config = struct {
    period_ms: i64 = 1_000,
    k: usize = 3,
    quorum: usize = 2,
    suspect_timeout_ms: i64 = 3_000,

    fn sanitized(self: Config) Error!Config {
        if (self.period_ms <= 0) return error.InvalidConfig;
        if (self.k == 0) return error.InvalidConfig;
        if (self.suspect_timeout_ms < 0) return error.InvalidConfig;
        var c = self;
        if (c.quorum < 2) c.quorum = 2;
        if (c.quorum > max_witnesses) c.quorum = max_witnesses;
        return c;
    }

    /// Overlay `[mesh.sazanami]` TOML keys onto this config. Missing keys leave the
    /// field at its current (default) value, preserving behavior.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getInt("mesh.sazanami.probe_period_ms")) |v| cfg.period_ms = v;
        if (doc.getUint("mesh.sazanami.indirect_probes")) |v| cfg.k = @intCast(v);
        if (doc.getUint("mesh.sazanami.witness_quorum")) |v| cfg.quorum = @intCast(v);
        if (doc.getInt("mesh.sazanami.suspect_timeout_ms")) |v| cfg.suspect_timeout_ms = v;
    }
};

pub const WitnessSnapshot = struct {
    ids: [max_witnesses]NodeId = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const WitnessSnapshot) []const NodeId {
        return self.ids[0..self.len];
    }
};

const WitnessSet = struct {
    ids: [max_witnesses]NodeId = @splat(0),
    len: u8 = 0,

    fn clear(self: *WitnessSet) void {
        self.len = 0;
    }

    fn add(self: *WitnessSet, id: NodeId) bool {
        if (!validNode(id)) return false;
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            if (self.ids[i] == id) return false;
        }
        if (self.len >= max_witnesses) return false;
        self.ids[self.len] = id;
        self.len += 1;
        return true;
    }

    fn merge(self: *WitnessSet, ids: []const NodeId) bool {
        var changed = false;
        for (ids) |id| {
            changed = self.add(id) or changed;
        }
        return changed;
    }

    fn hasQuorum(self: *const WitnessSet, quorum: usize) bool {
        return self.len >= quorum;
    }

    fn snapshot(self: *const WitnessSet) WitnessSnapshot {
        var out = WitnessSnapshot{};
        out.len = self.len;
        @memcpy(out.ids[0..self.len], self.ids[0..self.len]);
        return out;
    }
};

pub const Ping = struct { target: NodeId };
pub const PingReq = struct { target: NodeId, via: NodeId };
pub const Declare = struct {
    node: NodeId,
    state: State,
    incarnation: Incarnation = 0,
    witnesses: WitnessSnapshot = .{},
};

pub const Action = union(enum) {
    Ping: Ping,
    PingReq: PingReq,
    Declare: Declare,
};

pub const MembershipDelta = struct {
    node: NodeId,
    state: State,
    incarnation: Incarnation = 0,
    witnesses: []const NodeId = &.{},
};

const Member = struct {
    id: NodeId,
    state: State = .alive,
    incarnation: Incarnation = 0,
    suspect_since_ms: i64 = 0,
    awaiting_ack: bool = false,
    ping_deadline_ms: i64 = 0,
    witnesses: WitnessSet = .{},
    dirty: bool = true,
};

pub const Sazanami = struct {
    allocator: std.mem.Allocator,
    self_id: NodeId,
    cfg: Config,
    self_incarnation: Incarnation = 0,
    self_dirty: bool = true,
    next_probe_ms: i64 = 0,
    members: std.ArrayList(Member) = .empty,

    pub fn init(allocator: std.mem.Allocator, self_id: NodeId, cfg: Config) Error!Sazanami {
        if (!validNode(self_id)) return error.InvalidNode;
        return .{
            .allocator = allocator,
            .self_id = self_id,
            .cfg = try cfg.sanitized(),
        };
    }

    pub fn deinit(self: *Sazanami) void {
        self.members.deinit(self.allocator);
        self.* = .{
            .allocator = self.allocator,
            .self_id = self.self_id,
            .cfg = self.cfg,
            .members = .empty,
        };
    }

    pub fn freeActions(self: *Sazanami, actions: []Action) void {
        self.allocator.free(actions);
    }

    /// Advance Sazanami state and return caller-owned actions.
    pub fn tick(self: *Sazanami, now_ms: i64, rng: *Rng) Error![]Action {
        var actions: std.ArrayList(Action) = .empty;
        errdefer actions.deinit(self.allocator);

        try self.handleProbeTimeouts(now_ms, rng, &actions);
        try self.promoteTimedOutSuspects(now_ms, &actions);
        if (now_ms >= self.next_probe_ms) {
            if (self.chooseProbeTarget(rng)) |idx| {
                self.members.items[idx].awaiting_ack = true;
                self.members.items[idx].ping_deadline_ms = now_ms + self.cfg.period_ms;
                try actions.append(self.allocator, .{ .Ping = .{ .target = self.members.items[idx].id } });
                self.next_probe_ms = now_ms + self.cfg.period_ms;
            }
        }
        try self.appendDirtyDeclares(&actions);
        return actions.toOwnedSlice(self.allocator);
    }

    pub fn onAck(self: *Sazanami, from: NodeId) Error!void {
        try self.validatePeer(from);
        const idx = try self.ensureMember(from);
        var m = &self.members.items[idx];
        m.awaiting_ack = false;
        if (m.state == .dead) return;
        if (m.state != .alive) {
            m.state = .alive;
            m.suspect_since_ms = 0;
            m.witnesses.clear();
            m.dirty = true;
        }
    }

    /// Handle an inbound PING_REQ by asking the caller to ping `target`.
    pub fn onPingReq(
        self: *Sazanami,
        from: NodeId,
        target: NodeId,
        now_ms: i64,
    ) Error![]Action {
        try self.validatePeer(from);
        if (!validNode(target) or target == self.self_id) return error.InvalidNode;
        _ = now_ms;
        _ = try self.ensureMember(from);

        var actions: std.ArrayList(Action) = .empty;
        errdefer actions.deinit(self.allocator);
        try actions.append(self.allocator, .{ .Ping = .{ .target = target } });
        try self.appendDirtyDeclares(&actions);
        return actions.toOwnedSlice(self.allocator);
    }

    pub fn onMembershipDelta(self: *Sazanami, delta: MembershipDelta, now_ms: i64) Error!void {
        if (!validNode(delta.node)) return error.InvalidNode;

        if (delta.node == self.self_id) {
            try self.applyDeltaAboutSelf(delta);
            return;
        }

        switch (delta.state) {
            .alive => try self.applyAlive(delta.node, delta.incarnation),
            .suspect => try self.applySuspect(delta.node, delta.incarnation, delta.witnesses, now_ms),
            .dead => try self.applyDead(delta.node, delta.incarnation, delta.witnesses, now_ms),
        }
    }

    pub fn status(self: *const Sazanami, node: NodeId) State {
        if (node == self.self_id) return .alive;
        if (self.findMember(node)) |idx| return self.members.items[idx].state;
        return .dead;
    }

    /// Whether Sazanami already tracks `node`. Distinguishes a genuinely-dead
    /// member from an unknown one (both report `.dead` via `status`), so callers
    /// can register a peer once without resurrecting suspects on every tick.
    pub fn isMember(self: *const Sazanami, node: NodeId) bool {
        return node == self.self_id or self.findMember(node) != null;
    }

    fn applyDeltaAboutSelf(self: *Sazanami, delta: MembershipDelta) Error!void {
        switch (delta.state) {
            .alive => {
                if (delta.incarnation > self.self_incarnation) {
                    self.self_incarnation = delta.incarnation;
                    self.self_dirty = true;
                }
            },
            .suspect, .dead => {
                if (delta.incarnation >= self.self_incarnation) {
                    self.self_incarnation = delta.incarnation + 1;
                    self.self_dirty = true;
                }
            },
        }
    }

    fn applyAlive(self: *Sazanami, node: NodeId, incarnation: Incarnation) Error!void {
        const idx = try self.ensureMember(node);
        var m = &self.members.items[idx];
        if (m.state == .dead and incarnation <= m.incarnation) return;
        if (incarnation > m.incarnation or (incarnation == m.incarnation and m.state == .suspect)) {
            m.incarnation = incarnation;
            m.state = .alive;
            m.suspect_since_ms = 0;
            m.awaiting_ack = false;
            m.witnesses.clear();
            m.dirty = true;
        }
    }

    fn applySuspect(
        self: *Sazanami,
        node: NodeId,
        incarnation: Incarnation,
        witnesses: []const NodeId,
        now_ms: i64,
    ) Error!void {
        const idx = try self.ensureMember(node);
        var m = &self.members.items[idx];
        if (incarnation < m.incarnation) return;
        if (m.state == .dead and incarnation <= m.incarnation) return;

        var changed = false;
        if (incarnation > m.incarnation or m.state == .alive) {
            m.incarnation = incarnation;
            m.state = .suspect;
            m.suspect_since_ms = now_ms;
            m.awaiting_ack = false;
            m.witnesses.clear();
            changed = true;
        }

        changed = m.witnesses.merge(witnesses) or changed;
        if (changed) m.dirty = true;
    }

    fn applyDead(
        self: *Sazanami,
        node: NodeId,
        incarnation: Incarnation,
        witnesses: []const NodeId,
        now_ms: i64,
    ) Error!void {
        try self.applySuspect(node, incarnation, witnesses, now_ms);
        if (self.findMember(node)) |idx| {
            var m = &self.members.items[idx];
            if (m.state == .suspect and m.witnesses.hasQuorum(self.cfg.quorum)) {
                m.state = .dead;
                m.awaiting_ack = false;
                m.dirty = true;
            }
        }
    }

    fn handleProbeTimeouts(
        self: *Sazanami,
        now_ms: i64,
        rng: *Rng,
        actions: *std.ArrayList(Action),
    ) Error!void {
        for (self.members.items) |*m| {
            if (!m.awaiting_ack or now_ms < m.ping_deadline_ms) continue;
            m.awaiting_ack = false;
            if (m.state == .dead) continue;
            if (m.state == .alive) {
                m.state = .suspect;
                m.suspect_since_ms = now_ms;
                m.witnesses.clear();
            }
            _ = m.witnesses.add(self.self_id);
            m.dirty = true;
            try self.appendPingReqs(m.id, rng, actions);
        }
    }

    fn promoteTimedOutSuspects(
        self: *Sazanami,
        now_ms: i64,
        actions: *std.ArrayList(Action),
    ) Error!void {
        for (self.members.items) |*m| {
            if (m.state != .suspect) continue;
            if (!m.witnesses.hasQuorum(self.cfg.quorum)) continue;
            if (now_ms - m.suspect_since_ms < self.cfg.suspect_timeout_ms) continue;
            m.state = .dead;
            m.awaiting_ack = false;
            m.dirty = true;
            try actions.append(self.allocator, .{ .Declare = self.declareFor(m.*) });
            m.dirty = false;
        }
    }

    /// Probe both alive and suspect members. Continuing to probe a suspect lets
    /// this node accrue its own first-hand witness (a remote suspicion alone
    /// stops nothing) so a quorum can actually form, and detects recovery when a
    /// falsely-suspected node answers. Dead members are never re-probed.
    fn chooseProbeTarget(self: *Sazanami, rng: *Rng) ?usize {
        var count: usize = 0;
        for (self.members.items) |m| {
            if (m.state != .dead) count += 1;
        }
        if (count == 0) return null;

        var pick = rng.index(count);
        for (self.members.items, 0..) |m, idx| {
            if (m.state == .dead) continue;
            if (pick == 0) return idx;
            pick -= 1;
        }
        return null;
    }

    fn appendPingReqs(
        self: *Sazanami,
        target: NodeId,
        rng: *Rng,
        actions: *std.ArrayList(Action),
    ) Error!void {
        var witnesses: [max_witnesses]NodeId = undefined;
        var len: usize = 0;
        for (self.members.items) |m| {
            if (m.id == target or m.state != .alive) continue;
            witnesses[len] = m.id;
            len += 1;
            if (len == witnesses.len) break;
        }
        if (len == 0) return;

        const want = @min(self.cfg.k, len);
        var i: usize = 0;
        while (i < want) : (i += 1) {
            const j = i + rng.index(len - i);
            std.mem.swap(NodeId, &witnesses[i], &witnesses[j]);
            try actions.append(self.allocator, .{ .PingReq = .{
                .target = target,
                .via = witnesses[i],
            } });
        }
    }

    fn appendDirtyDeclares(self: *Sazanami, actions: *std.ArrayList(Action)) Error!void {
        if (self.self_dirty) {
            try actions.append(self.allocator, .{ .Declare = .{
                .node = self.self_id,
                .state = .alive,
                .incarnation = self.self_incarnation,
            } });
            self.self_dirty = false;
        }

        for (self.members.items) |*m| {
            if (!m.dirty) continue;
            try actions.append(self.allocator, .{ .Declare = self.declareFor(m.*) });
            m.dirty = false;
        }
    }

    fn declareFor(_: *Sazanami, m: Member) Declare {
        return .{
            .node = m.id,
            .state = m.state,
            .incarnation = m.incarnation,
            .witnesses = m.witnesses.snapshot(),
        };
    }

    fn ensureMember(self: *Sazanami, node: NodeId) Error!usize {
        try self.validatePeer(node);
        if (self.findMember(node)) |idx| return idx;
        try self.members.append(self.allocator, .{ .id = node });
        std.mem.sort(Member, self.members.items, {}, lessMember);
        return self.findMember(node).?;
    }

    fn validatePeer(self: *const Sazanami, node: NodeId) Error!void {
        if (!validNode(node) or node == self.self_id) return error.InvalidNode;
    }

    fn findMember(self: *const Sazanami, node: NodeId) ?usize {
        for (self.members.items, 0..) |m, idx| {
            if (m.id == node) return idx;
        }
        return null;
    }
};

fn validNode(id: NodeId) bool {
    return id != 0;
}

fn lessMember(_: void, a: Member, b: Member) bool {
    return a.id < b.id;
}

fn hasAction(actions: []const Action, comptime tag: std.meta.Tag(Action), node: NodeId) bool {
    for (actions) |action| switch (action) {
        .Ping => |p| if (tag == .Ping and p.target == node) return true,
        .PingReq => |p| if (tag == .PingReq and p.target == node) return true,
        .Declare => |d| if (tag == .Declare and d.node == node) return true,
    };
    return false;
}

const testing = std.testing;

test "healthy node stays alive" {
    var det = try Sazanami.init(testing.allocator, 1, .{ .period_ms = 100 });
    defer det.deinit();
    var rng = Rng.init(7);

    try det.onMembershipDelta(.{ .node = 2, .state = .alive }, 0);
    var actions = try det.tick(0, &rng);
    try testing.expect(hasAction(actions, .Ping, 2));
    det.freeActions(actions);

    try det.onAck(2);
    actions = try det.tick(100, &rng);
    defer det.freeActions(actions);
    try testing.expectEqual(State.alive, det.status(2));
}

test "missed acks transition alive to suspect and request witnesses" {
    var det = try Sazanami.init(testing.allocator, 1, .{ .period_ms = 100, .k = 2 });
    defer det.deinit();
    var rng = Rng.init(11);

    for ([_]NodeId{ 2, 3, 4 }) |node| {
        try det.onMembershipDelta(.{ .node = node, .state = .alive }, 0);
    }

    var actions = try det.tick(0, &rng);
    var target: NodeId = 0;
    for (actions) |action| switch (action) {
        .Ping => |p| target = p.target,
        else => {},
    };
    det.freeActions(actions);

    actions = try det.tick(100, &rng);
    defer det.freeActions(actions);
    try testing.expectEqual(State.suspect, det.status(target));
    try testing.expect(hasAction(actions, .PingReq, target));
    try testing.expect(hasAction(actions, .Declare, target));
}

test "quorum of witnesses transitions suspect to dead" {
    var det = try Sazanami.init(testing.allocator, 1, .{
        .period_ms = 100,
        .quorum = 2,
        .suspect_timeout_ms = 50,
    });
    defer det.deinit();
    var rng = Rng.init(19);

    try det.onMembershipDelta(.{ .node = 9, .state = .suspect, .witnesses = &.{ 2, 3 } }, 0);
    try testing.expectEqual(State.suspect, det.status(9));

    const actions = try det.tick(50, &rng);
    defer det.freeActions(actions);
    try testing.expectEqual(State.dead, det.status(9));
    try testing.expect(hasAction(actions, .Declare, 9));
}

test "single accuser cannot force dead" {
    var det = try Sazanami.init(testing.allocator, 1, .{
        .period_ms = 100,
        .quorum = 2,
        .suspect_timeout_ms = 0,
    });
    defer det.deinit();
    var rng = Rng.init(23);

    try det.onMembershipDelta(.{
        .node = 5,
        .state = .dead,
        .incarnation = 0,
        .witnesses = &.{2},
    }, 0);

    const actions = try det.tick(10, &rng);
    defer det.freeActions(actions);
    try testing.expectEqual(State.suspect, det.status(5));
}

test "newer incarnation refutes stale suspicion" {
    var det = try Sazanami.init(testing.allocator, 1, .{ .period_ms = 100 });
    defer det.deinit();

    try det.onMembershipDelta(.{ .node = 6, .state = .suspect, .witnesses = &.{2} }, 0);
    try testing.expectEqual(State.suspect, det.status(6));

    try det.onMembershipDelta(.{ .node = 6, .state = .alive, .incarnation = 1 }, 10);
    try testing.expectEqual(State.alive, det.status(6));

    try det.onMembershipDelta(.{ .node = 6, .state = .suspect, .incarnation = 0, .witnesses = &.{3} }, 20);
    try testing.expectEqual(State.alive, det.status(6));
}

test "Config.applyToml overlays mesh.sazanami keys and leaves missing at defaults" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.sazanami]
        \\probe_period_ms = 2500
        \\indirect_probes = 5
        \\witness_quorum = 4
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);

    try std.testing.expectEqual(@as(i64, 2500), cfg.period_ms);
    try std.testing.expectEqual(@as(usize, 5), cfg.k);
    try std.testing.expectEqual(@as(usize, 4), cfg.quorum);
    // Untouched key keeps its default.
    try std.testing.expectEqual(@as(i64, 3_000), cfg.suspect_timeout_ms);
}
