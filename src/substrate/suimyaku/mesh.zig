// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Suimyaku mesh coordinator: partial-view membership + eager/lazy broadcast +
//! witnessed Sazanami failure detection, composed into one transport-agnostic
//! state machine.
//!
//! Each of the three pieces is an independently-tested pure driver
//! (`gossip_views.Views`, `gossip_views.Broadcast`, `sazanami.Sazanami`). This module is
//! the missing glue that makes them a working mesh:
//!
//!   * the overlay decides *who* a node keeps links to (active view);
//!   * Broadcast disseminates application payloads epidemically over those links,
//!     repairing gaps lazily with GRAFT;
//!   * witnessed Sazanami decides *which* peers are alive, and a quorum of witnesses
//!     is required before any node is declared dead (no single accuser).
//!
//! The feedback loop is the real work here:
//!   - when the overlay adds an active peer, Sazanami is told to start probing it;
//!   - when Sazanami declares a peer dead, the overlay disconnects it, and Broadcast
//!     prunes it from its eager/lazy sets on the next `syncActive`.
//!
//! Like `S2sLink`, this is initialized *in place*: `Broadcast` borrows
//! `&self.views`, so the struct must already live at its final address before
//! `init` runs. The reactor/daemon drives it by handing inbound `Wire` messages
//! to `recv` and flushing the returned `Envelope`s to the matching peer links;
//! `tick` advances time-based behaviour (probes, suspicion timeouts, GRAFT
//! retries). The coordinator is deterministic — all randomness comes from a
//! seeded `Rng` — so it slots straight into the DST harness.
const std = @import("std");

const gossip = @import("gossip_views.zig");
const sazanami = @import("sazanami.zig");
const membership_view = @import("membership_view.zig");
const toml = @import("../../proto/toml.zig");

pub const NodeId = membership_view.NodeId;
pub const Rng = membership_view.Rng;
pub const State = sazanami.State;

pub const Error = gossip.Error || sazanami.Error || std.mem.Allocator.Error;

pub const Config = struct {
    views: gossip.Config = .{},
    broadcaster: gossip.BroadcastConfig = .{},
    sazanami: sazanami.Config = .{},
    /// Deterministic seed for this node's overlay/probe randomness.
    rng_seed: u64 = 0,

    /// Overlay the composite `[mesh.*]` config by delegating to each embedded
    /// sub-config's `applyToml`. Missing keys leave every field at its default,
    /// so the mesh behaves identically until the orchestrator wires real values.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        cfg.views.applyToml(doc);
        cfg.broadcaster.applyToml(doc);
        cfg.sazanami.applyToml(doc);
        if (doc.getUint("mesh.rng_seed")) |v| cfg.rng_seed = v;
    }
};

/// One cross-node control/data message. The only heap-owning variant is
/// `eager` (it carries an application payload); ownership rules live with
/// `freeEnvelopes`/`freeRecv`.
pub const Wire = union(enum) {
    /// Bootstrap: a node asks `to` to fold it into the overlay.
    join,
    forward_join: struct { joining: NodeId, ttl: u8 },
    neighbor: struct { high_priority: bool },
    disconnect,
    shuffle: struct { origin: NodeId, ttl: u8, sample: gossip.ShuffleSample },
    shuffle_reply: struct { sample: gossip.ShuffleSample },
    eager: struct { msg_id: u64, payload: []const u8 },
    lazy: struct { msg_id: u64 },
    graft: struct { msg_id: u64 },
    prune: struct { msg_id: u64 },
    ping,
    ack,
    ping_req: struct { target: NodeId },
    membership: struct {
        node: NodeId,
        state: State,
        incarnation: u64,
        witnesses: sazanami.WitnessSnapshot,
    },
};

pub const Envelope = struct { to: NodeId, msg: Wire };

/// Result of feeding one inbound message: the outbound storm it produced, plus
/// an application payload if this message completed a not-yet-seen broadcast.
pub const RecvResult = struct {
    envelopes: []Envelope,
    /// Owned copy of a newly-delivered application payload, or null.
    delivered: ?[]u8 = null,
};

pub const Mesh = struct {
    allocator: std.mem.Allocator,
    self_id: NodeId,
    cfg: Config,
    views: gossip.Views,
    broadcaster: gossip.Broadcast,
    sazanami: sazanami.Sazanami,
    rng: Rng,
    bcast_seq: u64 = 0,

    /// Initialize in place. `self` must already be at its final address because
    /// `broadcaster` captures `&self.views`.
    pub fn init(self: *Mesh, allocator: std.mem.Allocator, self_id: NodeId, cfg: Config) Error!void {
        self.* = .{
            .allocator = allocator,
            .self_id = self_id,
            .cfg = cfg,
            .views = undefined,
            .broadcaster = undefined,
            .sazanami = undefined,
            .rng = Rng.init(cfg.rng_seed),
        };
        self.views = try gossip.Views.init(allocator, self_id, cfg.views);
        errdefer self.views.deinit();
        self.sazanami = try sazanami.Sazanami.init(allocator, self_id, cfg.sazanami);
        errdefer self.sazanami.deinit();
        self.broadcaster = gossip.Broadcast.init(allocator, &self.views, cfg.broadcaster);
    }

    pub fn deinit(self: *Mesh) void {
        self.broadcaster.deinit();
        self.sazanami.deinit();
        self.views.deinit();
        self.* = undefined;
    }

    pub fn activeView(self: *const Mesh) []const NodeId {
        return self.views.activeView();
    }

    pub fn passiveView(self: *const Mesh) []const NodeId {
        return self.views.passiveView();
    }

    pub fn status(self: *const Mesh, node: NodeId) State {
        return self.sazanami.status(node);
    }

    pub fn isActive(self: *const Mesh, node: NodeId) bool {
        return self.views.isActive(node);
    }

    pub fn hasMessage(self: *const Mesh, msg_id: u64) bool {
        return self.broadcaster.hasMessage(msg_id);
    }

    /// Free the envelope slice returned by `join`/`broadcast`/`tick`.
    pub fn freeEnvelopes(self: *Mesh, envelopes: []Envelope) void {
        for (envelopes) |env| {
            if (env.msg == .eager) self.allocator.free(env.msg.eager.payload);
        }
        self.allocator.free(envelopes);
    }

    pub fn freeRecv(self: *Mesh, result: RecvResult) void {
        self.freeEnvelopes(result.envelopes);
        if (result.delivered) |d| self.allocator.free(d);
    }

    /// Bootstrap into the mesh by asking `contact` to fold us in.
    pub fn join(self: *Mesh, contact: NodeId) Error![]Envelope {
        var out: std.ArrayList(Envelope) = .empty;
        errdefer self.freeEnvelopeList(&out);
        try out.append(self.allocator, .{ .to = contact, .msg = .join });
        return out.toOwnedSlice(self.allocator);
    }

    /// Epidemic-broadcast an application payload over the overlay.
    pub fn broadcast(self: *Mesh, payload: []const u8) Error![]Envelope {
        const msg_id = self.nextMsgId();
        var out: std.ArrayList(Envelope) = .empty;
        errdefer self.freeEnvelopeList(&out);
        const actions = try self.broadcaster.broadcast(msg_id, payload);
        defer self.allocator.free(actions);
        try self.translateGossip(&out, actions);
        return out.toOwnedSlice(self.allocator);
    }

    /// Advance time-based behaviour: Sazanami probing/suspicion, Broadcast GRAFT
    /// retries, and death-driven overlay eviction.
    pub fn tick(self: *Mesh, now_ms: i64) Error![]Envelope {
        var out: std.ArrayList(Envelope) = .empty;
        errdefer self.freeEnvelopeList(&out);

        const saz_actions = try self.sazanami.tick(now_ms, &self.rng);
        defer self.sazanami.freeActions(saz_actions);
        try self.translateSazanami(&out, saz_actions);

        const graft = try self.broadcaster.missingTimer(now_ms);
        defer self.allocator.free(graft);
        try self.translateGossip(&out, graft);

        try self.reconcile(&out, now_ms);
        return out.toOwnedSlice(self.allocator);
    }

    /// Feed one inbound message from `from`.
    pub fn recv(self: *Mesh, from: NodeId, msg: Wire, now_ms: i64) Error!RecvResult {
        var out: std.ArrayList(Envelope) = .empty;
        errdefer self.freeEnvelopeList(&out);
        var delivered: ?[]u8 = null;
        errdefer if (delivered) |d| self.allocator.free(d);

        switch (msg) {
            .join => try self.dispatchGossip(&out, try self.views.onJoin(from, now_ms, &self.rng)),
            .forward_join => |fj| try self.dispatchGossip(
                &out,
                try self.views.onForwardJoin(fj.joining, fj.ttl, from, now_ms, &self.rng),
            ),
            .neighbor => |n| try self.dispatchGossip(
                &out,
                try self.views.onNeighbor(from, n.high_priority, now_ms, &self.rng),
            ),
            .disconnect => try self.dispatchGossip(
                &out,
                try self.views.onDisconnect(from, now_ms, &self.rng),
            ),
            .shuffle => |s| try self.dispatchGossip(
                &out,
                try self.views.onShuffle(from, s.ttl, s.sample.items(), now_ms, &self.rng),
            ),
            // Shuffle replies only enrich the passive view; best-effort dropped
            // here (the coordinator never initiates shuffles yet).
            .shuffle_reply => {},
            .eager => |e| {
                const had = self.broadcaster.hasMessage(e.msg_id);
                const actions = try self.broadcaster.onEager(e.msg_id, e.payload, from);
                defer self.allocator.free(actions);
                try self.translateGossip(&out, actions);
                if (!had and self.broadcaster.hasMessage(e.msg_id)) {
                    delivered = try self.allocator.dupe(u8, e.payload);
                }
            },
            .lazy => |l| try self.dispatchGossip(&out, try self.broadcaster.onLazy(l.msg_id, from)),
            .graft => |g| try self.dispatchGossip(&out, try self.broadcaster.onGraft(g.msg_id, from)),
            .prune => |p| try self.dispatchGossip(&out, try self.broadcaster.onPrune(p.msg_id, from)),
            .ping => try out.append(self.allocator, .{ .to = from, .msg = .ack }),
            .ack => try self.sazanami.onAck(from),
            .ping_req => |pr| {
                const actions = try self.sazanami.onPingReq(from, pr.target, now_ms);
                defer self.sazanami.freeActions(actions);
                try self.translateSazanami(&out, actions);
            },
            .membership => |m| try self.sazanami.onMembershipDelta(.{
                .node = m.node,
                .state = m.state,
                .incarnation = m.incarnation,
                .witnesses = m.witnesses.slice(),
            }, now_ms),
        }

        try self.reconcile(&out, now_ms);
        return .{ .envelopes = try out.toOwnedSlice(self.allocator), .delivered = delivered };
    }

    // --- internal -----------------------------------------------------------

    /// Keep the overlay and the failure detector in agreement:
    ///   1. register every active-view peer as a Sazanami member so it gets probed
    ///      (Sazanami treats *unknown* nodes as dead, so this must run before any
    ///      death check, and it cannot resurrect a genuinely-dead member);
    ///   2. evict any active peer Sazanami now reports dead, so Broadcast drops it.
    /// Only the active view is reconciled: passive entries are an unprobed
    /// reserve, and an unknown passive node must not be mistaken for dead.
    fn reconcile(self: *Mesh, out: *std.ArrayList(Envelope), now_ms: i64) Error!void {
        // Snapshot the active view before touching Sazanami/views; overflow simply
        // defers the rest to the next tick.
        var live_buf: [256]NodeId = undefined;
        var live_len: usize = 0;
        for (self.views.activeView()) |peer| {
            if (live_len >= live_buf.len) break;
            live_buf[live_len] = peer;
            live_len += 1;
        }
        for (live_buf[0..live_len]) |peer| {
            // Register first contact only — re-asserting alive every tick would
            // resurrect a suspect/dead member and stall failure detection.
            if (!self.sazanami.isMember(peer)) {
                try self.sazanami.onMembershipDelta(.{ .node = peer, .state = .alive }, now_ms);
            }
        }

        var dead_buf: [256]NodeId = undefined;
        var dead_len: usize = 0;
        for (live_buf[0..live_len]) |peer| {
            if (self.sazanami.status(peer) == .dead and dead_len < dead_buf.len) {
                dead_buf[dead_len] = peer;
                dead_len += 1;
            }
        }
        for (dead_buf[0..dead_len]) |peer| {
            const actions = try self.views.onDisconnect(peer, now_ms, &self.rng);
            defer self.allocator.free(actions);
            try self.translateGossip(out, actions);
        }
    }

    fn dispatchGossip(self: *Mesh, out: *std.ArrayList(Envelope), actions: []gossip.Action) Error!void {
        defer self.allocator.free(actions);
        try self.translateGossip(out, actions);
    }

    fn translateGossip(self: *Mesh, out: *std.ArrayList(Envelope), actions: []const gossip.Action) Error!void {
        for (actions) |a| {
            const env: Envelope = switch (a) {
                .ForwardJoin => |x| .{ .to = x.to, .msg = .{ .forward_join = .{ .joining = x.joining, .ttl = x.ttl } } },
                .Neighbor => |x| .{ .to = x.to, .msg = .{ .neighbor = .{ .high_priority = x.high_priority } } },
                .Disconnect => |x| .{ .to = x.to, .msg = .disconnect },
                .Shuffle => |x| .{ .to = x.to, .msg = .{ .shuffle = .{ .origin = x.from, .ttl = x.ttl, .sample = x.sample } } },
                .ShuffleReply => |x| .{ .to = x.to, .msg = .{ .shuffle_reply = .{ .sample = x.sample } } },
                .EagerPush => |x| .{ .to = x.to, .msg = .{ .eager = .{ .msg_id = x.msg_id, .payload = try self.allocator.dupe(u8, x.payload) } } },
                .LazyPush => |x| .{ .to = x.to, .msg = .{ .lazy = .{ .msg_id = x.msg_id } } },
                .Graft => |x| .{ .to = x.to, .msg = .{ .graft = .{ .msg_id = x.msg_id } } },
                .Prune => |x| .{ .to = x.to, .msg = .{ .prune = .{ .msg_id = x.msg_id } } },
            };
            errdefer if (env.msg == .eager) self.allocator.free(env.msg.eager.payload);
            try out.append(self.allocator, env);
        }
    }

    /// Sazanami `Declare`s are membership gossip with no fixed recipient; fan them
    /// out over the active view so the epidemic spreads.
    fn translateSazanami(self: *Mesh, out: *std.ArrayList(Envelope), actions: []const sazanami.Action) Error!void {
        for (actions) |a| {
            switch (a) {
                .Ping => |x| try out.append(self.allocator, .{ .to = x.target, .msg = .ping }),
                .PingReq => |x| try out.append(self.allocator, .{ .to = x.via, .msg = .{ .ping_req = .{ .target = x.target } } }),
                .Declare => |x| {
                    for (self.views.activeView()) |peer| {
                        try out.append(self.allocator, .{ .to = peer, .msg = .{ .membership = .{
                            .node = x.node,
                            .state = x.state,
                            .incarnation = x.incarnation,
                            .witnesses = x.witnesses,
                        } } });
                    }
                },
            }
        }
    }

    fn freeEnvelopeList(self: *Mesh, list: *std.ArrayList(Envelope)) void {
        for (list.items) |env| {
            if (env.msg == .eager) self.allocator.free(env.msg.eager.payload);
        }
        list.deinit(self.allocator);
    }

    fn nextMsgId(self: *Mesh) u64 {
        self.bcast_seq += 1;
        var h = std.hash.Wyhash.init(self.self_id);
        h.update(std.mem.asBytes(&self.bcast_seq));
        return h.final();
    }
};

// ---------------------------------------------------------------------------
// Deterministic multi-node simulation (DST): a fixed set of in-process meshes,
// a single FIFO of in-flight envelopes, and a logical clock. Used to prove the
// three composed machines actually form an overlay, disseminate a broadcast to
// every node, and converge on a peer's death through witnessed Sazanami.
// ---------------------------------------------------------------------------

const testing = std.testing;

const SimMsg = struct { from: NodeId, env: Envelope };

fn dupEnv(allocator: std.mem.Allocator, env: Envelope) !Envelope {
    var copy = env;
    if (env.msg == .eager) {
        copy.msg = .{ .eager = .{
            .msg_id = env.msg.eager.msg_id,
            .payload = try allocator.dupe(u8, env.msg.eager.payload),
        } };
    }
    return copy;
}

fn Sim(comptime n: usize) type {
    return struct {
        const Self = @This();
        nodes: [n]Mesh = undefined,
        alive: [n]bool = @splat(true),
        queue: std.ArrayList(SimMsg) = .empty,
        delivered: [n]usize = @splat(0),
        now_ms: i64 = 0,
        allocator: std.mem.Allocator,

        fn idx(id: NodeId) usize {
            return @intCast(id - 1);
        }

        /// Initialize in place: each Mesh's Broadcast captures `&self.nodes[i].views`,
        /// so the Sim (and thus the nodes array) must already be at its final
        /// address before the meshes are built.
        fn init(self: *Self, allocator: std.mem.Allocator) !void {
            self.* = .{ .allocator = allocator };
            for (&self.nodes, 0..) |*node, i| {
                try node.init(allocator, @intCast(i + 1), .{
                    .views = .{ .active_max = n, .passive_max = n + 4 },
                    .sazanami = .{ .period_ms = 100, .suspect_timeout_ms = 300, .quorum = 2 },
                    .rng_seed = @intCast(0xC0FFEE + i),
                });
            }
        }

        fn deinit(self: *Self) void {
            for (&self.nodes) |*node| node.deinit();
            for (self.queue.items) |m| {
                if (m.env.msg == .eager) self.allocator.free(m.env.msg.eager.payload);
            }
            self.queue.deinit(self.allocator);
        }

        /// Enqueue envelopes sourced from `from`, taking ownership of any eager
        /// payloads (dup so the caller can free its own slice).
        fn enqueue(self: *Self, from: NodeId, envelopes: []const Envelope) !void {
            for (envelopes) |env| {
                try self.queue.append(self.allocator, .{ .from = from, .env = try dupEnv(self.allocator, env) });
            }
        }

        /// Drain the FIFO, delivering each message to a live destination and
        /// folding the resulting envelopes back in. Bounded to avoid runaway.
        fn drain(self: *Self) !void {
            var budget: usize = 1_000_000;
            while (self.queue.items.len > 0 and budget > 0) : (budget -= 1) {
                const m = self.queue.orderedRemove(0);
                defer if (m.env.msg == .eager) self.allocator.free(m.env.msg.eager.payload);
                const to = idx(m.env.to);
                if (!self.alive[to]) continue;
                var node = &self.nodes[to];
                const result = try node.recv(m.from, m.env.msg, self.now_ms);
                defer node.freeRecv(result);
                if (result.delivered != null) self.delivered[to] += 1;
                try self.enqueue(m.env.to, result.envelopes);
            }
            try testing.expect(budget > 0);
        }

        /// Tick every live node and drain, advancing the clock by `step_ms`.
        fn tickAll(self: *Self, step_ms: i64) !void {
            self.now_ms += step_ms;
            for (&self.nodes, 0..) |*node, i| {
                if (!self.alive[i]) continue;
                const envs = try node.tick(self.now_ms);
                defer node.freeEnvelopes(envs);
                try self.enqueue(@intCast(i + 1), envs);
            }
            try self.drain();
        }

        /// Bootstrap nodes 2..n into the overlay through node 1.
        fn joinThroughFirst(self: *Self) !void {
            var i: usize = 1;
            while (i < n) : (i += 1) {
                const envs = try self.nodes[i].join(1);
                defer self.nodes[i].freeEnvelopes(envs);
                try self.enqueue(@intCast(i + 1), envs);
            }
            try self.drain();
        }

        /// Force a complete overlay: every ordered pair becomes high-priority
        /// active neighbours. Deterministic, so membership/death assertions hold
        /// without depending on the random walk's overlay shape.
        fn wireComplete(self: *Self) !void {
            for (&self.nodes, 0..) |*node, i| {
                var j: usize = 0;
                while (j < n) : (j += 1) {
                    if (j == i) continue;
                    const r = try node.recv(@intCast(j + 1), .{ .neighbor = .{ .high_priority = true } }, self.now_ms);
                    defer node.freeRecv(r);
                    try self.enqueue(@intCast(i + 1), r.envelopes);
                }
            }
            try self.drain();
        }
    };
}

test "join bootstrap forms a connected overlay and floods a broadcast to all" {
    const allocator = testing.allocator;
    const N = 6;
    var sim: Sim(N) = undefined;
    try sim.init(allocator);
    defer sim.deinit();

    try sim.joinThroughFirst();
    var t: usize = 0;
    while (t < 8) : (t += 1) try sim.tickAll(100);

    // Connected: every node holds at least one active link.
    for (sim.nodes) |node| try testing.expect(node.activeView().len >= 1);

    // Broadcast from node 1 reaches every other node exactly once via the
    // Broadcast flood over the overlay (multi-hop eager fan-out).
    {
        const envs = try sim.nodes[0].broadcast("orochi-rises");
        defer sim.nodes[0].freeEnvelopes(envs);
        try sim.enqueue(1, envs);
    }
    try sim.drain();
    t = 0;
    while (t < 5) : (t += 1) try sim.tickAll(1000); // GRAFT-heal any lazy-only paths

    var d: usize = 1;
    while (d < N) : (d += 1) try testing.expectEqual(@as(usize, 1), sim.delivered[d]);
}

test "witnessed Sazanami converges on a dead peer and evicts it from the overlay" {
    const allocator = testing.allocator;
    const N = 4;
    var sim: Sim(N) = undefined;
    try sim.init(allocator);
    defer sim.deinit();

    try sim.wireComplete();
    var t: usize = 0;
    while (t < 8) : (t += 1) try sim.tickAll(100);

    // Complete overlay: every node knows every other is alive.
    for (sim.nodes, 0..) |node, ni| {
        var other: usize = 0;
        while (other < N) : (other += 1) {
            if (other == ni) continue;
            try testing.expectEqual(State.alive, node.status(@intCast(other + 1)));
        }
    }

    // Kill node N: drop its deliveries and stop ticking it.
    sim.alive[Sim(N).idx(N)] = false;

    // Survivors directly probe N, time out, cross-witness via suspect declares,
    // reach quorum, declare dead, and the dead state re-gossips to all.
    t = 0;
    while (t < 80) : (t += 1) try sim.tickAll(100);

    var s: usize = 0;
    while (s < N - 1) : (s += 1) {
        try testing.expectEqual(State.dead, sim.nodes[s].status(N));
        try testing.expect(!sim.nodes[s].isActive(N));
    }
}

test "GRAFT repair delivers a lazily-announced broadcast" {
    const allocator = testing.allocator;
    var a: Mesh = undefined;
    try a.init(allocator, 1, .{ .views = .{ .active_max = 4, .passive_max = 8 } });
    defer a.deinit();
    var b: Mesh = undefined;
    try b.init(allocator, 2, .{ .views = .{ .active_max = 4, .passive_max = 8 } });
    defer b.deinit();

    // Wire 1<->2 as active neighbours.
    a.freeRecv(try a.recv(2, .{ .neighbor = .{ .high_priority = true } }, 0));
    b.freeRecv(try b.recv(1, .{ .neighbor = .{ .high_priority = true } }, 0));
    try testing.expect(a.isActive(2));
    try testing.expect(b.isActive(1));

    // A already holds a message (seed it via an eager from a third party).
    const msg_id: u64 = 0xABCD;
    a.freeRecv(try a.recv(2, .{ .eager = .{ .msg_id = msg_id, .payload = "late" } }, 0));
    try testing.expect(a.hasMessage(msg_id));

    // B hears only the LAZY announcement: it lacks the body and must GRAFT.
    b.freeRecv(try b.recv(1, .{ .lazy = .{ .msg_id = msg_id } }, 0));
    try testing.expect(!b.hasMessage(msg_id));

    // Drive B's GRAFT timer, then shuttle messages until B delivers the body.
    var pending: std.ArrayList(SimMsg) = .empty;
    defer {
        for (pending.items) |m| if (m.env.msg == .eager) allocator.free(m.env.msg.eager.payload);
        pending.deinit(allocator);
    }
    {
        const graft = try b.tick(1);
        defer b.freeEnvelopes(graft);
        for (graft) |env| try pending.append(allocator, .{ .from = 2, .env = try dupEnv(allocator, env) });
    }

    var delivered = false;
    var now: i64 = 2;
    var round: usize = 0;
    while (pending.items.len > 0 and round < 100) : (round += 1) {
        now += 1;
        const m = pending.orderedRemove(0);
        defer if (m.env.msg == .eager) allocator.free(m.env.msg.eager.payload);
        const target: *Mesh = if (m.env.to == 1) &a else &b;
        const r = try target.recv(m.from, m.env.msg, now);
        defer target.freeRecv(r);
        if (m.env.to == 2 and r.delivered != null) delivered = true;
        for (r.envelopes) |env| try pending.append(allocator, .{ .from = m.env.to, .env = try dupEnv(allocator, env) });
    }
    try testing.expect(delivered);
    try testing.expect(b.hasMessage(msg_id));
}

test "Config.applyToml composite delegates to views/broadcaster/sazanami and rng_seed" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\rng_seed = 12345
        \\[mesh]
        \\rng_seed = 12345
        \\[mesh.gossip]
        \\active_view_max = 12
        \\graft_retry_ms = 500
        \\[mesh.sazanami]
        \\indirect_probes = 7
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 12), cfg.views.active_max);
    try std.testing.expectEqual(@as(i64, 500), cfg.broadcaster.graft_retry_ms);
    try std.testing.expectEqual(@as(usize, 7), cfg.sazanami.k);
    try std.testing.expectEqual(@as(u64, 12345), cfg.rng_seed);
}
