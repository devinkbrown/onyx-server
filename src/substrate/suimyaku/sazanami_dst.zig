// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic Ocean simulation for SAZANAMI witnessed failure detection.
//!
//! A multi-node cluster of `sazanami.Sazanami` detectors is driven over a seeded, virtual
//! transport with configurable loss and partitions. No sockets, no wall time, no
//! OS entropy: one master seed derives every per-node protocol RNG and the single
//! network RNG, so a failure replays byte-for-byte from `0x...`.
//!
//! The load-bearing invariant is SAZANAMI's safety property: **no node is ever
//! declared DEAD without a witness quorum**. A lone accuser cannot kill a peer;
//! only a quorum of independent witnesses can. Every `Declare(dead)` a detector
//! emits is checked to carry at least `quorum` witnesses, swept across a seed
//! campaign and under both a lossy link and a hard partition.
const std = @import("std");

const sazanami = @import("sazanami.zig");

const NodeId = sazanami.NodeId;
const Rng = sazanami.Rng;
const Action = sazanami.Action;
const State = sazanami.State;

/// Independent sub-stream derivation from one master seed (mirrors the
/// convergence harness so both DST suites share the same replay discipline).
fn deriveSeed(master_seed: u64, stream: u64) u64 {
    var x = master_seed +% 0x9e37_79b9_7f4a_7c15 +% (stream << 1);
    x = (x ^ (x >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    x = (x ^ (x >> 27)) *% 0x94d0_49bb_1331_11eb;
    return x ^ (x >> 31);
}

const WireKind = enum { ping, ack, ping_req, indirect_ping, declare };

const Wire = struct {
    due_ms: i64,
    seq: u64,
    kind: WireKind,
    from: NodeId,
    to: NodeId,
    subject: NodeId = 0, // ack: the node vouched alive
    target: NodeId = 0, // ping_req / indirect_ping subject
    origin: NodeId = 0, // indirect_ping: relay the ack back here
    declare: sazanami.Declare = undefined,
};

fn compareWire(_: void, a: Wire, b: Wire) std.math.Order {
    const due = std.math.order(a.due_ms, b.due_ms);
    if (due != .eq) return due;
    return std.math.order(a.seq, b.seq);
}

const WireQueue = std.PriorityQueue(Wire, void, compareWire);

const Config = struct {
    node_count: usize = 5,
    period_ms: i64 = 100,
    quorum: usize = 3,
    suspect_timeout_ms: i64 = 300,
    latency_ms: i64 = 10,
    jitter_ms: i64 = 5,
    drop_probability: f64 = 0.0,
    /// Index (0-based) of a node whose links are all severed for the whole run.
    isolated: ?usize = null,
};

/// Seed-replayable SAZANAMI cluster driver.
const Cluster = struct {
    allocator: std.mem.Allocator,
    seed: u64,
    cfg: Config,
    ids: std.ArrayList(NodeId) = .empty,
    nodes: std.ArrayList(sazanami.Sazanami) = .empty,
    rngs: std.ArrayList(Rng) = .empty,
    net_rng: Rng,
    queue: WireQueue,
    clock_ms: i64 = 0,
    next_seq: u64 = 0,

    // Invariant tracking.
    dead_declares: usize = 0,
    suspect_declares: usize = 0,
    solo_dead: bool = false,

    fn init(allocator: std.mem.Allocator, seed: u64, cfg: Config) !Cluster {
        var self = Cluster{
            .allocator = allocator,
            .seed = seed,
            .cfg = cfg,
            .net_rng = Rng.init(deriveSeed(seed, 0x9e7)),
            .queue = WireQueue.initContext({}),
        };
        errdefer self.deinit();

        const saz_cfg = sazanami.Config{
            .period_ms = cfg.period_ms,
            .quorum = cfg.quorum,
            .suspect_timeout_ms = cfg.suspect_timeout_ms,
        };

        var i: usize = 0;
        while (i < cfg.node_count) : (i += 1) {
            const id: NodeId = @intCast(i + 1); // NodeId 0 is invalid in sazanami.
            try self.ids.append(allocator, id);
            try self.nodes.append(allocator, try sazanami.Sazanami.init(allocator, id, saz_cfg));
            try self.rngs.append(allocator, Rng.init(deriveSeed(seed, id)));
        }

        // Bootstrap: every node starts knowing every peer is alive.
        for (self.ids.items, 0..) |_, a| {
            for (self.ids.items) |peer| {
                if (self.ids.items[a] == peer) continue;
                try self.nodes.items[a].onMembershipDelta(.{ .node = peer, .state = .alive }, 0);
            }
        }
        return self;
    }

    fn deinit(self: *Cluster) void {
        for (self.nodes.items) |*n| n.deinit();
        self.nodes.deinit(self.allocator);
        self.ids.deinit(self.allocator);
        self.rngs.deinit(self.allocator);
        self.queue.deinit(self.allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const Cluster, id: NodeId) ?usize {
        for (self.ids.items, 0..) |cand, idx| {
            if (cand == id) return idx;
        }
        return null;
    }

    fn isIsolated(self: *const Cluster, id: NodeId) bool {
        const victim = self.cfg.isolated orelse return false;
        return self.ids.items[victim] == id;
    }

    fn reachable(self: *const Cluster, id: NodeId) bool {
        return !self.isIsolated(id);
    }

    /// Enqueue a wire message unless the link is severed or the seeded drop hits.
    fn transmit(self: *Cluster, wire: Wire) !void {
        // A hard partition blocks every message that crosses the isolation line.
        if (self.isIsolated(wire.from) != self.isIsolated(wire.to)) return;
        if (self.net_rng.index(1_000_000) < @as(usize, @intFromFloat(self.cfg.drop_probability * 1_000_000.0))) return;

        var delay = self.cfg.latency_ms;
        if (self.cfg.jitter_ms > 0) delay += @intCast(self.net_rng.index(@intCast(self.cfg.jitter_ms + 1)));

        var out = wire;
        out.due_ms = self.clock_ms + delay;
        out.seq = self.next_seq;
        self.next_seq += 1;
        try self.queue.push(self.allocator, out);
    }

    /// The quorum the detector actually enforces. `sazanami.Config.sanitized` floors
    /// the quorum at 2, so a lone accuser can never kill a peer; mirror that here so
    /// the harness check is never looser than the detector it audits.
    fn effectiveQuorum(self: *const Cluster) usize {
        return @max(@as(usize, 2), self.cfg.quorum);
    }

    /// Single chokepoint for the DEAD-needs-quorum safety invariant. EVERY emitted
    /// `Declare` — whether flushed from a `tick` (via `dispatch`) or from an
    /// `onPingReq` reply relay — is funneled through here, so a future `sazanami.zig`
    /// regression that shipped a dead verdict without a witness quorum cannot slip
    /// past on the ping-req path.
    fn noteDeclare(self: *Cluster, from: NodeId, d: sazanami.Declare) void {
        switch (d.state) {
            .dead => {
                self.dead_declares += 1;
                if (d.witnesses.len < self.effectiveQuorum()) {
                    std.debug.print(
                        "SAZANAMI solo-DEAD seed=0x{x} declarer={d} node={d} witnesses={d} quorum={d}\n",
                        .{ self.seed, from, d.node, d.witnesses.len, self.effectiveQuorum() },
                    );
                    self.solo_dead = true;
                }
            },
            .suspect => self.suspect_declares += 1,
            .alive => {},
        }
    }

    /// Transport one node's emitted actions, enforcing the DEAD-needs-quorum
    /// invariant at the point of emission.
    fn dispatch(self: *Cluster, from: NodeId, actions: []const Action) !void {
        for (actions) |action| switch (action) {
            .Ping => |p| try self.transmit(.{
                .due_ms = 0,
                .seq = 0,
                .kind = .ping,
                .from = from,
                .to = p.target,
            }),
            .PingReq => |p| try self.transmit(.{
                .due_ms = 0,
                .seq = 0,
                .kind = .ping_req,
                .from = from,
                .to = p.via,
                .target = p.target,
            }),
            .Declare => |d| {
                self.noteDeclare(from, d);
                // Gossip the declare to every other node.
                for (self.ids.items) |peer| {
                    if (peer == from) continue;
                    try self.transmit(.{
                        .due_ms = 0,
                        .seq = 0,
                        .kind = .declare,
                        .from = from,
                        .to = peer,
                        .declare = d,
                    });
                }
            },
        };
    }

    fn deliver(self: *Cluster, wire: Wire) !void {
        switch (wire.kind) {
            .ping => {
                // Ping reached `to`; if reachable it acks the pinger.
                if (self.reachable(wire.to)) {
                    try self.transmit(.{
                        .due_ms = 0,
                        .seq = 0,
                        .kind = .ack,
                        .from = wire.to,
                        .to = wire.from,
                        .subject = wire.to,
                    });
                }
            },
            .ack => {
                if (self.indexOf(wire.to)) |idx| {
                    // Only error.InvalidNode is reachable here (subject is always a
                    // valid, distinct peer); nothing to recover, so drop it.
                    self.nodes.items[idx].onAck(wire.subject) catch {};
                }
            },
            .ping_req => {
                // `to` is the witness asked to probe `target` for `from`.
                if (self.indexOf(wire.to)) |via_idx| {
                    const acts = self.nodes.items[via_idx].onPingReq(wire.from, wire.target, self.clock_ms) catch return;
                    defer self.nodes.items[via_idx].freeActions(acts);
                    for (acts) |a| switch (a) {
                        .Ping => try self.transmit(.{
                            .due_ms = 0,
                            .seq = 0,
                            .kind = .indirect_ping,
                            .from = wire.to,
                            .to = wire.target,
                            .target = wire.target,
                            .origin = wire.from,
                        }),
                        .Declare => |d| {
                            // Same safety chokepoint as `dispatch`: a declare piggy-backed
                            // on an onPingReq reply must also carry a quorum if it is dead.
                            self.noteDeclare(wire.to, d);
                            try self.transmit(.{
                                .due_ms = 0,
                                .seq = 0,
                                .kind = .declare,
                                .from = wire.to,
                                .to = wire.from,
                                .declare = d,
                            });
                        },
                        .PingReq => unreachable, // onPingReq only returns Ping + Declare.
                    };
                }
            },
            .indirect_ping => {
                // Relay ack back to both the witness and the original prober.
                if (self.reachable(wire.to)) {
                    try self.transmit(.{
                        .due_ms = 0,
                        .seq = 0,
                        .kind = .ack,
                        .from = wire.to,
                        .to = wire.from,
                        .subject = wire.to,
                    });
                    try self.transmit(.{
                        .due_ms = 0,
                        .seq = 0,
                        .kind = .ack,
                        .from = wire.to,
                        .to = wire.origin,
                        .subject = wire.to,
                    });
                }
            },
            .declare => {
                if (self.indexOf(wire.to)) |idx| {
                    self.nodes.items[idx].onMembershipDelta(.{
                        .node = wire.declare.node,
                        .state = wire.declare.state,
                        .incarnation = wire.declare.incarnation,
                        .witnesses = wire.declare.witnesses.slice(),
                    }, self.clock_ms) catch {};
                }
            },
        }
    }

    fn drainUntil(self: *Cluster, horizon_ms: i64) !void {
        while (self.queue.peek()) |head| {
            if (head.due_ms > horizon_ms) break;
            const wire = self.queue.pop().?;
            if (wire.due_ms > self.clock_ms) self.clock_ms = wire.due_ms;
            try self.deliver(wire);
        }
    }

    fn run(self: *Cluster, total_ms: i64) !void {
        var t: i64 = 0;
        while (t <= total_ms) : (t += self.cfg.period_ms) {
            // Drain first so in-flight acks land (advancing the clock per-event to
            // their real due time), THEN pin the clock to the tick boundary. Pinning
            // before draining would compute follow-up acks from an inflated clock and
            // manufacture phantom probe timeouts.
            try self.drainUntil(t);
            if (t > self.clock_ms) self.clock_ms = t;
            for (self.ids.items, 0..) |id, idx| {
                const acts = try self.nodes.items[idx].tick(t, &self.rngs.items[idx]);
                defer self.nodes.items[idx].freeActions(acts);
                try self.dispatch(id, acts);
            }
        }
        // Flush anything still in flight so late deaths/refutations settle.
        try self.drainUntil(self.clock_ms + self.cfg.period_ms * 4);
        if (self.solo_dead) return error.SoloDeadWithoutQuorum;
    }

    fn status(self: *const Cluster, observer_idx: usize, subject_idx: usize) State {
        return self.nodes.items[observer_idx].status(self.ids.items[subject_idx]);
    }
};

const testing = std.testing;

test "Suimyaku SAZANAMI mesh never declares DEAD without a witness quorum under lossy links" {
    // Primary safety sweep: under a lossy (but connected) network the detector may
    // legitimately churn suspicions, yet no DEAD verdict may ever ship without a
    // quorum of witnesses backing it. Swept across a seed campaign.
    var s: u64 = 0;
    while (s < 128) : (s += 1) {
        const seed = 0x5a2a_0000 +% s;
        var cluster = try Cluster.init(testing.allocator, seed, .{
            .node_count = 5,
            .quorum = 3,
            .drop_probability = 0.30,
        });
        defer cluster.deinit();

        // `run` returns error.SoloDeadWithoutQuorum (after printing the seed) if
        // any DEAD declare carried fewer than `quorum` witnesses.
        try cluster.run(6000);
    }
}

test "Suimyaku SAZANAMI a fully-reachable cluster with no loss never suspects or kills a node" {
    // With zero loss and latency well under the probe period, every ping is acked
    // before its deadline: no node should ever be suspected, let alone declared
    // dead. Deterministic across the seed campaign.
    var s: u64 = 0;
    while (s < 64) : (s += 1) {
        const seed = 0x5a2a_a11e +% s;
        var cluster = try Cluster.init(testing.allocator, seed, .{
            .node_count = 5,
            .quorum = 3,
            .drop_probability = 0.0,
        });
        defer cluster.deinit();

        try cluster.run(4000);

        if (cluster.suspect_declares != 0 or cluster.dead_declares != 0) {
            std.debug.print(
                "SAZANAMI false liveness churn seed=0x{x} suspect={d} dead={d}\n",
                .{ seed, cluster.suspect_declares, cluster.dead_declares },
            );
            return error.FalseLivenessChurn;
        }
        for (cluster.ids.items, 0..) |_, observer| {
            for (cluster.ids.items, 0..) |_, subject| {
                if (observer == subject) continue;
                try testing.expectEqual(State.alive, cluster.status(observer, subject));
            }
        }
    }
}

test "Suimyaku SAZANAMI a hard-partitioned node is declared DEAD only on a witness quorum" {
    // The meaty case: sever node 0 entirely. Every reachable node keeps acking its
    // peers (no loss among them), so no reachable node may ever be declared dead;
    // meanwhile the isolated victim accrues independent witnesses until a quorum
    // forms and it is declared DEAD — carrying that quorum on every DEAD declare.
    var s: u64 = 0;
    while (s < 64) : (s += 1) {
        const seed = 0x5a2a_dead +% s;
        var cluster = try Cluster.init(testing.allocator, seed, .{
            .node_count = 5,
            .quorum = 3,
            .suspect_timeout_ms = 300,
            .drop_probability = 0.0,
            .isolated = 0,
        });
        defer cluster.deinit();

        try cluster.run(10_000); // returns SoloDead error if any dead lacked quorum

        // Reachable nodes (indices 1..) never falsely die at any reachable observer.
        for (cluster.ids.items, 0..) |_, observer| {
            if (observer == 0) continue;
            for (cluster.ids.items, 0..) |_, subject| {
                if (subject == 0 or subject == observer) continue;
                if (cluster.status(observer, subject) == .dead) {
                    std.debug.print(
                        "SAZANAMI false DEAD of reachable node seed=0x{x} observer={d} subject={d}\n",
                        .{ seed, observer + 1, subject + 1 },
                    );
                    return error.FalseDead;
                }
            }
        }

        // The isolated victim is actually detected dead by every reachable node.
        for (cluster.ids.items, 0..) |_, observer| {
            if (observer == 0) continue;
            if (cluster.status(observer, 0) != .dead) {
                std.debug.print(
                    "SAZANAMI isolated victim not detected seed=0x{x} observer={d} state={s}\n",
                    .{ seed, observer + 1, @tagName(cluster.status(observer, 0)) },
                );
                return error.VictimNotDetected;
            }
        }
        try testing.expect(cluster.dead_declares > 0);
    }
}

test "Suimyaku SAZANAMI partition detection replays byte-for-byte from its seed" {
    // A DST test must replay identically. Run the same partition program twice under
    // one seed and require identical detection statistics and final statuses.
    const seed = 0x5a2a_5eed_d57;
    const cfg = Config{
        .node_count = 5,
        .quorum = 3,
        .suspect_timeout_ms = 300,
        .drop_probability = 0.0,
        .isolated = 0,
    };

    var first = try Cluster.init(testing.allocator, seed, cfg);
    defer first.deinit();
    try first.run(10_000);

    var second = try Cluster.init(testing.allocator, seed, cfg);
    defer second.deinit();
    try second.run(10_000);

    try testing.expectEqual(first.dead_declares, second.dead_declares);
    try testing.expectEqual(first.suspect_declares, second.suspect_declares);
    for (first.ids.items, 0..) |_, observer| {
        for (first.ids.items, 0..) |_, subject| {
            try testing.expectEqual(
                first.status(observer, subject),
                second.status(observer, subject),
            );
        }
    }
}
