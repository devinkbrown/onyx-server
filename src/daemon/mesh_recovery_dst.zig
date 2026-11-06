// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! M08 deterministic fault campaign: recovery after node loss, partitions, and
//! clock skew.
//!
//! This is a seeded, I/O-free, test-only leaf. It composes the production
//! MESSAGE_V2 authorities exactly as the daemon orders them:
//!
//! * `relay_v2_replay_guard` (RVG2): read-only `probeMessage` first, then the
//!   mutating `admitMessage` only after every fallible reservation succeeded;
//! * `relay_v2_event_log` (RVL2): `prepareAccepted` / commit with the node's
//!   own required-membership snapshot (itself plus its configured direct
//!   neighbours), authenticated durable ACK confirmation, fair
//!   `collectPageForNode` anti-entropy, and explicit configured node
//!   retirement;
//! * `mesh_clock.MeshClock` for MESSAGE_V2 stamps plus the receiver
//!   future-skew deferral the live relay path applies before first admission;
//! * `clock.Hlc` and the `state.NetworkState` CRDTs (ban OR-set, presence and
//!   topic LWW registers, nick MV-register) merged with HLC receive folding.
//!
//! Unlike `undertow/convergence.zig`, whose anti-entropy is clique-wide and
//! omniscient, every packet here travels one hop along an explicitly
//! configured edge of a NON-CLIQUE topology (a line, a diamond, a 5-ring with a
//! chord). Accepted events flood onward on first acceptance; ACKs flow back
//! over the same edge; RVL2 repair pages travel the same lossy edges.
//!
//! A single master seed drives every fault stream through `deriveSeed(seed,
//! lane)` (the `convergence.zig` pattern): per-edge latency, jitter, drop,
//! duplication and reorder; workload choice; per-node keys. Per-node wall
//! clocks have offset, drift and scheduled step-backs/jumps. Partitions, crash
//! and restart, and permanent node loss are scripted. A BLAKE3 trace over every
//! delivery outcome plus each node's canonical checkpoints makes a whole
//! campaign byte-for-byte replayable from its seed.
//!
//! Admission is transactional: every allocation (queue capacity for ACK and
//! flood, published-history slot, pending-release slot and wire copy, RVL2
//! staged row) happens before RVG2 mutates, and nothing fallible follows RVG2
//! acceptance. Rejected, deferred, malformed and unauthorized inputs are
//! audited to leave the node byte-identical; duplicates may only touch RVL2
//! ingress exclusion and queue an ACK.
//!
//! Durability is a separate, explicit flush point. An accepted event first
//! becomes *pending*: RVG2/RVL2 are updated in volatile memory only. The
//! per-round group-commit `flushNode` encodes the live RVG2/RVL2 checkpoints
//! and MeshClock high water into the node's durable image, and only then
//! releases each pending event to local clients (the `published` history),
//! ACKs its sender, and floods it onward. A crash restores the LAST FLUSHED
//! image, never live state, and discards every pending event, so the window
//! between RVG2 admit and the durable flush is exercised. The scheduler runs
//! scripted crashes after a round's admissions and before its flush.
//! `MeshOptions.publish_before_flush` is a test-only mutation control that
//! restores the weaker publish/ACK/flood-at-admit order; the crash-window
//! regression test proves it violates exact-once.
//!
//! Modelled simplifications (explicit, not hidden): `published` is the
//! client-observed delivery log, so it never rolls back on crash; the CRDT
//! `NetworkState` and its HLC are write-through durable; the ACK_CONFIRM
//! receipt layer of `relay_v2_outbox` is not modelled; origin trust is the
//! static set of topology keys. The live daemon (`server.zig`) currently
//! carries RVG2/RVL2 across Helix handoff only and has no crash-durable
//! RVG2/RVL2 store, so the crash/restore lanes here specify the
//! flush-before-publish/ACK contract such a store must meet; they are not
//! evidence of production cold-crash recovery.

const std = @import("std");
const testing = std.testing;

const clock_mod = @import("../substrate/undertow/clock.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");
const message_relay_v2 = @import("../substrate/undertow/message_relay_v2.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");
const state_mod = @import("../substrate/undertow/state.zig");
const sign = @import("../crypto/sign.zig");
const event_log_mod = @import("relay_v2_event_log.zig");
const replay_guard = @import("relay_v2_replay_guard.zig");

const Allocator = std.mem.Allocator;
const Blake3 = std.crypto.hash.Blake3;
const Digest = [Blake3.digest_length]u8;
const Hlc = clock_mod.Hlc;
const MeshClock = mesh_clock.MeshClock;
const RelayId = message_relay_v2.RelayId;

/// Same splitmix64-derived stream split used by `undertow/convergence.zig`'s
/// private `deriveSeed`. Copied (that helper is private) so one master seed
/// deterministically drives every independent fault stream below.
fn deriveSeed(master_seed: u64, lane: u64) u64 {
    var x = master_seed +% 0x9e3779b97f4a7c15 +% (lane << 1);
    x = (x ^ (x >> 30)) *% 0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) *% 0x94d049bb133111eb;
    return x ^ (x >> 31);
}

fn seedBytes(seed: u64, lane: u64) [sign.seed_len]u8 {
    var out: [sign.seed_len]u8 = undefined;
    var filler = std.Random.Pcg.init(deriveSeed(seed, lane));
    filler.random().bytes(&out);
    return out;
}

fn hashU64(h: *Blake3, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    h.update(&bytes);
}

// ---------------------------------------------------------------------------
// Topology: explicit non-clique node/edge graphs.
// ---------------------------------------------------------------------------

const max_nodes: usize = 5;

const Edge = struct { a: u64, b: u64 };

const Topology = struct {
    name: []const u8,
    /// Ascending node ids.
    nodes: []const u64,
    edges: []const Edge,

    fn edgeIndexOf(self: *const Topology, a: u64, b: u64) ?usize {
        for (self.edges, 0..) |e, i| {
            if ((e.a == a and e.b == b) or (e.a == b and e.b == a)) return i;
        }
        return null;
    }

    fn neighborsInto(self: *const Topology, node: u64, buf: *[max_nodes]u64) []const u64 {
        var n: usize = 0;
        for (self.edges) |e| {
            const other = if (e.a == node) e.b else if (e.b == node) e.a else continue;
            buf[n] = other;
            n += 1;
        }
        return buf[0..n];
    }
};

/// Line A-B-C: no A-C edge. B is the only path between A and C.
const topology_line_abc = Topology{
    .name = "line A-B-C",
    .nodes = &.{ 1, 2, 3 },
    .edges = &.{ .{ .a = 1, .b = 2 }, .{ .a = 2, .b = 3 } },
};

/// Diamond A-{B,C}-D: A and D reach each other only through B or C. The two
/// arms of D are B-D and C-D.
const topology_diamond = Topology{
    .name = "diamond A-{B,C}-D",
    .nodes = &.{ 1, 2, 3, 4 },
    .edges = &.{ .{ .a = 1, .b = 2 }, .{ .a = 1, .b = 3 }, .{ .a = 2, .b = 4 }, .{ .a = 3, .b = 4 } },
};

/// 5-node ring with one chord (1-3): no single edge cut disconnects it.
const topology_ring_chord = Topology{
    .name = "5-ring+chord",
    .nodes = &.{ 1, 2, 3, 4, 5 },
    .edges = &.{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
        .{ .a = 3, .b = 4 },
        .{ .a = 4, .b = 5 },
        .{ .a = 5, .b = 1 },
        .{ .a = 1, .b = 3 },
    },
};

// ---------------------------------------------------------------------------
// Per-node skewed wall clock: true sim time + offset + drift + scheduled
// NTP-style step-backs/forward jumps, beneath `MeshClock` and `Hlc`.
// ---------------------------------------------------------------------------

const ClockStep = struct { at_round: usize, delta_ms: i64 };

const ClockSpec = struct {
    offset_ms: i64 = 0,
    drift_ppm: i64 = 0,
    steps: []const ClockStep = &.{},
};

const SkewedClock = struct {
    perceived_ms: i64,
    last_true_ms: u64,
    drift_ppm: i64,
    drift_remainder: i64 = 0,
    steps: []const ClockStep,
    next_step: usize = 0,
    mesh: MeshClock = .{},
    hlc: Hlc = .{},

    fn init(start_true_ms: u64, spec: ClockSpec) SkewedClock {
        return .{
            .perceived_ms = @as(i64, @intCast(start_true_ms)) + spec.offset_ms,
            .last_true_ms = start_true_ms,
            .drift_ppm = spec.drift_ppm,
            .steps = spec.steps,
        };
    }

    /// Advance to the new true simulated time, applying linear drift since the
    /// last advance and then every scheduled step due by `round`.
    fn advanceTo(self: *SkewedClock, true_ms: u64, round: usize) void {
        if (true_ms > self.last_true_ms) {
            const delta: i64 = @intCast(true_ms - self.last_true_ms);
            self.last_true_ms = true_ms;
            const drift_total = delta * self.drift_ppm + self.drift_remainder;
            const drift_ms = @divTrunc(drift_total, 1_000_000);
            self.drift_remainder = drift_total - drift_ms * 1_000_000;
            self.perceived_ms += delta + drift_ms;
        }
        while (self.next_step < self.steps.len and self.steps[self.next_step].at_round <= round) {
            self.perceived_ms += self.steps[self.next_step].delta_ms;
            self.next_step += 1;
        }
    }

    fn nowMs(self: *const SkewedClock) u64 {
        return if (self.perceived_ms < 0) 0 else @intCast(self.perceived_ms);
    }
};

// ---------------------------------------------------------------------------
// Seeded virtual network: per-edge latency/jitter/drop/duplication/reorder.
// ---------------------------------------------------------------------------

const FaultProfile = struct {
    latency_ms: u64 = 2,
    jitter_ms: u64 = 3,
    drop_probability: f64 = 0.12,
    dup_probability: f64 = 0.08,
    reorder_probability: f64 = 0.15,
    reorder_extra_ms: u64 = 12,
};

const reliable_profile = FaultProfile{
    .latency_ms = 1,
    .jitter_ms = 0,
    .drop_probability = 0,
    .dup_probability = 0,
    .reorder_probability = 0,
    .reorder_extra_ms = 0,
};

const max_wire_len: usize = 1536;

const PacketKind = enum(u8) { relay, ack };

const Packet = struct {
    kind: PacketKind,
    from: u64,
    to: u64,
    /// Endpoint incarnations at send time. A crash or loss bumps the node's
    /// incarnation, so every in-flight packet of the old process dies.
    from_incarnation: u32,
    to_incarnation: u32,
    relay_id: RelayId,
    len: u16,
    bytes: [max_wire_len]u8 = undefined,
};

const QueuedPacket = struct {
    due_ms: u64,
    seq: u64,
    packet: Packet,
};

fn comparePackets(_: void, a: QueuedPacket, b: QueuedPacket) std.math.Order {
    const order = std.math.order(a.due_ms, b.due_ms);
    if (order != .eq) return order;
    return std.math.order(a.seq, b.seq);
}

const PacketQueue = std.PriorityQueue(QueuedPacket, void, comparePackets);

// ---------------------------------------------------------------------------
// Per-node authority bundle.
// ---------------------------------------------------------------------------

/// The window exceeds every campaign's per-origin event count, so RVG2's
/// greatest-W retirement never discards a legitimately delayed event here.
const guard_config = replay_guard.Config{ .window_size = 64, .max_origins = 16 };
const log_config = event_log_mod.Config{
    .max_rows = 256,
    .max_confirmed_nodes_per_row = 8,
    .max_cursor_nodes = 8,
    .max_wire_bytes = max_wire_len,
    .max_aggregate_bytes = 1 << 20,
};
const page_len: usize = 2;
const default_start_ms: u64 = 1_700_000_000_000;
const relay_target = "#dst-mesh";
const nick_authority: state_mod.Authority = 10;
const uid_texts = [max_nodes][]const u8{ "001AAAAAA", "002BBBBBB", "003CCCCCC", "004DDDDDD", "005EEEEEE" };

const Published = std.AutoArrayHashMapUnmanaged(RelayId, []u8);

const NodeStats = struct {
    accepted: usize = 0,
    duplicate: usize = 0,
    deferred: usize = 0,
    rejected: usize = 0,
    unauthorized: usize = 0,
    malformed: usize = 0,
    acks_applied: usize = 0,
    /// Accepted events still pending when the node crashed: RVG2 admitted
    /// them in volatile memory but they were never flushed nor released.
    unflushed_lost: usize = 0,
};

/// One accepted event awaiting the durable flush that releases it.
const PendingRelease = struct {
    relay_id: RelayId,
    /// Null for local authorship.
    sender: ?u64,
    hlc: u64,
    /// Owned canonical wire; moves into `published` on release.
    wire: []u8,
};

/// Last flushed durable process image: the canonical RVG2 and RVL2
/// checkpoints plus the restart-persistent MeshClock high water, all captured
/// by one `flushNode`. `crdt_hlc` belongs to the write-through CRDT store and
/// is refreshed at crash.
const DurableImage = struct {
    guard: []u8,
    log: []u8,
    mesh_high_water: u64,
    crdt_hlc: Hlc,

    fn clone(self: *const DurableImage, allocator: Allocator) !DurableImage {
        const guard = try allocator.dupe(u8, self.guard);
        errdefer allocator.free(guard);
        return .{
            .guard = guard,
            .log = try allocator.dupe(u8, self.log),
            .mesh_high_water = self.mesh_high_water,
            .crdt_hlc = self.crdt_hlc,
        };
    }

    fn deinit(self: *DurableImage, allocator: Allocator) void {
        allocator.free(self.guard);
        allocator.free(self.log);
        self.* = undefined;
    }
};

const Node = struct {
    id: u64,
    keypair: sign.KeyPair,
    clock: SkewedClock,
    guard: replay_guard.Guard,
    log: event_log_mod.EventLog,
    state: state_mod.NetworkState,
    /// Exactly-once client-observed delivery log: RelayId -> canonical wire,
    /// in release order. Never rolled back by a crash. A second insert for
    /// one id is an `ExactOnceViolation`.
    published: Published = .empty,
    /// Accepted-but-unflushed events, in admission order. Volatile.
    pending: std.ArrayList(PendingRelease) = .empty,
    /// Sorted RVL2 required-membership snapshot: self plus configured direct
    /// neighbours, minus explicitly retired nodes.
    required_buf: [max_nodes]u64 = undefined,
    required_len: usize = 0,
    alive: bool = true,
    lost: bool = false,
    incarnation: u32 = 0,
    local_seq: u64 = 0,
    last_authored_hlc: u64 = 0,
    /// Greatest own stamp ever released. A crash rolls `last_authored_hlc`
    /// back to it: unreleased own stamps never escaped the process.
    released_authored_hlc: u64 = 0,
    last_crdt_hlc: Hlc = .{},
    flushed: DurableImage,
    stats: NodeStats = .{},

    fn pendingIndexOf(self: *const Node, relay_id: RelayId) ?usize {
        for (self.pending.items, 0..) |entry, i| {
            if (std.mem.eql(u8, &entry.relay_id, &relay_id)) return i;
        }
        return null;
    }

    fn dropPending(self: *Node, allocator: Allocator) void {
        for (self.pending.items) |entry| allocator.free(entry.wire);
        self.pending.clearRetainingCapacity();
    }

    fn required(self: *const Node) []const u64 {
        return self.required_buf[0..self.required_len];
    }

    fn requires(self: *const Node, id: u64) bool {
        return std.mem.indexOfScalar(u64, self.required(), id) != null;
    }

    fn isSurvivor(self: *const Node) bool {
        return self.alive and !self.lost;
    }

    fn deinit(self: *Node, allocator: Allocator) void {
        for (self.published.values()) |wire| allocator.free(wire);
        self.published.deinit(allocator);
        self.dropPending(allocator);
        self.pending.deinit(allocator);
        self.flushed.deinit(allocator);
        self.keypair.deinit();
        self.guard.deinit();
        self.log.deinit();
        self.state.deinit();
        self.* = undefined;
    }
};

const ScriptAction = union(enum) {
    cut: [2]u64,
    heal: [2]u64,
    crash: u64,
    restore: u64,
};

const ScriptEntry = struct { at_round: usize, action: ScriptAction };

const RunParams = struct {
    rounds: usize,
    author_probability: f64 = 0.4,
    max_authored: usize = 12,
    crdt_probability: f64 = 0,
    repair_every: usize = 2,
    merge_every: usize = 3,
    script: []const ScriptEntry = &.{},
};

const MeshOptions = struct {
    clock_specs: []const ClockSpec = &.{},
    future_skew_bound_ms: u64 = mesh_clock.default_max_future_skew_ms,
    tick_ms: u64 = 3,
    fault: FaultProfile = .{},
    /// Snapshot node state around every admission and fail when a
    /// non-accepting outcome mutated it. Disabled only for allocation sweeps.
    audit_rejections: bool = true,
    /// Mutation control only: release (publish, ACK, flood) at RVG2 admit,
    /// before the durable flush. Exact-once must then fail across a crash.
    publish_before_flush: bool = false,
};

const Outcome = enum(u8) { accepted, duplicate, deferred, rejected, unauthorized, malformed };

const CrdtKind = enum(u8) { topic, nick };

const CrdtWrite = struct {
    kind: CrdtKind,
    node_index: usize,
    stamp: u64,
    round: usize,
};

// ---------------------------------------------------------------------------
// Mesh harness.
// ---------------------------------------------------------------------------

/// One seeded, I/O-free deterministic fault-campaign mesh over a fixed
/// non-clique `Topology`.
const Mesh = struct {
    allocator: Allocator,
    seed: u64,
    topo: *const Topology,
    nodes: []Node,
    edge_cut: []bool,
    net_prng: std.Random.Pcg,
    wl_prng: std.Random.Pcg,
    fault: FaultProfile,
    tick_ms: u64,
    future_skew_bound_ms: u64,
    audit_rejections: bool,
    publish_before_flush: bool,
    true_ms: u64 = default_start_ms,
    round: usize = 0,
    next_seq: u64 = 0,
    queue: PacketQueue,
    trace: Blake3,
    authored: std.ArrayList(RelayId) = .empty,
    crdt_writes: std.ArrayList(CrdtWrite) = .empty,
    packets_sent: usize = 0,
    packets_dropped: usize = 0,
    packets_duplicated: usize = 0,
    packets_lost_in_flight: usize = 0,

    fn init(allocator: Allocator, seed: u64, topo: *const Topology, options: MeshOptions) !Mesh {
        std.debug.assert(topo.nodes.len <= max_nodes);
        std.debug.assert(options.clock_specs.len == 0 or options.clock_specs.len == topo.nodes.len);

        const nodes = try allocator.alloc(Node, topo.nodes.len);
        errdefer allocator.free(nodes);
        var built: usize = 0;
        errdefer for (nodes[0..built]) |*n| n.deinit(allocator);
        while (built < topo.nodes.len) : (built += 1) {
            const spec: ClockSpec = if (options.clock_specs.len == 0) .{} else options.clock_specs[built];
            nodes[built] = try initNode(allocator, seed, topo, built, spec);
        }

        const edge_cut = try allocator.alloc(bool, topo.edges.len);
        @memset(edge_cut, false);

        return .{
            .allocator = allocator,
            .seed = seed,
            .topo = topo,
            .nodes = nodes,
            .edge_cut = edge_cut,
            .net_prng = std.Random.Pcg.init(deriveSeed(seed, 1)),
            .wl_prng = std.Random.Pcg.init(deriveSeed(seed, 2)),
            .fault = options.fault,
            .tick_ms = options.tick_ms,
            .future_skew_bound_ms = options.future_skew_bound_ms,
            .audit_rejections = options.audit_rejections,
            .publish_before_flush = options.publish_before_flush,
            .queue = PacketQueue.initContext({}),
            .trace = Blake3.init(.{}),
        };
    }

    fn initNode(allocator: Allocator, seed: u64, topo: *const Topology, index: usize, spec: ClockSpec) !Node {
        const id = topo.nodes[index];
        var keypair = try sign.KeyPair.fromSeed(seedBytes(seed, 0x5eed_0000 + index));
        errdefer keypair.deinit();
        var guard = try replay_guard.Guard.init(allocator, guard_config);
        errdefer guard.deinit();
        var log = try event_log_mod.EventLog.init(allocator, log_config);
        errdefer log.deinit();
        // The initial durable image is the empty authority a fresh node
        // would flush at first start.
        const guard_bytes = try guard.encodeCheckpoint(allocator);
        errdefer allocator.free(guard_bytes);
        const log_bytes = try log.encodeCheckpoint(allocator);
        var node = Node{
            .id = id,
            .keypair = keypair,
            .clock = SkewedClock.init(default_start_ms, spec),
            .guard = guard,
            .log = log,
            .state = state_mod.NetworkState.init(allocator, id, id),
            .flushed = .{ .guard = guard_bytes, .log = log_bytes, .mesh_high_water = 0, .crdt_hlc = .{} },
        };
        var neighbor_buf: [max_nodes]u64 = undefined;
        const neighbors = topo.neighborsInto(id, &neighbor_buf);
        std.debug.assert(neighbors.len + 1 <= max_nodes);
        node.required_buf[0] = id;
        @memcpy(node.required_buf[1..][0..neighbors.len], neighbors);
        node.required_len = neighbors.len + 1;
        std.mem.sort(u64, node.required_buf[0..node.required_len], {}, std.sort.asc(u64));
        return node;
    }

    fn deinit(self: *Mesh) void {
        self.queue.deinit(self.allocator);
        self.authored.deinit(self.allocator);
        self.crdt_writes.deinit(self.allocator);
        for (self.nodes) |*n| n.deinit(self.allocator);
        self.allocator.free(self.nodes);
        self.allocator.free(self.edge_cut);
        self.* = undefined;
    }

    fn nodeIndexOf(self: *const Mesh, id: u64) usize {
        for (self.nodes, 0..) |n, i| if (n.id == id) return i;
        unreachable; // harness ids always come from the topology
    }

    fn nodeById(self: *Mesh, id: u64) *Node {
        return &self.nodes[self.nodeIndexOf(id)];
    }

    fn isEdgeLive(self: *const Mesh, a: u64, b: u64) bool {
        const i = self.topo.edgeIndexOf(a, b) orelse return false;
        return !self.edge_cut[i];
    }

    fn setEdge(self: *Mesh, a: u64, b: u64, live: bool) void {
        self.edge_cut[self.topo.edgeIndexOf(a, b).?] = !live;
        self.traceEvent(if (live) 'H' else 'X', a, b, null);
    }

    fn traceEvent(self: *Mesh, tag: u8, a: u64, b: u64, relay_id: ?RelayId) void {
        hashU64(&self.trace, self.round);
        self.trace.update(&.{tag});
        hashU64(&self.trace, a);
        hashU64(&self.trace, b);
        if (relay_id) |id| self.trace.update(&id);
    }

    fn originTrusted(self: *const Mesh, origin_pubkey: []const u8) bool {
        for (self.nodes) |n| {
            if (std.mem.eql(u8, &n.keypair.public_key, origin_pubkey)) return true;
        }
        return false;
    }

    // -- network -------------------------------------------------------------

    /// Queue slots one admission may need: each neighbour flood plus one ACK,
    /// each possibly duplicated by the fault model.
    fn sendSlots(self: *const Mesh, node_id: u64) usize {
        var buf: [max_nodes]u64 = undefined;
        return (self.topo.neighborsInto(node_id, &buf).len + 1) * 2;
    }

    /// Queue one packet into capacity the caller already reserved, so this is
    /// infallible and may run after a commit point. A cut edge or a dead
    /// endpoint means no link exists, so nothing is queued.
    fn sendReserved(
        self: *Mesh,
        from: *const Node,
        to_id: u64,
        kind: PacketKind,
        relay_id: RelayId,
        wire: []const u8,
    ) void {
        std.debug.assert(wire.len <= max_wire_len);
        const to = &self.nodes[self.nodeIndexOf(to_id)];
        if (!from.alive or !to.alive or !self.isEdgeLive(from.id, to_id)) return;
        const f = self.fault;
        const random = self.net_prng.random();
        self.packets_sent += 1;
        if (f.drop_probability > 0 and random.float(f64) < f.drop_probability) {
            self.packets_dropped += 1;
            return;
        }
        var delay: u64 = @max(f.latency_ms, 1);
        if (f.jitter_ms > 0) delay += random.intRangeAtMost(u64, 0, f.jitter_ms);
        if (f.reorder_probability > 0 and random.float(f64) < f.reorder_probability)
            delay += random.intRangeAtMost(u64, 1, @max(f.reorder_extra_ms, 1));
        const copies: usize = if (f.dup_probability > 0 and random.float(f64) < f.dup_probability) 2 else 1;
        if (copies == 2) self.packets_duplicated += 1;

        var packet = Packet{
            .kind = kind,
            .from = from.id,
            .to = to_id,
            .from_incarnation = from.incarnation,
            .to_incarnation = to.incarnation,
            .relay_id = relay_id,
            .len = @intCast(wire.len),
        };
        @memcpy(packet.bytes[0..wire.len], wire);
        for (0..copies) |copy| {
            std.debug.assert(self.queue.count() < self.queue.capacity());
            const extra: u64 = if (copy == 0) 0 else random.intRangeAtMost(u64, 0, f.jitter_ms + f.reorder_extra_ms);
            self.queue.push(self.allocator, .{
                .due_ms = self.true_ms + delay + extra,
                .seq = self.next_seq,
                .packet = packet,
            }) catch unreachable; // capacity reserved by the caller
            self.next_seq += 1;
        }
    }

    fn floodReserved(self: *Mesh, from: *const Node, except: ?u64, relay_id: RelayId, wire: []const u8) void {
        var buf: [max_nodes]u64 = undefined;
        for (self.topo.neighborsInto(from.id, &buf)) |peer| {
            if (except) |skip| if (peer == skip) continue;
            self.sendReserved(from, peer, .relay, relay_id, wire);
        }
    }

    // -- admission -------------------------------------------------------------

    /// One MESSAGE_V2 admission at `index`, received from `sender` (null for
    /// local authorship). Order mirrors the daemon: strict decode, read-only
    /// RVG2 probe, origin trust, future-skew deferral, all reservations, RVL2
    /// prepare, RVG2 admit, then an infallible commit that queues the event
    /// for release by the next durable flush.
    fn admitAt(self: *Mesh, index: usize, sender: ?u64, wire: []const u8) !Outcome {
        const node = &self.nodes[index];
        std.debug.assert(node.alive);
        if (wire.len == 0 or wire.len > max_wire_len) return .malformed;
        var owned = message_relay_v2.decode(self.allocator, wire) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .malformed,
        };
        defer owned.deinit(self.allocator);

        const relay_id = switch (try node.guard.probeMessage(owned.msg)) {
            .unseen => |id| id,
            .duplicate => |id| return self.admitDuplicate(index, sender, id, wire),
            .equivocation, .retired, .origin_mismatch, .bad_signature, .invalid_semantic => return .rejected,
        };
        if (!self.originTrusted(owned.msg.origin_pubkey)) return .unauthorized;

        const now_ms = node.clock.nowMs();
        const latest_physical = std.math.add(u64, now_ms, self.future_skew_bound_ms) catch std.math.maxInt(u64);
        if (MeshClock.physicalOf(owned.msg.hlc) > latest_physical) return .deferred;
        var staged_clock = node.clock.mesh;
        staged_clock.observeChecked(owned.msg.hlc, now_ms, self.future_skew_bound_ms) catch return .rejected;
        // RVG2 has never seen this id; a published copy would mean replay
        // authority was lost (for example a stale checkpoint).
        if (node.published.contains(relay_id)) return error.ExactOnceViolation;

        try self.queue.ensureUnusedCapacity(self.allocator, self.sendSlots(node.id));
        try node.published.ensureUnusedCapacity(self.allocator, 1);
        try node.pending.ensureUnusedCapacity(self.allocator, 1);
        var wire_copy: ?[]u8 = try self.allocator.dupe(u8, wire);
        defer if (wire_copy) |bytes| self.allocator.free(bytes);

        const prepare_result = node.log.prepareAccepted(relay_id, wire, node.id, sender, node.required()) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .rejected,
        };
        var prepared = switch (prepare_result) {
            .ready => |plan| plan,
            .conflict => return .rejected,
        };
        defer prepared.deinit();
        if (prepared.outcome() != .inserted) return .rejected;

        switch (try node.guard.admitMessage(owned.msg)) {
            .accepted => |id| std.debug.assert(std.mem.eql(u8, &id, &relay_id)),
            else => return .rejected,
        }

        // Commit point: nothing below can fail. Publication, ACK and flood
        // wait for the durable flush unless the mutation control is set.
        _ = prepared.commit();
        node.clock.mesh = staged_clock;
        const entry = PendingRelease{ .relay_id = relay_id, .sender = sender, .hlc = owned.msg.hlc, .wire = wire_copy.? };
        wire_copy = null;
        if (self.publish_before_flush) {
            self.release(node, entry);
        } else {
            node.pending.appendAssumeCapacity(entry);
        }
        return .accepted;
    }

    /// Release one durably flushed event: client publication, sender ACK and
    /// onward flood, all into capacity reserved by the caller.
    fn release(self: *Mesh, node: *Node, entry: PendingRelease) void {
        node.published.putAssumeCapacityNoClobber(entry.relay_id, entry.wire);
        if (entry.sender) |peer| {
            self.sendReserved(node, peer, .ack, entry.relay_id, &.{});
        } else {
            node.released_authored_hlc = @max(node.released_authored_hlc, entry.hlc);
        }
        self.floodReserved(node, entry.sender, entry.relay_id, entry.wire);
    }

    /// Durable group commit: encode the live RVG2/RVL2 checkpoints and the
    /// MeshClock high water, then release every pending event. Every fallible
    /// step (encoding, queue and history capacity, exact-once check) precedes
    /// the image swap; nothing fallible follows it.
    fn flushNode(self: *Mesh, index: usize) !void {
        const node = &self.nodes[index];
        std.debug.assert(node.alive);
        const pending = node.pending.items;
        for (pending) |entry| {
            if (node.published.contains(entry.relay_id)) return error.ExactOnceViolation;
        }
        try self.queue.ensureUnusedCapacity(self.allocator, self.sendSlots(node.id) * pending.len);
        try node.published.ensureUnusedCapacity(self.allocator, pending.len);
        const guard_bytes = try node.guard.encodeCheckpoint(self.allocator);
        errdefer self.allocator.free(guard_bytes);
        const log_bytes = try node.log.encodeCheckpoint(self.allocator);

        // Durable point: the image now covers every pending event.
        node.flushed.deinit(self.allocator);
        node.flushed = .{
            .guard = guard_bytes,
            .log = log_bytes,
            .mesh_high_water = node.clock.mesh.last_stamp,
            .crdt_hlc = node.clock.hlc,
        };
        for (pending) |entry| self.release(node, entry);
        node.pending.clearRetainingCapacity();
        if (pending.len != 0) self.traceEvent('F', node.id, pending.len, null);
    }

    fn flushAll(self: *Mesh) !void {
        for (self.nodes, 0..) |node, i| {
            if (node.alive) try self.flushNode(i);
        }
    }

    /// RVG2 proves prior acceptance: re-ACK the sender and record its ingress
    /// as a one-sweep RVL2 exclusion. Never republishes. An id accepted but
    /// not yet flushed is not durable, so it is neither ACKed nor recorded;
    /// the sender keeps its row and repairs again after the flush.
    fn admitDuplicate(self: *Mesh, index: usize, sender: ?u64, relay_id: RelayId, wire: []const u8) !Outcome {
        const node = &self.nodes[index];
        if (node.pendingIndexOf(relay_id) != null) return .duplicate;
        if (!node.published.contains(relay_id)) return error.ExactOnceViolation;
        const peer = sender orelse return .rejected;
        try self.queue.ensureUnusedCapacity(self.allocator, 2);
        if (node.log.contains(relay_id)) {
            const prepare_result = node.log.prepareAccepted(relay_id, wire, node.id, peer, node.required()) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .rejected,
            };
            var prepared = switch (prepare_result) {
                .ready => |plan| plan,
                .conflict => return .rejected,
            };
            defer prepared.deinit();
            _ = prepared.commit();
        }
        self.sendReserved(node, peer, .ack, relay_id, &.{});
        return .duplicate;
    }

    /// `admitAt` plus the mutation audit, stats, and trace.
    fn admitAudited(self: *Mesh, index: usize, sender: ?u64, wire: []const u8, relay_hint: ?RelayId) !Outcome {
        var before_core: Digest = undefined;
        var before_full: Digest = undefined;
        if (self.audit_rejections) {
            before_core = try self.nodeDigest(self.allocator, index, false);
            before_full = try self.nodeDigest(self.allocator, index, true);
        }
        const outcome = try self.admitAt(index, sender, wire);
        if (self.audit_rejections) switch (outcome) {
            .accepted => {},
            .duplicate => {
                const after = try self.nodeDigest(self.allocator, index, false);
                if (!std.mem.eql(u8, &before_core, &after)) return error.DuplicateMutatedAuthority;
            },
            .deferred, .rejected, .unauthorized, .malformed => {
                const after = try self.nodeDigest(self.allocator, index, true);
                if (!std.mem.eql(u8, &before_full, &after)) return error.RejectedAdmissionMutated;
            },
        };
        const stats = &self.nodes[index].stats;
        switch (outcome) {
            .accepted => stats.accepted += 1,
            .duplicate => stats.duplicate += 1,
            .deferred => stats.deferred += 1,
            .rejected => stats.rejected += 1,
            .unauthorized => stats.unauthorized += 1,
            .malformed => stats.malformed += 1,
        }
        self.traceEvent('A' + @backingInt(outcome), self.nodes[index].id, sender orelse 0, relay_hint);
        return outcome;
    }

    /// Inject one wire at `index` as if received over the edge from `from_id`,
    /// always audited.
    fn inject(self: *Mesh, index: usize, from_id: u64, wire: []const u8) !Outcome {
        const saved = self.audit_rejections;
        self.audit_rejections = true;
        defer self.audit_rejections = saved;
        return self.admitAudited(index, from_id, wire, null);
    }

    /// Author one MESSAGE_V2 event at `index`. The MeshClock is stamped on a
    /// staged copy; clock, sequence and authored list advance only when the
    /// local admission commits.
    fn authorAt(self: *Mesh, index: usize, text: []const u8) !RelayId {
        const node = &self.nodes[index];
        if (!node.isSurvivor()) return error.NodeDown;
        var staged = node.clock.mesh;
        const seq = node.local_seq + 1;
        const hlc = staged.stamp(node.clock.nowMs(), seq);
        if (hlc <= node.last_authored_hlc) return error.ClockRegression;
        var prefix_buf: [48]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "node{d}!u@dst.test", .{node.id});
        const wire = try makeWire(self.allocator, &node.keypair, hlc, prefix, text);
        defer self.allocator.free(wire.bytes);
        try self.authored.ensureUnusedCapacity(self.allocator, 1);
        if (try self.admitAudited(index, null, wire.bytes, wire.id) != .accepted)
            return error.LocalAuthorshipRejected;
        node.local_seq = seq;
        node.last_authored_hlc = hlc;
        self.authored.appendAssumeCapacity(wire.id);
        return wire.id;
    }

    /// Authenticated direct-neighbour durable ACK. A row already retired, or a
    /// node no longer required after configured retirement, is a no-op.
    fn applyAck(self: *Mesh, index: usize, from_id: u64, relay_id: RelayId) !void {
        const node = &self.nodes[index];
        self.traceEvent('K', node.id, from_id, relay_id);
        if (!node.log.contains(relay_id)) return;
        var plan = node.log.prepareAuthenticatedDurableAck(relay_id, from_id) catch |err| switch (err) {
            error.NodeNotRequired => return,
            else => return err,
        };
        defer plan.deinit();
        _ = plan.commit();
        node.stats.acks_applied += 1;
    }

    fn deliver(self: *Mesh, packet: *const Packet) !void {
        const to_index = self.nodeIndexOf(packet.to);
        const to = &self.nodes[to_index];
        const from = &self.nodes[self.nodeIndexOf(packet.from)];
        if (!to.alive or to.incarnation != packet.to_incarnation or
            from.incarnation != packet.from_incarnation or !self.isEdgeLive(packet.from, packet.to))
        {
            self.packets_lost_in_flight += 1;
            self.traceEvent('L', packet.from, packet.to, packet.relay_id);
            return;
        }
        switch (packet.kind) {
            .relay => _ = try self.admitAudited(to_index, packet.from, packet.bytes[0..packet.len], packet.relay_id),
            .ack => try self.applyAck(to_index, packet.from, packet.relay_id),
        }
    }

    fn deliverDue(self: *Mesh) !void {
        while (self.queue.peek()) |head| {
            if (head.due_ms > self.true_ms) break;
            const item = self.queue.pop().?;
            try self.deliver(&item.packet);
        }
    }

    /// RVL2 anti-entropy along every live edge. Each node pages what each
    /// required live neighbour has not durably confirmed and sends it over the
    /// same lossy edge.
    fn repairRound(self: *Mesh) !void {
        for (self.nodes) |*node| {
            if (!node.alive) continue;
            // Repair runs after the round's flush: an unflushed row is never
            // paged out.
            std.debug.assert(node.pending.items.len == 0);
            var neighbor_buf: [max_nodes]u64 = undefined;
            for (self.topo.neighborsInto(node.id, &neighbor_buf)) |peer| {
                if (!self.isEdgeLive(node.id, peer) or !self.nodeById(peer).alive) continue;
                if (!node.requires(peer)) continue;
                try self.queue.ensureUnusedCapacity(self.allocator, page_len * 2);
                var page: [page_len]event_log_mod.PageItem = undefined;
                const count = try node.log.collectPageForNode(peer, &page);
                for (page[0..count]) |item| self.sendReserved(node, peer, .relay, item.relay_id, item.wire);
                if (count != 0) self.traceEvent('R', node.id, peer, null);
            }
        }
    }

    // -- CRDT lane ---------------------------------------------------------------

    fn crdtMergeRound(self: *Mesh) !void {
        for (self.topo.edges, 0..) |edge, edge_index| {
            if (self.edge_cut[edge_index]) continue;
            const a = self.nodeById(edge.a);
            const b = self.nodeById(edge.b);
            if (!a.alive or !b.alive) continue;
            try mergeInto(a, b);
            try mergeInto(b, a);
        }
    }

    /// Full-state exchange with HLC receive folding, so a later local write is
    /// causally newer than everything merged, whatever the skew.
    fn mergeInto(dst: *Node, src: *const Node) !void {
        try dst.state.merge(&src.state);
        _ = try dst.clock.hlc.recv(dst.clock.nowMs(), src.clock.hlc);
    }

    fn crdtWrite(self: *Mesh, index: usize, kind: CrdtKind) !Hlc {
        const node = &self.nodes[index];
        if (!node.isSurvivor()) return error.NodeDown;
        try self.crdt_writes.ensureUnusedCapacity(self.allocator, 1);
        var staged = node.clock.hlc;
        const stamp = try staged.now(node.clock.nowMs());
        if (Hlc.compare(node.last_crdt_hlc, stamp) != .lt) return error.ClockRegression;
        const uid = try state_mod.Uid.init(uid_texts[index]);
        switch (kind) {
            .topic => {
                var text_buf: [48]u8 = undefined;
                const text = try std.fmt.bufPrint(&text_buf, "topic {d}/{d}", .{ node.id, self.crdt_writes.items.len });
                try node.state.setTopic(try crdtChannel(), try state_mod.TopicText.init(text), uid, stamp);
            },
            .nick => try node.state.claimNick(try contestedNick(), uid, nick_authority, stamp),
        }
        node.clock.hlc = staged;
        node.last_crdt_hlc = stamp;
        self.crdt_writes.appendAssumeCapacity(.{ .kind = kind, .node_index = index, .stamp = stamp.toU64(), .round = self.round });
        self.traceEvent('C', node.id, stamp.toU64(), null);
        return stamp;
    }

    // -- crash, restore, loss ------------------------------------------------------

    /// Process crash: the last flushed image is all that survives. Every
    /// pending (accepted, unflushed) event is discarded: it was never
    /// published, ACKed or forwarded, and a lost local authorship leaves the
    /// authored set. Volatile authority is dropped and every in-flight packet
    /// of this incarnation dies. Only the fresh-authority allocation is
    /// fallible, and it precedes every mutation.
    fn crashNode(self: *Mesh, id: u64) !void {
        const node = self.nodeById(id);
        if (!node.isSurvivor()) return error.NodeDown;
        var fresh_guard = try replay_guard.Guard.init(self.allocator, guard_config);
        errdefer fresh_guard.deinit();
        const fresh_log = try event_log_mod.EventLog.init(self.allocator, log_config);

        for (node.pending.items) |entry| {
            if (entry.sender != null) continue;
            for (self.authored.items, 0..) |authored_id, i| {
                if (!std.mem.eql(u8, &authored_id, &entry.relay_id)) continue;
                _ = self.authored.orderedRemove(i);
                break;
            }
        }
        node.stats.unflushed_lost += node.pending.items.len;
        node.dropPending(self.allocator);
        node.last_authored_hlc = node.released_authored_hlc;
        node.flushed.crdt_hlc = node.clock.hlc;
        node.guard.deinit();
        node.guard = fresh_guard;
        node.log.deinit();
        node.log = fresh_log;
        node.clock.mesh = .{};
        node.clock.hlc = .{};
        node.alive = false;
        node.incarnation +%= 1;
        self.traceEvent('D', id, node.incarnation, null);
    }

    /// Restart from `image`. Both checkpoints are strictly decoded into
    /// candidates first; any corruption or allocation failure leaves the node
    /// down and byte-identical.
    fn restoreNode(self: *Mesh, id: u64, image: *const DurableImage) !void {
        const node = self.nodeById(id);
        if (node.alive or node.lost) return error.InvalidRestore;
        var guard = try replay_guard.Guard.decodeCheckpoint(self.allocator, guard_config, image.guard);
        errdefer guard.deinit();
        const log = try event_log_mod.EventLog.decodeCheckpoint(self.allocator, log_config, image.log);

        node.guard.deinit();
        node.guard = guard;
        node.log.deinit();
        node.log = log;
        node.clock.mesh = .{
            .last_physical = MeshClock.physicalOf(image.mesh_high_water),
            .last_stamp = image.mesh_high_water,
        };
        node.clock.hlc = image.crdt_hlc;
        node.alive = true;
        node.incarnation +%= 1;
        self.traceEvent('U', id, node.incarnation, null);
    }

    /// Restart from the node's own last flushed image, which stays its
    /// durable image after the restart.
    fn restoreFromDurable(self: *Mesh, id: u64) !void {
        const node = self.nodeById(id);
        try self.restoreNode(id, &node.flushed);
    }

    /// Permanent loss: the process never returns and every edge to it is gone.
    fn loseNode(self: *Mesh, id: u64) void {
        const node = self.nodeById(id);
        node.alive = false;
        node.lost = true;
        node.incarnation +%= 1;
        for (self.topo.edges, 0..) |edge, edge_index| {
            if (edge.a == id or edge.b == id) self.edge_cut[edge_index] = true;
        }
        self.traceEvent('Z', id, 0, null);
    }

    /// Configuration-authorized retirement of `id` from every survivor's
    /// RVL2 membership: prepare on every affected log first (fallible), then
    /// commit all (infallible). `results[i]` is null where `id` was not
    /// required.
    fn retireNodeEverywhere(self: *Mesh, id: u64, results: *[max_nodes]?event_log_mod.NodeRetirementResult) !void {
        var plans: [max_nodes]?event_log_mod.PreparedNodeRetirement = @splat(null);
        defer for (&plans) |*slot| {
            if (slot.*) |*plan| plan.deinit();
        };
        for (self.nodes, 0..) |*node, i| {
            results[i] = null;
            if (node.lost or node.id == id or !node.requires(id)) continue;
            if (!node.alive or node.required_len <= 2) return error.InvalidRetirement;
            plans[i] = try node.log.prepareConfiguredNodeRetirement(id);
        }
        for (self.nodes, 0..) |*node, i| {
            if (plans[i] == null) continue;
            results[i] = plans[i].?.commit();
            const at = std.mem.indexOfScalar(u64, node.required(), id).?;
            std.mem.copyForwards(u64, node.required_buf[at .. node.required_len - 1], node.required_buf[at + 1 .. node.required_len]);
            node.required_len -= 1;
        }
        self.traceEvent('T', id, 0, null);
    }

    fn applyAction(self: *Mesh, action: ScriptAction) !void {
        switch (action) {
            .cut => |e| self.setEdge(e[0], e[1], false),
            .heal => |e| self.setEdge(e[0], e[1], true),
            .crash => |id| try self.crashNode(id),
            .restore => |id| try self.restoreFromDurable(id),
        }
    }

    // -- scheduler -------------------------------------------------------------------

    fn pickSurvivor(self: *const Mesh, random: std.Random) ?usize {
        var buf: [max_nodes]usize = undefined;
        var n: usize = 0;
        for (self.nodes, 0..) |node, i| {
            if (!node.isSurvivor()) continue;
            buf[n] = i;
            n += 1;
        }
        if (n == 0) return null;
        return buf[random.intRangeLessThan(usize, 0, n)];
    }

    /// One round: deliveries and authorship admit events as pending; scripted
    /// actions then run, so a scripted crash lands after this round's
    /// admissions and before their flush; the group-commit flush releases the
    /// rest; repair and merge follow.
    fn stepRound(self: *Mesh, params: RunParams) !void {
        self.true_ms += self.tick_ms;
        for (self.nodes) |*node| node.clock.advanceTo(self.true_ms, self.round);
        try self.deliverDue();
        if (params.author_probability > 0 and self.authored.items.len < params.max_authored) {
            const random = self.wl_prng.random();
            if (random.float(f64) < params.author_probability) {
                if (self.pickSurvivor(random)) |index| {
                    var text_buf: [24]u8 = undefined;
                    _ = try self.authorAt(index, try std.fmt.bufPrint(&text_buf, "m{d}", .{self.authored.items.len}));
                }
            }
        }
        if (params.crdt_probability > 0) {
            const random = self.wl_prng.random();
            if (random.float(f64) < params.crdt_probability) {
                if (self.pickSurvivor(random)) |index| {
                    const kind: CrdtKind = if (random.boolean()) .topic else .nick;
                    _ = try self.crdtWrite(index, kind);
                }
            }
        }
        for (params.script) |entry| {
            if (entry.at_round == self.round) try self.applyAction(entry.action);
        }
        try self.flushAll();
        if (params.repair_every != 0 and self.round % params.repair_every == 0) try self.repairRound();
        if (params.merge_every != 0 and self.round % params.merge_every == 0) try self.crdtMergeRound();
        self.round += 1;
    }

    fn runRounds(self: *Mesh, params: RunParams) !void {
        for (0..params.rounds) |_| try self.stepRound(params);
    }

    /// Quiescent: nothing in flight, every survivor's RVL2 log fully retired
    /// (every required neighbour durably confirmed every row), and every
    /// survivor's CRDT state equal.
    fn quiescent(self: *const Mesh) bool {
        if (self.queue.count() != 0) return false;
        var reference: ?*const Node = null;
        for (self.nodes) |*node| {
            if (!node.isSurvivor()) continue;
            if (node.log.len() != 0) return false;
            if (reference) |ref| {
                if (!node.state.eql(&ref.state)) return false;
            } else reference = node;
        }
        return true;
    }

    /// Reliable-network rounds with repair and merge every round, without
    /// requiring quiescence.
    fn runReliable(self: *Mesh, rounds: usize) !void {
        const saved = self.fault;
        self.fault = reliable_profile;
        defer self.fault = saved;
        try self.runRounds(.{ .rounds = rounds, .author_probability = 0, .repair_every = 1, .merge_every = 1 });
    }

    /// Run reliable rounds until quiescent; bounded so a stuck campaign fails
    /// with its seed rather than looping.
    fn settle(self: *Mesh, max_rounds: usize) !usize {
        return self.settleEvery(max_rounds, 1);
    }

    fn settleEvery(self: *Mesh, max_rounds: usize, repair_every: usize) !usize {
        const saved = self.fault;
        self.fault = reliable_profile;
        defer self.fault = saved;
        var used: usize = 0;
        while (!self.quiescent()) : (used += 1) {
            if (used == max_rounds) {
                std.debug.print("M08 no convergence: topo={s} seed=0x{x} round={d}\n", .{ self.topo.name, self.seed, self.round });
                return error.NoConvergence;
            }
            try self.stepRound(.{ .rounds = 1, .author_probability = 0, .repair_every = repair_every, .merge_every = 1 });
        }
        return used;
    }

    // -- digests ---------------------------------------------------------------------

    /// Canonical node digest. `core` covers RVG2, published history and
    /// clocks; `full` adds RVL2, membership, liveness, durable image and the
    /// shared queue position.
    fn nodeDigest(self: *const Mesh, allocator: Allocator, index: usize, full: bool) !Digest {
        const node = &self.nodes[index];
        var h = Blake3.init(.{});
        const guard_bytes = try node.guard.encodeCheckpoint(allocator);
        defer allocator.free(guard_bytes);
        h.update(guard_bytes);
        hashU64(&h, node.published.count());
        for (node.published.keys(), node.published.values()) |id, wire| {
            h.update(&id);
            hashU64(&h, wire.len);
            h.update(wire);
        }
        hashU64(&h, node.clock.mesh.last_physical);
        hashU64(&h, node.clock.mesh.last_stamp);
        hashU64(&h, node.clock.hlc.toU64());
        hashU64(&h, node.local_seq);
        hashU64(&h, node.last_authored_hlc);
        hashU64(&h, node.released_authored_hlc);
        hashU64(&h, node.pending.items.len);
        for (node.pending.items) |entry| {
            h.update(&entry.relay_id);
            hashU64(&h, entry.sender orelse 0);
            hashU64(&h, entry.hlc);
            h.update(entry.wire);
        }
        if (full) {
            const log_bytes = try node.log.encodeCheckpoint(allocator);
            defer allocator.free(log_bytes);
            h.update(log_bytes);
            for (node.required()) |id| hashU64(&h, id);
            hashU64(&h, @intFromBool(node.alive));
            hashU64(&h, @intFromBool(node.lost));
            hashU64(&h, node.incarnation);
            h.update(node.flushed.guard);
            h.update(node.flushed.log);
            hashU64(&h, node.flushed.mesh_high_water);
            hashU64(&h, node.flushed.crdt_hlc.toU64());
            hashU64(&h, self.queue.count());
            hashU64(&h, self.next_seq);
        }
        var out: Digest = undefined;
        h.final(&out);
        return out;
    }

    /// Whole-harness digest for allocation-atomicity sweeps.
    fn meshDigest(self: *const Mesh, allocator: Allocator) !Digest {
        var h = Blake3.init(.{});
        for (self.nodes, 0..) |node, i| {
            const d = try self.nodeDigest(allocator, i, true);
            h.update(&d);
            h.update(std.mem.asBytes(&node.stats));
        }
        hashU64(&h, self.authored.items.len);
        hashU64(&h, self.crdt_writes.items.len);
        hashU64(&h, self.round);
        hashU64(&h, self.true_ms);
        h.update(std.mem.asBytes(&self.net_prng));
        h.update(std.mem.asBytes(&self.wl_prng));
        var out: Digest = undefined;
        h.final(&out);
        return out;
    }

    fn finalDigest(self: *Mesh) !Digest {
        var h = self.trace;
        const whole = try self.meshDigest(self.allocator);
        h.update(&whole);
        var out: Digest = undefined;
        h.final(&out);
        return out;
    }
};

// ---------------------------------------------------------------------------
// Wire helpers.
// ---------------------------------------------------------------------------

fn crdtChannel() !state_mod.ChannelName {
    return state_mod.ChannelName.init(relay_target);
}

fn contestedNick() !state_mod.Nick {
    return state_mod.Nick.init("contested");
}

const OwnedWire = struct { id: RelayId, bytes: []u8 };

fn makeWire(allocator: Allocator, kp: *const sign.KeyPair, hlc: u64, prefix: []const u8, text: []const u8) !OwnedWire {
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    var msg = message_relay_v2.RelayMessage{
        .verb = .privmsg,
        .target = relay_target,
        .source_prefix = prefix,
        .text = text,
        .scope_kind = .channel,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try message_relay_v2.stampOrigin(allocator, &msg, kp, &pubkey, &signature);
    const id = switch (try message_relay_v2.verifyAndRelayId(allocator, msg)) {
        .verified => |vid| vid,
        else => return error.TestUnexpectedResult,
    };
    return .{ .id = id, .bytes = try message_relay_v2.encode(allocator, msg) };
}

const Rewrite = enum { tamper_text, origin_mismatch, equivocate };

/// Hostile rewrites of a captured wire: an in-transit text edit (signature no
/// longer covers it), a forged origin handle, and an origin-signed equivocating
/// twin at the same (origin, HLC).
fn rewriteWire(allocator: Allocator, wire: []const u8, how: Rewrite, kp: ?*const sign.KeyPair) ![]u8 {
    var owned = try message_relay_v2.decode(allocator, wire);
    defer owned.deinit(allocator);
    var msg = owned.msg;
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    switch (how) {
        .tamper_text => msg.text = "tampered in transit",
        .origin_mismatch => msg.origin_node ^= 1,
        .equivocate => {
            msg.text = "equivocating twin";
            try message_relay_v2.stampOrigin(allocator, &msg, kp.?, &pubkey, &signature);
        },
    }
    return message_relay_v2.encode(allocator, msg);
}

fn originNodeOf(mesh: *Mesh, wire: []const u8) !*Node {
    var owned = try message_relay_v2.decode(mesh.allocator, wire);
    defer owned.deinit(mesh.allocator);
    for (mesh.nodes) |*node| {
        if (std.mem.eql(u8, &node.keypair.public_key, owned.msg.origin_pubkey)) return node;
    }
    return error.TestUnexpectedResult;
}

// ---------------------------------------------------------------------------
// Shared assertions.
// ---------------------------------------------------------------------------

/// Exact convergence over survivors: every RVL2 log fully retired, accepted
/// count equal to the published count (each id accepted exactly once), equal
/// published id sets with byte-identical origin-signed wires that still
/// verify to their id, and equal CRDT state. With `all_authored`, every
/// authored id is present. Returns the converged event count.
fn expectConverged(mesh: *Mesh, all_authored: bool) !usize {
    var reference: ?*Node = null;
    for (mesh.nodes) |*node| {
        if (!node.isSurvivor()) continue;
        try testing.expectEqual(@as(usize, 0), node.log.len());
        try testing.expectEqual(@as(usize, 0), node.pending.items.len);
        try testing.expectEqual(node.published.count() + node.stats.unflushed_lost, node.stats.accepted);
        if (reference) |ref| {
            try testing.expectEqual(ref.published.count(), node.published.count());
            for (ref.published.keys(), ref.published.values()) |id, wire| {
                const other = node.published.get(id) orelse return error.TestExpectedEqual;
                try testing.expectEqualSlices(u8, wire, other);
            }
            try testing.expect(node.state.eql(&ref.state));
        } else reference = node;
    }
    const ref = reference orelse return error.TestUnexpectedResult;
    for (ref.published.keys(), ref.published.values()) |id, wire| {
        var owned = try message_relay_v2.decode(mesh.allocator, wire);
        defer owned.deinit(mesh.allocator);
        switch (try message_relay_v2.verifyAndRelayId(mesh.allocator, owned.msg)) {
            .verified => |verified| try testing.expectEqualSlices(u8, &id, &verified),
            else => return error.TestUnexpectedResult,
        }
    }
    if (all_authored) {
        for (mesh.authored.items) |id| try testing.expect(ref.published.contains(id));
        try testing.expectEqual(mesh.authored.items.len, ref.published.count());
    }
    return ref.published.count();
}

/// Hostile lane at `at_id`, as if received from neighbour `from_id`: an exact
/// replayed capture is a non-publishing duplicate; tampered, forged-origin,
/// equivocating, untrusted-origin, truncated and garbage inputs are rejected
/// with the audited node byte-identical and nothing forwarded.
fn expectHostileRejected(mesh: *Mesh, at_id: u64, from_id: u64) !void {
    const allocator = mesh.allocator;
    const at_index = mesh.nodeIndexOf(at_id);
    const node = &mesh.nodes[at_index];
    try testing.expect(node.published.count() > 0);
    const capture = try allocator.dupe(u8, node.published.values()[0]);
    defer allocator.free(capture);
    const published_before = node.published.count();
    const accepted_before = node.stats.accepted;

    try testing.expectEqual(Outcome.duplicate, try mesh.inject(at_index, from_id, capture));

    const tampered = try rewriteWire(allocator, capture, .tamper_text, null);
    defer allocator.free(tampered);
    try testing.expectEqual(Outcome.rejected, try mesh.inject(at_index, from_id, tampered));

    const forged_origin = try rewriteWire(allocator, capture, .origin_mismatch, null);
    defer allocator.free(forged_origin);
    try testing.expectEqual(Outcome.rejected, try mesh.inject(at_index, from_id, forged_origin));

    const origin = try originNodeOf(mesh, capture);
    const twin = try rewriteWire(allocator, capture, .equivocate, &origin.keypair);
    defer allocator.free(twin);
    try testing.expectEqual(Outcome.rejected, try mesh.inject(at_index, from_id, twin));

    var stranger = try sign.KeyPair.fromSeed(@splat(0xa5));
    defer stranger.deinit();
    const foreign = try makeWire(allocator, &stranger, node.clock.mesh.last_stamp, "mallory!m@evil.test", "spoof");
    defer allocator.free(foreign.bytes);
    try testing.expectEqual(Outcome.unauthorized, try mesh.inject(at_index, from_id, foreign.bytes));

    try testing.expectEqual(Outcome.malformed, try mesh.inject(at_index, from_id, capture[0 .. capture.len / 2]));
    const garbage: [64]u8 = @splat(0xff);
    try testing.expectEqual(Outcome.malformed, try mesh.inject(at_index, from_id, &garbage));

    try testing.expectEqual(published_before, node.published.count());
    try testing.expectEqual(accepted_before, node.stats.accepted);
    for (mesh.nodes) |*other| try testing.expect(!other.published.contains(foreign.id));
}

const CampaignTotals = struct {
    dropped: usize = 0,
    duplicated: usize = 0,
    lost_in_flight: usize = 0,
    duplicates: usize = 0,

    fn add(self: *CampaignTotals, mesh: *const Mesh) void {
        self.dropped += mesh.packets_dropped;
        self.duplicated += mesh.packets_duplicated;
        self.lost_in_flight += mesh.packets_lost_in_flight;
        for (mesh.nodes) |node| self.duplicates += node.stats.duplicate;
    }

    /// The fault model really fired: drops, duplicated sends, packets killed
    /// by a cut edge or crash, and RVG2 duplicate suppression.
    fn expectNonVacuous(self: CampaignTotals) !void {
        try testing.expect(self.dropped > 0);
        try testing.expect(self.duplicated > 0);
        try testing.expect(self.lost_in_flight > 0);
        try testing.expect(self.duplicates > 0);
    }
};

// ---------------------------------------------------------------------------
// Test 1: A-B-C line partition/rejoin.
// ---------------------------------------------------------------------------

test "M08 recovery DST: A-B-C line partition B-C, rejoin, exact-once RelayId acceptance and byte-identical signed wires on every node across a seed campaign" {
    const seeds = [_]u64{ 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006 };
    var totals: CampaignTotals = .{};
    for (seeds) |seed| {
        errdefer std.debug.print("M08 line campaign failed: seed=0x{x}\n", .{seed});
        var mesh = try Mesh.init(testing.allocator, seed, &topology_line_abc, .{});
        defer mesh.deinit();

        const script = [_]ScriptEntry{.{ .at_round = 12, .action = .{ .cut = .{ 2, 3 } } }};
        try mesh.runRounds(.{ .rounds = 30, .max_authored = 8, .script = &script });

        // Partitioned: A's event can reach B but not C; C's reaches nobody.
        const a_id = try mesh.authorAt(mesh.nodeIndexOf(1), "partition-a");
        const c_id = try mesh.authorAt(mesh.nodeIndexOf(3), "partition-c");
        try mesh.runRounds(.{ .rounds = 20, .author_probability = 0 });
        try testing.expect(!mesh.nodeById(3).published.contains(a_id));
        try testing.expect(!mesh.nodeById(1).published.contains(c_id));
        try testing.expect(!mesh.nodeById(2).published.contains(c_id));

        mesh.setEdge(2, 3, true);
        try mesh.runRounds(.{ .rounds = 30, .max_authored = 14 });
        _ = try mesh.settle(800);
        const converged = try expectConverged(&mesh, true);
        try testing.expect(converged >= 4);
        for (mesh.nodes) |node| try testing.expectEqual(mesh.authored.items.len, node.stats.accepted);

        try expectHostileRejected(&mesh, 2, 1);
        try expectHostileRejected(&mesh, 3, 2);
        _ = try mesh.settle(200);
        try testing.expectEqual(converged, try expectConverged(&mesh, true));
        totals.add(&mesh);
    }
    try totals.expectNonVacuous();
}

// ---------------------------------------------------------------------------
// Test 2: diamond arm cut / D isolated / rejoin, plus CRDT tombstones.
// ---------------------------------------------------------------------------

fn presenceTombstoned(node: *const Node, uid: state_mod.Uid) ?bool {
    for (node.state.users.items) |user| {
        if (!state_mod.Uid.eql(user.uid, uid)) continue;
        const lease = user.presence.get() orelse return null;
        return lease.tombstoned;
    }
    return null;
}

test "M08 recovery DST: diamond A-{B,C}-D arm cut, then D isolated, then rejoin; CRDT state including ban/presence tombstones converges with no resurrection" {
    const seeds = [_]u64{ 0x2001, 0x2002, 0x2003, 0x2004 };
    var totals: CampaignTotals = .{};
    for (seeds) |seed| {
        errdefer std.debug.print("M08 diamond campaign failed: seed=0x{x}\n", .{seed});
        var mesh = try Mesh.init(testing.allocator, seed, &topology_diamond, .{});
        defer mesh.deinit();

        const chan = try crdtChannel();
        const setter = try state_mod.Uid.init(uid_texts[0]);
        const ghost = try state_mod.Uid.init("009GHOST");
        const a = mesh.nodeById(1);
        const d = mesh.nodeById(4);

        // Connected: A bans a mask and leases presence; D learns both.
        try mesh.runRounds(.{ .rounds = 8 });
        try a.state.addBan(chan, .ban, "*!*@stale.example", .{ .setter = setter }, try a.clock.hlc.now(a.clock.nowMs()));
        try a.state.setPresence(ghost, .{ .expires_at_ms = a.clock.nowMs() + 60_000 }, try a.clock.hlc.now(a.clock.nowMs()));
        try mesh.runReliable(6);
        try testing.expect(try d.state.hasBan(chan, .ban, "*!*@stale.example"));
        try testing.expectEqual(@as(?bool, false), presenceTombstoned(d, ghost));

        // Cut one arm (B-D), then the other (C-D): D isolated.
        const script = [_]ScriptEntry{
            .{ .at_round = mesh.round + 4, .action = .{ .cut = .{ 2, 4 } } },
            .{ .at_round = mesh.round + 14, .action = .{ .cut = .{ 3, 4 } } },
        };
        try mesh.runRounds(.{ .rounds = 20, .script = &script });

        // While D is isolated: A removes the ban and tombstones presence; D
        // concurrently adds a different ban; both sides author relay events.
        try a.state.removeBan(chan, .ban, "*!*@STALE.example");
        try a.state.setPresence(ghost, .{ .tombstoned = true }, try a.clock.hlc.now(a.clock.nowMs()));
        try d.state.addBan(chan, .ban, "*!*@fresh.example", .{ .setter = try state_mod.Uid.init(uid_texts[3]) }, try d.clock.hlc.now(d.clock.nowMs()));
        const a_id = try mesh.authorAt(mesh.nodeIndexOf(1), "while-d-isolated");
        const d_id = try mesh.authorAt(mesh.nodeIndexOf(4), "from-isolated-d");
        try mesh.runRounds(.{ .rounds = 20 });
        try testing.expect(try d.state.hasBan(chan, .ban, "*!*@stale.example"));
        try testing.expect(!(try a.state.hasBan(chan, .ban, "*!*@fresh.example")));
        try testing.expect(!d.published.contains(a_id));
        try testing.expect(!a.published.contains(d_id));

        mesh.setEdge(2, 4, true);
        try mesh.runRounds(.{ .rounds = 4 });
        mesh.setEdge(3, 4, true);
        try mesh.runRounds(.{ .rounds = 20, .max_authored = 16 });
        _ = try mesh.settle(800);
        try testing.expect(try expectConverged(&mesh, true) >= 4);

        for (mesh.nodes) |*node| {
            try testing.expect(!(try node.state.hasBan(chan, .ban, "*!*@stale.example")));
            try testing.expect(try node.state.hasBan(chan, .ban, "*!*@fresh.example"));
            try testing.expectEqual(@as(?bool, true), presenceTombstoned(node, ghost));
        }
        // Extra merges after convergence change nothing (no resurrection).
        try mesh.runReliable(5);
        for (mesh.nodes) |*node| try testing.expect(!(try node.state.hasBan(chan, .ban, "*!*@stale.example")));
        try testing.expect(mesh.quiescent());
        totals.add(&mesh);
    }
    try totals.expectNonVacuous();
}

// ---------------------------------------------------------------------------
// Test 3: clock skew keeps LWW winners identical and own stamps increasing.
// ---------------------------------------------------------------------------

const LwwKey = struct {
    stamp: u64,
    node_id: u64,

    fn greater(a: LwwKey, b: LwwKey) bool {
        if (a.stamp != b.stamp) return a.stamp > b.stamp;
        return a.node_id > b.node_id;
    }
};

/// Independent reference: the (stamp, node) maximum over every write of
/// `kind`, matching both the LWW register and the equal-authority nick
/// tie-break.
fn referenceWinner(mesh: *const Mesh, kind: CrdtKind) ?CrdtWrite {
    var best: ?CrdtWrite = null;
    for (mesh.crdt_writes.items) |write| {
        if (write.kind != kind) continue;
        const key = LwwKey{ .stamp = write.stamp, .node_id = mesh.nodes[write.node_index].id };
        if (best) |current| {
            const current_key = LwwKey{ .stamp = current.stamp, .node_id = mesh.nodes[current.node_index].id };
            if (!key.greater(current_key)) continue;
        }
        best = write;
    }
    return best;
}

fn expectTopicWinner(mesh: *const Mesh, winner: CrdtWrite) !void {
    const chan = try crdtChannel();
    for (mesh.nodes) |*node| {
        var found = false;
        for (node.state.topics.items) |entry| {
            if (!state_mod.ChannelName.eql(entry.channel, chan)) continue;
            try testing.expectEqual(winner.stamp, entry.register.timestamp);
            try testing.expectEqual(mesh.nodes[winner.node_index].id, entry.register.replica_id);
            found = true;
        }
        try testing.expect(found);
    }
}

test "M08 recovery DST: per-node clock offset/drift/step-back keeps LWW winners identical on all nodes and own stamps strictly increasing" {
    const seeds = [_]u64{ 0x3001, 0x3002, 0x3003, 0x3004 };
    const step_back = [_]ClockStep{.{ .at_round = 30, .delta_ms = -5_000 }};
    const jump = [_]ClockStep{.{ .at_round = 45, .delta_ms = 3_000 }};
    const specs = [_]ClockSpec{
        .{ .offset_ms = 0, .drift_ppm = 400, .steps = &step_back },
        .{ .offset_ms = 2_500, .drift_ppm = -600 },
        .{ .offset_ms = -4_000, .drift_ppm = 150 },
        .{ .offset_ms = 700, .drift_ppm = 90, .steps = &jump },
        .{ .offset_ms = -1_200, .drift_ppm = -250 },
    };
    // Node 3 is fully isolated for rounds 15..50.
    const script = [_]ScriptEntry{
        .{ .at_round = 15, .action = .{ .cut = .{ 2, 3 } } },
        .{ .at_round = 15, .action = .{ .cut = .{ 3, 4 } } },
        .{ .at_round = 15, .action = .{ .cut = .{ 1, 3 } } },
        .{ .at_round = 50, .action = .{ .heal = .{ 2, 3 } } },
        .{ .at_round = 52, .action = .{ .heal = .{ 3, 4 } } },
        .{ .at_round = 54, .action = .{ .heal = .{ 1, 3 } } },
    };
    for (seeds) |seed| {
        errdefer std.debug.print("M08 skew campaign failed: seed=0x{x}\n", .{seed});
        var mesh = try Mesh.init(testing.allocator, seed, &topology_ring_chord, .{ .clock_specs = &specs });
        defer mesh.deinit();

        var params = RunParams{ .rounds = 20, .crdt_probability = 0.6, .max_authored = 10, .script = &script };
        try mesh.runRounds(params);
        const before = try mesh.crdtWrite(0, .topic);
        _ = try mesh.crdtWrite(2, .nick);
        params.rounds = 12; // crosses node 1's -5s step at round 30
        try mesh.runRounds(params);
        // Node 1's wall clock is now behind its last stamp, yet its next
        // stamp is strictly newer (and its relay MeshClock never regressed).
        try testing.expect(mesh.nodes[0].clock.nowMs() < before.wall_ms);
        const after = try mesh.crdtWrite(0, .topic);
        try testing.expectEqual(std.math.Order.lt, Hlc.compare(before, after));
        params.rounds = 30;
        try mesh.runRounds(params);
        _ = try mesh.settle(800);
        _ = try expectConverged(&mesh, true);

        const topic_winner = referenceWinner(&mesh, .topic).?;
        try expectTopicWinner(&mesh, topic_winner);
        const nick_winner = referenceWinner(&mesh, .nick).?;
        const nick = try contestedNick();
        const winner_uid = try state_mod.Uid.init(uid_texts[nick_winner.node_index]);
        for (mesh.nodes) |*node| {
            try testing.expectEqual(state_mod.NickOutcome.keep_nick, node.state.resolveNick(nick, winner_uid).outcome);
            for (mesh.crdt_writes.items) |write| {
                if (write.kind != .nick or write.node_index == nick_winner.node_index) continue;
                const loser = try state_mod.Uid.init(uid_texts[write.node_index]);
                try testing.expectEqual(state_mod.NickOutcome.rename_to_uid, node.state.resolveNick(nick, loser).outcome);
            }
        }

        // Causality beats skew: the node whose wall clock is 4s behind writes
        // after observing the winner, and its write wins everywhere.
        const causal = try mesh.crdtWrite(2, .topic);
        try testing.expect(causal.toU64() > topic_winner.stamp);
        _ = try mesh.settle(200);
        const final_winner = referenceWinner(&mesh, .topic).?;
        try testing.expectEqual(@as(usize, 2), final_winner.node_index);
        try expectTopicWinner(&mesh, final_winner);
    }
}

// ---------------------------------------------------------------------------
// Test 4: future-skew deferral, then exactly-once repair.
// ---------------------------------------------------------------------------

test "M08 recovery DST: an event beyond the future-skew bound is rejected without mutation, then repaired exactly once after the receiver clock advances" {
    const seeds = [_]u64{ 0x4001, 0x4002, 0x4003 };
    const bound_ms: u64 = 300;
    const correction = [_]ClockStep{.{ .at_round = 8, .delta_ms = -1_500 }};
    const specs = [_]ClockSpec{ .{}, .{}, .{ .offset_ms = 1_500, .steps = &correction } };
    for (seeds) |seed| {
        errdefer std.debug.print("M08 future-skew campaign failed: seed=0x{x}\n", .{seed});
        var mesh = try Mesh.init(testing.allocator, seed, &topology_line_abc, .{
            .clock_specs = &specs,
            .future_skew_bound_ms = bound_ms,
            .tick_ms = 20,
        });
        defer mesh.deinit();
        const b_index = mesh.nodeIndexOf(2);
        const c_index = mesh.nodeIndexOf(3);
        const b = &mesh.nodes[b_index];

        try mesh.runRounds(.{ .rounds = 2, .author_probability = 0 });
        const first = try mesh.authorAt(c_index, "ahead-1");
        const second = try mesh.authorAt(c_index, "ahead-2");
        const c_hlc = mesh.nodes[c_index].last_authored_hlc;
        try mesh.runRounds(.{ .rounds = 15, .author_probability = 0 });
        // Every attempt so far was deferred under audit: no mutation at B.
        try testing.expect(b.stats.deferred > 0);
        try testing.expectEqual(@as(usize, 0), b.stats.accepted);
        try testing.expect(!b.published.contains(first));
        try testing.expect(!b.published.contains(second));
        try testing.expect(b.clock.mesh.last_stamp < c_hlc);

        // Hostile far-future and maximal stamps from a trusted origin never
        // admit and never poison the receiver clock.
        const c_keypair = &mesh.nodes[c_index].keypair;
        const far_physical = b.clock.nowMs() + 10 * 24 * 60 * 60 * 1000;
        const far = try makeWire(testing.allocator, c_keypair, (far_physical << mesh_clock.seq_bits) | 1, "node3!u@dst.test", "far-future");
        defer testing.allocator.free(far.bytes);
        const max_stamp = try makeWire(testing.allocator, c_keypair, std.math.maxInt(u64), "node3!u@dst.test", "max-stamp");
        defer testing.allocator.free(max_stamp.bytes);
        try testing.expectEqual(Outcome.deferred, try mesh.inject(b_index, 3, far.bytes));
        try testing.expectEqual(Outcome.deferred, try mesh.inject(b_index, 3, max_stamp.bytes));
        try testing.expect(b.clock.mesh.last_stamp < c_hlc);

        // As true time passes B's clock reaches the bound; RVL2 repair then
        // delivers each event exactly once everywhere.
        _ = try mesh.settle(400);
        _ = try expectConverged(&mesh, true);
        for (mesh.nodes) |node| {
            try testing.expectEqual(@as(usize, 2), node.stats.accepted);
            try testing.expect(!node.published.contains(far.id));
            try testing.expect(!node.published.contains(max_stamp.id));
        }
        // B folded C's stamp into its clock: B's next event is causally newer.
        _ = try mesh.authorAt(b_index, "after-skew");
        try testing.expect(b.last_authored_hlc > c_hlc);
        _ = try mesh.settle(200);
        _ = try expectConverged(&mesh, true);
    }
}

// ---------------------------------------------------------------------------
// Test 5: node B crash, checkpoint restore, replayed captures, convergence.
// ---------------------------------------------------------------------------

test "M08 recovery DST: node B crash mid-campaign restores guard and event log from checkpoint, rejects replayed captures, and converges" {
    const seeds = [_]u64{ 0x5001, 0x5002, 0x5003 };
    const restart_step = [_]ClockStep{.{ .at_round = 40, .delta_ms = -3_000 }};
    const specs = [_]ClockSpec{ .{}, .{ .offset_ms = 250, .steps = &restart_step }, .{} };
    var totals: CampaignTotals = .{};
    for (seeds) |seed| {
        errdefer std.debug.print("M08 crash campaign failed: seed=0x{x}\n", .{seed});
        var mesh = try Mesh.init(testing.allocator, seed, &topology_line_abc, .{ .clock_specs = &specs });
        defer mesh.deinit();
        const b_index = mesh.nodeIndexOf(2);
        const b = &mesh.nodes[b_index];

        try mesh.runRounds(.{ .rounds = 18, .max_authored = 6, .author_probability = 0.6 });
        _ = try mesh.authorAt(b_index, "b-before-crash");
        try mesh.runRounds(.{ .rounds = 2, .author_probability = 0 });

        // Captures of everything B ever delivered, for later replay.
        var captures: std.ArrayList([]u8) = .empty;
        defer {
            for (captures.items) |wire| testing.allocator.free(wire);
            captures.deinit(testing.allocator);
        }
        for (b.published.values()) |wire| {
            try captures.ensureUnusedCapacity(testing.allocator, 1);
            captures.appendAssumeCapacity(try testing.allocator.dupe(u8, wire));
        }
        try testing.expect(captures.items.len >= 2);

        // B authors once more and crashes before the group-commit flush: the
        // event was admitted to RVG2/RVL2 in memory only, so it is lost with
        // the process and never reaches a client, a neighbour or the image.
        const flushed_guard = try testing.allocator.dupe(u8, b.flushed.guard);
        defer testing.allocator.free(flushed_guard);
        const unflushed_id = try mesh.authorAt(b_index, "b-unflushed");
        try testing.expect(!b.published.contains(unflushed_id));
        try mesh.crashNode(2); // mid-campaign, with traffic in flight
        try testing.expectEqual(@as(usize, 1), b.stats.unflushed_lost);
        for (mesh.authored.items) |id| try testing.expect(!std.mem.eql(u8, &id, &unflushed_id));
        try testing.expectEqualSlices(u8, flushed_guard, b.flushed.guard);
        var image = try b.flushed.clone(testing.allocator);
        defer image.deinit(testing.allocator);

        // B is the only A-C path: downtime events stay on their side.
        try mesh.runRounds(.{ .rounds = 10, .max_authored = 12 });
        const a_id = try mesh.authorAt(mesh.nodeIndexOf(1), "a-while-b-down");
        const c_id = try mesh.authorAt(mesh.nodeIndexOf(3), "c-while-b-down");
        try mesh.runRounds(.{ .rounds = 8, .author_probability = 0 });
        try testing.expect(!mesh.nodeById(3).published.contains(a_id));
        try testing.expect(!mesh.nodeById(1).published.contains(c_id));

        // Corrupted or truncated images fail closed: B stays down, unchanged.
        const down_digest = try mesh.meshDigest(testing.allocator);
        var corrupt_log = try image.clone(testing.allocator);
        defer corrupt_log.deinit(testing.allocator);
        corrupt_log.log[corrupt_log.log.len / 2] ^= 0x40;
        try testing.expect(std.meta.isError(mesh.restoreNode(2, &corrupt_log)));
        var corrupt_guard = try image.clone(testing.allocator);
        defer corrupt_guard.deinit(testing.allocator);
        corrupt_guard.guard[corrupt_guard.guard.len - 1] ^= 0x01;
        try testing.expect(std.meta.isError(mesh.restoreNode(2, &corrupt_guard)));
        var truncated = try image.clone(testing.allocator);
        defer truncated.deinit(testing.allocator);
        const truncated_view = DurableImage{
            .guard = truncated.guard[0 .. truncated.guard.len - 3],
            .log = truncated.log,
            .mesh_high_water = truncated.mesh_high_water,
            .crdt_hlc = truncated.crdt_hlc,
        };
        try testing.expect(std.meta.isError(mesh.restoreNode(2, &truncated_view)));
        try testing.expect(!b.alive);
        try testing.expectEqualSlices(u8, &down_digest, &(try mesh.meshDigest(testing.allocator)));

        // Restart right after round 40 stepped B's wall clock back 3s.
        while (mesh.round <= 40) try mesh.stepRound(.{ .rounds = 1, .author_probability = 0 });
        try mesh.restoreFromDurable(2);
        try testing.expectError(error.InvalidRestore, mesh.restoreNode(2, &image));
        const restored_guard = try b.guard.encodeCheckpoint(testing.allocator);
        defer testing.allocator.free(restored_guard);
        try testing.expectEqualSlices(u8, image.guard, restored_guard);
        const restored_log = try b.log.encodeCheckpoint(testing.allocator);
        defer testing.allocator.free(restored_log);
        try testing.expectEqualSlices(u8, image.log, restored_log);

        // Every pre-crash capture replays as a non-publishing duplicate.
        const published_before = b.published.count();
        for (captures.items) |wire| {
            try testing.expectEqual(Outcome.duplicate, try mesh.inject(b_index, 1, wire));
        }
        try testing.expectEqual(published_before, b.published.count());

        // Restart-persistent MeshClock: post-restart stamps beat pre-crash ones
        // even though the wall clock went backwards.
        try testing.expect(b.clock.nowMs() < MeshClock.physicalOf(image.mesh_high_water));
        _ = try mesh.authorAt(b_index, "b-after-restart");
        try testing.expect(b.last_authored_hlc > image.mesh_high_water);

        try mesh.runRounds(.{ .rounds = 20, .max_authored = 16 });
        _ = try mesh.settle(800);
        try testing.expect(try expectConverged(&mesh, true) >= 6);
        for (mesh.nodes) |*node| try testing.expect(!node.published.contains(unflushed_id));
        totals.add(&mesh);
    }
    try totals.expectNonVacuous();
}

// ---------------------------------------------------------------------------
// Test 5b: crash between RVG2 admit and the durable flush.
// ---------------------------------------------------------------------------

/// Line A-B-C, reliable links. C authors X and flushes, so X travels to B
/// while C's RVL2 row still waits on B's durable ACK. B admits X and crashes
/// before its flush, then restarts from its last (pre-X) flushed image.
/// Returns X and its canonical wire (owned by C's history).
fn crashBetweenAdmitAndFlush(mesh: *Mesh) !struct { id: RelayId, wire: []const u8 } {
    const b_index = mesh.nodeIndexOf(2);
    const c_index = mesh.nodeIndexOf(3);
    const b = &mesh.nodes[b_index];
    const c = &mesh.nodes[c_index];
    const x = try mesh.authorAt(c_index, "x");
    try mesh.flushNode(c_index);
    try testing.expect(c.log.contains(x));
    // Deliver only C's flood to B; no flush runs before the crash.
    mesh.true_ms += reliable_profile.latency_ms;
    try mesh.deliverDue();
    try testing.expectEqual(@as(usize, 1), b.stats.accepted);
    const pre_x_guard = try testing.allocator.dupe(u8, b.flushed.guard);
    defer testing.allocator.free(pre_x_guard);
    try mesh.crashNode(2);
    try testing.expect(!c.log.isConfirmedBy(x, 2));
    try mesh.restoreFromDurable(2);
    try testing.expectEqualSlices(u8, pre_x_guard, b.flushed.guard);
    const wire = c.published.get(x).?;
    var owned = try message_relay_v2.decode(testing.allocator, wire);
    defer owned.deinit(testing.allocator);
    // The restored RVG2 has forgotten X: replay authority rolled back.
    try testing.expect(try b.guard.probeMessage(owned.msg) == .unseen);
    return .{ .id = x, .wire = wire };
}

test "M08 recovery DST: crash between RVG2 admit and durable flush" {
    const seeds = [_]u64{ 0x5b01, 0x5b02, 0x5b03 };
    for (seeds) |seed| {
        errdefer std.debug.print("M08 crash-window campaign failed: seed=0x{x}\n", .{seed});
        // Flush-gated release: nothing escaped B before the crash, so C's
        // repair re-admits X once and every node holds X exactly once.
        {
            var mesh = try Mesh.init(testing.allocator, seed, &topology_line_abc, .{ .fault = reliable_profile });
            defer mesh.deinit();
            const b = &mesh.nodes[mesh.nodeIndexOf(2)];
            const x = try crashBetweenAdmitAndFlush(&mesh);
            try testing.expectEqual(@as(usize, 1), b.stats.unflushed_lost);
            try testing.expect(!b.published.contains(x.id));
            _ = try mesh.settle(200);
            try testing.expectEqual(@as(usize, 1), try expectConverged(&mesh, true));
            try testing.expectEqual(@as(usize, 2), b.stats.accepted);
            try testing.expectEqual(@as(usize, 1), b.published.count());
            for (mesh.nodes) |*node| {
                try testing.expectEqualSlices(u8, x.wire, node.published.get(x.id).?);
            }
            // A later replay of X stays a non-publishing duplicate at B.
            try testing.expectEqual(Outcome.duplicate, try mesh.inject(mesh.nodeIndexOf(2), 3, x.wire));
            try testing.expectEqual(@as(usize, 1), b.published.count());
        }
        // Mutation control: publish/ACK/flood at admit, before the flush.
        // B's clients already saw X when the crash rolled RVG2 back, so C's
        // repair re-admits X and exact-once fails.
        {
            var mesh = try Mesh.init(testing.allocator, seed, &topology_line_abc, .{
                .fault = reliable_profile,
                .publish_before_flush = true,
            });
            defer mesh.deinit();
            const b = &mesh.nodes[mesh.nodeIndexOf(2)];
            const x = try crashBetweenAdmitAndFlush(&mesh);
            try testing.expectEqual(@as(usize, 0), b.stats.unflushed_lost);
            try testing.expect(b.published.contains(x.id));
            try testing.expectError(error.ExactOnceViolation, mesh.settle(200));
        }
    }
}

// ---------------------------------------------------------------------------
// Test 6: a permanently lost diamond node is retired by configuration.
// ---------------------------------------------------------------------------

test "M08 recovery DST: a permanently lost diamond node is retired via configured node retirement so the survivors retire rows and converge" {
    const seeds = [_]u64{ 0x6001, 0x6002, 0x6003 };
    for (seeds) |seed| {
        errdefer std.debug.print("M08 node-loss campaign failed: seed=0x{x}\n", .{seed});
        var mesh = try Mesh.init(testing.allocator, seed, &topology_diamond, .{});
        defer mesh.deinit();
        const d_index = mesh.nodeIndexOf(4);
        const d_origin = mesh.nodes[d_index].keypair.public_key;

        try mesh.runRounds(.{ .rounds = 16, .max_authored = 6 });
        _ = try mesh.authorAt(d_index, "d-last-words-1");
        try mesh.runRounds(.{ .rounds = 6, .author_probability = 0 });
        _ = try mesh.authorAt(d_index, "d-last-words-2");
        try mesh.runRounds(.{ .rounds = 1, .author_probability = 0 });
        mesh.loseNode(4);

        try mesh.runRounds(.{ .rounds = 12, .max_authored = 12 });
        // Liveness alone never retires authority: rows waiting on D persist.
        try mesh.runReliable(60);
        try testing.expect(!mesh.quiescent());
        try testing.expect(mesh.nodeById(2).log.len() + mesh.nodeById(3).log.len() > 0);
        try testing.expectEqual(@as(usize, 0), mesh.nodeById(1).log.len());

        // A concurrent prepared mutation blocks a second retirement plan.
        {
            var held = try mesh.nodeById(2).log.prepareConfiguredNodeRetirement(4);
            defer held.deinit();
            try testing.expectError(error.PreparedMutationActive, mesh.nodeById(2).log.prepareConfiguredNodeRetirement(4));
        }

        var results: [max_nodes]?event_log_mod.NodeRetirementResult = undefined;
        try mesh.retireNodeEverywhere(4, &results);
        try testing.expect(results[mesh.nodeIndexOf(1)] == null);
        const b_result = results[mesh.nodeIndexOf(2)].?;
        const c_result = results[mesh.nodeIndexOf(3)].?;
        try testing.expect(b_result.rows_changed + c_result.rows_changed > 0);
        try testing.expect(b_result.rows_retired + c_result.rows_retired > 0);
        try testing.expect(!mesh.nodeById(2).requires(4));
        try testing.expect(!mesh.nodeById(3).requires(4));

        _ = try mesh.settle(800);
        const converged = try expectConverged(&mesh, false);

        // All-or-nothing among survivors, and D's pre-loss events that reached
        // any survivor are delivered to every survivor exactly once.
        const a = mesh.nodeById(1);
        for (mesh.authored.items) |id| {
            const on_a = a.published.contains(id);
            for (mesh.nodes) |*node| {
                if (node.isSurvivor()) try testing.expectEqual(on_a, node.published.contains(id));
            }
        }
        var d_events: usize = 0;
        for (a.published.values()) |wire| {
            const origin = try originNodeOf(&mesh, wire);
            if (!std.mem.eql(u8, &origin.keypair.public_key, &d_origin)) continue;
            d_events += 1;
            // Replays of the lost node's captures stay duplicates everywhere.
            try testing.expectEqual(Outcome.duplicate, try mesh.inject(mesh.nodeIndexOf(2), 1, wire));
            try testing.expectEqual(Outcome.duplicate, try mesh.inject(mesh.nodeIndexOf(3), 1, wire));
        }
        try testing.expect(d_events >= 1);
        _ = try mesh.settle(200);
        try testing.expectEqual(converged, try expectConverged(&mesh, false));
    }
}

// ---------------------------------------------------------------------------
// Test 7: the full partition/skew/crash program replays byte-for-byte.
// ---------------------------------------------------------------------------

const ProgramResult = struct {
    digest: Digest,
    /// Accepted-but-unflushed events the scripted crash discarded.
    unflushed_lost: usize,
};

fn runFullProgram(allocator: Allocator, seed: u64, topo: *const Topology) !ProgramResult {
    const early_step = [_]ClockStep{.{ .at_round = 22, .delta_ms = -2_000 }};
    const restart_step = [_]ClockStep{.{ .at_round = 30, .delta_ms = -3_000 }};
    var specs = [_]ClockSpec{
        .{ .offset_ms = 0, .drift_ppm = 200, .steps = &early_step },
        .{ .offset_ms = 1_500, .drift_ppm = -300 },
        .{ .offset_ms = -900, .drift_ppm = 100 },
        .{ .offset_ms = 400, .drift_ppm = 50 },
        .{ .offset_ms = -200, .drift_ppm = -80 },
    };
    const middle = topo.nodes.len / 2;
    specs[middle].steps = &restart_step;
    var mesh = try Mesh.init(allocator, seed, topo, .{ .clock_specs = specs[0..topo.nodes.len] });
    defer mesh.deinit();

    const e0 = topo.edges[0];
    const middle_id = topo.nodes[middle];
    const script = [_]ScriptEntry{
        .{ .at_round = 10, .action = .{ .cut = .{ e0.a, e0.b } } },
        .{ .at_round = 18, .action = .{ .crash = middle_id } },
        .{ .at_round = 30, .action = .{ .restore = middle_id } },
        .{ .at_round = 34, .action = .{ .heal = .{ e0.a, e0.b } } },
    };
    try mesh.runRounds(.{ .rounds = 50, .max_authored = 10, .crdt_probability = 0.3, .script = &script });
    _ = try mesh.settle(800);
    var neighbor_buf: [max_nodes]u64 = undefined;
    const first = topo.nodes[0];
    try expectHostileRejected(&mesh, first, topo.neighborsInto(first, &neighbor_buf)[0]);
    _ = try mesh.settle(200);
    _ = try expectConverged(&mesh, true);
    var unflushed_lost: usize = 0;
    for (mesh.nodes) |node| unflushed_lost += node.stats.unflushed_lost;
    return .{ .digest = try mesh.finalDigest(), .unflushed_lost = unflushed_lost };
}

test "M08 recovery DST: the full partition/skew/crash program replays byte-for-byte from its seed (equal trace hashes)" {
    const topos = [_]*const Topology{ &topology_line_abc, &topology_diamond, &topology_ring_chord };
    var unflushed_lost: usize = 0;
    for (topos) |topo| {
        var seed: u64 = 0x7000;
        while (seed < 0x7000 + 3) : (seed += 1) {
            errdefer std.debug.print("M08 replay failed: topo={s} seed=0x{x}\n", .{ topo.name, seed });
            const first = try runFullProgram(testing.allocator, seed, topo);
            const second = try runFullProgram(testing.allocator, seed, topo);
            try testing.expectEqualSlices(u8, &first.digest, &second.digest);
            try testing.expectEqual(first.unflushed_lost, second.unflushed_lost);
            unflushed_lost += first.unflushed_lost;
        }
    }
    // The scripted crashes really hit the admit-to-flush window.
    try testing.expect(unflushed_lost > 0);
    // Distinct seeds must diverge, catching a degenerate always-equal hash.
    const a = try runFullProgram(testing.allocator, 0x7000, &topology_line_abc);
    const b = try runFullProgram(testing.allocator, 0x7001, &topology_line_abc);
    try testing.expect(!std.mem.eql(u8, &a.digest, &b.digest));
}

// ---------------------------------------------------------------------------
// Test 8: allocation failure sweeps.
// ---------------------------------------------------------------------------

/// Smallest complete partition/rejoin program: C authors while B-C is cut,
/// so the event can only arrive through RVL2 repair after the heal. Repair is
/// sparse so each run stays small enough to sweep every allocation index;
/// convergence is checked structurally (signature checks run elsewhere).
fn tinyPartitionProgram(allocator: Allocator) !void {
    var mesh = try Mesh.init(allocator, 0x8042, &topology_line_abc, .{
        .fault = reliable_profile,
        .audit_rejections = false,
    });
    defer mesh.deinit();
    mesh.setEdge(2, 3, false);
    const id = try mesh.authorAt(2, "y");
    try mesh.runRounds(.{ .rounds = 2, .author_probability = 0, .repair_every = 0 });
    try testing.expect(!mesh.nodes[1].published.contains(id));
    mesh.setEdge(2, 3, true);
    _ = try mesh.settleEvery(40, 4);
    for (mesh.nodes) |*node| {
        try testing.expectEqual(@as(usize, 1), node.published.count());
        try testing.expectEqual(@as(usize, 1), node.stats.accepted);
        try testing.expect(node.published.contains(id));
        try testing.expectEqual(@as(usize, 0), node.log.len());
    }
}

/// Repeat `op` with allocation failure injected at every successive index
/// until it succeeds. Each failed attempt must return OutOfMemory and leave
/// the whole harness byte-identical. Returns the number of failed attempts.
fn expectAtomicUnderOom(failing: *std.testing.FailingAllocator, mesh: *Mesh, op: anytype) !usize {
    var offset: usize = 0;
    while (offset <= 4096) : (offset += 1) {
        const before = try mesh.meshDigest(testing.allocator);
        failing.fail_index = failing.alloc_index + offset;
        const result = op.run(mesh);
        failing.fail_index = std.math.maxInt(usize);
        if (result) |_| {
            return offset;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqualSlices(u8, &before, &(try mesh.meshDigest(testing.allocator)));
        }
    }
    return error.TestUnexpectedResult;
}

test "M08 recovery DST: A-B-C partition/rejoin run is leak-free and transactional under checkAllAllocationFailures" {
    try testing.checkAllAllocationFailures(testing.allocator, tinyPartitionProgram, .{});

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
    var mesh = try Mesh.init(failing.allocator(), 0x8043, &topology_line_abc, .{
        .fault = reliable_profile,
        .audit_rejections = false,
    });
    defer mesh.deinit();

    // Local authorship at A.
    const LocalAuthor = struct {
        fn run(_: @This(), m: *Mesh) !void {
            _ = try m.authorAt(0, "sweep");
        }
    };
    try testing.expect(try expectAtomicUnderOom(&failing, &mesh, LocalAuthor{}) > 0);
    const relay_id = mesh.authored.items[0];
    try testing.expect(!mesh.nodes[0].published.contains(relay_id));

    // Durable flush and release at A.
    const Flush = struct {
        index: usize,
        fn run(self: @This(), m: *Mesh) !void {
            try m.flushNode(self.index);
        }
    };
    try testing.expect(try expectAtomicUnderOom(&failing, &mesh, Flush{ .index = 0 }) > 0);
    try testing.expectEqual(@as(usize, 0), mesh.nodes[0].pending.items.len);
    const wire = try testing.allocator.dupe(u8, mesh.nodes[0].published.get(relay_id).?);
    defer testing.allocator.free(wire);

    // First remote admission at B: decode, probe, reservations, RVL2, RVG2.
    const RemoteAdmit = struct {
        wire: []const u8,
        fn run(self: @This(), m: *Mesh) !void {
            if (try m.admitAudited(1, 1, self.wire, null) != .accepted) return error.TestUnexpectedResult;
        }
    };
    try testing.expect(try expectAtomicUnderOom(&failing, &mesh, RemoteAdmit{ .wire = wire }) > 0);
    try testing.expectEqual(@as(usize, 0), mesh.nodes[1].published.count());
    // Unflushed duplicate: neither ACKed nor recorded.
    try testing.expectEqual(Outcome.duplicate, try mesh.admitAudited(1, 1, wire, null));
    try testing.expect(try expectAtomicUnderOom(&failing, &mesh, Flush{ .index = 1 }) > 0);
    try testing.expectEqual(@as(usize, 1), mesh.nodes[1].published.count());
    try testing.expectEqual(Outcome.duplicate, try mesh.admitAudited(1, 1, wire, null));

    // Durable ACK confirmation at A.
    const Ack = struct {
        id: RelayId,
        fn run(self: @This(), m: *Mesh) !void {
            try m.applyAck(0, 2, self.id);
        }
    };
    _ = try expectAtomicUnderOom(&failing, &mesh, Ack{ .id = relay_id });
    try testing.expect(!mesh.nodes[0].log.contains(relay_id) or mesh.nodes[0].log.isConfirmedBy(relay_id, 2));

    // Crash and checkpoint restore at B. The crash captures nothing (the
    // image was flushed earlier); any allocation it makes must still be
    // atomic.
    const Crash = struct {
        fn run(_: @This(), m: *Mesh) !void {
            try m.crashNode(2);
        }
    };
    _ = try expectAtomicUnderOom(&failing, &mesh, Crash{});
    try testing.expect(!mesh.nodes[1].alive);
    const Restore = struct {
        fn run(_: @This(), m: *Mesh) !void {
            try m.restoreFromDurable(2);
        }
    };
    try testing.expect(try expectAtomicUnderOom(&failing, &mesh, Restore{}) > 0);
    try testing.expect(mesh.nodes[1].alive);
    try testing.expect(mesh.nodes[1].log.contains(relay_id));
    try testing.expectEqual(Outcome.duplicate, try mesh.admitAudited(1, 1, wire, null));

    _ = try mesh.settle(60);
    try testing.expectEqual(@as(usize, 1), try expectConverged(&mesh, true));
}
