// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Measured-cost route selection with time-based hysteresis.
//!
//! Pure leaf: `std`, `link_health.zig`, and the substrate `mesh_topology.zig`
//! (for `NodeId`) only. No sockets, no files, no clock reads: every timestamp
//! is a caller-supplied monotonic millisecond value.
//!
//! Authority boundary. This module ranks next hops that the caller's
//! authority layer (for example session-replica `Store.hasReplicaParent` plus
//! a secured-peer check) has already accepted. It never reads signed frames,
//! origins, accounts, or wire bytes. `Candidate` deliberately carries only
//! `{next_hop, cost}` so no route can be smuggled past the caller's check, and
//! `Selector.select` returns either `null` or a `next_hop` copied from the
//! caller's candidate slice for that call. A hop that appears with any
//! ineligible (`null`) entry in the slice is ineligible as a whole, so a
//! duplicate entry can only narrow the choice, never widen it.
//!
//! Hysteresis guards only a *voluntary* switch to a cheaper path: a challenger
//! must beat the incumbent by more than `max(abs_margin, incumbent *
//! rel_margin_pct / 100)`, hold that lead for `min_challenge_ms`, and the
//! incumbent must have held the slot for `min_dwell_ms`. An incumbent that is
//! absent from the candidate set, or ineligible, is replaced at once.
//!
//! Cost contract. `Candidate.cost` is the end-to-end cost of reaching the
//! destination through `next_hop`, never the cost of the first link alone.
//! `measuredLinkCost` is one link; it is a valid `Candidate.cost` only when
//! the destination is that link's peer. For every destination `PathGraph`
//! sums measured link costs along BFS-shortest paths and emits one
//! candidate per local first hop, so a cheap first link followed by a slow
//! one cannot beat a route that is cheaper end to end. `Selector` is the
//! only hysteresis layer: feed it `PathGraph.candidates`, not
//! `mesh_topology.Topology.nextHop`, which has already applied its own static
//! margin and exposes a single hop per destination.

const std = @import("std");
const link_health = @import("link_health.zig");
const mesh_topology = @import("../substrate/undertow/mesh_topology.zig");

pub const NodeId = mesh_topology.NodeId;

// -- measuredLinkCost ---------------------------------------------------

/// Ceiling of every cost this module produces. Small enough that sums of a
/// few costs never approach `u32` overflow in callers.
pub const max_link_cost: u32 = 60_000;

/// Cap on the backlog contribution so one congested queue cannot dominate the
/// RTT signal without bound.
pub const max_backlog_penalty: u32 = 2_000;

/// Queued send bytes per unit of backlog penalty.
pub const backlog_bytes_per_cost_unit: u64 = 4_096;

/// Flat penalty while Ripple suspects the peer. A `.dead` peer is excluded
/// (cost `null`), never merely penalised.
pub const suspect_penalty: u32 = 500;

/// Measured cost of forwarding over the single link `h`, or `null` when the
/// link cannot be chosen: not `.established`, partitioned, Ripple-dead, or no
/// RTT sample. Use it as a `MeasuredEdge.cost`; it is a `Candidate.cost` only
/// for the destination at the far end of this link.
///
///   clamp(snapshotRtt + 2*jitterMs + backlogPenalty + suspectPenalty, 1, max_link_cost)
///
/// Every term is bounded (`u32` RTT/jitter, capped backlog, constant suspect
/// penalty) and summed in `u64`, so no input can overflow before the clamp.
/// `now_ms` is accepted for interface stability with time-weighted callers;
/// the current cost depends only on the snapshot fields.
pub fn measuredLinkCost(h: *const link_health.LinkHealth, now_ms: u64) ?u32 {
    _ = now_ms;
    if (h.state != .established) return null;
    if (h.partitioned) return null;
    if (h.ripple == .dead) return null;
    if (h.ewma_rtt_ms == null or h.rtt_count == 0) return null;

    const rtt: u64 = h.snapshotRtt();
    const jitter: u64 = h.jitterMs();
    const backlog: u64 = backlogPenalty(h.send_backlog_bytes);
    const suspect: u64 = if (h.ripple == .suspect) suspect_penalty else 0;
    const total = rtt + 2 * jitter + backlog + suspect;
    return @intCast(std.math.clamp(total, 1, @as(u64, max_link_cost)));
}

fn backlogPenalty(bytes: u64) u64 {
    return @min(bytes / backlog_bytes_per_cost_unit, @as(u64, max_backlog_penalty));
}

// -- Selector -------------------------------------------------------------

pub const default_max_destinations: usize = 4_096;
pub const default_abs_margin: u32 = 5;
pub const default_rel_margin_pct: u32 = 10;
pub const default_min_dwell_ms: u64 = 5_000;
pub const default_min_challenge_ms: u64 = 2_000;

/// Hard bound on one `select` call's candidate slice. Duplicate-hop
/// canonicalisation is quadratic in the slice length, so the bound keeps a
/// call's work fixed. Mesh peer fan-out is far below this.
pub const max_candidates: usize = 256;

/// One authority-accepted next hop toward a destination. `cost` is the
/// end-to-end path cost through `next_hop` (see `PathGraph`). `cost == null`
/// means the route exists but cannot be chosen now (some link on every
/// shortest path through `next_hop` is unusable).
pub const Candidate = struct {
    next_hop: NodeId,
    cost: ?u32,
};

pub const Reason = enum {
    /// First decision for an untracked destination.
    initial_choice,
    /// Incumbent kept; no challenger beats it by the margin.
    kept_incumbent,
    /// Incumbent kept; a challenger beats it by the margin but has not held
    /// the lead for `min_challenge_ms`, or dwell is not yet complete.
    challenge_pending,
    /// Sustained challenger after dwell: switched.
    switched_challenger_sustained,
    /// Incumbent absent or ineligible: switched to the cheapest eligible.
    failover_incumbent_ineligible,
    /// Empty or all-ineligible candidate set. Tracking for the destination is
    /// dropped.
    no_eligible_candidate,
};

pub const Decision = struct {
    /// `null` or a hop copied from this call's candidate slice.
    next_hop: ?NodeId,
    /// `next_hop` differs from the hop this selector previously held for the
    /// destination. Always false for `initial_choice`.
    switched: bool,
    reason: Reason,
};

pub const SelectError = std.mem.Allocator.Error || error{
    /// A new destination was refused at `max_destinations`. Tracked
    /// destinations are unaffected.
    TooManyDestinations,
    /// The candidate slice exceeds `max_candidates`. No state changed.
    TooManyCandidates,
};

/// Per-destination hysteresis state.
pub const Incumbent = struct {
    next_hop: NodeId,
    /// Effective cost of `next_hop` at the most recent `select`.
    cost: u32,
    selected_at_ms: u64,
    /// Challenger currently beating the incumbent by the margin, if any.
    challenger: ?NodeId = null,
    /// When `challenger` started its uninterrupted lead. Meaningful only
    /// while `challenger != null`.
    challenger_since_ms: u64 = 0,
};

pub const Options = struct {
    max_destinations: usize = default_max_destinations,
    abs_margin: u32 = default_abs_margin,
    rel_margin_pct: u32 = default_rel_margin_pct,
    min_dwell_ms: u64 = default_min_dwell_ms,
    min_challenge_ms: u64 = default_min_challenge_ms,
};

/// Bounded per-destination next-hop chooser. In-memory only; owns no
/// authority. Not thread-safe: use from one reactor.
pub const Selector = struct {
    allocator: std.mem.Allocator,
    incumbents: std.AutoArrayHashMapUnmanaged(NodeId, Incumbent) = .empty,
    options: Options,

    pub fn init(allocator: std.mem.Allocator) Selector {
        return initWithOptions(allocator, .{});
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, options: Options) Selector {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *Selector) void {
        self.incumbents.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const Selector) usize {
        return self.incumbents.count();
    }

    /// Current hysteresis state for `dest`, for oper/diagnostic views.
    pub fn current(self: *const Selector, dest: NodeId) ?Incumbent {
        return self.incumbents.get(dest);
    }

    /// Drop all hysteresis memory for `dest`.
    pub fn forget(self: *Selector, dest: NodeId) void {
        _ = self.incumbents.swapRemove(dest);
    }

    /// `peer` went down: drop every incumbent routed through it so the next
    /// `select` fails over without hysteresis, and cancel any challenge led by
    /// it so a dead challenger cannot later win on elapsed time. O(n), no
    /// allocation.
    pub fn invalidatePeer(self: *Selector, peer: NodeId) void {
        var i = self.incumbents.count();
        while (i > 0) {
            i -= 1;
            const value = &self.incumbents.values()[i];
            if (value.next_hop == peer) {
                // Moves the last entry (already visited) into `i`.
                self.incumbents.swapRemoveAt(i);
                continue;
            }
            if (value.challenger) |c| if (c == peer) {
                value.challenger = null;
            };
        }
    }

    /// Choose a next hop for `dest` from authority-accepted `candidates`.
    ///
    /// On any error no state changes. The returned hop is `null` or a member
    /// of `candidates` whose every entry is eligible.
    pub fn select(self: *Selector, dest: NodeId, candidates: []const Candidate, now_ms: u64) SelectError!Decision {
        if (candidates.len > max_candidates) return error.TooManyCandidates;

        const index = self.incumbents.getIndex(dest) orelse {
            const best = cheapestEligible(candidates, null) orelse
                return .{ .next_hop = null, .switched = false, .reason = .no_eligible_candidate };
            if (self.incumbents.count() >= self.options.max_destinations) return error.TooManyDestinations;
            try self.incumbents.put(self.allocator, dest, .{
                .next_hop = best.next_hop,
                .cost = best.cost,
                .selected_at_ms = now_ms,
            });
            return .{ .next_hop = best.next_hop, .switched = false, .reason = .initial_choice };
        };
        const inc = &self.incumbents.values()[index];

        inc.cost = switch (eligibility(candidates, inc.next_hop)) {
            .cost => |cost| cost,
            .absent, .ineligible => {
                const best = cheapestEligible(candidates, null) orelse {
                    self.incumbents.swapRemoveAt(index);
                    return .{ .next_hop = null, .switched = true, .reason = .no_eligible_candidate };
                };
                // `best` is eligible and the old hop is not, so they differ.
                inc.* = .{ .next_hop = best.next_hop, .cost = best.cost, .selected_at_ms = now_ms };
                return .{ .next_hop = best.next_hop, .switched = true, .reason = .failover_incumbent_ineligible };
            },
        };

        // Keep the tracked challenger's timer while it still leads by the
        // margin, even if another hop is momentarily cheaper; otherwise two
        // alternating challengers could each reset the other forever.
        const target: Pick = keep: {
            if (inc.challenger) |tracked| {
                switch (eligibility(candidates, tracked)) {
                    .cost => |cost| if (self.beats(inc.cost, cost))
                        break :keep .{ .next_hop = tracked, .cost = cost },
                    .absent, .ineligible => {},
                }
            }
            inc.challenger = null;
            const best = cheapestEligible(candidates, inc.next_hop) orelse
                return .{ .next_hop = inc.next_hop, .switched = false, .reason = .kept_incumbent };
            if (!self.beats(inc.cost, best.cost))
                return .{ .next_hop = inc.next_hop, .switched = false, .reason = .kept_incumbent };
            inc.challenger = best.next_hop;
            inc.challenger_since_ms = now_ms;
            break :keep best;
        };

        if (elapsedAtLeast(now_ms, inc.selected_at_ms, self.options.min_dwell_ms) and
            elapsedAtLeast(now_ms, inc.challenger_since_ms, self.options.min_challenge_ms))
        {
            inc.* = .{ .next_hop = target.next_hop, .cost = target.cost, .selected_at_ms = now_ms };
            return .{ .next_hop = target.next_hop, .switched = true, .reason = .switched_challenger_sustained };
        }
        return .{ .next_hop = inc.next_hop, .switched = false, .reason = .challenge_pending };
    }

    /// `challenger` beats `incumbent` by strictly more than the margin.
    fn beats(self: *const Selector, incumbent: u32, challenger: u32) bool {
        if (challenger >= incumbent) return false;
        const rel: u64 = @as(u64, incumbent) * self.options.rel_margin_pct / 100;
        const margin = @max(@as(u64, self.options.abs_margin), rel);
        return @as(u64, incumbent - challenger) > margin;
    }
};

/// Deterministic, order-independent cheapest eligible hop with no hysteresis
/// state. Callers use it to degrade when `Selector.select` reports
/// `OutOfMemory` or `TooManyDestinations`; it has the same authority
/// guarantee as `select`.
pub fn cheapest(candidates: []const Candidate) error{TooManyCandidates}!?Candidate {
    if (candidates.len > max_candidates) return error.TooManyCandidates;
    const best = cheapestEligible(candidates, null) orelse return null;
    return .{ .next_hop = best.next_hop, .cost = best.cost };
}

// -- PathGraph --------------------------------------------------------------

/// Hard bound on the edge slice given to `PathGraph.init`, keeping build
/// memory and per-destination work fixed.
pub const max_path_edges: usize = 16_384;

/// One undirected link with its caller-supplied measured cost. `cost == null`
/// means the link is known but cannot carry traffic now. A remote link that
/// this node does not measure must be supplied by the caller (for example a
/// gossiped measurement); this module never invents a cost.
pub const MeasuredEdge = struct {
    a: NodeId,
    b: NodeId,
    cost: ?u32,
};

pub const PathGraphError = std.mem.Allocator.Error || error{
    /// The edge slice exceeds `max_path_edges`. Nothing was allocated.
    TooManyEdges,
};

const no_path: u64 = std.math.maxInt(u64);
const unreached: u32 = std.math.maxInt(u32);

const PathLink = struct {
    to: u32,
    cost: ?u32,
};

/// Measured-cost view of the mesh rooted at `local`, producing end-to-end
/// `Candidate`s per destination.
///
/// BFS over every known link alone decides reachability, hop distance and
/// which local neighbours are next-hop candidates (those on a BFS-shortest
/// path), matching `mesh_topology`: cost never creates a route and never
/// lengthens one. A candidate's cost is the cheapest sum of link costs over
/// the shortest paths through it; it is `null` when every such path crosses
/// an unusable (`null`) link. Duplicate links canonicalise like duplicate
/// candidates: any `null` entry makes the link unusable, otherwise the worst
/// cost wins, so results are independent of edge order.
///
/// Built once per topology/measurement change; `candidates` then reuses
/// preallocated scratch and never allocates. Not thread-safe.
pub const PathGraph = struct {
    local: u32,
    /// Sorted, unique node ids; a node's index is its position here.
    nodes: []NodeId,
    /// CSR adjacency: `links[offsets[i]..offsets[i + 1]]`, sorted by `to`,
    /// one canonical entry per neighbour.
    offsets: []u32,
    links: []PathLink,
    // Per-destination scratch.
    dist: []u32,
    best: []u64,
    queue: []u32,

    /// On error nothing is retained.
    pub fn init(allocator: std.mem.Allocator, local: NodeId, edges: []const MeasuredEdge) PathGraphError!PathGraph {
        if (edges.len > max_path_edges) return error.TooManyEdges;

        const ids = try allocator.alloc(NodeId, 2 * edges.len + 1);
        defer allocator.free(ids);
        ids[0] = local;
        for (edges, 0..) |e, i| {
            ids[1 + 2 * i] = e.a;
            ids[2 + 2 * i] = e.b;
        }
        std.mem.sort(NodeId, ids, {}, std.sort.asc(NodeId));
        var n: usize = 0;
        for (ids) |id| {
            if (n != 0 and ids[n - 1] == id) continue;
            ids[n] = id;
            n += 1;
        }

        const nodes = try allocator.dupe(NodeId, ids[0..n]);
        errdefer allocator.free(nodes);
        const offsets = try allocator.alloc(u32, n + 1);
        errdefer allocator.free(offsets);
        var links = try allocator.alloc(PathLink, 2 * edges.len);
        errdefer allocator.free(links);
        const dist = try allocator.alloc(u32, n);
        errdefer allocator.free(dist);
        const best = try allocator.alloc(u64, n);
        errdefer allocator.free(best);
        const queue = try allocator.alloc(u32, n);
        errdefer allocator.free(queue);

        // Counting sort of directed half-edges into CSR; self-loops dropped.
        @memset(offsets, 0);
        for (edges) |e| {
            if (e.a == e.b) continue;
            offsets[indexOf(nodes, e.a).? + 1] += 1;
            offsets[indexOf(nodes, e.b).? + 1] += 1;
        }
        for (1..offsets.len) |i| offsets[i] += offsets[i - 1];
        @memcpy(queue, offsets[0..n]); // fill cursor per node
        for (edges) |e| {
            if (e.a == e.b) continue;
            const ia = indexOf(nodes, e.a).?;
            const ib = indexOf(nodes, e.b).?;
            links[queue[ia]] = .{ .to = ib, .cost = e.cost };
            queue[ia] += 1;
            links[queue[ib]] = .{ .to = ia, .cost = e.cost };
            queue[ib] += 1;
        }

        // Sort each node's links and merge duplicates in place (`w` never
        // passes the read cursor, and `offsets[i + 1]` is read before it is
        // rewritten on the next iteration).
        var w: u32 = 0;
        for (0..n) |i| {
            const start = offsets[i];
            const end = offsets[i + 1];
            const run = links[start..end];
            std.mem.sort(PathLink, run, {}, lessPathLink);
            offsets[i] = w;
            for (run) |link| {
                if (w > offsets[i] and links[w - 1].to == link.to) {
                    links[w - 1].cost = worstCost(links[w - 1].cost, link.cost);
                    continue;
                }
                links[w] = link;
                w += 1;
            }
        }
        offsets[n] = w;

        return .{
            .local = indexOf(nodes, local).?,
            .nodes = nodes,
            .offsets = offsets,
            .links = links,
            .dist = dist,
            .best = best,
            .queue = queue,
        };
    }

    pub fn deinit(self: *PathGraph, allocator: std.mem.Allocator) void {
        allocator.free(self.nodes);
        allocator.free(self.offsets);
        allocator.free(self.links);
        allocator.free(self.dist);
        allocator.free(self.best);
        allocator.free(self.queue);
        self.* = undefined;
    }

    /// End-to-end candidates toward `dest`, written into `out` sorted by
    /// `next_hop`. Empty when `dest` is local, unknown or unreachable. Every
    /// `next_hop` is a neighbour of `local` in the caller's edges; the caller
    /// still intersects with its authority layer before `Selector.select`.
    /// Fails closed with `TooManyCandidates` (no partial set) when more
    /// candidates exist than fit `out`. Never allocates.
    pub fn candidates(self: *PathGraph, dest: NodeId, out: []Candidate) error{TooManyCandidates}![]Candidate {
        const d = indexOf(self.nodes, dest) orelse return out[0..0];
        if (d == self.local) return out[0..0];

        // BFS from `dest`; `queue` ends in nondecreasing distance order.
        @memset(self.dist, unreached);
        self.dist[d] = 0;
        self.queue[0] = d;
        var head: usize = 0;
        var tail: usize = 1;
        while (head < tail) : (head += 1) {
            const v = self.queue[head];
            for (self.neighbours(v)) |link| {
                if (self.dist[link.to] != unreached) continue;
                self.dist[link.to] = self.dist[v] + 1;
                self.queue[tail] = link.to;
                tail += 1;
            }
        }
        const local_dist = self.dist[self.local];
        if (local_dist == unreached) return out[0..0];

        // Cheapest usable cost to `dest` over shortest paths only: a node at
        // distance k extends only neighbours at distance k - 1, which BFS
        // order has already finalised. Sums stay far below u64 overflow
        // (at most 2 * max_path_edges + 1 hops of at most maxInt(u32)).
        self.best[d] = 0;
        for (self.queue[1..tail]) |v| {
            var cheapest_cost = no_path;
            for (self.neighbours(v)) |link| {
                if (self.dist[link.to] + 1 != self.dist[v]) continue;
                const link_cost = link.cost orelse continue;
                const rest = self.best[link.to];
                if (rest == no_path) continue;
                cheapest_cost = @min(cheapest_cost, rest + link_cost);
            }
            self.best[v] = cheapest_cost;
        }

        var count: usize = 0;
        for (self.neighbours(self.local)) |link| {
            if (self.dist[link.to] + 1 != local_dist) continue;
            if (count == out.len) return error.TooManyCandidates;
            const rest = self.best[link.to];
            out[count] = .{
                .next_hop = self.nodes[link.to],
                .cost = if (link.cost) |c| (if (rest == no_path) null else saturateU32(rest + c)) else null,
            };
            count += 1;
        }
        return out[0..count];
    }

    fn neighbours(self: *const PathGraph, v: u32) []const PathLink {
        return self.links[self.offsets[v]..self.offsets[v + 1]];
    }
};

fn indexOf(nodes: []const NodeId, id: NodeId) ?u32 {
    const i = std.sort.binarySearch(NodeId, nodes, id, orderNode) orelse return null;
    return @intCast(i);
}

fn orderNode(key: NodeId, item: NodeId) std.math.Order {
    return std.math.order(key, item);
}

fn lessPathLink(_: void, a: PathLink, b: PathLink) bool {
    return a.to < b.to;
}

/// Duplicate-link canonicalisation: unusable dominates, else the worst cost.
fn worstCost(a: ?u32, b: ?u32) ?u32 {
    return @max(a orelse return null, b orelse return null);
}

fn saturateU32(v: u64) u32 {
    return @intCast(@min(v, @as(u64, std.math.maxInt(u32))));
}

/// False when the clock moved backwards: a voluntary switch is never made on
/// a non-monotonic reading (failover does not depend on elapsed time).
fn elapsedAtLeast(now_ms: u64, since_ms: u64, min_ms: u64) bool {
    if (now_ms < since_ms) return false;
    return now_ms - since_ms >= min_ms;
}

const Pick = struct {
    next_hop: NodeId,
    cost: u32,
};

const Eligibility = union(enum) {
    absent,
    ineligible,
    cost: u32,
};

/// Canonical view of `hop` in `candidates`: any `null` entry makes the hop
/// ineligible; otherwise its cost is the worst (highest) duplicate entry.
fn eligibility(candidates: []const Candidate, hop: NodeId) Eligibility {
    var worst: ?u32 = null;
    for (candidates) |c| {
        if (c.next_hop != hop) continue;
        const cost = c.cost orelse return .ineligible;
        worst = @max(worst orelse cost, cost);
    }
    return if (worst) |cost| .{ .cost = cost } else .absent;
}

/// Cheapest canonically eligible hop, excluding `exclude`. Ties go to the
/// lowest `NodeId`.
fn cheapestEligible(candidates: []const Candidate, exclude: ?NodeId) ?Pick {
    var best: ?Pick = null;
    for (candidates) |c| {
        if (c.cost == null) continue;
        if (exclude) |x| if (c.next_hop == x) continue;
        const cost = switch (eligibility(candidates, c.next_hop)) {
            .cost => |cost| cost,
            .absent, .ineligible => continue,
        };
        if (best) |b| {
            if (cost > b.cost or (cost == b.cost and c.next_hop >= b.next_hop)) continue;
        }
        best = .{ .next_hop = c.next_hop, .cost = cost };
    }
    return best;
}

// -- PeerRanking --------------------------------------------------------------

/// Hard bound on adjacent peers `PeerRanking` tracks. Matches the mesh status
/// view (`mesh_report.Status.max_peers`); the trust-root membership that feeds
/// MESSAGE_V2 is far smaller in practice.
pub const max_ranked_peers: usize = 256;

pub const RankOptions = struct {
    abs_margin: u32 = default_abs_margin,
    rel_margin_pct: u32 = default_rel_margin_pct,
    /// A cost change beyond the margin must persist this long before the
    /// ranked cost follows it. Also delays promotion of an ineligible peer.
    min_challenge_ms: u64 = default_min_challenge_ms,
    /// Minimum time between two voluntary changes of one peer's ranked cost.
    min_dwell_ms: u64 = default_min_dwell_ms,
};

/// Ordering class of one peer. Lower sorts first.
pub const RankClass = enum(u2) {
    /// Ranked with a usable measured cost.
    eligible = 0,
    /// Not tracked (table full, or never observed): ordering only, it is never
    /// dropped from a fan-out.
    unranked = 1,
    /// Tracked but currently unusable (down, partitioned, Ripple-dead, no RTT
    /// sample, or recently recovered and still inside the promotion delay).
    ineligible = 2,
};

/// Totally ordered sort key for one adjacent peer.
pub const RankKey = struct {
    class: RankClass,
    cost: u32,
    node: NodeId,

    pub fn lessThan(a: RankKey, b: RankKey) bool {
        if (a.class != b.class) return @backingInt(a.class) < @backingInt(b.class);
        if (a.cost != b.cost) return a.cost < b.cost;
        return a.node < b.node;
    }
};

pub const RankStats = struct {
    observations: u64 = 0,
    /// The ranked cost of a peer changed (promotion, demotion, or a sustained
    /// move beyond the margin). Initial insertion is not a change.
    changes: u64 = 0,
    /// Ranked cost moved to ineligible immediately.
    demotions: u64 = 0,
    /// Ineligible peer became eligible after the promotion delay.
    promotions: u64 = 0,
    /// Observation of a beyond-margin move that hysteresis held back.
    held: u64 = 0,
    /// New peer refused because the table was full of peers observed in the
    /// current refresh.
    refused: u64 = 0,
};

pub const PeerRank = struct {
    node: NodeId,
    /// Ranked (stabilised) cost; `null` = ineligible.
    ranked: ?u32,
    /// Most recent raw observation, for diagnostics.
    last_raw: ?u32,
    changed_at_ms: u64,
    /// Raw cost of the pending beyond-margin move, if any. A pending move to
    /// eligibility from `ranked == null` is recorded with `pending_cost` set.
    pending: bool = false,
    pending_cost: u32 = 0,
    pending_since_ms: u64 = 0,
    /// Refresh generation that last observed this peer.
    seen_generation: u64 = 0,
};

/// Hysteresis-stable ranking of directly adjacent peers by measured link cost,
/// used only to ORDER emission across a fan-out set the caller has already
/// decided. It never adds, removes, or substitutes a peer, so custody and
/// exact-once obligations are unchanged by construction.
///
/// Anti-flap rules: a peer becoming unusable is demoted at once (fail closed);
/// any other change of the ranked cost (including promotion back to eligible)
/// needs a beyond-margin move sustained for `min_challenge_ms`, and at least
/// `min_dwell_ms` since the previous change. A backward clock never triggers a
/// voluntary change.
///
/// Fixed storage, no allocation, so every mutation is allocation-failure
/// trivially atomic. Process-local soft state: it is rebuilt from fresh RTT
/// samples after restart or Helix upgrade and is deliberately not migrated.
/// Not thread-safe: use from the reactor that owns the mesh links.
pub const PeerRanking = struct {
    entries: [max_ranked_peers]PeerRank = undefined,
    len: usize = 0,
    generation: u64 = 1,
    options: RankOptions = .{},
    stats: RankStats = .{},

    pub fn init(options: RankOptions) PeerRanking {
        return .{ .options = options };
    }

    pub fn get(self: *const PeerRanking, node: NodeId) ?PeerRank {
        const i = self.indexOf(node) orelse return null;
        return self.entries[i];
    }

    pub fn key(self: *const PeerRanking, node: NodeId) RankKey {
        const i = self.indexOf(node) orelse return .{ .class = .unranked, .cost = 0, .node = node };
        const entry = &self.entries[i];
        return if (entry.ranked) |cost|
            .{ .class = .eligible, .cost = cost, .node = node }
        else
            .{ .class = .ineligible, .cost = 0, .node = node };
    }

    /// Start a refresh pass: peers not observed before `endRefresh` are demoted.
    pub fn beginRefresh(self: *PeerRanking) void {
        self.generation +%= 1;
        if (self.generation == 0) self.generation = 1;
    }

    /// Demote every tracked peer the current refresh did not observe (its link
    /// is gone or not established). The entry is kept so the promotion delay
    /// still damps a flapping reconnect.
    pub fn endRefresh(self: *PeerRanking, now_ms: u64) void {
        for (self.entries[0..self.len]) |*entry| {
            if (entry.seen_generation == self.generation) continue;
            self.apply(entry, null, now_ms);
        }
    }

    /// Record one measurement. `cost == null` means the link is unusable now.
    /// Returns false only when a new peer was refused (table full of peers
    /// seen in this refresh); nothing changed in that case.
    pub fn observe(self: *PeerRanking, node: NodeId, cost: ?u32, now_ms: u64) bool {
        if (self.indexOf(node)) |i| {
            const entry = &self.entries[i];
            entry.seen_generation = self.generation;
            self.stats.observations +|= 1;
            self.apply(entry, cost, now_ms);
            return true;
        }
        const slot = if (self.len < max_ranked_peers) blk: {
            self.len += 1;
            break :blk self.len - 1;
        } else self.evictableIndex() orelse {
            self.stats.refused +|= 1;
            return false;
        };
        self.stats.observations +|= 1;
        self.entries[slot] = .{
            .node = node,
            .ranked = cost,
            .last_raw = cost,
            .changed_at_ms = now_ms,
            .seen_generation = self.generation,
        };
        return true;
    }

    /// Link to `node` dropped: demote immediately (no allocation, idempotent).
    pub fn noteDown(self: *PeerRanking, node: NodeId, now_ms: u64) void {
        const i = self.indexOf(node) orelse return;
        self.apply(&self.entries[i], null, now_ms);
    }

    pub fn forget(self: *PeerRanking, node: NodeId) void {
        const i = self.indexOf(node) orelse return;
        self.len -= 1;
        if (i != self.len) self.entries[i] = self.entries[self.len];
    }

    pub fn eligibleCount(self: *const PeerRanking) usize {
        var n: usize = 0;
        for (self.entries[0..self.len]) |entry| {
            if (entry.ranked != null) n += 1;
        }
        return n;
    }

    pub fn tracked(self: *const PeerRanking) []const PeerRank {
        return self.entries[0..self.len];
    }

    fn apply(self: *PeerRanking, entry: *PeerRank, cost: ?u32, now_ms: u64) void {
        entry.last_raw = cost;
        const raw = cost orelse {
            entry.pending = false;
            if (entry.ranked != null) {
                entry.ranked = null;
                entry.changed_at_ms = now_ms;
                self.stats.changes +|= 1;
                self.stats.demotions +|= 1;
            }
            return;
        };
        if (entry.ranked) |ranked| {
            if (!self.beyondMargin(ranked, raw)) {
                entry.pending = false;
                return;
            }
            // A pending move must keep its direction; reversing restarts it.
            if (entry.pending and ((entry.pending_cost < ranked) != (raw < ranked))) entry.pending = false;
        }
        if (!entry.pending) {
            entry.pending = true;
            entry.pending_since_ms = now_ms;
        }
        entry.pending_cost = raw;
        if (elapsedAtLeast(now_ms, entry.pending_since_ms, self.options.min_challenge_ms) and
            elapsedAtLeast(now_ms, entry.changed_at_ms, self.options.min_dwell_ms))
        {
            if (entry.ranked == null) self.stats.promotions +|= 1;
            entry.ranked = raw;
            entry.changed_at_ms = now_ms;
            entry.pending = false;
            self.stats.changes +|= 1;
            return;
        }
        self.stats.held +|= 1;
    }

    fn beyondMargin(self: *const PeerRanking, ranked: u32, raw: u32) bool {
        const diff: u64 = if (raw > ranked) raw - ranked else ranked - raw;
        const rel: u64 = @as(u64, ranked) * self.options.rel_margin_pct / 100;
        return diff > @max(@as(u64, self.options.abs_margin), rel);
    }

    fn indexOf(self: *const PeerRanking, node: NodeId) ?usize {
        for (self.entries[0..self.len], 0..) |entry, i| {
            if (entry.node == node) return i;
        }
        return null;
    }

    /// An entry not seen in the current refresh may make room for a live peer.
    fn evictableIndex(self: *const PeerRanking) ?usize {
        for (self.entries[0..self.len], 0..) |entry, i| {
            if (entry.seen_generation != self.generation) return i;
        }
        return null;
    }
};

// -- Tests ------------------------------------------------------------------

const testing = std.testing;

fn establishedHealth(now_ms: u64, rtt_ms: u32) link_health.LinkHealth {
    var h = link_health.LinkHealth.init(now_ms);
    h.transition(.established, now_ms);
    h.observeRtt(rtt_ms, now_ms);
    return h;
}

fn expectMember(candidates: []const Candidate, d: Decision) !void {
    const hop = d.next_hop orelse return;
    try testing.expect(eligibility(candidates, hop) == .cost);
}

test "route_cost: measuredLinkCost null for down/partitioned/ripple-dead/no-sample links" {
    for ([_]link_health.PeerState{ .connecting, .handshaking, .draining, .down }) |state| {
        var h = establishedHealth(0, 10);
        h.transition(state, 1);
        try testing.expectEqual(@as(?u32, null), measuredLinkCost(&h, 1));
    }

    var partitioned = establishedHealth(0, 10);
    partitioned.partitioned = true;
    try testing.expectEqual(@as(?u32, null), measuredLinkCost(&partitioned, 0));

    var dead = establishedHealth(0, 10);
    dead.ripple = .dead;
    try testing.expectEqual(@as(?u32, null), measuredLinkCost(&dead, 0));

    var no_sample = link_health.LinkHealth.init(0);
    no_sample.transition(.established, 0);
    try testing.expectEqual(@as(?u32, null), measuredLinkCost(&no_sample, 0));

    // The same link becomes eligible once it is established with a sample.
    try testing.expectEqual(@as(?u32, 10), measuredLinkCost(&establishedHealth(0, 10), 0));
}

test "route_cost: measuredLinkCost monotone in rtt, jitter and backlog; saturates at max_link_cost without overflow" {
    // Exact formula: rtt 20, one sample (no jitter), 8 KiB backlog (2 units).
    var exact = establishedHealth(0, 20);
    exact.noteSendBacklog(2 * backlog_bytes_per_cost_unit + 1);
    try testing.expectEqual(@as(?u32, 22), measuredLinkCost(&exact, 0));

    // Floor clamp: a 0 ms sample still yields the minimum cost of 1.
    try testing.expectEqual(@as(?u32, 1), measuredLinkCost(&establishedHealth(0, 0), 0));

    var prev: u32 = 0;
    for ([_]u32{ 1, 5, 20, 200, 2_000, 50_000 }) |rtt| {
        const cost = measuredLinkCost(&establishedHealth(0, rtt), 0).?;
        try testing.expect(cost > prev);
        prev = cost;
    }

    var steady = link_health.LinkHealth.init(0);
    steady.transition(.established, 0);
    var jittery = steady;
    for (0..4) |i| {
        steady.observeRtt(50, i);
        jittery.observeRtt(if (i % 2 == 0) 10 else 90, i);
    }
    try testing.expect(measuredLinkCost(&steady, 5).? < measuredLinkCost(&jittery, 5).?);

    prev = 0;
    for ([_]u64{ 0, 4_096, 65_536, 1 << 20 }) |bytes| {
        var h = establishedHealth(0, 20);
        h.noteSendBacklog(bytes);
        const cost = measuredLinkCost(&h, 0).?;
        try testing.expect(cost > prev);
        prev = cost;
    }

    // Backlog penalty is capped exactly.
    var capped = establishedHealth(0, 20);
    capped.noteSendBacklog(std.math.maxInt(u64));
    try testing.expectEqual(@as(?u32, 20 + max_backlog_penalty), measuredLinkCost(&capped, 0));

    var suspect = establishedHealth(0, 20);
    suspect.ripple = .suspect;
    try testing.expectEqual(@as(?u32, 20 + suspect_penalty), measuredLinkCost(&suspect, 0));

    // Saturation: extreme inputs clamp to the ceiling, never wrap or panic.
    var extreme = link_health.LinkHealth.init(0);
    extreme.transition(.established, 0);
    for (0..8) |i| extreme.observeRtt(if (i % 2 == 0) std.math.maxInt(u32) else 0, i);
    extreme.noteSendBacklog(std.math.maxInt(u64));
    extreme.ripple = .suspect;
    try testing.expectEqual(@as(?u32, max_link_cost), measuredLinkCost(&extreme, 9));
}

test "route_cost: selector picks the cheapest of several candidates on first decision, ties go to the lowest NodeId" {
    var sel = Selector.init(testing.allocator);
    defer sel.deinit();

    const orders = [_][3]Candidate{
        .{ .{ .next_hop = 30, .cost = 50 }, .{ .next_hop = 10, .cost = 20 }, .{ .next_hop = 20, .cost = 20 } },
        .{ .{ .next_hop = 20, .cost = 20 }, .{ .next_hop = 30, .cost = 50 }, .{ .next_hop = 10, .cost = 20 } },
        .{ .{ .next_hop = 10, .cost = 20 }, .{ .next_hop = 20, .cost = 20 }, .{ .next_hop = 30, .cost = 50 } },
    };
    for (orders, 0..) |cands, i| {
        const d = try sel.select(@intCast(100 + i), &cands, 0);
        try testing.expectEqual(@as(?NodeId, 10), d.next_hop);
        try testing.expectEqual(false, d.switched);
        try testing.expectEqual(Reason.initial_choice, d.reason);
        try testing.expectEqual(@as(u32, 20), sel.current(@intCast(100 + i)).?.cost);
    }
}

test "route_cost: sub-margin improvement keeps the incumbent (no switch)" {
    var sel = Selector.initWithOptions(testing.allocator, .{
        .abs_margin = 10,
        .rel_margin_pct = 0,
        .min_dwell_ms = 0,
        .min_challenge_ms = 0,
    });
    defer sel.deinit();

    _ = try sel.select(1, &.{.{ .next_hop = 1, .cost = 100 }}, 0);
    // Exactly at the margin (100 - 90 = 10) is not "more than" the margin.
    for ([_]u32{ 99, 95, 90 }) |c| {
        const d = try sel.select(1, &.{
            .{ .next_hop = 1, .cost = 100 },
            .{ .next_hop = 2, .cost = c },
        }, 1_000);
        try testing.expectEqual(@as(?NodeId, 1), d.next_hop);
        try testing.expectEqual(false, d.switched);
        try testing.expectEqual(Reason.kept_incumbent, d.reason);
        try testing.expectEqual(@as(?NodeId, null), sel.current(1).?.challenger);
    }

    // The relative margin dominates for large costs: 10% of 10_000 = 1_000.
    var rel = Selector.initWithOptions(testing.allocator, .{
        .abs_margin = 1,
        .rel_margin_pct = 10,
        .min_dwell_ms = 0,
        .min_challenge_ms = 0,
    });
    defer rel.deinit();
    _ = try rel.select(1, &.{.{ .next_hop = 1, .cost = 10_000 }}, 0);
    const kept = try rel.select(1, &.{
        .{ .next_hop = 1, .cost = 10_000 },
        .{ .next_hop = 2, .cost = 9_000 },
    }, 1);
    try testing.expectEqual(Reason.kept_incumbent, kept.reason);
    const moved = try rel.select(1, &.{
        .{ .next_hop = 1, .cost = 10_000 },
        .{ .next_hop = 2, .cost = 8_999 },
    }, 2);
    try testing.expectEqual(@as(?NodeId, 2), moved.next_hop);
    try testing.expectEqual(Reason.switched_challenger_sustained, moved.reason);
}

test "route_cost: above-margin improvement switches only after min_challenge_ms sustained lead and min_dwell_ms" {
    var sel = Selector.initWithOptions(testing.allocator, .{
        .abs_margin = 5,
        .rel_margin_pct = 0,
        .min_dwell_ms = 1_000,
        .min_challenge_ms = 500,
    });
    defer sel.deinit();

    _ = try sel.select(1, &.{.{ .next_hop = 1, .cost = 100 }}, 0);
    const cands = [_]Candidate{
        .{ .next_hop = 1, .cost = 100 },
        .{ .next_hop = 2, .cost = 50 },
    };

    // Lead starts at t=200; challenge would be sustained at 700, but dwell
    // (selected at 0) is not complete until 1_000.
    try testing.expectEqual(Reason.challenge_pending, (try sel.select(1, &cands, 200)).reason);
    try testing.expectEqual(@as(u64, 200), sel.current(1).?.challenger_since_ms);
    const d_dwell = try sel.select(1, &cands, 900);
    try testing.expectEqual(@as(?NodeId, 1), d_dwell.next_hop);
    try testing.expectEqual(Reason.challenge_pending, d_dwell.reason);

    // Lead interrupted: the challenge timer resets.
    try testing.expectEqual(Reason.kept_incumbent, (try sel.select(1, &.{.{ .next_hop = 1, .cost = 100 }}, 1_500)).reason);
    try testing.expectEqual(@as(?NodeId, null), sel.current(1).?.challenger);

    // Dwell is complete, but the renewed lead from t=2_000 has not lasted.
    try testing.expectEqual(Reason.challenge_pending, (try sel.select(1, &cands, 2_000)).reason);
    try testing.expectEqual(Reason.challenge_pending, (try sel.select(1, &cands, 2_499)).reason);

    const d = try sel.select(1, &cands, 2_500);
    try testing.expectEqual(@as(?NodeId, 2), d.next_hop);
    try testing.expectEqual(true, d.switched);
    try testing.expectEqual(Reason.switched_challenger_sustained, d.reason);
    const now_inc = sel.current(1).?;
    try testing.expectEqual(@as(u64, 2_500), now_inc.selected_at_ms);
    try testing.expectEqual(@as(?NodeId, null), now_inc.challenger);

    // The old hop needs its own full dwell + challenge to win back.
    const back = [_]Candidate{
        .{ .next_hop = 1, .cost = 10 },
        .{ .next_hop = 2, .cost = 50 },
    };
    try testing.expectEqual(Reason.challenge_pending, (try sel.select(1, &back, 2_600)).reason);
    try testing.expectEqual(Reason.challenge_pending, (try sel.select(1, &back, 3_400)).reason);
    try testing.expectEqual(Reason.switched_challenger_sustained, (try sel.select(1, &back, 3_500)).reason);
}

test "route_cost: oscillating costs around the margin produce at most one switch over N rounds (anti-flap)" {
    var sel = Selector.initWithOptions(testing.allocator, .{
        .abs_margin = 5,
        .rel_margin_pct = 0,
        .min_dwell_ms = 3_000,
        .min_challenge_ms = 1_000,
    });
    defer sel.deinit();

    _ = try sel.select(1, &.{.{ .next_hop = 1, .cost = 100 }}, 0);

    // Phase 1: the challenger's lead flaps every 200 ms, far below
    // min_challenge_ms, so it never accumulates a sustained lead.
    var switches: u32 = 0;
    var t: u64 = 100;
    for (0..200) |round| {
        const c: u32 = if (round % 2 == 0) 50 else 97;
        const d = try sel.select(1, &.{
            .{ .next_hop = 1, .cost = 100 },
            .{ .next_hop = 2, .cost = c },
        }, t);
        if (d.switched) switches += 1;
        t += 200;
    }
    try testing.expectEqual(@as(u32, 0), switches);

    // Phase 2: both hops oscillate symmetrically each round with a period
    // shorter than dwell + challenge; whoever holds the slot keeps it.
    for (0..200) |round| {
        const a: u32 = if (round % 2 == 0) 40 else 100;
        const b: u32 = if (round % 2 == 0) 100 else 40;
        const d = try sel.select(1, &.{
            .{ .next_hop = 1, .cost = a },
            .{ .next_hop = 2, .cost = b },
        }, t);
        if (d.switched) switches += 1;
        t += 200;
    }
    try testing.expectEqual(@as(u32, 0), switches);

    // Phase 3: a continuous lead produces exactly one switch, then none.
    for (0..50) |_| {
        const d = try sel.select(1, &.{
            .{ .next_hop = 1, .cost = 100 },
            .{ .next_hop = 2, .cost = 50 },
        }, t);
        if (d.switched) switches += 1;
        t += 200;
    }
    try testing.expectEqual(@as(u32, 1), switches);
    try testing.expectEqual(@as(NodeId, 2), sel.current(1).?.next_hop);
}

test "route_cost: two alternating challengers that both lead still switch once" {
    var sel = Selector.initWithOptions(testing.allocator, .{
        .abs_margin = 5,
        .rel_margin_pct = 0,
        .min_dwell_ms = 0,
        .min_challenge_ms = 1_000,
    });
    defer sel.deinit();

    _ = try sel.select(1, &.{.{ .next_hop = 1, .cost = 100 }}, 0);
    var switches: u32 = 0;
    var t: u64 = 100;
    for (0..20) |round| {
        // Hops 2 and 3 alternate as cheapest; both beat the incumbent.
        const two: u32 = if (round % 2 == 0) 40 else 45;
        const three: u32 = if (round % 2 == 0) 45 else 40;
        const d = try sel.select(1, &.{
            .{ .next_hop = 1, .cost = 100 },
            .{ .next_hop = 2, .cost = two },
            .{ .next_hop = 3, .cost = three },
        }, t);
        if (d.switched) {
            switches += 1;
            // The first tracked challenger (cheapest at t=100) wins.
            try testing.expectEqual(@as(?NodeId, 2), d.next_hop);
        }
        t += 200;
    }
    try testing.expectEqual(@as(u32, 1), switches);
}

test "route_cost: incumbent removed or ineligible fails over immediately to the cheapest remaining" {
    var sel = Selector.initWithOptions(testing.allocator, .{
        .min_dwell_ms = 1_000_000,
        .min_challenge_ms = 1_000_000,
    });
    defer sel.deinit();

    _ = try sel.select(1, &.{.{ .next_hop = 1, .cost = 10 }}, 0);

    // Incumbent absent from the candidate set.
    const d1 = try sel.select(1, &.{
        .{ .next_hop = 3, .cost = 700 },
        .{ .next_hop = 2, .cost = 500 },
    }, 1);
    try testing.expectEqual(@as(?NodeId, 2), d1.next_hop);
    try testing.expectEqual(true, d1.switched);
    try testing.expectEqual(Reason.failover_incumbent_ineligible, d1.reason);
    try testing.expectEqual(@as(u64, 1), sel.current(1).?.selected_at_ms);

    // Incumbent present but ineligible.
    const d2 = try sel.select(1, &.{
        .{ .next_hop = 2, .cost = null },
        .{ .next_hop = 3, .cost = 20 },
    }, 2);
    try testing.expectEqual(@as(?NodeId, 3), d2.next_hop);
    try testing.expectEqual(Reason.failover_incumbent_ineligible, d2.reason);

    // Incumbent duplicated with one ineligible entry is ineligible as a whole.
    const d3 = try sel.select(1, &.{
        .{ .next_hop = 3, .cost = 20 },
        .{ .next_hop = 4, .cost = 900 },
        .{ .next_hop = 3, .cost = null },
    }, 3);
    try testing.expectEqual(@as(?NodeId, 4), d3.next_hop);
    try testing.expectEqual(Reason.failover_incumbent_ineligible, d3.reason);

    // Nothing eligible: null, tracking dropped, next eligible set is fresh.
    const d4 = try sel.select(1, &.{.{ .next_hop = 4, .cost = null }}, 4);
    try testing.expectEqual(@as(?NodeId, null), d4.next_hop);
    try testing.expectEqual(true, d4.switched);
    try testing.expectEqual(Reason.no_eligible_candidate, d4.reason);
    try testing.expectEqual(@as(usize, 0), sel.len());
    try testing.expectEqual(Reason.initial_choice, (try sel.select(1, &.{.{ .next_hop = 5, .cost = 1 }}, 5)).reason);
}

test "route_cost: returned next_hop is always a member of the candidate slice; empty or all-ineligible returns null (authority not widened)" {
    var sel = Selector.init(testing.allocator);
    defer sel.deinit();

    const empty = try sel.select(1, &.{}, 0);
    try testing.expectEqual(@as(?NodeId, null), empty.next_hop);
    try testing.expectEqual(false, empty.switched);
    try testing.expectEqual(Reason.no_eligible_candidate, empty.reason);

    const all_ineligible = try sel.select(2, &.{
        .{ .next_hop = 10, .cost = null },
        .{ .next_hop = 20, .cost = null },
    }, 0);
    try testing.expectEqual(@as(?NodeId, null), all_ineligible.next_hop);
    try testing.expectEqual(Reason.no_eligible_candidate, all_ineligible.reason);

    // A hop listed both eligible and ineligible is never chosen.
    const shadowed = try sel.select(3, &.{
        .{ .next_hop = 10, .cost = 1 },
        .{ .next_hop = 10, .cost = null },
    }, 0);
    try testing.expectEqual(@as(?NodeId, null), shadowed.next_hop);
    try testing.expectEqual(@as(?Candidate, null), try cheapest(&.{
        .{ .next_hop = 10, .cost = null },
        .{ .next_hop = 10, .cost = 1 },
    }));
    try testing.expectEqual(@as(usize, 0), sel.len());

    // Property: under random candidate sets, durations and peer
    // invalidations, every decision is null or an eligible member of the
    // slice, and the stateless fallback obeys the same rule.
    var stress = Selector.initWithOptions(testing.allocator, .{
        .max_destinations = 6,
        .min_dwell_ms = 300,
        .min_challenge_ms = 200,
    });
    defer stress.deinit();
    var prng = std.Random.DefaultPrng.init(0xC057_0004);
    const random = prng.random();
    var now: u64 = 0;
    var buf: [6]Candidate = undefined;
    for (0..4_000) |_| {
        const n = random.uintAtMost(usize, buf.len);
        for (buf[0..n]) |*c| c.* = .{
            .next_hop = random.intRangeAtMost(NodeId, 1, 6),
            .cost = if (random.uintLessThan(u8, 4) == 0) null else random.intRangeAtMost(u32, 1, 200),
        };
        const cands = buf[0..n];
        if (random.uintLessThan(u8, 16) == 0) stress.invalidatePeer(random.intRangeAtMost(NodeId, 1, 6));
        const dest = random.intRangeAtMost(NodeId, 1, 8);
        const d = stress.select(dest, cands, now) catch |err| {
            try testing.expectEqual(error.TooManyDestinations, err);
            try testing.expect(stress.current(dest) == null);
            continue;
        };
        try expectMember(cands, d);
        if (d.next_hop) |hop| try testing.expectEqual(hop, stress.current(dest).?.next_hop);
        if (try cheapest(cands)) |c| try testing.expect(eligibility(cands, c.next_hop) == .cost);
        try testing.expect(stress.len() <= 6);
        now += random.uintAtMost(u64, 150);
    }
}

test "route_cost: decisions are independent of candidate order" {
    const base = [_]Candidate{
        .{ .next_hop = 4, .cost = 30 },
        .{ .next_hop = 2, .cost = 30 },
        .{ .next_hop = 7, .cost = null },
        .{ .next_hop = 4, .cost = 35 },
        .{ .next_hop = 9, .cost = 60 },
    };
    var prng = std.Random.DefaultPrng.init(0x0DE5);
    const random = prng.random();
    for (0..64) |_| {
        var perm = base;
        random.shuffle(Candidate, &perm);
        var sel = Selector.initWithOptions(testing.allocator, .{ .min_dwell_ms = 0, .min_challenge_ms = 0 });
        defer sel.deinit();
        const d = try sel.select(1, &perm, 0);
        try testing.expectEqual(@as(?NodeId, 2), d.next_hop);
        // Hop 4's canonical cost is its worst duplicate (35).
        const d2 = try sel.select(1, &.{
            perm[0],                          perm[1], perm[2], perm[3], perm[4],
            .{ .next_hop = 2, .cost = null },
        }, 1);
        try testing.expectEqual(@as(?NodeId, 4), d2.next_hop);
        try testing.expectEqual(@as(u32, 35), sel.current(1).?.cost);
    }
}

test "route_cost: invalidatePeer and forget reset hysteresis without allocation" {
    var sel = Selector.initWithOptions(testing.allocator, .{ .min_dwell_ms = 0, .min_challenge_ms = 1_000 });
    defer sel.deinit();

    for (1..21) |dest| _ = try sel.select(@intCast(dest), &.{.{ .next_hop = if (dest % 2 == 0) 9 else 8, .cost = 100 }}, 0);
    try testing.expectEqual(@as(usize, 20), sel.len());

    // Destination 1 (via 8) has a pending challenge led by 9.
    try testing.expectEqual(Reason.challenge_pending, (try sel.select(1, &.{
        .{ .next_hop = 8, .cost = 100 },
        .{ .next_hop = 9, .cost = 10 },
    }, 10)).reason);

    sel.invalidatePeer(9);
    try testing.expectEqual(@as(usize, 10), sel.len());
    for (sel.incumbents.values()) |v| {
        try testing.expectEqual(@as(NodeId, 8), v.next_hop);
        try testing.expectEqual(@as(?NodeId, null), v.challenger);
    }

    // A recovered 9 must restart its challenge rather than win on the
    // elapsed time of the cancelled one.
    const again = try sel.select(1, &.{
        .{ .next_hop = 8, .cost = 100 },
        .{ .next_hop = 9, .cost = 10 },
    }, 5_000);
    try testing.expectEqual(Reason.challenge_pending, again.reason);
    try testing.expectEqual(@as(u64, 5_000), sel.current(1).?.challenger_since_ms);

    // A destination routed via 9 starts fresh.
    try testing.expectEqual(Reason.initial_choice, (try sel.select(2, &.{.{ .next_hop = 7, .cost = 30 }}, 5_001)).reason);

    sel.forget(3);
    try testing.expect(sel.current(3) == null);
    try testing.expectEqual(Reason.initial_choice, (try sel.select(3, &.{.{ .next_hop = 8, .cost = 999 }}, 5_002)).reason);
    sel.forget(12345); // unknown destination is a no-op
    sel.invalidatePeer(12345);

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var no_alloc = Selector.initWithOptions(failing.allocator(), .{});
    defer no_alloc.deinit();
    no_alloc.invalidatePeer(1);
    no_alloc.forget(1);
    try testing.expectEqual(@as(usize, 0), failing.allocations);
}

test "route_cost: non-monotonic clock never triggers a voluntary switch" {
    var sel = Selector.initWithOptions(testing.allocator, .{ .min_dwell_ms = 0, .min_challenge_ms = 0 });
    defer sel.deinit();
    _ = try sel.select(1, &.{.{ .next_hop = 1, .cost = 100 }}, 10_000);
    const cands = [_]Candidate{ .{ .next_hop = 1, .cost = 100 }, .{ .next_hop = 2, .cost = 1 } };
    const d = try sel.select(1, &cands, 9_000);
    try testing.expectEqual(@as(?NodeId, 1), d.next_hop);
    try testing.expectEqual(Reason.challenge_pending, d.reason);
    // Failover is unaffected by the clock.
    const f = try sel.select(1, &.{.{ .next_hop = 2, .cost = 1 }}, 0);
    try testing.expectEqual(@as(?NodeId, 2), f.next_hop);
    try testing.expectEqual(Reason.failover_incumbent_ineligible, f.reason);
}

test "route_cost: bounds and allocation failure leave state byte-identical and retry succeeds" {
    var too_many: [max_candidates + 1]Candidate = undefined;
    for (&too_many, 0..) |*c, i| c.* = .{ .next_hop = @intCast(i + 1), .cost = 1 };

    {
        var sel = Selector.initWithOptions(testing.allocator, .{ .max_destinations = 2 });
        defer sel.deinit();
        _ = try sel.select(1, &.{.{ .next_hop = 10, .cost = 5 }}, 0);
        _ = try sel.select(2, &.{.{ .next_hop = 20, .cost = 5 }}, 0);
        try testing.expectError(error.TooManyDestinations, sel.select(3, &.{.{ .next_hop = 30, .cost = 5 }}, 0));
        try testing.expectError(error.TooManyCandidates, sel.select(1, &too_many, 1));
        try testing.expectError(error.TooManyCandidates, cheapest(&too_many));
        try testing.expectEqual(@as(usize, 2), sel.len());
        try testing.expectEqual(@as(NodeId, 10), sel.current(1).?.next_hop);
        try testing.expectEqual(@as(u64, 0), sel.current(1).?.selected_at_ms);
        // Untracked destinations with nothing eligible are not refused.
        try testing.expectEqual(Reason.no_eligible_candidate, (try sel.select(3, &.{}, 0)).reason);
        // Tracked destinations keep updating at the bound.
        try testing.expectEqual(@as(?NodeId, 10), (try sel.select(1, &.{.{ .next_hop = 10, .cost = 6 }}, 1)).next_hop);
        // Degraded stateless choice is still available.
        try testing.expectEqual(@as(NodeId, 30), (try cheapest(&.{.{ .next_hop = 30, .cost = 5 }})).?.next_hop);
    }

    // Sweep every allocation index: each failure leaves tracked state
    // exactly as before the failing call, and the retry then succeeds.
    var fail_index: usize = 0;
    var saw_success = false;
    while (!saw_success) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var sel = Selector.initWithOptions(failing.allocator(), .{});
        defer sel.deinit();

        var completed: NodeId = 0;
        const ok = for (1..41) |d| {
            const dest: NodeId = @intCast(d);
            const before_len = sel.len();
            const before = sel.incumbents.values()[0..before_len];
            const snapshot = try testing.allocator.dupe(Incumbent, before);
            defer testing.allocator.free(snapshot);
            _ = sel.select(dest, &.{.{ .next_hop = dest + 100, .cost = 7 }}, d) catch |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                try testing.expectEqual(before_len, sel.len());
                try testing.expect(sel.current(dest) == null);
                try testing.expectEqualSlices(Incumbent, snapshot, sel.incumbents.values());
                break false;
            };
            completed = dest;
        } else true;

        if (!ok) {
            failing.fail_index = std.math.maxInt(usize);
            const retry = try sel.select(completed + 1, &.{.{ .next_hop = completed + 101, .cost = 7 }}, 99);
            try testing.expectEqual(@as(?NodeId, completed + 101), retry.next_hop);
            try testing.expectEqual(Reason.initial_choice, retry.reason);
        } else {
            saw_success = true;
            try testing.expectEqual(@as(usize, 40), sel.len());
        }
    }
    try testing.expect(fail_index > 1);
}

fn pathCandidates(graph: *PathGraph, dest: NodeId, buf: []Candidate) ![]Candidate {
    return graph.candidates(dest, buf);
}

test "route_cost: path costs sum downstream links, so a cheap first link with a slow tail loses (M04 review regression)" {
    // L=1, A=2, B=3, D=4. L-A 10 ms, A-D 500 ms, L-B 50 ms, B-D 5 ms.
    // Local links are costed from live LinkHealth exactly as wired.
    const local_a = measuredLinkCost(&establishedHealth(0, 10), 0).?;
    const local_b = measuredLinkCost(&establishedHealth(0, 50), 0).?;
    const edges = [_]MeasuredEdge{
        .{ .a = 1, .b = 2, .cost = local_a },
        .{ .a = 2, .b = 4, .cost = 500 },
        .{ .a = 1, .b = 3, .cost = local_b },
        .{ .a = 3, .b = 4, .cost = 5 },
    };
    var graph = try PathGraph.init(testing.allocator, 1, &edges);
    defer graph.deinit(testing.allocator);
    var buf: [max_candidates]Candidate = undefined;

    const to_d = try pathCandidates(&graph, 4, &buf);
    try testing.expectEqualSlices(Candidate, &.{
        .{ .next_hop = 2, .cost = 510 },
        .{ .next_hop = 3, .cost = 55 },
    }, to_d);

    var sel = Selector.init(testing.allocator);
    defer sel.deinit();
    const d = try sel.select(4, to_d, 0);
    try testing.expectEqual(@as(?NodeId, 3), d.next_hop);
    try testing.expectEqual(Reason.initial_choice, d.reason);
    try testing.expectEqual(@as(u32, 55), sel.current(4).?.cost);

    // Direct neighbours: the only shortest path is the local link itself, so
    // the candidate cost equals that link's measured cost.
    try testing.expectEqualSlices(Candidate, &.{.{ .next_hop = 2, .cost = local_a }}, try pathCandidates(&graph, 2, &buf));
    try testing.expectEqualSlices(Candidate, &.{.{ .next_hop = 3, .cost = local_b }}, try pathCandidates(&graph, 3, &buf));

    // A direct-neighbour destination reachable over two parallel local links
    // (canonicalised duplicates) and a diamond where the cheaper local link
    // is also cheaper end to end still picks the cheaper link.
    const diamond = [_]MeasuredEdge{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 1, .b = 3, .cost = 50 },
        .{ .a = 2, .b = 4, .cost = 5 },
        .{ .a = 3, .b = 4, .cost = 5 },
    };
    var g2 = try PathGraph.init(testing.allocator, 1, &diamond);
    defer g2.deinit(testing.allocator);
    try testing.expectEqual(@as(?NodeId, 2), (try sel.select(40, try pathCandidates(&g2, 4, &buf), 0)).next_hop);
    try testing.expectEqual(@as(?NodeId, 2), (try sel.select(2, try pathCandidates(&g2, 2, &buf), 0)).next_hop);
}

test "route_cost: a downstream degradation switches through Selector hysteresis, not instantly" {
    var sel = Selector.initWithOptions(testing.allocator, .{
        .abs_margin = 5,
        .rel_margin_pct = 10,
        .min_dwell_ms = 1_000,
        .min_challenge_ms = 500,
    });
    defer sel.deinit();
    var buf: [max_candidates]Candidate = undefined;

    // A-D healthy: via A costs 15, via B costs 55.
    var healthy = try PathGraph.init(testing.allocator, 1, &.{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 4, .cost = 5 },
        .{ .a = 1, .b = 3, .cost = 50 },
        .{ .a = 3, .b = 4, .cost = 5 },
    });
    defer healthy.deinit(testing.allocator);
    try testing.expectEqual(@as(?NodeId, 2), (try sel.select(4, try healthy.candidates(4, &buf), 0)).next_hop);

    // A-D degrades to 500 ms beyond the first hop. The rebuilt graph makes B
    // the end-to-end winner; Selector still waits for dwell + challenge.
    var degraded = try PathGraph.init(testing.allocator, 1, &.{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 4, .cost = 500 },
        .{ .a = 1, .b = 3, .cost = 50 },
        .{ .a = 3, .b = 4, .cost = 5 },
    });
    defer degraded.deinit(testing.allocator);
    const pending = try sel.select(4, try degraded.candidates(4, &buf), 600);
    try testing.expectEqual(@as(?NodeId, 2), pending.next_hop);
    try testing.expectEqual(Reason.challenge_pending, pending.reason);
    try testing.expectEqual(Reason.challenge_pending, (try sel.select(4, try degraded.candidates(4, &buf), 1_099)).reason);
    const moved = try sel.select(4, try degraded.candidates(4, &buf), 1_100);
    try testing.expectEqual(@as(?NodeId, 3), moved.next_hop);
    try testing.expectEqual(Reason.switched_challenger_sustained, moved.reason);

    // A downstream link going unusable on the incumbent's only path fails
    // over at once.
    var broken = try PathGraph.init(testing.allocator, 1, &.{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 4, .cost = 5 },
        .{ .a = 1, .b = 3, .cost = 50 },
        .{ .a = 3, .b = 4, .cost = null },
    });
    defer broken.deinit(testing.allocator);
    const failover = try sel.select(4, try broken.candidates(4, &buf), 1_101);
    try testing.expectEqual(@as(?NodeId, 2), failover.next_hop);
    try testing.expectEqual(Reason.failover_incumbent_ineligible, failover.reason);
}

test "route_cost: path cost never creates or lengthens a route; unusable links poison only their paths" {
    var buf: [max_candidates]Candidate = undefined;

    // A cheap 3-hop path (via 2) never displaces the 2-hop BFS route (via 3).
    var g = try PathGraph.init(testing.allocator, 1, &.{
        .{ .a = 1, .b = 2, .cost = 1 },
        .{ .a = 2, .b = 5, .cost = 1 },
        .{ .a = 5, .b = 4, .cost = 1 },
        .{ .a = 1, .b = 3, .cost = 100 },
        .{ .a = 3, .b = 4, .cost = 100 },
        .{ .a = 20, .b = 21, .cost = 1 },
    });
    defer g.deinit(testing.allocator);
    try testing.expectEqualSlices(Candidate, &.{.{ .next_hop = 3, .cost = 200 }}, try g.candidates(4, &buf));
    try testing.expectEqual(@as(usize, 0), (try g.candidates(1, &buf)).len); // local
    try testing.expectEqual(@as(usize, 0), (try g.candidates(99, &buf)).len); // unknown
    try testing.expectEqual(@as(usize, 0), (try g.candidates(21, &buf)).len); // partitioned

    // Via 2 there are two shortest paths to 4; the unusable one is skipped
    // and the usable one costed. An unusable local link makes its hop null.
    var poison = try PathGraph.init(testing.allocator, 1, &.{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 6, .cost = 1 },
        .{ .a = 6, .b = 4, .cost = null },
        .{ .a = 2, .b = 7, .cost = 2 },
        .{ .a = 7, .b = 4, .cost = 3 },
        .{ .a = 1, .b = 3, .cost = null },
        .{ .a = 3, .b = 8, .cost = 1 },
        .{ .a = 8, .b = 4, .cost = 1 },
        .{ .a = 1, .b = 9, .cost = 1 },
        .{ .a = 9, .b = 10, .cost = null },
        .{ .a = 10, .b = 4, .cost = 1 },
    });
    defer poison.deinit(testing.allocator);
    const got = try poison.candidates(4, &buf);
    try testing.expectEqualSlices(Candidate, &.{
        .{ .next_hop = 2, .cost = 15 },
        .{ .next_hop = 3, .cost = null },
        .{ .next_hop = 9, .cost = null },
    }, got);
    try testing.expectEqual(@as(NodeId, 2), (try cheapest(got)).?.next_hop);

    // Saturation: costs clamp to maxInt(u32) instead of wrapping.
    var huge = try PathGraph.init(testing.allocator, 1, &.{
        .{ .a = 1, .b = 2, .cost = std.math.maxInt(u32) },
        .{ .a = 2, .b = 3, .cost = std.math.maxInt(u32) },
    });
    defer huge.deinit(testing.allocator);
    try testing.expectEqualSlices(Candidate, &.{.{ .next_hop = 2, .cost = std.math.maxInt(u32) }}, try huge.candidates(3, &buf));
}

test "route_cost: path candidates are independent of edge order and canonicalise duplicate links" {
    const base = [_]MeasuredEdge{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 4, .b = 2, .cost = 5 },
        .{ .a = 2, .b = 4, .cost = 7 }, // duplicate: worst (7) wins
        .{ .a = 1, .b = 3, .cost = 1 },
        .{ .a = 3, .b = 4, .cost = 1 },
        .{ .a = 4, .b = 3, .cost = null }, // duplicate with null: unusable
        .{ .a = 5, .b = 5, .cost = 1 }, // self-loop ignored
        .{ .a = 1, .b = 6, .cost = 2 },
        .{ .a = 6, .b = 4, .cost = 2 },
    };
    const want = [_]Candidate{
        .{ .next_hop = 2, .cost = 17 },
        .{ .next_hop = 3, .cost = null },
        .{ .next_hop = 6, .cost = 4 },
    };
    var prng = std.Random.DefaultPrng.init(0x0004_ED6E);
    const random = prng.random();
    var buf: [max_candidates]Candidate = undefined;
    for (0..64) |_| {
        var perm = base;
        random.shuffle(MeasuredEdge, &perm);
        var g = try PathGraph.init(testing.allocator, 1, &perm);
        defer g.deinit(testing.allocator);
        try testing.expectEqualSlices(Candidate, &want, try g.candidates(4, &buf));
        try testing.expectEqual(@as(usize, 0), (try g.candidates(5, &buf)).len);
    }
}

/// Brute force over a dense matrix: shortest hop count, then the cheapest
/// usable exact-length walk through each first hop.
fn bruteCandidates(n: usize, present: *const [8][8]bool, cost: *const [8][8]?u32, local: usize, dest: usize, out: []Candidate) []Candidate {
    if (dest >= n) return out[0..0]; // unknown node
    var dist: [8]?usize = @splat(null);
    dist[dest] = 0;
    var changed = true;
    while (changed) {
        changed = false;
        for (0..n) |v| for (0..n) |u| {
            if (!present[v][u]) continue;
            const du = dist[u] orelse continue;
            if (dist[v] == null or dist[v].? > du + 1) {
                dist[v] = du + 1;
                changed = true;
            }
        };
    }
    const k = dist[local] orelse return out[0..0];
    if (k == 0) return out[0..0];
    var count: usize = 0;
    for (0..n) |h| {
        if (!present[local][h] or dist[h] == null or dist[h].? + 1 != k) continue;
        const first = cost[local][h];
        const rest = cheapestWalk(n, present, cost, h, dest, k - 1);
        out[count] = .{
            .next_hop = @intCast(h),
            .cost = if (first != null and rest != null) saturateU32(@as(u64, first.?) + rest.?) else null,
        };
        count += 1;
    }
    return out[0..count];
}

fn cheapestWalk(n: usize, present: *const [8][8]bool, cost: *const [8][8]?u32, from: usize, dest: usize, hops: usize) ?u64 {
    if (hops == 0) return if (from == dest) 0 else null;
    var best: ?u64 = null;
    for (0..n) |u| {
        if (!present[from][u]) continue;
        const c = cost[from][u] orelse continue;
        const rest = cheapestWalk(n, present, cost, u, dest, hops - 1) orelse continue;
        best = @min(best orelse std.math.maxInt(u64), rest + c);
    }
    return best;
}

test "route_cost: path candidates match a brute-force shortest-path cost model on random graphs" {
    var prng = std.Random.DefaultPrng.init(0x0004_B7F0);
    const random = prng.random();
    var edges: [20]MeasuredEdge = undefined;
    var got_buf: [max_candidates]Candidate = undefined;
    var want_buf: [8]Candidate = undefined;
    for (0..500) |_| {
        const n: usize = random.intRangeAtMost(usize, 2, 8);
        const m = random.uintAtMost(usize, edges.len);
        var present: [8][8]bool = @splat(@splat(false));
        var cost: [8][8]?u32 = @splat(@splat(null));
        for (edges[0..m]) |*e| {
            const a = random.uintLessThan(usize, n);
            const b = random.uintLessThan(usize, n);
            const c: ?u32 = if (random.uintLessThan(u8, 5) == 0) null else random.intRangeAtMost(u32, 0, 100);
            e.* = .{ .a = @intCast(a), .b = @intCast(b), .cost = c };
            if (a == b) continue;
            const merged: ?u32 = if (present[a][b]) worstCost(cost[a][b], c) else c;
            present[a][b] = true;
            present[b][a] = true;
            cost[a][b] = merged;
            cost[b][a] = merged;
        }
        const local = random.uintLessThan(usize, n);
        var g = try PathGraph.init(testing.allocator, @intCast(local), edges[0..m]);
        defer g.deinit(testing.allocator);
        for (0..n + 1) |dest| {
            const want = bruteCandidates(n, &present, &cost, local, dest, &want_buf);
            try testing.expectEqualSlices(Candidate, want, try g.candidates(@intCast(dest), &got_buf));
        }
    }
}

test "route_cost: PathGraph bounds fail closed and init is allocation-failure clean" {
    var too_many: [max_path_edges + 1]MeasuredEdge = undefined;
    for (&too_many, 0..) |*e, i| e.* = .{ .a = 0, .b = @intCast(i + 1), .cost = 1 };
    try testing.expectError(error.TooManyEdges, PathGraph.init(testing.allocator, 0, &too_many));

    // More candidates than `out` holds: error, never a truncated set.
    var star = try PathGraph.init(testing.allocator, 0, &.{
        .{ .a = 0, .b = 1, .cost = 1 },
        .{ .a = 0, .b = 2, .cost = 1 },
        .{ .a = 0, .b = 3, .cost = 1 },
        .{ .a = 1, .b = 9, .cost = 1 },
        .{ .a = 2, .b = 9, .cost = 1 },
        .{ .a = 3, .b = 9, .cost = 1 },
    });
    defer star.deinit(testing.allocator);
    var small: [2]Candidate = undefined;
    try testing.expectError(error.TooManyCandidates, star.candidates(9, &small));
    var exact: [3]Candidate = undefined;
    try testing.expectEqual(@as(usize, 3), (try star.candidates(9, &exact)).len);

    // Every allocation index fails cleanly (the testing allocator reports
    // leaks), then a normal build succeeds.
    const edges = [_]MeasuredEdge{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 4, .cost = 500 },
        .{ .a = 1, .b = 3, .cost = 50 },
        .{ .a = 3, .b = 4, .cost = 5 },
    };
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var g = PathGraph.init(failing.allocator(), 1, &edges) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            continue;
        };
        defer g.deinit(failing.allocator());
        var buf: [max_candidates]Candidate = undefined;
        try testing.expectEqual(@as(NodeId, 3), (try cheapest(try g.candidates(4, &buf))).?.next_hop);
        break;
    }
    try testing.expect(fail_index > 1);
}

fn rankOrder(r: *const PeerRanking, nodes: []NodeId) void {
    const Ctx = struct {
        r: *const PeerRanking,
        fn less(ctx: @This(), a: NodeId, b: NodeId) bool {
            return RankKey.lessThan(ctx.r.key(a), ctx.r.key(b));
        }
    };
    std.sort.insertion(NodeId, nodes, Ctx{ .r = r }, Ctx.less);
}

test "route_cost mesh ranking: cheaper measured peer orders first; unknown and unusable peers stay in the set" {
    var r = PeerRanking.init(.{});
    try testing.expect(r.observe(30, 80, 0));
    try testing.expect(r.observe(10, 200, 0));
    try testing.expect(r.observe(20, null, 0));
    var nodes = [_]NodeId{ 40, 20, 10, 30 };
    rankOrder(&r, &nodes);
    // eligible by cost, then the untracked peer, then the unusable one.
    try testing.expectEqualSlices(NodeId, &.{ 30, 10, 40, 20 }, &nodes);
    // Ties go to the lowest node id.
    try testing.expect(r.observe(5, 80, 0));
    var tie = [_]NodeId{ 30, 5 };
    rankOrder(&r, &tie);
    try testing.expectEqualSlices(NodeId, &.{ 5, 30 }, &tie);
}

test "route_cost mesh ranking: sub-margin moves never reorder; sustained beyond-margin moves reorder only after challenge and dwell" {
    var r = PeerRanking.init(.{ .abs_margin = 10, .rel_margin_pct = 0, .min_challenge_ms = 1_000, .min_dwell_ms = 3_000 });
    _ = r.observe(1, 100, 0);
    _ = r.observe(2, 105, 0);
    // Peer 2 dips below peer 1 by less than the margin relative to its own rank.
    _ = r.observe(2, 96, 500);
    try testing.expectEqual(@as(?u32, 105), r.get(2).?.ranked);
    var nodes = [_]NodeId{ 2, 1 };
    rankOrder(&r, &nodes);
    try testing.expectEqualSlices(NodeId, &.{ 1, 2 }, &nodes);

    // Beyond margin: held until the challenge has lasted 1 s AND dwell 3 s.
    _ = r.observe(2, 50, 1_000);
    try testing.expectEqual(@as(?u32, 105), r.get(2).?.ranked);
    _ = r.observe(2, 50, 2_100); // challenge met, dwell not yet
    try testing.expectEqual(@as(?u32, 105), r.get(2).?.ranked);
    _ = r.observe(2, 52, 3_000); // both met
    try testing.expectEqual(@as(?u32, 52), r.get(2).?.ranked);
    rankOrder(&r, &nodes);
    try testing.expectEqualSlices(NodeId, &.{ 2, 1 }, &nodes);
    try testing.expectEqual(@as(u64, 1), r.stats.changes);
    try testing.expect(r.stats.held >= 2);
}

test "route_cost mesh ranking: oscillation around the margin produces at most one reorder (anti-flap)" {
    var r = PeerRanking.init(.{ .abs_margin = 5, .rel_margin_pct = 0, .min_challenge_ms = 2_000, .min_dwell_ms = 5_000 });
    _ = r.observe(1, 100, 0);
    _ = r.observe(2, 100, 0);
    var t: u64 = 0;
    var reorders: usize = 0;
    var last_first: NodeId = 1;
    for (0..400) |round| {
        t += 250;
        // Peer 2 alternates every probe between clearly cheaper and clearly dearer.
        _ = r.observe(2, if (round % 2 == 0) 60 else 140, t);
        _ = r.observe(1, 100, t);
        var nodes = [_]NodeId{ 1, 2 };
        rankOrder(&r, &nodes);
        if (nodes[0] != last_first) reorders += 1;
        last_first = nodes[0];
    }
    try testing.expectEqual(@as(usize, 0), reorders);
    try testing.expectEqual(@as(u64, 0), r.stats.changes);
}

test "route_cost mesh ranking: unusable link demotes at once; recovery waits out the promotion delay" {
    var r = PeerRanking.init(.{ .min_challenge_ms = 2_000, .min_dwell_ms = 5_000 });
    _ = r.observe(1, 10, 0);
    _ = r.observe(2, 90, 0);
    r.noteDown(1, 100);
    try testing.expectEqual(RankClass.ineligible, r.key(1).class);
    var nodes = [_]NodeId{ 1, 2 };
    rankOrder(&r, &nodes);
    try testing.expectEqualSlices(NodeId, &.{ 2, 1 }, &nodes);
    // A reconnect with good RTT is not trusted immediately.
    _ = r.observe(1, 10, 200);
    try testing.expectEqual(RankClass.ineligible, r.key(1).class);
    _ = r.observe(1, 10, 2_300);
    try testing.expectEqual(RankClass.ineligible, r.key(1).class); // dwell since demotion
    _ = r.observe(1, 10, 5_100);
    try testing.expectEqual(RankClass.eligible, r.key(1).class);
    try testing.expectEqual(@as(u64, 1), r.stats.demotions);
    try testing.expectEqual(@as(u64, 1), r.stats.promotions);
    // A flap during the delay restarts it.
    r.noteDown(1, 6_000);
    _ = r.observe(1, 10, 6_500);
    r.noteDown(1, 7_000);
    _ = r.observe(1, 10, 12_500);
    try testing.expectEqual(RankClass.ineligible, r.key(1).class);
}

test "route_cost mesh ranking: refresh demotes unseen peers; backward clock never changes a rank" {
    var r = PeerRanking.init(.{ .abs_margin = 1, .rel_margin_pct = 0, .min_challenge_ms = 0, .min_dwell_ms = 0 });
    _ = r.observe(1, 10, 1_000);
    _ = r.observe(2, 20, 1_000);
    r.beginRefresh();
    _ = r.observe(2, 20, 1_100);
    r.endRefresh(1_100);
    try testing.expectEqual(RankClass.ineligible, r.key(1).class);
    try testing.expectEqual(RankClass.eligible, r.key(2).class);
    // Clock steps back: a beyond-margin move is held, not applied.
    _ = r.observe(2, 200, 500);
    try testing.expectEqual(@as(?u32, 20), r.get(2).?.ranked);
}

test "route_cost mesh ranking: bounded table refuses live overflow, evicts only stale entries, never drops from ordering" {
    var r = PeerRanking.init(.{});
    for (0..max_ranked_peers) |i| try testing.expect(r.observe(@intCast(i + 1), 50, 0));
    const before = r;
    try testing.expect(!r.observe(9_999, 1, 0));
    try testing.expectEqual(@as(u64, 1), r.stats.refused);
    try testing.expectEqualSlices(PeerRank, before.tracked(), r.tracked());
    try testing.expectEqual(RankClass.unranked, r.key(9_999).class);

    // Next refresh observes all but one; that stale entry can be replaced.
    r.beginRefresh();
    for (1..max_ranked_peers) |i| _ = r.observe(@intCast(i + 1), 50, 10);
    try testing.expect(r.observe(9_999, 1, 10));
    try testing.expect(r.get(1) == null);
    try testing.expectEqual(max_ranked_peers, r.tracked().len);
    r.forget(9_999);
    try testing.expect(r.get(9_999) == null);
    try testing.expectEqual(max_ranked_peers - 1, r.tracked().len);
}
