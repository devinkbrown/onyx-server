// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Multi-hop mesh topology view for the Undertow peer graph.
//!
//! This module is pure graph state: callers provide the peer links, choose the
//! local node, and own all transport decisions. The topology stores sorted
//! undirected adjacency and a BFS closure rooted at the local node so routing
//! queries are deterministic and allocation-free after initialization.
//!
//! BFS alone decides reachability, hop `distance`, and the candidate next
//! hops: cost never creates a route, never changes a hop distance, and only
//! orders the next-hop choice among BFS-shortest paths over known links.

const std = @import("std");
const route_table = @import("route_table.zig");

pub const NodeId = route_table.NodeId;

/// Per-link cost used when a caller supplies no measured cost. With this
/// default a route's total cost equals its BFS hop distance, so cost-aware
/// selection reproduces the previous behaviour exactly when unused.
pub const default_link_cost: u32 = 1;

/// Hysteresis margin for measured-cost route selection: a challenger next
/// hop replaces the incumbent only when its total cost is lower by more
/// than this margin. Ties and sub-margin improvements keep the incumbent.
pub const cost_hysteresis_margin: u64 = 4;

/// One undirected peer link.
pub const Edge = struct {
    a: NodeId,
    b: NodeId,
    /// Caller-supplied measured cost of traversing this link. This is an
    /// explicit topology input only; no metrics pipeline feeds it. When the
    /// same link is supplied more than once, the first cost wins.
    cost: u32 = default_link_cost,
};

pub const Error = std.mem.Allocator.Error || error{
    DistanceOverflow,
};

const Link = struct {
    node: NodeId,
    cost: u32,
};

const Route = struct {
    distance: u32,
    next_hop: ?NodeId,
    cost: u64 = 0,
    parent: ?NodeId = null,
};

/// Immutable topology snapshot rooted at one local node.
pub const Topology = struct {
    local: NodeId,
    adjacency: std.AutoHashMapUnmanaged(NodeId, std.ArrayListUnmanaged(Link)) = .empty,
    routes: std.AutoHashMapUnmanaged(NodeId, Route) = .empty,
    reachable_nodes: std.ArrayListUnmanaged(NodeId) = .empty,

    /// Build a topology snapshot from undirected edges and the local node id.
    pub fn init(allocator: std.mem.Allocator, local: NodeId, edges: []const Edge) Error!Topology {
        var self = Topology{ .local = local };
        errdefer self.deinit(allocator);

        try self.ensureNode(allocator, local);
        for (edges) |edge| try self.addEdge(allocator, edge);
        self.sortAdjacency();
        try self.computeRoutes(allocator);

        return self;
    }

    /// Release all storage owned by this snapshot.
    pub fn deinit(self: *Topology, allocator: std.mem.Allocator) void {
        var it = self.adjacency.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        self.adjacency.deinit(allocator);
        self.routes.deinit(allocator);
        self.reachable_nodes.deinit(allocator);
        self.* = undefined;
    }

    /// Return the first hop toward `dest`, or null for local/unreachable nodes.
    pub fn nextHop(self: *const Topology, dest: NodeId) ?NodeId {
        const route = self.routes.get(dest) orelse return null;
        return route.next_hop;
    }

    /// Return the shortest-path hop count from the local node to `dest`.
    pub fn distance(self: *const Topology, dest: NodeId) ?u32 {
        const route = self.routes.get(dest) orelse return null;
        return route.distance;
    }

    /// Return the total measured cost of the selected route to `dest`, or
    /// null when `dest` has no BFS route. With default link costs this
    /// equals `distance`.
    pub fn cost(self: *const Topology, dest: NodeId) ?u64 {
        const route = self.routes.get(dest) orelse return null;
        return route.cost;
    }

    /// Return the local partition in deterministic BFS order.
    pub fn reachable(self: *const Topology) []const NodeId {
        return self.reachable_nodes.items;
    }

    /// Return whether `other` is outside the local partition.
    pub fn partitioned(self: *const Topology, other: NodeId) bool {
        return !self.routes.contains(other);
    }

    fn addEdge(self: *Topology, allocator: std.mem.Allocator, edge: Edge) Error!void {
        try self.ensureNode(allocator, edge.a);
        try self.ensureNode(allocator, edge.b);

        if (edge.a == edge.b) return;
        try self.addNeighbor(allocator, edge.a, edge.b, edge.cost);
        try self.addNeighbor(allocator, edge.b, edge.a, edge.cost);
    }

    fn ensureNode(self: *Topology, allocator: std.mem.Allocator, node: NodeId) Error!void {
        if (self.adjacency.contains(node)) return;
        try self.adjacency.put(allocator, node, .empty);
    }

    fn addNeighbor(
        self: *Topology,
        allocator: std.mem.Allocator,
        from: NodeId,
        to: NodeId,
        link_cost: u32,
    ) Error!void {
        const neighbors = self.adjacency.getPtr(from).?;
        for (neighbors.items) |existing| {
            if (existing.node == to) return;
        }
        try neighbors.append(allocator, .{ .node = to, .cost = link_cost });
    }

    fn sortAdjacency(self: *Topology) void {
        var it = self.adjacency.iterator();
        while (it.next()) |entry| {
            std.mem.sort(Link, entry.value_ptr.items, {}, lessLink);
        }
    }

    fn linkCost(self: *const Topology, from: NodeId, to: NodeId) ?u64 {
        const neighbors = self.adjacency.get(from) orelse return null;
        for (neighbors.items) |link| {
            if (link.node == to) return link.cost;
        }
        return null;
    }

    fn computeRoutes(self: *Topology, allocator: std.mem.Allocator) Error!void {
        self.routes.clearRetainingCapacity();
        self.reachable_nodes.clearRetainingCapacity();

        var queue: std.ArrayListUnmanaged(NodeId) = .empty;
        defer queue.deinit(allocator);

        try self.routes.put(allocator, self.local, .{
            .distance = 0,
            .next_hop = null,
        });
        try self.reachable_nodes.append(allocator, self.local);
        try queue.append(allocator, self.local);

        // Phase 1: BFS is authoritative. It alone fixes reachability, hop
        // distance, reachable order, and each route's incumbent next hop
        // (the first BFS discovery, exactly as before cost existed).
        var head: usize = 0;
        while (head < queue.items.len) : (head += 1) {
            const current = queue.items[head];
            const current_route = self.routes.get(current).?;
            const neighbors = self.adjacency.get(current) orelse continue;

            for (neighbors.items) |link| {
                const neighbor = link.node;
                if (self.routes.contains(neighbor)) continue;
                if (current_route.distance == std.math.maxInt(u32)) return error.DistanceOverflow;

                const next_hop = if (current == self.local) neighbor else current_route.next_hop.?;
                const next_distance = current_route.distance + 1;
                try self.routes.put(allocator, neighbor, .{
                    .distance = next_distance,
                    .next_hop = next_hop,
                    .parent = current,
                });
                try self.reachable_nodes.append(allocator, neighbor);
                try queue.append(allocator, neighbor);
            }
        }

        self.selectRouteCosts();
    }

    /// Phase 2: assign each route a total cost and, subject to hysteresis,
    /// a next hop. Only BFS predecessors (`distance - 1`) may parent a node,
    /// so every candidate route is a BFS-shortest path over a known link and
    /// cost can neither create reachability nor alter a hop distance.
    /// `reachable_nodes` is in BFS order, so a predecessor's route is final
    /// before any node it can parent is evaluated.
    fn selectRouteCosts(self: *Topology) void {
        for (self.reachable_nodes.items) |node| {
            if (node == self.local) continue;
            const route = self.routes.getPtr(node).?;
            const route_distance = route.distance;
            const parent = route.parent.?;
            const parent_route = self.routes.get(parent).?;

            // The BFS parent is the incumbent; its cost is the bar to beat.
            var best_parent = parent;
            var best_next_hop = route.next_hop.?;
            var best_cost = parent_route.cost + (self.linkCost(node, parent) orelse continue);

            const neighbors = self.adjacency.get(node) orelse continue;
            for (neighbors.items) |link| {
                if (link.node == best_parent) continue;
                const challenger = self.routes.get(link.node) orelse continue;
                if (challenger.distance + 1 != route_distance) continue;

                const challenger_cost = challenger.cost + link.cost;
                if (challenger_cost >= best_cost) continue;
                if (best_cost - challenger_cost <= cost_hysteresis_margin) continue;

                best_parent = link.node;
                best_next_hop = if (link.node == self.local) node else challenger.next_hop.?;
                best_cost = challenger_cost;
            }

            route.parent = best_parent;
            route.next_hop = best_next_hop;
            route.cost = best_cost;
        }
    }
};

fn lessLink(_: void, a: Link, b: Link) bool {
    return a.node < b.node;
}

test "linear chain next hop and distance" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
        .{ .a = 3, .b = 4 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(2));
    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(3));
    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(4));
    try std.testing.expectEqual(@as(?u32, 0), topo.distance(1));
    try std.testing.expectEqual(@as(?u32, 1), topo.distance(2));
    try std.testing.expectEqual(@as(?u32, 2), topo.distance(3));
    try std.testing.expectEqual(@as(?u32, 3), topo.distance(4));
    try std.testing.expectEqualSlices(NodeId, &.{ 1, 2, 3, 4 }, topo.reachable());
}

test "partitioned component is detected" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 10, .b = 11 },
        .{ .a = 20, .b = 21 },
    };

    var topo = try Topology.init(allocator, 10, &edges);
    defer topo.deinit(allocator);

    try std.testing.expect(!topo.partitioned(10));
    try std.testing.expect(!topo.partitioned(11));
    try std.testing.expect(topo.partitioned(20));
    try std.testing.expect(topo.partitioned(21));
    try std.testing.expectEqualSlices(NodeId, &.{ 10, 11 }, topo.reachable());
}

test "tie break chooses lowest next hop deterministically" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 3 },
        .{ .a = 4, .b = 8 },
        .{ .a = 1, .b = 2 },
        .{ .a = 3, .b = 8 },
        .{ .a = 2, .b = 8 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(8));
    try std.testing.expectEqual(@as(?u32, 2), topo.distance(8));
    try std.testing.expectEqualSlices(NodeId, &.{ 1, 2, 3, 8, 4 }, topo.reachable());
}

test "cost hysteresis sub-margin improvement keeps incumbent" {
    const allocator = std.testing.allocator;
    // Incumbent via 2 costs 20; challenger via 3 costs 17 (improvement 3,
    // within cost_hysteresis_margin), so the incumbent must be kept.
    const edges = [_]Edge{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 8, .cost = 10 },
        .{ .a = 1, .b = 3, .cost = 8 },
        .{ .a = 3, .b = 8, .cost = 9 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(8));
    try std.testing.expectEqual(@as(?u64, 20), topo.cost(8));
    try std.testing.expectEqual(@as(?u32, 2), topo.distance(8));
}

test "cost hysteresis above-margin improvement switches next hop" {
    const allocator = std.testing.allocator;
    // Challenger via 3 costs 10 against the incumbent's 20: an improvement
    // greater than cost_hysteresis_margin, so the next hop must switch.
    const edges = [_]Edge{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 8, .cost = 10 },
        .{ .a = 1, .b = 3, .cost = 5 },
        .{ .a = 3, .b = 8, .cost = 5 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, 3), topo.nextHop(8));
    try std.testing.expectEqual(@as(?u64, 10), topo.cost(8));
    try std.testing.expectEqual(@as(?u32, 2), topo.distance(8));
}

test "cost hysteresis equal cost keeps incumbent" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 2, .cost = 10 },
        .{ .a = 2, .b = 8, .cost = 10 },
        .{ .a = 1, .b = 3, .cost = 7 },
        .{ .a = 3, .b = 8, .cost = 13 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(8));
    try std.testing.expectEqual(@as(?u64, 20), topo.cost(8));
}

test "cost never creates a route to an unknown destination" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 2, .cost = 1 },
        .{ .a = 20, .b = 21, .cost = 1 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    // Node 99 appears in no link at all; node 21 is known but disconnected.
    // A cheap cost on either component must not invent reachability.
    try std.testing.expectEqual(@as(?NodeId, null), topo.nextHop(99));
    try std.testing.expectEqual(@as(?u64, null), topo.cost(99));
    try std.testing.expectEqual(@as(?u32, null), topo.distance(99));
    try std.testing.expect(topo.partitioned(99));
    try std.testing.expectEqual(@as(?NodeId, null), topo.nextHop(21));
    try std.testing.expectEqual(@as(?u64, null), topo.cost(21));
    try std.testing.expect(topo.partitioned(21));
}

test "unreachable destination returns null" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 3, .b = 4 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, null), topo.nextHop(4));
    try std.testing.expectEqual(@as(?u32, null), topo.distance(4));
    try std.testing.expect(topo.partitioned(4));
}
