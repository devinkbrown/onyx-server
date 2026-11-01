// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper CLONES report — snapshot aggregation of connection clones.
//!
//! Given a snapshot slice of connections (each with optional account, IP
//! string, network prefix string, and nick), this module aggregates by
//! exact IP and by network prefix (/24 for IPv4, /64 for IPv6), classifies
//! groups whose member count meets or exceeds a threshold as clone clusters,
//! and renders a report sorted by cluster size descending for an oper reply.
//!
//! This is a pure, bounded, read-only aggregator. It owns no long-lived
//! state, reads no clock, and performs no I/O. It never mutates the input
//! slice. All allocations are released by `Report.deinit`. This is distinct
//! from the stateful `clone_detect`/`clone_limit` throttles, which enforce
//! connection limits at accept time; this module only *reports*.
const std = @import("std");

/// A single connection as seen by the report. Borrowed for the duration of
/// the scan; the report copies any bytes it needs to retain.
pub const Connection = struct {
    /// Logged-in account name, or null when unauthenticated.
    account: ?[]const u8 = null,
    /// Exact remote IP, e.g. "192.0.2.10" or "2001:db8::1". Required.
    ip: []const u8,
    /// Network prefix the IP belongs to, e.g. "192.0.2.0/24" or
    /// "2001:db8::/64". Required; the caller computes the masked form.
    prefix: []const u8,
    /// Client nick at scan time. Required.
    nick: []const u8,
};

/// How connections are grouped within a cluster.
pub const GroupKind = enum {
    /// Grouped by exact remote IP.
    exact_ip,
    /// Grouped by network prefix (/24 or /64).
    net_prefix,
};

pub const Params = struct {
    /// Minimum member count for a group to be reported as a clone cluster.
    /// Must be >= 2; a single connection is never a clone.
    threshold: usize = 2,
    /// Hard cap on distinct connections accepted in one scan.
    max_connections: usize = 65_536,
    /// Hard cap on the byte length of any single input field.
    max_field_len: usize = 256,
};

pub const ScanError = error{
    EmptyIp,
    EmptyPrefix,
    EmptyNick,
    FieldTooLong,
    InvalidParams,
    TooManyConnections,
} || std.mem.Allocator.Error;

/// One member line within a cluster.
pub const Member = struct {
    account: ?[]const u8,
    ip: []const u8,
    nick: []const u8,
};

/// A reported clone cluster: a group whose size met the threshold.
pub const Cluster = struct {
    kind: GroupKind,
    /// The grouping key: the exact IP or the network prefix.
    key: []const u8,
    /// Member connections, in stable first-seen order.
    members: []Member,

    pub fn size(self: *const Cluster) usize {
        return self.members.len;
    }
};

/// Owned result of a scan. Call `deinit` to release all backing memory.
pub const Report = struct {
    allocator: std.mem.Allocator,
    clusters: []Cluster,
    /// Backing arena for all copied strings and member arrays.
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Report) void {
        self.arena.deinit();
        self.allocator.free(self.clusters);
        self.* = undefined;
    }

    /// Total number of clusters that met the threshold.
    pub fn clusterCount(self: *const Report) usize {
        return self.clusters.len;
    }

    /// Render the report as human-readable oper reply lines into `writer`.
    /// One header line per cluster followed by indented member lines.
    pub fn render(self: *const Report, writer: anytype) !void {
        if (self.clusters.len == 0) {
            try writer.writeAll("No clone clusters found.\n");
            return;
        }
        for (self.clusters) |cluster| {
            const kind_str = switch (cluster.kind) {
                .exact_ip => "ip",
                .net_prefix => "net",
            };
            try writer.print(
                "Cluster {s} {s} ({d} clients)\n",
                .{ kind_str, cluster.key, cluster.members.len },
            );
            for (cluster.members) |member| {
                const acct = member.account orelse "*";
                try writer.print(
                    "  {s} {s} {s}\n",
                    .{ member.nick, member.ip, acct },
                );
            }
        }
    }
};

fn validParams(params: Params) bool {
    return params.threshold >= 2 and
        params.max_connections > 0 and
        params.max_field_len > 0;
}

const Group = struct {
    kind: GroupKind,
    key: []const u8,
    members: std.ArrayList(Member),
};

/// Scan `connections` and produce a sorted clone report. The input slice is
/// never mutated. On success the caller owns the returned `Report` and must
/// call `deinit`. Connections are aggregated both by exact IP and by network
/// prefix; both kinds of cluster may appear in the result.
pub fn scan(
    allocator: std.mem.Allocator,
    connections: []const Connection,
    params: Params,
) ScanError!Report {
    if (!validParams(params)) return error.InvalidParams;
    if (connections.len > params.max_connections) return error.TooManyConnections;

    for (connections) |conn| try validateConnection(conn, params.max_field_len);

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    // Two passes of aggregation: exact IP, then network prefix. Each uses a
    // string-keyed map into a flat list of groups so first-seen insertion
    // order is preserved within each group's member list.
    var groups: std.ArrayList(Group) = .empty;
    // groups lives in the arena, so no explicit deinit needed on error.

    var ip_index = std.StringHashMap(usize).init(a);
    var net_index = std.StringHashMap(usize).init(a);

    for (connections) |conn| {
        try insertInto(a, &groups, &ip_index, .exact_ip, conn.ip, conn);
        try insertInto(a, &groups, &net_index, .net_prefix, conn.prefix, conn);
    }

    // Collect only groups that meet the threshold.
    var clusters: std.ArrayList(Cluster) = .empty;
    defer clusters.deinit(allocator);
    for (groups.items) |group| {
        if (group.members.items.len < params.threshold) continue;
        try clusters.append(allocator, .{
            .kind = group.kind,
            .key = group.key,
            .members = group.members.items,
        });
    }

    const owned = try clusters.toOwnedSlice(allocator);
    errdefer allocator.free(owned);

    std.mem.sort(Cluster, owned, {}, lessThan);

    return .{
        .allocator = allocator,
        .clusters = owned,
        .arena = arena,
    };
}

fn validateConnection(conn: Connection, max_field_len: usize) ScanError!void {
    if (conn.ip.len == 0) return error.EmptyIp;
    if (conn.prefix.len == 0) return error.EmptyPrefix;
    if (conn.nick.len == 0) return error.EmptyNick;
    if (conn.ip.len > max_field_len or
        conn.prefix.len > max_field_len or
        conn.nick.len > max_field_len)
    {
        return error.FieldTooLong;
    }
    if (conn.account) |acct| {
        if (acct.len > max_field_len) return error.FieldTooLong;
    }
}

fn insertInto(
    a: std.mem.Allocator,
    groups: *std.ArrayList(Group),
    index: *std.StringHashMap(usize),
    kind: GroupKind,
    raw_key: []const u8,
    conn: Connection,
) std.mem.Allocator.Error!void {
    const member = try copyMember(a, conn);

    if (index.get(raw_key)) |gi| {
        try groups.items[gi].members.append(a, member);
        return;
    }

    const key_copy = try a.dupe(u8, raw_key);
    var member_list: std.ArrayList(Member) = .empty;
    try member_list.append(a, member);

    const gi = groups.items.len;
    try groups.append(a, .{
        .kind = kind,
        .key = key_copy,
        .members = member_list,
    });
    try index.put(key_copy, gi);
}

fn copyMember(a: std.mem.Allocator, conn: Connection) std.mem.Allocator.Error!Member {
    const account_copy: ?[]const u8 = if (conn.account) |acct|
        try a.dupe(u8, acct)
    else
        null;
    return .{
        .account = account_copy,
        .ip = try a.dupe(u8, conn.ip),
        .nick = try a.dupe(u8, conn.nick),
    };
}

/// Order: larger clusters first. Ties broken deterministically by kind
/// (exact_ip before net_prefix), then by key bytes, then by first member's
/// nick so the report is fully stable regardless of input ordering.
fn lessThan(_: void, a: Cluster, b: Cluster) bool {
    if (a.members.len != b.members.len) {
        return a.members.len > b.members.len;
    }
    const a_kind = @backingInt(a.kind);
    const b_kind = @backingInt(b.kind);
    if (a_kind != b_kind) return a_kind < b_kind;

    const key_cmp = std.mem.order(u8, a.key, b.key);
    if (key_cmp != .eq) return key_cmp == .lt;

    const a_nick = if (a.members.len > 0) a.members[0].nick else "";
    const b_nick = if (b.members.len > 0) b.members[0].nick else "";
    return std.mem.order(u8, a_nick, b_nick) == .lt;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mk(account: ?[]const u8, ip: []const u8, prefix: []const u8, nick: []const u8) Connection {
    return .{ .account = account, .ip = ip, .prefix = prefix, .nick = nick };
}

test "groups by exact IP and reports clusters at threshold" {
    const conns = [_]Connection{
        mk(null, "192.0.2.10", "192.0.2.0/24", "alice"),
        mk(null, "192.0.2.10", "192.0.2.0/24", "alice_"),
        mk(null, "192.0.2.11", "192.0.2.0/24", "bob"),
    };

    var report = try scan(testing.allocator, &conns, .{ .threshold = 2 });
    defer report.deinit();

    // Exact-IP cluster for .10 (2 members) and net-prefix cluster /24 (3).
    var saw_ip = false;
    var saw_net = false;
    for (report.clusters) |c| {
        switch (c.kind) {
            .exact_ip => {
                try testing.expectEqualStrings("192.0.2.10", c.key);
                try testing.expectEqual(@as(usize, 2), c.members.len);
                saw_ip = true;
            },
            .net_prefix => {
                try testing.expectEqualStrings("192.0.2.0/24", c.key);
                try testing.expectEqual(@as(usize, 3), c.members.len);
                saw_net = true;
            },
        }
    }
    try testing.expect(saw_ip and saw_net);
}

test "threshold classification excludes singletons" {
    const conns = [_]Connection{
        mk("acct1", "10.0.0.1", "10.0.0.0/24", "n1"),
        mk("acct2", "10.0.0.2", "10.0.0.0/24", "n2"),
        mk("acct3", "10.0.1.1", "10.0.1.0/24", "n3"),
    };

    // Threshold 3: only the /24 with 2 members fails; nothing has 3.
    var report = try scan(testing.allocator, &conns, .{ .threshold = 3 });
    defer report.deinit();
    try testing.expectEqual(@as(usize, 0), report.clusterCount());

    // Threshold 2: the 10.0.0.0/24 prefix has 2 members and qualifies.
    var report2 = try scan(testing.allocator, &conns, .{ .threshold = 2 });
    defer report2.deinit();
    var found = false;
    for (report2.clusters) |c| {
        if (c.kind == .net_prefix and std.mem.eql(u8, c.key, "10.0.0.0/24")) {
            try testing.expectEqual(@as(usize, 2), c.members.len);
            found = true;
        }
    }
    try testing.expect(found);
    // No exact-IP cluster: every IP is unique.
    for (report2.clusters) |c| try testing.expect(c.kind != .exact_ip);
}

test "ordering is by cluster size descending" {
    const conns = [_]Connection{
        // 203.0.113.5 appears 3 times (biggest exact-IP cluster).
        mk(null, "203.0.113.5", "203.0.113.0/24", "a"),
        mk(null, "203.0.113.5", "203.0.113.0/24", "b"),
        mk(null, "203.0.113.5", "203.0.113.0/24", "c"),
        // 203.0.113.6 appears twice.
        mk(null, "203.0.113.6", "203.0.113.0/24", "d"),
        mk(null, "203.0.113.6", "203.0.113.0/24", "e"),
    };

    var report = try scan(testing.allocator, &conns, .{ .threshold = 2 });
    defer report.deinit();

    try testing.expect(report.clusters.len >= 2);
    // First cluster must be the largest (the /24 with 5 members).
    try testing.expectEqual(@as(usize, 5), report.clusters[0].members.len);
    // Sizes are monotonically non-increasing.
    var prev = report.clusters[0].members.len;
    for (report.clusters[1..]) |c| {
        try testing.expect(c.members.len <= prev);
        prev = c.members.len;
    }
}

test "ipv6 /64 prefix aggregation" {
    const conns = [_]Connection{
        mk(null, "2001:db8::1", "2001:db8::/64", "x"),
        mk(null, "2001:db8::2", "2001:db8::/64", "y"),
        mk(null, "2001:db8:1::1", "2001:db8:1::/64", "z"),
    };

    var report = try scan(testing.allocator, &conns, .{ .threshold = 2 });
    defer report.deinit();

    var found = false;
    for (report.clusters) |c| {
        if (c.kind == .net_prefix and std.mem.eql(u8, c.key, "2001:db8::/64")) {
            try testing.expectEqual(@as(usize, 2), c.members.len);
            found = true;
        }
        // The lone 2001:db8:1::/64 must not be reported.
        if (c.kind == .net_prefix) {
            try testing.expect(!std.mem.eql(u8, c.key, "2001:db8:1::/64"));
        }
    }
    try testing.expect(found);
}

test "ipv4 and ipv6 clusters coexist and members preserve order and account" {
    const conns = [_]Connection{
        mk("alice", "192.0.2.1", "192.0.2.0/24", "alice1"),
        mk("alice", "192.0.2.1", "192.0.2.0/24", "alice2"),
        mk(null, "2001:db8::a", "2001:db8::/64", "v6a"),
        mk(null, "2001:db8::b", "2001:db8::/64", "v6b"),
    };

    var report = try scan(testing.allocator, &conns, .{ .threshold = 2 });
    defer report.deinit();

    for (report.clusters) |c| {
        if (c.kind == .exact_ip and std.mem.eql(u8, c.key, "192.0.2.1")) {
            try testing.expectEqual(@as(usize, 2), c.members.len);
            // First-seen order preserved.
            try testing.expectEqualStrings("alice1", c.members[0].nick);
            try testing.expectEqualStrings("alice2", c.members[1].nick);
            try testing.expectEqualStrings("alice", c.members[0].account.?);
        }
    }
}

test "empty input yields no clusters and renders friendly message" {
    var report = try scan(testing.allocator, &.{}, .{});
    defer report.deinit();
    try testing.expectEqual(@as(usize, 0), report.clusterCount());

    var buf: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try report.render(&writer);
    try testing.expectEqualStrings("No clone clusters found.\n", writer.buffered());
}

test "render emits header and member lines" {
    const conns = [_]Connection{
        mk(null, "192.0.2.10", "192.0.2.0/24", "alice"),
        mk(null, "192.0.2.10", "192.0.2.0/24", "alice_"),
    };
    var report = try scan(testing.allocator, &conns, .{ .threshold = 2 });
    defer report.deinit();

    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try report.render(&writer);
    const out = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "Cluster ip 192.0.2.10") != null);
    try testing.expect(std.mem.indexOf(u8, out, "alice") != null);
    try testing.expect(std.mem.indexOf(u8, out, "alice_") != null);
}

test "input validation rejects malformed connections and bad params" {
    const bad_ip = [_]Connection{mk(null, "", "p/24", "n")};
    try testing.expectError(error.EmptyIp, scan(testing.allocator, &bad_ip, .{}));

    const bad_prefix = [_]Connection{mk(null, "1.2.3.4", "", "n")};
    try testing.expectError(error.EmptyPrefix, scan(testing.allocator, &bad_prefix, .{}));

    const bad_nick = [_]Connection{mk(null, "1.2.3.4", "p/24", "")};
    try testing.expectError(error.EmptyNick, scan(testing.allocator, &bad_nick, .{}));

    const ok = [_]Connection{mk(null, "1.2.3.4", "1.2.3.0/24", "n")};
    try testing.expectError(error.InvalidParams, scan(testing.allocator, &ok, .{ .threshold = 1 }));
    try testing.expectError(error.InvalidParams, scan(testing.allocator, &ok, .{ .max_connections = 0 }));

    const two = [_]Connection{
        mk(null, "1.2.3.4", "1.2.3.0/24", "n"),
        mk(null, "1.2.3.5", "1.2.3.0/24", "m"),
    };
    try testing.expectError(error.TooManyConnections, scan(testing.allocator, &two, .{ .max_connections = 1 }));

    const long = &@as([300]u8, @splat('x'));
    const too_long = [_]Connection{mk(null, "1.2.3.4", "1.2.3.0/24", long)};
    try testing.expectError(error.FieldTooLong, scan(testing.allocator, &too_long, .{ .max_field_len = 256 }));
}

test "no leak on large bounded scan" {
    var conns: [200]Connection = undefined;
    // 100 distinct IPs, each appearing twice -> 100 exact-IP clusters,
    // all in one /24 -> 1 net cluster of 200 members.
    var i: usize = 0;
    var ip_bufs: [100][32]u8 = undefined;
    while (i < 100) : (i += 1) {
        const ip = std.fmt.bufPrint(&ip_bufs[i], "198.51.100.{d}", .{i}) catch unreachable;
        conns[i * 2] = mk(null, ip, "198.51.100.0/24", "na");
        conns[i * 2 + 1] = mk(null, ip, "198.51.100.0/24", "nb");
    }

    var report = try scan(testing.allocator, &conns, .{ .threshold = 2 });
    defer report.deinit();

    try testing.expect(report.clusters[0].members.len == 200);
    try testing.expect(report.clusters[0].kind == .net_prefix);
}
