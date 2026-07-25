// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free runtime counters for the daemon hot path.
//!
//! The hot path (accept/recv/send/line dispatch) must never allocate or take a
//! lock to record a metric, so counters are atomic values bumped inline.
//! Rendering — Prometheus exposition text or an oper STATS dump — is a
//! cold path that snapshots the counters into a caller-provided buffer.
//!
//! These complement the structured `qlog`/`trace` flight recorder (which keeps
//! the last N *events*); this keeps monotonic *totals* and a couple of gauges.
const std = @import("std");

/// Monotonic counters (only ever increase) plus two gauges (active connections,
/// established S2S links) which move both ways. The server embeds one.
pub const Stats = struct {
    const AtomicU64 = std.atomic.Value(u64);
    const AtomicI64 = std.atomic.Value(i64);

    // --- counters (monotonic) ---
    connections_total: AtomicU64 = .init(0),
    s2s_accepts_total: AtomicU64 = .init(0),
    messages_in_total: AtomicU64 = .init(0),
    bytes_in_total: AtomicU64 = .init(0),
    bytes_out_total: AtomicU64 = .init(0),
    errors_total: AtomicU64 = .init(0),
    quits_total: AtomicU64 = .init(0),

    // --- gauges (up/down) ---
    connections_active: AtomicI64 = .init(0),
    /// Mooring-/S2S-**established** peer links (AKE complete). Not TCP accepts.
    s2s_links_active: AtomicI64 = .init(0),
    /// TCP-level S2S peer slots currently open (inbound accept or outbound dial).
    /// Useful for "dial stuck before AKE" diagnosis; not the mesh-health signal.
    s2s_tcp_active: AtomicI64 = .init(0),

    pub fn onAccept(self: *Stats) void {
        _ = self.connections_total.fetchAdd(1, .monotonic);
        _ = self.connections_active.fetchAdd(1, .monotonic);
    }

    /// TCP S2S peer accepted or outbound dial slot opened. Does **not** mean
    /// Mooring is up — use `onS2sEstablished` for that.
    pub fn onS2sAccept(self: *Stats) void {
        _ = self.s2s_accepts_total.fetchAdd(1, .monotonic);
        _ = self.s2s_tcp_active.fetchAdd(1, .monotonic);
    }

    /// Secured (or plaintext CRDT) link finished handshake — mesh-routable peer.
    pub fn onS2sEstablished(self: *Stats) void {
        _ = self.s2s_links_active.fetchAdd(1, .monotonic);
    }

    /// A connection closed. `was_s2s` selects S2S gauges; `s2s_was_established`
    /// drops the Mooring-established gauge only when AKE had completed.
    pub fn onClose(self: *Stats, was_s2s: bool, s2s_was_established: bool) void {
        if (was_s2s) {
            decrementPositive(&self.s2s_tcp_active);
            if (s2s_was_established) decrementPositive(&self.s2s_links_active);
        } else {
            decrementPositive(&self.connections_active);
        }
    }

    /// Backward-compatible close for client-only paths.
    pub fn onCloseClient(self: *Stats) void {
        self.onClose(false, false);
    }

    pub fn onBytesIn(self: *Stats, n: usize) void {
        _ = self.bytes_in_total.fetchAdd(@as(u64, @intCast(n)), .monotonic);
    }

    pub fn onBytesOut(self: *Stats, n: usize) void {
        _ = self.bytes_out_total.fetchAdd(@as(u64, @intCast(n)), .monotonic);
    }

    pub fn onLine(self: *Stats) void {
        _ = self.messages_in_total.fetchAdd(1, .monotonic);
    }

    pub fn onError(self: *Stats) void {
        _ = self.errors_total.fetchAdd(1, .monotonic);
    }

    pub fn onQuit(self: *Stats) void {
        _ = self.quits_total.fetchAdd(1, .monotonic);
    }

    /// One metric's identity for rendering: Prometheus name, HELP text, type, and
    /// the live value. `prom` is the metric name; `irc` is the short token used
    /// in the oper STATS dump.
    const Row = struct {
        prom: []const u8,
        irc: []const u8,
        help: []const u8,
        kind: enum { counter, gauge },
        value: i128,
    };

    fn rows(self: *const Stats) [10]Row {
        return .{
            .{ .prom = "onyx_connections_total", .irc = "conns", .help = "Total client connections accepted", .kind = .counter, .value = self.connections_total.load(.acquire) },
            .{ .prom = "onyx_connections_active", .irc = "conns_active", .help = "Currently open client connections", .kind = .gauge, .value = self.connections_active.load(.acquire) },
            .{ .prom = "onyx_s2s_accepts_total", .irc = "s2s", .help = "Total server-to-server TCP peer slots opened", .kind = .counter, .value = self.s2s_accepts_total.load(.acquire) },
            .{ .prom = "onyx_s2s_tcp_active", .irc = "s2s_tcp", .help = "Currently open S2S TCP peer slots (pre- or post-AKE)", .kind = .gauge, .value = self.s2s_tcp_active.load(.acquire) },
            .{ .prom = "onyx_s2s_links_active", .irc = "s2s_active", .help = "Currently Mooring/CRDT-established S2S links", .kind = .gauge, .value = self.s2s_links_active.load(.acquire) },
            .{ .prom = "onyx_messages_in_total", .irc = "msgs_in", .help = "Total complete protocol lines received", .kind = .counter, .value = self.messages_in_total.load(.acquire) },
            .{ .prom = "onyx_bytes_in_total", .irc = "bytes_in", .help = "Total bytes received from clients", .kind = .counter, .value = self.bytes_in_total.load(.acquire) },
            .{ .prom = "onyx_bytes_out_total", .irc = "bytes_out", .help = "Total bytes queued to clients", .kind = .counter, .value = self.bytes_out_total.load(.acquire) },
            .{ .prom = "onyx_quits_total", .irc = "quits", .help = "Total client disconnects", .kind = .counter, .value = self.quits_total.load(.acquire) },
            .{ .prom = "onyx_errors_total", .irc = "errors", .help = "Total recoverable hot-path errors", .kind = .counter, .value = self.errors_total.load(.acquire) },
        };
    }

    fn decrementPositive(counter: *AtomicI64) void {
        var current = counter.load(.monotonic);
        while (current > 0) {
            if (counter.cmpxchgWeak(current, current - 1, .monotonic, .monotonic)) |next| {
                current = next;
            } else {
                return;
            }
        }
    }

    /// Append Prometheus exposition text (HELP/TYPE/sample per metric) to `out`.
    pub fn writePrometheus(self: *const Stats, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        for (self.rows()) |row| {
            try out.print(allocator, "# HELP {s} {s}\n", .{ row.prom, row.help });
            try out.print(allocator, "# TYPE {s} {s}\n", .{ row.prom, @tagName(row.kind) });
            try out.print(allocator, "{s} {d}\n", .{ row.prom, row.value });
        }
    }

    /// Emit one compact `token=value` line per metric via `sink` (e.g. an oper
    /// notice callback). Never allocates; formats into a small stack buffer.
    pub fn forEachLine(
        self: *const Stats,
        ctx: anytype,
        comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void,
    ) !void {
        var buf: [96]u8 = undefined;
        for (self.rows()) |row| {
            const line = std.fmt.bufPrint(&buf, "{s} = {d}", .{ row.irc, row.value }) catch continue;
            try emit(ctx, line);
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "counters and gauges move as expected" {
    var s = Stats{};
    s.onAccept();
    s.onAccept();
    s.onBytesIn(100);
    s.onLine();
    s.onClose(false, false);
    try testing.expectEqual(@as(u64, 2), s.connections_total.load(.acquire));
    try testing.expectEqual(@as(i64, 1), s.connections_active.load(.acquire));
    try testing.expectEqual(@as(u64, 100), s.bytes_in_total.load(.acquire));
    try testing.expectEqual(@as(u64, 1), s.messages_in_total.load(.acquire));
}

test "gauges never go negative on extra closes" {
    var s = Stats{};
    s.onClose(false, false);
    s.onClose(true, false);
    s.onClose(true, true);
    try testing.expectEqual(@as(i64, 0), s.connections_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_tcp_active.load(.acquire));
}

test "s2s TCP accept is distinct from Mooring established" {
    var s = Stats{};
    s.onS2sAccept();
    try testing.expectEqual(@as(i64, 1), s.s2s_tcp_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.connections_active.load(.acquire));
    s.onS2sEstablished();
    try testing.expectEqual(@as(i64, 1), s.s2s_links_active.load(.acquire));
    s.onClose(true, true);
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_tcp_active.load(.acquire));
}

test "prometheus export carries HELP, TYPE, and samples" {
    const allocator = testing.allocator;
    var s = Stats{};
    s.onAccept();
    s.onBytesIn(42);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try s.writePrometheus(allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "# TYPE onyx_connections_total counter") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_bytes_in_total 42") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_connections_active 1") != null);
}

test "forEachLine emits one token line per metric" {
    var s = Stats{};
    s.onAccept();
    const Collector = struct {
        count: usize = 0,
        saw_conns: bool = false,
        fn emit(self: *@This(), line: []const u8) !void {
            self.count += 1;
            if (std.mem.startsWith(u8, line, "conns =")) self.saw_conns = true;
        }
    };
    var c = Collector{};
    try s.forEachLine(&c, Collector.emit);
    try testing.expectEqual(@as(usize, 10), c.count);
    try testing.expect(c.saw_conns);
}
