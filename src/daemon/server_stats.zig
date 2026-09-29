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
const HdrHistogram = @import("../substrate/hdr_histogram.zig").HdrHistogram;

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.Thread.yield() catch {};
}

/// Four fixed, unlabeled latency series. Each reactor owns one recording slot.
pub const LatencyStats = struct {
    pub const Series = enum(u2) {
        tls_handshake,
        privmsg_fanout,
        mooring_rtt,
        media_relay,
    };

    const series_count = 4;
    const bounds = [_]u64{ 100, 500, 1000, 5000, 10000, 50000, 100000 };
    const names = [_][]const u8{
        "onyx_tls_handshake_us",
        "onyx_privmsg_fanout_us",
        "onyx_mooring_rtt_us",
        "onyx_media_relay_us",
    };
    const config = @import("../substrate/hdr_histogram.zig").Config{
        .significant_figures = 2,
        .max_trackable_value = 60_000_000,
    };

    const Slot = struct {
        mutex: std.atomic.Mutex = .unlocked,
        histograms: [series_count]HdrHistogram,
        exact_sums: [series_count]u128 = .{ 0, 0, 0, 0 },
        boundary_corrections: [series_count][bounds.len]u64 = std.mem.zeroes([series_count][bounds.len]u64),
    };

    allocator: std.mem.Allocator,
    published: Slot,
    reactors: []Slot,

    pub fn init(allocator: std.mem.Allocator, reactor_count: usize) !LatencyStats {
        var published: Slot = undefined;
        var ready: usize = 0;
        errdefer for (published.histograms[0..ready]) |*hist| hist.deinit();
        for (&published.histograms) |*hist| {
            hist.* = try HdrHistogram.init(allocator, config);
            ready += 1;
        }
        published.exact_sums = .{ 0, 0, 0, 0 };
        published.boundary_corrections = std.mem.zeroes(@TypeOf(published.boundary_corrections));
        published.mutex = .unlocked;

        const reactors = try allocator.alloc(Slot, reactor_count);
        errdefer allocator.free(reactors);
        var initialized: usize = 0;
        errdefer {
            for (reactors[0..initialized]) |*slot| {
                for (&slot.histograms) |*hist| hist.deinit();
            }
        }
        for (reactors) |*slot| {
            var slot_ready: usize = 0;
            errdefer for (slot.histograms[0..slot_ready]) |*hist| hist.deinit();
            for (&slot.histograms) |*hist| {
                hist.* = try HdrHistogram.init(allocator, config);
                slot_ready += 1;
            }
            slot.exact_sums = .{ 0, 0, 0, 0 };
            slot.boundary_corrections = std.mem.zeroes(@TypeOf(slot.boundary_corrections));
            slot.mutex = .unlocked;
            initialized += 1;
        }
        return .{ .allocator = allocator, .published = published, .reactors = reactors };
    }

    pub fn deinit(self: *LatencyStats) void {
        for (&self.published.histograms) |*hist| hist.deinit();
        for (self.reactors) |*slot| {
            for (&slot.histograms) |*hist| hist.deinit();
        }
        self.allocator.free(self.reactors);
    }

    /// Recording is allocation-free. The caller must use its owning reactor index.
    pub fn record(self: *LatencyStats, series: Series, reactor_index: usize, value_us: u64) void {
        const idx = @intFromEnum(series);
        const slot = &self.reactors[reactor_index];
        lockSpin(&slot.mutex);
        defer slot.mutex.unlock();
        slot.histograms[idx].recordValue(value_us);
        slot.exact_sums[idx] += value_us;
        // HDR buckets can straddle a fixed Prometheus `le` boundary. Retain
        // the count on the included side so cumulative buckets stay exact.
        const sample = @max(@as(u64, 1), value_us);
        const magnitude = slot.histograms[idx].sub_bucket_half_count_magnitude;
        const bits_needed: u32 = 64 - @clz(sample);
        const bucket: u32 = if (bits_needed <= magnitude + 1) 0 else bits_needed - magnitude - 1;
        const width = @as(u64, 1) << @as(u6, @intCast(bucket));
        const lower = (sample / width) * width;
        for (bounds, 0..) |bound, bound_idx| {
            if (sample <= bound and lower + width - 1 > bound) {
                slot.boundary_corrections[idx][bound_idx] += 1;
            }
        }
    }

    /// Only reactor 0 may call this. Slot locks protect concurrent recorders.
    pub fn mergeShards(self: *LatencyStats) void {
        lockSpin(&self.published.mutex);
        defer self.published.mutex.unlock();
        for (self.reactors) |*slot| {
            {
                lockSpin(&slot.mutex);
                defer slot.mutex.unlock();
                for (0..series_count) |idx| {
                    self.published.histograms[idx].merge(slot.histograms[idx]) catch unreachable;
                    slot.histograms[idx].reset();
                    self.published.exact_sums[idx] += slot.exact_sums[idx];
                    slot.exact_sums[idx] = 0;
                    for (0..bounds.len) |bound_idx| {
                        self.published.boundary_corrections[idx][bound_idx] += slot.boundary_corrections[idx][bound_idx];
                        slot.boundary_corrections[idx][bound_idx] = 0;
                    }
                }
            }
        }
    }

    pub fn writePrometheus(self: *const LatencyStats, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const published = @constCast(&self.published);
        lockSpin(&published.mutex);
        defer published.mutex.unlock();
        for (names, 0..) |name, idx| {
            const hist = self.published.histograms[idx];
            try out.print(allocator, "# HELP {s} Observed latency in microseconds\n", .{name});
            try out.print(allocator, "# TYPE {s} histogram\n", .{name});
            for (bounds, 0..) |bound, bound_idx| {
                try out.print(allocator, "{s}_bucket{{le=\"{d}\"}} {d}\n", .{ name, bound, cumulativeCount(hist, bound) + self.published.boundary_corrections[idx][bound_idx] });
            }
            try out.print(allocator, "{s}_bucket{{le=\"+Inf\"}} {d}\n", .{ name, hist.totalCount() });
            try out.print(allocator, "{s}_count {d}\n", .{ name, hist.totalCount() });
            try out.print(allocator, "{s}_sum {d}\n", .{ name, self.published.exact_sums[idx] });
        }
    }

    /// Count buckets wholly below the boundary; exact straddling counts are
    /// added from the bounded correction counters recorded with each sample.
    fn cumulativeCount(hist: HdrHistogram, bound: u64) u64 {
        var count: u64 = 0;
        for (hist.counts, 0..) |n, index| {
            if (n == 0) continue;
            var lower: u64 = undefined;
            var width: u64 = undefined;
            if (index < hist.sub_bucket_count) {
                lower = @intCast(index);
                width = 1;
            } else {
                const relative = index - hist.sub_bucket_count;
                const bucket = relative / hist.sub_bucket_half_count + 1;
                const offset = relative % hist.sub_bucket_half_count;
                width = @as(u64, 1) << @as(u6, @intCast(bucket));
                lower = (@as(u64, hist.sub_bucket_half_count) + offset) * width;
            }
            if (lower + width - 1 <= bound) count += n;
        }
        return count;
    }
};

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

test "GAP-O1 fixed histograms preserve counts sums and peer health" {
    const allocator = testing.allocator;
    var latency = try LatencyStats.init(allocator, 2);
    defer latency.deinit();
    latency.record(.tls_handshake, 0, 100);
    latency.record(.tls_handshake, 0, 100_000);
    latency.record(.privmsg_fanout, 1, 501);
    latency.record(.mooring_rtt, 0, 1_500_000);
    latency.record(.media_relay, 1, 1_001);
    latency.mergeShards();
    latency.mergeShards();

    var stats = Stats{};
    stats.onS2sEstablished();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try stats.writePrometheus(allocator, &out);
    try latency.writePrometheus(allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_s2s_links_active 1\n") != null);
    for ([_][]const u8{
        "onyx_tls_handshake_us_count 2\n",
        "onyx_tls_handshake_us_bucket{le=\"100000\"} 2\n",
        "onyx_tls_handshake_us_sum 100100\n",
        "onyx_privmsg_fanout_us_count 1\n",
        "onyx_mooring_rtt_us_count 1\n",
        "onyx_media_relay_us_count 1\n",
        "onyx_mooring_rtt_us_sum 1500000\n",
        "onyx_privmsg_fanout_us_sum 501\n",
    }) |expected| try testing.expect(std.mem.indexOf(u8, out.items, expected) != null);

    var bucket_lines: usize = 0;
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "_bucket{le=\"") == null) continue;
        bucket_lines += 1;
        var allowed = false;
        inline for ([_][]const u8{ "100", "500", "1000", "5000", "10000", "50000", "100000", "+Inf" }) |label| {
            const suffix = "_bucket{le=\"" ++ label ++ "\"}";
            if (std.mem.indexOf(u8, line, suffix) != null) allowed = true;
        }
        try testing.expect(allowed);
    }
    try testing.expectEqual(@as(usize, 32), bucket_lines);

    var empty = try LatencyStats.init(allocator, 1);
    defer empty.deinit();
    var down = Stats{};
    var empty_out: std.ArrayList(u8) = .empty;
    defer empty_out.deinit(allocator);
    try down.writePrometheus(allocator, &empty_out);
    try empty.writePrometheus(allocator, &empty_out);
    try testing.expect(std.mem.indexOf(u8, empty_out.items, "onyx_s2s_links_active 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, empty_out.items, "onyx_mooring_rtt_us_count 0\n") != null);
}
