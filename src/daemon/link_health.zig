// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-peer S2S mesh link health tracker.
//!
//! Pure data structure + math: maintains live quality metrics for each mesh
//! peer link that the `MESH`/`NETSTAT` oper view consumes. It owns no sockets
//! and no server types. The registry copies peer names on insert so callers
//! may pass transient slices, and it grows with the number of peers. There is
//! no fixed peer count and no name-length ceiling.
//!
//! Time is supplied by the caller as a monotonic millisecond clock; this module
//! never reads the system clock.
const std = @import("std");

/// Lifecycle state of a mesh peer link. Names mirror the Undertow link state
/// machine (idle -> handshaking -> established -> draining) so values map 1:1
/// onto the mesh report enum, with `connecting` covering pre-handshake dialing
/// and `down` covering a closed/dead link.
pub const PeerState = enum {
    connecting,
    handshaking,
    established,
    draining,
    down,
};

/// Number of recent RTT samples retained for jitter estimation.
pub const rtt_ring_len: usize = 8;

/// EWMA smoothing factor numerator/denominator. The smoothed RTT is updated as
///   ewma = ewma + alpha * (sample - ewma)
/// with alpha = alpha_num / alpha_den. The default (1/8) weights history
/// heavily while still tracking sustained changes, matching common TCP RTT
/// smoothing practice.
pub const default_alpha_num: u32 = 1;
pub const default_alpha_den: u32 = 8;

/// Live health metrics for a single mesh peer link.
pub const LinkHealth = struct {
    /// Current lifecycle state.
    state: PeerState = .connecting,
    /// Monotonic-ms timestamp of the last state transition.
    state_since_ms: u64 = 0,
    /// Monotonic-ms timestamp of the last observed activity (rtt/bytes).
    last_activity_ms: u64 = 0,

    /// Bytes sitting in this peer's outbound queue. Independent of RTT.
    send_backlog_bytes: u64 = 0,
    /// Monotonic ms of the last finished anti-entropy round, or null.
    last_anti_entropy_ms: ?u64 = null,
    /// Mesh says this peer is on the other side of a partition. Distinct from
    /// `state == .down`, which means the peer itself is gone.
    partitioned: bool = false,
    /// Ripple's suspicion of this peer. Not a value-sync state.
    ripple: RippleSuspicion = .none,
    /// Value-sync progress with this peer. Not a Ripple suspicion.
    value_sync: ValueSync = .idle,

    /// Smoothed RTT in milliseconds (fixed-point f64), or null until the first
    /// sample is observed.
    ewma_rtt_ms: ?f64 = null,
    /// EWMA smoothing factor.
    alpha_num: u32 = default_alpha_num,
    alpha_den: u32 = default_alpha_den,

    /// Cumulative bytes received from / sent to this peer.
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,

    /// Bounded ring of recent raw RTT samples (ms) for jitter estimation.
    rtt_ring: [rtt_ring_len]u32 = @splat(0),
    /// Number of valid entries currently in the ring (saturates at len).
    rtt_count: u8 = 0,
    /// Next write index into the ring.
    rtt_head: u8 = 0,

    /// Create a health record in the initial `connecting` state at `now_ms`.
    pub fn init(now_ms: u64) LinkHealth {
        return .{
            .state = .connecting,
            .state_since_ms = now_ms,
            .last_activity_ms = now_ms,
        };
    }

    /// Create a health record with a custom EWMA alpha. `alpha_den` is clamped
    /// to at least 1 to avoid division by zero.
    pub fn initWithAlpha(now_ms: u64, alpha_num: u32, alpha_den: u32) LinkHealth {
        var self = init(now_ms);
        self.alpha_num = alpha_num;
        self.alpha_den = @max(alpha_den, 1);
        return self;
    }

    /// Record a state transition. Resets the in-state timer to `now_ms` and
    /// counts as activity. Transitioning to the same state still refreshes the
    /// timestamp (e.g. a re-handshake).
    pub fn transition(self: *LinkHealth, new_state: PeerState, now_ms: u64) void {
        self.state = new_state;
        self.state_since_ms = now_ms;
        self.last_activity_ms = now_ms;
    }

    /// Milliseconds spent in the current state as of `now_ms`. Guards against a
    /// clock that appears to move backwards by returning 0.
    pub fn since(self: *const LinkHealth, now_ms: u64) u64 {
        if (now_ms <= self.state_since_ms) return 0;
        return now_ms - self.state_since_ms;
    }

    /// Feed a fresh RTT sample (ms). Updates the EWMA, pushes onto the jitter
    /// ring, and marks activity.
    pub fn observeRtt(self: *LinkHealth, rtt_ms: u32, now_ms: u64) void {
        const sample: f64 = @floatFromInt(rtt_ms);
        if (self.ewma_rtt_ms) |prev| {
            const alpha = @as(f64, @floatFromInt(self.alpha_num)) /
                @as(f64, @floatFromInt(@max(self.alpha_den, 1)));
            self.ewma_rtt_ms = prev + alpha * (sample - prev);
        } else {
            self.ewma_rtt_ms = sample;
        }

        self.rtt_ring[self.rtt_head] = rtt_ms;
        self.rtt_head = @intCast((@as(usize, self.rtt_head) + 1) % rtt_ring_len);
        if (self.rtt_count < rtt_ring_len) self.rtt_count += 1;

        self.last_activity_ms = now_ms;
    }

    /// Accumulate received-byte count and mark activity.
    pub fn addIn(self: *LinkHealth, n: u64, now_ms: u64) void {
        self.bytes_in +%= n;
        self.last_activity_ms = now_ms;
    }

    /// Accumulate sent-byte count and mark activity.
    pub fn addOut(self: *LinkHealth, n: u64, now_ms: u64) void {
        self.bytes_out +%= n;
        self.last_activity_ms = now_ms;
    }

    /// Smoothed RTT rounded to whole milliseconds. Returns 0 if no sample yet.
    pub fn snapshotRtt(self: *const LinkHealth) u32 {
        const v = self.ewma_rtt_ms orelse return 0;
        if (v <= 0) return 0;
        return @intFromFloat(@round(v));
    }

    /// Mean absolute deviation of the retained RTT samples, in ms. A crude but
    /// stable jitter estimate; returns 0 with fewer than two samples.
    pub fn jitterMs(self: *const LinkHealth) u32 {
        const n: usize = self.rtt_count;
        if (n < 2) return 0;

        var sum: u64 = 0;
        for (0..n) |i| sum += self.rtt_ring[i];
        const mean: f64 = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(n));

        var dev: f64 = 0;
        for (0..n) |i| {
            const s: f64 = @floatFromInt(self.rtt_ring[i]);
            dev += @abs(s - mean);
        }
        const jitter = dev / @as(f64, @floatFromInt(n));
        if (jitter <= 0) return 0;
        return @intFromFloat(@round(jitter));
    }

    /// Milliseconds since the last observed activity as of `now_ms`.
    pub fn idleMs(self: *const LinkHealth, now_ms: u64) u64 {
        if (now_ms <= self.last_activity_ms) return 0;
        return now_ms - self.last_activity_ms;
    }

    /// A "still here" liveness update. `peer_hlc` is ignored: an older hybrid
    /// logical clock must not freeze the local activity stamp.
    pub fn noteStillHere(self: *LinkHealth, now_ms: u64, peer_hlc: u64) void {
        _ = peer_hlc;
        self.last_activity_ms = now_ms;
    }

    pub fn noteSendBacklog(self: *LinkHealth, bytes: u64) void {
        self.send_backlog_bytes = bytes;
    }

    pub fn noteAntiEntropy(self: *LinkHealth, now_ms: u64) void {
        self.last_anti_entropy_ms = now_ms;
    }

    pub fn isDown(self: *const LinkHealth) bool {
        return self.state == .down;
    }
};

/// Ripple failure suspicion. Kept off the value-sync field on purpose.
pub const RippleSuspicion = enum { none, suspect, dead };

/// Anti-entropy / value-sync progress. Kept off the Ripple field on purpose.
pub const ValueSync = enum { idle, syncing, synced };

/// One peer in the registry. The name is an owned copy of the full peer id.
pub const Entry = struct {
    name_bytes: []u8,
    health: LinkHealth = .{},

    /// Borrowed view of this entry's owned name bytes.
    pub fn name(self: *const Entry) []const u8 {
        return self.name_bytes;
    }
};

/// Growable peer-link table. Insert copies the name and appends a slot; the
/// table's length is the number of peers, not a compile-time ceiling.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Registry) void {
        for (self.entries.items) |entry| self.allocator.free(entry.name_bytes);
        self.entries.deinit(self.allocator);
    }

    /// Number of peers currently tracked.
    pub fn len(self: *const Registry) usize {
        return self.entries.items.len;
    }

    /// Find the health record for `name`, or null if absent.
    pub fn get(self: *Registry, name: []const u8) ?*LinkHealth {
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.name_bytes, name)) return &entry.health;
        }
        return null;
    }

    /// Find the full entry for `name`, or null if absent.
    pub fn getEntry(self: *Registry, name: []const u8) ?*Entry {
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.name_bytes, name)) return entry;
        }
        return null;
    }

    /// Return the existing record for `name`, or create a fresh one in the
    /// `connecting` state. Copies the whole name. A returned pointer is valid
    /// until the next insert that grows the table.
    pub fn upsert(self: *Registry, name: []const u8, now_ms: u64) !*LinkHealth {
        if (self.get(name)) |existing| return existing;
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.entries.append(self.allocator, .{
            .name_bytes = owned,
            .health = LinkHealth.init(now_ms),
        });
        return &self.entries.items[self.entries.items.len - 1].health;
    }

    /// Remove the record for `name`. Returns true if a peer was dropped.
    pub fn remove(self: *Registry, name: []const u8) bool {
        for (self.entries.items, 0..) |entry, i| {
            if (!std.mem.eql(u8, entry.name_bytes, name)) continue;
            const removed = self.entries.swapRemove(i);
            self.allocator.free(removed.name_bytes);
            return true;
        }
        return false;
    }

    /// Prometheus gauges for the four per-peer facts, plus Ripple suspicion
    /// and value-sync as their own series. One sample per peer.
    pub fn writePrometheus(self: *Registry, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        try out.print(allocator, "# HELP onyx_peer_rtt_ms Smoothed Mooring RTT for this peer in milliseconds\n", .{});
        try out.print(allocator, "# TYPE onyx_peer_rtt_ms gauge\n", .{});
        try out.print(allocator, "# HELP onyx_peer_send_backlog_bytes Bytes queued toward this peer\n", .{});
        try out.print(allocator, "# TYPE onyx_peer_send_backlog_bytes gauge\n", .{});
        try out.print(allocator, "# HELP onyx_peer_last_anti_entropy_ms Monotonic milliseconds of the last anti-entropy round; 0 means none yet\n", .{});
        try out.print(allocator, "# TYPE onyx_peer_last_anti_entropy_ms gauge\n", .{});
        try out.print(allocator, "# HELP onyx_peer_partitioned 1 when the mesh reports this peer partitioned\n", .{});
        try out.print(allocator, "# TYPE onyx_peer_partitioned gauge\n", .{});
        try out.print(allocator, "# HELP onyx_peer_down 1 when the peer link state is down\n", .{});
        try out.print(allocator, "# TYPE onyx_peer_down gauge\n", .{});
        try out.print(allocator, "# HELP onyx_peer_ripple_suspicion Ripple suspicion 0=none 1=suspect 2=dead\n", .{});
        try out.print(allocator, "# TYPE onyx_peer_ripple_suspicion gauge\n", .{});
        try out.print(allocator, "# HELP onyx_peer_value_sync Value-sync 0=idle 1=syncing 2=synced\n", .{});
        try out.print(allocator, "# TYPE onyx_peer_value_sync gauge\n", .{});
        for (self.entries.items) |*entry| {
            const h = entry.health;
            try writePeerGauge(allocator, out, "onyx_peer_rtt_ms", entry.name(), h.snapshotRtt());
            try writePeerGauge(allocator, out, "onyx_peer_send_backlog_bytes", entry.name(), h.send_backlog_bytes);
            try writePeerGauge(allocator, out, "onyx_peer_last_anti_entropy_ms", entry.name(), h.last_anti_entropy_ms orelse 0);
            try writePeerGauge(allocator, out, "onyx_peer_partitioned", entry.name(), @as(u8, if (h.partitioned) 1 else 0));
            try writePeerGauge(allocator, out, "onyx_peer_down", entry.name(), @as(u8, if (h.isDown()) 1 else 0));
            try writePeerGauge(allocator, out, "onyx_peer_ripple_suspicion", entry.name(), @intFromEnum(h.ripple));
            try writePeerGauge(allocator, out, "onyx_peer_value_sync", entry.name(), @intFromEnum(h.value_sync));
        }
    }

    /// One oper line per peer. Same facts as `writePrometheus`.
    pub fn writeOperView(self: *Registry, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        for (self.entries.items) |*entry| {
            const h = entry.health;
            try out.print(allocator, "peer={s} rtt_ms={d} send_backlog={d} anti_entropy_ms={d} partitioned={d} down={d} ripple={s} value_sync={s}\n", .{
                entry.name(),
                h.snapshotRtt(),
                h.send_backlog_bytes,
                h.last_anti_entropy_ms orelse 0,
                @as(u8, if (h.partitioned) 1 else 0),
                @as(u8, if (h.isDown()) 1 else 0),
                @tagName(h.ripple),
                @tagName(h.value_sync),
            });
        }
    }
};

fn writePeerGauge(allocator: std.mem.Allocator, out: *std.ArrayList(u8), metric: []const u8, peer: []const u8, value: anytype) !void {
    try out.print(allocator, "{s}{{peer=\"", .{metric});
    for (peer) |c| switch (c) {
        '\\', '"' => {
            try out.append(allocator, '\\');
            try out.append(allocator, c);
        },
        '\n' => try out.appendSlice(allocator, "\\n"),
        else => try out.append(allocator, c),
    };
    try out.print(allocator, "\"}} {d}\n", .{value});
}

const testing = std.testing;

test "EWMA converges toward a steady RTT" {
    // Arrange
    var h = LinkHealth.init(0);

    // Act: feed a constant 100ms RTT repeatedly from a cold start.
    var t: u64 = 0;
    for (0..40) |_| {
        t += 10;
        h.observeRtt(100, t);
    }

    // Assert: smoothed RTT should be at (first sample seeds it) the steady value.
    try testing.expectEqual(@as(u32, 100), h.snapshotRtt());

    // Act: now shift the steady value to 200ms and let it converge.
    for (0..200) |_| {
        t += 10;
        h.observeRtt(200, t);
    }

    // Assert: EWMA tracks the new steady state.
    try testing.expectEqual(@as(u32, 200), h.snapshotRtt());
}

test "EWMA seeds on first sample then smooths a step" {
    // Arrange: alpha = 1/2 so a step moves the average halfway each tick.
    var h = LinkHealth.initWithAlpha(0, 1, 2);

    // Act + Assert: first sample seeds directly.
    h.observeRtt(40, 1);
    try testing.expectEqual(@as(u32, 40), h.snapshotRtt());

    // Step to 80: 40 + 0.5*(80-40) = 60.
    h.observeRtt(80, 2);
    try testing.expectEqual(@as(u32, 60), h.snapshotRtt());

    // Again: 60 + 0.5*(80-60) = 70.
    h.observeRtt(80, 3);
    try testing.expectEqual(@as(u32, 70), h.snapshotRtt());
}

test "snapshotRtt is zero before any sample" {
    const h = LinkHealth.init(5);
    try testing.expectEqual(@as(u32, 0), h.snapshotRtt());
    try testing.expectEqual(@as(u32, 0), h.jitterMs());
}

test "state transitions update since and reset the timer" {
    // Arrange
    var h = LinkHealth.init(1000);
    try testing.expectEqual(PeerState.connecting, h.state);
    try testing.expectEqual(@as(u64, 0), h.since(1000));
    try testing.expectEqual(@as(u64, 250), h.since(1250));

    // Act
    h.transition(.handshaking, 1300);

    // Assert: timer resets at the transition moment.
    try testing.expectEqual(PeerState.handshaking, h.state);
    try testing.expectEqual(@as(u64, 0), h.since(1300));
    try testing.expectEqual(@as(u64, 700), h.since(2000));

    // Act + Assert: full lifecycle to down.
    h.transition(.established, 2000);
    try testing.expectEqual(PeerState.established, h.state);
    h.transition(.draining, 3000);
    h.transition(.down, 3500);
    try testing.expectEqual(PeerState.down, h.state);
    try testing.expectEqual(@as(u64, 500), h.since(4000));
}

test "since guards against a backwards clock" {
    var h = LinkHealth.init(1000);
    try testing.expectEqual(@as(u64, 0), h.since(900));
}

test "byte counters accumulate independently" {
    // Arrange
    var h = LinkHealth.init(0);

    // Act
    h.addIn(100, 1);
    h.addIn(50, 2);
    h.addOut(200, 3);

    // Assert
    try testing.expectEqual(@as(u64, 150), h.bytes_in);
    try testing.expectEqual(@as(u64, 200), h.bytes_out);
    try testing.expectEqual(@as(u64, 3), h.last_activity_ms);
    try testing.expectEqual(@as(u64, 7), h.idleMs(10));
}

test "jitter is zero for constant samples and positive for varying ones" {
    // Arrange: constant RTT -> no jitter.
    var steady = LinkHealth.init(0);
    for (0..5) |i| steady.observeRtt(50, @intCast(i));
    try testing.expectEqual(@as(u32, 0), steady.jitterMs());

    // Act: alternating samples produce non-zero jitter.
    var noisy = LinkHealth.init(0);
    noisy.observeRtt(10, 1);
    noisy.observeRtt(90, 2);
    noisy.observeRtt(10, 3);
    noisy.observeRtt(90, 4);

    // Assert: mean is 50, mean abs deviation is 40.
    try testing.expectEqual(@as(u32, 40), noisy.jitterMs());
}

test "jitter ring is bounded and wraps" {
    // Arrange
    var h = LinkHealth.init(0);

    // Act: push more than the ring capacity.
    for (0..rtt_ring_len + 4) |i| h.observeRtt(@intCast(i), @intCast(i));

    // Assert: count saturates at the ring length.
    try testing.expectEqual(@as(u8, @intCast(rtt_ring_len)), h.rtt_count);
}

test "registry upsert returns same record and is idempotent" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    const a1 = try reg.upsert("alpha", 100);
    a1.transition(.established, 200);
    const a2 = try reg.upsert("alpha", 999);

    try testing.expectEqual(a1, a2);
    try testing.expectEqual(PeerState.established, a2.state);
    try testing.expectEqual(@as(usize, 1), reg.len());
}

test "registry get and remove" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.upsert("beta", 0);
    _ = try reg.upsert("gamma", 0);

    try testing.expect(reg.get("beta") != null);
    try testing.expect(reg.get("missing") == null);
    try testing.expect(reg.remove("beta"));
    try testing.expect(reg.get("beta") == null);
    try testing.expect(!reg.remove("beta"));
    try testing.expectEqual(@as(usize, 1), reg.len());
}

test "registry owns name bytes copied from transient slices" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var buf = [_]u8{ 'p', 'e', 'e', 'r', '1' };

    _ = try reg.upsert(&buf, 0);
    @memset(&buf, 'x');

    const entry = reg.getEntry("peer1").?;
    try testing.expectEqualStrings("peer1", entry.name());
}

test "registry grows past the old 64-peer ceiling and keeps the full name" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var name_buf: [16]u8 = undefined;
    for (0..128) |i| {
        const name = std.fmt.bufPrint(&name_buf, "peer-{d}", .{i}) catch unreachable;
        _ = try reg.upsert(name, @intCast(i));
    }
    try testing.expectEqual(@as(usize, 128), reg.len());
    try testing.expect(reg.get("peer-0") != null);
    try testing.expect(reg.get("peer-127") != null);

    var long_buf: [200]u8 = @splat('n');
    const long = long_buf[0..];
    _ = try reg.upsert(long, 0);
    const entry = reg.getEntry(long).?;
    try testing.expectEqual(long.len, entry.name().len);
    try testing.expectEqualStrings(long, entry.name());
    try testing.expectEqual(@as(usize, 129), reg.len());
}

test "registry remove drops one peer and leaves the rest" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.upsert("a", 0);
    _ = try reg.upsert("b", 0);
    _ = try reg.upsert("c", 0);
    try testing.expect(reg.remove("b"));

    try testing.expect(reg.get("a") != null);
    try testing.expect(reg.get("b") == null);
    try testing.expect(reg.get("c") != null);
    try testing.expectEqual(@as(usize, 2), reg.len());
}

test "GAP-O2 peer facts stay distinct and a stale HLC still counts as present" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const slow = try reg.upsert("slow", 0);
    slow.transition(.established, 1_000);
    slow.observeRtt(800, 1_000);
    slow.noteSendBacklog(4096);
    slow.noteAntiEntropy(50);
    slow.ripple = .suspect;
    slow.value_sync = .syncing;
    slow.noteStillHere(1_100, 0);
    try testing.expectEqual(@as(u64, 0), slow.idleMs(1_100));

    const gone = try reg.upsert("gone", 0);
    gone.transition(.down, 1_000);

    const split = try reg.upsert("split", 0);
    split.transition(.established, 1_000);
    split.partitioned = true;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try reg.writePrometheus(testing.allocator, &out);
    try reg.writeOperView(testing.allocator, &out);
    const text = out.items;
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_rtt_ms{peer=\"slow\"} 800\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_send_backlog_bytes{peer=\"slow\"} 4096\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_last_anti_entropy_ms{peer=\"slow\"} 50\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_down{peer=\"gone\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_partitioned{peer=\"gone\"} 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_partitioned{peer=\"split\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_down{peer=\"split\"} 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_ripple_suspicion{peer=\"slow\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_peer_value_sync{peer=\"slow\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "peer=slow rtt_ms=800 send_backlog=4096 anti_entropy_ms=50 partitioned=0 down=0 ripple=suspect value_sync=syncing\n") != null);
    std.debug.print("GAP-O2 branch=peer rtt backlog anti-entropy partitioned-vs-down; hlc does not gate liveness\n", .{});
}
