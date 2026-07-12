// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic per-IP connection clone and reconnect throttle detection.
//!
//! Callers provide a stable IP string and monotonic-ish time in milliseconds.
//! This module reads no clock and performs no I/O. State is bounded by
//! `max_tracked_ips`, `max_ip_len`, and `max_connects_per_window`.
//!
//! When the tracking table is saturated (more distinct source IPs than
//! `max_tracked_ips`, even after pruning window-expired empty entries) a new,
//! untracked source IP is reported `.connect_throttled` — a full table means the
//! node is under a distributed connect flood, exactly what this throttle exists
//! to blunt. It fails TOWARD refuse and never admits a new IP for free once
//! saturated (an earlier design erred here, which a caller could only swallow as
//! a fail-OPEN admit).
const std = @import("std");

pub const Decision = enum {
    allow,
    clone_limited,
    connect_throttled,
};

pub const Params = struct {
    max_concurrent_per_ip: usize,
    max_connects_per_window: usize,
    window_ms: u64,
    max_tracked_ips: usize = 4096,
    max_ip_len: usize = 128,
};

pub const CloneDetectError = error{
    EmptyIp,
    IpTooLong,
    InvalidParams,
} || std.mem.Allocator.Error;

pub const CloneDetector = struct {
    allocator: std.mem.Allocator,
    params: Params,
    ips: std.StringHashMap(IpState),

    pub fn init(allocator: std.mem.Allocator, params: Params) CloneDetector {
        std.debug.assert(validParams(params));
        return .{
            .allocator = allocator,
            .params = params,
            .ips = std.StringHashMap(IpState).init(allocator),
        };
    }

    pub fn initChecked(allocator: std.mem.Allocator, params: Params) CloneDetectError!CloneDetector {
        if (!validParams(params)) return error.InvalidParams;
        return init(allocator, params);
    }

    pub fn deinit(self: *CloneDetector) void {
        var it = self.ips.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.ips.deinit();
        self.* = undefined;
    }

    /// Classify and, when allowed, record a new active connection for `ip`.
    pub fn classifyConnect(self: *CloneDetector, now_ms: i64, ip: []const u8) CloneDetectError!Decision {
        try self.validateIp(ip);

        if (self.ips.getPtr(ip)) |state| {
            state.prune(now_ms, self.params.window_ms);
            return self.classifyExisting(now_ms, state);
        }

        // A saturated table means the node is tracking more distinct source IPs
        // than its bound — a distributed connect flood. Fail TOWARD refuse rather
        // than admitting the new IP untracked.
        if (!self.hasRoomForNewIp(now_ms)) return .connect_throttled;

        const owned_ip = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned_ip);

        var state: IpState = .{};
        errdefer state.deinit(self.allocator);

        const decision = try self.classifyExisting(now_ms, &state);
        if (decision == .allow) {
            try self.ips.put(owned_ip, state);
        }
        return decision;
    }

    /// Release one active connection for `ip`. Returns false when none exists.
    pub fn disconnect(self: *CloneDetector, ip: []const u8) bool {
        const state = self.ips.getPtr(ip) orelse return false;
        if (state.active == 0) return false;
        state.active -= 1;
        return true;
    }

    pub fn prune(self: *CloneDetector, now_ms: i64) void {
        while (self.removeOneExpiredEmptyIp(now_ms)) {}
    }

    pub fn activeCount(self: *const CloneDetector, ip: []const u8) usize {
        const state = self.ips.getPtr(ip) orelse return 0;
        return state.active;
    }

    pub fn recentCount(self: *const CloneDetector, ip: []const u8) usize {
        const state = self.ips.getPtr(ip) orelse return 0;
        return state.recent.items.len;
    }

    pub fn trackedIps(self: *const CloneDetector) usize {
        return self.ips.count();
    }

    fn classifyExisting(self: *CloneDetector, now_ms: i64, state: *IpState) CloneDetectError!Decision {
        // `max_concurrent_per_ip == 0` disables the concurrent dimension, leaving
        // a pure connection-rate throttle (used when a separate limiter owns the
        // concurrent cap). `active` is still tracked for empty-state pruning.
        if (self.params.max_concurrent_per_ip != 0 and state.active >= self.params.max_concurrent_per_ip) {
            return .clone_limited;
        }
        if (state.recent.items.len >= self.params.max_connects_per_window) {
            return .connect_throttled;
        }

        try state.recent.append(self.allocator, now_ms);
        state.active += 1;
        return .allow;
    }

    /// Whether a new source IP can be tracked. At the bound, first reclaim room
    /// by pruning window-expired empty entries; a still-full table has no room
    /// (the caller fails toward refuse). Reads `now_ms`, never a clock.
    fn hasRoomForNewIp(self: *CloneDetector, now_ms: i64) bool {
        if (self.ips.count() < self.params.max_tracked_ips) return true;
        self.prune(now_ms);
        return self.ips.count() < self.params.max_tracked_ips;
    }

    fn removeOneExpiredEmptyIp(self: *CloneDetector, now_ms: i64) bool {
        var it = self.ips.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.prune(now_ms, self.params.window_ms);
            if (!entry.value_ptr.empty()) continue;

            const key = entry.key_ptr.*;
            const removed = self.ips.fetchRemove(key).?;
            self.allocator.free(removed.key);
            var state = removed.value;
            state.deinit(self.allocator);
            return true;
        }
        return false;
    }

    fn validateIp(self: *const CloneDetector, ip: []const u8) CloneDetectError!void {
        if (ip.len == 0) return error.EmptyIp;
        if (ip.len > self.params.max_ip_len) return error.IpTooLong;
    }
};

const IpState = struct {
    active: usize = 0,
    recent: std.ArrayList(i64) = .empty,

    fn deinit(self: *IpState, allocator: std.mem.Allocator) void {
        self.recent.deinit(allocator);
        self.* = undefined;
    }

    fn prune(self: *IpState, now_ms: i64, window_ms: u64) void {
        var write: usize = 0;
        for (self.recent.items) |connected_at| {
            if (insideWindow(connected_at, now_ms, window_ms)) {
                self.recent.items[write] = connected_at;
                write += 1;
            }
        }
        self.recent.shrinkRetainingCapacity(write);
    }

    fn empty(self: *const IpState) bool {
        return self.active == 0 and self.recent.items.len == 0;
    }
};

fn validParams(params: Params) bool {
    // `max_concurrent_per_ip` may be 0 (concurrent dimension disabled → pure
    // connection-rate throttle); the rate window must always be configured.
    return params.max_connects_per_window > 0 and
        params.window_ms > 0 and
        params.max_tracked_ips > 0 and
        params.max_ip_len > 0;
}

fn insideWindow(connected_at: i64, now_ms: i64, window_ms: u64) bool {
    const delta = @as(i128, now_ms) - @as(i128, connected_at);
    if (delta < 0) return true;
    return @as(u128, @intCast(delta)) < @as(u128, window_ms);
}

test "clone limit triggers at N concurrent" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 2,
        .max_connects_per_window = 8,
        .window_ms = 1000,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "192.0.2.10"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(1, "192.0.2.10"));
    try std.testing.expectEqual(Decision.clone_limited, try detector.classifyConnect(2, "192.0.2.10"));
    try std.testing.expectEqual(@as(usize, 2), detector.activeCount("192.0.2.10"));
}

test "throttle triggers on rapid reconnects" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 1,
        .max_connects_per_window = 2,
        .window_ms = 1000,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "198.51.100.7"));
    try std.testing.expect(detector.disconnect("198.51.100.7"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(10, "198.51.100.7"));
    try std.testing.expect(detector.disconnect("198.51.100.7"));
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(20, "198.51.100.7"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(1000, "198.51.100.7"));
}

test "releases on disconnect" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 1,
        .max_connects_per_window = 4,
        .window_ms = 1000,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "203.0.113.4"));
    try std.testing.expectEqual(Decision.clone_limited, try detector.classifyConnect(1, "203.0.113.4"));
    try std.testing.expect(detector.disconnect("203.0.113.4"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(2, "203.0.113.4"));
    try std.testing.expectEqual(@as(usize, 1), detector.activeCount("203.0.113.4"));
}

test "concurrent dimension disabled leaves a pure rate throttle" {
    // max_concurrent_per_ip = 0 → unlimited concurrent; only the rate window caps.
    var detector = try CloneDetector.initChecked(std.testing.allocator, .{
        .max_concurrent_per_ip = 0,
        .max_connects_per_window = 3,
        .window_ms = 1000,
    });
    defer detector.deinit();

    // Three rapid connects pass without ever tripping clone_limited, even though
    // all three stay active (no disconnect).
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "192.0.2.1"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(1, "192.0.2.1"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(2, "192.0.2.1"));
    // Fourth within the window is rate-throttled, not clone-limited.
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(3, "192.0.2.1"));
    // After the window slides, connects flow again.
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(1001, "192.0.2.1"));
}

test "state is bounded and prunes empty expired IPs" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 2,
        .max_connects_per_window = 2,
        .window_ms = 100,
        .max_tracked_ips = 2,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "10.0.0.1"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "10.0.0.2"));
    // Table full with two still-active entries: a third distinct IP is throttled
    // (fail-closed), not admitted, and not tracked.
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(1, "10.0.0.3"));
    try std.testing.expectEqual(@as(usize, 2), detector.trackedIps());

    try std.testing.expect(detector.disconnect("10.0.0.1"));
    detector.prune(100);
    try std.testing.expectEqual(@as(usize, 1), detector.trackedIps());
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(100, "10.0.0.3"));
    try std.testing.expect(detector.trackedIps() <= 2);
}

test "full tracking table fails toward refuse, never silent-admit" {
    // Regression: a distributed connect flood fills the bounded table with
    // distinct, still-active source IPs (so pruning reclaims nothing). A brand-new
    // source IP must be throttled — the historical fail-open bug returned an error
    // the admission caller swallowed as `.allow`, disabling the throttle for
    // exactly the flood it exists to stop. Mirrors conn_throttle's pure-rate config
    // (concurrent dimension owned by a separate limiter).
    var detector = try CloneDetector.initChecked(std.testing.allocator, .{
        .max_concurrent_per_ip = 0,
        .max_connects_per_window = 8,
        .window_ms = 60_000,
        .max_tracked_ips = 2,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "2001:db8::1"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "2001:db8::2"));
    // Both entries stay active within the window → no room to reclaim → refuse.
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(1, "2001:db8::3"));
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(2, "2001:db8::4"));
    // The refused IPs were never tracked (no unbounded growth past the cap).
    try std.testing.expectEqual(@as(usize, 2), detector.trackedIps());
    try std.testing.expectEqual(@as(usize, 0), detector.activeCount("2001:db8::3"));
}

test "no leak across denied connects and deinit" {
    var detector = try CloneDetector.initChecked(std.testing.allocator, .{
        .max_concurrent_per_ip = 1,
        .max_connects_per_window = 1,
        .window_ms = 50,
        .max_tracked_ips = 4,
        .max_ip_len = 16,
    });
    defer detector.deinit();

    try std.testing.expectError(error.EmptyIp, detector.classifyConnect(0, ""));
    try std.testing.expectError(error.IpTooLong, detector.classifyConnect(0, "12345678901234567"));

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "192.0.2.1"));
    try std.testing.expectEqual(Decision.clone_limited, try detector.classifyConnect(1, "192.0.2.1"));
    try std.testing.expect(detector.disconnect("192.0.2.1"));
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(2, "192.0.2.1"));

    detector.prune(50);
    try std.testing.expectEqual(@as(usize, 0), detector.trackedIps());
}
