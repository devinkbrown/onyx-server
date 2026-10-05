// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic per-IP connection clone and reconnect throttle detection.
//!
//! Callers provide a stable IP string and monotonic-ish time in milliseconds.
//! This module reads no clock and performs no I/O. State is bounded by
//! `max_tracked_ips`, `max_ip_len`, and `max_connects_per_window`.
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
    TooManyTrackedIps,
    InvalidParams,
} || std.mem.Allocator.Error;

/// A single admission checkpoint must fit inside the Helix state arena. The
/// aggregate arena writer applies the same limit across all capsules.
pub const max_checkpoint_bytes: usize = @import("helix/live.zig").max_arena_bytes;
pub const checkpoint_magic = [_]u8{ 'C', 'L', 'D', 'T' };
pub const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 4 + 1 + 3 + 4 + 5 * 8 + 4;
const checkpoint_checksum_len: usize = 32;
const checkpoint_row_min_len: usize = 4 + 1 + 8 + 4;
const checkpoint_domain = "onyx-clone-detector-checkpoint-v1";

pub const CheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    ConfigMismatch,
    NonCanonicalOrder,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Structural validation for Helix's pre-adopt relation pass; never allocates.
/// The final restore additionally checks the successor's expected Params.
pub fn validateUpgradeCheckpoint(bytes: []const u8) CheckpointError!void {
    if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const expected_len = std.math.add(usize, checkpoint_header_len + checkpoint_checksum_len, body_len) catch return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    const saved_digest: [checkpoint_checksum_len]u8 = bytes[bytes.len - checkpoint_checksum_len ..][0..checkpoint_checksum_len].*;
    if (!std.crypto.timing_safe.eql([checkpoint_checksum_len]u8, digest, saved_digest)) return error.ChecksumMismatch;

    var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
    const max_concurrent = try reader.readU64();
    const max_recent = try reader.readU64();
    const window_ms = try reader.readU64();
    const max_ips = try reader.readU64();
    const max_ip_len = try reader.readU64();
    if (max_recent == 0 or window_ms == 0 or max_ips == 0 or max_ip_len == 0 or
        max_concurrent > std.math.maxInt(usize) or max_recent > std.math.maxInt(usize) or
        max_ips > std.math.maxInt(usize) or max_ip_len > std.math.maxInt(usize))
        return error.InvalidField;
    const count: usize = try reader.readU32();
    if (count > max_ips) return error.CheckpointTooLarge;
    if (count > body_len / checkpoint_row_min_len) return error.Truncated;
    var previous_ip: ?[]const u8 = null;
    for (0..count) |_| {
        const ip_len: usize = try reader.readU32();
        if (ip_len == 0 or ip_len > max_ip_len) return error.InvalidField;
        const ip = try reader.take(ip_len);
        if (previous_ip) |previous| {
            if (std.mem.order(u8, previous, ip) != .lt) return error.NonCanonicalOrder;
        }
        previous_ip = ip;
        const active = try reader.readU64();
        if (active > std.math.maxInt(usize) or (max_concurrent != 0 and active > max_concurrent)) return error.InvalidField;
        const recent_count: usize = try reader.readU32();
        if (recent_count > max_recent or recent_count > reader.remaining() / 8) return error.InvalidField;
        _ = try reader.take(recent_count * 8);
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

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

        try self.ensureRoomForNewIp(now_ms);

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

    /// Capture every tracked row, including an empty row retained after a
    /// disconnect. Row and timestamp order are exact; no clock is consulted.
    /// The caller owns the returned bytes.
    pub fn exportUpgradeCheckpoint(self: *const CloneDetector, allocator: std.mem.Allocator) CheckpointError![]u8 {
        if (!validParams(self.params)) return error.InvalidField;
        const count = self.ips.count();
        if (count > self.params.max_tracked_ips or count > std.math.maxInt(u32)) return error.CheckpointTooLarge;

        const keys = try allocator.alloc([]const u8, count);
        defer allocator.free(keys);
        var it = self.ips.iterator();
        var index: usize = 0;
        while (it.next()) |entry| : (index += 1) {
            if (index >= keys.len) return error.InvalidField;
            keys[index] = entry.key_ptr.*;
        }
        if (index != keys.len) return error.InvalidField;
        std.mem.sort([]const u8, keys, {}, ipLess);

        var total_len: usize = checkpoint_header_len + checkpoint_checksum_len;
        for (keys) |ip| {
            const state = self.ips.get(ip) orelse return error.InvalidField;
            if (ip.len == 0 or ip.len > self.params.max_ip_len or ip.len > std.math.maxInt(u32) or
                state.recent.items.len > self.params.max_connects_per_window or
                state.recent.items.len > std.math.maxInt(u32) or
                (self.params.max_concurrent_per_ip != 0 and state.active > self.params.max_concurrent_per_ip))
                return error.InvalidField;
            try checkpointAddLen(&total_len, checkpoint_row_min_len - 1);
            try checkpointAddLen(&total_len, ip.len);
            const timestamp_bytes = std.math.mul(usize, state.recent.items.len, 8) catch return error.CheckpointTooLarge;
            try checkpointAddLen(&total_len, timestamp_bytes);
        }

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        var writer = CheckpointWriter{ .bytes = out };
        writer.writeBytes(&checkpoint_magic);
        writer.writeByte(checkpoint_version);
        writer.writeBytes(&.{ 0, 0, 0 });
        writer.writeU32(@intCast(total_len - checkpoint_header_len - checkpoint_checksum_len));
        writer.writeU64(@intCast(self.params.max_concurrent_per_ip));
        writer.writeU64(@intCast(self.params.max_connects_per_window));
        writer.writeU64(self.params.window_ms);
        writer.writeU64(@intCast(self.params.max_tracked_ips));
        writer.writeU64(@intCast(self.params.max_ip_len));
        writer.writeU32(@intCast(count));
        for (keys) |ip| {
            const state = self.ips.get(ip).?;
            writer.writeU32(@intCast(ip.len));
            writer.writeBytes(ip);
            writer.writeU64(@intCast(state.active));
            writer.writeU32(@intCast(state.recent.items.len));
            for (state.recent.items) |when| writer.writeI64(when);
        }
        std.debug.assert(writer.pos + checkpoint_checksum_len == out.len);
        var digest: [checkpoint_checksum_len]u8 = undefined;
        checkpointChecksum(out[0..writer.pos], &digest);
        writer.writeBytes(&digest);
        return out;
    }

    /// Build a separate, fully validated detector for pre-COMMIT staging. The
    /// expected configuration must match the predecessor exactly, so an upgrade
    /// cannot silently reinterpret an admission window or capacity.
    pub fn restoreUpgradeCheckpoint(
        allocator: std.mem.Allocator,
        expected_params: Params,
        bytes: []const u8,
    ) CheckpointError!CloneDetector {
        if (!validParams(expected_params)) return error.InvalidField;
        try validateUpgradeCheckpoint(bytes);

        var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
        if (try reader.readU64() != expected_params.max_concurrent_per_ip or
            try reader.readU64() != expected_params.max_connects_per_window or
            try reader.readU64() != expected_params.window_ms or
            try reader.readU64() != expected_params.max_tracked_ips or
            try reader.readU64() != expected_params.max_ip_len)
            return error.ConfigMismatch;
        const count: usize = try reader.readU32();
        if (count > expected_params.max_tracked_ips) return error.CheckpointTooLarge;

        var restored = CloneDetector.init(allocator, expected_params);
        errdefer restored.deinit();
        var previous_ip: ?[]const u8 = null;
        for (0..count) |_| {
            const ip_len: usize = try reader.readU32();
            if (ip_len == 0 or ip_len > expected_params.max_ip_len) return error.InvalidField;
            const ip = try reader.take(ip_len);
            if (previous_ip) |previous| {
                if (std.mem.order(u8, previous, ip) != .lt) return error.NonCanonicalOrder;
            }
            previous_ip = ip;
            const active = try reader.readU64();
            if (active > std.math.maxInt(usize) or
                (expected_params.max_concurrent_per_ip != 0 and active > expected_params.max_concurrent_per_ip))
                return error.InvalidField;
            const recent_count: usize = try reader.readU32();
            if (recent_count > expected_params.max_connects_per_window) return error.InvalidField;
            if (recent_count > reader.remaining() / 8) return error.Truncated;

            var state: IpState = .{ .active = @intCast(active) };
            errdefer state.deinit(allocator);
            try state.recent.ensureTotalCapacityPrecise(allocator, recent_count);
            for (0..recent_count) |_| try state.recent.append(allocator, try reader.readI64());
            const owned_ip = try allocator.dupe(u8, ip);
            errdefer allocator.free(owned_ip);
            try restored.ips.put(owned_ip, state);
        }
        if (reader.remaining() != 0) return error.TrailingBytes;
        return restored;
    }

    /// The live detector changes only after a complete decode succeeds.
    pub fn replaceFromUpgradeCheckpoint(self: *CloneDetector, bytes: []const u8) CheckpointError!void {
        var replacement = try restoreUpgradeCheckpoint(self.allocator, self.params, bytes);
        const old = self.*;
        self.* = replacement;
        replacement = old;
        replacement.deinit();
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

    fn ensureRoomForNewIp(self: *CloneDetector, now_ms: i64) CloneDetectError!void {
        if (self.ips.count() < self.params.max_tracked_ips) return;
        self.prune(now_ms);
        if (self.ips.count() >= self.params.max_tracked_ips) return error.TooManyTrackedIps;
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

fn ipLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn checkpointAddLen(total: *usize, amount: usize) CheckpointError!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

fn checkpointChecksum(bytes: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checkpoint_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const CheckpointWriter = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeBytes(self: *CheckpointWriter, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn writeByte(self: *CheckpointWriter, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeU32(self: *CheckpointWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    fn writeU64(self: *CheckpointWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    fn writeI64(self: *CheckpointWriter, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const CheckpointReader) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    fn readU32(self: *CheckpointReader) CheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn readU64(self: *CheckpointReader) CheckpointError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn readI64(self: *CheckpointReader) CheckpointError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }
};

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
    try std.testing.expectError(error.TooManyTrackedIps, detector.classifyConnect(1, "10.0.0.3"));

    try std.testing.expect(detector.disconnect("10.0.0.1"));
    detector.prune(100);
    try std.testing.expectEqual(@as(usize, 1), detector.trackedIps());
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(100, "10.0.0.3"));
    try std.testing.expect(detector.trackedIps() <= 2);
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

test "clone checkpoint preserves active, recent order, and empty tracked rows" {
    const params = Params{
        .max_concurrent_per_ip = 0,
        .max_connects_per_window = 3,
        .window_ms = 100,
        .max_tracked_ips = 3,
        .max_ip_len = 8,
    };
    var source = CloneDetector.init(std.testing.allocator, params);
    defer source.deinit();
    try std.testing.expectEqual(Decision.allow, try source.classifyConnect(7, "bb"));
    try std.testing.expectEqual(Decision.allow, try source.classifyConnect(3, "bb"));
    try std.testing.expectEqual(Decision.allow, try source.classifyConnect(-9, "aa"));
    try std.testing.expect(source.disconnect("aa"));
    source.ips.getPtr("aa").?.prune(100, params.window_ms);
    try std.testing.expectEqual(@as(usize, 0), source.recentCount("aa"));
    try std.testing.expectEqual(@as(usize, 2), source.trackedIps());

    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    var restored = try CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, wire);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 2), restored.trackedIps());
    try std.testing.expectEqual(@as(usize, 0), restored.activeCount("aa"));
    try std.testing.expectEqual(@as(usize, 0), restored.recentCount("aa"));
    try std.testing.expectEqual(@as(usize, 2), restored.activeCount("bb"));
    try std.testing.expectEqualSlices(i64, &.{ 7, 3 }, restored.ips.get("bb").?.recent.items);
    const reencoded = try restored.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);

    var reverse = CloneDetector.init(std.testing.allocator, params);
    defer reverse.deinit();
    try std.testing.expectEqual(Decision.allow, try reverse.classifyConnect(-9, "aa"));
    try std.testing.expect(reverse.disconnect("aa"));
    reverse.ips.getPtr("aa").?.prune(100, params.window_ms);
    try std.testing.expectEqual(Decision.allow, try reverse.classifyConnect(7, "bb"));
    try std.testing.expectEqual(Decision.allow, try reverse.classifyConnect(3, "bb"));
    const reverse_wire = try reverse.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reverse_wire);
    try std.testing.expectEqualSlices(u8, wire, reverse_wire);
}

test "clone checkpoint rejects malformed and mismatched state" {
    const params = Params{
        .max_concurrent_per_ip = 2,
        .max_connects_per_window = 2,
        .window_ms = 100,
        .max_tracked_ips = 2,
        .max_ip_len = 4,
    };
    var source = CloneDetector.init(std.testing.allocator, params);
    defer source.deinit();
    _ = try source.classifyConnect(1, "aa");
    _ = try source.classifyConnect(2, "bb");
    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);

    for (0..wire.len) |n| {
        try std.testing.expectError(error.Truncated, CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, wire[0..n]));
    }
    try std.testing.expectError(error.ConfigMismatch, CloneDetector.restoreUpgradeCheckpoint(
        std.testing.allocator,
        .{ .max_concurrent_per_ip = 2, .max_connects_per_window = 2, .window_ms = 101, .max_tracked_ips = 2, .max_ip_len = 4 },
        wire,
    ));
    var damaged = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(damaged);
    damaged[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, damaged));
    damaged[4] = checkpoint_version;
    damaged[checkpoint_header_len + 4] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, damaged));

    @memcpy(damaged, wire);
    // The second sorted two-byte IP starts after one 16+2+8 byte row.
    const second_ip_offset = checkpoint_header_len + (4 + 2 + 8 + 4 + 8) + 4;
    @memcpy(damaged[second_ip_offset..][0..2], "aa");
    testRechecksum(damaged);
    try std.testing.expectError(error.NonCanonicalOrder, CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(u32, damaged[checkpoint_header_len..][0..4], 0, .little);
    testRechecksum(damaged);
    try std.testing.expectError(error.InvalidField, CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(u32, damaged[checkpoint_header_len + 4 + 2 + 8 ..][0..4], 3, .little);
    testRechecksum(damaged);
    try std.testing.expectError(error.InvalidField, CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, damaged));

    const trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, CloneDetector.restoreUpgradeCheckpoint(std.testing.allocator, params, trailing));
}

test "clone checkpoint allocation failures leave live state untouched" {
    const params = Params{
        .max_concurrent_per_ip = 2,
        .max_connects_per_window = 2,
        .window_ms = 100,
        .max_tracked_ips = 3,
    };
    var source = CloneDetector.init(std.testing.allocator, params);
    defer source.deinit();
    _ = try source.classifyConnect(1, "a");
    _ = try source.classifyConnect(2, "b");
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, detector: *const CloneDetector) !void {
            const bytes = try detector.exportUpgradeCheckpoint(allocator);
            defer allocator.free(bytes);
            try std.testing.expectEqual(@as(usize, 2), detector.trackedIps());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});

    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    const RestoreSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Params, bytes: []const u8) !void {
            var target = CloneDetector.init(allocator, cfg);
            defer target.deinit();
            _ = try target.classifyConnect(9, "keeper");
            target.replaceFromUpgradeCheckpoint(bytes) catch |err| {
                try std.testing.expectEqual(@as(usize, 1), target.trackedIps());
                try std.testing.expectEqual(@as(usize, 1), target.activeCount("keeper"));
                return err;
            };
            try std.testing.expectEqual(@as(usize, 2), target.trackedIps());
            try std.testing.expectEqual(@as(usize, 0), target.activeCount("keeper"));
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, RestoreSweep.run, .{ params, wire });
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    @memcpy(bytes[bytes.len - checkpoint_checksum_len ..], &digest);
}
