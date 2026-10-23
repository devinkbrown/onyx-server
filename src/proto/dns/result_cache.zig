// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded, allocator-owned DNS results. Keys are canonical names and IN query
//! kinds; unaliased NXDOMAIN applies across kinds, while NODATA does not.
//! Allocate once at initialization. Lookups and replacement never allocate.

const std = @import("std");
const types = @import("message_types.zig");
const names = @import("name_codec.zig");
const response = @import("response.zig");

pub const max_entries: usize = 4096;
pub const max_positive_ttl_seconds: u32 = 86400;
pub const max_negative_ttl_seconds: u32 = 300;
pub const InitError = std.mem.Allocator.Error || error{InvalidCapacity};

const Key = struct {
    name: [names.max_text_len]u8 = @splat(0),
    name_len: u8 = 0,
    // Zero is the name-wide, unaliased NXDOMAIN key. All other keys are IN
    // query types, so an A result cannot answer AAAA or PTR.
    kind: u16,
};
const Entry = struct { result: response.Result, expires_ms: i64 };

/// One resolver configuration owns one cache. Clear it when that configuration
/// changes; a split-horizon result must not cross resolver trust boundaries.
pub const Cache = struct {
    entries: std.AutoHashMap(Key, Entry),
    capacity: usize,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) InitError!Cache {
        if (capacity > max_entries) return error.InvalidCapacity;
        var entries = std.AutoHashMap(Key, Entry).init(allocator);
        errdefer entries.deinit();
        try entries.ensureTotalCapacity(@intCast(capacity));
        return .{ .entries = entries, .capacity = capacity };
    }

    pub fn deinit(self: *Cache) void {
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn clear(self: *Cache) void {
        self.entries.clearRetainingCapacity();
    }

    pub fn count(self: *const Cache) usize {
        return self.entries.count();
    }

    pub fn get(self: *Cache, now_ms: i64, name: []const u8, kind: types.RecordType) ?response.Result {
        var key = keyFor(name, kind) orelse return null;
        if (self.getKey(now_ms, key)) |result| return result;
        key.kind = 0;
        return self.getKey(now_ms, key);
    }

    fn getKey(self: *Cache, now_ms: i64, key: Key) ?response.Result {
        const entry = self.entries.get(key) orelse return null;
        if (now_ms >= entry.expires_ms) {
            _ = self.entries.remove(key);
            return null;
        }
        var result = entry.result;
        const remaining: i128 = @as(i128, entry.expires_ms) - now_ms;
        result.ttl_seconds = @intCast(@min(result.ttl_seconds, @divTrunc(remaining, 1000)));
        return result;
    }

    /// `result` must come from the validating resolver for this name and type.
    /// A zero lifetime is useful to the current caller but cannot be cached.
    /// Errors (including SERVFAIL and timeout) are not representable as results.
    pub fn put(self: *Cache, now_ms: i64, name: []const u8, kind: types.RecordType, result: response.Result) bool {
        if (self.capacity == 0 or result.outcome == .alias) return false;
        var key = keyFor(name, kind) orelse return false;
        const negative = result.outcome == .nxdomain or result.outcome == .nodata;
        const ttl = @min(result.ttl_seconds, if (negative) max_negative_ttl_seconds else max_positive_ttl_seconds);
        // Even a non-cacheable new answer supersedes an old answer of this kind.
        // An NXDOMAIN after aliases applies to the canonical target, not to the
        // existing original CNAME, and therefore stays under a typed query key.
        if (result.outcome == .nxdomain and result.alias_count == 0) {
            for ([_]u16{ 0, 1, 28, 12 }) |cached_kind| {
                key.kind = cached_kind;
                _ = self.entries.remove(key);
            }
            key.kind = 0;
        } else {
            var wildcard = key;
            wildcard.kind = 0;
            _ = self.entries.remove(wildcard);
            _ = self.entries.remove(key);
        }
        if (ttl == 0) return false;
        if (self.entries.count() == self.capacity) self.evictFirstExpiry();
        var stored = result;
        stored.ttl_seconds = ttl;
        self.entries.putAssumeCapacity(key, .{ .result = stored, .expires_ms = now_ms +| @as(i64, ttl) * 1000 });
        return true;
    }

    fn evictFirstExpiry(self: *Cache) void {
        var iterator = self.entries.iterator();
        const first = iterator.next().?;
        var victim = first.key_ptr.*;
        var expires = first.value_ptr.expires_ms;
        while (iterator.next()) |entry| {
            if (entry.value_ptr.expires_ms < expires) {
                victim = entry.key_ptr.*;
                expires = entry.value_ptr.expires_ms;
            }
        }
        _ = self.entries.remove(victim);
    }
};

fn keyFor(name: []const u8, kind: types.RecordType) ?Key {
    if (kind == .txt) return null;
    var key = Key{ .kind = @backingInt(kind) };
    const normalized = names.normalize(&key.name, name) catch return null;
    key.name_len = @intCast(normalized.len);
    return key;
}

test "DNS result cache canonical keys isolate families and expire at exact TTL" {
    var cache = try Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    var result = response.Result{ .outcome = .positive, .canonical_name = .{}, .ttl_seconds = 2 };
    result.addresses[0] = .{ .ipv4 = .{ 192, 0, 2, 1 } };
    result.address_count = 1;
    try std.testing.expect(cache.put(1000, "HOST.TEST.", .a, result));
    try std.testing.expectEqual(@as(u32, 1), cache.get(1999, "host.test", .a).?.ttl_seconds);
    try std.testing.expect(cache.get(2000, "host.test", .aaaa) == null);
    try std.testing.expect(cache.get(2000, "host.test", .ptr) == null);
    try std.testing.expect(cache.get(2999, "host.test", .a) != null);
    try std.testing.expect(cache.get(3000, "host.test", .a) == null);
    try std.testing.expectEqual(@as(usize, 0), cache.count());
}

test "DNS negative cache distinguishes name-wide NXDOMAIN typed NODATA and aliases" {
    var cache = try Cache.init(std.testing.allocator, 4);
    defer cache.deinit();
    var result = response.Result{ .outcome = .nodata, .canonical_name = .{}, .ttl_seconds = 900 };
    try std.testing.expect(cache.put(1000, "empty.test", .a, result));
    try std.testing.expect(cache.get(1000, "empty.test", .aaaa) == null);
    try std.testing.expectEqual(@as(u32, 300), cache.get(1000, "empty.test", .a).?.ttl_seconds);
    result.outcome = .nxdomain;
    try std.testing.expect(cache.put(1000, "empty.test", .aaaa, result));
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    try std.testing.expectEqual(response.Outcome.nxdomain, cache.get(1000, "empty.test", .a).?.outcome);
    try std.testing.expect(cache.get(1000, "empty.test", .ptr) != null);
    result.alias_count = 1;
    try std.testing.expect(cache.put(1000, "alias.test", .a, result));
    try std.testing.expect(cache.get(1000, "alias.test", .aaaa) == null);
    try std.testing.expect(cache.get(1000, "alias.test", .a) != null);
    result.outcome = .positive;
    result.alias_count = 0;
    try std.testing.expect(cache.put(1000, "empty.test", .a, result));
    try std.testing.expectEqual(response.Outcome.positive, cache.get(1000, "empty.test", .a).?.outcome);
    try std.testing.expect(cache.get(1000, "empty.test", .aaaa) == null);
}

test "DNS result cache caps memory and TTL and excludes zero TTL and incomplete aliases" {
    var cache = try Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    var result = response.Result{ .outcome = .positive, .canonical_name = .{}, .ttl_seconds = 1 };
    try std.testing.expect(cache.put(0, "first.test", .a, result));
    result.ttl_seconds = 2;
    try std.testing.expect(cache.put(0, "second.test", .a, result));
    result.ttl_seconds = std.math.maxInt(u32);
    try std.testing.expect(cache.put(0, "third.test", .a, result));
    try std.testing.expectEqual(@as(usize, 2), cache.count());
    try std.testing.expect(cache.get(0, "first.test", .a) == null);
    try std.testing.expectEqual(max_positive_ttl_seconds, cache.get(0, "third.test", .a).?.ttl_seconds);
    result.ttl_seconds = 0;
    try std.testing.expect(!cache.put(0, "second.test", .a, result));
    try std.testing.expect(cache.get(0, "second.test", .a) == null);
    result.ttl_seconds = 10;
    result.outcome = .alias;
    try std.testing.expect(!cache.put(0, "alias.test", .a, result));
    result.outcome = .positive;
    try std.testing.expect(cache.put(std.math.maxInt(i64) - 1, "near-limit.test", .a, result));
    try std.testing.expect(cache.get(std.math.maxInt(i64), "near-limit.test", .a) == null);
    cache.clear();
    try std.testing.expectEqual(@as(usize, 0), cache.count());
    try std.testing.expectError(error.InvalidCapacity, Cache.init(std.testing.allocator, max_entries + 1));
}

test "DNS result cache allocation failure leaves no owned storage" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var cache = try Cache.init(allocator, 8);
            defer cache.deinit();
            const result = response.Result{ .outcome = .nodata, .canonical_name = .{}, .ttl_seconds = 1 };
            for (0..16) |i| {
                const name = if (i % 2 == 0) "first.test" else "second.test";
                try std.testing.expect(cache.put(0, name, .a, result));
            }
            try std.testing.expectEqual(@as(usize, 2), cache.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Scenario.run, .{});
}
