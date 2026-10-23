// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned forward/reverse DNS caches and TTL expiry.

const std = @import("std");
const wire = @import("wire.zig");

pub const CacheError = error{
    TooManyAddresses,
} || std.mem.Allocator.Error;

pub const HostCacheEntry = struct {
    addrs: [wire.max_cache_addrs]wire.Address = undefined,
    addrs_len: usize = 0,
    expires_ms: i64 = 0,

    pub fn addressSlice(self: *const HostCacheEntry) []const wire.Address {
        return self.addrs[0..self.addrs_len];
    }
};

pub const PtrCacheEntry = struct {
    ptr: []const u8,
    expires_ms: i64,
};

/// TTL cache for forward and reverse resolver results.
pub const Cache = struct {
    allocator: std.mem.Allocator,
    hosts: std.StringHashMap(HostCacheEntry),
    ptrs: std.AutoHashMap(AddressKey, PtrCacheEntry),

    pub fn init(allocator: std.mem.Allocator) Cache {
        return .{
            .allocator = allocator,
            .hosts = std.StringHashMap(HostCacheEntry).init(allocator),
            .ptrs = std.AutoHashMap(AddressKey, PtrCacheEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Cache) void {
        var hit = self.hosts.iterator();
        while (hit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.hosts.deinit();

        var pit = self.ptrs.iterator();
        while (pit.next()) |entry| {
            self.allocator.free(entry.value_ptr.ptr);
        }
        self.ptrs.deinit();
    }

    pub fn putHost(
        self: *Cache,
        now_ms: i64,
        host: []const u8,
        addrs: []const wire.Address,
        ttl_seconds: u32,
    ) CacheError!void {
        if (addrs.len > wire.max_cache_addrs) return error.TooManyAddresses;

        var value = HostCacheEntry{ .addrs_len = addrs.len, .expires_ms = expiresAt(now_ms, ttl_seconds) };
        for (addrs, 0..) |addr, i| value.addrs[i] = addr;

        const owned_key = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned_key);

        const gop = try self.hosts.getOrPut(owned_key);
        if (gop.found_existing) {
            self.allocator.free(owned_key);
            gop.value_ptr.* = value;
            return;
        }
        gop.value_ptr.* = value;
    }

    pub fn getHost(self: *Cache, now_ms: i64, host: []const u8) ?HostCacheEntry {
        const entry = self.hosts.getEntry(host) orelse return null;
        if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
            const owned_key = entry.key_ptr.*;
            _ = self.hosts.remove(owned_key);
            self.allocator.free(owned_key);
            return null;
        }
        return entry.value_ptr.*;
    }

    pub fn putPtr(
        self: *Cache,
        now_ms: i64,
        address: wire.Address,
        ptr: []const u8,
        ttl_seconds: u32,
    ) CacheError!void {
        const key = addressKey(address);
        const value = PtrCacheEntry{
            .ptr = try self.allocator.dupe(u8, ptr),
            .expires_ms = expiresAt(now_ms, ttl_seconds),
        };
        errdefer self.allocator.free(value.ptr);

        const gop = try self.ptrs.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.ptr);
            gop.value_ptr.* = value;
            return;
        }
        gop.value_ptr.* = value;
    }

    pub fn getPtr(self: *Cache, now_ms: i64, address: wire.Address) ?[]const u8 {
        const key = addressKey(address);
        const entry = self.ptrs.getEntry(key) orelse return null;
        if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
            const removed = self.ptrs.fetchRemove(key).?;
            self.allocator.free(removed.value.ptr);
            return null;
        }
        return entry.value_ptr.ptr;
    }

    pub fn pruneExpired(self: *Cache, now_ms: i64) void {
        var host_keys: [32][]const u8 = undefined;
        while (true) {
            var count: usize = 0;
            var it = self.hosts.iterator();
            while (it.next()) |entry| {
                if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
                    host_keys[count] = entry.key_ptr.*;
                    count += 1;
                    if (count == host_keys.len) break;
                }
            }
            if (count == 0) break;
            for (host_keys[0..count]) |key| {
                _ = self.hosts.remove(key);
                self.allocator.free(key);
            }
        }

        var ptr_keys: [32]AddressKey = undefined;
        while (true) {
            var count: usize = 0;
            var it = self.ptrs.iterator();
            while (it.next()) |entry| {
                if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
                    ptr_keys[count] = entry.key_ptr.*;
                    count += 1;
                    if (count == ptr_keys.len) break;
                }
            }
            if (count == 0) break;
            for (ptr_keys[0..count]) |key| {
                const removed = self.ptrs.fetchRemove(key).?;
                self.allocator.free(removed.value.ptr);
            }
        }
    }
};

const AddressFamily = enum { ipv4, ipv6 };

const AddressKey = struct {
    family: AddressFamily,
    bytes: [16]u8,
};

fn addressKey(self: wire.Address) AddressKey {
    var out = AddressKey{ .family = .ipv4, .bytes = @as([16]u8, @splat(0)) };
    switch (self) {
        .ipv4 => |bytes| {
            out.family = .ipv4;
            @memcpy(out.bytes[0..4], &bytes);
        },
        .ipv6 => |bytes| {
            out.family = .ipv6;
            @memcpy(out.bytes[0..16], &bytes);
        },
    }
    return out;
}

fn expiresAt(now_ms: i64, ttl_seconds: u32) i64 {
    return now_ms + @as(i64, @intCast(ttl_seconds)) * 1000;
}

fn isExpired(now_ms: i64, expires_ms: i64) bool {
    return now_ms >= expires_ms;
}
test "cache returns hits and expires forward and reverse entries" {
    var cache = Cache.init(std.testing.allocator);
    defer cache.deinit();

    const addrs = [_]wire.Address{
        .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
    };
    try cache.putHost(1000, "localhost", &addrs, 2);
    const hit = cache.getHost(1999, "localhost").?;
    try std.testing.expectEqual(@as(usize, 2), hit.addrs_len);
    try std.testing.expect(cache.getHost(3000, "localhost") == null);

    try cache.putPtr(4000, addrs[0], "localhost", 1);
    try std.testing.expectEqualStrings("localhost", cache.getPtr(4999, addrs[0]).?);
    try std.testing.expect(cache.getPtr(5000, addrs[0]) == null);
}
