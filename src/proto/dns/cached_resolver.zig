// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Worker-owned resolver with a bounded result cache. No internal threads or
//! shared global cache; callers serialize access and clear on policy changes.

const std = @import("std");
const config = @import("resolver_config.zig");
const engine = @import("query_engine.zig");
const wire = @import("message_types.zig");
const response = @import("response.zig");
const cache = @import("result_cache.zig");
const platform = @import("../../substrate/platform.zig");

pub const Resolver = struct {
    config: config.ResolverConfig,
    results: cache.Cache,

    pub fn init(allocator: std.mem.Allocator, cfg: config.ResolverConfig, capacity: usize) cache.InitError!Resolver {
        return .{ .config = cfg, .results = try cache.Cache.init(allocator, capacity) };
    }

    pub fn deinit(self: *Resolver) void {
        self.results.deinit();
        self.* = undefined;
    }

    /// Use this method for policy changes; cached split-horizon answers from
    /// the previous nameservers are invalid in the new resolver context.
    pub fn setConfig(self: *Resolver, cfg: config.ResolverConfig) void {
        self.results.clear();
        self.config = cfg;
    }

    pub fn resolve(self: *Resolver, name: []const u8, kind: wire.RecordType, options: engine.Options) engine.Error!response.Result {
        const started_ms = platform.monotonicMillis();
        if (self.results.get(started_ms, name, kind)) |hit| return hit;
        const result = try engine.resolve(&self.config, name, kind, options);
        _ = self.results.put(started_ms, name, kind, result);
        return result;
    }
};

test "DNS cached resolver reuses validated positive and negative replies but not server failures" {
    const fixture = @import("test_server.zig");
    for ([_]fixture.Mode{ .valid, .nxdomain, .nodata, .servfail }) |mode| {
        var server = try fixture.Server.init(false, mode);
        defer server.deinit();
        try server.start();
        var resolver = try Resolver.init(std.testing.allocator, server.resolverConfig(), 8);
        defer resolver.deinit();
        if (mode == .servfail) {
            try std.testing.expectError(error.ServerFailure, resolver.resolve("lookup.test", .a, .{}));
            try std.testing.expectEqual(@as(usize, 0), resolver.results.count());
        } else {
            const first = try resolver.resolve("lookup.test", .a, .{});
            const cached = try resolver.resolve("LOOKUP.TEST.", .a, .{});
            try std.testing.expectEqual(first.outcome, cached.outcome);
            try std.testing.expectEqual(@as(usize, 1), resolver.results.count());
        }
        try server.join();
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
        resolver.setConfig(server.resolverConfig());
        try std.testing.expectEqual(@as(usize, 0), resolver.results.count());
    }
}

test "DNS cached resolver does not retain timeout or malformed packet failures" {
    const fixture = @import("test_server.zig");
    for ([_]fixture.Mode{ .silent, .malformed }) |mode| {
        var server = try fixture.Server.init(false, mode);
        defer server.deinit();
        try server.start();
        var resolver = try Resolver.init(std.testing.allocator, server.resolverConfig(), 8);
        defer resolver.deinit();
        const expected = if (mode == .silent) error.Timeout else error.InvalidResponse;
        try std.testing.expectError(expected, resolver.resolve("lookup.test", .a, .{ .total_timeout_ms = 100 }));
        try std.testing.expectEqual(@as(usize, 0), resolver.results.count());
        try server.join();
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    }
}
