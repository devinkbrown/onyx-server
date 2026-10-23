// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");
const engine = @import("query_engine.zig");
const fixture = @import("test_server.zig");
const response = @import("response.zig");
const platform = @import("../../substrate/platform.zig");

test "DNS connected UDP rejects foreign source mismatched ID and question then accepts valid reply" {
    for ([_]fixture.Mode{ .valid, .wrong_id, .wrong_question, .foreign_source, .wrong_tc_id, .wrong_tc_question }) |mode| {
        var server = try fixture.Server.init(false, mode);
        defer server.deinit();
        try server.start();
        const result = try engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{});
        try server.join();
        try std.testing.expectEqual(response.Outcome.positive, result.outcome);
        try std.testing.expectEqual(@as(usize, 1), result.address_count);
        try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &result.addresses[0].ipv4);
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
        try std.testing.expectEqual(@as(usize, 0), server.tcp_queries);
    }
}

test "DNS native IPv6 nameserver supports AAAA and PTR queries" {
    for ([_]@import("wire.zig").RecordType{ .aaaa, .ptr }) |kind| {
        var server = try fixture.Server.init(true, .valid);
        defer server.deinit();
        try server.start();
        const result = try engine.resolve(&server.resolverConfig(), "lookup.test", kind, .{});
        try server.join();
        try std.testing.expectEqual(response.Outcome.positive, result.outcome);
        if (kind == .aaaa) {
            try std.testing.expectEqual(@as(usize, 1), result.address_count);
            try std.testing.expectEqual(@as(u8, 7), result.addresses[0].ipv6[15]);
        } else try std.testing.expectEqualStrings("ptr.test", result.ptr_name.slice());
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    }
}

test "DNS follows cross-packet aliases with minimum chain TTL and rejects cycles" {
    var server = try fixture.Server.init(false, .alias_followup);
    defer server.deinit();
    try server.start();
    const result = try engine.resolve(&server.resolverConfig(), "LOOKUP.TEST.", .a, .{});
    try server.join();
    try std.testing.expectEqualStrings("canonical.test", result.canonical_name.slice());
    try std.testing.expect(result.ttl_seconds > 0 and result.ttl_seconds <= 7);
    try std.testing.expectEqual(@as(usize, 1), result.alias_count);
    try std.testing.expectEqual(@as(usize, 2), server.udp_queries);

    var cycle = try fixture.Server.init(false, .alias_cycle);
    defer cycle.deinit();
    try cycle.start();
    try std.testing.expectError(error.AliasLoop, engine.resolve(&cycle.resolverConfig(), "lookup.test", .a, .{}));
    try cycle.join();
    try std.testing.expectEqual(@as(usize, 2), cycle.udp_queries);
}

test "DNS negative responses preserve SOA lifetime while server failure remains an error" {
    for ([_]fixture.Mode{ .nxdomain, .nodata, .servfail }) |mode| {
        var server = try fixture.Server.init(false, mode);
        defer server.deinit();
        try server.start();
        if (mode == .servfail) {
            try std.testing.expectError(error.ServerFailure, engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{}));
        } else {
            const result = try engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{});
            try std.testing.expectEqual(if (mode == .nxdomain) response.Outcome.nxdomain else .nodata, result.outcome);
            try std.testing.expectEqual(@as(u32, 10), result.ttl_seconds);
        }
        try server.join();
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    }
}

test "DNS validates partial TC envelope and reads fragmented TCP response larger than UDP legacy limit" {
    var server = try fixture.Server.init(false, .tcp_fragmented);
    defer server.deinit();
    try server.start();
    const result = try engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{});
    try server.join();
    try std.testing.expectEqual(response.Outcome.positive, result.outcome);
    try std.testing.expectEqual(@as(usize, 1), result.address_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &result.addresses[0].ipv4);
    try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    try std.testing.expectEqual(@as(usize, 1), server.tcp_queries);
}

test "DNS TCP oversized prefix and incomplete frame fail closed" {
    for ([_]fixture.Mode{ .tcp_oversize, .tcp_partial }) |mode| {
        var server = try fixture.Server.init(false, mode);
        defer server.deinit();
        try server.start();
        const expected = if (mode == .tcp_oversize) error.OversizeMessage else error.TruncatedMessage;
        try std.testing.expectError(expected, engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{}));
        try server.join();
        try std.testing.expectEqual(@as(usize, 1), server.tcp_queries);
    }
}

test "DNS TCP partial prefix cannot extend whole lookup deadline" {
    var server = try fixture.Server.init(false, .tcp_slow);
    defer server.deinit();
    try server.start();
    const start = platform.monotonicMillis();
    try std.testing.expectError(error.Timeout, engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{ .total_timeout_ms = 60 }));
    const elapsed = platform.monotonicMillis() - start;
    try std.testing.expect(elapsed >= 40 and elapsed < 500);
    try server.join();
    try std.testing.expectEqual(@as(usize, 1), server.tcp_queries);
}

test "DNS retries and nameservers share one total deadline" {
    var server = try fixture.Server.init(false, .silent);
    defer server.deinit();
    server.expected_queries = 3;
    try server.start();
    var cfg = server.resolverConfig();
    cfg.attempts = 255;
    cfg.timeout_ms = 50;
    for (0..3) |_| cfg.addNameserver(server.address);
    const start = platform.monotonicMillis();
    try std.testing.expectError(error.Timeout, engine.resolve(&cfg, "lookup.test", .a, .{ .total_timeout_ms = 140 }));
    const elapsed = platform.monotonicMillis() - start;
    try std.testing.expect(elapsed >= 100 and elapsed < 750);
    try server.join();
    try std.testing.expectEqual(@as(usize, 3), server.udp_queries);
}

test "DNS configured attempts are capped even when overall budget remains" {
    var server = try fixture.Server.init(false, .silent);
    defer server.deinit();
    server.expected_queries = engine.max_attempts;
    try server.start();
    var cfg = server.resolverConfig();
    cfg.attempts = 255;
    cfg.timeout_ms = 20;
    try std.testing.expectError(error.Timeout, engine.resolve(&cfg, "lookup.test", .a, .{ .total_timeout_ms = 500 }));
    try server.join();
    try std.testing.expectEqual(@as(usize, engine.max_attempts), server.udp_queries);
}

test "DNS cross-packet aliases cannot revisit an intermediate owner" {
    var server = try fixture.Server.init(false, .alias_cross_cycle);
    defer server.deinit();
    try server.start();
    try std.testing.expectError(error.AliasLoop, engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{}));
    try server.join();
    try std.testing.expectEqual(@as(usize, 2), server.udp_queries);
}

test "DNS alias TTL ages while waiting for later packets" {
    var server = try fixture.Server.init(false, .alias_slow);
    defer server.deinit();
    try server.start();
    const result = try engine.resolve(&server.resolverConfig(), "lookup.test", .a, .{});
    try server.join();
    try std.testing.expectEqual(response.Outcome.positive, result.outcome);
    // Less than one whole second remains of the original one-second alias.
    try std.testing.expectEqual(@as(u32, 0), result.ttl_seconds);
    try std.testing.expectEqual(@as(usize, 2), server.udp_queries);
}
