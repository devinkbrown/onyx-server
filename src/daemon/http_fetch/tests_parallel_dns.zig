// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Actual public dual-family API, bounded peers, and a non-serializable barrier.

const std = @import("std");
const builtin = @import("builtin");
const resolution = @import("resolution.zig");
const HostFamilies = @import("contracts.zig").HostFamilies;
const Peer = @import("parallel_dns_fixture.zig").Peer;
const fixture = @import("../../proto/dns/test_server.zig");
const platform = @import("../../substrate/platform.zig");

fn usePeer(peer: *const Peer) void {
    resolution.Testing.config = .{ .text = "nameserver 127.0.0.1", .dns_port = peer.port };
}

fn expectBoth(found: HostFamilies, v4_last: u8, v6_last: u8) !void {
    try std.testing.expectEqual([4]u8{ 203, 0, 113, v4_last }, found.v4.?);
    try std.testing.expectEqual([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, v6_last }, found.v6.?);
}

test "dual dns query collects A and AAAA from one nameserver" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]Peer.Reply{ .positive, .wrong_id }) |reply| {
        var peer = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0);
        defer peer.deinit();
        peer.replies = .{ reply, reply };
        try peer.start();
        usePeer(&peer);
        const found = try resolution.resolveHostFamilies("lookup.test", 500);
        try peer.join();
        try expectBoth(found, 9, 9);
        // A serial implementation cannot obtain either answer: the fixture
        // emits nothing until both real questions arrive, in either order.
        try std.testing.expect(peer.answered_after_both);
        try std.testing.expectEqual([2]usize{ 1, 1 }, peer.queries);
    }
}

test "http_fetch parallel DNS retains either family when the other is silent" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for (0..2) |silent| {
        var peer = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0);
        defer peer.deinit();
        peer.replies[silent] = .silent;
        try peer.start();
        usePeer(&peer);
        const started = platform.monotonicMillis();
        const found = try resolution.resolveHostFamilies("lookup.test", 120);
        const elapsed = platform.monotonicMillis() - started;
        try peer.join();
        if (silent == 0) {
            try std.testing.expect(found.v4 == null);
            try std.testing.expectEqual(@as(u8, 9), found.v6.?[15]);
        } else {
            try std.testing.expectEqual(@as(u8, 9), found.v4.?[3]);
            try std.testing.expect(found.v6 == null);
        }
        // In particular, successful A must still join the silent AAAA helper.
        try std.testing.expect(elapsed >= 80 and elapsed < 400);
        try std.testing.expect(peer.answered_after_both);
        try std.testing.expectEqual([2]usize{ 1, 1 }, peer.queries);
    }
    var delayed = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0);
    defer delayed.deinit();
    delayed.replies = .{ .negative, .positive };
    delayed.delay_ms[1] = 80;
    try delayed.start();
    usePeer(&delayed);
    const found = try resolution.resolveHostFamilies("lookup.test", 300);
    try delayed.join();
    // An immediate A error cannot return before the helper's later success.
    try std.testing.expect(found.v4 == null);
    try std.testing.expectEqual(@as(u8, 9), found.v6.?[15]);
    try std.testing.expectEqual([2]usize{ 1, 1 }, delayed.queries);
}

test "http_fetch parallel DNS preserves per-family ordered backup selection" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    const policies = [_][2]Peer.Reply{ .{ .negative, .positive }, .{ .positive, .negative }, .{ .negative, .negative }, .{ .silent, .silent } };
    for (policies) |replies| {
        var primary = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0);
        defer primary.deinit();
        primary.replies = replies;
        var backup = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 2 } }, primary.port);
        defer backup.deinit();
        backup.positive_last = 8;
        for (replies, 0..) |reply, family| backup.expected[family] = if (reply == .positive) 0 else 1;
        backup.require_both = backup.expected[0] == 1 and backup.expected[1] == 1;
        try primary.start();
        try backup.start();
        resolution.Testing.config = .{ .text = "nameserver 127.0.0.1\nnameserver 127.0.0.2\noptions timeout:99 attempts:99", .dns_port = primary.port };
        const started = platform.monotonicMillis();
        const found = try resolution.resolveHostFamilies("lookup.test", 300);
        const elapsed = platform.monotonicMillis() - started;
        try primary.join();
        try backup.join();
        try expectBoth(found, if (replies[0] == .positive) 9 else 8, if (replies[1] == .positive) 9 else 8);
        try std.testing.expectEqual([2]usize{ 1, 1 }, primary.queries);
        try std.testing.expectEqual(backup.expected, backup.queries);
        try std.testing.expect(elapsed < 600);
    }
}

test "http_fetch parallel DNS helper start failure performs A only without serial fallback" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    resolution.Testing.worker_start = .fail;
    defer resolution.Testing.worker_start = .normal;
    for ([_]Peer.Reply{ .positive, .negative }) |reply| {
        var peer = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0);
        defer peer.deinit();
        peer.expected = .{ 1, 0 };
        peer.require_both = false;
        peer.replies[0] = reply;
        try peer.start();
        usePeer(&peer);
        if (reply == .positive) {
            const found = try resolution.resolveHostFamilies("lookup.test", 80);
            try std.testing.expectEqual(@as(u8, 9), found.v4.?[3]);
            try std.testing.expect(found.v6 == null);
        } else try std.testing.expectError(error.HostNotFound, resolution.resolveHostFamilies("lookup.test", 80));
        try peer.join();
        try std.testing.expectEqual([2]usize{ 1, 0 }, peer.queries);
    }
    resolution.Testing.config = .{ .text = "" };
    try std.testing.expectError(error.NoNameservers, resolution.resolveHostFamilies("lookup.test", 80));
}

test "http_fetch parallel DNS keeps config name and literal error precedence" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    resolution.Testing.config = .{ .text = null };
    const v4 = try resolution.resolveHostFamilies("127.0.0.7", 0);
    try std.testing.expectEqual(@as(u8, 7), v4.v4.?[3]);
    const v6 = try resolution.resolveHostFamilies("::1", 0);
    try std.testing.expectEqual(@as(u8, 1), v6.v6.?[15]);
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostFamilies("", 20));
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostFamilies("bad\x00name", 20));
    for ([_]?[]const u8{ null, "", "nameserver invalid", "nameserver fe80::1" }) |text| {
        resolution.Testing.config = .{ .text = text };
        try std.testing.expectError(error.NoNameservers, resolution.resolveHostFamilies("bad..name", 20));
    }
    resolution.Testing.config = .{ .text = "nameserver 127.0.0.1", .dns_port = 0 };
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostFamilies("bad..name", 20));
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostFamilies("lookup.test", 20));
}

test "http_fetch parallel DNS shares zero small and oversized caller deadlines" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]u31{ 0, 20, std.math.maxInt(u31) }) |budget| {
        var peer = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0);
        defer peer.deinit();
        peer.fixture_timeout_ms = 250;
        if (budget == std.math.maxInt(u31)) {
            peer.replies = .{ .silent, .silent };
        } else peer.delay_ms = .{ 80, 80 };
        try peer.start();
        usePeer(&peer);
        const started = platform.monotonicMillis();
        try std.testing.expectError(error.HostNotFound, resolution.resolveHostFamilies("lookup.test", budget));
        const elapsed = platform.monotonicMillis() - started;
        peer.join() catch |err| {
            if (budget != 0 or err != error.Timeout) return err;
        };
        if (budget == std.math.maxInt(u31)) {
            try std.testing.expect(elapsed >= 4500 and elapsed < 6000);
        } else try std.testing.expect(elapsed < 400);
        if (budget != 0) try std.testing.expectEqual([2]usize{ 1, 1 }, peer.queries);
    }
}

test "http_fetch parallel DNS follows both CNAME paths under the common deadline" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    var peer = try Peer.init(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0);
    defer peer.deinit();
    peer.replies = .{ .alias, .alias };
    peer.expected = .{ 2, 2 };
    try peer.start();
    usePeer(&peer);
    const found = try resolution.resolveHostFamilies("lookup.test", 500);
    try peer.join();
    try expectBoth(found, 9, 9);
    try std.testing.expect(peer.answered_after_both);
    try std.testing.expectEqual([2]usize{ 2, 2 }, peer.queries);
}

test "http_fetch parallel DNS uses scoped IPv6 nameserver and custom port" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    var address: [16]u8 = @splat(0);
    address[15] = 1;
    var peer = try Peer.init(.{ .ipv6 = address }, 0);
    defer peer.deinit();
    try peer.start();
    resolution.Testing.config = .{ .text = "nameserver ::1%1", .dns_port = peer.port };
    const found = try resolution.resolveHostFamilies("lookup.test", 500);
    try peer.join();
    try expectBoth(found, 9, 9);
    try std.testing.expectEqual([2]usize{ 1, 1 }, peer.queries);
}

test "http_fetch parallel DNS retains validated TCP success when the other family times out" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    // This shared fixture serves one UDP->TCP exchange and leaves the other
    // family silent. Which family wins is intentionally not prescribed.
    var server = try fixture.Server.init(false, .tcp_fragmented);
    defer server.deinit();
    try server.start();
    resolution.Testing.config = .{ .text = "nameserver 127.0.0.1", .dns_port = server.port };
    const started = platform.monotonicMillis();
    const found = try resolution.resolveHostFamilies("lookup.test", 300);
    const elapsed = platform.monotonicMillis() - started;
    try server.join();
    try std.testing.expect((found.v4 != null) != (found.v6 != null));
    if (found.v4) |bytes| try std.testing.expectEqual(@as(u8, 7), bytes[3]);
    if (found.v6) |bytes| try std.testing.expectEqual(@as(u8, 7), bytes[15]);
    try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    try std.testing.expectEqual(@as(usize, 1), server.tcp_queries);
    try std.testing.expect(elapsed < 600);
}
