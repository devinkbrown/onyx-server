// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real SystemResolver callback tests with controlled config and loopback DNS.

const std = @import("std");
const builtin = @import("builtin");
const acme = @import("acme_runner.zig");
const lookup = @import("dns_address_lookup.zig");
const fixture = @import("dns_address_lookup_fixture.zig");
const Server = @import("../proto/dns/test_server.zig").Server;
const Mode = @import("../proto/dns/test_server.zig").Mode;
const platform = @import("../substrate/platform.zig");
const Deadline = @import("../proto/dns/deadline.zig").Deadline;
const one_server = "nameserver 127.0.0.1\noptions timeout:99 attempts:99\n";

fn posixOnly() !void {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
}

fn configured(file: *fixture.ConfigFile, dns_port: u16) !std.Io.net.IpAddress {
    var system = acme.SystemResolver{ .allocator = std.testing.allocator, .io = file.io(), .dns_port = dns_port };
    const resolver = system.resolver();
    try std.testing.expect(resolver.ctx == @as(*anyopaque, @ptrCast(&system)));
    return resolver.resolveFn(resolver.ctx, "host.test", 8443);
}

fn expectAddress(address: std.Io.net.IpAddress) !void {
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &address.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 8443), address.ip4.port);
}

test "ACME DNS SystemResolver literal fast path requires no config allocation or I/O" {
    var file = fixture.ConfigFile{ .text = "", .deny = true };
    var system = acme.SystemResolver{ .allocator = std.testing.failing_allocator, .io = file.io(), .resolv_conf_max_bytes = 0, .dns_port = 0 };
    const resolver = system.resolver();
    const ipv4 = try resolver.resolveFn(resolver.ctx, "192.0.2.9", 8443);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 9 }, &ipv4.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 8443), ipv4.ip4.port);
    const ipv6 = try resolver.resolveFn(resolver.ctx, "::1", 443);
    try std.testing.expectEqual(@as(u8, 1), ipv6.ip6.bytes[15]);
    try std.testing.expectEqual(@as(u16, 443), ipv6.ip6.port);
    try std.testing.expectEqual(@as(usize, 0), file.opens);
}

test "ACME DNS SystemResolver preserves read limit allocation and config error contracts" {
    try posixOnly();
    var file = fixture.ConfigFile{ .text = one_server, .deny = true };
    var system = acme.SystemResolver{ .allocator = std.testing.allocator, .io = file.io() };
    const resolver = system.resolver();
    try std.testing.expectError(error.NoNameservers, resolver.resolveFn(resolver.ctx, "host.test", 443));
    try std.testing.expectEqual(@as(usize, 0), file.closes);
    file.deny = false;
    system.resolv_conf_max_bytes = one_server.len - 1;
    try std.testing.expectError(error.NoNameservers, resolver.resolveFn(resolver.ctx, "host.test", 443));
    try std.testing.expectEqual(@as(usize, 1), file.closes);
    system.resolv_conf_max_bytes = 65536;
    system.allocator = std.testing.failing_allocator;
    try std.testing.expectError(error.NoNameservers, resolver.resolveFn(resolver.ctx, "host.test", 443));
    try std.testing.expectEqual(@as(usize, 2), file.closes);
    system.allocator = std.testing.allocator;
    file.text = "";
    try std.testing.expectError(error.NoNameservers, resolver.resolveFn(resolver.ctx, "bad..name", 443));
    file.text = one_server;
    try std.testing.expectError(error.InvalidName, resolver.resolveFn(resolver.ctx, "bad..name", 443));
    try std.testing.expectEqual(@as(usize, 4), file.closes);
}

test "ACME DNS actual SystemResolver rejects wrong ID question and foreign source" {
    try posixOnly();
    for ([_]Mode{ .wrong_id, .wrong_question, .foreign_source }) |mode| {
        var server = try Server.init(false, mode);
        defer server.deinit();
        try server.start();
        var file = fixture.ConfigFile{ .text = one_server };
        try expectAddress(try configured(&file, server.port));
        try server.join();
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
        try std.testing.expectEqual(@as(usize, 1), file.opens);
        try std.testing.expectEqual(file.opens, file.closes);
    }
}

test "ACME DNS actual SystemResolver rejects QR owner and RCODE address forgeries" {
    try posixOnly();
    for ([_]fixture.Peer.Mode{ .wrong_qr, .unrelated_owner, .nxdomain_with_a }) |mode| {
        var server = try fixture.Peer.init(.{ 127, 0, 0, 1 }, 0, mode);
        defer server.deinit();
        try server.start();
        var file = fixture.ConfigFile{ .text = one_server };
        try expectAddress(try configured(&file, server.port));
        try server.join();
        try std.testing.expectEqual(@as(usize, 1), server.queries);
    }
}

test "ACME DNS actual SystemResolver uses one three second silent-server budget" {
    try posixOnly();
    var server = try Server.init(false, .silent);
    defer server.deinit();
    try server.start();
    var file = fixture.ConfigFile{ .text = one_server };
    const start = platform.monotonicMillis();
    try std.testing.expectError(error.HostNotFound, configured(&file, server.port));
    const elapsed = platform.monotonicMillis() - start;
    try server.join();
    try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    try std.testing.expect(elapsed >= 2800 and elapsed < 4000);
    try std.testing.expectEqual(file.opens, file.closes);
}

test "ACME DNS actual SystemResolver gives fourth nameserver time after three silent servers" {
    try posixOnly();
    var last = try Server.init(false, .valid);
    defer last.deinit();
    last.fixture_timeout_ms = 4500;
    var first = try fixture.Peer.init(.{ 127, 0, 0, 2 }, last.port, .silent);
    defer first.deinit();
    var second = try fixture.Peer.init(.{ 127, 0, 0, 3 }, last.port, .silent);
    defer second.deinit();
    var third = try fixture.Peer.init(.{ 127, 0, 0, 4 }, last.port, .silent);
    defer third.deinit();
    try first.start();
    try second.start();
    try third.start();
    try last.start();
    var file = fixture.ConfigFile{ .text = "nameserver 127.0.0.2\nnameserver 127.0.0.3\nnameserver 127.0.0.4\nnameserver 127.0.0.1\noptions timeout:99 attempts:99\n" };
    const start = platform.monotonicMillis();
    try expectAddress(try configured(&file, last.port));
    const elapsed = platform.monotonicMillis() - start;
    try first.join();
    try second.join();
    try third.join();
    try last.join();
    try std.testing.expectEqual(@as(usize, 1), first.queries);
    try std.testing.expectEqual(@as(usize, 1), second.queries);
    try std.testing.expectEqual(@as(usize, 1), third.queries);
    try std.testing.expectEqual(@as(usize, 1), last.udp_queries);
    try std.testing.expect(elapsed >= 2000 and elapsed < 3500);
}

test "ACME DNS actual SystemResolver continues after first negative and no-data answers" {
    try posixOnly();
    for ([_]fixture.Peer.Mode{ .nxdomain, .nodata }) |mode| {
        var last = try Server.init(false, .valid);
        defer last.deinit();
        var first = try fixture.Peer.init(.{ 127, 0, 0, 2 }, last.port, mode);
        defer first.deinit();
        try first.start();
        try last.start();
        var file = fixture.ConfigFile{ .text = "nameserver 127.0.0.2\nnameserver 127.0.0.1\n" };
        try expectAddress(try configured(&file, last.port));
        try first.join();
        try last.join();
        try std.testing.expectEqual(@as(usize, 1), first.queries);
        try std.testing.expectEqual(@as(usize, 1), last.udp_queries);
    }
}

test "ACME DNS actual SystemResolver follows CNAME and validated TCP fallback" {
    try posixOnly();
    for ([_]Mode{ .alias_followup, .tcp_fragmented }) |mode| {
        var server = try Server.init(false, mode);
        defer server.deinit();
        try server.start();
        var file = fixture.ConfigFile{ .text = one_server };
        try expectAddress(try configured(&file, server.port));
        try server.join();
        try std.testing.expectEqual(@as(usize, if (mode == .alias_followup) 2 else 1), server.udp_queries);
        try std.testing.expectEqual(@as(usize, if (mode == .tcp_fragmented) 1 else 0), server.tcp_queries);
    }
}

test "ACME DNS actual SystemResolver uses scoped IPv6 nameserver custom port for A target" {
    try posixOnly();
    var server = try Server.init(true, .valid);
    defer server.deinit();
    try server.start();
    var file = fixture.ConfigFile{ .text = "nameserver ::1%1\n" };
    try expectAddress(try configured(&file, server.port));
    try server.join();
    try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
}

test "ACME DNS shared address adapter supports explicit AAAA and supplied expired deadline" {
    try posixOnly();
    var server = try Server.init(false, .valid);
    defer server.deinit();
    try server.start();
    const address = try lookup.resolve(one_server, "host.test", 8443, server.port, .aaaa, 3000);
    try std.testing.expectEqual(@as(u8, 7), address.ip6.bytes[15]);
    try std.testing.expectEqual(@as(u16, 8443), address.ip6.port);
    try server.join();
    try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    const deadline = Deadline{ .expires_ms = platform.monotonicMillis() - 1 };
    try std.testing.expectError(error.HostNotFound, lookup.resolveUntil(one_server, "host.test", 443, server.port, .a, deadline));
}
