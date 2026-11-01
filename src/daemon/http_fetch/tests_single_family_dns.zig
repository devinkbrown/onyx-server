// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Controlled DNS tests through the actual public HTTP single-family helpers.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = if (builtin.os.tag == .windows) std.os.linux else posix.system;
const dns = @import("../../proto/dns.zig");
const fixture = @import("../../proto/dns/test_server.zig");
const Packet = @import("../../proto/dns/test_packet.zig").Packet;
const platform = @import("../../substrate/platform.zig");
const resolution = @import("resolution.zig");
const native = @import("native_io.zig");

fn useServer(server: *const fixture.Server) void {
    resolution.Testing.config = .{
        .text = if (server.address == .ipv4) "nameserver 127.0.0.1" else "nameserver ::1",
        .dns_port = server.port,
    };
}

test "http_fetch native DNS UDP transport binds replies to query identity" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]fixture.Mode{ .valid, .wrong_id, .wrong_question, .foreign_source, .wrong_tc_id, .wrong_tc_question }) |mode| {
        var server = try fixture.Server.init(false, mode);
        defer server.deinit();
        try server.start();
        useServer(&server);
        const found = try resolution.resolveHostA("lookup.test", 8443, 400);
        try server.join();
        try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &found.ip4.bytes);
        try std.testing.expectEqual(@as(u16, 8443), found.ip4.port);
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
        try std.testing.expectEqual(@as(usize, 0), server.tcp_queries);
    }
}

test "http_fetch single-family DNS keeps literal and family contracts" {
    resolution.Testing.config = .{ .text = null };
    defer resolution.Testing.config = null;
    const a4 = try resolution.resolveHostA("127.0.0.9", 8080, 0);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 9 }, &a4.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 8080), a4.ip4.port);
    const a6 = try resolution.resolveHostA("::1", 8081, 0);
    try std.testing.expectEqual(@as(u8, 1), a6.ip6.bytes[15]);
    try std.testing.expectEqual(@as(u16, 8081), a6.ip6.port);
    const aaaa6 = try resolution.resolveHostAAAA("::1", 8082, 0);
    try std.testing.expectEqual(@as(u16, 8082), aaaa6.ip6.port);
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd) {
        // An IPv4 literal historically falls through the AAAA lookup path.
        try std.testing.expectError(error.NoNameservers, resolution.resolveHostAAAA("127.0.0.9", 8083, 0));
        var server = try fixture.Server.init(false, .valid);
        defer server.deinit();
        try server.start();
        useServer(&server);
        const found = try resolution.resolveHostAAAA("127.0.0.9", 8083, 400);
        try server.join();
        try std.testing.expectEqual(@as(u8, 7), found.ip6.bytes[15]);
        try std.testing.expectEqual(@as(u16, 8083), found.ip6.port);
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    }
}

test "http_fetch single-family DNS preserves config and hostname error policy" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]?[]const u8{ null, "", "nameserver invalid", "nameserver fe80::1" }) |text| {
        resolution.Testing.config = .{ .text = text };
        try std.testing.expectError(error.NoNameservers, resolution.resolveHostA("bad..name", 443, 20));
        try std.testing.expectError(error.NoNameservers, resolution.resolveHostAAAA("lookup.test", 443, 20));
    }
    resolution.Testing.config = .{ .text = "nameserver 127.0.0.1", .dns_port = 0 };
    for ([_][]const u8{ "", "bad..name", "invalid\x00name" }) |name| {
        try std.testing.expectError(error.HostNotFound, resolution.resolveHostA(name, 443, 20));
        try std.testing.expectError(error.HostNotFound, resolution.resolveHostAAAA(name, 443, 20));
    }
    const long_name: [254]u8 = @splat('a');
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostA(&long_name, 443, 20));
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostA("lookup.test", 443, 20));
}

test "http_fetch single-family DNS zero and small budgets reject delayed replies" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]u31{ 0, 20 }) |budget| {
        var server = try fixture.Server.init(false, .valid);
        defer server.deinit();
        const script = [_]fixture.Step{.{ .name = "lookup.test", .qtype = .a, .delay_ms = 80, .reply = .{ .address = .{ .ipv4 = .{ 192, 0, 2, 7 } } } }};
        server.script = &script;
        server.fixture_timeout_ms = 200;
        try server.start();
        useServer(&server);
        const started = platform.monotonicMillis();
        try std.testing.expectError(error.HostNotFound, resolution.resolveHostA("lookup.test", 443, budget));
        const elapsed = platform.monotonicMillis() - started;
        server.join() catch |err| {
            if (budget != 0 or err != error.Timeout or server.udp_queries != 0) return err;
        };
        try std.testing.expect(elapsed < 500);
        if (budget != 0) try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    }
}

test "http_fetch single-family DNS oversized caller budget remains capped" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    var server = try fixture.Server.init(false, .silent);
    defer server.deinit();
    try server.start();
    useServer(&server);
    const started = platform.monotonicMillis();
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostAAAA("lookup.test", 443, std.math.maxInt(u31)));
    const elapsed = platform.monotonicMillis() - started;
    try server.join();
    try std.testing.expect(elapsed >= 4500 and elapsed < 6000);
    try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
}

/// One finite responder for backup-address and unrelated-owner integration
/// cases. It uses the query received from the real public HTTP resolver.
const Responder = struct {
    fd: sys.fd_t,
    unrelated_owner: bool = false,
    served: bool = false,

    fn init(address: [4]u8, port: u16) !Responder {
        const fd = try native.udpSocket();
        errdefer native.closeFd(fd);
        try native.setRecvTimeout(fd, 1000);
        var bound = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(address) };
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&bound), @sizeOf(@TypeOf(bound)))));
        return .{ .fd = fd };
    }

    fn run(self: *Responder) void {
        var bytes: [512]u8 = undefined;
        var peer: posix.sockaddr.storage = undefined;
        var length: posix.socklen_t = @sizeOf(@TypeOf(peer));
        const received = sys.recvfrom(self.fd, &bytes, bytes.len, 0, @ptrCast(&peer), &length);
        if (posix.errno(received) != .SUCCESS or received < 12) return;
        const message = dns.parseMessage(1, 0, bytes[0..@intCast(received)]) catch return;
        if (message.question_count != 1) return;
        const question = message.questions[0];
        var packet = Packet.init(message.header.id, question.name.slice(), question.qtype) catch return;
        packet.address(if (self.unrelated_owner) "unrelated.test" else question.name.slice(), 30, .{ .ipv4 = .{ 192, 0, 2, 7 } }) catch return;
        const response = packet.slice();
        const sent = sys.sendto(self.fd, response.ptr, response.len, 0, @ptrCast(&peer), length);
        self.served = posix.errno(sent) == .SUCCESS and sent == response.len;
    }
};

test "http_fetch single-family DNS retains silent and negative primary fallback order" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]fixture.Mode{ .silent, .nxdomain, .nodata }) |mode| {
        var primary = try fixture.Server.init(false, mode);
        defer primary.deinit();
        var backup = try Responder.init(.{ 127, 0, 0, 2 }, primary.port);
        defer native.closeFd(backup.fd);
        try primary.start();
        const thread = try std.Thread.spawn(.{}, Responder.run, .{&backup});
        var joined = false;
        defer if (!joined) thread.join();
        resolution.Testing.config = .{
            .text = "nameserver 127.0.0.1\nnameserver 127.0.0.2\noptions timeout:99 attempts:99\n",
            .dns_port = primary.port,
        };
        const started = platform.monotonicMillis();
        const found = try resolution.resolveHostA("lookup.test", 8443, 160);
        thread.join();
        joined = true;
        try primary.join();
        try std.testing.expect(backup.served);
        try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &found.ip4.bytes);
        try std.testing.expectEqual(@as(u16, 8443), found.ip4.port);
        try std.testing.expect(platform.monotonicMillis() - started < 400);
        try std.testing.expectEqual(@as(usize, 1), primary.udp_queries);
    }
}

test "http_fetch single-family DNS rejects malformed and unrelated-owner replies" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    {
        var server = try fixture.Server.init(false, .malformed);
        defer server.deinit();
        try server.start();
        useServer(&server);
        try std.testing.expectError(error.HostNotFound, resolution.resolveHostA("lookup.test", 443, 40));
        try server.join();
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    }
    var responder = try Responder.init(.{ 127, 0, 0, 1 }, 0);
    defer native.closeFd(responder.fd);
    responder.unrelated_owner = true;
    var address: sys.sockaddr.in = undefined;
    var length: posix.socklen_t = @sizeOf(@TypeOf(address));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(responder.fd, @ptrCast(&address), &length)));
    resolution.Testing.config = .{ .text = "nameserver 127.0.0.1", .dns_port = std.mem.bigToNative(u16, address.port) };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(error.HostNotFound, resolution.resolveHostA("lookup.test", 443, 40));
    thread.join();
    joined = true;
    try std.testing.expect(responder.served);
}

test "http_fetch single-family DNS supports scoped IPv6 nameservers and custom target port" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]bool{ false, true }) |aaaa| {
        var server = try fixture.Server.init(true, .valid);
        defer server.deinit();
        try server.start();
        resolution.Testing.config = .{ .text = "nameserver ::1%1", .dns_port = server.port };
        const found = if (aaaa) try resolution.resolveHostAAAA("lookup.test", 9443, 400) else try resolution.resolveHostA("lookup.test", 9443, 400);
        try server.join();
        if (aaaa) {
            try std.testing.expectEqual(@as(u8, 7), found.ip6.bytes[15]);
            try std.testing.expectEqual(@as(u16, 9443), found.ip6.port);
        } else {
            try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &found.ip4.bytes);
            try std.testing.expectEqual(@as(u16, 9443), found.ip4.port);
        }
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
    }
}

test "http_fetch single-family DNS follows aliases and validated TCP fallback" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    defer resolution.Testing.config = null;
    for ([_]fixture.Mode{ .alias_followup, .tcp_fragmented }) |mode| {
        var server = try fixture.Server.init(false, mode);
        defer server.deinit();
        if (mode == .alias_followup) server.expected_queries = 2;
        try server.start();
        useServer(&server);
        const found = try resolution.resolveHostA("lookup.test", 443, 800);
        try server.join();
        try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &found.ip4.bytes);
        try std.testing.expectEqual(if (mode == .alias_followup) @as(usize, 2) else 1, server.udp_queries);
        try std.testing.expectEqual(if (mode == .tcp_fragmented) @as(usize, 1) else 0, server.tcp_queries);
    }
}
