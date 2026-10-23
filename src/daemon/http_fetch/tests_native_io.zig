// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the outbound HTTP implementation.

const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const net = std.Io.net;
const get = @import("client.zig").get;
const getAtAddress = @import("client.zig").getAtAddress;
const wallClockSeconds = @import("tls_exchange.zig").wallClockSeconds;
const setBlocking = @import("native_io.zig").setBlocking;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const closeFd = @import("native_io.zig").closeFd;
const writeAll = @import("native_io.zig").writeAll;
const readSmallFile = @import("native_io.zig").readSmallFile;
const osEntropy = @import("native_io.zig").osEntropy;

test "http_fetch native loopback request timeout entropy and descriptor failure" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const metrics = @import("../metrics_http.zig");
    var snapshot = metrics.MetricsSnapshot.init(std.testing.allocator);
    defer snapshot.deinit();
    try snapshot.set("native_worker_probe 1\n");
    var server = try metrics.MetricsServer.init(&snapshot, 0);
    defer server.shutdown();
    const request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    // An open TCP backlog with no HTTP worker must fail within receive timeout.
    try std.testing.expectError(error.RecvTimeout, get(std.testing.allocator, "127.0.0.1", server.port, false, request, .{ .recv_timeout_ms = 40 }));
    try server.spawn();
    const response = try get(std.testing.allocator, "127.0.0.1", server.port, false, request, .{});
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, response, "native_worker_probe 1\n"));
    var random: [32]u8 = @splat(0);
    osEntropy(&random);
    try std.testing.expect(!std.mem.allEqual(u8, &random, 0));
    try std.testing.expect(wallClockSeconds() > 1_700_000_000);
    var empty: [1]u8 = undefined;
    try std.testing.expectError(error.NoNameservers, readSmallFile("/definitely-missing-onyx-resolver", &empty));
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expectError(error.RecvTimeout, setRecvTimeout(-1, 1));
        try std.testing.expectError(error.ConnectFailed, setBlocking(-1));
    }
}

test "http_fetch Linux IPv6 pinned loopback HTTP" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const listener_rc = sys.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    if (posix.errno(listener_rc) != .SUCCESS) return error.SkipZigTest;
    const listener: sys.fd_t = @intCast(listener_rc);
    defer closeFd(listener);
    var loopback: [16]u8 = @splat(0);
    loopback[15] = 1;
    var address = posix.sockaddr.in6{ .port = 0, .addr = loopback, .flowinfo = 0, .scope_id = 0 };
    if (posix.errno(sys.bind(listener, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS or
        posix.errno(sys.listen(listener, 1)) != .SUCCESS) return error.SkipZigTest;
    var address_len: posix.socklen_t = @sizeOf(@TypeOf(address));
    if (posix.errno(sys.getsockname(listener, @ptrCast(&address), &address_len)) != .SUCCESS) return error.TestUnexpectedResult;
    const port = std.mem.bigToNative(u16, address.port);
    const Worker = struct {
        listener: sys.fd_t,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.failure = err;
            };
        }

        fn serve(self: *@This()) !void {
            var polls = [_]posix.pollfd{.{ .fd = self.listener, .events = posix.POLL.IN, .revents = 0 }};
            if (posix.errno(sys.poll(&polls, 1, 3000)) != .SUCCESS or polls[0].revents & posix.POLL.IN == 0)
                return error.TestUnexpectedResult;
            const client_rc = sys.accept(self.listener, null, null);
            if (posix.errno(client_rc) != .SUCCESS) return error.TestUnexpectedResult;
            const client: sys.fd_t = @intCast(client_rc);
            defer closeFd(client);
            var request: [256]u8 = undefined;
            var size: usize = 0;
            while (std.mem.indexOf(u8, request[0..size], "\r\n\r\n") == null) {
                if (size == request.len) return error.TestUnexpectedResult;
                const n = sys.read(client, request[size..].ptr, request.len - size);
                if (posix.errno(n) != .SUCCESS or n == 0) return error.TestUnexpectedResult;
                size += @intCast(n);
            }
            if (!std.mem.startsWith(u8, request[0..size], "GET /ipv6 HTTP/1.1\r\n"))
                return error.TestUnexpectedResult;
            const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
            try writeAll(client, response);
        }
    };
    var worker = Worker{ .listener = listener };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const pinned = try net.IpAddress.parse("::1", port);
    const request = "GET /ipv6 HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n";
    const response = try getAtAddress(std.testing.allocator, "[::1]", port, false, request, pinned, .{});
    defer std.testing.allocator.free(response);
    thread.join();
    joined = true;
    if (worker.failure) |err| return err;
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nOK"));
}
