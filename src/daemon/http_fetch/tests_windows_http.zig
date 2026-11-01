// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the outbound HTTP implementation.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const net = std.Io.net;
const get = @import("client.zig").get;
const getAtAddress = @import("client.zig").getAtAddress;
const postSignedAtAddress = @import("client.zig").postSignedAtAddress;
const max_tls_record = @import("tls_exchange.zig").max_tls_record;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const closeFd = @import("native_io.zig").closeFd;
const writeAll = @import("native_io.zig").writeAll;
const readSome = @import("native_io.zig").readSome;
const win = @import("windows_abi.zig").win;

test "http_fetch Windows plaintext loopback timeout and response limit" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("../metrics_http.zig");
    const a = std.testing.allocator;
    var snapshot = metrics.MetricsSnapshot.init(a);
    defer snapshot.deinit();
    try snapshot.set("windows_fetch_probe 1\n");
    var server = try metrics.MetricsServer.init(&snapshot, 0);
    defer server.shutdown();
    const request = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    // A connected listener without an HTTP worker must honor the receive bound.
    try std.testing.expectError(error.RecvTimeout, get(a, "127.0.0.1", server.port, false, request, .{ .recv_timeout_ms = 80 }));
    var established = false;
    try std.testing.expectError(error.RecvTimeout, get(a, "localhost", server.port, false, request, .{
        .recv_timeout_ms = 80,
        .connect_established = &established,
    }));
    try std.testing.expect(established); // A connected request must not replay on AAAA.
    try server.spawn();
    try std.testing.expectError(error.ResponseTooLarge, get(a, "127.0.0.1", server.port, false, request, .{ .max_response_bytes = 32 }));
    const response = try get(a, "127.0.0.1", server.port, false, request, .{});
    defer a.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, response, "windows_fetch_probe 1\n"));
    const pinned = try net.IpAddress.parse("127.0.0.1", server.port);
    const bypasses_dns = try getAtAddress(a, "onyx-address-pin.invalid.", server.port, false, request, pinned, .{});
    defer a.free(bypasses_dns);
    try std.testing.expect(std.mem.startsWith(u8, bypasses_dns, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expectError(error.ConnectFailed, getAtAddress(a, "onyx-address-pin.invalid.", server.port - 1, false, request, pinned, .{}));
}

test "http_fetch Windows IPv6 pinned and literal loopback HTTP" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.TestUnexpectedResult;
    defer _ = win.WSACleanup();
    const listener = win.WSASocketW(win.af_inet6, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (listener == win.invalid_socket) return error.TestUnexpectedResult;
    defer _ = win.closesocket(listener);
    var address = win.SockAddr6{ .family = win.af_inet6, .port = 0, .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    if (win.bind(listener, &address, @sizeOf(win.SockAddr6)) != 0 or win.listen(listener, 2) != 0)
        return error.TestUnexpectedResult;
    var address_len: i32 = @sizeOf(win.SockAddr6);
    if (win.getsockname(listener, &address, &address_len) != 0 or address_len != @sizeOf(win.SockAddr6))
        return error.TestUnexpectedResult;
    const port = std.mem.bigToNative(u16, address.port);
    const Worker = struct {
        listener: usize,
        port: u16,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.failure = err;
            };
        }

        fn serve(self: *@This()) !void {
            for (0..4) |index| {
                var reads = win.FdSet{ .count = 1, .sockets = undefined };
                reads.sockets[0] = self.listener;
                var timeout = win.Timeval{ .seconds = 3, .microseconds = 0 };
                if (win.select(0, &reads, null, null, &timeout) != 1) return error.TestUnexpectedResult;
                const client = win.accept(self.listener, null, null);
                if (client == win.invalid_socket) return error.TestUnexpectedResult;
                {
                    defer _ = win.closesocket(client);
                    try setRecvTimeout(client, 2000);
                    var request: [512]u8 = undefined;
                    var size: usize = 0;
                    while (std.mem.indexOf(u8, request[0..size], "\r\n\r\n") == null) {
                        if (size == request.len) return error.TestUnexpectedResult;
                        size += try readSome(client, request[size..]);
                    }
                    if (index == 3) {
                        var host_header_buf: [80]u8 = undefined;
                        const host_header = try std.fmt.bufPrint(&host_header_buf, "Host: onyx-address-pin.invalid.:{d}\r\n", .{self.port});
                        if (!std.mem.startsWith(u8, request[0..size], "POST /signed HTTP/1.1\r\n") or
                            std.mem.indexOf(u8, request[0..size], "X-Onyx-Signature: sha256=test") == null or
                            std.mem.indexOf(u8, request[0..size], host_header) == null)
                            return error.TestUnexpectedResult;
                    } else if (!std.mem.startsWith(u8, request[0..size], "GET /ipv6 HTTP/1.1\r\n")) {
                        return error.TestUnexpectedResult;
                    }
                    try writeAll(client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                }
            }
        }
    };
    var worker = Worker{ .listener = listener, .port = port };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const request = "GET /ipv6 HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n";
    const pinned = try net.IpAddress.parse("::1", port);
    const first = try getAtAddress(std.testing.allocator, "localhost", port, false, request, pinned, .{});
    defer std.testing.allocator.free(first);
    try std.testing.expect(std.mem.endsWith(u8, first, "\r\n\r\nOK"));
    const second = try get(std.testing.allocator, "::1", port, false, request, .{});
    defer std.testing.allocator.free(second);
    try std.testing.expect(std.mem.endsWith(u8, second, "\r\n\r\nOK"));
    // localhost has an A answer, but only the IPv6 listener is open. The
    // failed IPv4 dial must fall through to the AAAA address before any send.
    var established = false;
    const third = try get(std.testing.allocator, "localhost", port, false, request, .{
        .connect_established = &established,
        .connect_timeout_ms = 250,
    });
    defer std.testing.allocator.free(third);
    try std.testing.expect(established);
    try std.testing.expect(std.mem.endsWith(u8, third, "\r\n\r\nOK"));
    const signed = try postSignedAtAddress(std.testing.allocator, .{
        .tls = false,
        .host = "onyx-address-pin.invalid.",
        .port = port,
        .path = "/signed",
    }, "{}", "sha256=test", pinned, .{});
    defer std.testing.allocator.free(signed);
    try std.testing.expect(std.mem.endsWith(u8, signed, "\r\n\r\nOK"));
    thread.join();
    joined = true;
    if (worker.failure) |err| return err;
}

test "http_fetch Windows HTTPS loopback verifies trusted anchor and rejects untrusted anchor" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("../metrics_http.zig");
    const selfsign = @import("../../proto/x509_selfsign.zig");
    const tls_server = @import("../../crypto/tls_server.zig");
    const a = std.testing.allocator;
    var snapshot = metrics.MetricsSnapshot.init(a);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();

    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x67));
    var cert_buffer: [2048]u8 = undefined;
    const cert = try selfsign.buildSelfSigned(&cert_buffer, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x67, 1 },
        .key_pair = kp,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    const Worker = struct {
        listener: usize,
        chain: []const []const u8,
        key_pair: std.crypto.sign.Ed25519.KeyPair,
        expect_http: bool,
        request_seen: bool = false,
        alert_seen: bool = false,
        fallback_seen: bool = false,
        failure: ?anyerror = null,

        fn readable(fd: usize, timeout_ms: u32) !bool {
            var reads = win.FdSet{ .count = 1, .sockets = undefined };
            reads.sockets[0] = fd;
            var timeout = win.Timeval{ .seconds = @intCast(timeout_ms / 1000), .microseconds = @intCast((timeout_ms % 1000) * 1000) };
            const rc = win.select(0, &reads, null, null, &timeout);
            if (rc < 0) return error.TestUnexpectedResult;
            return rc > 0;
        }

        fn readExact(fd: usize, bytes: []u8) !void {
            var offset: usize = 0;
            while (offset < bytes.len) {
                offset += try readSome(fd, bytes[offset..]);
            }
        }

        fn record(fd: usize, buffer: []u8) ![]u8 {
            try readExact(fd, buffer[0..5]);
            const len = 5 + @as(usize, std.mem.readInt(u16, buffer[3..5], .big));
            if (len > buffer.len) return error.TestUnexpectedResult;
            try readExact(fd, buffer[5..len]);
            return buffer[0..len];
        }

        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.failure = err;
            };
        }

        fn exchange(self: *@This()) !void {
            if (!try readable(self.listener, 2000)) return error.TestUnexpectedResult;
            const fd = win.accept(self.listener, null, null);
            if (fd == win.invalid_socket) return error.TestUnexpectedResult;
            defer closeFd(fd);
            var blocking: u32 = 0;
            if (win.ioctlsocket(fd, win.fionbio, &blocking) != 0) return error.TestUnexpectedResult;
            try setRecvTimeout(fd, 2000);

            var engine = try tls_server.Server.init(std.heap.page_allocator, .{
                .cert_chain = self.chain,
                .signing_key = self.key_pair,
            });
            defer engine.deinit();
            var buffer: [max_tls_record]u8 = undefined;
            while (!engine.handshakeDone()) {
                switch (try engine.feed(try record(fd, &buffer))) {
                    .bytes_to_send => |bytes| {
                        defer std.heap.page_allocator.free(bytes);
                        try writeAll(fd, bytes);
                    },
                    .need_more => {},
                }
                if (!self.expect_http) {
                    // The client must reject the unknown anchor before an HTTP
                    // request. Drain its fatal alert, then check for a fallback.
                    try std.testing.expectError(error.TlsAlert, engine.feed(try record(fd, &buffer)));
                    self.alert_seen = true;
                    self.fallback_seen = try readable(self.listener, 250);
                    return;
                }
            }
            const request = try engine.decrypt(try record(fd, &buffer));
            defer std.heap.page_allocator.free(request);
            self.request_seen = std.mem.startsWith(u8, request, "GET /trusted HTTP/1.1\r\n");
            const response = try engine.encrypt("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            defer std.heap.page_allocator.free(response);
            try writeAll(fd, response);
        }
    };

    const request = "GET /trusted HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    var trusted_worker = Worker{ .listener = listener.listen_fd, .chain = &chain, .key_pair = kp, .expect_http = true };
    const trusted_thread = try std.Thread.spawn(.{}, Worker.run, .{&trusted_worker});
    var trusted_joined = false;
    defer if (!trusted_joined) trusted_thread.join();
    const trusted = get(a, "127.0.0.1", listener.port, true, request, .{ .trust_anchors = &chain, .recv_timeout_ms = 2000 });
    defer if (trusted) |response| a.free(response) else |_| {};
    trusted_thread.join();
    trusted_joined = true;
    if (trusted_worker.failure) |err| return err;
    try std.testing.expect(trusted_worker.request_seen);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", try trusted);

    var untrusted_worker = Worker{ .listener = listener.listen_fd, .chain = &chain, .key_pair = kp, .expect_http = false };
    const untrusted_thread = try std.Thread.spawn(.{}, Worker.run, .{&untrusted_worker});
    var untrusted_joined = false;
    defer if (!untrusted_joined) untrusted_thread.join();
    const untrusted = get(a, "127.0.0.1", listener.port, true, request, .{ .recv_timeout_ms = 2000 });
    defer if (untrusted) |response| a.free(response) else |_| {};
    untrusted_thread.join();
    untrusted_joined = true;
    if (untrusted_worker.failure) |err| return err;
    try std.testing.expectError(error.UnknownCa, untrusted);
    try std.testing.expect(untrusted_worker.alert_seen and !untrusted_worker.request_seen and !untrusted_worker.fallback_seen);

    // A pinned IPv6 connection must keep the hostname for SNI and certificate
    // verification, exactly as the IPv4 path does.
    const listener6 = win.WSASocketW(win.af_inet6, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (listener6 == win.invalid_socket) return error.TestUnexpectedResult;
    defer _ = win.closesocket(listener6);
    var address6 = win.SockAddr6{ .family = win.af_inet6, .port = 0, .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    if (win.bind(listener6, &address6, @sizeOf(win.SockAddr6)) != 0 or win.listen(listener6, 1) != 0)
        return error.TestUnexpectedResult;
    var address6_len: i32 = @sizeOf(win.SockAddr6);
    if (win.getsockname(listener6, &address6, &address6_len) != 0 or address6_len != @sizeOf(win.SockAddr6))
        return error.TestUnexpectedResult;
    const port6 = std.mem.bigToNative(u16, address6.port);
    var cert_buffer6: [2048]u8 = undefined;
    const cert6 = try selfsign.buildSelfSigned(&cert_buffer6, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x67, 6 },
        .key_pair = kp,
        .dns_names = &.{"localhost"},
        .is_ca = true,
    });
    const chain6 = [_][]const u8{cert6};
    var ipv6_worker = Worker{ .listener = listener6, .chain = &chain6, .key_pair = kp, .expect_http = true };
    const ipv6_thread = try std.Thread.spawn(.{}, Worker.run, .{&ipv6_worker});
    var ipv6_joined = false;
    defer if (!ipv6_joined) ipv6_thread.join();
    const pinned6 = try net.IpAddress.parse("::1", port6);
    const request6 = "GET /trusted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const ipv6_response = getAtAddress(a, "localhost", port6, true, request6, pinned6, .{ .trust_anchors = &chain6, .recv_timeout_ms = 2000 });
    defer if (ipv6_response) |response| a.free(response) else |_| {};
    ipv6_thread.join();
    ipv6_joined = true;
    if (ipv6_worker.failure) |err| return err;
    try std.testing.expect(ipv6_worker.request_seen);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", try ipv6_response);
}
