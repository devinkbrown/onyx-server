// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the outbound HTTP implementation.

const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const tls_client_failure = @import("../tls_client_failure.zig");
const Error = @import("contracts.zig").Error;
const get = @import("client.zig").get;
const max_tls_record = @import("tls_exchange.zig").max_tls_record;
const sendFatal = @import("tls_exchange.zig").sendFatal;
const setBlocking = @import("native_io.zig").setBlocking;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const writeAll = @import("native_io.zig").writeAll;

test "TLS client fatal transport: http_fetch socket writer preserves control custody" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try tls_client_failure.testFatalTransportProof(true, writeAll);
}

test "TLS client fatal transport: http_fetch Windows socket writer preserves control custody" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const Callback = struct {
        fn send(fd: usize, client: *tls_client.Client, failure: tls_client.Error) void {
            sendFatal(fd, client, failure);
        }
    };
    try tls_client_failure.testWindowsFatalTransportProof(true, Callback.send);
}

test "TLS client fatal transport: HTTP POST response failure never opens a fallback connection" {
    // Live listener plus raw-fd writes; Windows HANDLEs cannot compile it.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    const runtime = @import("../os_runtime.zig");
    const metrics = @import("../metrics_http.zig");
    const tls_server = @import("../../crypto/tls_server.zig");
    var snapshot = metrics.MetricsSnapshot.init(a);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();
    const peer = try tls_client_failure.TestPeer.init(a);
    defer peer.deinit();
    peer.server.deinit();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x7c));
    peer.server = try tls_server.Server.init(a, .{ .cert_chain = &peer.chain, .signing_key = kp });
    const Worker = struct {
        listener: i32,
        peer: *tls_client_failure.TestPeer,
        request_seen: bool = false,
        alert_seen: bool = false,
        fallback_seen: bool = false,
        failure: ?anyerror = null,

        fn readable(fd: i32, ms: i32) !bool {
            var polls = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
            const rc = sys.poll(&polls, 1, ms);
            if (posix.errno(rc) != .SUCCESS) return error.TestUnexpectedResult;
            return rc > 0;
        }

        fn record(fd: i32, buffer: []u8) ![]u8 {
            try tls_client_failure.testReadExact(fd, buffer[0..5]);
            const n = 5 + @as(usize, std.mem.readInt(u16, buffer[3..5], .big));
            if (n > buffer.len) return error.TestUnexpectedResult;
            try tls_client_failure.testReadExact(fd, buffer[5..n]);
            return buffer[0..n];
        }

        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.failure = err;
            };
        }

        fn exchange(self: *@This()) !void {
            if (!try readable(self.listener, 2000)) return error.TestUnexpectedResult;
            const rc = sys.accept(self.listener, null, null);
            if (posix.errno(rc) != .SUCCESS) return error.TestUnexpectedResult;
            const fd: i32 = @intCast(rc);
            defer runtime.close(fd);
            try setBlocking(fd);
            try setRecvTimeout(fd, 1000);
            var buffer: [max_tls_record]u8 = undefined;
            const engine = &self.peer.server;
            while (!engine.handshakeDone()) {
                switch (try engine.feed(try record(fd, &buffer))) {
                    .bytes_to_send => |bytes| {
                        defer std.testing.allocator.free(bytes);
                        try writeAll(fd, bytes);
                    },
                    .need_more => {},
                }
            }
            const request = try engine.decrypt(try record(fd, &buffer));
            defer std.testing.allocator.free(request);
            self.request_seen = std.mem.startsWith(u8, request, "POST /once HTTP/1.1\r\n") and std.mem.endsWith(u8, request, "once");
            const malformed = try engine.encrypt("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            defer std.testing.allocator.free(malformed);
            malformed[malformed.len - 1] ^= 1; // authenticated response must fail
            try writeAll(fd, malformed);
            const alert = try record(fd, &buffer);
            try tls_client_failure.testExpectAlert(engine, alert, 20);
            self.alert_seen = true;
            self.fallback_seen = try readable(self.listener, 250);
        }
    };
    var worker = Worker{ .listener = listener.listen_fd, .peer = peer };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const request = "POST /once HTTP/1.1\r\nHost: irc.test\r\nContent-Length: 4\r\n\r\nonce";
    const result = get(a, "127.0.0.1", listener.port, true, request, .{ .insecure_skip_verify = true, .recv_timeout_ms = 1000 });
    defer if (result) |bytes| a.free(bytes) else |_| {};
    thread.join();
    joined = true;
    if (worker.failure) |err| return err;
    try std.testing.expectError(error.RecordAuthenticationFailed, result);
    try std.testing.expect(worker.request_seen and worker.alert_seen);
    try std.testing.expect(!worker.fallback_seen);
}
