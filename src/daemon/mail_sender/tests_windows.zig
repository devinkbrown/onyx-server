// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const std = @import("std");
const builtin = @import("builtin");
const smtp_client = @import("../../proto/smtp_client.zig");
const os_runtime = @import("../os_runtime.zig");
const store_mod = @import("../store.zig");
const testing = std.testing;
const Config = @import("config.zig").Config;
const max_tls_record = @import("limits.zig").max_tls_record;
const Sender = @import("core.zig").Sender;
const testConfig = @import("core.zig").testConfig;
const isLoopback = @import("resolution.zig").isLoopback;
const resolveRelayAddress = @import("resolution.zig").resolveRelayAddress;
const connectRelayAddress = @import("resolution.zig").connectRelayAddress;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const closeFd = @import("native_io.zig").closeFd;
const writeAll = @import("native_io.zig").writeAll;
const readSome = @import("native_io.zig").readSome;
const win = @import("windows_abi.zig").win;

test "Windows SMTP loopback rejection records a private failure WAL" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("../metrics_http.zig");
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var unjournaled = try Sender.init(allocator, testConfig());
    defer unjournaled.deinit();
    try std.testing.expectError(error.FailureJournalUnavailable, unjournaled.startChecked());
    try tmp.dir.createDir(io, "mail", .default_dir);
    try os_runtime.protectEmptyDirectoryWindows(io, tmp.dir, "mail");

    const broad_config = Config{
        .relay_host = "127.0.0.1",
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .failure_wal = "broad.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
        .private_failure_windows = true,
    };
    try std.testing.expectError(error.InsecurePermissions, Sender.init(allocator, broad_config));

    var snapshot = metrics.MetricsSnapshot.init(allocator);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();

    const Relay = struct {
        listener: usize,
        saw_ehlo: bool = false,
        saw_starttls: bool = false,
        failure: ?anyerror = null,

        fn readLine(fd: usize, out: []u8) ![]const u8 {
            for (out, 0..) |_, index| {
                _ = try readSome(fd, out[index .. index + 1]);
                if (index != 0 and out[index - 1] == '\r' and out[index] == '\n') return out[0 .. index + 1];
            }
            return error.SmtpReplyTooLarge;
        }
        fn exchange(self: *@This()) !void {
            var reads = win.FdSet{ .count = 1, .sockets = undefined };
            reads.sockets[0] = self.listener;
            var timeout = win.Timeval{ .seconds = 3, .microseconds = 0 };
            if (win.select(0, &reads, null, null, &timeout) != 1) return error.TestUnexpectedResult;
            const fd = win.accept(self.listener, null, null);
            if (fd == win.invalid_socket) return error.TestUnexpectedResult;
            defer closeFd(fd);
            var blocking: u32 = 0;
            if (win.ioctlsocket(fd, win.fionbio, &blocking) != 0) return error.TestUnexpectedResult;
            try setRecvTimeout(fd, 3000);
            try writeAll(fd, "220 onyx test relay\r\n");
            var line: [128]u8 = undefined;
            self.saw_ehlo = std.mem.eql(u8, try readLine(fd, &line), "EHLO onyx.test\r\n");
            try writeAll(fd, "250 STARTTLS\r\n");
            self.saw_starttls = std.mem.eql(u8, try readLine(fd, &line), "STARTTLS\r\n");
            try writeAll(fd, "454 TLS temporarily unavailable\r\n");
        }
        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.failure = err;
            };
        }
    };
    var relay = Relay{ .listener = listener.listen_fd };
    const thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
    var joined = false;
    defer if (!joined) thread.join();
    var sender = try Sender.init(allocator, .{
        .relay_host = "127.0.0.1",
        .relay_port = listener.port,
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .failure_wal = "mail/fail.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
        .private_failure_windows = true,
    });
    defer sender.deinit();
    try sender.startChecked();
    try std.testing.expect(sender.thread != null);
    try sender.settle("user@example.test", "verification", "private code");
    sender.stop();
    thread.join();
    joined = true;
    if (relay.failure) |err| {
        std.debug.print("Windows SMTP relay fixture failed: {s}, EHLO={any}, STARTTLS={any}\n", .{ @errorName(err), relay.saw_ehlo, relay.saw_starttls });
        return err;
    }
    try std.testing.expect(relay.saw_ehlo and relay.saw_starttls);

    {
        var store = try store_mod.OroStore.openPrivateWindowsWithConfig(allocator, io, tmp.dir, "mail/fail.wal", .{});
        defer store.deinit();
        const row = store.get(.props, "mailfail:1") orelse return error.TestUnexpectedResult;
        try std.testing.expect(std.mem.indexOf(u8, row, "SmtpFailed") != null);
        try std.testing.expect(std.mem.indexOf(u8, row, "user@example.test") != null);
    }
    const private_dir = try os_runtime.openPrivateDirectoryWindows(io, tmp.dir, "mail");
    defer private_dir.close(io);
    const private_wal = try os_runtime.openExistingPrivateWindows(private_dir, "fail.wal", .verify_only);
    private_wal.close(io);
}

test "Windows SMTP trusted STARTTLS delivers a complete message" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("../metrics_http.zig");
    const selfsign = @import("../../proto/x509_selfsign.zig");
    const tls_server = @import("../../crypto/tls_server.zig");
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "mail", .default_dir);
    try os_runtime.protectEmptyDirectoryWindows(io, tmp.dir, "mail");

    var snapshot = metrics.MetricsSnapshot.init(allocator);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();

    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x6d));
    var cert_buffer: [2048]u8 = undefined;
    const cert = try selfsign.buildSelfSigned(&cert_buffer, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x6d, 1 },
        .key_pair = key_pair,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};

    const Relay = struct {
        listener: usize,
        chain: []const []const u8,
        key_pair: std.crypto.sign.Ed25519.KeyPair,
        saw_message: bool = false,
        failure: ?anyerror = null,

        fn readExact(fd: usize, out: []u8) !void {
            var offset: usize = 0;
            while (offset < out.len) offset += try readSome(fd, out[offset..]);
        }
        fn readRecord(fd: usize, out: *[max_tls_record]u8) ![]const u8 {
            try readExact(fd, out[0..5]);
            const length = 5 + @as(usize, std.mem.readInt(u16, out[3..5], .big));
            if (length > out.len) return error.TestUnexpectedResult;
            try readExact(fd, out[5..length]);
            return out[0..length];
        }
        fn readLine(fd: usize, out: []u8) ![]const u8 {
            for (out, 0..) |_, index| {
                _ = try readSome(fd, out[index .. index + 1]);
                if (index != 0 and out[index - 1] == '\r' and out[index] == '\n') return out[0 .. index + 1];
            }
            return error.SmtpReplyTooLarge;
        }
        fn readApp(engine: *tls_server.Server, fd: usize, out: *[max_tls_record]u8) ![]u8 {
            return engine.decrypt(try readRecord(fd, out));
        }
        fn reply(engine: *tls_server.Server, fd: usize, line: []const u8) !void {
            const encrypted = try engine.encrypt(line);
            defer std.heap.page_allocator.free(encrypted);
            try writeAll(fd, encrypted);
        }
        fn expectApp(engine: *tls_server.Server, fd: usize, out: *[max_tls_record]u8, prefix: []const u8) !void {
            const command = try readApp(engine, fd, out);
            defer std.heap.page_allocator.free(command);
            if (!std.mem.startsWith(u8, command, prefix)) return error.TestUnexpectedResult;
        }
        fn exchange(self: *@This()) !void {
            var reads = win.FdSet{ .count = 1, .sockets = undefined };
            reads.sockets[0] = self.listener;
            var timeout = win.Timeval{ .seconds = 3, .microseconds = 0 };
            if (win.select(0, &reads, null, null, &timeout) != 1) return error.TestUnexpectedResult;
            const fd = win.accept(self.listener, null, null);
            if (fd == win.invalid_socket) return error.TestUnexpectedResult;
            defer closeFd(fd);
            var blocking: u32 = 0;
            if (win.ioctlsocket(fd, win.fionbio, &blocking) != 0) return error.TestUnexpectedResult;
            try setRecvTimeout(fd, 5000);
            try writeAll(fd, "220 onyx test relay\r\n");
            var line: [128]u8 = undefined;
            if (!std.mem.eql(u8, try readLine(fd, &line), "EHLO onyx.test\r\n")) return error.TestUnexpectedResult;
            try writeAll(fd, "250 STARTTLS\r\n");
            if (!std.mem.eql(u8, try readLine(fd, &line), "STARTTLS\r\n")) return error.TestUnexpectedResult;
            try writeAll(fd, "220 ready for TLS\r\n");

            var engine = try tls_server.Server.init(std.heap.page_allocator, .{
                .cert_chain = self.chain,
                .signing_key = self.key_pair,
            });
            defer engine.deinit();
            var buffer: [max_tls_record]u8 = undefined;
            while (!engine.handshakeDone()) {
                switch (try engine.feed(try readRecord(fd, &buffer))) {
                    .bytes_to_send => |bytes| {
                        defer std.heap.page_allocator.free(bytes);
                        try writeAll(fd, bytes);
                    },
                    .need_more => {},
                }
            }
            try expectApp(&engine, fd, &buffer, "EHLO onyx.test\r\n");
            try reply(&engine, fd, "250 authenticated TLS\r\n");
            try expectApp(&engine, fd, &buffer, "MAIL FROM:<onyx@example.test>\r\n");
            try reply(&engine, fd, "250 sender ok\r\n");
            try expectApp(&engine, fd, &buffer, "RCPT TO:<user@example.test>\r\n");
            try reply(&engine, fd, "250 recipient ok\r\n");
            try expectApp(&engine, fd, &buffer, "DATA\r\n");
            try reply(&engine, fd, "354 send message\r\n");
            const message = try readApp(&engine, fd, &buffer);
            defer std.heap.page_allocator.free(message);
            if (std.mem.indexOf(u8, message, "private success code") == null or
                !std.mem.endsWith(u8, message, "\r\n.\r\n")) return error.TestUnexpectedResult;
            self.saw_message = true;
            try reply(&engine, fd, "250 queued\r\n");
            try expectApp(&engine, fd, &buffer, "QUIT\r\n");
            try reply(&engine, fd, "221 bye\r\n");
        }
        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.failure = err;
            };
        }
    };
    var relay = Relay{ .listener = listener.listen_fd, .chain = &chain, .key_pair = key_pair };
    const thread = try std.Thread.spawn(.{}, Relay.run, .{&relay});
    var joined = false;
    defer if (!joined) thread.join();
    var sender = try Sender.init(allocator, .{
        .relay_host = "127.0.0.1",
        .relay_port = listener.port,
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .trust_anchors = &chain,
        .failure_wal = "mail/success.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
        .private_failure_windows = true,
    });
    defer sender.deinit();
    try sender.settle("user@example.test", "verification", "private success code");
    thread.join();
    joined = true;
    if (relay.failure) |err| return err;
    try std.testing.expect(relay.saw_message);
    try std.testing.expectEqual(@as(u64, 0), sender.failure_seq);
    try std.testing.expect(sender.pending_failure == null);
}

test "Windows SMTP connects to IPv6 loopback relay" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    defer _ = win.WSACleanup();

    const listener = win.WSASocketW(win.af_inet6, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (listener == win.invalid_socket) return error.SocketUnavailable;
    defer closeFd(listener);
    var local = win.SockAddr6{ .family = win.af_inet6, .port = 0, .addr = @as([15]u8, @splat(0)) ++ [_]u8{1} };
    if (win.bind(listener, &local, @sizeOf(win.SockAddr6)) != 0 or win.listen(listener, 1) != 0)
        return error.TestUnexpectedResult;
    var local_len: i32 = @sizeOf(win.SockAddr6);
    if (win.getsockname(listener, &local, &local_len) != 0 or local_len != @sizeOf(win.SockAddr6))
        return error.TestUnexpectedResult;
    const port = std.mem.bigToNative(u16, local.port);
    try std.testing.expect(port != 0);

    const address = try resolveRelayAddress("::1", port, 1000);
    try std.testing.expect(address == .ip6);
    try std.testing.expect(isLoopback(address));
    const primary = try resolveRelayAddress("localhost", port, 1000);
    try std.testing.expect(primary == .ip4);
    const client = try connectRelayAddress("localhost", port, primary, 1000, false, true);
    defer closeFd(client);
    var reads = win.FdSet{ .count = 1, .sockets = undefined };
    reads.sockets[0] = listener;
    var timeout = win.Timeval{ .seconds = 1, .microseconds = 0 };
    if (win.select(0, &reads, null, null, &timeout) != 1) return error.TestUnexpectedResult;
    const peer = win.accept(listener, null, null);
    if (peer == win.invalid_socket) return error.TestUnexpectedResult;
    defer closeFd(peer);
    try setRecvTimeout(peer, 1000);
    try writeAll(client, "6");
    var received: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try readSome(peer, &received));
    try std.testing.expectEqual(@as(u8, '6'), received[0]);

    const a = try resolveRelayAddress("127.0.0.1", port, 1000);
    try std.testing.expect(a == .ip4);
    try std.testing.expectError(error.ResolveTimeout, resolveRelayAddress("localhost", port, 0));
}
