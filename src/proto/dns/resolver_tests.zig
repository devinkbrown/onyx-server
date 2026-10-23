// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local fixtures for the public resolver compatibility entry points.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const win = @import("windows_abi.zig");
const wire = @import("wire.zig");
const config = @import("resolver_config.zig");

const resolver = @import("resolver.zig");
const transport = @import("transport.zig");
const Deadline = @import("deadline.zig").Deadline;
const resolveForward = resolver.resolveForward;
const resolveReverse = resolver.resolveReverse;
const resolveConfirmed = resolver.resolveConfirmed;
const forwardConfirms = resolver.forwardConfirms;

test "DNS Windows native UDP A and AAAA replies are identity checked and time bounded" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var startup: [408]u8 align(8) = @splat(0);
    try std.testing.expectEqual(@as(i32, 0), win.WSAStartup(0x0202, &startup));
    defer _ = win.WSACleanup();
    const socket = win.WSASocketW(win.af_inet, win.sock_dgram, win.ipproto_udp, null, 0, 1);
    try std.testing.expect(socket != win.invalid_socket);
    defer _ = win.closesocket(socket);
    var bind_addr = win.SockAddr4{ .family = win.af_inet, .port = 0, .addr = .{ 127, 0, 0, 1 } };
    try std.testing.expectEqual(@as(i32, 0), win.bind(socket, &bind_addr, @sizeOf(win.SockAddr4)));
    var addr_len: i32 = @sizeOf(win.SockAddr4);
    try std.testing.expectEqual(@as(i32, 0), win.getsockname(socket, &bind_addr, &addr_len));
    const timeout_ms: u32 = 1000;
    try std.testing.expectEqual(@as(i32, 0), win.setsockopt(socket, win.sol_socket, win.so_rcvtimeo, &timeout_ms, @sizeOf(u32)));

    const Responder = struct {
        socket: usize,
        served: std.atomic.Value(u32) = .{ .raw = 0 },

        fn run(self: *@This()) void {
            for (0..3) |index| {
                var query_buf: [wire.max_message_len]u8 = undefined;
                var peer: win.SockAddr4 = undefined;
                var peer_len: i32 = @sizeOf(win.SockAddr4);
                const got = win.recvfrom(self.socket, &query_buf, @intCast(query_buf.len), 0, &peer, &peer_len);
                if (got <= 0) return;
                const parsed = wire.parseMessage(1, 0, query_buf[0..@intCast(got)]) catch return;
                if (parsed.question_count != 1) return;
                const question = parsed.questions[0];
                const q = wire.Query{ .name = question.name.slice(), .qtype = question.qtype };
                const data: wire.AnswerData = switch (q.qtype) {
                    .a => .{ .a = .{ 192, 0, 2, 42 } },
                    .aaaa => .{ .aaaa = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 } },
                    else => return,
                };
                const answer = wire.Answer{ .name = q.name, .rr_type = q.qtype, .ttl = 30, .data = data };
                var response_buf: [wire.max_message_len]u8 = undefined;
                const response = wire.encodeMessage(&response_buf, .{
                    .id = if (index == 2) parsed.header.id +% 1 else parsed.header.id,
                    .response = true,
                    .questions = &.{q},
                    .answers = &.{answer},
                }) catch return;
                if (win.sendto(self.socket, response.ptr, @intCast(response.len), 0, &peer, peer_len) != @as(i32, @intCast(response.len))) return;
                _ = self.served.fetchAdd(1, .acq_rel);
            }
        }
    };
    var responder = Responder{ .socket = socket };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    var joined = false;
    defer if (!joined) thread.join();

    var cfg = config.ResolverConfig{ .port = std.mem.bigToNative(u16, bind_addr.port), .timeout_ms = 500, .attempts = 1 };
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    var addresses: [wire.max_cache_addrs]wire.Address = undefined;
    const a = try resolveForward(&cfg, "windows-dns.test", false, &addresses);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 192, 0, 2, 42 } }, a[0]);
    const aaaa = try resolveForward(&cfg, "windows-dns.test", true, &addresses);
    try std.testing.expectEqual(wire.Address{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 } }, aaaa[0]);
    try std.testing.expectError(error.Timeout, resolveForward(&cfg, "wrong-id.test", false, &addresses));
    thread.join();
    joined = true;
    try std.testing.expectEqual(@as(u32, 3), responder.served.load(.acquire));

    const start_ms = @import("../../substrate/platform.zig").monotonicMillis();
    try std.testing.expectError(error.Timeout, resolveForward(&cfg, "no-reply.test", false, &addresses));
    const elapsed_ms = @import("../../substrate/platform.zig").monotonicMillis() - start_ms;
    try std.testing.expect(elapsed_ms >= 0 and elapsed_ms < 3000);
}

test "forwardConfirms implements the FCrDNS match (anti-spoof)" {
    const ip = wire.Address{ .ipv4 = .{ 203, 0, 113, 7 } };
    const matching = [_]wire.Address{ .{ .ipv4 = .{ 198, 51, 100, 1 } }, ip };
    const spoofed = [_]wire.Address{.{ .ipv4 = .{ 198, 51, 100, 9 } }};
    try std.testing.expect(forwardConfirms(ip, &matching)); // PTR name resolves back → trust
    try std.testing.expect(!forwardConfirms(ip, &spoofed)); // forward set excludes IP → reject
    try std.testing.expect(!forwardConfirms(ip, &[_]wire.Address{})); // no data → reject
    // Family mismatch never confirms.
    const v6 = wire.Address{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    try std.testing.expect(!forwardConfirms(v6, &matching));
}

test "DNS native resolver forward reverse and confirmation use IPv4 and IPv6 UDP" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const sys = posix.system;
    const Worker = struct {
        fd: posix.fd_t,
        count: usize = 0,
        fn run(self: *@This()) void {
            for (0..4) |_| {
                var packet: [1024]u8 = undefined;
                var peer: posix.sockaddr.storage = undefined;
                var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer));
                const got = sys.recvfrom(self.fd, &packet, packet.len, 0, @ptrCast(&peer), &peer_len);
                if (posix.errno(got) != .SUCCESS) return;
                const parsed = wire.parseMessage(1, 0, packet[0..@intCast(got)]) catch return;
                if (parsed.question_count != 1) return;
                const q = parsed.questions[0];
                const question = wire.Query{ .name = q.name.slice(), .qtype = q.qtype };
                var ipv6: [16]u8 = @splat(0);
                ipv6[15] = 1;
                const answer = wire.Answer{ .name = question.name, .rr_type = q.qtype, .ttl = 5, .data = switch (q.qtype) {
                    .a => .{ .a = .{ 127, 0, 0, 7 } },
                    .aaaa => .{ .aaaa = ipv6 },
                    .ptr => .{ .ptr = "confirmed-worker.test" },
                    else => return,
                } };
                var reply_buf: [1024]u8 = undefined;
                const reply = wire.encodeMessage(&reply_buf, .{ .id = parsed.header.id, .response = true, .questions = &.{question}, .answers = &.{answer} }) catch return;
                const sent = sys.sendto(self.fd, reply.ptr, reply.len, 0, @ptrCast(&peer), peer_len);
                if (posix.errno(sent) != .SUCCESS or sent != reply.len) return;
                self.count += 1;
            }
        }
    };
    for ([_]bool{ false, true }) |ipv6| {
        const fd_raw = sys.socket(if (ipv6) posix.AF.INET6 else posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(fd_raw));
        const fd: posix.fd_t = @intCast(fd_raw);
        defer _ = sys.close(fd);
        const tv = sys.timeval{ .sec = 1, .usec = 0 };
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)))));
        var loopback6: [16]u8 = @splat(0);
        loopback6[15] = 1;
        var port: u16 = 0;
        if (ipv6) {
            var addr = posix.sockaddr.in6{ .port = 0, .flowinfo = 0, .addr = loopback6, .scope_id = 0 };
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))));
            var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&addr), &len)));
            port = std.mem.bigToNative(u16, addr.port);
        } else {
            var addr = posix.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))));
            var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&addr), &len)));
            port = std.mem.bigToNative(u16, addr.port);
        }
        var cfg = config.ResolverConfig{ .port = port, .timeout_ms = 100, .attempts = 1 };
        cfg.addNameserver(if (ipv6) .{ .ipv6 = loopback6 } else .{ .ipv4 = .{ 127, 0, 0, 1 } });
        var worker = Worker{ .fd = fd };
        const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
        var joined = false;
        defer if (!joined) thread.join();
        const target = if (ipv6) wire.Address{ .ipv6 = loopback6 } else wire.Address{ .ipv4 = .{ 127, 0, 0, 7 } };
        var addresses: [4]wire.Address = undefined;
        const forward = try resolveForward(&cfg, "confirmed-worker.test", ipv6, &addresses);
        try std.testing.expectEqual(@as(usize, 1), forward.len);
        try std.testing.expect(wire.addressEql(target, forward[0]));
        var host: [wire.max_domain_text_len]u8 = undefined;
        try std.testing.expectEqualStrings("confirmed-worker.test", try resolveReverse(&cfg, target, &host));
        try std.testing.expectEqualStrings("confirmed-worker.test", resolveConfirmed(&cfg, target, &host) orelse return error.TestUnexpectedResult);
        thread.join();
        joined = true;
        try std.testing.expectEqual(@as(usize, 4), worker.count);
    }
}

test "DNS native receive fails closed on invalid socket" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    var connection = transport.Connection{ .socket = -1, .protocol = .udp };
    var out: [12]u8 = undefined;
    try std.testing.expectError(error.ReceiveFailed, connection.receive(&out, Deadline.after(100)));
}

test "DNS Linux zero timeout expires before a delayed UDP reply" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const platform = @import("../../substrate/platform.zig");
    const fd_raw = linux.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(fd_raw));
    const fd: linux.fd_t = @intCast(fd_raw);
    defer _ = linux.close(fd);
    const fixture_timeout = linux.timeval{ .sec = 1, .usec = 0 };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&fixture_timeout), @sizeOf(linux.timeval))));
    var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))));
    var addr_len: posix.socklen_t = @sizeOf(@TypeOf(addr));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.getsockname(fd, @ptrCast(&addr), &addr_len)));

    const Responder = struct {
        fd: linux.fd_t,
        received: bool = false,

        fn run(self: *@This()) void {
            var packet: [wire.max_message_len]u8 = undefined;
            var peer: linux.sockaddr.in = undefined;
            var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer));
            const got = linux.recvfrom(self.fd, &packet, packet.len, 0, @ptrCast(&peer), &peer_len);
            if (posix.errno(got) != .SUCCESS) return;
            self.received = true;
            // The late reply releases a regressed zero-timeout receive, so the
            // regression fails an assertion instead of hanging the test gate.
            var remaining = linux.timespec{ .sec = 0, .nsec = 250 * std.time.ns_per_ms };
            while (true) {
                var next: linux.timespec = undefined;
                switch (posix.errno(linux.nanosleep(&remaining, &next))) {
                    .SUCCESS => break,
                    .INTR => remaining = next,
                    else => return,
                }
            }
            _ = linux.sendto(self.fd, &packet, got, 0, @ptrCast(&peer), peer_len);
        }
    };
    var responder = Responder{ .fd = fd };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    var joined = false;
    defer if (!joined) thread.join();

    var query_buf: [wire.max_message_len]u8 = undefined;
    const query = try wire.encodeQuery(&query_buf, 7, "zero-timeout.test", .a);
    var response: [wire.max_message_len]u8 = undefined;
    const started_ms = platform.monotonicMillis();
    var connection = try transport.Connection.open(.{ .address = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = std.mem.bigToNative(u16, addr.port) }, .udp, Deadline.after(1000));
    defer connection.close();
    try connection.send(query, Deadline.after(1000));
    const result = connection.receive(&response, Deadline.after(0));
    const elapsed_ms = platform.monotonicMillis() - started_ms;
    thread.join();
    joined = true;
    try std.testing.expect(responder.received);
    try std.testing.expectError(error.Timeout, result);
    try std.testing.expect(elapsed_ms >= 0 and elapsed_ms < 2000);
}
