// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blocking UDP resolution and forward-confirmed reverse DNS for resolver workers.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const win = @import("windows_abi.zig");
const wire = @import("wire.zig");
const config = @import("resolver_config.zig");

pub const ResolveError = error{
    NoNameservers,
    SocketUnavailable,
    SendFailed,
    Timeout,
    IdMismatch,
    ServerFailure,
    NameError,
    NoData,
    RandomSourceFailed,
} || wire.EncodeError || wire.DecodeError;

fn randomIdHost() ResolveError!u16 {
    switch (builtin.os.tag) {
        .linux => return error.RandomSourceFailed,
        .windows => {
            var bytes: [2]u8 = undefined;
            @import("../../substrate/platform.zig").fillOsEntropy(&bytes) catch return error.RandomSourceFailed;
            const id = std.mem.readInt(u16, &bytes, .little);
            return if (id == 0) 1 else id;
        },
        else => {
            var b: [2]u8 = undefined;
            std.c.arc4random_buf(&b, b.len);
            const id = std.mem.readInt(u16, &b, .little);
            return if (id == 0) 1 else id;
        },
    }
}

/// Pure FCrDNS decision: is `address` present in a PTR name's forward A/AAAA set?
pub fn forwardConfirms(address: wire.Address, forward_addrs: []const wire.Address) bool {
    for (forward_addrs) |a| {
        if (wire.addressEql(a, address)) return true;
    }
    return false;
}

/// Send one query to a single nameserver over a blocking, recv-timeout UDP
/// socket and return the raw response bytes (a slice of `recv_buf`).
fn queryServer(ns: wire.Address, scope_id: u32, port: u16, query: []const u8, recv_buf: []u8, timeout_ms: u32) ResolveError![]const u8 {
    switch (builtin.os.tag) {
        .windows => return queryServerWindows(ns, scope_id, port, query, recv_buf, timeout_ms),
        .linux => {
            const family: u32 = switch (ns) {
                .ipv4 => posix.AF.INET,
                .ipv6 => posix.AF.INET6,
            };
            const rc = linux.socket(family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
            if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
            const fd: linux.fd_t = @intCast(rc);
            defer _ = linux.close(fd);

            try configureLinuxTimeouts(fd, timeout_ms);

            switch (ns) {
                .ipv4 => |b| {
                    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(b) };
                    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
                        return error.SendFailed;
                },
                .ipv6 => |b| {
                    var sa = linux.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = b, .scope_id = 0 };
                    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
                        return error.SendFailed;
                },
            }

            const sent = linux.sendto(fd, query.ptr, query.len, 0, null, 0);
            if (posix.errno(sent) != .SUCCESS) return error.SendFailed;

            const got = linux.recvfrom(fd, recv_buf.ptr, recv_buf.len, 0, null, null);
            if (posix.errno(got) != .SUCCESS) return error.Timeout;
            return recv_buf[0..@intCast(got)];
        },
        .openbsd => {
            const sys = posix.system;
            const family: c_uint = if (ns == .ipv4) posix.AF.INET else posix.AF.INET6;
            const fd = sys.socket(family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
            if (posix.errno(fd) != .SUCCESS) return error.SocketUnavailable;
            defer _ = sys.close(fd);
            const finite_ms = @max(timeout_ms, 1);
            const tv = sys.timeval{ .sec = @intCast(finite_ms / 1000), .usec = @intCast((finite_ms % 1000) * 1000) };
            if (posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)))) != .SUCCESS or
                posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)))) != .SUCCESS) return error.SocketUnavailable;
            const connected = switch (ns) {
                .ipv4 => |bytes| blk: {
                    var addr = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(bytes) };
                    break :blk sys.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
                },
                .ipv6 => |bytes| blk: {
                    var addr = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = bytes, .scope_id = 0 };
                    break :blk sys.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
                },
            };
            if (posix.errno(connected) != .SUCCESS) return error.SendFailed;
            const sent = sys.sendto(fd, query.ptr, query.len, 0, null, 0);
            if (posix.errno(sent) != .SUCCESS or sent != query.len) return error.SendFailed;
            const received = sys.recvfrom(fd, recv_buf.ptr, recv_buf.len, 0, null, null);
            if (posix.errno(received) != .SUCCESS) return error.Timeout;
            return recv_buf[0..@intCast(received)];
        },
        else => return error.SocketUnavailable,
    }
}

fn configureLinuxTimeouts(fd: linux.fd_t, timeout_ms: u32) ResolveError!void {
    // A zero timeval disables the kernel deadline. Match the POSIX resolver's
    // minimum and fail closed if either blocking operation cannot be bounded.
    const finite_ms = @max(timeout_ms, 1);
    const tv = linux.timeval{ .sec = @intCast(finite_ms / 1000), .usec = @intCast((finite_ms % 1000) * 1000) };
    if (posix.errno(linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval))) != .SUCCESS or
        posix.errno(linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval))) != .SUCCESS)
        return error.SocketUnavailable;
}

fn queryServerWindows(ns: wire.Address, scope_id: u32, port: u16, query: []const u8, recv_buf: []u8, timeout_ms: u32) ResolveError![]const u8 {
    if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    defer _ = win.WSACleanup();
    const family: i32 = if (ns == .ipv4) win.af_inet else win.af_inet6;
    const socket = win.WSASocketW(family, win.sock_dgram, win.ipproto_udp, null, 0, 1);
    if (socket == win.invalid_socket) return error.SocketUnavailable;
    defer _ = win.closesocket(socket);

    // SO_RCVTIMEO and SO_SNDTIMEO bound each UDP attempt, even when the caller
    // supplies zero or an arbitrarily large timeout.
    const finite_ms: u32 = @max(1, @min(timeout_ms, 5000));
    if (win.setsockopt(socket, win.sol_socket, win.so_rcvtimeo, &finite_ms, @sizeOf(u32)) != 0 or
        win.setsockopt(socket, win.sol_socket, win.so_sndtimeo, &finite_ms, @sizeOf(u32)) != 0)
        return error.SocketUnavailable;
    const connected = switch (ns) {
        .ipv4 => |bytes| blk: {
            const addr = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, port), .addr = bytes };
            break :blk win.connect(socket, &addr, @sizeOf(win.SockAddr4));
        },
        .ipv6 => |bytes| blk: {
            const addr = win.SockAddr6{ .family = win.af_inet6, .port = std.mem.nativeToBig(u16, port), .addr = bytes, .scope_id = scope_id };
            break :blk win.connect(socket, &addr, @sizeOf(win.SockAddr6));
        },
    };
    if (connected != 0) return error.SendFailed;
    const sent = win.send(socket, query.ptr, @intCast(query.len), 0);
    if (sent < 0 or @as(usize, @intCast(sent)) != query.len) return error.SendFailed;
    const received = win.recv(socket, recv_buf.ptr, @intCast(recv_buf.len), 0);
    if (received <= 0) return error.Timeout;
    return recv_buf[0..@intCast(received)];
}

/// Query every configured nameserver (round-robin over `attempts`) until one
/// returns a well-formed, id-matched, non-error answer.
fn queryAll(
    comptime maxq: usize,
    comptime maxa: usize,
    cfg: *const config.ResolverConfig,
    name: []const u8,
    qtype: wire.RecordType,
    id: u16,
) ResolveError!wire.Message(maxq, maxa) {
    if (cfg.nameserver_count == 0) return error.NoNameservers;
    var qbuf: [wire.max_message_len]u8 = undefined;
    const query = try wire.encodeQuery(&qbuf, id, name, qtype);
    var rbuf: [wire.max_message_len]u8 = undefined;

    var attempt: u8 = 0;
    const attempts = if (builtin.os.tag == .windows) @min(cfg.attempts, 3) else cfg.attempts;
    while (attempt < attempts) : (attempt += 1) {
        for (cfg.nsSlice(), 0..) |ns, index| {
            const resp = queryServer(ns, cfg.nameserver_scope_ids[index], cfg.port, query, &rbuf, cfg.timeout_ms) catch continue;
            const msg = wire.parseMessage(maxq, maxa, resp) catch continue;
            if (msg.header.id != id or msg.header.flags & 0x7a00 != 0) continue;
            if (!wire.responseMatchesQuestion(maxq, maxa, &msg, name, qtype)) continue;
            switch (msg.header.rcode()) {
                0 => {
                    if ((qtype == .a or qtype == .aaaa) and msg.answer_count != 0) {
                        if (!wire.responseAnswersFollowCnames(maxa, resp, name, qtype)) continue;
                    } else if (!wire.responseAnswersInBailiwick(maxq, maxa, &msg, name, qtype)) continue;
                    return msg;
                },
                3 => return error.NameError, // NXDOMAIN — authoritative "no such name"
                else => continue, // SERVFAIL/REFUSED — try the next server
            }
        }
    }
    return error.Timeout;
}

fn randomId() ResolveError!u16 {
    // Linux getrandom is syscall 318. Off Linux that number is not getrandom.
    if (comptime builtin.os.tag != .linux) return randomIdHost();
    var b: [2]u8 = undefined;
    var filled: usize = 0;
    while (filled < b.len) {
        const rc = linux.getrandom(b[filled..].ptr, b.len - filled, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const got: usize = rc;
                if (got == 0) return error.RandomSourceFailed;
                filled += got;
            },
            .INTR => continue,
            else => return error.RandomSourceFailed,
        }
    }
    return std.mem.readInt(u16, &b, .little);
}

/// Forward-resolve `name` to A (or AAAA when `want_v6`) addresses into `out`.
pub fn resolveForward(cfg: *const config.ResolverConfig, name: []const u8, want_v6: bool, out: []wire.Address) ResolveError![]wire.Address {
    const qtype: wire.RecordType = if (want_v6) .aaaa else .a;
    const msg = try queryAll(1, wire.max_cache_addrs, cfg, name, qtype, try randomId());
    var n: usize = 0;
    for (msg.answerSlice()) |rr| {
        if (n >= out.len) break;
        switch (rr.data) {
            .a => |b| {
                out[n] = .{ .ipv4 = b };
                n += 1;
            },
            .aaaa => |b| {
                out[n] = .{ .ipv6 = b };
                n += 1;
            },
            else => {},
        }
    }
    if (n == 0) return error.NoData;
    return out[0..n];
}

/// Reverse-resolve `address` to its PTR hostname (no trailing dot) into `name_out`.
pub fn resolveReverse(cfg: *const config.ResolverConfig, address: wire.Address, name_out: []u8) ResolveError![]const u8 {
    var qbuf: [wire.max_domain_text_len]u8 = undefined;
    const qname = try wire.reverseName(&qbuf, address);
    const msg = try queryAll(1, wire.max_cache_addrs, cfg, qname, .ptr, try randomId());
    for (msg.answerSlice()) |rr| {
        if (rr.rr_type != .ptr) continue;
        const s = rr.data.ptr.slice();
        if (s.len == 0 or s.len > name_out.len) continue;
        @memcpy(name_out[0..s.len], s);
        return name_out[0..s.len];
    }
    return error.NoData;
}

/// Forward-confirmed reverse DNS. PTR(address) → name, then confirm `name`
/// forward-resolves back to `address`. Returns the trusted hostname, or null
/// when there is no PTR, no confirmation, or any lookup fails — in which case
/// the caller should fall back to the bare (cloaked) IP.
pub fn resolveConfirmed(cfg: *const config.ResolverConfig, address: wire.Address, name_out: []u8) ?[]const u8 {
    const name = resolveReverse(cfg, address, name_out) catch return null;
    var fwd: [wire.max_cache_addrs]wire.Address = undefined;
    const addrs = resolveForward(cfg, name, address == .ipv6, &fwd) catch return null;
    return if (forwardConfirms(address, addrs)) name else null;
}

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

test "DNS Linux timeout installation fails closed on invalid socket" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expectError(error.SocketUnavailable, configureLinuxTimeouts(-1, 0));
}

test "DNS Linux zero timeout expires before a delayed UDP reply" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const platform = @import("../../substrate/platform.zig");
    const fd_raw = linux.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(fd_raw));
    const fd: linux.fd_t = @intCast(fd_raw);
    defer _ = linux.close(fd);
    try configureLinuxTimeouts(fd, 1000);
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
    const result = queryServer(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 0, std.mem.bigToNative(u16, addr.port), query, &response, 0);
    const elapsed_ms = platform.monotonicMillis() - started_ms;
    thread.join();
    joined = true;
    try std.testing.expect(responder.received);
    try std.testing.expectError(error.Timeout, result);
    try std.testing.expect(elapsed_ms >= 0 and elapsed_ms < 2000);
}
