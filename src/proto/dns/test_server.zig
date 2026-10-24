// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Controlled loopback DNS servers. Every fixture wait has a finite deadline.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = if (builtin.os.tag == .linux) std.os.linux else posix.system;
const win = @import("windows_abi.zig");
const wire = @import("wire.zig");
const config = @import("resolver_config.zig");
const transport = @import("transport.zig");
const Deadline = @import("deadline.zig").Deadline;
const Packet = @import("test_packet.zig").Packet;
const response = @import("response.zig");
const Socket = transport.Socket;

const max_bind_attempts = 8;

/// Internal deterministic port-selection seam. Normal fixtures pass null and
/// ask the kernel for a fresh ephemeral port on every attempt.
const BindPlan = struct {
    ports: []const u16,
    attempts: usize = 0,
    tcp_collisions: usize = 0,
    udp_sockets: [max_bind_attempts]?Socket = @splat(null),
    listeners: [max_bind_attempts]?Socket = @splat(null),
};

pub const Mode = enum {
    valid,
    wrong_id,
    wrong_question,
    wrong_tc_id,
    wrong_tc_question,
    foreign_source,
    alias_followup,
    alias_cycle,
    alias_cross_cycle,
    alias_slow,
    nxdomain,
    nodata,
    servfail,
    silent,
    malformed,
    many_addresses,
    tcp_many_addresses,
    tcp_fragmented,
    tcp_oversize,
    tcp_partial,
    tcp_slow,
};

pub const Reply = union(enum) {
    silent,
    ptr: []const u8,
    address: wire.Address,
};

pub const Step = struct {
    name: []const u8,
    qtype: wire.RecordType,
    delay_ms: u32 = 0,
    reply: Reply,
};

pub const Server = struct {
    udp: Socket,
    listener: Socket,
    address: wire.Address,
    port: u16,
    mode: Mode,
    thread: ?std.Thread = null,
    udp_queries: usize = 0,
    tcp_queries: usize = 0,
    failure: ?anyerror = null,
    expected_queries: usize = 1,
    /// Optional deterministic requests/replies for daemon-worker integration.
    /// The caller retains these immutable steps through join/deinit.
    script: []const Step = &.{},
    fixture_timeout_ms: u32 = 2500,

    pub fn init(ipv6: bool, mode: Mode) !Server {
        return initWithPlan(ipv6, mode, null);
    }

    fn initWithPlan(ipv6: bool, mode: Mode, plan: ?*BindPlan) !Server {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd and builtin.os.tag != .windows) return error.SkipZigTest;
        if (comptime builtin.os.tag == .windows) {
            var startup: [408]u8 align(8) = @splat(0);
            if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
        }
        errdefer if (comptime builtin.os.tag == .windows) {
            _ = win.WSACleanup();
        };
        var loopback6: [16]u8 = @splat(0);
        loopback6[15] = 1;
        const address: wire.Address = if (ipv6) .{ .ipv6 = loopback6 } else .{ .ipv4 = .{ 127, 0, 0, 1 } };
        for (0..max_bind_attempts) |attempt| {
            const requested_port = if (plan) |p| blk: {
                p.attempts += 1;
                break :blk if (attempt < p.ports.len) p.ports[attempt] else 0;
            } else 0;
            // UDP and TCP have independent port namespaces. A UDP-selected
            // ephemeral number may already belong to a TCP socket. Retry only
            // that explicit bind error; bindPair retires both losing sockets.
            const pair = bindPair(ipv6, address, requested_port, plan) catch |err| switch (err) {
                error.AddressInUse => continue,
                else => return err,
            };
            return .{ .udp = pair.udp, .listener = pair.listener, .address = address, .port = pair.port, .mode = mode };
        }
        return error.AddressInUse;
    }

    pub fn resolverConfig(self: *const Server) config.ResolverConfig {
        var cfg = config.ResolverConfig{ .port = self.port, .timeout_ms = 1000, .attempts = 1 };
        cfg.addNameserver(self.address);
        return cfg;
    }

    pub fn start(self: *Server) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn join(self: *Server) !void {
        if (self.thread) |thread| thread.join();
        self.thread = null;
        if (self.failure) |err| return err;
    }

    pub fn deinit(self: *Server) void {
        if (self.thread) |thread| thread.join();
        closeSocket(self.listener);
        closeSocket(self.udp);
        if (comptime builtin.os.tag == .windows) _ = win.WSACleanup();
    }

    fn run(self: *Server) void {
        self.serve() catch |err| {
            self.failure = err;
        };
    }

    fn serve(self: *Server) !void {
        const deadline = Deadline.after(self.fixture_timeout_ms);
        const count: usize = if (self.script.len != 0) self.script.len else if (self.mode == .alias_followup or self.mode == .alias_cycle or self.mode == .alias_cross_cycle or self.mode == .alias_slow) 2 else self.expected_queries;
        for (0..count) |index| {
            var datagram = transport.Connection{ .socket = self.udp, .protocol = .udp };
            try datagram.wait(.read, deadline);
            var bytes: [wire.max_message_len]u8 = undefined;
            var peer: [128]u8 align(8) = undefined;
            var peer_len: u32 = peer.len;
            const got: usize = if (comptime builtin.os.tag == .windows) blk: {
                var length: i32 = @intCast(peer_len);
                const result = win.recvfrom(self.udp, &bytes, bytes.len, 0, @ptrCast(&peer), &length);
                if (result <= 0) return error.ReceiveFailed;
                peer_len = @intCast(length);
                break :blk @intCast(result);
            } else blk: {
                const result = sys.recvfrom(self.udp, &bytes, bytes.len, 0, @ptrCast(&peer), &peer_len);
                if (posix.errno(result) != .SUCCESS) return error.ReceiveFailed;
                break :blk @intCast(result);
            };
            const parsed = try wire.parseMessage(1, 0, bytes[0..got]);
            if (parsed.question_count != 1) return error.InvalidQuestion;
            const question = parsed.questions[0];
            const id = parsed.header.id;
            self.udp_queries += 1;
            if (self.script.len != 0) {
                const step = self.script[index];
                if (question.qtype != step.qtype or !std.mem.eql(u8, question.name.slice(), step.name)) return error.InvalidQuestion;
                if (step.delay_ms != 0) pause(@min(step.delay_ms, try deadline.remaining()));
                var reply = try Packet.init(id, question.name.slice(), question.qtype);
                switch (step.reply) {
                    .silent => continue,
                    .ptr => |name| try reply.nameRecord(question.name.slice(), 12, 30, name),
                    .address => |address| try reply.address(question.name.slice(), 30, address),
                }
                try sendDatagram(self.udp, reply.slice(), &peer, peer_len);
                continue;
            }
            if (self.mode == .silent) continue;
            var packet = try Packet.init(id, question.name.slice(), question.qtype);
            if (self.mode == .wrong_id or self.mode == .wrong_question or self.mode == .foreign_source or self.mode == .wrong_tc_id or self.mode == .wrong_tc_question) {
                var wrong = try Packet.init(if (self.mode == .wrong_id or self.mode == .wrong_tc_id) id +% 1 else id, if (self.mode == .wrong_question or self.mode == .wrong_tc_question) "unrelated.test" else question.name.slice(), question.qtype);
                try positive(&wrong, question, 99);
                if (self.mode == .wrong_tc_id or self.mode == .wrong_tc_question) wrong.flags(0x8380);
                if (self.mode == .foreign_source) {
                    const foreign = try create(self.address == .ipv6, .udp);
                    defer closeSocket(foreign);
                    try sendDatagram(foreign, wrong.slice(), &peer, peer_len);
                } else try sendDatagram(self.udp, wrong.slice(), &peer, peer_len);
            }
            switch (self.mode) {
                .alias_cross_cycle => {
                    try packet.nameRecord(question.name.slice(), 5, 7, "intermediate.test");
                    try packet.nameRecord("intermediate.test", 5, 7, if (index == 0) "canonical.test" else "final.test");
                    if (index != 0) try packet.address("final.test", 30, .{ .ipv4 = .{ 192, 0, 2, 7 } });
                },
                .alias_slow => {
                    if (index == 0) {
                        try packet.nameRecord(question.name.slice(), 5, 1, "canonical.test");
                    } else {
                        pause(100);
                        try positive(&packet, question, 7);
                    }
                },
                .alias_followup, .alias_cycle => {
                    if (index == 0 or self.mode == .alias_cycle) {
                        try packet.nameRecord(question.name.slice(), 5, 7, if (index == 0) "canonical.test" else "lookup.test");
                    } else try positive(&packet, question, 7);
                },
                .nxdomain, .nodata => {
                    if (self.mode == .nxdomain) packet.flags(0x8183);
                    try packet.soa("test", 40, 10);
                },
                .servfail => packet.flags(0x8182),
                .malformed => {
                    // Correct envelope, but a claimed RR missing its body.
                    std.mem.writeInt(u16, packet.bytes[6..8], 1, .big);
                    for (0..@import("query_engine.zig").max_rejected_datagrams) |_| try sendDatagram(self.udp, packet.slice(), &peer, peer_len);
                    return;
                },
                .many_addresses => {
                    for (0..wire.max_cache_addrs + 1) |address_index| {
                        try packet.address(question.name.slice(), 30, .{ .ipv4 = .{ 192, 0, 2, @intCast(address_index + 1) } });
                    }
                },
                .tcp_fragmented, .tcp_many_addresses, .tcp_oversize, .tcp_partial, .tcp_slow => {
                    packet.flags(0x8380);
                    // A complete question followed by a genuinely partial RR.
                    std.mem.writeInt(u16, packet.bytes[6..8], 1, .big);
                    packet.bytes[packet.len] = 0xc0;
                    packet.len += 1;
                    try sendDatagram(self.udp, packet.slice(), &peer, peer_len);
                    try self.serveTcp(deadline);
                    return;
                },
                else => try positive(&packet, question, 7),
            }
            try sendDatagram(self.udp, packet.slice(), &peer, peer_len);
        }
    }

    fn serveTcp(self: *Server, deadline: Deadline) !void {
        var listener = transport.Connection{ .socket = self.listener, .protocol = .tcp };
        try listener.wait(.read, deadline);
        const accepted: Socket = if (comptime builtin.os.tag == .windows) blk: {
            const socket = win.accept(self.listener, null, null);
            if (socket == win.invalid_socket) return error.SocketUnavailable;
            var nonblocking: u32 = 1;
            if (win.ioctlsocket(socket, win.fionbio, &nonblocking) != 0) {
                closeSocket(socket);
                return error.SocketUnavailable;
            }
            break :blk socket;
        } else blk: {
            const socket = sys.accept4(self.listener, null, null, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC);
            if (posix.errno(socket) != .SUCCESS) return error.SocketUnavailable;
            break :blk @intCast(socket);
        };
        defer closeSocket(accepted);
        var connection = transport.Connection{ .socket = accepted, .protocol = .tcp };
        var prefix: [2]u8 = undefined;
        try connection.receiveExact(&prefix, deadline);
        const len: usize = std.mem.readInt(u16, &prefix, .big);
        if (len > wire.max_message_len) return error.OversizeMessage;
        var bytes: [wire.max_message_len]u8 = undefined;
        try connection.receiveExact(bytes[0..len], deadline);
        const parsed = try wire.parseMessage(1, 0, bytes[0..len]);
        if (parsed.question_count != 1) return error.InvalidQuestion;
        self.tcp_queries += 1;
        const question = parsed.questions[0];
        var packet = try Packet.init(parsed.header.id, question.name.slice(), question.qtype);
        const padding: [600]u8 = @splat(0);
        try packet.record(.answer, question.name.slice(), 46, 30, &padding);
        if (self.mode == .tcp_many_addresses) {
            for (0..wire.max_cache_addrs + 1) |address_index| {
                try packet.address(question.name.slice(), 30, .{ .ipv4 = .{ 192, 0, 2, @intCast(address_index + 1) } });
            }
        } else try positive(&packet, question, 7);
        std.mem.writeInt(u16, &prefix, @intCast(if (self.mode == .tcp_oversize) response.max_packet_len + 1 else packet.len), .big);
        if (self.mode == .tcp_oversize) {
            try connection.send(&prefix, deadline);
            return;
        }
        try connection.send(prefix[0..1], deadline);
        pause(if (self.mode == .tcp_slow) 150 else 10);
        if (self.mode == .tcp_slow) {
            connection.send(prefix[1..], deadline) catch {};
            return;
        }
        try connection.send(prefix[1..], deadline);
        if (self.mode == .tcp_partial) {
            try connection.send(packet.slice()[0 .. packet.len / 2], deadline);
            return;
        }
        try connection.send(packet.slice()[0 .. packet.len / 2], deadline);
        pause(10);
        try connection.send(packet.slice()[packet.len / 2 ..], deadline);
    }
};

const BoundPair = struct { udp: Socket, listener: Socket, port: u16 };

fn bindPair(ipv6: bool, address: wire.Address, requested_port: u16, plan: ?*BindPlan) !BoundPair {
    const udp = try create(ipv6, .udp);
    errdefer closeSocket(udp);
    if (plan) |p| p.udp_sockets[p.attempts - 1] = udp;
    const port = try bindSocket(udp, address, requested_port);
    const listener = try create(ipv6, .tcp);
    errdefer closeSocket(listener);
    if (plan) |p| p.listeners[p.attempts - 1] = listener;
    _ = bindSocket(listener, address, port) catch |err| {
        if (err == error.AddressInUse) if (plan) |p| {
            p.tcp_collisions += 1;
        };
        return err;
    };
    if (comptime builtin.os.tag == .windows) {
        if (win.listen(listener, 1) != 0) return error.SocketUnavailable;
    } else if (posix.errno(sys.listen(listener, 1)) != .SUCCESS) return error.SocketUnavailable;
    return .{ .udp = udp, .listener = listener, .port = port };
}

fn positive(packet: *Packet, question: wire.Question, last: u8) !void {
    switch (question.qtype) {
        .a => try packet.address(question.name.slice(), 30, .{ .ipv4 = .{ 192, 0, 2, last } }),
        .aaaa => {
            var address: [16]u8 = @splat(0);
            address[15] = last;
            try packet.address(question.name.slice(), 30, .{ .ipv6 = address });
        },
        .ptr => try packet.nameRecord(question.name.slice(), 12, 30, "ptr.test"),
        .txt => return error.UnsupportedType,
    }
}

fn create(ipv6: bool, protocol: transport.Protocol) !Socket {
    if (comptime builtin.os.tag == .windows) {
        const socket = win.WSASocketW(if (ipv6) win.af_inet6 else win.af_inet, if (protocol == .udp) win.sock_dgram else win.sock_stream, if (protocol == .udp) win.ipproto_udp else win.ipproto_tcp, null, 0, win.socket_flags);
        if (socket == win.invalid_socket) return error.SocketUnavailable;
        errdefer closeSocket(socket);
        var nonblocking: u32 = 1;
        if (win.ioctlsocket(socket, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
        return socket;
    }
    const socket = sys.socket(if (ipv6) posix.AF.INET6 else posix.AF.INET, (if (protocol == .udp) @as(u32, posix.SOCK.DGRAM) else posix.SOCK.STREAM) | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, if (protocol == .udp) posix.IPPROTO.UDP else posix.IPPROTO.TCP);
    if (posix.errno(socket) != .SUCCESS) return error.SocketUnavailable;
    return @intCast(socket);
}

fn bindSocket(socket: Socket, address: wire.Address, port: u16) !u16 {
    if (comptime builtin.os.tag == .windows) {
        if (address == .ipv4) {
            var raw = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, port), .addr = address.ipv4 };
            var len: i32 = @sizeOf(@TypeOf(raw));
            if (win.bind(socket, &raw, len) != 0) return windowsBindError(win.WSAGetLastError());
            if (win.getsockname(socket, &raw, &len) != 0) return error.SocketNameFailed;
            return std.mem.bigToNative(u16, raw.port);
        }
        var raw = win.SockAddr6{ .family = win.af_inet6, .port = std.mem.nativeToBig(u16, port), .addr = address.ipv6 };
        var len: i32 = @sizeOf(@TypeOf(raw));
        if (win.bind(socket, @ptrCast(&raw), len) != 0) return windowsBindError(win.WSAGetLastError());
        if (win.getsockname(socket, @ptrCast(&raw), &len) != 0) return error.SocketNameFailed;
        return std.mem.bigToNative(u16, raw.port);
    }
    if (address == .ipv4) {
        var raw = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(address.ipv4) };
        var len: posix.socklen_t = @sizeOf(@TypeOf(raw));
        const result = posix.errno(sys.bind(socket, @ptrCast(&raw), len));
        if (result != .SUCCESS) return posixBindError(result);
        if (posix.errno(sys.getsockname(socket, @ptrCast(&raw), &len)) != .SUCCESS) return error.SocketNameFailed;
        return std.mem.bigToNative(u16, raw.port);
    }
    var raw = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .addr = address.ipv6, .scope_id = 0, .flowinfo = 0 };
    var len: posix.socklen_t = @sizeOf(@TypeOf(raw));
    const result = posix.errno(sys.bind(socket, @ptrCast(&raw), len));
    if (result != .SUCCESS) return posixBindError(result);
    if (posix.errno(sys.getsockname(socket, @ptrCast(&raw), &len)) != .SUCCESS) return error.SocketNameFailed;
    return std.mem.bigToNative(u16, raw.port);
}

const BindError = error{
    AddressInUse,
    PermissionDenied,
    AddressUnavailable,
    AddressFamilyUnsupported,
    InvalidSocket,
    InvalidArgument,
    SystemResources,
    Interrupted,
    SocketBindFailed,
};

fn posixBindError(code: posix.E) BindError {
    return switch (code) {
        .ADDRINUSE => error.AddressInUse,
        .ACCES, .PERM => error.PermissionDenied,
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .BADF, .NOTSOCK => error.InvalidSocket,
        .INVAL => error.InvalidArgument,
        .NOBUFS, .NOMEM => error.SystemResources,
        .INTR => error.Interrupted,
        else => error.SocketBindFailed,
    };
}

fn windowsBindError(code: i32) BindError {
    return switch (code) {
        10048 => error.AddressInUse, // WSAEADDRINUSE
        10013 => error.PermissionDenied,
        10049 => error.AddressUnavailable,
        10047 => error.AddressFamilyUnsupported,
        10038 => error.InvalidSocket,
        10022 => error.InvalidArgument,
        10055 => error.SystemResources,
        10004 => error.Interrupted,
        else => error.SocketBindFailed,
    };
}

fn sendDatagram(socket: Socket, bytes: []const u8, peer: *align(8) const [128]u8, peer_len: u32) !void {
    if (comptime builtin.os.tag == .windows) {
        const sent = win.sendto(socket, bytes.ptr, @intCast(bytes.len), 0, @ptrCast(peer), @intCast(peer_len));
        if (sent < 0 or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
    } else {
        const sent = sys.sendto(socket, bytes.ptr, bytes.len, 0, @ptrCast(@alignCast(peer)), peer_len);
        if (posix.errno(sent) != .SUCCESS or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
    }
}

fn closeSocket(socket: Socket) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(socket);
    } else {
        _ = sys.close(socket);
    }
}

fn pause(ms: u32) void {
    if (comptime builtin.os.tag == .windows) {
        var interval: i64 = -@as(i64, ms) * 10_000;
        _ = std.os.windows.ntdll.NtDelayExecution(.FALSE, &interval);
    } else {
        var remaining = sys.timespec{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
        while (true) {
            var next: sys.timespec = undefined;
            switch (posix.errno(sys.nanosleep(&remaining, &next))) {
                .SUCCESS => return,
                .INTR => remaining = next,
                else => return,
            }
        }
    }
}

/// Reserve TCP while confirming the same port is currently free for UDP.
/// This reproduces the independent namespaces without relying on randomness.
const OccupiedTcp = struct {
    socket: Socket,
    address: wire.Address,
    port: u16,

    fn init(ipv6: bool) !OccupiedTcp {
        var loopback6: [16]u8 = @splat(0);
        loopback6[15] = 1;
        const address: wire.Address = if (ipv6) .{ .ipv6 = loopback6 } else .{ .ipv4 = .{ 127, 0, 0, 1 } };
        for (0..max_bind_attempts) |_| {
            const socket = try create(ipv6, .tcp);
            var retained = false;
            defer if (!retained) closeSocket(socket);
            const port = try bindSocket(socket, address, 0);
            const probe = try create(ipv6, .udp);
            defer closeSocket(probe);
            _ = bindSocket(probe, address, port) catch |err| switch (err) {
                error.AddressInUse => continue,
                else => return err,
            };
            retained = true;
            return .{ .socket = socket, .address = address, .port = port };
        }
        return error.AddressInUse;
    }
};

fn startTestSockets() !void {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd and builtin.os.tag != .windows) return error.SkipZigTest;
    if (comptime builtin.os.tag == .windows) {
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    }
}

fn stopTestSockets() void {
    if (comptime builtin.os.tag == .windows) _ = win.WSACleanup();
}

fn expectSocketClosed(socket: Socket) !void {
    if (comptime builtin.os.tag == .windows) {
        var address: win.SockAddr4 = undefined;
        var len: i32 = @sizeOf(@TypeOf(address));
        try std.testing.expectEqual(@as(i32, -1), win.getsockname(socket, &address, &len));
        try std.testing.expectEqual(@as(i32, 10038), win.WSAGetLastError()); // WSAENOTSOCK
    } else {
        var address: posix.sockaddr.in = undefined;
        var len: posix.socklen_t = @sizeOf(@TypeOf(address));
        try std.testing.expectEqual(posix.E.BADF, posix.errno(sys.getsockname(socket, @ptrCast(&address), &len)));
    }
}

test "DNS fixture binding retries actual TCP namespace contention and serves UDP TCP" {
    try startTestSockets();
    defer stopTestSockets();
    for ([_]bool{ false, true }) |ipv6| {
        const occupied = try OccupiedTcp.init(ipv6);
        defer closeSocket(occupied.socket);
        const ports = [_]u16{occupied.port};
        var plan = BindPlan{ .ports = &ports };
        var server = try Server.initWithPlan(ipv6, .tcp_fragmented, &plan);
        defer server.deinit();
        try std.testing.expect(plan.attempts >= 2 and plan.attempts <= max_bind_attempts);
        try std.testing.expect(plan.tcp_collisions >= 1);
        try std.testing.expect(server.port != occupied.port);
        // The losing UDP socket must have been retired even though its bind
        // succeeded. TCP remains occupied throughout this assertion.
        const probe = try create(ipv6, .udp);
        defer closeSocket(probe);
        try std.testing.expectEqual(occupied.port, try bindSocket(probe, occupied.address, occupied.port));
        try server.start();
        const result = try @import("query_engine.zig").resolve(&server.resolverConfig(), "fixture.test", .a, .{});
        try server.join();
        try std.testing.expectEqual(response.Outcome.positive, result.outcome);
        try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &result.addresses[0].ipv4);
        try std.testing.expectEqual(@as(usize, 1), server.udp_queries);
        try std.testing.expectEqual(@as(usize, 1), server.tcp_queries);
    }
}

test "DNS fixture binding exhaustion is bounded and closes both losing descriptors" {
    try startTestSockets();
    defer stopTestSockets();
    for ([_]bool{ false, true }) |ipv6| {
        const occupied = try OccupiedTcp.init(ipv6);
        defer closeSocket(occupied.socket);
        const ports: [max_bind_attempts]u16 = @splat(occupied.port);
        var plan = BindPlan{ .ports = &ports };
        try std.testing.expectError(error.AddressInUse, Server.initWithPlan(ipv6, .valid, &plan));
        try std.testing.expectEqual(@as(usize, max_bind_attempts), plan.attempts);
        try std.testing.expectEqual(@as(usize, max_bind_attempts), plan.tcp_collisions);
        // No socket allocation between failure and these OS-level checks: a
        // leaked UDP or TCP handle from any attempt cannot be hidden by reuse.
        for (plan.udp_sockets, plan.listeners) |udp, listener| {
            try expectSocketClosed(udp.?);
            try expectSocketClosed(listener.?);
        }
        // Every prior attempt released this same UDP port as well, otherwise
        // a subsequent attempt would have failed before the counted TCP bind.
        const probe = try create(ipv6, .udp);
        defer closeSocket(probe);
        try std.testing.expectEqual(occupied.port, try bindSocket(probe, occupied.address, occupied.port));
    }
}

test "DNS fixture binding preserves non-collision errors" {
    try startTestSockets();
    defer stopTestSockets();
    const socket = try create(false, .udp);
    closeSocket(socket);
    try std.testing.expectError(error.InvalidSocket, bindSocket(socket, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 0));
}
