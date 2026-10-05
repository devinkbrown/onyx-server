// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Listener creation for the sharded multi-reactor daemon.
//!
//! In the sharded model every reactor thread runs its own io_uring and accepts
//! connections independently. Rather than a single shared listening socket (whose
//! accept queue would be a cross-thread contention point) or one accept thread
//! handing fds out, each reactor binds the *same* `(host, port)` with
//! `SO_REUSEPORT`. The kernel then keeps one accept queue per socket and
//! load-balances incoming connections across them by a 4-tuple hash — so accepts
//! scale with cores and a reactor only ever touches its own queue. `SO_REUSEADDR`
//! is also set so a restart can rebind immediately.
//!
//! This mirrors `server.createListener` (dual-stack, blocking accept driven by
//! io_uring, `CLOEXEC` socket) and adds the per-socket `SO_REUSEPORT` flag; it is
//! a standalone helper so the reactor-spawn path can call it once per shard.
//! Windows uses one exclusive dual-stack listener per port. It cannot supply
//! Linux's per-shard accept distribution without a shared acceptor.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const kernel_linux = @import("kernel_linux.zig");
const io_backend = @import("io_backend.zig");

pub const ReusePortError = error{
    Unsupported,
    InvalidAddress,
    PermissionDenied,
    AddressInUse,
    SocketUnavailable,
    Unexpected,
};

/// Create a TCP listener bound to `host:port` with `SO_REUSEPORT | SO_REUSEADDR`
/// set before bind, then `listen(backlog)`. Returns the listening fd; the caller
/// owns it. Linux/OpenBSD can create per-shard listeners; Windows creates one
/// exclusive listener because Winsock has no equivalent safe listener reuse.
/// On any failure the partial descriptor is closed.
pub fn createReusePortListener(host: []const u8, port: u16, backlog: u31) ReusePortError!linux.fd_t {
    if (comptime builtin.os.tag == .openbsd) return createOpenBsdListener(host, port, backlog, true);
    if (comptime builtin.os.tag == .windows) return createWindowsListener(host, port, backlog);
    if (builtin.os.tag != .linux) return error.Unsupported;

    const fd = try socketTcp();
    errdefer closeFd(fd);

    var yes: u32 = 1;
    // Both options must be set BEFORE bind. REUSEPORT is what lets N reactors
    // share the port with kernel-side accept load-balancing; REUSEADDR allows a
    // fast rebind after restart.
    try setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes));
    try setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&yes));
    // Dual-stack: a single AF_INET6 socket accepts both IPv6 and IPv4 (the
    // latter as IPv4-mapped ::ffff:a.b.c.d). Disable V6ONLY explicitly so the
    // behavior never depends on the net.ipv6.bindv6only sysctl. IPv4-mapped
    // peers are normalized back to real IPv4 in captureClientHost, so cloaking,
    // bans, reputation, and clone limits see the address family they expect.
    var v6only: u32 = 0;
    try setsockopt(fd, linux.IPPROTO.IPV6, linux.IPV6.V6ONLY, std.mem.asBytes(&v6only));

    var addr = try sockaddrIn6(host, port);
    try bindSocket(fd, &addr);
    try kernel_linux.applyListenerOptions(fd);
    try listenSocket(fd, backlog);
    return fd;
}

/// Whether `SO_REUSEPORT` is set on `fd` (used by tests and diagnostics).
pub fn hasReusePort(fd: linux.fd_t) bool {
    if (comptime builtin.os.tag == .windows) {
        return false;
    }
    var val: u32 = 0;
    var len: posix.socklen_t = @sizeOf(u32);
    const rc = posix.system.getsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, @ptrCast(&val), &len);
    if (posix.errno(rc) != .SUCCESS) return false;
    return val != 0;
}

/// One dual-stack, exclusive Winsock listener. Its returned i32 is an opaque
/// IOCP descriptor-table id, not a narrowed SOCKET; close it with
/// `io_backend.closeSocket`. Windows does not promise Linux SO_REUSEPORT's
/// per-shard accept distribution, so a duplicate bind fails closed.
pub fn createWindowsListener(host: []const u8, port: u16, backlog: u31) ReusePortError!linux.fd_t {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const parsed = try sockaddrIn6(host, port);
    const fd = try io_backend.openWindowsTcpSocket(@intCast(posix.AF.INET6));
    errdefer io_backend.closeSocket(fd);

    // Winsock SO_REUSEADDR allows another process to hijack a listening port;
    // SO_EXCLUSIVEADDRUSE is the secure server-side option. Its SDK value is
    // the bitwise complement of SO_REUSEADDR (0x0004).
    const yes: i32 = 1;
    try io_backend.setWindowsSocketOption(fd, 0xFFFF, ~@as(i32, 0x0004), std.mem.asBytes(&yes));
    const no: i32 = 0;
    try io_backend.setWindowsSocketOption(fd, 41, 27, std.mem.asBytes(&no)); // IPPROTO_IPV6 / IPV6_V6ONLY
    const addr = posix.sockaddr.in6{
        .port = parsed.port,
        .flowinfo = parsed.flowinfo,
        .addr = parsed.addr,
        .scope_id = parsed.scope_id,
    };
    try io_backend.bindWindowsSocket(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in6));
    try io_backend.listenWindowsSocket(fd, backlog);
    return fd;
}

/// OpenBSD sockets use their native address family and ABI. IPv6 sockets
/// cannot accept IPv4-mapped peers: wildcard dual-family listeners must be
/// created separately by the reactor owner. REUSEPORT permits duplicate
/// binding; it does not promise Linux's per-shard load-balancing policy.
pub fn createOpenBsdListener(host: []const u8, port: u16, backlog: u31, reuse_port: bool) ReusePortError!i32 {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    const ipv6 = std.mem.indexOfScalar(u8, host, ':') != null;
    const rc = posix.system.socket(if (ipv6) posix.AF.INET6 else posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, posix.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
    const fd: i32 = @intCast(rc);
    errdefer _ = posix.system.close(fd);
    const yes: u32 = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes)) catch return error.SocketUnavailable;
    if (reuse_port) posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&yes)) catch return error.SocketUnavailable;
    const bind_rc = if (ipv6) blk: {
        const ip = std.Io.net.Ip6Address.parse(host, port) catch return error.InvalidAddress;
        const addr = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = ip.bytes, .scope_id = ip.interface.index };
        break :blk posix.system.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    } else blk: {
        const ip = std.Io.net.Ip4Address.parse(if (host.len == 0) "0.0.0.0" else host, port) catch return error.InvalidAddress;
        const addr = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(ip.bytes) };
        break :blk posix.system.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    };
    switch (posix.errno(bind_rc)) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.SocketUnavailable,
    }
    if (posix.errno(posix.system.listen(fd, @intCast(backlog))) != .SUCCESS) return error.SocketUnavailable;
    return fd;
}

test "OpenBSD listeners bind native IPv4 and IPv6 addresses" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    for ([_][]const u8{ "127.0.0.1", "::1" }) |host| {
        const listener = try createOpenBsdListener(host, 0, 8, true);
        defer _ = posix.system.close(listener);
        var address: posix.sockaddr.storage = undefined;
        var len: posix.socklen_t = @sizeOf(@TypeOf(address));
        try std.testing.expect(posix.errno(posix.system.getsockname(listener, @ptrCast(&address), &len)) == .SUCCESS);
        const family: u32 = if (host[0] == ':') posix.AF.INET6 else posix.AF.INET;
        try std.testing.expectEqual(family, @as(u32, address.family));
        const bound_port = if (family == posix.AF.INET6)
            @as(*const posix.sockaddr.in6, @ptrCast(&address)).port
        else
            @as(*const posix.sockaddr.in, @ptrCast(&address)).port;
        try std.testing.expect(bound_port != 0);
        try std.testing.expect(hasReusePort(listener));
        const client = posix.system.socket(family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
        try std.testing.expect(posix.errno(client) == .SUCCESS);
        defer _ = posix.system.close(client);
        try std.testing.expect(posix.errno(posix.system.connect(client, @ptrCast(&address), len)) == .SUCCESS);
        // Client connect completion can precede listener readiness, especially
        // on IPv6. Bound the nonblocking accept retry to forty 50 ms polls.
        const accepted: posix.socket_t = blk: {
            for (0..40) |_| {
                const rc = posix.system.accept4(listener, null, null, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK);
                const accept_errno = posix.errno(rc);
                switch (accept_errno) {
                    .SUCCESS => break :blk @intCast(rc),
                    .AGAIN, .INTR => {},
                    else => {
                        std.debug.print("OpenBSD listener fixture host={s} accept errno={s}\n", .{ host, @tagName(accept_errno) });
                        return error.TestUnexpectedResult;
                    },
                }
                var ready = [_]posix.pollfd{.{ .fd = listener, .events = posix.POLL.IN, .revents = 0 }};
                const polled = posix.system.poll(&ready, ready.len, 50);
                if (polled < 0 and posix.errno(polled) == .INTR) continue;
                try std.testing.expect(polled >= 0);
            }
            std.debug.print("OpenBSD listener fixture host={s} accept readiness timed out\n", .{host});
            return error.TestUnexpectedResult;
        };
        defer _ = posix.system.close(accepted);
    }
}

test "Windows exclusive dual-stack listener accepts through IOCP" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidAddress, createWindowsListener("not-an-ip", 0, 8));
    const specific = try createWindowsListener("127.0.0.1", 0, 8);
    defer io_backend.closeSocket(specific);
    try std.testing.expect((try io_backend.socketPort(specific)) != 0);

    var backend = try io_backend.IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    const listener = try createReusePortListener("", 0, 8);
    defer io_backend.closeSocket(listener);
    var client: linux.fd_t = -1;
    defer io_backend.closeSocket(client);
    var accepted: linux.fd_t = -1;
    defer io_backend.closeSocket(accepted);
    defer backend.quiesce() catch @panic("Windows listener test left IOCP requests live");

    const port = try io_backend.socketPort(listener);
    try std.testing.expect(port != 0);
    try std.testing.expect(!hasReusePort(listener));
    if (createWindowsListener("", port, 8)) |duplicate| {
        io_backend.closeSocket(duplicate);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expect(err == error.AddressInUse or err == error.PermissionDenied);
    }

    // The mesh dials through canonical sockaddr_in6 even for IPv4 peers.
    // This verifies both sockets are dual-stack and ConnectEx reaches v4.
    client = try io_backend.openWindowsTcpSocket(@intCast(posix.AF.INET6));
    const peer = posix.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 },
        .scope_id = 0,
    };
    const accept_token = @import("ringlane.zig").FdToken{ .slot = 601, .gen = 4 };
    const connect_token = @import("ringlane.zig").FdToken{ .slot = 602, .gen = 4 };
    try backend.accept(accept_token, listener);
    try backend.connect(connect_token, client, @ptrCast(&peer), @sizeOf(posix.sockaddr.in6));
    try std.testing.expectEqual(@as(u32, 2), try backend.submit());
    var seen_connect = false;
    var events: [2]io_backend.Reaped = undefined;
    for (0..20) |_| {
        const count = try backend.reap(&events, 100);
        for (events[0..count]) |event| {
            if (event.op == .accept and std.meta.eql(event.token, accept_token)) {
                try std.testing.expect(event.result >= 0);
                accepted = event.result;
            } else if (event.op == .connect and std.meta.eql(event.token, connect_token)) {
                try std.testing.expectEqual(@as(i32, 0), event.result);
                seen_connect = true;
            } else return error.TestUnexpectedResult;
        }
        if (accepted >= 0 and seen_connect) break;
    }
    try std.testing.expect(accepted >= 0 and seen_connect);
    try std.testing.expectEqual(port, try io_backend.socketPort(accepted));
    switch (try io_backend.socketPeerAddress(accepted)) {
        .ipv6 => |bytes| {
            for (bytes[0..10]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
            try std.testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 127, 0, 0, 1 }, bytes[10..16]);
        },
        else => return error.TestUnexpectedResult,
    }
}

fn socketTcp() ReusePortError!linux.fd_t {
    const rc = linux.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES, .PERM => return error.PermissionDenied,
        .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.SocketUnavailable,
        else => return error.Unexpected,
    }
}

/// Build an IPv6 bind address. A wildcard host ("0.0.0.0", "::", or empty) binds
/// in6addr_any so the dual-stack socket accepts every interface and both
/// families. An IPv6 literal binds directly; an IPv4 literal binds as its
/// IPv4-mapped form (::ffff:a.b.c.d). Anything else is rejected.
fn sockaddrIn6(host: []const u8, port: u16) ReusePortError!posix.sockaddr.in6 {
    var addr: [16]u8 = @splat(0); // in6addr_any (dual-stack wildcard)
    if (host.len != 0 and !std.mem.eql(u8, host, "0.0.0.0") and !std.mem.eql(u8, host, "::")) {
        if (std.Io.net.Ip6Address.parse(host, port)) |a6| {
            addr = a6.bytes;
        } else |_| {
            const a4 = std.Io.net.Ip4Address.parse(host, port) catch return error.InvalidAddress;
            addr = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++ a4.bytes;
        }
    }
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = addr,
        .scope_id = 0,
    };
}

fn bindSocket(fd: linux.fd_t, addr: *const posix.sockaddr.in6) ReusePortError!void {
    const ptr: *const posix.sockaddr = @ptrCast(addr);
    const rc = linux.bind(fd, ptr, @sizeOf(posix.sockaddr.in6));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        else => return error.Unexpected,
    }
}

fn listenSocket(fd: linux.fd_t, backlog: u31) ReusePortError!void {
    const rc = linux.listen(fd, backlog);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ADDRINUSE => return error.AddressInUse,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}

fn setsockopt(fd: linux.fd_t, level: i32, optname: u32, opt: []const u8) ReusePortError!void {
    const rc = linux.setsockopt(fd, level, optname, opt.ptr, @intCast(opt.len));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

test "two reactors bind the same port with SO_REUSEPORT" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // A fixed high port in the ephemeral range. If the environment refuses the
    // bind (sandbox), skip rather than fail.
    const port: u16 = 54931;
    const first = createReusePortListener("127.0.0.1", port, 16) catch return error.SkipZigTest;
    defer closeFd(first);

    // The whole point: a SECOND socket binds the SAME port and also succeeds.
    const second = createReusePortListener("127.0.0.1", port, 16) catch |e| {
        // Only REUSEPORT makes this possible; an AddressInUse here means the
        // option did not take — that is a real failure, not an environment skip.
        if (e == error.AddressInUse) return error.TestUnexpectedResult;
        return error.SkipZigTest;
    };
    defer closeFd(second);

    try std.testing.expect(hasReusePort(first));
    try std.testing.expect(hasReusePort(second));
}

test "rejects a malformed host" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidAddress, createReusePortListener("not-an-ip", 0, 16));
}
