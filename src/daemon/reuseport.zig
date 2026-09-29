// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `SO_REUSEPORT` listener creation for the sharded multi-reactor daemon.
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
//! This mirrors `server.createListener` (IPv4, blocking accept driven by
//! io_uring, `CLOEXEC` socket) and adds the per-socket `SO_REUSEPORT` flag; it is
//! a standalone helper so the reactor-spawn path can call it once per shard.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const kernel_linux = @import("kernel_linux.zig");

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
/// owns it. Several reactors may call this for the same `(host, port)` and all
/// succeed — that is the point of `SO_REUSEPORT`. On any failure the partial fd
/// is closed (no leak). Linux-only (the daemon targets Linux + io_uring).
pub fn createReusePortListener(host: []const u8, port: u16, backlog: u31) ReusePortError!linux.fd_t {
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
    var val: u32 = 0;
    var len: posix.socklen_t = @sizeOf(u32);
    const rc = linux.getsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, @ptrCast(&val), &len);
    if (posix.errno(rc) != .SUCCESS) return false;
    return val != 0;
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
