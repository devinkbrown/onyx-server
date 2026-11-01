// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native outbound socket ownership, waits, and byte I/O.

const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const net = std.Io.net;
const Error = @import("contracts.zig").Error;
const win = @import("windows_abi.zig").win;

pub const Socket = if (builtin.os.tag == .windows) usize else sys.fd_t;

// ---- raw socket helpers (mirror acme_runner / server idiom) ------------------

pub fn connectAddr(addr: net.IpAddress, timeout_ms: u31) Error!Socket {
    if (comptime builtin.os.tag == .windows) return connectAddrWindows(addr, timeout_ms);
    const fd = try socketTcpNonblock(if (addr == .ip4) posix.AF.INET else posix.AF.INET6);
    errdefer closeFd(fd);
    const rc = switch (addr) {
        .ip4 => |a4| blk: {
            var sa = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, a4.port), .addr = @bitCast(a4.bytes) };
            break :blk sys.connect(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
        },
        .ip6 => |a6| blk: {
            var sa = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, a6.port), .addr = a6.bytes, .flowinfo = 0, .scope_id = a6.interface.index };
            break :blk sys.connect(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
        },
    };
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => try waitWritable(fd, timeout_ms),
        else => return error.ConnectFailed,
    }
    // Confirm the connect succeeded (SO_ERROR == 0).
    var err_val: i32 = 0;
    var err_len: sys.socklen_t = @sizeOf(i32);
    if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err_val), &err_len)) != .SUCCESS)
        return error.ConnectFailed;
    if (err_val != 0) return error.ConnectFailed;
    try setBlocking(fd);
    return fd;
}

fn connectAddrWindows(addr: net.IpAddress, timeout_ms: u31) Error!Socket {
    if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
    const family: i32 = switch (addr) {
        .ip4 => win.af_inet,
        .ip6 => win.af_inet6,
    };
    const fd = win.WSASocketW(family, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (fd == win.invalid_socket) return error.SocketUnavailable;
    errdefer _ = win.closesocket(fd);
    var nonblocking: u32 = 1;
    if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
    const connected = switch (addr) {
        .ip4 => |a4| blk: {
            const sa = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, a4.port), .addr = a4.bytes };
            break :blk win.connect(fd, &sa, @sizeOf(win.SockAddr4));
        },
        .ip6 => |a6| blk: {
            const sa = win.SockAddr6{ .family = win.af_inet6, .port = std.mem.nativeToBig(u16, a6.port), .addr = a6.bytes, .scope_id = a6.interface.index };
            break :blk win.connect(fd, &sa, @sizeOf(win.SockAddr6));
        },
    };
    if (connected != 0) {
        const err = win.WSAGetLastError();
        if (err != win.would_block and err != win.in_progress and err != win.already) return error.ConnectFailed;
        if (!try windowsWaitWritable(fd, @max(1, @min(timeout_ms, 60_000)))) return error.ConnectTimeout;
    }
    var socket_error: i32 = 0;
    var error_len: i32 = @sizeOf(i32);
    if (win.getsockopt(fd, win.sol_socket, win.so_error, &socket_error, &error_len) != 0 or
        socket_error != 0 or error_len != @sizeOf(i32)) return error.ConnectFailed;
    nonblocking = 0;
    if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
    return fd;
}

fn windowsWaitWritable(fd: usize, timeout_ms: u31) Error!bool {
    if (comptime builtin.os.tag != .windows) return error.ConnectFailed;
    var writes = win.FdSet{ .count = 1, .sockets = undefined };
    writes.sockets[0] = fd;
    var failures = win.FdSet{ .count = 1, .sockets = undefined };
    failures.sockets[0] = fd;
    var timeout = win.Timeval{ .seconds = @intCast(timeout_ms / 1000), .microseconds = @intCast((timeout_ms % 1000) * 1000) };
    // Winsock reports a failed nonblocking connect in exceptfds, not writefds.
    const ready = win.select(0, null, &writes, &failures, &timeout);
    if (ready < 0) return error.ConnectFailed;
    if (ready == 0) return false;
    if (failures.count != 0) return error.ConnectFailed;
    if (writes.count == 0) return error.ConnectFailed;
    return true;
}

fn waitWritable(fd: sys.fd_t, timeout_ms: u31) Error!void {
    // sys.pollfd/POLL/SOCK.* (not posix.*): these pair with the raw linux
    // syscalls; posix.* resolves to libc/ws2_32 on non-Linux (build-time only).
    var pfd = [_]sys.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    const rc = sys.poll(&pfd, 1, timeout_ms);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.ConnectFailed,
    }
    if (rc == 0) return error.ConnectTimeout;
    if (pfd[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) return error.ConnectFailed;
}

fn socketTcpNonblock(family: u32) Error!sys.fd_t {
    const rc = sys.socket(family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

pub fn udpSocket() Error!sys.fd_t {
    return udpSocketFamily(posix.AF.INET, false);
}

/// `nonblock` is for the dual A/AAAA poll. A blocking socket keeps
/// `SO_RCVTIMEO`, which is what a single query and the resolver tests use.
pub fn udpSocketFamily(family: u32, nonblock: bool) Error!sys.fd_t {
    // Socket type flags are comptime integers. A runtime `if` cannot produce
    // that type, so start from the blocking pair and add NONBLOCK after.
    var flags: u32 = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC;
    if (nonblock) flags |= posix.SOCK.NONBLOCK;
    const rc = sys.socket(family, flags, posix.IPPROTO.UDP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

pub fn setBlocking(fd: sys.fd_t) Error!void {
    if (comptime builtin.os.tag != .linux) {
        const old = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
        if (posix.errno(old) != .SUCCESS) return error.ConnectFailed;
        var flags: posix.O = @bitCast(@as(u32, @intCast(old)));
        flags.NONBLOCK = false;
        if (posix.errno(sys.fcntl(fd, posix.F.SETFL, @as(usize, @as(u32, @bitCast(flags))))) != .SUCCESS) return error.ConnectFailed;
        return;
    }
    const flags = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    _ = sys.fcntl(fd, posix.F.SETFL, flags & ~@as(usize, posix.SOCK.NONBLOCK));
}

pub fn setRecvTimeout(fd: Socket, timeout_ms: u31) Error!void {
    if (comptime builtin.os.tag == .windows) {
        const finite_ms: u32 = @max(1, @min(timeout_ms, 60_000));
        if (win.setsockopt(fd, win.sol_socket, win.so_rcvtimeo, &finite_ms, @sizeOf(u32)) != 0 or
            win.setsockopt(fd, win.sol_socket, win.so_sndtimeo, &finite_ms, @sizeOf(u32)) != 0)
            return error.RecvTimeout;
        return;
    }
    const finite_ms = if (builtin.os.tag == .linux) timeout_ms else @max(timeout_ms, 1);
    const tv = sys.timeval{ .sec = @intCast(finite_ms / 1000), .usec = @intCast((finite_ms % 1000) * 1000) };
    const recv_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(sys.timeval));
    const send_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, @ptrCast(&tv), @sizeOf(sys.timeval));
    if (comptime builtin.os.tag != .linux) {
        if (posix.errno(recv_rc) != .SUCCESS or posix.errno(send_rc) != .SUCCESS) return error.RecvTimeout;
    }
}

pub fn closeFd(fd: Socket) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(fd);
        return;
    }
    _ = sys.close(fd);
}

pub fn writeAll(fd: Socket, bytes: []const u8) Error!void {
    if (comptime builtin.os.tag == .windows) {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const amount: i32 = @intCast(@min(bytes.len - offset, std.math.maxInt(i32)));
            const sent = win.send(fd, bytes[offset..].ptr, amount, 0);
            if (sent > 0) {
                offset += @intCast(sent);
                continue;
            }
            if (sent == 0) return error.ConnectionClosed;
            switch (win.WSAGetLastError()) {
                win.interrupted => continue,
                win.timed_out, win.would_block => return error.RecvTimeout,
                else => return error.ConnectionClosed,
            }
        }
        return;
    }
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = if (comptime builtin.os.tag == .linux) sys.write(fd, bytes[off..].ptr, bytes.len - off) else sys.send(fd, bytes[off..].ptr, bytes.len - off, posix.MSG.NOSIGNAL);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.ConnectionClosed;
                off += n;
            },
            .INTR => {},
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}

pub fn readSome(fd: Socket, buf: []u8) Error!usize {
    if (comptime builtin.os.tag == .windows) {
        while (true) {
            const received = win.recv(fd, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(i32))), 0);
            if (received > 0) return @intCast(received);
            if (received == 0) return error.ConnectionClosed;
            switch (win.WSAGetLastError()) {
                win.interrupted => continue,
                win.timed_out, win.would_block => return error.RecvTimeout,
                else => return error.ConnectionClosed,
            }
        }
    }
    while (true) {
        const rc = sys.read(fd, buf.ptr, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                // read()==0 is EOF (peer FIN). Surface it as ConnectionClosed so
                // every caller terminates — notably the TLS handshake loop, which
                // otherwise feeds empty -> need_more -> reads EOF again forever,
                // pegging a core and leaking the socket in CLOSE-WAIT.
                if (n == 0) return error.ConnectionClosed;
                return n;
            },
            .INTR => continue,
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}

pub fn readSmallFile(path: [*:0]const u8, buf: []u8) ![]u8 {
    const rc = sys.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = builtin.os.tag != .linux }, @as(posix.mode_t, 0));
    if (posix.errno(rc) != .SUCCESS) return error.NoNameservers;
    const fd: sys.fd_t = @intCast(rc);
    defer closeFd(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const r = sys.read(fd, buf[total..].ptr, buf.len - total);
        switch (posix.errno(r)) {
            .SUCCESS => {
                const n: usize = @intCast(r);
                if (n == 0) break;
                total += n;
            },
            .INTR => continue,
            else => return error.NoNameservers,
        }
    }
    return buf[0..total];
}

pub fn osEntropy(buf: []u8) void {
    if (comptime builtin.os.tag != .linux) {
        sys.arc4random_buf(buf.ptr, buf.len);
        return;
    }
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = sys.getrandom(buf.ptr + filled, buf.len - filled, 0);
        if (posix.errno(rc) != .SUCCESS) {
            for (buf[filled..]) |*b| b.* = 0x55; // query IDs are not security-critical
            return;
        }
        filled += @intCast(rc);
    }
}
