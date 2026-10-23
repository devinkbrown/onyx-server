// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native SMTP socket ownership, readiness, and byte I/O.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const net = std.Io.net;
const smtp_client = @import("../../proto/smtp_client.zig");
const os_runtime = @import("../os_runtime.zig");
const win = @import("windows_abi.zig").win;

pub const Socket = if (builtin.os.tag == .windows) usize else linux.fd_t;

const SocketError = error{ SocketUnavailable, ConnectFailed, ConnectTimeout, ConnectionClosed, RecvTimeout };

pub fn connectAddr(addr: net.IpAddress, timeout_ms: u31) SocketError!Socket {
    if (comptime builtin.os.tag == .windows) return connectAddrWindows(addr, timeout_ms);
    if (comptime @import("builtin").os.tag == .openbsd) return @import("../native_network.zig").connect(addr, timeout_ms);
    const a4 = switch (addr) {
        .ip4 => |x| x,
        .ip6 => return error.ConnectFailed,
    };
    const fd = try socketTcpNonblock();
    errdefer closeFd(fd);
    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, a4.port), .addr = @bitCast(a4.bytes) };
    switch (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)))) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => try waitWritable(fd, timeout_ms),
        else => return error.ConnectFailed,
    }
    var err_val: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    if (posix.errno(linux.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err_val), &err_len)) != .SUCCESS)
        return error.ConnectFailed;
    if (err_val != 0) return error.ConnectFailed;
    setBlocking(fd);
    return fd;
}

fn connectAddrWindows(addr: net.IpAddress, timeout_ms: u31) SocketError!Socket {
    if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
    const family: i32 = switch (addr) {
        .ip4 => win.af_inet,
        .ip6 => win.af_inet6,
    };
    const fd = win.WSASocketW(family, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (fd == win.invalid_socket) return error.SocketUnavailable;
    errdefer _ = win.closesocket(fd);
    var nonblocking: u32 = 1;
    if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) return error.ConnectFailed;
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
    var readiness: WindowsConnectReady = .writable;
    if (connected != 0) {
        const err = win.WSAGetLastError();
        if (err != win.would_block and err != win.in_progress and err != win.already) return error.ConnectFailed;
        readiness = try windowsWaitConnect(fd, @max(1, @min(timeout_ms, 60_000)));
        if (readiness == .timed_out) return error.ConnectTimeout;
    }
    var socket_error: i32 = 0;
    var error_len: i32 = @sizeOf(i32);
    if (win.getsockopt(fd, win.sol_socket, win.so_error, &socket_error, &error_len) != 0 or
        readiness == .failed or socket_error != 0 or error_len != @sizeOf(i32)) return error.ConnectFailed;
    nonblocking = 0;
    if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
    return fd;
}

const WindowsConnectReady = enum { writable, failed, timed_out };

fn windowsWaitConnect(fd: usize, timeout_ms: u31) SocketError!WindowsConnectReady {
    if (comptime builtin.os.tag != .windows) return error.ConnectFailed;
    var writes = win.FdSet{ .count = 1, .sockets = undefined };
    writes.sockets[0] = fd;
    var failures = win.FdSet{ .count = 1, .sockets = undefined };
    failures.sockets[0] = fd;
    var timeout = win.Timeval{ .seconds = @intCast(timeout_ms / 1000), .microseconds = @intCast((timeout_ms % 1000) * 1000) };
    // Winsock reports successful nonblocking connects in writefds and failed
    // connects in exceptfds. Inspect SO_ERROR after either completion.
    const ready = win.select(0, null, &writes, &failures, &timeout);
    if (ready < 0) return error.ConnectFailed;
    if (ready == 0) return .timed_out;
    if (failures.count != 0) return .failed;
    if (writes.count != 0) return .writable;
    return error.ConnectFailed;
}

fn waitWritable(fd: linux.fd_t, timeout_ms: u31) SocketError!void {
    // Use linux.pollfd/POLL (not posix.*): these pair with the raw linux.poll
    // syscall and posix.* is the libc/ws2_32 struct on non-Linux (build-time only).
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    const rc = linux.poll(&pfd, 1, timeout_ms);
    if (posix.errno(rc) != .SUCCESS) return error.ConnectFailed;
    if (rc == 0) return error.ConnectTimeout;
    if (pfd[0].revents & (linux.POLL.ERR | linux.POLL.HUP) != 0) return error.ConnectFailed;
}

fn socketTcpNonblock() SocketError!linux.fd_t {
    const rc = linux.socket(posix.AF.INET, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn setBlocking(fd: linux.fd_t) void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    _ = linux.fcntl(fd, linux.F.SETFL, flags & ~@as(usize, linux.SOCK.NONBLOCK));
}

pub fn setRecvTimeout(fd: Socket, timeout_ms: u31) SocketError!void {
    if (comptime builtin.os.tag == .windows) {
        const finite_ms: u32 = @max(1, @min(timeout_ms, 60_000));
        if (win.setsockopt(fd, win.sol_socket, win.so_rcvtimeo, &finite_ms, @sizeOf(u32)) != 0 or
            win.setsockopt(fd, win.sol_socket, win.so_sndtimeo, &finite_ms, @sizeOf(u32)) != 0)
            return error.RecvTimeout;
        return;
    }
    if (comptime @import("builtin").os.tag == .openbsd) return @import("../native_network.zig").setTimeout(fd, timeout_ms);
    const tv = linux.timeval{ .sec = @divTrunc(timeout_ms, 1000), .usec = @as(i64, @intCast(timeout_ms % 1000)) * 1000 };
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
}

pub fn closeFd(fd: Socket) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(fd);
        return;
    }
    if (comptime @import("builtin").os.tag != .linux) return @import("../os_runtime.zig").close(fd);
    _ = linux.close(fd);
}

pub fn writeAll(fd: Socket, bytes: []const u8) SocketError!void {
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
    if (comptime @import("builtin").os.tag == .openbsd) return @import("../native_network.zig").writeAll(fd, bytes);
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
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

pub fn readSome(fd: Socket, buf: []u8) SocketError!usize {
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
    if (comptime @import("builtin").os.tag == .openbsd) return @import("../native_network.zig").readSome(fd, buf);
    while (true) {
        const rc = linux.read(fd, buf.ptr, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.ConnectionClosed;
                return n;
            },
            .INTR => continue,
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}
