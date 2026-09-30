// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native POSIX worker sockets with checked finite I/O and connect timeouts.
const std = @import("std");
const posix = std.posix;
const sys = posix.system;
const runtime = @import("os_runtime.zig");
const platform = @import("../substrate/platform.zig");
pub const Error = error{ SocketUnavailable, ConnectFailed, ConnectTimeout, ConnectionClosed, RecvTimeout };
pub fn socket(family: u32, datagram: bool, nonblocking: bool) Error!i32 {
    const flags = (if (datagram) @as(u32, posix.SOCK.DGRAM) else @as(u32, posix.SOCK.STREAM)) | posix.SOCK.CLOEXEC | (if (nonblocking) posix.SOCK.NONBLOCK else @as(u32, 0));
    const rc = sys.socket(family, flags, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
    return @intCast(rc);
}
pub fn connectSocket(fd: i32, address: std.Io.net.IpAddress) Error!void {
    const rc = switch (address) {
        .ip4 => |a| blk: {
            var native: posix.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes) };
            break :blk sys.connect(fd, @ptrCast(&native), @sizeOf(@TypeOf(native)));
        },
        .ip6 => |a| blk: {
            var native: posix.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = a.bytes, .flowinfo = 0, .scope_id = a.interface.index };
            break :blk sys.connect(fd, @ptrCast(&native), @sizeOf(@TypeOf(native)));
        },
    };
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => return error.ConnectTimeout,
        else => return error.ConnectFailed,
    }
}
pub fn connect(address: std.Io.net.IpAddress, timeout_ms: u31) Error!i32 {
    const fd = try socket(if (address == .ip4) posix.AF.INET else posix.AF.INET6, false, true);
    errdefer runtime.close(fd);
    connectSocket(fd, address) catch |err| switch (err) {
        error.ConnectTimeout => try waitWritable(fd, timeout_ms),
        else => return err,
    };
    var failure: c_int = 0;
    var length: posix.socklen_t = @sizeOf(c_int);
    if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&failure), &length)) != .SUCCESS or length != @sizeOf(c_int) or failure != 0) return error.ConnectFailed;
    try setBlocking(fd);
    try setTimeout(fd, timeout_ms);
    return fd;
}
pub fn setBlocking(fd: i32) Error!void {
    const old_flags = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (posix.errno(old_flags) != .SUCCESS) return error.ConnectFailed;
    var options: posix.O = @bitCast(@as(u32, @intCast(old_flags)));
    options.NONBLOCK = false;
    if (posix.errno(sys.fcntl(fd, posix.F.SETFL, @as(c_int, @intCast(@as(u32, @bitCast(options)))))) != .SUCCESS) return error.ConnectFailed;
}
pub fn waitWritable(fd: i32, timeout_ms: u31) Error!void {
    const deadline = platform.monotonicMillis() + timeout_ms;
    var polls = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    while (true) {
        const left = deadline - platform.monotonicMillis();
        if (left <= 0) return error.ConnectTimeout;
        const rc = sys.poll(&polls, 1, @intCast(@min(left, std.math.maxInt(c_int))));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.ConnectTimeout;
                if ((polls[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0 or (polls[0].revents & posix.POLL.OUT) == 0) return error.ConnectFailed;
                return;
            },
            .INTR => continue,
            else => return error.ConnectFailed,
        }
    }
}
pub fn setTimeout(fd: i32, ms: u31) Error!void {
    if (ms == 0) return error.RecvTimeout;
    const value: posix.timeval = .{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    for ([_]u32{ posix.SO.RCVTIMEO, posix.SO.SNDTIMEO }) |option| {
        if (posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, option, @ptrCast(&value), @sizeOf(@TypeOf(value)))) != .SUCCESS) return error.RecvTimeout;
    }
}
pub fn writeAll(fd: i32, bytes: []const u8) Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = sys.send(fd, bytes[offset..].ptr, bytes.len - offset, posix.MSG.NOSIGNAL);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.ConnectionClosed;
                offset += @intCast(rc);
            },
            .INTR => continue,
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}
pub fn readSome(fd: i32, bytes: []u8) Error!usize {
    while (true) {
        const rc = sys.read(fd, bytes.ptr, bytes.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.ConnectionClosed;
                return @intCast(rc);
            },
            .INTR => continue,
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}

test "OpenBSD native worker TCP connects both families and bounds idle receives" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    for ([_][]const u8{ "127.0.0.1", "::1" }) |host| {
        const listener = try @import("reuseport.zig").createOpenBsdListener(host, 0, 8, false);
        defer runtime.close(listener);
        var address: posix.sockaddr.storage = undefined;
        var length: posix.socklen_t = @sizeOf(@TypeOf(address));
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(listener, @ptrCast(&address), &length)));
        const port = if (host.len == 3) std.mem.bigToNative(u16, @as(*const posix.sockaddr.in6, @ptrCast(&address)).port) else std.mem.bigToNative(u16, @as(*const posix.sockaddr.in, @ptrCast(&address)).port);
        const target = try std.Io.net.IpAddress.parse(host, port);
        const client = try connect(target, 1000);
        defer runtime.close(client);
        var ready = [_]posix.pollfd{.{ .fd = listener, .events = posix.POLL.IN, .revents = 0 }};
        try std.testing.expectEqual(@as(c_int, 1), sys.poll(&ready, 1, 1000));
        const accepted = sys.accept(listener, null, null);
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(accepted));
        const server: i32 = @intCast(accepted);
        defer runtime.close(server);
        try setBlocking(server);
        try setTimeout(server, 1000);
        try writeAll(client, "SMTP ACME native");
        var buffer: [64]u8 = undefined;
        const n = try readSome(server, &buffer);
        try std.testing.expectEqualStrings("SMTP ACME native", buffer[0..n]);
        try setTimeout(server, 30);
        try std.testing.expectError(error.RecvTimeout, readSome(server, &buffer));
        try std.testing.expectError(error.RecvTimeout, setTimeout(-1, 30));
    }
}
