// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native POSIX operations used by the shared daemon lifecycle. Linux retains
//! raw syscalls; BSD uses the target ABI. Errors never cross an ABI boundary
//! as numeric Linux errno values.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;

pub const Fd = posix.fd_t;
pub const AddressStorage = posix.sockaddr.storage;
pub const AddressLength = posix.socklen_t;
pub const Error = error{ Interrupted, WouldBlock, PermissionDenied, InvalidDescriptor, Unexpected };

fn check(rc: anytype) Error!void {
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INTR => return error.Interrupted,
        .AGAIN => return error.WouldBlock,
        .ACCES, .PERM => return error.PermissionDenied,
        .BADF => return error.InvalidDescriptor,
        else => return error.Unexpected,
    }
}

/// Native Helix temporarily holds received and normalization copies alongside
/// canonical descriptor numbers. Use the existing per-process hard allowance;
/// never change the administrator's hard limit or a system-wide setting.
pub fn raiseOpenBsdFdAllowance() Error!void {
    if (comptime builtin.os.tag != .openbsd) return;
    var limit: sys.rlimit = undefined;
    try check(sys.getrlimit(.NOFILE, &limit));
    if (limit.cur < limit.max) {
        limit.cur = limit.max;
        try check(sys.setrlimit(.NOFILE, &limit));
    }
}

pub fn read(fd: Fd, bytes: []u8) Error!usize {
    const rc = sys.read(fd, bytes.ptr, bytes.len);
    try check(rc);
    return @intCast(rc);
}

pub fn write(fd: Fd, bytes: []const u8) Error!usize {
    const rc = sys.write(fd, bytes.ptr, bytes.len);
    try check(rc);
    return @intCast(rc);
}

pub fn pread(fd: Fd, bytes: []u8, offset: u64) Error!usize {
    const rc = sys.pread(fd, bytes.ptr, bytes.len, @intCast(offset));
    try check(rc);
    return @intCast(rc);
}

pub fn close(fd: Fd) void {
    if (fd >= 0) _ = sys.close(fd);
}

pub fn duplicate(fd: Fd) Error!Fd {
    const rc = sys.dup(fd);
    try check(rc);
    return @intCast(rc);
}

pub fn setCloexec(fd: Fd, enabled: bool) Error!void {
    const old = sys.fcntl(fd, posix.F.GETFD, @as(i32, 0));
    try check(old);
    const flags: usize = @intCast(old);
    const next = if (enabled) flags | posix.FD_CLOEXEC else flags & ~@as(usize, posix.FD_CLOEXEC);
    try check(sys.fcntl(fd, posix.F.SETFD, next));
}

pub fn setNonblocking(fd: Fd) Error!void {
    const old = sys.fcntl(fd, posix.F.GETFL, @as(i32, 0));
    try check(old);
    var flags: posix.O = @bitCast(@as(u32, @intCast(old)));
    flags.NONBLOCK = true;
    try check(sys.fcntl(fd, posix.F.SETFL, @as(usize, @as(u32, @bitCast(flags)))));
}

pub fn fdValid(fd: Fd) bool {
    if (fd < 0) return false;
    return posix.errno(sys.fcntl(fd, posix.F.GETFD, @as(i32, 0))) == .SUCCESS;
}

pub fn socketType(fd: Fd) Error!u32 {
    var value: u32 = 0;
    var len: AddressLength = @sizeOf(u32);
    try check(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.TYPE, @ptrCast(&value), &len));
    if (len != @sizeOf(u32)) return error.Unexpected;
    return value;
}

pub fn getpeername(fd: Fd, addr: *AddressStorage, len: *AddressLength) Error!void {
    try check(sys.getpeername(fd, @ptrCast(addr), len));
}

pub fn shutdownBoth(fd: Fd) void {
    _ = sys.shutdown(fd, posix.SHUT.RDWR);
}

pub fn sleepMillis(ms: u64) void {
    var remaining: sys.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast(ms % 1000 * std.time.ns_per_ms) };
    while (true) {
        var next: sys.timespec = undefined;
        const rc = sys.nanosleep(&remaining, &next);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => remaining = next,
            else => return,
        }
    }
}

pub fn openReadZ(path: [*:0]const u8) Error!Fd {
    const rc = sys.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, @as(posix.mode_t, 0));
    try check(rc);
    return @intCast(rc);
}

pub fn openTruncateZ(path: [*:0]const u8, mode: posix.mode_t) Error!Fd {
    const rc = sys.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, mode);
    try check(rc);
    return @intCast(rc);
}

test "native runtime descriptors retain CLOEXEC and reject retired handles" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const fd = try openReadZ("/dev/null");
    defer close(fd);
    var buffer: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try read(fd, &buffer));
    try std.testing.expectEqual(@as(usize, 0), try pread(fd, &buffer, 0));
    try std.testing.expectError(error.InvalidDescriptor, write(fd, "x"));
    try setNonblocking(fd);
    sleepMillis(1);
    const copy = try duplicate(fd);
    try std.testing.expect(fdValid(copy));
    try setCloexec(copy, true);
    const flags = sys.fcntl(copy, posix.F.GETFD, @as(i32, 0));
    try check(flags);
    try std.testing.expect(@as(usize, @intCast(flags)) & posix.FD_CLOEXEC != 0);
    close(copy);
    try std.testing.expect(!fdValid(copy));
    try std.testing.expectError(error.InvalidDescriptor, setCloexec(copy, true));
    try std.testing.expectError(error.InvalidDescriptor, socketType(copy));
    var pair: [2]Fd = undefined;
    try check(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &pair));
    defer for (pair) |socket| close(socket);
    try std.testing.expectEqual(@as(u32, posix.SOCK.STREAM), try socketType(pair[0]));
    var address: AddressStorage = undefined;
    var address_len: AddressLength = @sizeOf(AddressStorage);
    try getpeername(pair[0], &address, &address_len);
    try std.testing.expectEqual(@as(usize, 1), try write(pair[0], "x"));
    try std.testing.expectEqual(@as(usize, 1), try read(pair[1], &buffer));
    shutdownBoth(pair[0]);
    try std.testing.expectEqual(@as(usize, 0), try read(pair[1], &buffer));
    std.mem.doNotOptimizeAway(&openTruncateZ);
}
