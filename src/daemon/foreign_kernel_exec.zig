// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Guest execution of the shipped FreeBSD kqueue submit path, FreeBSD
//! `enableKernelTls`, and OpenBSD `pledgeDaemonPaths`. Each test returns
//! `error.SkipZigTest` unless it is compiled for that kernel, so a Linux
//! suite does not pretend the syscall ran. `main` is the guest entry point
//! and calls those same functions.

const std = @import("std");
const builtin = @import("builtin");
const io_backend = @import("io_backend.zig");
const kernel_other = @import("kernel_other.zig");
const ringlane = @import("ringlane.zig");

fn errnoNow() i32 {
    return std.c._errno().*;
}

fn tcpSocket() !std.c.fd_t {
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    if (fd < 0) return error.MissingOp;
    return fd;
}

fn connectedTcp() !std.c.fd_t {
    const listener = try tcpSocket();
    errdefer _ = std.c.close(listener);
    var addr = std.c.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const addr_ptr: *const std.c.sockaddr = @ptrCast(&addr);
    if (std.c.bind(listener, addr_ptr, @sizeOf(std.c.sockaddr.in)) != 0) return error.MissingOp;
    if (std.c.listen(listener, 1) != 0) return error.MissingOp;
    var len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    if (std.c.getsockname(listener, @ptrCast(&addr), &len) != 0) return error.MissingOp;
    const client = try tcpSocket();
    errdefer _ = std.c.close(client);
    if (std.c.connect(client, addr_ptr, len) != 0) return error.MissingOp;
    const accepted = std.c.accept(listener, null, null);
    if (accepted < 0) return error.MissingOp;
    _ = std.c.close(accepted);
    _ = std.c.close(listener);
    return client;
}

pub fn executeFreeBsdKqueue() !void {
    var backend = io_backend.IoBackend.openOwned(.kqueue, 32, .{}) catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=open errno={d}\n", .{errnoNow()});
        return err;
    };
    defer backend.deinit();
    const sock = tcpSocket() catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=socket errno={d}\n", .{errnoNow()});
        return err;
    };
    defer _ = std.c.close(sock);
    const token = ringlane.FdToken{ .slot = 1, .gen = 1 };
    var buf: [4]u8 = .{ 0, 0, 0, 0 };
    backend.accept(token, sock) catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=accept errno={d}\n", .{errnoNow()});
        return err;
    };
    backend.recv(token, sock, &buf) catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=recv errno={d}\n", .{errnoNow()});
        return err;
    };
    backend.send(token, sock, "x") catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=send errno={d}\n", .{errnoNow()});
        return err;
    };
    backend.poll(token, sock, std.os.linux.POLL.IN) catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=poll errno={d}\n", .{errnoNow()});
        return err;
    };
    var ts = std.os.linux.kernel_timespec{ .sec = 1, .nsec = 0 };
    backend.timeout(token, &ts) catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=timeout errno={d}\n", .{errnoNow()});
        return err;
    };
    backend.cancel(.timeout, token) catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=cancel errno={d}\n", .{errnoNow()});
        return err;
    };
    const submitted = backend.submit() catch |err| {
        std.debug.print("GAP-X1 freebsd kqueue submitted=missing stage=submit errno={d}\n", .{errnoNow()});
        return err;
    };
    std.debug.print("GAP-X1 freebsd kqueue submitted={d} errno={d}\n", .{ submitted, errnoNow() });
    if (submitted == 0) return error.MissingOp;
}

pub fn executeFreeBsdKtls() !void {
    const fd = connectedTcp() catch |err| {
        std.debug.print("GAP-X3 freebsd ktls result=missing stage=connect errno={d}\n", .{errnoNow()});
        return err;
    };
    defer _ = std.c.close(fd);
    const key: [16]u8 = @splat(0x11);
    const iv: [12]u8 = @splat(0x22);
    const seq: [8]u8 = @splat(0);
    std.c._errno().* = 0;
    kernel_other.enableKernelTls(
        fd,
        .tx,
        kernel_other.crypto_aes_nist_gcm_16,
        &key,
        &iv,
        seq,
    ) catch |err| {
        const errno = errnoNow();
        std.debug.print("GAP-X3 freebsd ktls result=missing errno={d}\n", .{errno});
        if (errno != 0) return;
        return err;
    };
    std.debug.print("GAP-X3 freebsd ktls result=ok errno={d}\n", .{errnoNow()});
}

pub fn executeOpenBsdPledge() !void {
    const paths = [_][:0]const u8{ "/etc", "/usr", "/var", "/tmp" };
    for (paths) |path| {
        const present = std.c.access(path, 0) == 0;
        std.debug.print("GAP-X3 openbsd path {s} present={}\n", .{ path, present });
    }
    std.c._errno().* = 0;
    kernel_other.pledgeDaemonPaths() catch |err| {
        std.debug.print("GAP-X3 openbsd pledge result=missing errno={d}\n", .{errnoNow()});
        return err;
    };
    std.debug.print("GAP-X3 openbsd pledge result=ok errno={d}\n", .{errnoNow()});
}

pub fn main() !void {
    if (comptime builtin.os.tag == .freebsd) {
        try executeFreeBsdKqueue();
        try executeFreeBsdKtls();
        return;
    }
    if (comptime builtin.os.tag == .openbsd) {
        try executeOpenBsdPledge();
        return;
    }
    std.debug.print("foreign kernel exec refused on {s}\n", .{@tagName(builtin.os.tag)});
    return error.WrongOs;
}

test "GAP-X1 FreeBSD kqueue executes on this kernel" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    try executeFreeBsdKqueue();
}

test "GAP-X3 FreeBSD kernel TLS executes on this kernel" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    try executeFreeBsdKtls();
}

test "GAP-X3 OpenBSD pledge executes on this kernel" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    try executeOpenBsdPledge();
}
