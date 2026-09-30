// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Guest execution of the shipped FreeBSD kqueue submit path, FreeBSD
//! `enableKernelTls`, OpenBSD `pledgeDaemonPaths`, and the Windows IOCP
//! submit path. Windows open loads the RIO table; the guest then calls
//! `dequeueRegistered` on that same table. Each test returns
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

pub fn executeBsdKqueueServe() !void {
    const listener = io_backend.listenTcp("127.0.0.1", 0) catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted=missing stage=listen errno={d}\n", .{ @tagName(builtin.os.tag), errnoNow() });
        return err;
    };
    defer io_backend.closeSocket(listener.fd);
    var backend = io_backend.IoBackend.openOwned(.kqueue, 32, .{}) catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted=missing stage=open errno={d}\n", .{ @tagName(builtin.os.tag), errnoNow() });
        return err;
    };
    defer backend.deinit();
    const listen_token = ringlane.FdToken{ .slot = 0, .gen = 1 };
    backend.accept(listen_token, listener.fd) catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted=missing stage=accept errno={d}\n", .{ @tagName(builtin.os.tag), errnoNow() });
        return err;
    };
    const submitted = backend.submit() catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted=missing stage=submit errno={d}\n", .{ @tagName(builtin.os.tag), errnoNow() });
        return err;
    };
    const client = tcpSocket() catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted=missing stage=client errno={d}\n", .{ @tagName(builtin.os.tag), submitted, errnoNow() });
        return err;
    };
    defer _ = std.c.close(client);
    var addr = std.c.sockaddr.in{
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const addr_ptr: *const std.c.sockaddr = @ptrCast(&addr);
    if (std.c.connect(client, addr_ptr, @intCast(@sizeOf(std.c.sockaddr.in))) != 0) {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted=missing stage=connect errno={d}\n", .{ @tagName(builtin.os.tag), submitted, errnoNow() });
        return error.MissingOp;
    }
    const ping = "PING x\r\n";
    if (std.c.send(client, ping, ping.len, 0) < 0) {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted=missing stage=send errno={d}\n", .{ @tagName(builtin.os.tag), submitted, errnoNow() });
        return error.MissingOp;
    }
    var evs: [4]io_backend.Reaped = undefined;
    const n_accept = backend.reap(&evs, 1000) catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted=missing stage=reap errno={d}\n", .{ @tagName(builtin.os.tag), submitted, errnoNow() });
        return err;
    };
    var accepted: i32 = -1;
    var i: usize = 0;
    while (i < n_accept) : (i += 1) {
        if (evs[i].op == .accept and evs[i].result >= 0) accepted = evs[i].result;
    }
    if (accepted < 0) {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted={d} bytes=0 errno={d}\n", .{ @tagName(builtin.os.tag), submitted, accepted, errnoNow() });
        return error.MissingOp;
    }
    defer io_backend.closeSocket(accepted);
    var buf: [64]u8 = @splat(0);
    const recv_token = ringlane.FdToken{ .slot = 1, .gen = 1 };
    backend.recv(recv_token, accepted, &buf) catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted={d} bytes=missing stage=recv errno={d}\n", .{ @tagName(builtin.os.tag), submitted, accepted, errnoNow() });
        return err;
    };
    _ = backend.submit() catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted={d} bytes=missing stage=recv-submit errno={d}\n", .{ @tagName(builtin.os.tag), submitted, accepted, errnoNow() });
        return err;
    };
    const n_recv = backend.reap(&evs, 1000) catch |err| {
        std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted={d} bytes=missing stage=recv-reap errno={d}\n", .{ @tagName(builtin.os.tag), submitted, accepted, errnoNow() });
        return err;
    };
    var bytes: i32 = 0;
    i = 0;
    while (i < n_recv) : (i += 1) {
        if (evs[i].op == .recv) bytes = evs[i].result;
    }
    std.debug.print("GAP-X1 {s} kqueue submitted={d} accepted={d} bytes={d} errno={d}\n", .{ @tagName(builtin.os.tag), submitted, accepted, bytes, errnoNow() });
    if (bytes <= 0) return error.MissingOp;
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

const WinSock = struct {
    const SockAddrIn = extern struct {
        family: u16,
        port: u16,
        addr: u32,
        zero: [8]u8,
    };

    extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(address_family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn bind(s: usize, addr: *const SockAddrIn, namelen: i32) callconv(.winapi) i32;
    extern "ws2_32" fn listen(s: usize, backlog: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(s: usize, addr: *SockAddrIn, namelen: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn connect(s: usize, addr: *const SockAddrIn, namelen: i32) callconv(.winapi) i32;
    extern "ws2_32" fn accept(s: usize, addr: ?*anyopaque, namelen: ?*i32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(s: usize) callconv(.winapi) i32;
};

const WinCom = struct {
    handle: ?*anyopaque = null,

    extern "kernel32" fn CreateFileA(name: [*:0]const u8, access: u32, share: u32, security: ?*anyopaque, disposition: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) *anyopaque;
    extern "kernel32" fn WriteFile(handle: *anyopaque, buffer: [*]const u8, len: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn CloseHandle(handle: *anyopaque) callconv(.winapi) i32;

    fn open() WinCom {
        const invalid: *anyopaque = @ptrFromInt(std.math.maxInt(usize));
        // WinPE's X: ramdisk is writable. COM1 produced no bytes on the
        // first boot, so the witness file is the record the screen types back.
        const handle = CreateFileA("X:\\onyx-out.txt", 4, 1, null, 4, 0x80, null);
        if (handle == invalid) return .{};
        return .{ .handle = handle };
    }

    fn write(self: WinCom, text: []const u8) void {
        std.debug.print("{s}\n", .{text});
        const handle = self.handle orelse return;
        var scratch: [160]u8 = undefined;
        if (text.len + 2 > scratch.len) return;
        @memcpy(scratch[0..text.len], text);
        scratch[text.len] = '\r';
        scratch[text.len + 1] = '\n';
        var wrote: u32 = 0;
        _ = WriteFile(handle, scratch[0 .. text.len + 2].ptr, @intCast(text.len + 2), &wrote, null);
    }

    fn close(self: *WinCom) void {
        if (self.handle) |handle| {
            _ = CloseHandle(handle);
            self.handle = null;
        }
    }
};

fn winSocket() !usize {
    const sock = WinSock.WSASocketW(
        io_backend.wsa_af_inet,
        io_backend.wsa_sock_stream,
        io_backend.wsa_ipproto_tcp,
        null,
        0,
        io_backend.wsa_flag_overlapped,
    );
    if (sock == 0 or sock == std.math.maxInt(usize)) return error.MissingOp;
    return sock;
}

fn socketFd(sock: usize) !std.os.linux.fd_t {
    const limit: usize = @intCast(std.math.maxInt(std.os.linux.fd_t));
    if (sock == 0 or sock > limit) return error.MissingOp;
    return @intCast(sock);
}

fn windowsPair() !struct { listener: usize, client: usize, accepted: usize } {
    var startup: [408]u8 = @splat(0);
    if (WinSock.WSAStartup(0x0202, &startup) != 0) return error.MissingOp;
    const listener = try winSocket();
    errdefer _ = WinSock.closesocket(listener);
    var addr = WinSock.SockAddrIn{
        .family = 2,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = @splat(0),
    };
    if (WinSock.bind(listener, &addr, @sizeOf(WinSock.SockAddrIn)) != 0) return error.MissingOp;
    if (WinSock.listen(listener, 1) != 0) return error.MissingOp;
    var len: i32 = @sizeOf(WinSock.SockAddrIn);
    if (WinSock.getsockname(listener, &addr, &len) != 0) return error.MissingOp;
    const client = try winSocket();
    errdefer _ = WinSock.closesocket(client);
    if (WinSock.connect(client, &addr, len) != 0) return error.MissingOp;
    const accepted = WinSock.accept(listener, null, null);
    if (accepted == 0 or accepted == std.math.maxInt(usize)) return error.MissingOp;
    return .{ .listener = listener, .client = client, .accepted = accepted };
}

pub fn executeWindowsIocp() !void {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var com = WinCom.open();
    defer com.close();
    // The completion port and the receive buffer stay mapped until process
    // exit. A pending AFD request writes them after submit returns.
    var backend = io_backend.IoBackend.openOwned(.iocp, 32, .{}) catch |err| {
        com.write("GAP-X3 windows rio result=missing stage=open");
        com.write("GUEST_EXIT:1");
        return err;
    };
    com.write("GAP-X3 windows rio result=ok");
    const witness = backend.dequeueRegistered();
    var dequeue_ok = false;
    var line_buf: [96]u8 = undefined;
    if (witness.ok) {
        dequeue_ok = true;
        if (std.fmt.bufPrint(&line_buf, "GAP-X3 windows rio dequeue={d} bytes={d} status={d}", .{ witness.count, witness.bytes, witness.status })) |text| {
            com.write(text);
        } else |_| com.write("GAP-X3 windows rio dequeue=fmt");
    } else if (std.fmt.bufPrint(&line_buf, "GAP-X3 windows rio dequeue=fail stage={s} errno={d} bytes={d}", .{ witness.stage, witness.errno, witness.bytes })) |text| {
        com.write(text);
    } else |_| com.write("GAP-X3 windows rio dequeue=fmt");
    const pair = windowsPair() catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=socket");
        com.write("GUEST_EXIT:1");
        return err;
    };
    const listen_fd = socketFd(pair.listener) catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=fd");
        com.write("GUEST_EXIT:1");
        return err;
    };
    const peer_fd = socketFd(pair.accepted) catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=fd");
        com.write("GUEST_EXIT:1");
        return err;
    };
    const token = ringlane.FdToken{ .slot = 1, .gen = 1 };
    const buf = std.heap.page_allocator.alloc(u8, 4) catch return error.OutOfMemory;
    @memset(buf, 0);
    backend.accept(token, listen_fd) catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=accept");
        com.write("GUEST_EXIT:1");
        return err;
    };
    backend.recv(token, peer_fd, buf) catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=recv");
        com.write("GUEST_EXIT:1");
        return err;
    };
    backend.send(token, peer_fd, "x") catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=send");
        com.write("GUEST_EXIT:1");
        return err;
    };
    backend.poll(token, peer_fd, std.os.linux.POLL.IN) catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=poll");
        com.write("GUEST_EXIT:1");
        return err;
    };
    var ts = std.os.linux.kernel_timespec{ .sec = 1, .nsec = 0 };
    backend.timeout(token, &ts) catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=timeout");
        com.write("GUEST_EXIT:1");
        return err;
    };
    backend.cancel(.timeout, token) catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=cancel");
        com.write("GUEST_EXIT:1");
        return err;
    };
    const submitted = backend.submit() catch |err| {
        com.write("GAP-X1 windows iocp submitted=missing stage=submit");
        com.write("GUEST_EXIT:1");
        return err;
    };
    if (std.fmt.bufPrint(&line_buf, "GAP-X1 windows iocp submitted={d}", .{submitted})) |text| {
        com.write(text);
    } else |_| {
        com.write("GAP-X1 windows iocp submitted=fmt");
    }
    _ = WinSock.closesocket(pair.listener);
    _ = WinSock.closesocket(pair.client);
    _ = WinSock.closesocket(pair.accepted);
    if (submitted == 0 or !dequeue_ok) {
        com.write("GUEST_EXIT:1");
        return error.MissingOp;
    }
    com.write("GUEST_EXIT:0");
    // `backend` and `buf` are deliberately not freed. A pending AFD request
    // can still write them, and process exit reclaims the pages.
}

pub fn main() !void {
    if (comptime builtin.os.tag == .freebsd) {
        try executeFreeBsdKqueue();
        try executeFreeBsdKtls();
        return;
    }
    if (comptime builtin.os.tag == .openbsd) {
        try executeBsdKqueueServe();
        try executeOpenBsdPledge();
        return;
    }
    if (comptime builtin.os.tag == .netbsd or builtin.os.tag == .dragonfly) {
        try executeBsdKqueueServe();
        return;
    }
    if (comptime builtin.os.tag == .windows) {
        // The witness lines are the result. Returning the error also prints
        // a stack, which hides those lines on the WinPE console.
        executeWindowsIocp() catch {};
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
    // Pledge/unveil is irreversible. Only the child may confine itself; a
    // second fork proves the shared test runner retained its proc capability.
    for (0..2) |attempt| {
        const child = std.c.fork();
        try std.testing.expect(child >= 0);
        if (child == 0) {
            if (attempt == 0) executeOpenBsdPledge() catch |err| {
                std.debug.print("OpenBSD pledge child failed: {s}\n", .{@errorName(err)});
                std.c._exit(101);
            };
            std.c._exit(0);
        }
        var status: c_int = 0;
        while (std.c.waitpid(child, &status, 0) < 0) {
            if (errnoNow() != @intFromEnum(std.c.E.INTR)) return error.TestUnexpectedResult;
        }
        const bits: u32 = @bitCast(status);
        try std.testing.expect(std.c.W.IFEXITED(bits));
        try std.testing.expectEqual(@as(u8, 0), std.c.W.EXITSTATUS(bits));
    }
}

test "GAP-X1 Windows IOCP and RIO executes on this kernel" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try executeWindowsIocp();
}
