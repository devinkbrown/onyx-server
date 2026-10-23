// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows SMTP socket ABI retained behind its lazy container.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");

pub const win = struct {
    pub const invalid_socket = std.math.maxInt(usize);
    pub const af_inet: i32 = 2;
    pub const af_inet6: i32 = 23;
    pub const sock_stream: i32 = 1;
    pub const ipproto_tcp: i32 = 6;
    pub const sol_socket: i32 = 0xffff;
    pub const so_error: i32 = 0x1007;
    pub const so_exclusiveaddruse: i32 = ~@as(i32, 0x0004);
    pub const so_rcvtimeo: i32 = 0x1006;
    pub const so_sndtimeo: i32 = 0x1005;
    pub const fionbio: u32 = 0x8004667e;
    pub const interrupted: i32 = 10004;
    pub const would_block: i32 = 10035;
    pub const in_progress: i32 = 10036;
    pub const already: i32 = 10037;
    pub const timed_out: i32 = 10060;

    pub const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: [4]u8,
        zero: [8]u8 = @splat(0),
    };
    pub const SockAddr6 = extern struct {
        family: u16,
        port: u16,
        flowinfo: u32 = 0,
        addr: [16]u8,
        scope_id: u32 = 0,
    };
    pub const FdSet = extern struct {
        count: u32,
        sockets: [64]usize,
    };
    pub const Timeval = extern struct {
        seconds: i32,
        microseconds: i32,
    };
    comptime {
        if (@sizeOf(SockAddr4) != 16 or @sizeOf(SockAddr6) != 28 or @sizeOf(FdSet) != 520 or @sizeOf(Timeval) != 8)
            @compileError("Windows SMTP socket ABI shape changed");
    }

    pub extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    pub extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
    pub extern "ws2_32" fn WSASocketW(family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    pub extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    pub extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
    pub extern "ws2_32" fn connect(socket: usize, address: *const anyopaque, address_len: i32) callconv(.winapi) i32;
    pub extern "ws2_32" fn bind(socket: usize, address: *const anyopaque, address_len: i32) callconv(.winapi) i32;
    pub extern "ws2_32" fn getsockname(socket: usize, address: *anyopaque, address_len: *i32) callconv(.winapi) i32;
    pub extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;
    pub extern "ws2_32" fn accept(socket: usize, address: ?*anyopaque, address_len: ?*i32) callconv(.winapi) usize;
    pub extern "ws2_32" fn select(ignored_nfds: i32, readfds: ?*FdSet, writefds: ?*FdSet, exceptfds: ?*FdSet, timeout: *Timeval) callconv(.winapi) i32;
    pub extern "ws2_32" fn getsockopt(socket: usize, level: i32, option: i32, value: *anyopaque, length: *i32) callconv(.winapi) i32;
    pub extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    pub extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, length: i32, flags: i32) callconv(.winapi) i32;
    pub extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, length: i32, flags: i32) callconv(.winapi) i32;
};
