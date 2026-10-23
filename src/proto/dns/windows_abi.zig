// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native Windows adapter-discovery and UDP ABI shared by configuration and transport.

const std = @import("std");

pub const invalid_socket = std.math.maxInt(usize);
pub const af_unspec: u32 = 0;
pub const af_inet: u16 = 2;
pub const af_inet6: u16 = 23;
pub const sock_dgram: i32 = 2;
pub const ipproto_udp: i32 = 17;
pub const sol_socket: i32 = 0xffff;
pub const so_rcvtimeo: i32 = 0x1006;
pub const so_sndtimeo: i32 = 0x1005;
pub const error_buffer_overflow: u32 = 111;
pub const max_adapter_bytes: usize = 4 * 1024 * 1024;
pub const if_oper_status_up: u32 = 1;

pub const SocketAddress = extern struct {
    sockaddr: ?*const anyopaque,
    length: i32,
};
pub const DnsServerAddress = extern struct {
    length: u32,
    reserved: u32,
    next: ?*DnsServerAddress,
    address: SocketAddress,
};
pub const AdapterAddresses = extern struct {
    length: u32,
    if_index: u32,
    next: ?*AdapterAddresses,
    adapter_name: ?[*:0]const u8,
    first_unicast: ?*anyopaque,
    first_anycast: ?*anyopaque,
    first_multicast: ?*anyopaque,
    first_dns: ?*DnsServerAddress,
    dns_suffix: ?[*:0]const u16,
    description: ?[*:0]const u16,
    friendly_name: ?[*:0]const u16,
    physical_address: [8]u8,
    physical_address_length: u32,
    flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: u32,
    ipv6_if_index: u32,
};
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

comptime {
    if (@sizeOf(AdapterAddresses) != 112 or @offsetOf(AdapterAddresses, "first_dns") != 48 or
        @offsetOf(AdapterAddresses, "oper_status") != 104 or
        @sizeOf(DnsServerAddress) != 32 or @sizeOf(SockAddr4) != 16 or @sizeOf(SockAddr6) != 28)
        @compileError("Windows DNS socket ABI shape changed");
}

pub extern "iphlpapi" fn GetAdaptersAddresses(family: u32, flags: u32, reserved: ?*anyopaque, adapters: ?*AdapterAddresses, size: *u32) callconv(.winapi) u32;
pub extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
pub extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
pub extern "ws2_32" fn WSASocketW(family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
pub extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
pub extern "ws2_32" fn bind(socket: usize, address: *const SockAddr4, address_len: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn getsockname(socket: usize, address: *SockAddr4, address_len: *i32) callconv(.winapi) i32;
pub extern "ws2_32" fn connect(socket: usize, address: *const anyopaque, address_len: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, length: i32, flags: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, length: i32, flags: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn recvfrom(socket: usize, bytes: [*]u8, length: i32, flags: i32, from: *SockAddr4, from_length: *i32) callconv(.winapi) i32;
pub extern "ws2_32" fn sendto(socket: usize, bytes: [*]const u8, length: i32, flags: i32, to: *const SockAddr4, to_length: i32) callconv(.winapi) i32;

// Nonblocking DNS TCP fallback and deadline-controlled UDP readiness.
pub const sock_stream: i32 = 1;
// WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT (Windows 7 SP1+).
pub const socket_flags: u32 = 0x81;
pub const ipproto_tcp: i32 = 6;
pub const so_error: i32 = 0x1007;
pub const fionbio: u32 = 0x8004667e;
pub const interrupted: i32 = 10004;
pub const would_block: i32 = 10035;
pub const in_progress: i32 = 10036;
pub const already: i32 = 10037;

pub const FdSet = extern struct {
    count: u32,
    sockets: [64]usize,
};
pub const Timeval = extern struct {
    seconds: i32,
    microseconds: i32,
};

pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
pub extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
pub extern "ws2_32" fn select(ignored_nfds: i32, readfds: ?*FdSet, writefds: ?*FdSet, exceptfds: ?*FdSet, timeout: *Timeval) callconv(.winapi) i32;
pub extern "ws2_32" fn getsockopt(socket: usize, level: i32, option: i32, value: *anyopaque, length: *i32) callconv(.winapi) i32;

pub extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;
pub extern "ws2_32" fn accept(socket: usize, address: ?*anyopaque, length: ?*i32) callconv(.winapi) usize;
