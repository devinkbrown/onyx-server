// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native connected UDP and framed TCP with nonblocking I/O and absolute deadlines.
//! A connection owns its socket and (on Windows) one balanced Winsock startup.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = if (builtin.os.tag == .linux) std.os.linux else posix.system;
const win = @import("windows_abi.zig");
const types = @import("message_types.zig");
const Deadline = @import("deadline.zig").Deadline;

pub const Error = error{ SocketUnavailable, ConnectFailed, SendFailed, ReceiveFailed, Timeout, TruncatedMessage, OversizeMessage };
pub const Socket = if (builtin.os.tag == .windows) usize else posix.fd_t;
pub const Protocol = enum { udp, tcp };
pub const Endpoint = struct { address: types.Address, scope_id: u32 = 0, port: u16 = 53 };
const Direction = enum { read, write };

pub const Connection = struct {
    socket: Socket,
    protocol: Protocol,

    pub fn open(endpoint: Endpoint, protocol: Protocol, deadline: Deadline) Error!Connection {
        _ = try deadline.remaining();
        if (comptime builtin.os.tag == .windows) return openWindows(endpoint, protocol, deadline);
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SocketUnavailable;
        const family: u32 = if (endpoint.address == .ipv4) posix.AF.INET else posix.AF.INET6;
        const kind: u32 = if (protocol == .udp) posix.SOCK.DGRAM else posix.SOCK.STREAM;
        const ip_protocol: u32 = if (protocol == .udp) posix.IPPROTO.UDP else posix.IPPROTO.TCP;
        const raw = sys.socket(family, kind | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, ip_protocol);
        if (posix.errno(raw) != .SUCCESS) return error.SocketUnavailable;
        var connection = Connection{ .socket = @intCast(raw), .protocol = protocol };
        errdefer connection.close();
        const connected = switch (endpoint.address) {
            .ipv4 => |bytes| blk: {
                var address = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, endpoint.port), .addr = @bitCast(bytes) };
                break :blk sys.connect(connection.socket, @ptrCast(&address), @sizeOf(@TypeOf(address)));
            },
            .ipv6 => |bytes| blk: {
                var address = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, endpoint.port), .addr = bytes, .scope_id = endpoint.scope_id, .flowinfo = 0 };
                break :blk sys.connect(connection.socket, @ptrCast(&address), @sizeOf(@TypeOf(address)));
            },
        };
        switch (posix.errno(connected)) {
            .SUCCESS => {},
            .INPROGRESS, .ALREADY, .AGAIN, .INTR => try connection.wait(.write, deadline),
            else => return error.ConnectFailed,
        }
        var socket_error: i32 = 0;
        var error_len: posix.socklen_t = @sizeOf(i32);
        if (posix.errno(sys.getsockopt(connection.socket, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&socket_error), &error_len)) != .SUCCESS or
            error_len != @sizeOf(i32) or socket_error != 0) return error.ConnectFailed;
        return connection;
    }

    fn openWindows(endpoint: Endpoint, protocol: Protocol, deadline: Deadline) Error!Connection {
        if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
        errdefer _ = win.WSACleanup();
        const family: i32 = if (endpoint.address == .ipv4) win.af_inet else win.af_inet6;
        const kind = if (protocol == .udp) win.sock_dgram else win.sock_stream;
        const ip_protocol = if (protocol == .udp) win.ipproto_udp else win.ipproto_tcp;
        const socket = win.WSASocketW(family, kind, ip_protocol, null, 0, win.socket_flags);
        if (socket == win.invalid_socket) return error.SocketUnavailable;
        errdefer _ = win.closesocket(socket);
        var nonblocking: u32 = 1;
        if (win.ioctlsocket(socket, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
        var connection = Connection{ .socket = socket, .protocol = protocol };
        const connected = switch (endpoint.address) {
            .ipv4 => |bytes| blk: {
                const address = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, endpoint.port), .addr = bytes };
                break :blk win.connect(socket, &address, @sizeOf(win.SockAddr4));
            },
            .ipv6 => |bytes| blk: {
                const address = win.SockAddr6{ .family = win.af_inet6, .port = std.mem.nativeToBig(u16, endpoint.port), .addr = bytes, .scope_id = endpoint.scope_id };
                break :blk win.connect(socket, &address, @sizeOf(win.SockAddr6));
            },
        };
        if (connected != 0) {
            switch (win.WSAGetLastError()) {
                win.would_block, win.in_progress, win.already, win.interrupted => try connection.wait(.write, deadline),
                else => return error.ConnectFailed,
            }
        }
        var socket_error: i32 = 0;
        var error_len: i32 = @sizeOf(i32);
        if (win.getsockopt(socket, win.sol_socket, win.so_error, &socket_error, &error_len) != 0 or
            socket_error != 0 or error_len != @sizeOf(i32)) return error.ConnectFailed;
        return connection;
    }

    pub fn close(self: *Connection) void {
        if (comptime builtin.os.tag == .windows) {
            _ = win.closesocket(self.socket);
            _ = win.WSACleanup();
        } else {
            _ = sys.close(self.socket);
        }
        self.* = undefined;
    }

    pub fn send(self: *Connection, bytes: []const u8, deadline: Deadline) Error!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            _ = try deadline.remaining();
            const sent: usize = if (comptime builtin.os.tag == .windows) blk: {
                const result = win.send(self.socket, bytes[offset..].ptr, @intCast(bytes.len - offset), 0);
                if (result < 0) switch (win.WSAGetLastError()) {
                    win.interrupted => continue,
                    win.would_block => {
                        try self.wait(.write, deadline);
                        continue;
                    },
                    else => return error.SendFailed,
                };
                break :blk @intCast(result);
            } else blk: {
                const result = sys.sendto(self.socket, bytes[offset..].ptr, bytes.len - offset, posix.MSG.NOSIGNAL, null, 0);
                switch (posix.errno(result)) {
                    .SUCCESS => break :blk @intCast(result),
                    .INTR => continue,
                    .AGAIN => {
                        try self.wait(.write, deadline);
                        continue;
                    },
                    else => return error.SendFailed,
                }
            };
            if (sent == 0 or (self.protocol == .udp and sent != bytes.len)) return error.SendFailed;
            offset += sent;
        }
    }

    pub fn receive(self: *Connection, out: []u8, deadline: Deadline) Error!usize {
        while (true) {
            _ = try deadline.remaining();
            const count: usize = if (comptime builtin.os.tag == .windows) blk: {
                const result = win.recv(self.socket, out.ptr, @intCast(out.len), 0);
                if (result < 0) switch (win.WSAGetLastError()) {
                    win.interrupted => continue,
                    win.would_block => {
                        try self.wait(.read, deadline);
                        continue;
                    },
                    else => return error.ReceiveFailed,
                };
                break :blk @intCast(result);
            } else blk: {
                const result = sys.recvfrom(self.socket, out.ptr, out.len, 0, null, null);
                switch (posix.errno(result)) {
                    .SUCCESS => break :blk @intCast(result),
                    .INTR => continue,
                    .AGAIN => {
                        try self.wait(.read, deadline);
                        continue;
                    },
                    else => return error.ReceiveFailed,
                }
            };
            if (count == 0 and self.protocol == .tcp) return error.TruncatedMessage;
            return count;
        }
    }

    pub fn receiveExact(self: *Connection, out: []u8, deadline: Deadline) Error!void {
        std.debug.assert(self.protocol == .tcp);
        var offset: usize = 0;
        while (offset < out.len) offset += try self.receive(out[offset..], deadline);
    }

    pub fn wait(self: *Connection, direction: Direction, deadline: Deadline) Error!void {
        while (true) {
            const remaining = try deadline.remaining();
            if (comptime builtin.os.tag == .windows) {
                var ready = win.FdSet{ .count = 1, .sockets = undefined };
                ready.sockets[0] = self.socket;
                var failed = ready;
                var timeout = win.Timeval{ .seconds = @intCast(remaining / 1000), .microseconds = @intCast((remaining % 1000) * 1000) };
                const result = win.select(0, if (direction == .read) &ready else null, if (direction == .write) &ready else null, &failed, &timeout);
                if (result < 0) {
                    if (win.WSAGetLastError() == win.interrupted) continue;
                    return error.SocketUnavailable;
                }
                if (result == 0) return error.Timeout;
                if (failed.count != 0) return error.ConnectFailed;
                if (ready.count != 0) return;
                return error.SocketUnavailable;
            } else {
                const wanted: i16 = if (direction == .read) posix.POLL.IN else posix.POLL.OUT;
                var pollfds = [_]posix.pollfd{.{ .fd = self.socket, .events = wanted, .revents = 0 }};
                const result = sys.poll(&pollfds, pollfds.len, @intCast(remaining));
                switch (posix.errno(result)) {
                    .SUCCESS => {},
                    .INTR => continue,
                    else => return error.SocketUnavailable,
                }
                if (result == 0) return error.Timeout;
                if (pollfds[0].revents & wanted != 0) return;
                if (pollfds[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) return error.ConnectFailed;
                return error.SocketUnavailable;
            }
        }
    }
};

pub fn tcpExchange(endpoint: Endpoint, query: []const u8, out: []u8, deadline: Deadline) Error![]const u8 {
    if (query.len > types.max_message_len) return error.OversizeMessage;
    var connection = try Connection.open(endpoint, .tcp, deadline);
    defer connection.close();
    var framed: [types.max_message_len + 2]u8 = undefined;
    std.mem.writeInt(u16, framed[0..2], @intCast(query.len), .big);
    @memcpy(framed[2..][0..query.len], query);
    try connection.send(framed[0 .. 2 + query.len], deadline);
    var prefix: [2]u8 = undefined;
    try connection.receiveExact(&prefix, deadline);
    const len: usize = std.mem.readInt(u16, &prefix, .big);
    if (len < 12) return error.TruncatedMessage;
    if (len > out.len) return error.OversizeMessage;
    try connection.receiveExact(out[0..len], deadline);
    return out[0..len];
}

test "DNS transport refuses expired deadlines before opening sockets" {
    try std.testing.expectError(error.Timeout, Connection.open(.{ .address = .{ .ipv4 = .{ 127, 0, 0, 1 } } }, .udp, .{ .expires_ms = 0 }));
}
