// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-private wake for the media worker. The Plane mutex serializes
//! signal/drain/close; readiness waits run only while the worker owns its life.
//! Never transferred or serialized: each prepared successor creates its own.
const std = @import("std");
const builtin = @import("builtin");
const ReactorWake = @import("reactor_wake.zig").ReactorWake;
const SocketHandle = @import("../substrate/media_socket.zig").SocketHandle;
const linux = std.os.linux;
const posix = std.posix;

const WindowsFdSet = extern struct { count: u32, sockets: [64]usize };
const WindowsTimeval = extern struct { seconds: i32, microseconds: i32 };
extern "ws2_32" fn select(ignored: i32, readfds: ?*WindowsFdSet, writefds: ?*WindowsFdSet, exceptfds: ?*WindowsFdSet, timeout: *WindowsTimeval) callconv(.winapi) i32;
extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;
extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
extern "ws2_32" fn getsockopt(socket: usize, level: i32, option: i32, value: *anyopaque, length: *i32) callconv(.winapi) i32;
extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;

pub const Wake = struct {
    resource: ReactorWake,
    pending: bool = false,

    pub fn init() !Wake {
        return .{ .resource = try ReactorWake.init() };
    }
    pub fn deinit(self: *Wake) void {
        self.resource.deinit();
        self.* = undefined;
    }
    /// A failed first signal is reported BEFORE queue publication. Saturation
    /// is success because the reliable stream/counter is already readable.
    pub fn signal(self: *Wake) error{WakeFailed}!void {
        if (self.pending) return;
        if (comptime builtin.os.tag == .windows) {
            const byte = [_]u8{1};
            while (send(self.resource.windows_write_socket, &byte, 1, 0) < 0) {
                const err = WSAGetLastError();
                if (err == 10004) continue;
                if (err != 10035) return error.WakeFailed;
                break;
            }
        } else if (comptime builtin.os.tag == .linux) {
            const value: u64 = 1;
            const bytes = std.mem.asBytes(&value);
            while (true) {
                const rc = linux.write(self.resource.handle, bytes.ptr, bytes.len);
                switch (linux.errno(rc)) {
                    .SUCCESS, .AGAIN => break,
                    .INTR => continue,
                    else => return error.WakeFailed,
                }
            }
        } else {
            const byte = [_]u8{1};
            while (true) {
                const rc = posix.system.sendto(self.resource.write_handle, &byte, 1, posix.MSG.NOSIGNAL, null, 0);
                switch (posix.errno(rc)) {
                    .SUCCESS, .AGAIN => break,
                    .INTR => continue,
                    else => return error.WakeFailed,
                }
            }
        }
        self.pending = true;
    }
    /// Coalescing allows at most one outstanding signal between drains. The
    /// underlying primitive also bounds its drain if foreign traffic arrives.
    pub fn drain(self: *Wake) void {
        self.resource.drain();
        self.pending = false;
    }
    fn clearMediaError(media: SocketHandle) error{WaitFailed}!void {
        var socket_error: i32 = 0;
        if (comptime builtin.os.tag == .windows) {
            while (true) {
                var length: i32 = @sizeOf(i32);
                if (getsockopt(media, 0xffff, 0x1007, &socket_error, &length) == 0) {
                    if (length != @sizeOf(i32)) return error.WaitFailed;
                    break;
                }
                if (WSAGetLastError() != 10004) return error.WaitFailed;
            }
        } else {
            while (true) {
                var length: posix.socklen_t = @sizeOf(i32);
                const rc = posix.system.getsockopt(media, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&socket_error), &length);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        if (length != @sizeOf(i32)) return error.WaitFailed;
                        break;
                    },
                    .INTR => continue,
                    else => return error.WaitFailed,
                }
            }
        }
    }
    pub const Ready = struct { media: bool = false, wake: bool = false };
    pub fn wait(self: *const Wake, media: SocketHandle, timeout_ms: u32) error{WaitFailed}!Ready {
        if (comptime builtin.os.tag == .windows) {
            var readable = WindowsFdSet{ .count = 2, .sockets = undefined };
            readable.sockets[0] = media;
            readable.sockets[1] = self.resource.windows_read_socket;
            var timeout = WindowsTimeval{ .seconds = @intCast(timeout_ms / 1000), .microseconds = @intCast((timeout_ms % 1000) * 1000) };
            const count = select(0, &readable, null, null, &timeout);
            if (count < 0) {
                const err = WSAGetLastError();
                if (err == 10004) return .{};
                // Ordinary UDP ICMP/reset errors do not retire the worker.
                if (err == 10052 or err == 10054 or err == 10061) {
                    try clearMediaError(media);
                    return .{};
                }
                return error.WaitFailed;
            }
            var ready: Ready = .{};
            for (readable.sockets[0..readable.count]) |fd| {
                ready.media = ready.media or fd == media;
                ready.wake = ready.wake or fd == self.resource.windows_read_socket;
            }
            if (ready.wake) {
                // select readability also includes EOF on the reliable wake
                // stream. EOF/private-stream failure is terminal, not a wake.
                var byte: [1]u8 = undefined;
                const peeked = recv(self.resource.windows_read_socket, &byte, 1, 2); // MSG_PEEK
                if (peeked == 0) return error.WaitFailed;
                if (peeked < 0) {
                    const err = WSAGetLastError();
                    if (err == 10004 or err == 10035) ready.wake = false else return error.WaitFailed;
                }
            }
            return ready;
        } else {
            var fds = [_]posix.pollfd{
                .{ .fd = media, .events = posix.POLL.IN, .revents = 0 },
                .{ .fd = self.resource.fd(), .events = posix.POLL.IN, .revents = 0 },
            };
            const count = posix.system.poll(&fds, fds.len, @intCast(@min(timeout_ms, std.math.maxInt(c_int))));
            switch (posix.errno(count)) {
                .SUCCESS => {},
                .INTR => return .{},
                else => return error.WaitFailed,
            }
            if (fds[1].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0 or
                fds[0].revents & (posix.POLL.HUP | posix.POLL.NVAL) != 0) return error.WaitFailed;
            // UDP POLLERR may be an asynchronous ICMP error from an earlier
            // send. Consume SO_ERROR so it cannot create a persistent spin;
            // preserve readiness for any actual datagram that arrived too.
            if (fds[0].revents & posix.POLL.ERR != 0) try clearMediaError(media);
            return .{ .media = fds[0].revents & posix.POLL.IN != 0, .wake = fds[1].revents & posix.POLL.IN != 0 };
        }
    }
};

test "media pump private wake coalesces and preserves signal before wait" {
    const MediaSocket = @import("../substrate/media_socket.zig").MediaSocket;
    const loopback = @import("../substrate/media_socket.zig").loopback_be;
    var media = try MediaSocket.bind(loopback, 0);
    defer media.deinit();
    var wake = try Wake.init();
    defer wake.deinit();
    try std.testing.expectEqualDeep(Wake.Ready{}, try wake.wait(media.fd, 0));
    // One pending reliable signal represents arbitrarily many publications.
    for (0..1024) |_| try wake.signal();
    const ready = try wake.wait(media.fd, 0);
    try std.testing.expect(ready.wake and !ready.media);
    wake.drain();
    try std.testing.expectEqualDeep(Wake.Ready{}, try wake.wait(media.fd, 0));
    try wake.signal();
    try std.testing.expect((try wake.wait(media.fd, 100)).wake);
    wake.drain();
    try std.testing.expectEqualDeep(Wake.Ready{}, try wake.wait(media.fd, 0));
}

test "media pump private wait consumes recoverable UDP ICMP without retiring wake" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const media_socket = @import("../substrate/media_socket.zig");
    var media = try media_socket.MediaSocket.bind(media_socket.loopback_be, 0);
    defer media.deinit();
    var peer = try media_socket.MediaSocket.bind(media_socket.loopback_be, 0);
    const peer_port = try peer.localPort();
    peer.deinit();
    var wake = try Wake.init();
    defer wake.deinit();
    var address = posix.system.sockaddr.in{ .port = std.mem.nativeToBig(u16, peer_port), .addr = media_socket.loopback_be };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(posix.system.connect(media.fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))));
    const destination = try media_socket.TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, peer_port);
    try std.testing.expectEqual(media_socket.SendDisposition.sent, media.trySendTo(destination, "icmp-probe"));
    var fds = [_]posix.pollfd{.{ .fd = media.fd, .events = posix.POLL.IN, .revents = 0 }};
    const count = posix.system.poll(&fds, 1, 1000);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(count));
    try std.testing.expect(fds[0].revents & posix.POLL.ERR != 0);
    // This is the actual recoverable POLLERR branch, not a fabricated verdict.
    _ = try wake.wait(media.fd, 0);
    fds[0].revents = 0;
    try std.testing.expectEqual(@as(usize, 0), posix.system.poll(&fds, 1, 0));
    try wake.signal();
    try std.testing.expect((try wake.wait(media.fd, 100)).wake);
    wake.drain();
    var recovered_peer = try media_socket.MediaSocket.bind(media_socket.loopback_be, peer_port);
    defer recovered_peer.deinit();
    recovered_peer.setRecvTimeoutMs(200);
    try std.testing.expectEqual(media_socket.SendDisposition.sent, media.trySendTo(destination, "recovered"));
    var bytes: [64]u8 = undefined;
    const recovered = recovered_peer.recvFrom(&bytes) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("recovered", recovered.data);
}

test "media pump private wait rejects invalid wake descriptor through actual readiness syscall" {
    const media_socket = @import("../substrate/media_socket.zig");
    var media = try media_socket.MediaSocket.bind(media_socket.loopback_be, 0);
    defer media.deinit();
    var wake = try Wake.init();
    defer wake.deinit();
    if (comptime builtin.os.tag == .windows) {
        const original = wake.resource.windows_read_socket;
        defer wake.resource.windows_read_socket = original;
        wake.resource.windows_read_socket = std.math.maxInt(usize);
        try std.testing.expectError(error.WaitFailed, wake.wait(media.fd, 0));
    } else {
        const original = wake.resource.handle;
        defer wake.resource.handle = original;
        wake.resource.handle = std.math.maxInt(@TypeOf(original));
        try std.testing.expectError(error.WaitFailed, wake.wait(media.fd, 0));
    }
}
