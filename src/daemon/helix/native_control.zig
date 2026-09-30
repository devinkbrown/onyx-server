// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenBSD Helix control messages. Descriptor custody stays separate from arena
//! contents: an executed candidate receives descriptors only after negotiation.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const runtime = @import("../os_runtime.zig");
pub const max_fds = 32;
pub const max_payload = 4096;
pub const Error = error{ Unsupported, SocketFailed, SendFailed, ReceiveFailed, WouldBlock, Protocol, TooLarge, DescriptorFailed };
const header_size = std.mem.alignForward(usize, @sizeOf(sys.cmsghdr), @sizeOf(usize));
const control_size = header_size + max_fds * @sizeOf(i32);

pub const Pair = struct {
    parent: i32 = -1,
    child: i32 = -1,
    pub fn init() Error!Pair {
        if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
        var fds: [2]i32 = undefined;
        if (posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &fds)) != .SUCCESS) return error.SocketFailed;
        errdefer for (fds) |fd| runtime.close(fd);
        for (fds) |fd| runtime.setNonblocking(fd) catch return error.SocketFailed;
        return .{ .parent = fds[0], .child = fds[1] };
    }
    pub fn deinit(self: *Pair) void {
        runtime.close(self.parent);
        runtime.close(self.child);
        self.* = .{};
    }
};

pub fn send(fd: i32, payload: []const u8, fds: []const i32) Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    if (payload.len == 0 or payload.len > max_payload or fds.len > max_fds) return error.TooLarge;
    var control: [control_size]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
    const used = header_size + std.mem.alignForward(usize, fds.len * @sizeOf(i32), @sizeOf(usize));
    if (fds.len != 0) {
        const hdr: *sys.cmsghdr = @ptrCast(&control);
        hdr.* = .{ .len = @intCast(header_size + fds.len * @sizeOf(i32)), .level = posix.SOL.SOCKET, .type = sys.SCM.RIGHTS };
        @memcpy(control[header_size..][0 .. fds.len * @sizeOf(i32)], std.mem.sliceAsBytes(fds));
    }
    var iov: posix.iovec_const = .{ .base = payload.ptr, .len = payload.len };
    const msg: sys.msghdr_const = .{ .name = null, .namelen = 0, .iov = @ptrCast(&iov), .iovlen = 1, .control = if (fds.len == 0) null else &control, .controllen = if (fds.len == 0) 0 else @intCast(used), .flags = 0 };
    while (true) {
        const rc = sys.sendmsg(fd, &msg, posix.MSG.NOSIGNAL);
        switch (posix.errno(rc)) {
            .SUCCESS => if (@as(usize, @intCast(rc)) == payload.len) return else return error.SendFailed,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.SendFailed,
        }
    }
}

pub const Message = struct {
    payload: [max_payload]u8 = undefined,
    length: usize = 0,
    fds: [max_fds]i32 = @splat(-1),
    fd_count: usize = 0,
    pub fn bytes(self: *const Message) []const u8 {
        return self.payload[0..self.length];
    }
    pub fn deinit(self: *Message) void {
        for (self.fds[0..self.fd_count]) |fd| runtime.close(fd);
        std.crypto.secureZero(u8, &self.payload);
        self.* = .{};
    }
};

/// No allocations after recvmsg: every delivered descriptor has immediate
/// custody and is closed on any validation or CLOEXEC failure.
pub fn receive(fd: i32) Error!Message {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    var result: Message = .{};
    errdefer result.deinit();
    var control: [control_size]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
    var iov: posix.iovec = .{ .base = &result.payload, .len = result.payload.len };
    var msg: sys.msghdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(&iov), .iovlen = 1, .control = &control, .controllen = control.len, .flags = 0 };
    const count = while (true) {
        const rc = sys.recvmsg(fd, &msg, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => break @as(usize, @intCast(rc)),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.ReceiveFailed,
        }
    };
    var offset: usize = 0;
    var malformed = false;
    const end = @min(@as(usize, msg.controllen), control.len);
    while (offset + @sizeOf(sys.cmsghdr) <= end) {
        const hdr: *const sys.cmsghdr = @ptrCast(@alignCast(control[offset..].ptr));
        const length: usize = hdr.len;
        if (length < header_size or length > end - offset) {
            malformed = true;
            break;
        }
        const data_len = length - header_size;
        if (hdr.level == posix.SOL.SOCKET and hdr.type == sys.SCM.RIGHTS) {
            if (data_len % @sizeOf(i32) != 0) malformed = true;
            var index: usize = 0;
            while (index + @sizeOf(i32) <= data_len) : (index += @sizeOf(i32)) {
                const delivered = std.mem.bytesToValue(i32, control[offset + header_size + index ..][0..@sizeOf(i32)]);
                if (result.fd_count == max_fds) {
                    runtime.close(delivered);
                    malformed = true;
                } else {
                    result.fds[result.fd_count] = delivered;
                    result.fd_count += 1;
                }
            }
        } else malformed = true;
        offset += std.mem.alignForward(usize, length, @sizeOf(usize));
    }
    if (malformed or count == 0 or count > max_payload or (msg.flags & (posix.MSG.TRUNC | posix.MSG.CTRUNC)) != 0) return error.Protocol;
    for (result.fds[0..result.fd_count]) |delivered| runtime.setCloexec(delivered, true) catch return error.DescriptorFailed;
    result.length = count;
    return result;
}

test "OpenBSD Helix control passes descriptors with independent CLOEXEC custody" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    var pair = try Pair.init();
    defer pair.deinit();
    var source: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &source)));
    defer runtime.close(source[0]);
    defer runtime.close(source[1]);
    try send(pair.parent, "STAGE generation", &.{source[0]});
    var received = try receive(pair.child);
    defer received.deinit();
    try std.testing.expectEqualStrings("STAGE generation", received.bytes());
    try std.testing.expectEqual(@as(usize, 1), received.fd_count);
    const transferred = received.fds[0];
    const flags = sys.fcntl(transferred, posix.F.GETFD, @as(c_int, 0));
    try std.testing.expect(posix.errno(flags) == .SUCCESS and (flags & posix.FD_CLOEXEC) != 0);
    try std.testing.expectEqual(@as(usize, 4), try runtime.write(source[1], "live"));
    var bytes: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try runtime.read(transferred, &bytes));
    try std.testing.expectEqualStrings("live", &bytes);
    received.deinit();
    try std.testing.expect(!runtime.fdValid(transferred));
    try std.testing.expect(runtime.fdValid(source[0]));
    try send(pair.child, "READY", &.{});
    var ready = try receive(pair.parent);
    defer ready.deinit();
    try std.testing.expectEqualStrings("READY", ready.bytes());
    try std.testing.expectEqual(@as(usize, 0), ready.fd_count);
}
