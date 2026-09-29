// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! I/O backend for accept, recv, send, poll, cancel, and timeout.
//!
//! Linux keeps today's Ringlane ring (`ringlane.zig`). Windows IOCP and BSD
//! kqueue select the same operations and fail closed: no completion port is
//! created, no kqueue fd is opened, and a missing op returns `error.MissingOp`.
//! Helix USR2 adoption stays on `LinuxServer`; every other family refuses a
//! capsule instead of adopting it.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const ringlane = @import("ringlane.zig");
const capsule = @import("helix/capsule.zig");

const Allocator = std.mem.Allocator;

pub const Family = enum { ringlane, iocp, kqueue };

pub const Op = enum { accept, recv, send, poll, cancel, timeout };

pub const required_ops = [_]Op{ .accept, .recv, .send, .poll, .cancel, .timeout };

pub fn familyFor(tag: std.Target.Os.Tag) Family {
    return switch (tag) {
        .linux => .ringlane,
        .windows => .iocp,
        .freebsd, .netbsd, .openbsd, .dragonfly, .macos, .ios => .kqueue,
        else => .kqueue,
    };
}

pub const IoBackend = struct {
    family: Family,
    entries: u16,
    features: ringlane.RingFeatures = .{},
    owned: ?ringlane.Ring = null,
    borrowed: ?*ringlane.Ring = null,

    pub fn openOwned(family: Family, entries: u16, features: ringlane.RingFeatures) !IoBackend {
        switch (family) {
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                return .{
                    .family = .ringlane,
                    .entries = entries,
                    .features = features,
                    .owned = try ringlane.Ring.init(entries, features),
                };
            },
            .iocp, .kqueue => return .{
                .family = family,
                .entries = entries,
            },
        }
    }

    pub fn closed(family: Family, entries: u16) IoBackend {
        return .{ .family = family, .entries = entries };
    }

    pub fn borrow(ring: *ringlane.Ring) IoBackend {
        return .{
            .family = .ringlane,
            .entries = 0,
            .features = ring.features,
            .borrowed = ring,
        };
    }

    pub fn deinit(self: *IoBackend) void {
        if (self.owned) |*ring| ring.deinit();
        self.owned = null;
        self.borrowed = null;
    }

    /// Move the owned Linux ring out. The caller deinits that ring.
    /// IOCP and kqueue have nothing to move.
    pub fn detachOwned(self: *IoBackend) ?ringlane.Ring {
        if (self.family != .ringlane) return null;
        const ring = self.owned orelse return null;
        self.owned = null;
        return ring;
    }

    fn ringPtr(self: *IoBackend) ?*ringlane.Ring {
        if (self.borrowed) |ring| return ring;
        if (self.owned) |*ring| return ring;
        return null;
    }

    pub fn opImplemented(self: *IoBackend, op: Op) bool {
        _ = op;
        if (self.family != .ringlane) return false;
        return self.ringPtr() != null;
    }

    pub fn requireAll(self: *IoBackend) error{MissingOp}!void {
        for (required_ops) |op| {
            if (!self.opImplemented(op)) return error.MissingOp;
        }
    }

    pub fn accept(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t) !void {
        const ring = self.ringPtr() orelse return error.MissingOp;
        if (self.family != .ringlane) return error.MissingOp;
        return ring.submitAccept(token, fd);
    }

    pub fn recv(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
        const ring = self.ringPtr() orelse return error.MissingOp;
        if (self.family != .ringlane) return error.MissingOp;
        return ring.submitRecv(token, fd, buffer);
    }

    pub fn send(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        const ring = self.ringPtr() orelse return error.MissingOp;
        if (self.family != .ringlane) return error.MissingOp;
        return ring.submitSend(token, fd, buffer);
    }

    pub fn poll(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        const ring = self.ringPtr() orelse return error.MissingOp;
        if (self.family != .ringlane) return error.MissingOp;
        return ring.submitPollAdd(token, fd, poll_mask);
    }

    pub fn cancel(self: *IoBackend, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        const ring = self.ringPtr() orelse return error.MissingOp;
        if (self.family != .ringlane) return error.MissingOp;
        return ring.submitExactCancel(kind, token);
    }

    pub fn timeout(self: *IoBackend, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        const ring = self.ringPtr() orelse return error.MissingOp;
        if (self.family != .ringlane) return error.MissingOp;
        return ring.submitTimeout(token, ts);
    }

    pub fn submit(self: *IoBackend) !u32 {
        const ring = self.ringPtr() orelse return error.MissingOp;
        if (self.family != .ringlane) return error.MissingOp;
        return ring.submit();
    }

    /// Look at a capsule and refuse it. This function does not adopt sessions.
    /// Linux adoption stays `LinuxServer.adoptInheritedSessions`.
    pub fn refuseCapsule(self: *const IoBackend, allocator: Allocator, bytes: []const u8) error{Usr2Refused}!void {
        if (capsule.decode(allocator, bytes)) |decoded| {
            var owned = decoded;
            owned.deinit(allocator);
        } else |_| {}
        switch (self.family) {
            .ringlane, .iocp, .kqueue => return error.Usr2Refused,
        }
    }
};

pub fn openLinuxRing(entries: u16, features: ringlane.RingFeatures) !ringlane.Ring {
    var backend = try IoBackend.openOwned(.ringlane, entries, features);
    return backend.detachOwned() orelse {
        backend.deinit();
        return error.Unsupported;
    };
}

pub fn submitAccept(ring: *ringlane.Ring, token: ringlane.FdToken, fd: linux.fd_t) !void {
    var backend = IoBackend.borrow(ring);
    return backend.accept(token, fd) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitRecv(ring: *ringlane.Ring, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
    var backend = IoBackend.borrow(ring);
    return backend.recv(token, fd, buffer) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitSend(ring: *ringlane.Ring, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
    var backend = IoBackend.borrow(ring);
    return backend.send(token, fd, buffer) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitPoll(ring: *ringlane.Ring, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
    var backend = IoBackend.borrow(ring);
    return backend.poll(token, fd, poll_mask) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitCancel(ring: *ringlane.Ring, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
    var backend = IoBackend.borrow(ring);
    return backend.cancel(kind, token) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitTimeout(ring: *ringlane.Ring, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
    var backend = IoBackend.borrow(ring);
    return backend.timeout(token, ts) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

/// PortableServer's init. A family with a missing op cannot become the reactor.
/// The Linux ring is opened by `openLinuxRing`, not here.
pub fn refusePortableReactor(tag: std.Target.Os.Tag, entries: u16) error{Unsupported}!void {
    var backend = IoBackend.closed(familyFor(tag), entries);
    backend.requireAll() catch return error.Unsupported;
    unreachable;
}

/// Non-Linux Helix path. Refuses adoption; does not decode a capsule into a session.
pub fn refuseForeignCapsule() error{Unsupported}!void {
    const backend = IoBackend.closed(switch (builtin.os.tag) {
        .windows => .iocp,
        else => .kqueue,
    }, 0);
    switch (backend.family) {
        .iocp, .kqueue => return error.Unsupported,
        .ringlane => return error.Unsupported,
    }
}

fn posixSocket() !linux.fd_t {
    const rc = linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => return error.SocketUnavailable,
    }
}

test "GAP-X1 IoBackend queues accept recv send poll cancel and timeout on the linux ring and iocp and kqueue fail closed" {
    const token = ringlane.FdToken{ .slot = 7, .gen = 3 };
    var live = try IoBackend.openOwned(.ringlane, 32, .{});
    defer live.deinit();
    try live.requireAll();
    try std.testing.expect(!live.features.sqpoll);
    try std.testing.expect(!live.features.defer_taskrun);
    for (required_ops) |op| try std.testing.expect(live.opImplemented(op));

    const fd = try posixSocket();
    defer _ = linux.close(fd);
    var buf: [4]u8 = .{ 0, 0, 0, 0 };
    try live.accept(token, fd);
    try live.recv(token, fd, &buf);
    try live.send(token, fd, "x");
    try live.poll(token, fd, linux.POLL.IN);
    var ts = linux.kernel_timespec{ .sec = 60, .nsec = 0 };
    try live.timeout(token, &ts);
    try live.cancel(.accept, token);
    const queued = live.ringPtr() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 6), queued.inner.sq_ready());
    try std.testing.expect(try live.submit() >= 1);

    var moved = try openLinuxRing(32, .{});
    defer moved.deinit();
    try std.testing.expect(!moved.features.sqpoll);
    try std.testing.expect(!moved.features.defer_taskrun);
    try submitAccept(&moved, token, fd);
    try submitRecv(&moved, token, fd, &buf);
    try submitSend(&moved, token, fd, "x");
    try submitPoll(&moved, token, fd, linux.POLL.IN);
    try submitTimeout(&moved, token, &ts);
    try submitCancel(&moved, .accept, token);
    try std.testing.expectEqual(@as(u32, 6), moved.inner.sq_ready());
    try std.testing.expect(try moved.submit() >= 1);

    const allocator = std.testing.allocator;
    const encoded = try capsule.encode(allocator, capsule.make(.monitor_list, &.{}));
    defer allocator.free(encoded);
    {
        var decoded = try capsule.decode(allocator, encoded);
        defer decoded.deinit(allocator);
        try std.testing.expectEqual(capsule.CapsuleKind.monitor_list, decoded.header.kind);
    }

    var iocp = try IoBackend.openOwned(.iocp, 32, .{});
    defer iocp.deinit();
    var kq = try IoBackend.openOwned(.kqueue, 32, .{});
    defer kq.deinit();
    for ([_]*IoBackend{ &iocp, &kq }) |backend| {
        try std.testing.expectError(error.MissingOp, backend.requireAll());
        try std.testing.expectError(error.MissingOp, backend.accept(token, fd));
        try std.testing.expectError(error.MissingOp, backend.recv(token, fd, &buf));
        try std.testing.expectError(error.MissingOp, backend.send(token, fd, "x"));
        try std.testing.expectError(error.MissingOp, backend.poll(token, fd, linux.POLL.IN));
        try std.testing.expectError(error.MissingOp, backend.cancel(.recv, token));
        try std.testing.expectError(error.MissingOp, backend.timeout(token, &ts));
        try std.testing.expectError(error.MissingOp, backend.submit());
        try std.testing.expectError(error.Usr2Refused, backend.refuseCapsule(allocator, encoded));
        for (required_ops) |op| try std.testing.expect(!backend.opImplemented(op));
    }
    try std.testing.expectError(error.Usr2Refused, live.refuseCapsule(allocator, encoded));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.windows, 32));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.freebsd, 32));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.linux, live.entries));
    try std.testing.expectError(error.Unsupported, refuseForeignCapsule());

    std.debug.print("GAP-X1 branch=linux ringlane queued accept recv send poll cancel and timeout; iocp and kqueue return MissingOp; portable init refuses; a USR2 capsule is refused off the Linux adopt path\n", .{});
}
