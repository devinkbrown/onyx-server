// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! I/O backend for accept, recv, send, poll, cancel, and timeout.
//!
//! Linux keeps today's Ringlane ring (`ringlane.zig`). FreeBSD implements the
//! same operations on a kqueue fd via `kevent`. A missing filter, a closed
//! queue, or a `kevent` error returns `error.MissingOp` and is not reported as
//! a completed submit. Windows IOCP and every other kernel have no completion
//! port here; opening them returns `error.MissingOp`. Helix USR2 adoption stays
//! on `LinuxServer`.

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
    /// Heap kqueue state. Null on the Linux ring path so a borrowed backend
    /// stays a pointer, not a change batch, on the hot path.
    kq: ?*Kqueue = null,

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
            .iocp => return error.MissingOp,
            .kqueue => {
                const opened = try Kqueue.open(entries);
                const kq = std.heap.page_allocator.create(Kqueue) catch {
                    var doomed = opened;
                    doomed.deinit();
                    return error.OutOfMemory;
                };
                kq.* = opened;
                return .{
                    .family = .kqueue,
                    .entries = entries,
                    .kq = kq,
                };
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
        if (comptime builtin.os.tag == .linux) {
            if (self.owned) |*ring| ring.deinit();
        }
        self.owned = null;
        self.borrowed = null;
        if (self.kq) |kq| {
            kq.deinit();
            std.heap.page_allocator.destroy(kq);
            self.kq = null;
        }
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
        switch (self.family) {
            .ringlane => return self.ringPtr() != null,
            .kqueue => {
                const kq = self.kq orelse return false;
                if (kq.fd < 0) return false;
                return switch (op) {
                    .accept, .recv, .send, .poll, .cancel, .timeout => true,
                };
            },
            .iocp => return false,
        }
    }

    fn kqueuePtr(self: *IoBackend) !*Kqueue {
        if (self.family != .kqueue) return error.MissingOp;
        if (self.kq) |kq| return kq;
        const kq = std.heap.page_allocator.create(Kqueue) catch return error.OutOfMemory;
        kq.* = Kqueue.unopened(self.entries);
        self.kq = kq;
        return kq;
    }

    /// Filter and flags recorded for a kqueue change that was not submitted.
    /// `error.MissingOp` when that slot was not described.
    pub fn describedChange(self: *IoBackend, index: usize) error{MissingOp}!Kqueue.Queued {
        const kq = self.kq orelse return error.MissingOp;
        if (index >= kq.n) return error.MissingOp;
        const change = kq.changes[index];
        return .{
            .filter = change.filter,
            .flags = change.flags,
            .ident = change.ident,
            .data = change.data,
        };
    }

    pub fn requireAll(self: *IoBackend) error{MissingOp}!void {
        for (required_ops) |op| {
            if (!self.opImplemented(op)) return error.MissingOp;
        }
    }

    pub fn accept(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueAccept(token, fd),
            .iocp => return error.MissingOp,
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitAccept(token, fd);
            },
        }
    }

    pub fn recv(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueRecv(token, fd),
            .iocp => return error.MissingOp,
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitRecv(token, fd, buffer);
            },
        }
    }

    pub fn send(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueSend(token, fd),
            .iocp => return error.MissingOp,
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitSend(token, fd, buffer);
            },
        }
    }

    pub fn poll(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueuePoll(token, fd, poll_mask),
            .iocp => return error.MissingOp,
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitPollAdd(token, fd, poll_mask);
            },
        }
    }

    pub fn cancel(self: *IoBackend, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueCancel(kind, token),
            .iocp => return error.MissingOp,
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitExactCancel(kind, token);
            },
        }
    }

    pub fn timeout(self: *IoBackend, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueTimeout(token, ts),
            .iocp => return error.MissingOp,
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitTimeout(token, ts);
            },
        }
    }

    pub fn submit(self: *IoBackend) !u32 {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).submit(),
            .iocp => return error.MissingOp,
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submit();
            },
        }
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

/// PortableServer's init. Opens the native backend, requires every op, then
/// still refuses: the reactor loop is the Linux ring. A missing op is the
/// same refusal. The Linux ring used by `LinuxServer` is `openLinuxRing`.
pub fn refusePortableReactor(tag: std.Target.Os.Tag, entries: u16) error{Unsupported}!void {
    var backend = IoBackend.openOwned(familyFor(tag), entries, .{}) catch return error.Unsupported;
    defer backend.deinit();
    backend.requireAll() catch return error.Unsupported;
    return error.Unsupported;
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

/// FreeBSD kqueue. One `kevent` submit is at most `submit_batch` changes;
/// that bound is the syscall batch, not a connection ceiling. Registrations
/// grow. A closed queue, a full batch, an unknown cancel, or a `kevent`
/// error returns `error.MissingOp` and is not a completed submit.
///
/// `std.c.Kevent` is `void` off FreeBSD, and this daemon does not link libc
/// on Linux. Every libc call sits in a function that is not analyzed unless
/// `builtin.os.tag == .freebsd`.
const Kqueue = struct {
    fd: i32 = -1,
    cap: u16 = 0,
    n: u16 = 0,
    changes: [submit_batch]Change = @splat(.{}),
    regs: []Reg = &.{},

    pub const submit_batch = 256;

    pub const evfilt_read: i16 = -1;
    pub const evfilt_write: i16 = -2;
    pub const evfilt_timer: i16 = -7;
    pub const ev_add: u16 = 0x0001;
    pub const ev_delete: u16 = 0x0002;
    pub const ev_enable: u16 = 0x0004;
    pub const ev_oneshot: u16 = 0x0010;
    pub const ev_receipt: u16 = 0x0040;
    pub const ev_error: u16 = 0x4000;

    pub const Change = struct {
        ident: usize = 0,
        filter: i16 = 0,
        flags: u16 = 0,
        fflags: u32 = 0,
        data: i64 = 0,
        udata: usize = 0,
    };

    pub const Queued = struct {
        filter: i16,
        flags: u16,
        ident: usize,
        data: i64,
    };

    const Reg = struct {
        token: usize = 0,
        ident: usize = 0,
        filter: i16 = 0,
        live: bool = false,
    };

    pub fn unopened(entries: u16) Kqueue {
        return .{ .fd = -1, .cap = batchCap(entries) };
    }

    pub fn open(entries: u16) !Kqueue {
        if (entries == 0) return error.MissingOp;
        if (comptime builtin.os.tag != .freebsd) return error.MissingOp;
        return .{ .fd = try openFd(), .cap = batchCap(entries) };
    }

    pub fn deinit(self: *Kqueue) void {
        if (comptime builtin.os.tag == .freebsd) self.closeFreeBsd();
        self.fd = -1;
        self.n = 0;
        if (self.regs.len != 0) {
            std.heap.page_allocator.free(self.regs);
            self.regs = &.{};
        }
    }

    pub fn enqueueAccept(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t) !void {
        return self.enqueueFilter(token, fd, evfilt_read, ev_add | ev_enable, 0, false);
    }

    pub fn enqueueRecv(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t) !void {
        return self.enqueueFilter(token, fd, evfilt_read, ev_add | ev_enable, 0, false);
    }

    pub fn enqueueSend(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t) !void {
        return self.enqueueFilter(token, fd, evfilt_write, ev_add | ev_enable, 0, false);
    }

    pub fn enqueuePoll(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        if (poll_mask == 0) return error.MissingOp;
        const filter: i16 = if ((poll_mask & linux.POLL.OUT) != 0) evfilt_write else evfilt_read;
        return self.enqueueFilter(token, fd, filter, ev_add | ev_enable, 0, false);
    }

    pub fn enqueueCancel(self: *Kqueue, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        const token_key = packToken(token);
        switch (kind) {
            .poll, .other => return error.MissingOp,
            .timeout => {
                const before = self.n;
                self.pushStored(.{
                    .ident = token_key,
                    .filter = evfilt_timer,
                    .flags = ev_delete,
                    .udata = token_key,
                }) catch |err| {
                    if (self.n != before) self.forget(token_key, evfilt_timer);
                    return err;
                };
                self.forget(token_key, evfilt_timer);
            },
            .accept, .recv => try self.enqueueDelete(token_key, evfilt_read),
            .send, .connect => try self.enqueueDelete(token_key, evfilt_write),
        }
    }

    pub fn enqueueTimeout(self: *Kqueue, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        const ms = try timeoutMillis(ts);
        return self.enqueueFilter(token, 0, evfilt_timer, ev_add | ev_oneshot, ms, true);
    }

    pub fn submit(self: *Kqueue) !u32 {
        if (self.fd < 0 or self.n == 0) return error.MissingOp;
        if (comptime builtin.os.tag != .freebsd) return error.MissingOp;
        return self.submitFreeBsd();
    }

    fn enqueueFilter(
        self: *Kqueue,
        token: ringlane.FdToken,
        fd: linux.fd_t,
        filter: i16,
        flags: u16,
        data: i64,
        timer: bool,
    ) !void {
        const token_key = packToken(token);
        const ident: usize = if (timer) token_key else blk: {
            if (fd < 0) return error.MissingOp;
            break :blk @as(usize, @intCast(fd));
        };
        const change = Change{
            .ident = ident,
            .filter = filter,
            .flags = flags,
            .data = data,
            .udata = token_key,
        };
        try self.remember(change);
        return self.pushStored(change);
    }

    fn enqueueDelete(self: *Kqueue, token_key: usize, filter: i16) !void {
        const ident = self.lookup(token_key, filter) orelse return error.MissingOp;
        const before = self.n;
        self.pushStored(.{
            .ident = ident,
            .filter = filter,
            .flags = ev_delete,
            .udata = token_key,
        }) catch |err| {
            if (self.n != before) self.forget(token_key, filter);
            return err;
        };
        self.forget(token_key, filter);
    }

    fn pushStored(self: *Kqueue, change: Change) !void {
        if (self.n >= self.cap) return error.MissingOp;
        self.changes[self.n] = change;
        self.n += 1;
        if (self.fd < 0) return error.MissingOp;
    }

    fn remember(self: *Kqueue, change: Change) !void {
        var i: usize = 0;
        while (i < self.regs.len) : (i += 1) {
            if (self.regs[i].live and self.regs[i].token == change.udata and self.regs[i].filter == change.filter) {
                self.regs[i].ident = change.ident;
                return;
            }
        }
        i = 0;
        while (i < self.regs.len) : (i += 1) {
            if (!self.regs[i].live) {
                self.regs[i] = .{
                    .token = change.udata,
                    .ident = change.ident,
                    .filter = change.filter,
                    .live = true,
                };
                return;
            }
        }
        const old = self.regs;
        const new_len = if (old.len == 0) @as(usize, 16) else std.math.mul(usize, old.len, 2) catch return error.OutOfMemory;
        const grown = std.heap.page_allocator.alloc(Reg, new_len) catch return error.OutOfMemory;
        if (old.len != 0) {
            @memcpy(grown[0..old.len], old);
            std.heap.page_allocator.free(old);
        }
        var z: usize = old.len;
        while (z < grown.len) : (z += 1) grown[z] = .{};
        grown[old.len] = .{
            .token = change.udata,
            .ident = change.ident,
            .filter = change.filter,
            .live = true,
        };
        self.regs = grown;
    }

    fn lookup(self: *const Kqueue, token: usize, filter: i16) ?usize {
        var i: usize = self.regs.len;
        while (i > 0) {
            i -= 1;
            if (self.regs[i].live and self.regs[i].token == token and self.regs[i].filter == filter) return self.regs[i].ident;
        }
        return null;
    }

    fn forget(self: *Kqueue, token: usize, filter: i16) void {
        for (self.regs) |*reg| {
            if (reg.live and reg.token == token and reg.filter == filter) reg.live = false;
        }
    }

    fn batchCap(entries: u16) u16 {
        return @min(entries, @as(u16, submit_batch));
    }

    fn packToken(token: ringlane.FdToken) usize {
        return (@as(usize, token.gen) << 32) | @as(usize, token.slot);
    }

    fn timeoutMillis(ts: *const linux.kernel_timespec) !i64 {
        if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return error.MissingOp;
        const sec_ms = std.math.mul(i64, ts.sec, 1000) catch return error.MissingOp;
        return std.math.add(i64, sec_ms, @divTrunc(ts.nsec, 1_000_000)) catch return error.MissingOp;
    }

    fn openFd() !i32 {
        const raw = std.c.kqueue();
        if (raw < 0) return error.MissingOp;
        // F_SETFD = 2, FD_CLOEXEC = 1. std.c.F is `void` on FreeBSD.
        const cloexec = std.c.fcntl(raw, @as(i32, 2), @as(i32, 1));
        if (cloexec < 0) {
            _ = std.c.close(raw);
            return error.MissingOp;
        }
        // Reachable only if kqueue() returned the minimum i32. The branch
        // keeps the kevent body in the FreeBSD daemon's analysis.
        if (raw == std.math.minInt(i32)) freebsdTypecheck(raw);
        return raw;
    }

    fn closeFreeBsd(self: *Kqueue) void {
        if (self.fd >= 0) _ = std.c.close(self.fd);
    }

    fn submitFreeBsd(self: *Kqueue) !u32 {
        const n_changes: usize = self.n;
        if (n_changes == 0 or n_changes > submit_batch) return error.MissingOp;
        var batch: [submit_batch]std.c.Kevent = undefined;
        var i: usize = 0;
        while (i < n_changes) : (i += 1) {
            const change = self.changes[i];
            batch[i] = .{
                .ident = change.ident,
                .filter = change.filter,
                .flags = change.flags | ev_receipt,
                .fflags = change.fflags,
                .data = change.data,
                .udata = change.udata,
            };
        }
        self.n = 0;
        var out: [submit_batch]std.c.Kevent = undefined;
        const timeout = std.c.timespec{ .sec = 0, .nsec = 0 };
        const rc = std.c.kevent(
            self.fd,
            &batch,
            @intCast(n_changes),
            &out,
            @intCast(n_changes),
            &timeout,
        );
        if (rc <= 0) return error.MissingOp;
        const got: usize = @intCast(rc);
        if (got != n_changes) return error.MissingOp;
        var j: usize = 0;
        while (j < got) : (j += 1) {
            if ((out[j].flags & ev_error) == 0 or out[j].data != 0) return error.MissingOp;
        }
        return @intCast(n_changes);
    }

    fn bsdStreamSocket() !i32 {
        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
        if (fd < 0) return error.MissingOp;
        return fd;
    }

    fn proveQueued(backend: *IoBackend, sock: linux.fd_t) !u32 {
        const token = ringlane.FdToken{ .slot = 1, .gen = 1 };
        var buf: [4]u8 = .{ 0, 0, 0, 0 };
        try backend.accept(token, sock);
        try backend.recv(token, sock, &buf);
        try backend.send(token, sock, "x");
        try backend.poll(token, sock, linux.POLL.IN);
        var ts = linux.kernel_timespec{ .sec = 1, .nsec = 0 };
        try backend.timeout(token, &ts);
        try backend.cancel(.timeout, token);
        const submitted = try backend.submit();
        if (submitted == 0) return error.MissingOp;
        backend.poll(token, sock, 0) catch |err| switch (err) {
            error.MissingOp => {},
            else => |e| return e,
        };
        return submitted;
    }

    fn exerciseLive() !void {
        var backend = try IoBackend.openOwned(.kqueue, 32, .{});
        defer backend.deinit();
        try backend.requireAll();
        const sock = try bsdStreamSocket();
        defer {
            if (comptime builtin.os.tag == .freebsd) _ = std.c.close(sock);
        }
        const submitted = try proveQueued(&backend, sock);
        if (submitted == 0) return error.MissingOp;
    }

    fn freebsdTypecheck(fd: i32) void {
        var queue = Kqueue.unopened(32);
        queue.fd = fd;
        var backend = IoBackend{
            .family = .kqueue,
            .entries = 32,
            .kq = &queue,
        };
        _ = proveQueued(&backend, fd) catch {};
        backend.kq = null;
        if (bsdStreamSocket()) |sock| {
            _ = std.c.close(sock);
        } else |_| {}
        exerciseLive() catch {};
    }
};

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

    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.iocp, 32, .{}));
    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.kqueue, 32, .{}));
    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.kqueue, 0, .{}));

    var closed_kq = IoBackend.closed(.kqueue, 32);
    defer closed_kq.deinit();
    try std.testing.expectError(error.MissingOp, closed_kq.requireAll());
    for (required_ops) |op| try std.testing.expect(!closed_kq.opImplemented(op));
    try std.testing.expectError(error.MissingOp, closed_kq.accept(token, fd));
    try std.testing.expectError(error.MissingOp, closed_kq.recv(token, fd, &buf));
    try std.testing.expectError(error.MissingOp, closed_kq.send(token, fd, "x"));
    try std.testing.expectError(error.MissingOp, closed_kq.poll(token, fd, linux.POLL.IN));
    try std.testing.expectError(error.MissingOp, closed_kq.cancel(.recv, token));
    try std.testing.expectError(error.MissingOp, closed_kq.timeout(token, &ts));
    const token_key = (@as(usize, token.gen) << 32) | @as(usize, token.slot);
    const fd_ident: usize = @intCast(fd);
    const described = [_]struct { filter: i16, flags: u16, ident: usize, data: i64 }{
        .{ .filter = -1, .flags = 0x0005, .ident = fd_ident, .data = 0 },
        .{ .filter = -1, .flags = 0x0005, .ident = fd_ident, .data = 0 },
        .{ .filter = -2, .flags = 0x0005, .ident = fd_ident, .data = 0 },
        .{ .filter = -1, .flags = 0x0005, .ident = fd_ident, .data = 0 },
        .{ .filter = -1, .flags = 0x0002, .ident = fd_ident, .data = 0 },
        .{ .filter = -7, .flags = 0x0011, .ident = token_key, .data = 60_000 },
    };
    for (described, 0..) |want, index| {
        const got = try closed_kq.describedChange(index);
        try std.testing.expectEqual(want.filter, got.filter);
        try std.testing.expectEqual(want.flags, got.flags);
        try std.testing.expectEqual(want.ident, got.ident);
        try std.testing.expectEqual(want.data, got.data);
    }
    try std.testing.expectEqual(@as(u16, 0x0001 | 0x0004), (try closed_kq.describedChange(0)).flags);
    try std.testing.expectEqual(@as(u16, 0x0001 | 0x0010), (try closed_kq.describedChange(5)).flags);
    const queued_n = closed_kq.kq.?.n;
    try std.testing.expectError(error.MissingOp, closed_kq.poll(token, fd, 0));
    try std.testing.expectError(error.MissingOp, closed_kq.cancel(.other, token));
    try std.testing.expectError(error.MissingOp, closed_kq.cancel(.poll, token));
    try std.testing.expectEqual(queued_n, closed_kq.kq.?.n);
    try std.testing.expectError(error.MissingOp, closed_kq.submit());
    try std.testing.expectEqual(queued_n, closed_kq.kq.?.n);
    try std.testing.expectError(error.Usr2Refused, closed_kq.refuseCapsule(allocator, encoded));

    var one = IoBackend.closed(.kqueue, 1);
    defer one.deinit();
    try std.testing.expectError(error.MissingOp, one.accept(token, fd));
    try std.testing.expectEqual(@as(u16, 1), one.kq.?.n);
    try std.testing.expectError(error.MissingOp, one.recv(token, fd, &buf));
    try std.testing.expectEqual(@as(u16, 1), one.kq.?.n);
    try std.testing.expectError(error.MissingOp, one.describedChange(1));

    var bad_ts = linux.kernel_timespec{ .sec = -1, .nsec = 0 };
    const before_bad = closed_kq.kq.?.n;
    try std.testing.expectError(error.MissingOp, closed_kq.timeout(token, &bad_ts));
    try std.testing.expectEqual(before_bad, closed_kq.kq.?.n);
    try std.testing.expectError(error.MissingOp, closed_kq.accept(token, -1));
    try std.testing.expectEqual(before_bad, closed_kq.kq.?.n);

    try std.testing.expectError(error.Usr2Refused, live.refuseCapsule(allocator, encoded));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.windows, 32));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.freebsd, 32));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.linux, live.entries));
    try std.testing.expectError(error.Unsupported, refuseForeignCapsule());
    if (comptime builtin.os.tag == .freebsd) try Kqueue.exerciseLive();

    std.debug.print("GAP-X1 branch=linux ring queued six ops; this host did not execute kqueue or IOCP; closed kqueue describes FreeBSD filters and returns MissingOp; portable init refuses; USR2 capsule refused\n", .{});
}
