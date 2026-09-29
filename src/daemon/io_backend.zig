// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! I/O backend for accept, recv, send, poll, cancel, and timeout.
//!
//! Linux keeps today's Ringlane ring (`ringlane.zig`). FreeBSD implements the
//! same operations on a kqueue fd via `kevent`. Windows implements them on an
//! I/O completion port: `NtReadFile` / `NtWriteFile`, AFD wait-for-listen and
//! AFD poll, `NtCancelIoFileEx`, and an NT timer. `Iocp.open` also loads the
//! Winsock Registered I/O function table and returns `error.MissingOp` when
//! that table is missing; the pointers are not called. A missing op, a closed
//! port or queue, or a kernel status other than success or pending returns
//! `error.MissingOp` and is not reported as a finished transfer. No reactor
//! drains the port. Helix USR2 adoption stays on `LinuxServer`.

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
    /// Heap IOCP state. Null on the Linux ring path.
    iocp: ?*Iocp = null,

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
            .iocp => {
                const opened = try Iocp.open(entries);
                const iocp = std.heap.page_allocator.create(Iocp) catch {
                    var doomed = opened;
                    doomed.deinit();
                    return error.OutOfMemory;
                };
                iocp.* = opened;
                return .{
                    .family = .iocp,
                    .entries = entries,
                    .iocp = iocp,
                };
            },
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
        if (self.iocp) |iocp| {
            iocp.deinit();
            std.heap.page_allocator.destroy(iocp);
            self.iocp = null;
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
            .iocp => {
                const iocp = self.iocp orelse return false;
                if (iocp.port == 0) return false;
                return switch (op) {
                    .accept, .recv, .send, .poll, .cancel, .timeout => true,
                };
            },
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

    fn iocpPtr(self: *IoBackend) !*Iocp {
        if (self.family != .iocp) return error.MissingOp;
        if (self.iocp) |iocp| return iocp;
        const iocp = std.heap.page_allocator.create(Iocp) catch return error.OutOfMemory;
        iocp.* = Iocp.unopened(self.entries);
        self.iocp = iocp;
        return iocp;
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

    /// Packet recorded for an IOCP op that was not submitted.
    /// `error.MissingOp` when that slot was not described.
    pub fn describedPacket(self: *IoBackend, index: usize) error{MissingOp}!Iocp.Packet {
        const iocp = self.iocp orelse return error.MissingOp;
        if (index >= iocp.n) return error.MissingOp;
        return iocp.packets[index];
    }

    pub fn requireAll(self: *IoBackend) error{MissingOp}!void {
        for (required_ops) |op| {
            if (!self.opImplemented(op)) return error.MissingOp;
        }
    }

    pub fn accept(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueAccept(token, fd),
            .iocp => return (try self.iocpPtr()).enqueueAccept(token, fd),
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
            .iocp => return (try self.iocpPtr()).enqueueRecv(token, fd, buffer),
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
            .iocp => return (try self.iocpPtr()).enqueueSend(token, fd, buffer),
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
            .iocp => return (try self.iocpPtr()).enqueuePoll(token, fd, poll_mask),
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
            .iocp => return (try self.iocpPtr()).enqueueCancel(kind, token),
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
            .iocp => return (try self.iocpPtr()).enqueueTimeout(token, ts),
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
            .iocp => return (try self.iocpPtr()).submit(),
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

/// Windows completion port. One submit posts at most `submit_batch` kernel
/// requests; that bound is the batch, not a connection ceiling. A closed
/// port, a full batch, an unknown cancel, or a status other than success or
/// pending returns `error.MissingOp`.
///
/// Accept is AFD wait-for-listen (`0x1200C`) and poll is AFD select
/// (`0x12024`), the ReactOS/libuv packing `(FILE_DEVICE_NETWORK << 12) |
/// (operation << 2) | method`. Recv and send are `NtReadFile` / `NtWriteFile`
/// after the handle is associated with the port. Timeout arms an NT timer and
/// does not synthesize a completion packet. Nothing calls
/// `NtRemoveIoCompletion` on the success path, so a posted request is not
/// reported as bytes already transferred.
///
/// Open also loads `RIO_EXTENSION_FUNCTION_TABLE` through `WSAIoctl`. A failed
/// or partial table closes the new port and returns `error.MissingOp`. The
/// stored pointers are not called.
///
/// `ntdll` and `ws2_32` calls sit in functions that are not analyzed unless
/// `builtin.os.tag == .windows`. This Linux host does not execute them.
const Iocp = struct {
    port: usize = 0,
    cap: u16 = 0,
    n: u16 = 0,
    /// Empty unless `open` stored a table `rioTableUsable` accepted.
    rio: RioTable = .{},
    packets: [submit_batch]Packet = @splat(.{}),
    regs: []Reg = &.{},
    armed: []usize = &.{},

    pub const submit_batch = 256;

    pub const op_accept: u8 = 1;
    pub const op_recv: u8 = 2;
    pub const op_send: u8 = 3;
    pub const op_timeout: u8 = 4;
    pub const op_poll: u8 = 6;
    pub const op_cancel: u8 = 7;

    /// FILE_DEVICE_NETWORK is 0x12. AFD wait-for-listen is operation 3,
    /// METHOD_BUFFERED. AFD select (poll) is operation 9, METHOD_BUFFERED.
    pub const ioctl_afd_wait_for_listen: u32 = (0x12 << 12) | (3 << 2) | 0;
    pub const ioctl_afd_poll: u32 = (0x12 << 12) | (9 << 2) | 0;

    pub const Packet = struct {
        op: u8 = 0,
        handle: usize = 0,
        length: u32 = 0,
        token: usize = 0,
        ioctl: u32 = 0,
        buf: usize = 0,
    };

    const Reg = struct {
        token: usize = 0,
        handle: usize = 0,
        op: u8 = 0,
        live: bool = false,
    };

    pub fn unopened(entries: u16) Iocp {
        return .{ .port = 0, .cap = batchCap(entries) };
    }

    pub fn open(entries: u16) !Iocp {
        if (entries == 0) return error.MissingOp;
        if (comptime builtin.os.tag != .windows) return error.MissingOp;
        const port = try openHandle();
        var opened = Iocp{
            .port = port,
            .cap = batchCap(entries),
        };
        // The Registered I/O table is part of opening the Windows backend.
        // A missing table is not an open port with ordinary sockets underneath.
        opened.rio = loadRioForDaemon() catch |err| {
            opened.deinit();
            return err;
        };
        if (!rioTableUsable(&opened.rio)) {
            opened.deinit();
            return error.MissingOp;
        }
        return opened;
    }

    pub fn deinit(self: *Iocp) void {
        if (comptime builtin.os.tag == .windows) self.closeWindows();
        self.port = 0;
        self.n = 0;
        self.rio = .{};
        if (self.regs.len != 0) {
            std.heap.page_allocator.free(self.regs);
            self.regs = &.{};
        }
        if (self.armed.len != 0) {
            std.heap.page_allocator.free(self.armed);
            self.armed = &.{};
        }
    }

    pub fn enqueueAccept(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t) !void {
        const handle = try handleOf(fd);
        try self.remember(packToken(token), handle, op_accept);
        return self.pushStored(.{
            .op = op_accept,
            .handle = handle,
            .token = packToken(token),
            .ioctl = ioctl_afd_wait_for_listen,
        });
    }

    pub fn enqueueRecv(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
        if (buffer.len == 0 or buffer.len > std.math.maxInt(u32)) return error.MissingOp;
        const handle = try handleOf(fd);
        try self.remember(packToken(token), handle, op_recv);
        return self.pushStored(.{
            .op = op_recv,
            .handle = handle,
            .length = @intCast(buffer.len),
            .token = packToken(token),
            .buf = @intFromPtr(buffer.ptr),
        });
    }

    pub fn enqueueSend(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        if (buffer.len == 0 or buffer.len > std.math.maxInt(u32)) return error.MissingOp;
        const handle = try handleOf(fd);
        try self.remember(packToken(token), handle, op_send);
        return self.pushStored(.{
            .op = op_send,
            .handle = handle,
            .length = @intCast(buffer.len),
            .token = packToken(token),
            .buf = @intFromPtr(buffer.ptr),
        });
    }

    pub fn enqueuePoll(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        if (poll_mask == 0) return error.MissingOp;
        const handle = try handleOf(fd);
        try self.remember(packToken(token), handle, op_poll);
        return self.pushStored(.{
            .op = op_poll,
            .handle = handle,
            .length = poll_mask,
            .token = packToken(token),
            .ioctl = ioctl_afd_poll,
        });
    }

    pub fn enqueueCancel(self: *Iocp, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        const op: u8 = switch (kind) {
            .accept => op_accept,
            .recv => op_recv,
            .send => op_send,
            .timeout => op_timeout,
            .poll, .other, .connect => return error.MissingOp,
        };
        const token_key = packToken(token);
        const handle = self.lookup(token_key, op) orelse return error.MissingOp;
        const before = self.n;
        self.pushStored(.{
            .op = op_cancel,
            .handle = handle,
            .length = op,
            .token = token_key,
        }) catch |err| {
            if (self.n != before) self.forget(token_key, op);
            return err;
        };
        self.forget(token_key, op);
    }

    pub fn enqueueTimeout(self: *Iocp, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        const ms = timeoutMillis(ts) orelse return error.MissingOp;
        if (ms > std.math.maxInt(u32)) return error.MissingOp;
        try self.remember(packToken(token), 0, op_timeout);
        return self.pushStored(.{
            .op = op_timeout,
            .length = @intCast(ms),
            .token = packToken(token),
        });
    }

    pub fn submit(self: *Iocp) !u32 {
        if (self.port == 0 or self.n == 0) return error.MissingOp;
        if (comptime builtin.os.tag != .windows) return error.MissingOp;
        return self.submitWindows();
    }

    fn pushStored(self: *Iocp, packet: Packet) !void {
        if (self.n >= self.cap) return error.MissingOp;
        self.packets[self.n] = packet;
        self.n += 1;
        if (self.port == 0) return error.MissingOp;
    }

    fn remember(self: *Iocp, token_key: usize, handle: usize, op: u8) !void {
        var i: usize = 0;
        while (i < self.regs.len) : (i += 1) {
            if (self.regs[i].live and self.regs[i].token == token_key and self.regs[i].op == op) {
                self.regs[i].handle = handle;
                return;
            }
        }
        i = 0;
        while (i < self.regs.len) : (i += 1) {
            if (!self.regs[i].live) {
                self.regs[i] = .{ .token = token_key, .handle = handle, .op = op, .live = true };
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
        grown[old.len] = .{ .token = token_key, .handle = handle, .op = op, .live = true };
        self.regs = grown;
    }

    fn lookup(self: *Iocp, token_key: usize, op: u8) ?usize {
        for (self.regs) |reg| {
            if (reg.live and reg.token == token_key and reg.op == op) return reg.handle;
        }
        return null;
    }

    fn forget(self: *Iocp, token_key: usize, op: u8) void {
        for (self.regs) |*reg| {
            if (reg.live and reg.token == token_key and reg.op == op) reg.live = false;
        }
    }

    fn batchCap(entries: u16) u16 {
        if (entries == 0 or entries > submit_batch) return submit_batch;
        return entries;
    }

    fn packToken(token: ringlane.FdToken) usize {
        return (@as(usize, token.gen) << 32) | @as(usize, token.slot);
    }

    fn handleOf(fd: linux.fd_t) !usize {
        if (fd < 0) return error.MissingOp;
        return @intCast(fd);
    }

    fn timeoutMillis(ts: *const linux.kernel_timespec) ?i64 {
        if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return null;
        const sec_ms = std.math.mul(i64, ts.sec, 1000) catch return null;
        return std.math.add(i64, sec_ms, @divTrunc(ts.nsec, 1_000_000)) catch null;
    }

    fn openHandle() !usize {
        const w = std.os.windows;
        var handle: w.HANDLE = undefined;
        const status = NtCreateIoCompletion(&handle, w.ACCESS_MASK.Specific.IoCompletion.ALL_ACCESS, null, 0);
        if (status != .SUCCESS) return error.MissingOp;
        const raw = @intFromPtr(handle);
        if (raw == 0) windowsTypecheck(raw);
        return raw;
    }

    fn closeWindows(self: *Iocp) void {
        const w = std.os.windows;
        if (self.port != 0) {
            _ = w.ntdll.NtClose(@ptrFromInt(self.port));
            self.port = 0;
        }
        for (self.armed) |timer| {
            if (timer != 0) _ = w.ntdll.NtClose(@ptrFromInt(timer));
        }
    }

    fn rememberTimer(self: *Iocp, timer: usize) !void {
        const old = self.armed;
        const grown = std.heap.page_allocator.alloc(usize, old.len + 1) catch return error.OutOfMemory;
        if (old.len != 0) {
            @memcpy(grown[0..old.len], old);
            std.heap.page_allocator.free(old);
        }
        grown[old.len] = timer;
        self.armed = grown;
    }

    fn submitWindows(self: *Iocp) !u32 {
        const n_packets = self.n;
        if (n_packets == 0 or n_packets > submit_batch) return error.MissingOp;
        var queued: [submit_batch]Packet = undefined;
        @memcpy(queued[0..n_packets], self.packets[0..n_packets]);
        self.n = 0;
        var i: u16 = 0;
        while (i < n_packets) : (i += 1) {
            try self.postOne(queued[i]);
        }
        return n_packets;
    }

    fn postOne(self: *Iocp, packet: Packet) !void {
        const w = std.os.windows;
        switch (packet.op) {
            op_accept => {
                var out: [8]u8 = @splat(0);
                try self.device(packet, &out);
            },
            op_recv, op_send => {
                if (packet.buf == 0 or packet.length == 0) return error.MissingOp;
                try self.associate(packet.handle);
                var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
                const status = if (packet.op == op_recv)
                    w.ntdll.NtReadFile(
                        @ptrFromInt(packet.handle),
                        null,
                        null,
                        null,
                        &iosb,
                        @ptrFromInt(packet.buf),
                        packet.length,
                        null,
                        null,
                    )
                else
                    w.ntdll.NtWriteFile(
                        @ptrFromInt(packet.handle),
                        null,
                        null,
                        null,
                        &iosb,
                        @ptrFromInt(packet.buf),
                        packet.length,
                        null,
                        null,
                    );
                if (status != .SUCCESS and status != .PENDING) return error.MissingOp;
            },
            op_poll => {
                var out: [64]u8 = @splat(0);
                try self.device(packet, &out);
            },
            op_cancel => try self.cancelOne(packet),
            op_timeout => try self.armTimer(packet),
            else => return error.MissingOp,
        }
    }

    fn associate(self: *Iocp, handle: usize) !void {
        const w = std.os.windows;
        var info = extern struct {
            port: w.HANDLE,
            key: ?*anyopaque,
        }{
            .port = @ptrFromInt(self.port),
            .key = @ptrFromInt(handle),
        };
        var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
        const status = w.ntdll.NtSetInformationFile(
            @ptrFromInt(handle),
            &iosb,
            @ptrCast(&info),
            @sizeOf(@TypeOf(info)),
            .Completion,
        );
        if (status != .SUCCESS) return error.MissingOp;
    }

    fn device(self: *Iocp, packet: Packet, out: []u8) !void {
        const w = std.os.windows;
        try self.associate(packet.handle);
        var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
        const code: w.CTL_CODE = @bitCast(packet.ioctl);
        const status = w.ntdll.NtDeviceIoControlFile(
            @ptrFromInt(packet.handle),
            null,
            null,
            null,
            &iosb,
            code,
            null,
            0,
            if (out.len == 0) null else @ptrCast(out.ptr),
            @intCast(out.len),
        );
        if (status != .SUCCESS and status != .PENDING) return error.MissingOp;
    }

    fn cancelOne(self: *Iocp, packet: Packet) !void {
        const w = std.os.windows;
        if (packet.length == op_timeout) {
            const timer = self.lookup(packet.token, op_timeout) orelse return error.MissingOp;
            if (timer == 0) return error.MissingOp;
            var state: w.BOOLEAN = .FALSE;
            const status = NtCancelTimer(@ptrFromInt(timer), &state);
            if (status != .SUCCESS) return error.MissingOp;
            return;
        }
        var request = std.mem.zeroes(w.IO_STATUS_BLOCK);
        var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
        const status = NtCancelIoFileEx(@ptrFromInt(packet.handle), &request, &iosb);
        if (status != .SUCCESS and status != .PENDING) return error.MissingOp;
    }

    fn armTimer(self: *Iocp, packet: Packet) !void {
        const w = std.os.windows;
        var timer: w.HANDLE = undefined;
        const created = NtCreateTimer(&timer, w.ACCESS_MASK.Specific.Timer.ALL_ACCESS, null, .Notification);
        if (created != .SUCCESS) return error.MissingOp;
        const raw = @intFromPtr(timer);
        const due: w.LARGE_INTEGER = -@as(w.LARGE_INTEGER, packet.length) * 10_000;
        var previous: w.BOOLEAN = .FALSE;
        const armed = NtSetTimer(timer, &due, null, null, .FALSE, 0, &previous);
        if (armed != .SUCCESS) {
            _ = w.ntdll.NtClose(timer);
            return error.MissingOp;
        }
        self.rememberTimer(raw) catch {
            _ = w.ntdll.NtClose(timer);
            return error.OutOfMemory;
        };
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
        return submitted;
    }

    fn exerciseLive() !void {
        var backend = try IoBackend.openOwned(.iocp, 32, .{});
        defer backend.deinit();
        try backend.requireAll();
        const submitted = try proveQueued(&backend, 1);
        if (submitted == 0) return error.MissingOp;
    }

    fn windowsTypecheck(raw: usize) void {
        var port = Iocp.unopened(32);
        port.port = raw;
        var backend = IoBackend{
            .family = .iocp,
            .entries = 32,
            .iocp = &port,
        };
        _ = proveQueued(&backend, 1) catch {};
        backend.iocp = null;
        var key: ?*anyopaque = null;
        var apc: ?*anyopaque = null;
        var iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
        _ = NtRemoveIoCompletion(@ptrFromInt(raw), &key, &apc, &iosb, null);
        exerciseLive() catch {};
    }
};

extern "ntdll" fn NtCreateIoCompletion(
    IoCompletionHandle: *std.os.windows.HANDLE,
    DesiredAccess: std.os.windows.ACCESS_MASK,
    ObjectAttributes: ?*const anyopaque,
    Count: std.os.windows.ULONG,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtRemoveIoCompletion(
    IoCompletionHandle: std.os.windows.HANDLE,
    KeyContext: *?*anyopaque,
    ApcContext: *?*anyopaque,
    IoStatusBlock: *std.os.windows.IO_STATUS_BLOCK,
    Timeout: ?*const std.os.windows.LARGE_INTEGER,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtCancelIoFileEx(
    FileHandle: std.os.windows.HANDLE,
    IoRequestToCancel: *std.os.windows.IO_STATUS_BLOCK,
    IoStatusBlock: *std.os.windows.IO_STATUS_BLOCK,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtCreateTimer(
    TimerHandle: *std.os.windows.HANDLE,
    DesiredAccess: std.os.windows.ACCESS_MASK,
    ObjectAttributes: ?*const anyopaque,
    TimerType: std.os.windows.TIMER_TYPE,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtSetTimer(
    TimerHandle: std.os.windows.HANDLE,
    DueTime: *const std.os.windows.LARGE_INTEGER,
    TimerApcRoutine: ?*anyopaque,
    TimerContext: ?*anyopaque,
    ResumeTimer: std.os.windows.BOOLEAN,
    Period: std.os.windows.LONG,
    PreviousState: ?*std.os.windows.BOOLEAN,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtCancelTimer(
    TimerHandle: std.os.windows.HANDLE,
    CurrentState: ?*std.os.windows.BOOLEAN,
) callconv(.winapi) std.os.windows.NTSTATUS;

/// `WSAID_MULTIPLE_RIO` from `mswsock.h`: `8509e081-96dd-4005-b165-9e2ee8c79e3f`.
pub const RioGuid = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

pub const rio_guid: RioGuid = .{
    .data1 = 0x8509e081,
    .data2 = 0x96dd,
    .data3 = 0x4005,
    .data4 = .{ 0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f },
};

/// `_WSAIORW(IOC_WS2, 36)` = `IOC_INOUT | IOC_WS2 | 36`.
pub const sio_get_multiple_rio: u32 = 0xC8000024;
pub const wsa_flag_overlapped: u32 = 0x01;
pub const wsa_flag_registered_io: u32 = 0x100;
pub const wsa_af_inet: i32 = 2;
pub const wsa_sock_stream: i32 = 1;
pub const wsa_ipproto_tcp: i32 = 6;

/// One pointer from `RIO_EXTENSION_FUNCTION_TABLE`. Opaque because this daemon
/// does not call `RIOReceive` or `RIOSend`; Windows recv and send stay on
/// `NtReadFile` / `NtWriteFile`.
pub const RioFn = ?*anyopaque;

/// Userspace image of `RIO_EXTENSION_FUNCTION_TABLE`. On 64-bit Windows the
/// `u32` size is padded to the first pointer, then thirteen pointers: 112 bytes.
pub const RioTable = extern struct {
    cb_size: u32 = 0,
    receive: RioFn = null,
    receive_ex: RioFn = null,
    send: RioFn = null,
    send_ex: RioFn = null,
    close_completion_queue: RioFn = null,
    create_completion_queue: RioFn = null,
    create_request_queue: RioFn = null,
    dequeue_completion: RioFn = null,
    deregister_buffer: RioFn = null,
    notify: RioFn = null,
    register_buffer: RioFn = null,
    resize_completion_queue: RioFn = null,
    resize_request_queue: RioFn = null,
};

comptime {
    if (@sizeOf(RioGuid) != 16) @compileError("WSAID_MULTIPLE_RIO is 16 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(RioTable) != 112) {
        @compileError(std.fmt.comptimePrint(
            "RIO_EXTENSION_FUNCTION_TABLE is {d} bytes, want 112",
            .{@sizeOf(RioTable)},
        ));
    }
}

const rio_fields = [_][]const u8{
    "receive",
    "receive_ex",
    "send",
    "send_ex",
    "close_completion_queue",
    "create_completion_queue",
    "create_request_queue",
    "dequeue_completion",
    "deregister_buffer",
    "notify",
    "register_buffer",
    "resize_completion_queue",
    "resize_request_queue",
};

/// True only when `cbSize` is the struct size and every required pointer is set.
/// A zero table, a short `cbSize`, or any null function is unusable.
pub fn rioTableUsable(table: *const RioTable) bool {
    if (table.cb_size != @sizeOf(RioTable)) return false;
    inline for (rio_fields) |name| {
        if (@field(table, name) == null) return false;
    }
    return true;
}

/// Loads the RIO table for an existing socket. Socket `0` and `INVALID_SOCKET`
/// fail before `WSAIoctl`. Every non-Windows host fails before `WSAIoctl`.
pub fn loadRegisteredIo(socket: usize) !RioTable {
    if (socket == 0 or socket == std.math.maxInt(usize)) return error.MissingOp;
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    return ioctlRegisteredIo(socket);
}

/// Socket plus table load used by `Iocp.open`. Off Windows this is `MissingOp`
/// and does not call Winsock. The probe socket is closed; the function
/// pointers are what open keeps. `WSACleanup` is not called.
fn loadRioForDaemon() !RioTable {
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    std.mem.doNotOptimizeAway(&loadRegisteredIo);
    const sock = try openRegisteredSocket();
    defer closeRegisteredSocket(sock);
    const table = try loadRegisteredIo(sock);
    if (!rioTableUsable(&table)) return error.MissingOp;
    return table;
}

fn openRegisteredSocket() !usize {
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    if (comptime @sizeOf(usize) != 8) return error.MissingOp;
    // `WSADATA` on Win64 is 408 bytes. The bytes are not interpreted.
    var startup: [408]u8 = @splat(0);
    const started = WSAStartup(0x0202, &startup);
    if (started != 0) return error.MissingOp;
    const sock = WSASocketW(
        wsa_af_inet,
        wsa_sock_stream,
        wsa_ipproto_tcp,
        null,
        0,
        wsa_flag_overlapped | wsa_flag_registered_io,
    );
    if (sock == 0 or sock == std.math.maxInt(usize)) return error.MissingOp;
    return sock;
}

fn closeRegisteredSocket(socket: usize) void {
    if (comptime builtin.os.tag != .windows) return;
    if (socket == 0 or socket == std.math.maxInt(usize)) return;
    _ = closesocket(socket);
}

fn ioctlRegisteredIo(socket: usize) !RioTable {
    var table = RioTable{ .cb_size = @intCast(@sizeOf(RioTable)) };
    var bytes: u32 = 0;
    const rc = WSAIoctl(
        socket,
        sio_get_multiple_rio,
        &rio_guid,
        @sizeOf(RioGuid),
        &table,
        @intCast(@sizeOf(RioTable)),
        &bytes,
        null,
        null,
    );
    if (rc != 0) return error.MissingOp;
    if (bytes < @sizeOf(RioTable)) return error.MissingOp;
    if (!rioTableUsable(&table)) return error.MissingOp;
    return table;
}

extern "ws2_32" fn WSAStartup(
    version_requested: u16,
    data: *anyopaque,
) callconv(.winapi) i32;

extern "ws2_32" fn WSASocketW(
    address_family: i32,
    socket_type: i32,
    protocol: i32,
    protocol_info: ?*anyopaque,
    group: u32,
    flags: u32,
) callconv(.winapi) usize;

extern "ws2_32" fn WSAIoctl(
    socket: usize,
    control_code: u32,
    in_buffer: ?*const anyopaque,
    in_bytes: u32,
    out_buffer: ?*anyopaque,
    out_bytes: u32,
    bytes_returned: *u32,
    overlapped: ?*anyopaque,
    completion: ?*anyopaque,
) callconv(.winapi) i32;

extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;

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

    var closed_iocp = IoBackend.closed(.iocp, 32);
    defer closed_iocp.deinit();
    try std.testing.expectError(error.MissingOp, closed_iocp.requireAll());
    for (required_ops) |op| try std.testing.expect(!closed_iocp.opImplemented(op));
    try std.testing.expectEqual(Iocp.ioctl_afd_wait_for_listen, @as(u32, 0x1200c));
    try std.testing.expectEqual(Iocp.ioctl_afd_poll, @as(u32, 0x12024));
    var send_bytes = [_]u8{'x'};
    try std.testing.expectError(error.MissingOp, closed_iocp.accept(token, fd));
    try std.testing.expectError(error.MissingOp, closed_iocp.recv(token, fd, &buf));
    try std.testing.expectError(error.MissingOp, closed_iocp.send(token, fd, &send_bytes));
    try std.testing.expectError(error.MissingOp, closed_iocp.poll(token, fd, linux.POLL.IN));
    try std.testing.expectError(error.MissingOp, closed_iocp.cancel(.recv, token));
    try std.testing.expectError(error.MissingOp, closed_iocp.timeout(token, &ts));
    const iocp_packets = [_]Iocp.Packet{
        .{ .op = Iocp.op_accept, .handle = fd_ident, .token = token_key, .ioctl = Iocp.ioctl_afd_wait_for_listen },
        .{ .op = Iocp.op_recv, .handle = fd_ident, .length = buf.len, .token = token_key, .buf = @intFromPtr(&buf) },
        .{ .op = Iocp.op_send, .handle = fd_ident, .length = 1, .token = token_key, .buf = @intFromPtr(&send_bytes) },
        .{ .op = Iocp.op_poll, .handle = fd_ident, .length = linux.POLL.IN, .token = token_key, .ioctl = Iocp.ioctl_afd_poll },
        .{ .op = Iocp.op_cancel, .handle = fd_ident, .length = Iocp.op_recv, .token = token_key },
        .{ .op = Iocp.op_timeout, .length = 60_000, .token = token_key },
    };
    for (iocp_packets, 0..) |want, index| {
        const got = try closed_iocp.describedPacket(index);
        try std.testing.expectEqual(want.op, got.op);
        try std.testing.expectEqual(want.handle, got.handle);
        try std.testing.expectEqual(want.length, got.length);
        try std.testing.expectEqual(want.token, got.token);
        try std.testing.expectEqual(want.ioctl, got.ioctl);
        try std.testing.expectEqual(want.buf, got.buf);
    }
    const iocp_n = closed_iocp.iocp.?.n;
    try std.testing.expectError(error.MissingOp, closed_iocp.poll(token, fd, 0));
    try std.testing.expectError(error.MissingOp, closed_iocp.cancel(.other, token));
    try std.testing.expectError(error.MissingOp, closed_iocp.cancel(.poll, token));
    try std.testing.expectEqual(iocp_n, closed_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, closed_iocp.submit());
    try std.testing.expectEqual(iocp_n, closed_iocp.iocp.?.n);
    try std.testing.expectError(error.Usr2Refused, closed_iocp.refuseCapsule(allocator, encoded));

    var one_iocp = IoBackend.closed(.iocp, 1);
    defer one_iocp.deinit();
    try std.testing.expectError(error.MissingOp, one_iocp.accept(token, fd));
    try std.testing.expectEqual(@as(u16, 1), one_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, one_iocp.recv(token, fd, &buf));
    try std.testing.expectEqual(@as(u16, 1), one_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, one_iocp.describedPacket(1));
    const before_iocp_bad = closed_iocp.iocp.?.n;
    try std.testing.expectError(error.MissingOp, closed_iocp.timeout(token, &bad_ts));
    try std.testing.expectEqual(before_iocp_bad, closed_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, closed_iocp.accept(token, -1));
    try std.testing.expectEqual(before_iocp_bad, closed_iocp.iocp.?.n);

    try std.testing.expectError(error.Usr2Refused, live.refuseCapsule(allocator, encoded));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.windows, 32));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.freebsd, 32));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.linux, live.entries));
    try std.testing.expectError(error.Unsupported, refuseForeignCapsule());
    if (comptime builtin.os.tag == .freebsd) try Kqueue.exerciseLive();
    if (comptime builtin.os.tag == .windows) try Iocp.exerciseLive();

    std.debug.print("GAP-X1 branch=linux ring queued six ops; this host did not execute kqueue or IOCP; closed kqueue describes FreeBSD filters; closed IOCP describes AFD wait-for-listen and AFD poll and returns MissingOp; portable init refuses; USR2 capsule refused\n", .{});
}

test "GAP-X3 Windows RIO fails closed off Windows" {
    const ioc_inout: u32 = 0x80000000 | 0x40000000;
    const ioc_ws2: u32 = 0x08000000;
    try std.testing.expectEqual(ioc_inout | ioc_ws2 | 36, sio_get_multiple_rio);
    try std.testing.expectEqual(@as(u32, 0xC8000024), sio_get_multiple_rio);
    try std.testing.expectEqual(@as(u32, 0x01), wsa_flag_overlapped);
    try std.testing.expectEqual(@as(u32, 0x100), wsa_flag_registered_io);
    try std.testing.expectEqual(@as(u32, 0x101), wsa_flag_overlapped | wsa_flag_registered_io);
    try std.testing.expectEqual(@as(i32, 2), wsa_af_inet);
    try std.testing.expectEqual(@as(i32, 1), wsa_sock_stream);
    try std.testing.expectEqual(@as(i32, 6), wsa_ipproto_tcp);
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(RioGuid));
    try std.testing.expectEqual(@as(usize, 112), @sizeOf(RioTable));
    const guid_bytes = std.mem.asBytes(&rio_guid);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x81, 0xe0, 0x09, 0x85, 0xdd, 0x96, 0x05, 0x40,
        0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f,
    }, guid_bytes);

    const zero = RioTable{};
    try std.testing.expect(!rioTableUsable(&zero));
    const ptr: RioFn = @as(*anyopaque, @ptrFromInt(1));
    var full = RioTable{ .cb_size = @intCast(@sizeOf(RioTable)) };
    inline for (rio_fields) |name| @field(full, name) = ptr;
    try std.testing.expect(rioTableUsable(&full));
    inline for (rio_fields) |name| {
        const saved = @field(full, name);
        @field(full, name) = null;
        try std.testing.expect(!rioTableUsable(&full));
        @field(full, name) = saved;
    }
    try std.testing.expect(rioTableUsable(&full));
    full.cb_size = @intCast(@sizeOf(RioTable) - 1);
    try std.testing.expect(!rioTableUsable(&full));

    const unopened = Iocp.unopened(32);
    try std.testing.expectEqual(@as(usize, 0), unopened.port);
    try std.testing.expect(!rioTableUsable(&unopened.rio));
    try std.testing.expectError(error.MissingOp, Iocp.open(0));
    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.iocp, 32, .{}));
    try std.testing.expectError(error.MissingOp, loadRegisteredIo(0));
    try std.testing.expectError(error.MissingOp, loadRegisteredIo(std.math.maxInt(usize)));
    try std.testing.expectError(error.MissingOp, loadRegisteredIo(1));
    try std.testing.expectError(error.MissingOp, loadRioForDaemon());
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.windows, 32));

    std.debug.print("GAP-X3 branch=windows RIO loads the function table with WSAIoctl SIO 0xC8000024 and GUID 8509e081-96dd-4005-b165-9e2ee8c79e3f on a WSA_FLAG_REGISTERED_IO socket during Iocp.open; a null or short table is MissingOp and the port is closed; off Windows this returns MissingOp before any WSA call; recv and send stay NtReadFile and NtWriteFile; this host did not execute WSAIoctl; heading stays unmarked; whole-accept not claimed\n", .{});
}
