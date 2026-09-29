// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! I/O backend for accept, recv, send, poll, cancel, and timeout.
//!
//! Linux keeps today's Ringlane ring (`ringlane.zig`). FreeBSD, OpenBSD,
//! NetBSD, and Dragonfly implement the same operations on a kqueue fd.
//! Windows implements them on an I/O completion port: AFD receive and send,
//! AFD wait-for-listen and AFD poll, `NtCancelIoFileEx`, and an NT timer.
//! `Iocp.open` loads the Winsock Registered I/O function table and returns
//! `error.MissingOp` when that table is missing. `dequeueRegistered` is what
//! calls those pointers. `reap` finishes accept, recv, and send: the ring
//! reports the completion, kqueue performs the syscall, and IOCP collects
//! `NtRemoveIoCompletion` then `accept`s a waited listen. A missing op, a
//! closed port or queue, or a kernel status other than success or pending
//! returns `error.MissingOp` and is not reported as a finished transfer.
//! Helix USR2 adoption stays on `LinuxServer`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const ringlane = @import("ringlane.zig");
const capsule = @import("helix/capsule.zig");

const Allocator = std.mem.Allocator;

pub const Family = enum { ringlane, iocp, kqueue };

pub const Op = enum { accept, recv, send, poll, cancel, timeout };

pub const required_ops = [_]Op{ .accept, .recv, .send, .poll, .cancel, .timeout };

/// One finished accept, recv, send, poll, or timeout from `reap`.
/// `result` is the new socket for accept, the byte count for recv and send,
/// or a negative errno. Timeout uses `0`.
pub const Reaped = struct {
    op: Op,
    token: ringlane.FdToken,
    result: i32,
};

pub const Listener = struct {
    fd: linux.fd_t,
    port: u16,
};

pub const ListenError = error{ InvalidAddress, SocketUnavailable, AddressInUse, PermissionDenied, Unsupported };

/// One `RIODequeueCompletion` against the table `Iocp.open` stored.
/// `ok` is true only when that call returned a 4-byte success and the peer
/// socket read those same bytes. A closed port, a non-Windows host, or a
/// kernel error leaves `ok` false and names the failing `stage`.
pub const RioWitness = struct {
    ok: bool = false,
    stage: []const u8 = "",
    count: u32 = 0,
    status: i32 = 0,
    bytes: u32 = 0,
    errno: i32 = 0,
};

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
            .kqueue => return (try self.kqueuePtr()).enqueueRecv(token, fd, buffer),
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
            .kqueue => return (try self.kqueuePtr()).enqueueSend(token, fd, buffer),
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

    /// kqueue stays armed after a successful submit. The ring and IOCP post
    /// one operation and the caller queues the next one.
    pub fn levelTriggered(self: *const IoBackend) bool {
        return self.family == .kqueue;
    }

    pub fn queueFd(self: *const IoBackend) linux.fd_t {
        if (self.kq) |kq| return kq.fd;
        return -1;
    }

    /// Wait up to `wait_ms` for completions. `0` does not block. A closed
    /// backend is `error.MissingOp`. An empty wait is `0`, not a transfer.
    pub fn reap(self: *IoBackend, out: []Reaped, wait_ms: u32) !u32 {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).reap(out, wait_ms),
            .iocp => return (try self.iocpPtr()).reap(out, wait_ms),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                return self.reapRing(out, wait_ms);
            },
        }
    }

    fn reapRing(self: *IoBackend, out: []Reaped, wait_ms: u32) !u32 {
        const ring = self.ringPtr() orelse return error.MissingOp;
        var cqes: [32]linux.io_uring_cqe = undefined;
        const Sink = struct {
            dest: []Reaped,
            n: usize = 0,

            pub fn onCompletion(sink: *@This(), completion: ringlane.Completion) void {
                if (sink.n >= sink.dest.len) return;
                const item: ?Reaped = switch (completion) {
                    .accept => |ev| .{ .op = .accept, .token = ev.token, .result = ev.res },
                    .recv => |ev| .{ .op = .recv, .token = ev.token, .result = ev.res },
                    .send => |ev| .{ .op = .send, .token = ev.token, .result = ev.res },
                    .poll => |ev| .{ .op = .poll, .token = ev.token, .result = ev.res },
                    .timeout => .{ .op = .timeout, .token = .{ .slot = 0, .gen = 0 }, .result = 0 },
                    .connect, .other => null,
                };
                if (item) |got| {
                    sink.dest[sink.n] = got;
                    sink.n += 1;
                }
            }
        };
        var sink = Sink{ .dest = out };
        const wait_nr: u32 = if (wait_ms == 0) 0 else 1;
        try ring.reapCompletions(cqes[0..@min(cqes.len, @max(out.len, 1))], wait_nr, &sink);
        return @intCast(sink.n);
    }

    /// Send four bytes through the Registered I/O table stored on this port
    /// and dequeue that send. This does not issue a second `WSAIoctl`. Off
    /// Windows, and on a port whose table was not loaded, it returns before
    /// any function pointer is called.
    pub fn dequeueRegistered(self: *IoBackend) RioWitness {
        if (comptime builtin.os.tag != .windows) return .{ .stage = "off-windows" };
        const iocp = self.iocp orelse return .{ .stage = "closed" };
        if (iocp.port == 0 or !rioTableUsable(&iocp.rio)) return .{ .stage = "closed" };
        return dequeueLoadedRio(&iocp.rio);
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

/// Opens the native backend and requires every op. A missing op is
/// `error.Unsupported`. The Linux ring used by `LinuxServer` is `openLinuxRing`.
pub fn refusePortableReactor(tag: std.Target.Os.Tag, entries: u16) error{Unsupported}!void {
    var backend = IoBackend.openOwned(familyFor(tag), entries, .{}) catch return error.Unsupported;
    defer backend.deinit();
    backend.requireAll() catch return error.Unsupported;
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

fn kqueueOs() bool {
    return switch (builtin.os.tag) {
        .freebsd, .openbsd, .netbsd, .dragonfly => true,
        else => false,
    };
}

/// kqueue on FreeBSD, OpenBSD, NetBSD, and Dragonfly. One `kevent` submit is
/// at most `submit_batch` changes; that bound is the syscall batch, not a
/// connection ceiling. Registrations grow. A closed queue, a full batch, an
/// unknown cancel, or a `kevent` error returns `error.MissingOp`.
///
/// FreeBSD submit ORs `EV_RECEIPT` and requires one zero-error receipt per
/// change. The other three apply the change list with `nevents == 0` and
/// treat a zero return as success. `EV_RECEIPT` is not set there. libc calls
/// sit in functions that are not analyzed unless `kqueueOs()` is true, so
/// the Linux daemon does not link libc.
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
        kind: ringlane.OpKind = .other,
        buf_ptr: usize = 0,
        len: usize = 0,
    };

    pub fn unopened(entries: u16) Kqueue {
        return .{ .fd = -1, .cap = batchCap(entries) };
    }

    pub fn open(entries: u16) !Kqueue {
        if (entries == 0) return error.MissingOp;
        if (comptime !kqueueOs()) return error.MissingOp;
        return .{ .fd = try openFd(), .cap = batchCap(entries) };
    }

    pub fn deinit(self: *Kqueue) void {
        if (comptime kqueueOs()) self.closeQueue();
        self.fd = -1;
        self.n = 0;
        if (self.regs.len != 0) {
            std.heap.page_allocator.free(self.regs);
            self.regs = &.{};
        }
    }

    pub fn enqueueAccept(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t) !void {
        return self.enqueueFilter(token, fd, evfilt_read, ev_add | ev_enable, 0, false, .accept, "");
    }

    pub fn enqueueRecv(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
        if (buffer.len == 0) return error.MissingOp;
        return self.enqueueFilter(token, fd, evfilt_read, ev_add | ev_enable, 0, false, .recv, buffer);
    }

    pub fn enqueueSend(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        if (buffer.len == 0) return error.MissingOp;
        return self.enqueueFilter(token, fd, evfilt_write, ev_add | ev_enable, 0, false, .send, buffer);
    }

    pub fn enqueuePoll(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        if (poll_mask == 0) return error.MissingOp;
        const filter: i16 = if ((poll_mask & linux.POLL.OUT) != 0) evfilt_write else evfilt_read;
        return self.enqueueFilter(token, fd, filter, ev_add | ev_enable, 0, false, .poll, "");
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
        return self.enqueueFilter(token, 0, evfilt_timer, ev_add | ev_oneshot, ms, true, .timeout, "");
    }

    pub fn submit(self: *Kqueue) !u32 {
        if (self.fd < 0 or self.n == 0) return error.MissingOp;
        if (comptime builtin.os.tag == .freebsd) return self.submitFreeBsd();
        if (comptime builtin.os.tag == .openbsd or builtin.os.tag == .netbsd or builtin.os.tag == .dragonfly) {
            return self.submitAck();
        }
        return error.MissingOp;
    }

    pub fn reap(self: *Kqueue, out: []Reaped, wait_ms: u32) !u32 {
        if (self.fd < 0) return error.MissingOp;
        if (comptime !kqueueOs()) return error.MissingOp;
        return self.reapNative(out, wait_ms);
    }

    fn enqueueFilter(
        self: *Kqueue,
        token: ringlane.FdToken,
        fd: linux.fd_t,
        filter: i16,
        flags: u16,
        data: i64,
        timer: bool,
        kind: ringlane.OpKind,
        buf: []const u8,
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
        try self.remember(change, kind, if (buf.len == 0) 0 else @intFromPtr(buf.ptr), buf.len);
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

    fn remember(self: *Kqueue, change: Change, kind: ringlane.OpKind, buf_ptr: usize, len: usize) !void {
        var i: usize = 0;
        while (i < self.regs.len) : (i += 1) {
            if (self.regs[i].live and self.regs[i].token == change.udata and self.regs[i].filter == change.filter) {
                self.regs[i].ident = change.ident;
                self.regs[i].kind = kind;
                self.regs[i].buf_ptr = buf_ptr;
                self.regs[i].len = len;
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
                    .kind = kind,
                    .buf_ptr = buf_ptr,
                    .len = len,
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
            .kind = kind,
            .buf_ptr = buf_ptr,
            .len = len,
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

    fn closeQueue(self: *Kqueue) void {
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

    fn fillKevent(change: Change) std.c.Kevent {
        var ev = std.mem.zeroes(std.c.Kevent);
        ev.ident = change.ident;
        ev.filter = @intCast(change.filter);
        ev.flags = @intCast(change.flags);
        ev.fflags = @intCast(change.fflags);
        ev.data = @intCast(change.data);
        ev.udata = change.udata;
        return ev;
    }

    fn submitAck(self: *Kqueue) !u32 {
        const n_changes: usize = self.n;
        if (n_changes == 0 or n_changes > submit_batch) return error.MissingOp;
        var batch: [submit_batch]std.c.Kevent = undefined;
        var i: usize = 0;
        while (i < n_changes) : (i += 1) batch[i] = fillKevent(self.changes[i]);
        self.n = 0;
        var out: [1]std.c.Kevent = undefined;
        const timeout = std.c.timespec{ .sec = 0, .nsec = 0 };
        const rc = std.c.kevent(self.fd, &batch, @intCast(n_changes), &out, 0, &timeout);
        if (rc != 0) return error.MissingOp;
        return @intCast(n_changes);
    }

    fn reapNative(self: *Kqueue, out: []Reaped, wait_ms: u32) !u32 {
        var evs: [32]std.c.Kevent = undefined;
        const max: usize = @min(out.len, evs.len);
        if (max == 0) return 0;
        var none: [1]std.c.Kevent = .{std.mem.zeroes(std.c.Kevent)};
        const ts = std.c.timespec{
            .sec = @intCast(wait_ms / 1000),
            .nsec = @intCast(@as(u64, wait_ms % 1000) * 1_000_000),
        };
        const rc = std.c.kevent(self.fd, &none, 0, &evs, @intCast(max), &ts);
        if (rc < 0) return error.MissingOp;
        const got: usize = @intCast(rc);
        var n: usize = 0;
        var i: usize = 0;
        while (i < got and n < out.len) : (i += 1) {
            const ev = evs[i];
            const filter: i16 = @intCast(ev.filter);
            const flags: u16 = @truncate(ev.flags);
            const data: i64 = @intCast(ev.data);
            const token = unpackToken(ev.udata);
            if ((flags & ev_error) != 0) {
                const errno: i32 = if (data > 0 and data <= std.math.maxInt(i32)) @intCast(data) else 1;
                out[n] = .{ .op = opForFilter(filter), .token = token, .result = -errno };
                n += 1;
                continue;
            }
            if (filter == evfilt_timer) {
                out[n] = .{ .op = .timeout, .token = token, .result = 0 };
                n += 1;
                continue;
            }
            const reg = self.findReg(ev.udata, filter);
            if (filter == evfilt_read) {
                if (reg) |slot| {
                    if (slot.kind == .accept) {
                        out[n] = .{ .op = .accept, .token = token, .result = self.acceptReady(ev.ident) };
                        n += 1;
                        continue;
                    }
                }
                out[n] = .{ .op = .recv, .token = token, .result = transfer(.recv, ev.ident, reg) };
                n += 1;
                continue;
            }
            if (filter == evfilt_write) {
                out[n] = .{ .op = .send, .token = token, .result = transfer(.send, ev.ident, reg) };
                self.deleteFilter(ev.ident, filter);
                if (reg) |slot| slot.live = false;
                n += 1;
            }
        }
        return @intCast(n);
    }

    fn acceptReady(self: *Kqueue, ident: usize) i32 {
        _ = self;
        const listened: i32 = @intCast(ident);
        const fd = std.c.accept(listened, null, null);
        if (fd < 0) return -positiveErrno();
        if (!setNonBlock(fd)) {
            _ = std.c.close(fd);
            return -1;
        }
        return fd;
    }

    fn deleteFilter(self: *Kqueue, ident: usize, filter: i16) void {
        var batch: [1]std.c.Kevent = .{fillKevent(.{
            .ident = ident,
            .filter = filter,
            .flags = ev_delete,
        })};
        var out: [1]std.c.Kevent = undefined;
        const timeout = std.c.timespec{ .sec = 0, .nsec = 0 };
        _ = std.c.kevent(self.fd, &batch, 1, &out, 0, &timeout);
    }

    fn findReg(self: *Kqueue, token: usize, filter: i16) ?*Reg {
        var i: usize = self.regs.len;
        while (i > 0) {
            i -= 1;
            if (self.regs[i].live and self.regs[i].token == token and self.regs[i].filter == filter) return &self.regs[i];
        }
        return null;
    }

    fn unpackToken(key: usize) ringlane.FdToken {
        return .{ .slot = @truncate(key), .gen = @truncate(key >> 32) };
    }

    fn opForFilter(filter: i16) Op {
        if (filter == Kqueue.evfilt_write) return .send;
        if (filter == Kqueue.evfilt_timer) return .timeout;
        return .recv;
    }

    fn positiveErrno() i32 {
        const err = std.c._errno().*;
        if (err <= 0) return 1;
        return err;
    }

    fn setNonBlock(fd: i32) bool {
        // F_GETFL = 3, F_SETFL = 4, O_NONBLOCK = 4 on these BSDs.
        const flags = std.c.fcntl(fd, @as(i32, 3), @as(i32, 0));
        if (flags < 0) return false;
        return std.c.fcntl(fd, @as(i32, 4), flags | @as(@TypeOf(flags), 4)) >= 0;
    }

    fn transfer(kind: ringlane.OpKind, ident: usize, reg: ?*Reg) i32 {
        const slot = reg orelse return -1;
        if (slot.buf_ptr == 0 or slot.len == 0) return -1;
        const fd: i32 = @intCast(ident);
        var done: usize = 0;
        while (done < slot.len) {
            const ptr: [*]u8 = @ptrFromInt(slot.buf_ptr + done);
            const n: isize = if (kind == .recv)
                std.c.recv(fd, ptr, slot.len - done, 0)
            else
                std.c.send(fd, ptr, slot.len - done, 0);
            if (n < 0) {
                const err = std.c._errno().*;
                if (err == 4) continue;
                if (err == 35) {
                    if (done == 0) return -35;
                    break;
                }
                if (done == 0) return if (err == 0) -1 else -err;
                break;
            }
            if (n == 0) break;
            done += @intCast(n);
            if (kind == .recv) break;
        }
        if (done > std.math.maxInt(i32)) return std.math.maxInt(i32);
        return @intCast(done);
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
            if (comptime kqueueOs()) _ = std.c.close(sock);
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
        if (listenTcp("127.0.0.1", 0)) |listener| {
            closeSocket(listener.fd);
        } else |_| {}
    }
};

/// Windows completion port. One submit posts at most `submit_batch` kernel
/// requests; that bound is the batch, not a connection ceiling. A closed
/// port, a full batch, an unknown cancel, or a status other than success,
/// pending, or a closed connection returns `error.MissingOp`. A closed
/// connection is that operation's result and does not stop the listener.
///
/// Accept is AFD wait-for-listen (`0x1200C`) completed by `IOCTL_AFD_ACCEPT`
/// (`0x12010`) onto a new socket. Poll is AFD select (`0x12024`). The packing
/// is `(FILE_DEVICE_NETWORK << 12) | (operation << 2) | method`. Recv and
/// send are `IOCTL_AFD_RECEIVE` / `IOCTL_AFD_SEND` (`0x12017` / `0x1201F`).
/// A raw `NtReadFile` on an AFD socket returns `STATUS_INVALID_PARAMETER`.
/// Timeout arms an NT timer and does not synthesize a completion packet.
/// `STATUS_SUCCESS` is a finished AFD operation and `reap` returns it before
/// waiting. `STATUS_PENDING` is reported only from `NtRemoveIoCompletion`.
/// A duplicate port packet for that slot is discarded. Winsock `accept`
/// after wait-for-listen returns `WSAEWOULDBLOCK` or a socket whose first
/// receive is `STATUS_CONNECTION_RESET`, so the sequence from the wait is
/// what adopts the connection.
///
/// Open also loads `RIO_EXTENSION_FUNCTION_TABLE` through `WSAIoctl`. A failed
/// or partial table closes the new port and returns `error.MissingOp`.
/// `dequeueRegistered` calls that stored table; nothing else does.
///
/// `ntdll` and `ws2_32` calls sit in functions that are not analyzed unless
/// `builtin.os.tag == .windows`. This Linux host does not execute them.
///
/// `AFD_POLL_INFO` for one handle. `exclusive` is the `BOOLEAN Unique` byte
/// plus the three padding bytes AFD.sys expects before the handle (mio layout).
const AfdPollHandle = extern struct {
    handle: usize,
    events: u32,
    status: i32,
};

const AfdPollInfo = extern struct {
    timeout: i64,
    handle_count: u32,
    exclusive: u32,
    handles: AfdPollHandle,
};

/// `WSABUF` and `AFD_RECV_INFO` / `AFD_SEND_INFO`. The pointer inside the
/// info struct must stay valid until the request completes.
const AfdWsaBuf = extern struct {
    len: u32,
    buf: [*]u8,
};

const AfdDataInfo = extern struct {
    buffers: *AfdWsaBuf,
    count: u32,
    afd_flags: u32,
    tdi_flags: u32,
};

/// `AFD_ACCEPT_INFO`. `SanActive` is a `BOOLEAN` followed by padding so
/// `Sequence` is at offset 4 and `AcceptHandle` is at offset 8. A zero flag
/// has the same first four bytes as a `ULONG` flag.
const AfdAcceptInfo = extern struct {
    san_active: u8,
    sequence: i32,
    accept_handle: usize,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(AfdPollInfo) != 32) @compileError("AFD_POLL_INFO is 32 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(AfdWsaBuf) != 16) @compileError("WSABUF is 16 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(AfdDataInfo) != 24) @compileError("AFD_RECV_INFO is 24 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(AfdAcceptInfo) != 16) @compileError("AFD_ACCEPT_INFO is 16 bytes");
    if (@offsetOf(AfdAcceptInfo, "sequence") != 4) @compileError("AFD_ACCEPT_INFO sequence");
    if (@offsetOf(AfdAcceptInfo, "accept_handle") != 8) @compileError("AFD_ACCEPT_INFO handle");
}

const Iocp = struct {
    port: usize = 0,
    cap: u16 = 0,
    n: u16 = 0,
    /// Empty unless `open` stored a table `rioTableUsable` accepted.
    rio: RioTable = .{},
    packets: [submit_batch]Packet = @splat(.{}),
    regs: []Reg = &.{},
    armed: []usize = &.{},
    /// Handles already associated with `port`. A second association fails.
    bound: []usize = &.{},
    /// Live for the life of the port. A pending NT request writes these after
    /// `postOne` returns; a stack copy would dangle.
    iosbs: [submit_batch]std.os.windows.IO_STATUS_BLOCK = undefined,
    /// In-flight AFD ops. A slot stays live until `reap` collects its IOSB.
    /// `submit_batch` is the in-flight batch, not a connection ceiling.
    slot_live: [submit_batch]bool = @splat(false),
    slot_pkt: [submit_batch]Packet = @splat(.{}),
    poll_infos: [submit_batch]AfdPollInfo = undefined,
    wsa_bufs: [submit_batch]AfdWsaBuf = undefined,
    data_infos: [submit_batch]AfdDataInfo = undefined,
    /// `AFD_LISTEN_RESPONSE_INFO_TL` is a sequence plus a `SOCKADDR`.
    accept_outs: [submit_batch][128]u8 = undefined,
    /// Finished before the port wait. One slot, one result; this is not a
    /// connection ceiling.
    ready: [submit_batch]Reaped = undefined,
    ready_head: u16 = 0,
    ready_n: u16 = 0,

    pub const submit_batch = 256;

    pub const op_accept: u8 = 1;
    pub const op_recv: u8 = 2;
    pub const op_send: u8 = 3;
    pub const op_timeout: u8 = 4;
    pub const op_poll: u8 = 6;
    pub const op_cancel: u8 = 7;

    /// FILE_DEVICE_NETWORK is 0x12. AFD wait-for-listen is operation 3,
    /// METHOD_BUFFERED. AFD receive is operation 5 and AFD send is operation
    /// 7, both METHOD_NEITHER. AFD select (poll) is operation 9, METHOD_BUFFERED.
    pub const ioctl_afd_wait_for_listen: u32 = (0x12 << 12) | (3 << 2) | 0;
    pub const ioctl_afd_accept: u32 = (0x12 << 12) | (4 << 2) | 0;
    pub const ioctl_afd_receive: u32 = (0x12 << 12) | (5 << 2) | 3;
    pub const ioctl_afd_send: u32 = (0x12 << 12) | (7 << 2) | 3;
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
        if (self.bound.len != 0) {
            std.heap.page_allocator.free(self.bound);
            self.bound = &.{};
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
            .ioctl = ioctl_afd_receive,
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
            .ioctl = ioctl_afd_send,
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

    pub fn reap(self: *Iocp, out: []Reaped, wait_ms: u32) !u32 {
        if (self.port == 0) return error.MissingOp;
        if (comptime builtin.os.tag != .windows) return error.MissingOp;
        return self.reapWindows(out, wait_ms);
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
        while (self.popReady()) |ev| {
            if (ev.op == .accept and ev.result >= 0) _ = closesocket(@intCast(ev.result));
        }
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
        var need: u16 = 0;
        var free_slots: u16 = 0;
        var i: u16 = 0;
        while (i < n_packets) : (i += 1) {
            switch (queued[i].op) {
                op_accept, op_recv, op_send, op_poll => need += 1,
                else => {},
            }
        }
        i = 0;
        while (i < submit_batch) : (i += 1) {
            if (!self.slot_live[i]) free_slots += 1;
        }
        if (need > free_slots) {
            @memcpy(self.packets[0..n_packets], queued[0..n_packets]);
            self.n = n_packets;
            return error.MissingOp;
        }
        i = 0;
        while (i < n_packets) : (i += 1) try self.postOne(queued[i]);
        return n_packets;
    }

    fn claimSlot(self: *Iocp, packet: Packet) !u16 {
        var i: u16 = 0;
        while (i < submit_batch) : (i += 1) {
            if (self.slot_live[i]) continue;
            self.slot_live[i] = true;
            self.slot_pkt[i] = packet;
            self.iosbs[i] = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
            return i;
        }
        return error.MissingOp;
    }

    fn postOne(self: *Iocp, packet: Packet) !void {
        switch (packet.op) {
            op_cancel => return self.cancelOne(packet),
            op_timeout => return self.armTimer(packet),
            op_accept, op_recv, op_send, op_poll => {},
            else => return error.MissingOp,
        }
        if ((packet.op == op_recv or packet.op == op_send) and
            (packet.buf == 0 or packet.length == 0 or packet.ioctl == 0))
        {
            return error.MissingOp;
        }
        const index = try self.claimSlot(packet);
        errdefer self.slot_live[index] = false;
        const iosb = &self.iosbs[index];
        const done = switch (packet.op) {
            op_accept => blk: {
                const out = &self.accept_outs[index];
                @memset(out, 0);
                break :blk try self.device(packet, iosb, "", out);
            },
            op_recv, op_send => blk: {
                if (packet.buf == 0 or packet.length == 0 or packet.ioctl == 0) return error.MissingOp;
                const wsa = &self.wsa_bufs[index];
                wsa.* = .{
                    .len = packet.length,
                    .buf = @ptrFromInt(packet.buf),
                };
                const info = &self.data_infos[index];
                // AFD_OVERLAPPED is 0x2. TDI_RECEIVE_NORMAL is 0x20. Send uses
                // no TDI flag; the kernel rejects a raw NtReadFile / NtWriteFile.
                info.* = .{
                    .buffers = wsa,
                    .count = 1,
                    .afd_flags = 0x2,
                    .tdi_flags = if (packet.op == op_recv) @as(u32, 0x20) else 0,
                };
                var none: [0]u8 = .{};
                break :blk try self.device(packet, iosb, std.mem.asBytes(info), &none);
            },
            op_poll => blk: {
                // AFD poll is METHOD_BUFFERED and reads the handle list from
                // the input. A null input is rejected by the kernel.
                const info = &self.poll_infos[index];
                info.* = .{
                    .timeout = -10_000_000,
                    .handle_count = 1,
                    .exclusive = 0,
                    .handles = .{
                        .handle = packet.handle,
                        .events = packet.length,
                        .status = 0,
                    },
                };
                const bytes = std.mem.asBytes(info);
                break :blk try self.device(packet, iosb, bytes, bytes);
            },
            else => return error.MissingOp,
        };
        if (done) try self.finishInline(index);
    }

    fn finishInline(self: *Iocp, index: u16) !void {
        const packet = self.slot_pkt[index];
        const iosb = self.iosbs[index];
        const ev = finishPosted(packet, iosb, &self.accept_outs[index]);
        self.slot_live[index] = false;
        self.pushReady(ev) catch |err| {
            if (ev.op == .accept and ev.result >= 0) _ = closesocket(@intCast(ev.result));
            return err;
        };
    }

    fn pushReady(self: *Iocp, ev: Reaped) !void {
        if (self.ready_n >= submit_batch) return error.MissingOp;
        const idx = (self.ready_head + self.ready_n) % submit_batch;
        self.ready[idx] = ev;
        self.ready_n += 1;
    }

    fn popReady(self: *Iocp) ?Reaped {
        if (self.ready_n == 0) return null;
        const ev = self.ready[self.ready_head];
        self.ready_head = (self.ready_head + 1) % submit_batch;
        self.ready_n -= 1;
        return ev;
    }

    fn associate(self: *Iocp, handle: usize) !void {
        for (self.bound) |known| {
            if (known == handle) return;
        }
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
        if (status != .SUCCESS) {
            std.debug.print("GAP-X1 windows iocp status=0x{x} op=associate\n", .{@intFromEnum(status)});
            return error.MissingOp;
        }
        const old = self.bound;
        const grown = std.heap.page_allocator.alloc(usize, old.len + 1) catch return error.OutOfMemory;
        if (old.len != 0) {
            @memcpy(grown[0..old.len], old);
            std.heap.page_allocator.free(old);
        }
        grown[old.len] = handle;
        self.bound = grown;
    }

    /// `true` means the ioctl finished inline. The bytes are already in the
    /// caller buffer and `reap` must observe them without waiting for a port
    /// packet that may never arrive.
    fn device(self: *Iocp, packet: Packet, iosb: *std.os.windows.IO_STATUS_BLOCK, in_buf: []const u8, out: []u8) !bool {
        const w = std.os.windows;
        try self.associate(packet.handle);
        iosb.* = std.mem.zeroes(w.IO_STATUS_BLOCK);
        const code: w.CTL_CODE = @bitCast(packet.ioctl);
        const status = w.ntdll.NtDeviceIoControlFile(
            @ptrFromInt(packet.handle),
            null,
            null,
            @ptrCast(iosb),
            iosb,
            code,
            if (in_buf.len == 0) null else @ptrCast(in_buf.ptr),
            @intCast(in_buf.len),
            if (out.len == 0) null else @ptrCast(out.ptr),
            @intCast(out.len),
        );
        if (status == .SUCCESS) return true;
        if (status == .PENDING) return false;
        // One peer reset is that operation's result. MissingOp here ends the
        // listen loop, which is what a reset of the accepted socket did.
        if (closedConnection(status)) {
            iosb.u.Status = status;
            std.debug.print("GAP-X1 windows iocp closed status=0x{x} op={d}\n", .{ @intFromEnum(status), packet.op });
            return true;
        }
        std.debug.print("GAP-X1 windows iocp status=0x{x} op={d}\n", .{ @intFromEnum(status), packet.op });
        return error.MissingOp;
    }

    fn cancelOne(self: *Iocp, packet: Packet) !void {
        const w = std.os.windows;
        if (packet.length == op_timeout) {
            // The timer object exists only after armTimer, which runs earlier
            // in this submit. The enqueue-time registration stores no handle.
            if (self.armed.len == 0) return error.MissingOp;
            const timer = self.armed[self.armed.len - 1];
            if (timer == 0) return error.MissingOp;
            var state: w.BOOLEAN = .FALSE;
            const status = NtCancelTimer(@ptrFromInt(timer), &state);
            if (status != .SUCCESS) {
                std.debug.print("GAP-X1 windows iocp status=0x{x} op={d}\n", .{ @intFromEnum(status), packet.op });
                return error.MissingOp;
            }
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

    fn reapWindows(self: *Iocp, out: []Reaped, wait_ms: u32) !u32 {
        var n: u32 = 0;
        while (n < out.len) {
            const ev = self.popReady() orelse break;
            out[n] = ev;
            n += 1;
        }
        var waited = false;
        var skips: u16 = 0;
        while (n < out.len) {
            const item = self.takeOne(if (waited) 0 else wait_ms) catch |err| switch (err) {
                error.Unmatched => {
                    skips += 1;
                    if (skips > submit_batch) return error.MissingOp;
                    waited = true;
                    continue;
                },
                else => return err,
            };
            waited = true;
            if (item) |got| {
                out[n] = got;
                n += 1;
            } else break;
        }
        return n;
    }

    fn takeOne(self: *Iocp, wait_ms: u32) !?Reaped {
        const w = std.os.windows;
        var key: ?*anyopaque = null;
        var apc: ?*anyopaque = null;
        var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
        var due: w.LARGE_INTEGER = if (wait_ms == 0) 0 else -@as(w.LARGE_INTEGER, wait_ms) * 10_000;
        const status = NtRemoveIoCompletion(@ptrFromInt(self.port), &key, &apc, &iosb, &due);
        if (status == .TIMEOUT) return null;
        if (status != .SUCCESS) return error.MissingOp;
        const apc_addr = @intFromPtr(apc);
        var i: usize = 0;
        while (i < submit_batch) : (i += 1) {
            if (!self.slot_live[i]) continue;
            if (@intFromPtr(&self.iosbs[i]) != apc_addr) continue;
            const packet = self.slot_pkt[i];
            self.slot_live[i] = false;
            return finishPosted(packet, iosb, &self.accept_outs[i]);
        }
        // The port packet was removed. A synchronous success already cleared
        // its slot, so this copy must not stop the rest of the drain.
        return error.Unmatched;
    }

    fn finishPosted(packet: Packet, iosb: std.os.windows.IO_STATUS_BLOCK, accept_out: []const u8) Reaped {
        const token = ringlane.FdToken{
            .slot = @truncate(packet.token),
            .gen = @truncate(packet.token >> 32),
        };
        const op: Op = switch (packet.op) {
            op_accept => .accept,
            op_recv => .recv,
            op_send => .send,
            op_poll => .poll,
            else => .cancel,
        };
        if (iosb.u.Status != .SUCCESS) return .{ .op = op, .token = token, .result = -1 };
        if (packet.op == op_accept) {
            const sock = acceptSequence(packet.handle, accept_out) catch {
                return .{ .op = .accept, .token = token, .result = -1 };
            };
            return .{ .op = .accept, .token = token, .result = sock };
        }
        if (iosb.Information > std.math.maxInt(i32)) {
            return .{ .op = op, .token = token, .result = std.math.maxInt(i32) };
        }
        return .{ .op = op, .token = token, .result = @intCast(iosb.Information) };
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
        if (listenTcp("127.0.0.1", 0)) |listener| {
            closeSocket(listener.fd);
        } else |_| {}
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

/// One pointer from `RIO_EXTENSION_FUNCTION_TABLE`. The daemon calls these
/// only from `dequeueRegistered`. Ordinary accept, recv, and send stay on
/// `IOCTL_AFD_RECEIVE` and `IOCTL_AFD_SEND`.
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

/// `RIO_BUF`. `buffer_id` is the value `RIORegisterBuffer` returned.
const RioBuf = extern struct {
    buffer_id: usize,
    offset: u32,
    length: u32,
};

/// `RIORESULT`. `status` is 0 on success. `request_context` is the pointer
/// value passed to `RIOSend`, not a length the caller invents after the fact.
const RioResult = extern struct {
    status: i32 = -1,
    bytes: u32 = 0,
    socket_context: u64 = 0,
    request_context: u64 = 0,
};

/// `sockaddr_in` for the loopback pair the dequeue uses. 16 bytes.
const RioSockAddr = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

/// `(RIO_BUFFERID)(ULONG_PTR)0xFFFFFFFF` from the Windows SDK.
const rio_invalid_buffer_id: usize = 0xFFFFFFFF;
/// `RIO_CORRUPT_CQ`. A dequeue count of this value is a failed queue, not a transfer.
pub const rio_corrupt_cq: u32 = 0xFFFFFFFF;
/// Opaque `RIOSend` request context. The kernel must copy it into `RIORESULT`.
const rio_request_context: u64 = 0x33554144;
const rio_payload = "RIO!";

comptime {
    if (@sizeOf(RioGuid) != 16) @compileError("WSAID_MULTIPLE_RIO is 16 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(RioTable) != 112) {
        @compileError(std.fmt.comptimePrint(
            "RIO_EXTENSION_FUNCTION_TABLE is {d} bytes, want 112",
            .{@sizeOf(RioTable)},
        ));
    }
    if (@sizeOf(usize) == 8 and @sizeOf(RioBuf) != 16) @compileError("RIO_BUF is 16 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(RioResult) != 24) @compileError("RIORESULT is 24 bytes");
    if (@sizeOf(RioSockAddr) != 16) @compileError("sockaddr_in is 16 bytes");
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

extern "ws2_32" fn bind(socket: usize, addr: *const RioSockAddr, namelen: i32) callconv(.winapi) i32;

extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;

extern "ws2_32" fn getsockname(socket: usize, addr: *RioSockAddr, namelen: *i32) callconv(.winapi) i32;

extern "ws2_32" fn connect(socket: usize, addr: *const RioSockAddr, namelen: i32) callconv(.winapi) i32;

extern "ws2_32" fn accept(socket: usize, addr: ?*anyopaque, namelen: ?*i32) callconv(.winapi) usize;

extern "ws2_32" fn recv(socket: usize, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;

extern "ws2_32" fn setsockopt(socket: usize, level: i32, name: i32, value: *const anyopaque, len: i32) callconv(.winapi) i32;

extern "ws2_32" fn select(nfds: i32, readfds: ?*RioFdSet, writefds: ?*RioFdSet, exceptfds: ?*RioFdSet, timeout: ?*RioTimeval) callconv(.winapi) i32;

extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;

fn acceptOne(handle: usize) error{ WouldBlock, SocketFailed }!i32 {
    const sock = accept(handle, null, null);
    const bad = sock == 0 or sock == std.math.maxInt(usize) or sock > std.math.maxInt(i32);
    if (bad) {
        if (sock != 0 and sock != std.math.maxInt(usize)) _ = closesocket(sock);
        if (WSAGetLastError() == 10035) return error.WouldBlock;
        return error.SocketFailed;
    }
    return @intCast(sock);
}

fn closedConnection(status: std.os.windows.NTSTATUS) bool {
    return switch (@intFromEnum(status)) {
        // DISCONNECTED, RESET, LOCAL_DISCONNECT, REMOTE_DISCONNECT,
        // REFUSED, INVALID, ABORTED.
        0xC000020C, 0xC000020D, 0xC000013B, 0xC000013C, 0xC0000236, 0xC000023A, 0xC0000241 => true,
        else => false,
    };
}

/// Move the connection named by the wait-for-listen sequence onto a new
/// overlapped socket. The first four bytes of `out` are that sequence.
fn acceptSequence(listener: usize, out: []const u8) error{SocketFailed}!i32 {
    if (out.len < 4) return error.SocketFailed;
    const sequence = std.mem.readInt(i32, out[0..4], .little);
    const sock = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (sock == 0 or sock == std.math.maxInt(usize)) return error.SocketFailed;
    const info = AfdAcceptInfo{
        .san_active = 0,
        .sequence = sequence,
        .accept_handle = sock,
    };
    var iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
    const code: std.os.windows.CTL_CODE = @bitCast(Iocp.ioctl_afd_accept);
    const status = std.os.windows.ntdll.NtDeviceIoControlFile(
        @ptrFromInt(listener),
        null,
        null,
        null,
        &iosb,
        code,
        &info,
        @sizeOf(AfdAcceptInfo),
        null,
        0,
    );
    if (status != .SUCCESS) {
        _ = closesocket(sock);
        std.debug.print("GAP-X1 windows afd accept status=0x{x} seq={d}\n", .{ @intFromEnum(status), sequence });
        return error.SocketFailed;
    }
    if (sock > std.math.maxInt(i32)) {
        _ = closesocket(sock);
        return error.SocketFailed;
    }
    return @intCast(sock);
}

/// One `accept` on a blocking listener. Off Windows this is `SocketFailed`
/// and does not call the host `accept`.
pub fn pullAccept(fd: linux.fd_t) error{ WouldBlock, SocketFailed }!linux.fd_t {
    if (comptime builtin.os.tag != .windows) return error.SocketFailed;
    if (fd < 0) return error.SocketFailed;
    return acceptOne(@intCast(fd));
}

extern "kernel32" fn Sleep(milliseconds: u32) callconv(.winapi) void;

fn rioPtr(comptime T: type, ptr: RioFn) ?T {
    const raw = ptr orelse return null;
    return @as(T, @ptrFromInt(@intFromPtr(raw)));
}

fn socketLive(socket: usize) bool {
    return socket != 0 and socket != std.math.maxInt(usize);
}

fn rioCloseCq(table: *const RioTable, cq: *anyopaque) void {
    const Func = *const fn (*anyopaque) callconv(.winapi) void;
    const func = rioPtr(Func, table.close_completion_queue) orelse return;
    func(cq);
}

fn rioDeregister(table: *const RioTable, buffer_id: usize) void {
    const Func = *const fn (usize) callconv(.winapi) void;
    const func = rioPtr(Func, table.deregister_buffer) orelse return;
    func(buffer_id);
}

/// `SOL_SOCKET` and `SO_RCVTIMEO`. Winsock takes milliseconds in a `DWORD`.
const sol_socket: i32 = 0xFFFF;
const so_rcvtimeo: i32 = 0x1006;

/// Windows `fd_set` is a count plus sockets, not a POSIX bitmask.
/// `long` in `timeval` is 32 bits on x64 Windows.
const RioFdSet = extern struct {
    count: u32,
    pad: u32 = 0,
    array: [64]usize = @splat(0),
};

const RioTimeval = extern struct {
    sec: i32,
    usec: i32,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(RioFdSet) != 520) @compileError("WINSOCK fd_set is 520 bytes");
    if (@sizeOf(RioTimeval) != 8) @compileError("WINSOCK timeval is 8 bytes");
}

const RioConnect = struct {
    socket: usize,
    addr: RioSockAddr,
    len: i32,
    rc: i32 = 1,
    err: i32 = 0,
};

fn rioConnect(job: *RioConnect) void {
    job.rc = connect(job.socket, &job.addr, job.len);
    if (job.rc != 0) job.err = WSAGetLastError();
}

/// Calls the table `Iocp.open` already loaded. The listening socket is a
/// normal overlapped socket. The client is `WSA_FLAG_REGISTERED_IO`. A
/// registered socket rejects `FIONBIO` (`WSAEOPNOTSUPP`), so `connect` runs
/// on a second thread and `select` waits on the listener. One `RIOSend` of
/// `RIO!` is dequeued, then the accepted socket must read those four bytes.
/// A null pointer, a refused call, an empty queue, or a peer mismatch
/// returns a witness with `ok` false and does not invent a count.
fn dequeueLoadedRio(table: *const RioTable) RioWitness {
    const invalid = std.math.maxInt(usize);
    var listener: usize = invalid;
    var client: usize = invalid;
    var accepted: usize = invalid;
    var cq: ?*anyopaque = null;
    var buffer_id: usize = 0;
    const payload = std.heap.page_allocator.alloc(u8, rio_payload.len) catch {
        return .{ .stage = "memory" };
    };
    defer std.heap.page_allocator.free(payload);
    defer {
        if (socketLive(client)) _ = closesocket(client);
        if (cq) |queue| rioCloseCq(table, queue);
        if (buffer_id != 0 and buffer_id != rio_invalid_buffer_id) rioDeregister(table, buffer_id);
        if (socketLive(accepted)) _ = closesocket(accepted);
        if (socketLive(listener)) _ = closesocket(listener);
    }
    @memcpy(payload, rio_payload);

    listener = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (!socketLive(listener)) return .{ .stage = "socket", .errno = WSAGetLastError() };
    var addr = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = @splat(0),
    };
    if (bind(listener, &addr, @sizeOf(RioSockAddr)) != 0) return .{ .stage = "bind", .errno = WSAGetLastError() };
    if (listen(listener, 1) != 0) return .{ .stage = "listen", .errno = WSAGetLastError() };
    var name_len: i32 = @sizeOf(RioSockAddr);
    if (getsockname(listener, &addr, &name_len) != 0) return .{ .stage = "name", .errno = WSAGetLastError() };

    client = WSASocketW(
        wsa_af_inet,
        wsa_sock_stream,
        wsa_ipproto_tcp,
        null,
        0,
        wsa_flag_overlapped | wsa_flag_registered_io,
    );
    if (!socketLive(client)) return .{ .stage = "client", .errno = WSAGetLastError() };
    var job = RioConnect{ .socket = client, .addr = addr, .len = name_len };
    var connector: ?std.Thread = null;
    defer if (connector) |thread| thread.join();
    connector = std.Thread.spawn(.{}, rioConnect, .{&job}) catch return .{ .stage = "thread" };

    var ready = RioFdSet{ .count = 1 };
    ready.array[0] = listener;
    var wait = RioTimeval{ .sec = 2, .usec = 0 };
    const selected = select(0, &ready, null, null, &wait);
    if (selected <= 0) {
        const err = if (selected < 0) WSAGetLastError() else job.err;
        if (socketLive(client)) {
            _ = closesocket(client);
            client = std.math.maxInt(usize);
        }
        return .{ .stage = "select", .errno = err };
    }
    accepted = accept(listener, null, null);
    if (!socketLive(accepted)) return .{ .stage = "accept", .errno = WSAGetLastError() };
    var timeout_ms: i32 = 2000;
    _ = setsockopt(accepted, sol_socket, so_rcvtimeo, &timeout_ms, @sizeOf(i32));

    const CreateCq = *const fn (u32, ?*anyopaque) callconv(.winapi) ?*anyopaque;
    const create_cq = rioPtr(CreateCq, table.create_completion_queue) orelse return .{ .stage = "table" };
    cq = create_cq(32, null);
    const queue = cq orelse return .{ .stage = "cq", .errno = WSAGetLastError() };

    const CreateRq = *const fn (usize, u32, u32, u32, u32, *anyopaque, *anyopaque, ?*anyopaque) callconv(.winapi) ?*anyopaque;
    const create_rq = rioPtr(CreateRq, table.create_request_queue) orelse return .{ .stage = "table" };
    const rq = create_rq(client, 1, 1, 1, 1, queue, queue, @ptrFromInt(0x22115249)) orelse {
        return .{ .stage = "rq", .errno = WSAGetLastError() };
    };

    const Register = *const fn ([*]u8, u32) callconv(.winapi) usize;
    const register = rioPtr(Register, table.register_buffer) orelse return .{ .stage = "table" };
    buffer_id = register(payload.ptr, @intCast(payload.len));
    if (buffer_id == 0 or buffer_id == rio_invalid_buffer_id) {
        return .{ .stage = "register", .errno = WSAGetLastError() };
    }

    var rio_buf = RioBuf{
        .buffer_id = buffer_id,
        .offset = 0,
        .length = @intCast(payload.len),
    };
    const Send = *const fn (*anyopaque, *RioBuf, u32, u32, ?*anyopaque) callconv(.winapi) i32;
    const send = rioPtr(Send, table.send) orelse return .{ .stage = "table" };
    if (send(rq, &rio_buf, 1, 0, @ptrFromInt(@as(usize, rio_request_context))) == 0) {
        return .{ .stage = "send", .errno = WSAGetLastError() };
    }

    const Dequeue = *const fn (*anyopaque, [*]RioResult, u32) callconv(.winapi) u32;
    const dequeue = rioPtr(Dequeue, table.dequeue_completion) orelse return .{ .stage = "table" };
    var results: [4]RioResult = @splat(.{});
    var count: u32 = 0;
    var polls: u32 = 0;
    while (polls < 200) : (polls += 1) {
        count = dequeue(queue, &results, results.len);
        if (count == rio_corrupt_cq) return .{ .stage = "corrupt", .errno = WSAGetLastError() };
        if (count != 0) break;
        Sleep(10);
    }
    if (count == 0 or count > results.len) {
        return .{ .stage = "empty", .count = count, .errno = 0 };
    }

    var found = false;
    var got = RioResult{};
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        if (results[index].request_context == rio_request_context) {
            got = results[index];
            found = true;
            break;
        }
    }
    if (!found) {
        return .{
            .stage = "context",
            .count = count,
            .status = results[0].status,
            .bytes = results[0].bytes,
            .errno = 0,
        };
    }
    if (got.status != 0) {
        return .{ .stage = "status", .count = count, .status = got.status, .bytes = got.bytes, .errno = 0 };
    }
    if (got.bytes != rio_payload.len) {
        return .{ .stage = "short", .count = count, .status = got.status, .bytes = got.bytes, .errno = 0 };
    }

    var peer: [4]u8 = @splat(0);
    const n = recv(accepted, &peer, @intCast(peer.len), 0);
    if (n != @as(i32, rio_payload.len) or !std.mem.eql(u8, peer[0..rio_payload.len], rio_payload)) {
        return .{
            .stage = "peer",
            .count = count,
            .status = got.status,
            .bytes = if (n > 0) @intCast(n) else 0,
            .errno = WSAGetLastError(),
        };
    }
    return .{
        .ok = true,
        .stage = "dequeued",
        .count = count,
        .status = got.status,
        .bytes = got.bytes,
        .errno = 0,
    };
}

fn ipv4Bits(host: []const u8) ListenError!u32 {
    if (host.len == 0 or std.mem.eql(u8, host, "0.0.0.0")) return 0;
    const parsed = std.Io.net.Ip4Address.parse(host, 0) catch return error.InvalidAddress;
    return @bitCast(parsed.bytes);
}

/// Bind an IPv4 TCP listener. `port` 0 asks the kernel for an ephemeral port.
/// The returned fd is close-on-exec. BSD listeners are nonblocking so a second
/// `accept` cannot stall the reap loop. The Linux ring path stays blocking;
/// io_uring waits, and userspace does not call `accept` again.
pub fn listenTcp(host: []const u8, port: u16) ListenError!Listener {
    if (comptime builtin.os.tag == .linux) return listenLinux(host, port);
    if (comptime builtin.os.tag == .windows) return listenWindows(host, port);
    if (comptime kqueueOs()) return listenBsd(host, port);
    return error.Unsupported;
}

pub fn closeSocket(fd: linux.fd_t) void {
    if (fd < 0) return;
    if (comptime builtin.os.tag == .linux) {
        _ = linux.close(fd);
        return;
    }
    if (comptime builtin.os.tag == .windows) {
        _ = closesocket(@intCast(fd));
        return;
    }
    if (comptime kqueueOs()) _ = std.c.close(fd);
}

fn listenLinux(host: []const u8, port: u16) ListenError!Listener {
    const ip = try ipv4Bits(host);
    const rc = linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    const fd: linux.fd_t = switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.SocketUnavailable,
    };
    errdefer _ = linux.close(fd);
    var yes: i32 = 1;
    _ = linux.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(i32));
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip,
    };
    switch (std.posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)))) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        else => return error.SocketUnavailable,
    }
    switch (std.posix.errno(linux.listen(fd, 128))) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        else => return error.SocketUnavailable,
    }
    var storage: linux.sockaddr.storage = undefined;
    var slen: std.posix.socklen_t = @sizeOf(linux.sockaddr.storage);
    if (std.posix.errno(linux.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SocketUnavailable;
    const bound: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
}

fn listenBsd(host: []const u8, port: u16) ListenError!Listener {
    const ip = try ipv4Bits(host);
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    if (fd < 0) return error.SocketUnavailable;
    errdefer _ = std.c.close(fd);
    var yes: i32 = 1;
    _ = std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, &yes, @sizeOf(i32));
    var addr = std.c.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip,
    };
    const addr_ptr: *std.c.sockaddr = @ptrCast(&addr);
    if (std.c.bind(fd, addr_ptr, @intCast(@sizeOf(std.c.sockaddr.in))) != 0) return bsdListenError();
    if (std.c.listen(fd, 128) != 0) return bsdListenError();
    if (std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) < 0) return error.SocketUnavailable;
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(i32, 0));
    if (flags < 0) return error.SocketUnavailable;
    if (std.c.fcntl(fd, std.c.F.SETFL, flags | @as(@TypeOf(flags), 4)) < 0) return error.SocketUnavailable;
    var len: std.c.socklen_t = @intCast(@sizeOf(std.c.sockaddr.in));
    if (std.c.getsockname(fd, addr_ptr, &len) != 0) return error.SocketUnavailable;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port) };
}

fn bsdListenError() ListenError {
    const err = std.c._errno().*;
    if (err == 48 or err == 98) return error.AddressInUse;
    if (err == 1 or err == 13) return error.PermissionDenied;
    return error.SocketUnavailable;
}

fn listenWindows(host: []const u8, port: u16) ListenError!Listener {
    const ip = try ipv4Bits(host);
    var startup: [408]u8 = @splat(0);
    if (WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    const sock = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (sock == 0 or sock == std.math.maxInt(usize)) return error.SocketUnavailable;
    errdefer _ = closesocket(sock);
    const limit: usize = @intCast(std.math.maxInt(i32));
    if (sock > limit) return error.SocketUnavailable;
    const fd: linux.fd_t = @intCast(sock);
    var addr = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip,
        .zero = @splat(0),
    };
    if (bind(sock, &addr, @sizeOf(RioSockAddr)) != 0) return windowsListenError();
    if (listen(sock, 128) != 0) return windowsListenError();
    var name_len: i32 = @sizeOf(RioSockAddr);
    if (getsockname(sock, &addr, &name_len) != 0) return error.SocketUnavailable;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port) };
}

fn windowsListenError() ListenError {
    const err = WSAGetLastError();
    if (err == 10048) return error.AddressInUse;
    if (err == 10013) return error.PermissionDenied;
    return error.SocketUnavailable;
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
    try std.testing.expectEqual(Iocp.ioctl_afd_accept, @as(u32, 0x12010));
    try std.testing.expectEqual(Iocp.ioctl_afd_receive, @as(u32, 0x12017));
    try std.testing.expectEqual(Iocp.ioctl_afd_send, @as(u32, 0x1201f));
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
        .{ .op = Iocp.op_recv, .handle = fd_ident, .length = buf.len, .token = token_key, .buf = @intFromPtr(&buf), .ioctl = Iocp.ioctl_afd_receive },
        .{ .op = Iocp.op_send, .handle = fd_ident, .length = 1, .token = token_key, .buf = @intFromPtr(&send_bytes), .ioctl = Iocp.ioctl_afd_send },
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
    try refusePortableReactor(.linux, live.entries);
    try std.testing.expectError(error.Unsupported, refuseForeignCapsule());
    if (comptime builtin.os.tag == .freebsd) try Kqueue.exerciseLive();
    if (comptime builtin.os.tag == .windows) try Iocp.exerciseLive();

    std.debug.print("GAP-X1 branch=linux ring queued six ops; this host did not execute kqueue or IOCP; closed kqueue describes FreeBSD filters; closed IOCP describes AFD wait-for-listen and AFD poll and returns MissingOp; portable init opens the native backend and refuses a missing op; USR2 capsule refused\n", .{});
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
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(RioBuf));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(RioResult));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), rio_corrupt_cq);
    var closed_rio = IoBackend.closed(.iocp, 32);
    defer closed_rio.deinit();
    const witness = closed_rio.dequeueRegistered();
    try std.testing.expect(!witness.ok);
    try std.testing.expectEqualStrings("off-windows", witness.stage);
    try std.testing.expectEqual(@as(u32, 0), witness.count);
    try std.testing.expectEqual(@as(u32, 0), witness.bytes);
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

    std.debug.print("GAP-X3 branch=windows RIO loads the function table with WSAIoctl SIO 0xC8000024 and GUID 8509e081-96dd-4005-b165-9e2ee8c79e3f on a WSA_FLAG_REGISTERED_IO socket during Iocp.open; dequeueRegistered calls that stored table; off Windows it returns stage off-windows before any pointer call; a null or short table is MissingOp and the port is closed; recv and send on the IOCP path are IOCTL_AFD_RECEIVE and IOCTL_AFD_SEND; this host did not execute WSAIoctl or RIODequeueCompletion; heading stays unmarked; whole-accept not claimed\n", .{});
}
