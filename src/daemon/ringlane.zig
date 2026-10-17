// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ringlane submission and completion.
//!
//! Linux io_uring only. The production ring lives here; `substrate/io/ring.zig`
//! stays the unfinished prototype and is not this backend.
//!
//! The live ring probes multishot accept and multishot wake-poll, sizes the
//! completion queue for a full reactor batch, and arms cooperative task-work.
//! `IORING_SETUP_DEFER_TASKRUN` and `IORING_SETUP_SINGLE_ISSUER` are never
//! requested. Recv and send stay one-shot: the connection buffer is released
//! on the first CQE, which is the Helix snapshot point.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const IoUring = linux.IoUring;

pub const default_cqe_batch: usize = 256;
pub const max_cqe_batch: usize = 4096;
pub const min_cq_entries: u32 = 256;

pub const RingFeatures = struct {
    multishot_accept: bool = false,
    multishot_recv: bool = false,
    buf_ring: bool = false,
    send_zc: bool = false,
    fixed_files: bool = false,
    defer_taskrun: bool = false,
    sqpoll: bool = false,

    pub const baseline: @This() = .{};

    /// Bit layout of this struct. `Ring.init` does not pass `DEFER_TASKRUN`
    /// or `SINGLE_ISSUER` to the kernel. Portable backends still reject a
    /// caller that sets any fast-path flag, so those defaults stay false.
    fn setupFlags(self: @This()) u32 {
        var flags: u32 = 0;
        if (self.sqpoll) flags |= linux.IORING_SETUP_SQPOLL;
        if (self.defer_taskrun) {
            flags |= linux.IORING_SETUP_DEFER_TASKRUN;
            flags |= linux.IORING_SETUP_SINGLE_ISSUER;
        }
        return flags;
    }
};

pub const OpKind = enum(u8) {
    other = 0,
    accept = 1,
    recv = 2,
    send = 3,
    timeout = 4,
    connect = 5,
    // poll: readiness watch on a bare fd (e.g. a reactor's cross-reactor
    // wake eventfd). Fires a `.poll` completion when the fd is readable.
    poll = 6,
};

pub const FdToken = struct {
    slot: u32,
    gen: u32,
};

const gen_bits = 28;
const slot_bits = 28;
const slot_shift = gen_bits;
const kind_shift = gen_bits + slot_bits;
const field_mask: u64 = (1 << gen_bits) - 1;
const slot_max: u32 = (1 << slot_bits) - 1;
const gen_max: u32 = (1 << gen_bits) - 1;

pub fn encodeUserData(kind: OpKind, token: FdToken) error{TokenOutOfRange}!u64 {
    if (token.slot > slot_max or token.gen > gen_max) return error.TokenOutOfRange;
    return (@as(u64, @intFromEnum(kind)) << kind_shift) |
        (@as(u64, token.slot) << slot_shift) |
        @as(u64, token.gen);
}

pub fn decodeUserData(raw: u64) error{UnknownOpKind}!struct { kind: OpKind, token: FdToken } {
    const kind_raw: u8 = @intCast(raw >> kind_shift);
    const kind: OpKind = switch (kind_raw) {
        0 => .other,
        1 => .accept,
        2 => .recv,
        3 => .send,
        4 => .timeout,
        5 => .connect,
        6 => .poll,
        else => return error.UnknownOpKind,
    };
    return .{
        .kind = kind,
        .token = .{
            .slot = @intCast((raw >> slot_shift) & field_mask),
            .gen = @intCast(raw & field_mask),
        },
    };
}

pub const AcceptEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
};

pub const RecvEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
};

pub const SendEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
    notif: bool,
};

pub const ConnectEvent = struct {
    token: FdToken,
    res: i32,
};

pub const PollEvent = struct {
    token: FdToken,
    res: i32,
    more: bool = false,
};

pub const Completion = union(OpKind) {
    other: void,
    accept: AcceptEvent,
    recv: RecvEvent,
    send: SendEvent,
    timeout: void,
    connect: ConnectEvent,
    poll: PollEvent,
};

fn decodeCompletion(cqe: linux.io_uring_cqe) error{UnknownOpKind}!Completion {
    const ud = try decodeUserData(cqe.user_data);
    const more = (cqe.flags & linux.IORING_CQE_F_MORE) != 0;
    return switch (ud.kind) {
        .other => .{ .other = {} },
        .accept => .{ .accept = .{ .token = ud.token, .res = cqe.res, .more = more } },
        .recv => .{ .recv = .{ .token = ud.token, .res = cqe.res, .more = more } },
        .send => .{ .send = .{
            .token = ud.token,
            .res = cqe.res,
            .more = more,
            .notif = (cqe.flags & linux.IORING_CQE_F_NOTIF) != 0,
        } },
        .timeout => .{ .timeout = {} },
        .connect => .{ .connect = .{ .token = ud.token, .res = cqe.res } },
        .poll => .{ .poll = .{ .token = ud.token, .res = cqe.res, .more = more } },
    };
}

pub fn isUnsupportedInitError(err: anyerror) bool {
    return switch (err) {
        error.PermissionDenied,
        error.SystemOutdated,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.ArgumentsInvalid,
        => true,
        else => false,
    };
}

const ProbeAnswers = struct {
    accept: bool,
    poll: bool,
};

var probe_mu: std.atomic.Mutex = .unlocked;
var accept_answer: ?bool = null;
var poll_answer: ?bool = null;

fn ensureProbes() ProbeAnswers {
    if (comptime builtin.os.tag != .linux) return .{ .accept = false, .poll = false };
    while (!probe_mu.tryLock()) std.Thread.yield() catch {};
    defer probe_mu.unlock();
    if (accept_answer == null) {
        if (probeAcceptMultishot()) |known| accept_answer = known;
    }
    if (poll_answer == null) {
        if (probePollMultishot()) |known| poll_answer = known;
    }
    return .{
        .accept = accept_answer orelse false,
        .poll = poll_answer orelse false,
    };
}

fn isErrno(res: i32, err: linux.E) bool {
    return res == -@as(i32, @intFromEnum(err));
}

fn openLoopbackListener() ?linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return null;
    const fd: linux.fd_t = @intCast(rc);
    var addr = linux.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    if (posix.errno(linux.listen(fd, 16)) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

/// `true` when a cancelled multishot accept completes with MORE clear.
/// `false` when the kernel rejects the opcode. `null` is inconclusive.
fn probeAcceptMultishot() ?bool {
    var ring = IoUring.init(8, 0) catch return null;
    defer ring.deinit();
    const listener = openLoopbackListener() orelse return null;
    defer _ = linux.close(listener);
    const accept_ud = encodeUserData(.accept, .{ .slot = 1, .gen = 1 }) catch return null;
    _ = ring.accept_multishot(accept_ud, listener, null, null, posix.SOCK.CLOEXEC) catch return null;
    var ts = linux.kernel_timespec{ .sec = 0, .nsec = 1_000_000 };
    const timeout_ud = encodeUserData(.timeout, .{ .slot = 2, .gen = 1 }) catch return null;
    _ = ring.timeout(timeout_ud, &ts, 0, 0) catch return null;
    _ = ring.submit_and_wait(1) catch return null;
    var cqes: [8]linux.io_uring_cqe = undefined;
    const ready = ring.copy_cqes(&cqes, 0) catch return null;
    for (cqes[0..ready]) |cqe| {
        const decoded = decodeUserData(cqe.user_data) catch continue;
        if (decoded.kind != .accept) continue;
        if (isErrno(cqe.res, .INVAL) or isErrno(cqe.res, .OPNOTSUPP)) return false;
        return null;
    }
    const cancel_ud = encodeUserData(.other, .{ .slot = 3, .gen = 1 }) catch return null;
    _ = ring.cancel(cancel_ud, accept_ud, 0) catch return null;
    var spins: u8 = 0;
    while (spins < 8) : (spins += 1) {
        _ = ring.submit_and_wait(1) catch return null;
        const n = ring.copy_cqes(&cqes, 0) catch return null;
        for (cqes[0..n]) |cqe| {
            if (cqe.user_data != accept_ud) continue;
            if ((cqe.flags & linux.IORING_CQE_F_MORE) != 0) return false;
            if (isErrno(cqe.res, .INVAL) or isErrno(cqe.res, .OPNOTSUPP)) return false;
            if (isErrno(cqe.res, .CANCELED)) return true;
            return null;
        }
    }
    return null;
}

fn probePollMultishot() ?bool {
    var ring = IoUring.init(8, 0) catch return null;
    defer ring.deinit();
    const efd_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    if (posix.errno(efd_rc) != .SUCCESS) return null;
    const efd: linux.fd_t = @intCast(efd_rc);
    defer _ = linux.close(efd);
    const poll_ud = encodeUserData(.poll, .{ .slot = 4, .gen = 1 }) catch return null;
    const sqe = ring.poll_add(poll_ud, efd, linux.POLL.IN) catch return null;
    sqe.len = linux.IORING_POLL_ADD_MULTI;
    var ts = linux.kernel_timespec{ .sec = 0, .nsec = 1_000_000 };
    const timeout_ud = encodeUserData(.timeout, .{ .slot = 5, .gen = 1 }) catch return null;
    _ = ring.timeout(timeout_ud, &ts, 0, 0) catch return null;
    _ = ring.submit_and_wait(1) catch return null;
    var cqes: [8]linux.io_uring_cqe = undefined;
    const ready = ring.copy_cqes(&cqes, 0) catch return null;
    for (cqes[0..ready]) |cqe| {
        const decoded = decodeUserData(cqe.user_data) catch continue;
        if (decoded.kind != .poll) continue;
        if (isErrno(cqe.res, .INVAL) or isErrno(cqe.res, .OPNOTSUPP)) return false;
        return null;
    }
    const cancel_ud = encodeUserData(.other, .{ .slot = 6, .gen = 1 }) catch return null;
    _ = ring.cancel(cancel_ud, poll_ud, 0) catch return null;
    var spins: u8 = 0;
    while (spins < 8) : (spins += 1) {
        _ = ring.submit_and_wait(1) catch return null;
        const n = ring.copy_cqes(&cqes, 0) catch return null;
        for (cqes[0..n]) |cqe| {
            if (cqe.user_data != poll_ud) continue;
            if ((cqe.flags & linux.IORING_CQE_F_MORE) != 0) return false;
            if (isErrno(cqe.res, .INVAL) or isErrno(cqe.res, .OPNOTSUPP)) return false;
            if (isErrno(cqe.res, .CANCELED)) return true;
            return null;
        }
    }
    return null;
}

fn completionQueueEntries(sq: u16) u32 {
    const sq_entries: u32 = sq;
    var want: u32 = sq_entries * 4;
    if (want < min_cq_entries) want = min_cq_entries;
    if (want > 32768) want = 32768;
    if (want < sq_entries) want = sq_entries;
    var rounded: u32 = 1;
    while (rounded < want) rounded <<= 1;
    return rounded;
}

fn openParams(entries: u16, flags: u32, cq_entries: u32) !IoUring {
    var params = std.mem.zeroInit(linux.io_uring_params, .{
        .flags = flags,
        .cq_entries = cq_entries,
        .sq_thread_idle = 1000,
    });
    return IoUring.init_params(entries, &params);
}

fn runtimeFlags(sqpoll: bool, fast: bool) u32 {
    var flags: u32 = 0;
    if (sqpoll) flags |= linux.IORING_SETUP_SQPOLL;
    if (fast) {
        flags |= linux.IORING_SETUP_COOP_TASKRUN;
        flags |= linux.IORING_SETUP_TASKRUN_FLAG;
        flags |= linux.IORING_SETUP_CQSIZE;
    }
    return flags;
}

fn openInner(entries: u16, features: RingFeatures) !IoUring {
    const cq = completionQueueEntries(entries);
    const attempts = [_]u32{
        runtimeFlags(features.sqpoll, true),
        runtimeFlags(features.sqpoll, false) | linux.IORING_SETUP_CQSIZE,
        runtimeFlags(features.sqpoll, false) | linux.IORING_SETUP_COOP_TASKRUN | linux.IORING_SETUP_TASKRUN_FLAG,
        runtimeFlags(features.sqpoll, false),
    };
    for (attempts, 0..) |flags, index| {
        const opened = if ((flags & linux.IORING_SETUP_CQSIZE) != 0)
            openParams(entries, flags, cq)
        else
            IoUring.init(entries, flags);
        if (opened) |ring| return ring else |err| switch (err) {
            error.ArgumentsInvalid => {
                if (index + 1 == attempts.len) return err;
            },
            else => |other| return other,
        }
    }
    return error.ArgumentsInvalid;
}

pub const Ring = struct {
    inner: IoUring,
    features: RingFeatures,
    accept_multishot: bool,
    poll_multishot: bool,

    pub fn init(entries: u16, features: RingFeatures) !Ring {
        const probed = ensureProbes();
        return .{
            .inner = try openInner(entries, features),
            .features = features,
            .accept_multishot = probed.accept,
            .poll_multishot = probed.poll,
        };
    }

    pub fn deinit(self: *Ring) void {
        self.inner.deinit();
    }

    fn flushOverflow(self: *Ring) !void {
        if (!self.inner.cq_ring_needs_flush()) return;
        _ = try self.inner.enter(0, 0, linux.IORING_ENTER_GETEVENTS);
    }

    fn enterSubmit(self: *Ring, wait_nr: u32) !u32 {
        try self.flushOverflow();
        return self.submitWaiting(wait_nr) catch |err| switch (err) {
            error.CompletionQueueOvercommitted => {
                try self.flushOverflow();
                return self.submitWaiting(wait_nr);
            },
            else => |other| return other,
        };
    }

    fn submitWaiting(self: *Ring, wait_nr: u32) !u32 {
        if (wait_nr == 0) return self.inner.submit();
        return self.inner.submit_and_wait(wait_nr);
    }

    pub fn submit(self: *Ring) !u32 {
        return self.enterSubmit(0);
    }

    pub fn submitAndWait(self: *Ring, wait_nr: u32) !u32 {
        return self.enterSubmit(wait_nr);
    }

    pub fn submitAccept(self: *Ring, token: FdToken, listener_fd: linux.fd_t) !void {
        // Accept with SOCK_CLOEXEC so every accepted socket defaults to
        // close-on-exec. Helix UPGRADE re-execs the daemon in place; the
        // design (see performUpgrade) explicitly CLEARs CLOEXEC only after
        // every required client/transport sidecar has sealed successfully.
        // Any omitted live client refuses UPGRADE before exec, leaving the
        // predecessor serving. Deliberately unestablished mesh dials may use
        // the redial path; every other inherited fd is exact or fatal.
        // Without this default those sockets can leak across execve as orphans:
        // a re-exec'd meshed node strands its peer link (the peer keeps a
        // zombie ESTAB socket and dedups away every re-dial → split-brain).
        const user_data = try encodeUserData(.accept, token);
        if (self.accept_multishot) {
            _ = try self.inner.accept_multishot(user_data, listener_fd, null, null, posix.SOCK.CLOEXEC);
        } else {
            _ = try self.inner.accept(user_data, listener_fd, null, null, posix.SOCK.CLOEXEC);
        }
    }

    /// One-shot into the caller buffer. A multishot or provided-buffer recv
    /// would still own that memory after the CQE Helix snapshots.
    pub fn submitRecv(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []u8) !void {
        _ = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer = buffer }, 0);
    }

    pub fn submitConnect(self: *Ring, token: FdToken, fd: linux.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
        _ = try self.inner.connect(try encodeUserData(.connect, token), fd, addr, addrlen);
    }

    /// Copy send. A zero-copy send posts a later `IORING_CQE_F_NOTIF`, and
    /// the daemon releases the send buffer on the first completion.
    pub fn submitSend(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        _ = try self.inner.send(try encodeUserData(.send, token), fd, buffer, 0);
    }

    /// Cancel one exact-generation socket operation by the same `user_data`
    /// identity with which it was submitted. Cancelling by fd is not safe:
    /// a slot can carry RECV and SEND concurrently, and an fd may later be
    /// reused. The matching original CQE is still reaped and applied before
    /// Helix snapshots any socket buffer.
    pub fn exactCancelUserData(kind: OpKind, token: FdToken) !struct { completion: u64, target: u64 } {
        if (kind != .accept and kind != .recv and kind != .send and kind != .connect)
            return error.InvalidCancelKind;
        return .{
            .completion = try encodeUserData(.other, token),
            .target = try encodeUserData(kind, token),
        };
    }

    pub fn submitExactCancel(self: *Ring, kind: OpKind, token: FdToken) !void {
        const ud = try exactCancelUserData(kind, token);
        _ = try self.inner.cancel(ud.completion, ud.target, 0);
    }

    /// Queue a relative single-shot timeout; fires as a `.timeout` completion.
    pub fn submitTimeout(self: *Ring, token: FdToken, ts: *const linux.kernel_timespec) !void {
        _ = try self.inner.timeout(try encodeUserData(.timeout, token), ts, 0, 0);
    }

    /// Watch `fd` for readability. A probed multishot poll stays armed while
    /// `IORING_CQE_F_MORE` is set; otherwise the caller re-arms one shot.
    pub fn submitPollAdd(self: *Ring, token: FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        const user_data = try encodeUserData(.poll, token);
        const sqe = try self.inner.poll_add(user_data, fd, poll_mask);
        if (self.poll_multishot) sqe.len = linux.IORING_POLL_ADD_MULTI;
    }

    pub fn reapCompletions(self: *Ring, out: []linux.io_uring_cqe, wait_nr: u32, handler: anytype) !void {
        const n = try self.inner.copy_cqes(out, wait_nr);
        for (out[0..n]) |cqe| {
            const completion = decodeCompletion(cqe) catch continue;
            handler.onCompletion(completion);
        }
    }

    /// Post one completion onto `target` with IORING_OP_MSG_RING, then drain
    /// both rings so the boot handshake is not left for the accept loop.
    pub fn bootMsgRing(source: *Ring, target: *Ring) !void {
        const token = FdToken{ .slot = 1, .gen = 1 };
        const posted = try encodeUserData(.poll, token);
        const sqe = try source.inner.get_sqe();
        sqe.prep_rw(.MSG_RING, target.inner.fd, 0, 1, posted);
        sqe.user_data = try encodeUserData(.other, token);
        sqe.rw_flags = 0;
        _ = try source.enterSubmit(1);
        var source_cqe: [1]linux.io_uring_cqe = undefined;
        const source_n = try source.inner.copy_cqes(&source_cqe, 0);
        if (source_n != 1 or source_cqe[0].res != 0) return error.Unexpected;
        if (source_cqe[0].user_data != try encodeUserData(.other, token)) return error.Unexpected;
        _ = try target.enterSubmit(1);
        var target_cqe: [1]linux.io_uring_cqe = undefined;
        const target_n = try target.inner.copy_cqes(&target_cqe, 0);
        if (target_n != 1 or target_cqe[0].res != 1) return error.Unexpected;
        if (target_cqe[0].user_data != posted) return error.Unexpected;
    }
};

fn listenLoopback() ?struct { fd: linux.fd_t, port: u16 } {
    const fd = openLoopbackListener() orelse return null;
    var storage: linux.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(@TypeOf(storage));
    if (posix.errno(linux.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    const bound: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
}

fn connectLoopback(port: u16) ?linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return null;
    const fd: linux.fd_t = @intCast(rc);
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (posix.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

fn hasCloexec(fd: linux.fd_t) bool {
    const flags = linux.fcntl(fd, posix.F.GETFD, 0);
    return posix.errno(flags) == .SUCCESS and (flags & posix.FD_CLOEXEC) != 0;
}

test "GAP-X2 ringlane submission identity round-trips and completions keep their flags" {
    const token = FdToken{ .slot = 0x1234, .gen = 0x5678 };
    const kinds = [_]OpKind{ .other, .accept, .recv, .send, .timeout, .connect, .poll };
    for (kinds) |kind| {
        const raw = try encodeUserData(kind, token);
        const decoded = try decodeUserData(raw);
        try std.testing.expectEqual(kind, decoded.kind);
        try std.testing.expectEqual(token.slot, decoded.token.slot);
        try std.testing.expectEqual(token.gen, decoded.token.gen);
    }
    try std.testing.expectError(error.TokenOutOfRange, encodeUserData(.recv, .{ .slot = slot_max + 1, .gen = 0 }));

    inline for (.{ OpKind.accept, .recv, .send, .connect }) |kind| {
        const ud = try Ring.exactCancelUserData(kind, token);
        try std.testing.expectEqual(try encodeUserData(kind, token), ud.target);
        try std.testing.expectEqual(try encodeUserData(.other, token), ud.completion);
    }
    try std.testing.expectError(error.InvalidCancelKind, Ring.exactCancelUserData(.timeout, token));
    try std.testing.expectError(error.InvalidCancelKind, Ring.exactCancelUserData(.poll, token));

    var cqe = std.mem.zeroes(linux.io_uring_cqe);
    cqe.user_data = try encodeUserData(.send, token);
    cqe.res = -11;
    cqe.flags = linux.IORING_CQE_F_MORE | linux.IORING_CQE_F_NOTIF;
    switch (try decodeCompletion(cqe)) {
        .send => |ev| {
            try std.testing.expect(ev.more);
            try std.testing.expect(ev.notif);
            try std.testing.expectEqual(@as(i32, -11), ev.res);
            try std.testing.expectEqual(token.slot, ev.token.slot);
            try std.testing.expectEqual(token.gen, ev.token.gen);
        },
        else => return error.TestUnexpectedResult,
    }
    cqe.user_data = try encodeUserData(.recv, token);
    cqe.flags = linux.IORING_CQE_F_MORE;
    cqe.res = 4;
    switch (try decodeCompletion(cqe)) {
        .recv => |ev| {
            try std.testing.expect(ev.more);
            try std.testing.expectEqual(@as(i32, 4), ev.res);
        },
        else => return error.TestUnexpectedResult,
    }
    cqe.user_data = try encodeUserData(.poll, token);
    cqe.flags = linux.IORING_CQE_F_MORE;
    cqe.res = 1;
    switch (try decodeCompletion(cqe)) {
        .poll => |ev| {
            try std.testing.expect(ev.more);
            try std.testing.expectEqual(@as(i32, 1), ev.res);
        },
        else => return error.TestUnexpectedResult,
    }
    cqe.user_data = try encodeUserData(.timeout, token);
    cqe.flags = 0;
    switch (try decodeCompletion(cqe)) {
        .timeout => {},
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(u32, 0), RingFeatures.baseline.setupFlags());
    const armed = (RingFeatures{ .sqpoll = true, .defer_taskrun = true }).setupFlags();
    try std.testing.expect((armed & linux.IORING_SETUP_SQPOLL) != 0);
    try std.testing.expect((armed & linux.IORING_SETUP_DEFER_TASKRUN) != 0);
    try std.testing.expect((armed & linux.IORING_SETUP_SINGLE_ISSUER) != 0);
    try std.testing.expect(isUnsupportedInitError(error.SystemOutdated));
    const Other = error{Unexpected};
    try std.testing.expect(!isUnsupportedInitError(Other.Unexpected));

    // The codec and feature-bit assertions above are platform-independent.
    // Opening a physical io_uring is a Linux-only fixture.
    if (comptime builtin.os.tag != .linux) return;
    var ring = Ring.init(32, .{}) catch |err| {
        if (isUnsupportedInitError(err)) {
            std.debug.print("GAP-X2 branch=ringlane submission and completion moved; baseline ring init refused with a listed error\n", .{});
            return;
        }
        return err;
    };
    defer ring.deinit();
    try std.testing.expectEqual(@as(u32, 0), try ring.submit());
    try std.testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try std.testing.expect((ring.inner.flags & linux.IORING_SETUP_SINGLE_ISSUER) == 0);
    try std.testing.expect(ring.inner.cq.cqes.len >= min_cq_entries);
    var forced = try Ring.init(32, .{ .defer_taskrun = true });
    defer forced.deinit();
    try std.testing.expect((forced.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try std.testing.expect((forced.inner.flags & linux.IORING_SETUP_SINGLE_ISSUER) == 0);
    try std.testing.expect((forced.inner.flags & linux.IORING_SETUP_COOP_TASKRUN) != 0);
    std.debug.print("GAP-X2 branch=ringlane submission and completion moved out of server.zig and the codec still round-trips\n", .{});
}

test "ringlane: multishot accept keeps CLOEXEC and cancels without a further connection" {
    if (comptime builtin.os.tag != .linux) return;
    var ring = Ring.init(32, .{}) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    defer ring.deinit();
    if (!ring.accept_multishot or !ring.poll_multishot) {
        std.debug.print("ringlane probe refused multishot accept={} poll={}\n", .{
            ring.accept_multishot,
            ring.poll_multishot,
        });
        return error.TestUnexpectedResult;
    }
    try std.testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try std.testing.expect((ring.inner.flags & linux.IORING_SETUP_COOP_TASKRUN) != 0);
    try std.testing.expect(ring.inner.cq.cqes.len >= min_cq_entries);

    const listener = listenLoopback() orelse return error.SkipZigTest;
    defer _ = linux.close(listener.fd);
    const token = FdToken{ .slot = 4, .gen = 1 };
    try ring.submitAccept(token, listener.fd);
    _ = try ring.submit();
    const clients = [_]linux.fd_t{
        connectLoopback(listener.port) orelse return error.TestUnexpectedResult,
        connectLoopback(listener.port) orelse return error.TestUnexpectedResult,
    };
    defer {
        for (clients) |fd| _ = linux.close(fd);
    }

    const Sink = struct {
        events: [8]AcceptEvent = undefined,
        n: usize = 0,
        pub fn onCompletion(self: *@This(), completion: Completion) void {
            switch (completion) {
                .accept => |ev| {
                    if (self.n < self.events.len) {
                        self.events[self.n] = ev;
                        self.n += 1;
                    }
                },
                else => {},
            }
        }
    };
    var sink = Sink{};
    var cqes: [8]linux.io_uring_cqe = undefined;
    var got: usize = 0;
    var spins: usize = 0;
    while (got < 2 and spins < 20) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        const before = sink.n;
        try ring.reapCompletions(&cqes, 0, &sink);
        got += sink.n - before;
    }
    try std.testing.expectEqual(@as(usize, 2), got);
    var accepted: [2]linux.fd_t = .{ -1, -1 };
    defer {
        for (accepted) |fd| {
            if (fd >= 0) _ = linux.close(fd);
        }
    }
    for (sink.events[0..2], 0..) |ev, index| {
        try std.testing.expectEqual(token.slot, ev.token.slot);
        try std.testing.expectEqual(token.gen, ev.token.gen);
        try std.testing.expect(ev.more);
        try std.testing.expect(ev.res >= 0);
        accepted[index] = ev.res;
        try std.testing.expect(hasCloexec(ev.res));
    }

    try ring.submitExactCancel(.accept, token);
    var canceled = false;
    spins = 0;
    while (!canceled and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        sink.n = 0;
        try ring.reapCompletions(&cqes, 0, &sink);
        for (sink.events[0..sink.n]) |ev| {
            if (isErrno(ev.res, .CANCELED)) {
                try std.testing.expect(!ev.more);
                canceled = true;
            } else if (ev.res >= 0) {
                _ = linux.close(ev.res);
                return error.TestUnexpectedResult;
            }
        }
    }
    try std.testing.expect(canceled);

    const extra = connectLoopback(listener.port) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(extra);
    var ts = linux.kernel_timespec{ .sec = 0, .nsec = 50_000_000 };
    try ring.submitTimeout(.{ .slot = 9, .gen = 1 }, &ts);
    _ = try ring.submitAndWait(1);
    sink.n = 0;
    try ring.reapCompletions(&cqes, 0, &sink);
    for (sink.events[0..sink.n]) |ev| {
        if (ev.res >= 0) _ = linux.close(ev.res);
        return error.TestUnexpectedResult;
    }
    std.debug.print("ringlane: multishot accept kept CLOEXEC across two connections and cancel stopped the arm; cq={d}\n", .{ring.inner.cq.cqes.len});
}
