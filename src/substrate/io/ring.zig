// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ringlane io_uring prototype — not the production backend.
//!
//! The live daemon ring is `src/daemon/ringlane.zig`. The daemon does not
//! import this file. Connect, poll, and exact-generation cancel of accept,
//! recv, send, and connect are submittable here, and accept passes
//! `SOCK_CLOEXEC`. `kernelProbe` asks the kernel whether multishot accept and
//! multishot poll work. `narrow` stays pure: it only folds a capability set
//! the caller already measured.
//!
//! `Ring.init` sizes the completion queue to at least 256 entries and requests
//! cooperative task-work, walking a shorter setup ladder only when the kernel
//! returns `ArgumentsInvalid`. It never passes `IORING_SETUP_DEFER_TASKRUN`
//! or `IORING_SETUP_SINGLE_ISSUER`. Submit flushes a completion-queue overflow
//! and retries once. The ordinary recv and send paths stay copies.
//!
//! `registerProvidedBuffers` registers one provided-buffer group.
//! `submitRecvBufRing` is the one-shot select. `submitRecvMultishot` stays
//! armed only when `multishot_recv` is set and that group is registered.
//! `replenishProvidedBuffer` publishes a used buffer again.
//! `submitSendZc` is the zero-copy send. `registerFixedFiles` installs one
//! fixed file table, and the fixed submit helpers address it by index.
//! `buf_ring.registerAll` stays pure bookkeeping and does not register buffers
//! with the kernel. The production ring in `src/daemon/ringlane.zig` arms its
//! own multishot recv and zero-copy send. This file is not that backend.
//!
//! The `Reactor` seam (`src/substrate/reactor.zig`) does not dispatch here.
//!
//! Design rules followed here:
//!   - Feature gating is a comptime `RingFeatures` profile. Unsupported branches
//!     compile out; runtime probing narrows further and fails closed.
//!   - Every connection is referenced by a generational `FdToken{ slot, gen }`,
//!     not a pointer, so handoff/snapshots are stable and stale completions are
//!     rejected (planning/01 section 2, fixed-file generation idea).
//!   - The op kind and the FdToken are packed into the SQE `user_data` and
//!     decoded back out of each CQE. That pack/unpack and the feature-selection
//!     logic are PURE (no syscalls) so they unit-test without a live ring.
//!
//! Test constraint: the sandbox/CI may forbid io_uring setup. Tests that need a
//! real ring attempt `Ring.init` and `return error.SkipZigTest` on any setup
//! error (EPERM/ENOSYS/etc.). The pure logic is always exercised.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
// io_uring is a Linux-only fast path; `void` off-Linux so the pure helpers in
// this file (user_data codec, FdToken, RingFeatures, CQE decode) stay portable.
const IoUring = if (builtin.os.tag == .linux) linux.IoUring else void;
const buf_ring = @import("buf_ring.zig");

/// Smallest completion queue this ring will open. A reactor batch is 256,
/// and the kernel default of twice the submission queue is too small for it.
pub const min_cq_entries: u32 = 256;

// ---------------------------------------------------------------------------
// Feature gating (comptime Kernel persona)
// ---------------------------------------------------------------------------

/// Comptime feature profile gating which io_uring fast paths are compiled in.
/// Mirrors the `Kernel` struct in planning/01 section 2. A field being `true`
/// here only means "compile the code path"; runtime probing (`probe`) may still
/// turn an unsupported feature off and fall back.
pub const RingFeatures = struct {
    /// Multishot accept: one SQE yields repeated accept CQEs (kernel >= 5.19).
    multishot_accept: bool = false,
    /// Multishot recv: one SQE yields repeated recv CQEs (needs buf_ring).
    multishot_recv: bool = false,
    /// Provided buffer rings for recv (kernel >= 5.19).
    buf_ring: bool = false,
    /// Zero-copy send for bulk fanout (kernel >= 6.0).
    send_zc: bool = false,
    /// Registered (fixed) file table for sockets.
    fixed_files: bool = false,
    /// IORING_SETUP_DEFER_TASKRUN (kernel >= 6.1, implies SINGLE_ISSUER).
    defer_taskrun: bool = false,
    /// IORING_SETUP_SQPOLL kernel submission polling thread.
    sqpoll: bool = false,

    /// Conservative profile: plain accept/recv/send only. Works on the widest
    /// range of kernels and inside restricted sandboxes. The default.
    pub const baseline: RingFeatures = .{};

    /// Sketch only. `Ring.init` keeps the field and never passes
    /// `DEFER_TASKRUN` or `SINGLE_ISSUER` to the kernel.
    pub const linux_6_1_safe: RingFeatures = .{
        .multishot_accept = true,
        .multishot_recv = true,
        .buf_ring = true,
        .fixed_files = true,
        .defer_taskrun = true,
    };

    /// linux_6_8_fast persona: everything in linux_6_1_safe plus zero-copy send.
    pub const linux_6_8_fast: RingFeatures = .{
        .multishot_accept = true,
        .multishot_recv = true,
        .buf_ring = true,
        .send_zc = true,
        .fixed_files = true,
        .defer_taskrun = true,
    };

    /// Translate a feature profile into io_uring setup flags.
    /// Pure: no syscalls, unit-testable. `defer_taskrun` implies
    /// `SINGLE_ISSUER`, which the kernel requires alongside DEFER_TASKRUN.
    pub fn setupFlags(self: RingFeatures) u32 {
        var flags: u32 = 0;
        if (self.sqpoll) flags |= linux.IORING_SETUP_SQPOLL;
        if (self.defer_taskrun) {
            flags |= linux.IORING_SETUP_DEFER_TASKRUN;
            flags |= linux.IORING_SETUP_SINGLE_ISSUER;
        }
        return flags;
    }

    /// Return a copy with any features unsupported by `caps` disabled (fail
    /// closed). Pure: pass a `RingFeatures` built from `kernelProbe`, or any
    /// other measured set. This function does not call the kernel.
    pub fn narrow(self: RingFeatures, caps: RingFeatures) RingFeatures {
        var result: RingFeatures = .{
            .multishot_accept = self.multishot_accept and caps.multishot_accept,
            .multishot_recv = self.multishot_recv and caps.multishot_recv and caps.buf_ring,
            .buf_ring = self.buf_ring and caps.buf_ring,
            .send_zc = self.send_zc and caps.send_zc,
            .fixed_files = self.fixed_files and caps.fixed_files,
            .defer_taskrun = self.defer_taskrun and caps.defer_taskrun,
            .sqpoll = self.sqpoll and caps.sqpoll,
        };
        result.buf_ring = result.buf_ring or result.multishot_recv;
        return result;
    }
};

// ---------------------------------------------------------------------------
// Generational handles + user_data codec (PURE)
// ---------------------------------------------------------------------------

/// Operation kind, packed into the high bits of `user_data`. Keep this small so
/// it fits in `OpKindBits`. `.other` is the catch-all for ops without a typed
/// completion (nop, close, cancel, ...).
pub const OpKind = enum(u8) {
    other = 0,
    accept = 1,
    recv = 2,
    send = 3,
    timeout = 4,
    connect = 5,
    // poll: readiness watch on a bare fd (a reactor wake eventfd). The same
    // numeric value as the production ring, so a user_data word means the
    // same kind in both codecs.
    poll = 6,
};

/// Generational handle for a connection slot. The slot indexes a fixed table;
/// the generation is bumped every time the slot is recycled so a completion that
/// names a stale generation can be dropped instead of mis-delivered (planning/01
/// section 2). Pointer-free by design so it survives snapshot/handoff.
pub const FdToken = struct {
    slot: u32,
    gen: u32,

    pub fn eql(a: FdToken, b: FdToken) bool {
        return a.slot == b.slot and a.gen == b.gen;
    }
};

// user_data layout (64 bits):
//   bits [56,64)  op kind   (8 bits)
//   bits [28,56)  slot      (28 bits)
//   bits [ 0,28)  gen       (28 bits)
//
// 28 bits is ample for both slot count and generation counter while leaving a
// full byte for the op kind. Values that exceed the field width are rejected at
// encode time rather than silently truncated.
const OpKindBits = 8;
const SlotBits = 28;
const GenBits = 28;

const SlotMax: u32 = (1 << SlotBits) - 1;
const GenMax: u32 = (1 << GenBits) - 1;

const GenMask: u64 = (1 << GenBits) - 1;
const SlotMask: u64 = (1 << SlotBits) - 1;
const OpKindMask: u64 = (1 << OpKindBits) - 1;

const SlotShift = GenBits; // 28
const OpKindShift = GenBits + SlotBits; // 56

/// Decoded `user_data`: which kind of op completed and which connection it
/// belongs to. Pure value, no ownership.
pub const UserData = struct {
    kind: OpKind,
    token: FdToken,
};

/// Pack an op kind + FdToken into a 64-bit `user_data` value. Pure.
/// Returns `error.TokenOutOfRange` if slot/gen do not fit their fields, so a bad
/// caller cannot create an ambiguous handle.
pub fn encodeUserData(kind: OpKind, token: FdToken) error{TokenOutOfRange}!u64 {
    if (token.slot > SlotMax or token.gen > GenMax) return error.TokenOutOfRange;
    const k: u64 = @as(u64, @intFromEnum(kind)) << OpKindShift;
    const s: u64 = @as(u64, token.slot) << SlotShift;
    const g: u64 = @as(u64, token.gen);
    return k | s | g;
}

/// Safely convert a raw byte into an `OpKind`, validating it against the
/// defined enum values. `std.meta.intToEnum` does not exist in Zig 0.16, so we
/// roll a comptime-checked converter. Pure.
fn opKindFromInt(raw: u8) error{UnknownOpKind}!OpKind {
    inline for (@typeInfo(OpKind).@"enum".field_values) |f_value| {
        if (raw == f_value) return @enumFromInt(f_value);
    }
    return error.UnknownOpKind;
}

/// Decode a `user_data` value back into kind + token. Pure.
/// Returns `error.UnknownOpKind` if the kind byte is not a defined `OpKind`,
/// so a corrupt/forged completion is rejected rather than misrouted.
pub fn decodeUserData(raw: u64) error{UnknownOpKind}!UserData {
    const kind_raw: u8 = @intCast((raw >> OpKindShift) & OpKindMask);
    const kind = try opKindFromInt(kind_raw);
    const slot: u32 = @intCast((raw >> SlotShift) & SlotMask);
    const gen: u32 = @intCast(raw & GenMask);
    return .{ .kind = kind, .token = .{ .slot = slot, .gen = gen } };
}

// ---------------------------------------------------------------------------
// Typed completion events
// ---------------------------------------------------------------------------

/// An accept completion. `res` is the raw CQE result (new fd, or negative
/// errno). `more` is set when the kernel will keep delivering on this multishot
/// SQE, so the caller knows not to re-arm.
pub const AcceptEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
};

/// A recv completion. `res` is byte count or negative errno. `buffer_id` is the
/// provided-buffer ring index when buffer selection was used (else null).
pub const RecvEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
    buffer_id: ?u16,
};

/// A send completion. A copy send emits exactly one CQE and needs no separate
/// release notification: reaping that CQE is the point at which the send buffer
/// is free to reuse (the kernel may read it any time up to then — it is NOT
/// copied at submission). Zero-copy sends instead emit a primary CQE plus a
/// notification CQE; `more` on the primary zero-copy CQE means "notification
/// pending, buffer still kernel-owned", not multishot continuation. Callers must
/// use `bufferReleased()` instead of hand-rolling `more`/`notif` checks.
pub const SendEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
    notif: bool,

    /// Returns true only for the zero-copy notification CQE that releases the
    /// caller-owned buffer back to user space.
    pub fn bufferReleased(self: SendEvent) bool {
        return self.notif;
    }
};

/// A timeout completion. `res` is the raw CQE result (e.g. -ETIME on expiry).
pub const TimeoutEvent = struct {
    token: FdToken,
    res: i32,
};

/// A connect completion. `res` is 0, or a negative errno. Connect is one-shot.
pub const ConnectEvent = struct {
    token: FdToken,
    res: i32,
};

/// A poll completion. `more` is set while a multishot poll arm stays live.
pub const PollEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
};

/// Catch-all for ops without a dedicated typed event.
pub const OtherEvent = struct {
    token: FdToken,
    res: i32,
    flags: u32,
};

/// Typed completion decoded from a CQE via its `user_data`.
pub const Completion = union(OpKind) {
    other: OtherEvent,
    accept: AcceptEvent,
    recv: RecvEvent,
    send: SendEvent,
    timeout: TimeoutEvent,
    connect: ConnectEvent,
    poll: PollEvent,
};

/// Decode a raw CQE into a typed `Completion`. Pure (operates on a plain CQE
/// value, no ring access), so it is unit-testable against synthetic CQEs.
/// Propagates `decodeUserData` errors so forged/corrupt completions are rejected
/// rather than misrouted.
pub fn decodeCompletion(cqe: linux.io_uring_cqe) error{UnknownOpKind}!Completion {
    const ud = try decodeUserData(cqe.user_data);
    const more = (cqe.flags & linux.IORING_CQE_F_MORE) != 0;
    return switch (ud.kind) {
        .accept => .{ .accept = .{ .token = ud.token, .res = cqe.res, .more = more } },
        .recv => .{ .recv = .{
            .token = ud.token,
            .res = cqe.res,
            .more = more,
            .buffer_id = cqe.buffer_id() catch null,
        } },
        .send => .{ .send = .{
            .token = ud.token,
            .res = cqe.res,
            .more = more,
            .notif = (cqe.flags & linux.IORING_CQE_F_NOTIF) != 0,
        } },
        .timeout => .{ .timeout = .{ .token = ud.token, .res = cqe.res } },
        .connect => .{ .connect = .{ .token = ud.token, .res = cqe.res } },
        .poll => .{ .poll = .{ .token = ud.token, .res = cqe.res, .more = more } },
        .other => .{ .other = .{ .token = ud.token, .res = cqe.res, .flags = cqe.flags } },
    };
}

/// Cancel one exact-generation socket operation by the same `user_data`
/// identity it was submitted with. Cancelling by fd is not safe: a slot can
/// carry recv and send at once, and the descriptor may be reused. Poll and
/// timeout are not socket-quiesce targets.
pub fn exactCancelUserData(kind: OpKind, token: FdToken) error{ InvalidCancelKind, TokenOutOfRange }!struct { completion: u64, target: u64 } {
    if (kind != .accept and kind != .recv and kind != .send and kind != .connect)
        return error.InvalidCancelKind;
    return .{
        .completion = try encodeUserData(.other, token),
        .target = try encodeUserData(kind, token),
    };
}

// ---------------------------------------------------------------------------
// Ring
// ---------------------------------------------------------------------------

/// How many CQEs `reapCompletions` copies per call by default.
pub const default_cqe_batch = 256;

/// Observable result of a completion reaping pass.
pub const ReapStats = struct {
    /// CQEs successfully decoded and delivered to `handler.onCompletion`.
    processed: u32,
    /// CQEs copied from the kernel but skipped because `decodeCompletion` failed.
    skipped: u32,
};

/// Errors that mean "this environment cannot run io_uring"; callers (and tests)
/// can treat these as a clean skip rather than a hard failure.
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

/// Kernel answers for the two multishot arms this prototype is allowed to use.
/// `false` means the probe failed closed, including when it could not decide.
pub const ProbeAnswers = struct {
    accept: bool = false,
    poll: bool = false,
};

/// Read the cached multishot probe. The first call opens a scratch ring.
/// A later call reuses a definitive yes or no. An inconclusive attempt is not
/// cached. Off Linux both answers are false.
pub fn kernelProbe() ProbeAnswers {
    return KernelProbe.ensure();
}

const KernelProbe = if (builtin.os.tag != .linux) struct {
    pub fn ensure() ProbeAnswers {
        return .{};
    }
} else struct {
    var mu: std.atomic.Mutex = .unlocked;
    var accept_answer: ?bool = null;
    var poll_answer: ?bool = null;

    pub fn ensure() ProbeAnswers {
        while (!mu.tryLock()) std.Thread.yield() catch {};
        defer mu.unlock();
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
};

/// io_uring-backed reactor core. Thin wrapper over `std.os.linux.IoUring` that
/// adds typed submission helpers and typed completion decoding. One `Ring` per
/// shard is the intended deployment shape (planning/01 SQ policy). This is not
/// the daemon backend.
pub const Ring = if (builtin.os.tag == .linux) struct {
    inner: IoUring,
    features: RingFeatures,
    accept_multishot: bool = false,
    poll_multishot: bool = false,
    /// One kernel-registered provided-buffer group, or null when none is live.
    provided: ?buf_ring.LiveBufRing = null,
    /// Shortest registered buffer. A buffer-select recv uses this as its cap.
    provided_len: u32 = 0,
    /// Number of entries in the registered fixed file table. Zero means none.
    fixed_count: u32 = 0,

    /// Set up a ring with `entries` SQ slots (power of two, 1..32768). The
    /// completion queue is at least `min_cq_entries`. Cooperative task-work is
    /// requested first. `defer_taskrun` is not a setup flag. In restricted
    /// environments the errors satisfy `isUnsupportedInitError`.
    pub fn init(entries: u16, features: RingFeatures) !Ring {
        const probed = kernelProbe();
        return .{
            .inner = try openInner(entries, features),
            .features = features,
            .accept_multishot = probed.accept,
            .poll_multishot = probed.poll,
        };
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

    pub fn deinit(self: *Ring) void {
        // Unregister while the io_uring fd is still open. `free_buf_ring`
        // munmaps even when the unregister syscall fails. The kernel also
        // drops a fixed file table when the ring closes.
        if (self.provided) |*live| live.deinit();
        self.provided = null;
        self.provided_len = 0;
        if (self.fixed_count != 0) {
            self.inner.unregister_files() catch {};
            self.fixed_count = 0;
        }
        self.inner.deinit();
    }

    fn bufferCap(buffers: []const []u8) error{ EmptyBuffer, BufferTooLarge }!u32 {
        var cap: u32 = std.math.maxInt(u32);
        for (buffers) |buffer| {
            if (buffer.len == 0) return error.EmptyBuffer;
            if (buffer.len > std.math.maxInt(u32)) return error.BufferTooLarge;
            const n: u32 = @intCast(buffer.len);
            if (n < cap) cap = n;
        }
        return cap;
    }

    /// Register one provided-buffer group and publish every caller slice.
    /// One group per ring. `buffers.len` must be a non-zero power of two no
    /// larger than `buf_ring.max_buffer_count`. Each slice must be non-empty,
    /// fit in a `u32`, and stay live until the matching recv completion.
    /// The daemon does not call this.
    pub fn registerProvidedBuffers(self: *Ring, group_id: u16, buffers: [][]u8) !void {
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        if (self.provided != null) return error.AlreadyRegistered;
        if (buffers.len == 0 or buffers.len > buf_ring.max_buffer_count) return error.EntriesNotInRange;
        if (!std.math.isPowerOfTwo(buffers.len)) return error.EntriesNotPowerOfTwo;
        const cap = try bufferCap(buffers);
        const entries: u16 = @intCast(buffers.len);
        var live = try buf_ring.LiveBufRing.init(&self.inner, entries, group_id);
        errdefer live.deinit();
        for (buffers, 0..) |buffer, id| {
            try live.publish(buffer, @intCast(id));
        }
        self.provided = live;
        self.provided_len = cap;
    }

    /// Publish one used buffer back into the registered group. `buffer` must
    /// be the same slice the kernel selected for `buffer_id`.
    pub fn replenishProvidedBuffer(self: *Ring, buffer: []u8, buffer_id: u16) !void {
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        if (self.provided) |*live| {
            try live.publish(buffer, buffer_id);
            return;
        }
        return error.NotRegistered;
    }

    /// Install one fixed file table. A later submit addresses a slot by index
    /// with `IOSQE_FIXED_FILE`. One table per ring. The daemon does not call this.
    pub fn registerFixedFiles(self: *Ring, fds: []const linux.fd_t) !void {
        if (!self.features.fixed_files) return error.FeatureNotEnabled;
        if (self.fixed_count != 0) return error.AlreadyRegistered;
        if (fds.len == 0 or fds.len > std.math.maxInt(u32)) return error.EntriesNotInRange;
        try self.inner.register_files(fds);
        self.fixed_count = @intCast(fds.len);
    }

    fn fixedFd(self: *Ring, index: u32) error{ FeatureNotEnabled, NotRegistered, FileIndexOutOfRange }!linux.fd_t {
        if (!self.features.fixed_files) return error.FeatureNotEnabled;
        if (self.fixed_count == 0) return error.NotRegistered;
        if (index >= self.fixed_count) return error.FileIndexOutOfRange;
        return @intCast(index);
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

    /// Flush queued SQEs to the kernel. Returns the number submitted.
    pub fn submit(self: *Ring) !u32 {
        return self.enterSubmit(0);
    }

    /// Submit queued SQEs and block until at least `wait_nr` completions exist.
    pub fn submitAndWait(self: *Ring, wait_nr: u32) !u32 {
        return self.enterSubmit(wait_nr);
    }

    /// Post one completion onto `target` with `IORING_OP_MSG_RING` and drain
    /// both rings. The posted word is a poll identity; the source completion
    /// is `.other`.
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

    // --- typed submission helpers -----------------------------------------

    /// Arm an accept on `listener_fd` for `token`. Uses multishot accept when
    /// the kernel probe succeeded, otherwise one shot. Does not submit.
    pub fn submitAccept(self: *Ring, token: FdToken, listener_fd: linux.fd_t) !void {
        // SOCK_CLOEXEC so an accepted socket cannot leak across execve. Helix
        // clears that bit only after the successor has sealed the fds it keeps.
        const ud = try encodeUserData(.accept, token);
        if (self.accept_multishot) {
            _ = try self.inner.accept_multishot(ud, listener_fd, null, null, posix.SOCK.CLOEXEC);
        } else {
            _ = try self.inner.accept(ud, listener_fd, null, null, posix.SOCK.CLOEXEC);
        }
    }

    /// Arm a one-shot connect. `addr` must stay live until the connect CQE.
    pub fn submitConnect(self: *Ring, token: FdToken, fd: linux.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
        _ = try self.inner.connect(try encodeUserData(.connect, token), fd, addr, addrlen);
    }

    /// Watch `fd` for readiness. A probed multishot poll stays armed while
    /// `IORING_CQE_F_MORE` is set; otherwise the caller re-arms one shot.
    pub fn submitPollAdd(self: *Ring, token: FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        const user_data = try encodeUserData(.poll, token);
        const sqe = try self.inner.poll_add(user_data, fd, poll_mask);
        if (self.poll_multishot) sqe.len = linux.IORING_POLL_ADD_MULTI;
    }

    /// Queue an exact-generation cancel. The original CQE is still delivered.
    pub fn submitExactCancel(self: *Ring, kind: OpKind, token: FdToken) !void {
        const ud = try exactCancelUserData(kind, token);
        _ = try self.inner.cancel(ud.completion, ud.target, 0);
    }

    /// Arm a recv on `fd` for `token` into a caller-provided buffer. Provided
    /// buffer-ring (buf_ring) recv is gated behind that feature and uses
    /// `submitRecvBufRing` instead. Does not submit.
    pub fn submitRecv(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []u8) !void {
        const ud = try encodeUserData(.recv, token);
        _ = try self.inner.recv(ud, fd, .{ .buffer = buffer }, 0);
    }

    /// Arm a one-shot recv on `fd` for `token` that selects a buffer from the
    /// registered group. The read is capped at the shortest registered buffer.
    /// Fails closed when the feature is off, no group is registered, or
    /// `group_id` is not that group. Does not submit. Does not arm multishot.
    pub fn submitRecvBufRing(self: *Ring, token: FdToken, fd: linux.fd_t, group_id: u16) !void {
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        const live = self.provided orelse return error.NotRegistered;
        if (live.group_id != group_id) return error.NotRegistered;
        const ud = try encodeUserData(.recv, token);
        _ = try self.inner.recv(ud, fd, .{ .buffer_selection = .{
            .group_id = group_id,
            .len = self.provided_len,
        } }, 0);
    }

    /// Arm a multishot recv that keeps selecting from the registered group.
    /// Each data completion keeps `more` set until cancel, close, or an empty
    /// group. Fails closed without a registered group. Does not submit.
    pub fn submitRecvMultishot(self: *Ring, token: FdToken, fd: linux.fd_t, group_id: u16) !void {
        if (!self.features.multishot_recv or !self.features.buf_ring) return error.FeatureNotEnabled;
        const live = self.provided orelse return error.NotRegistered;
        if (live.group_id != group_id) return error.NotRegistered;
        const ud = try encodeUserData(.recv, token);
        const sqe = try self.inner.recv(ud, fd, .{ .buffer_selection = .{
            .group_id = group_id,
            .len = self.provided_len,
        } }, 0);
        sqe.ioprio |= linux.IORING_RECV_MULTISHOT;
    }

    /// Queue a copy send of `buffer` on `fd` for `token`. `IORING_OP_SEND` does
    /// NOT copy at submission time — a send that cannot complete inline is punted
    /// to async work and the kernel reads `buffer` at execution time — so the
    /// caller MUST keep `buffer` stable and live until the matching send CQE is
    /// reaped. Unlike a zero-copy send there is no separate release notification:
    /// reaping that one send CQE is the signal that `buffer` is free to reuse.
    /// Does not use zero-copy even when `features.send_zc` is enabled.
    pub fn submitSend(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        const ud = try encodeUserData(.send, token);
        _ = try self.inner.send(ud, fd, buffer, 0);
    }

    /// Queue a copy send through fixed file `index`. Requires a registered table.
    pub fn submitSendFixed(self: *Ring, token: FdToken, index: u32, buffer: []const u8) !void {
        const fd = try self.fixedFd(index);
        const sqe = try self.inner.send(try encodeUserData(.send, token), fd, buffer, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;
    }

    /// Arm a one-shot copy recv through fixed file `index`. Requires a registered table.
    pub fn submitRecvFixed(self: *Ring, token: FdToken, index: u32, buffer: []u8) !void {
        const fd = try self.fixedFd(index);
        const sqe = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer = buffer }, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;
    }

    /// Queue a zero-copy send of `buffer` on `fd` for `token`. Requires
    /// `features.send_zc`; otherwise returns `error.FeatureNotEnabled`. The
    /// caller must keep `buffer` alive until the zero-copy notification CQE is
    /// observed and `SendEvent.bufferReleased()` returns true. Does not submit.
    pub fn submitSendZc(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        if (!self.features.send_zc) return error.FeatureNotEnabled;
        const ud = try encodeUserData(.send, token);
        _ = try self.inner.send_zc(ud, fd, buffer, 0, 0);
    }

    /// Queue a (relative, single-shot) timeout for `token` after `ns`
    /// nanoseconds. `ts` must outlive the operation (kernel reads it later), so
    /// the caller owns the storage. Does not submit.
    pub fn submitTimeout(self: *Ring, token: FdToken, ts: *const linux.kernel_timespec) !void {
        const ud = try encodeUserData(.timeout, token);
        _ = try self.inner.timeout(ud, ts, 0, 0);
    }

    // --- completion reaping ------------------------------------------------

    /// Copy ready CQEs into `out`, decode each into a typed `Completion`, and
    /// invoke `handler.onCompletion(Completion)` for each. Returns processed and
    /// skipped counts so corrupt or undecodable CQEs are observable. `wait_nr` >
    /// 0 blocks for that many completions first.
    ///
    /// CQEs that fail to decode (unknown op kind) increment `skipped` rather
    /// than crashing the loop; this is the attacker/corruption-resistant path.
    pub fn reapCompletions(
        self: *Ring,
        out: []linux.io_uring_cqe,
        wait_nr: u32,
        handler: anytype,
    ) !ReapStats {
        const n = try self.inner.copy_cqes(out, wait_nr);
        return dispatchCompletions(out[0..n], handler);
    }

    /// Non-blocking variant of `reapCompletions` over the default batch.
    pub fn poll(self: *Ring, handler: anytype) !ReapStats {
        var cqes: [default_cqe_batch]linux.io_uring_cqe = undefined;
        return self.reapCompletions(&cqes, 0, handler);
    }
} else struct {
    // io_uring reactor core is a Linux-only fast path; the pure user_data codec,
    // FdToken, RingFeatures, and CQE decode above remain portable + tested.
};

fn dispatchCompletions(cqes: []const linux.io_uring_cqe, handler: anytype) ReapStats {
    var stats: ReapStats = .{ .processed = 0, .skipped = 0 };
    for (cqes) |cqe| {
        const completion = decodeCompletion(cqe) catch {
            stats.skipped += 1;
            continue;
        };
        handler.onCompletion(completion);
        stats.processed += 1;
    }
    return stats;
}

// ===========================================================================
// Tests — pure logic always runs; ring tests skip when io_uring is unavailable.
// ===========================================================================

const testing = std.testing;

test "encode/decode user_data round-trips for every op kind" {
    const tokens = [_]FdToken{
        .{ .slot = 0, .gen = 0 },
        .{ .slot = 1, .gen = 1 },
        .{ .slot = 12345, .gen = 67890 },
        .{ .slot = SlotMax, .gen = GenMax },
    };
    inline for (@typeInfo(OpKind).@"enum".field_values) |f_value| {
        const kind: OpKind = @enumFromInt(f_value);
        for (tokens) |tok| {
            const raw = try encodeUserData(kind, tok);
            const ud = try decodeUserData(raw);
            try testing.expectEqual(kind, ud.kind);
            try testing.expect(tok.eql(ud.token));
        }
    }
}

test "encodeUserData rejects out-of-range slot and gen" {
    try testing.expectError(error.TokenOutOfRange, encodeUserData(.recv, .{ .slot = SlotMax + 1, .gen = 0 }));
    try testing.expectError(error.TokenOutOfRange, encodeUserData(.recv, .{ .slot = 0, .gen = GenMax + 1 }));
}

test "decodeUserData rejects unknown op kind" {
    // Op kind byte 0xFF is not a defined OpKind.
    const raw: u64 = @as(u64, 0xFF) << OpKindShift;
    try testing.expectError(error.UnknownOpKind, decodeUserData(raw));
}

test "user_data fields do not bleed into each other" {
    // gen all-ones, slot zero, kind zero -> only gen bits set.
    const only_gen = try encodeUserData(.other, .{ .slot = 0, .gen = GenMax });
    const ud_gen = try decodeUserData(only_gen);
    try testing.expectEqual(@as(u32, 0), ud_gen.token.slot);
    try testing.expectEqual(GenMax, ud_gen.token.gen);
    try testing.expectEqual(OpKind.other, ud_gen.kind);

    // slot all-ones, gen zero -> only slot bits set.
    const only_slot = try encodeUserData(.other, .{ .slot = SlotMax, .gen = 0 });
    const ud_slot = try decodeUserData(only_slot);
    try testing.expectEqual(SlotMax, ud_slot.token.slot);
    try testing.expectEqual(@as(u32, 0), ud_slot.token.gen);
}

test "FdToken generation rejects stale completions" {
    // A live token at gen 5; a completion arrives naming gen 4 (recycled slot).
    const live: FdToken = .{ .slot = 42, .gen = 5 };
    const stale_raw = try encodeUserData(.recv, .{ .slot = 42, .gen = 4 });
    const decoded = try decodeUserData(stale_raw);
    try testing.expect(!live.eql(decoded.token));
    try testing.expectEqual(live.slot, decoded.token.slot); // same slot
    try testing.expect(live.gen != decoded.token.gen); // different generation
}

test "RingFeatures.setupFlags maps features to io_uring flags" {
    try testing.expectEqual(@as(u32, 0), RingFeatures.baseline.setupFlags());

    const sqpoll_only: RingFeatures = .{ .sqpoll = true };
    try testing.expectEqual(linux.IORING_SETUP_SQPOLL, sqpoll_only.setupFlags());

    // defer_taskrun must also set SINGLE_ISSUER.
    const defer_flags = (RingFeatures{ .defer_taskrun = true }).setupFlags();
    try testing.expect((defer_flags & linux.IORING_SETUP_DEFER_TASKRUN) != 0);
    try testing.expect((defer_flags & linux.IORING_SETUP_SINGLE_ISSUER) != 0);
}

test "RingFeatures.narrow fails closed against capabilities" {
    // Want everything; kernel supports nothing -> get nothing.
    const got_none = RingFeatures.linux_6_8_fast.narrow(RingFeatures.baseline);
    try testing.expectEqual(RingFeatures.baseline, got_none);

    // multishot_recv requires both multishot_recv AND buf_ring capability.
    const want: RingFeatures = .{ .multishot_recv = true, .buf_ring = true };
    const caps_no_bufring: RingFeatures = .{ .multishot_recv = true, .buf_ring = false };
    const narrowed = want.narrow(caps_no_bufring);
    try testing.expect(!narrowed.multishot_recv);
    try testing.expect(!narrowed.buf_ring);
}

test "RingFeatures.narrow preserves buf_ring invariant for multishot recv" {
    const want: RingFeatures = .{ .multishot_recv = true, .buf_ring = false };
    const caps: RingFeatures = .{ .multishot_recv = true, .buf_ring = true };
    const narrowed = want.narrow(caps);
    try testing.expect(narrowed.multishot_recv);
    try testing.expect(narrowed.buf_ring);
}

test "decodeCompletion produces typed events with flags" {
    const tok: FdToken = .{ .slot = 7, .gen = 3 };

    // accept with F_MORE set (multishot still active).
    const acc_cqe: linux.io_uring_cqe = .{
        .user_data = try encodeUserData(.accept, tok),
        .res = 9,
        .flags = linux.IORING_CQE_F_MORE,
    };
    const acc = try decodeCompletion(acc_cqe);
    try testing.expect(acc == .accept);
    try testing.expectEqual(@as(i32, 9), acc.accept.res);
    try testing.expect(acc.accept.more);
    try testing.expect(tok.eql(acc.accept.token));

    // send notification CQE (zero-copy second completion).
    const send_cqe: linux.io_uring_cqe = .{
        .user_data = try encodeUserData(.send, tok),
        .res = 0,
        .flags = linux.IORING_CQE_F_NOTIF,
    };
    const snd = try decodeCompletion(send_cqe);
    try testing.expect(snd == .send);
    try testing.expect(snd.send.notif);
    try testing.expect(snd.send.bufferReleased());

    // recv with a selected buffer id.
    const recv_cqe: linux.io_uring_cqe = .{
        .user_data = try encodeUserData(.recv, tok),
        .res = 128,
        .flags = linux.IORING_CQE_F_BUFFER | (@as(u32, 17) << linux.IORING_CQE_BUFFER_SHIFT),
    };
    const rcv = try decodeCompletion(recv_cqe);
    try testing.expect(rcv == .recv);
    try testing.expectEqual(@as(?u16, 17), rcv.recv.buffer_id);

    // timeout.
    const to_cqe: linux.io_uring_cqe = .{
        .user_data = try encodeUserData(.timeout, tok),
        .res = -62, // -ETIME
        .flags = 0,
    };
    const to = try decodeCompletion(to_cqe);
    try testing.expect(to == .timeout);
    try testing.expectEqual(@as(i32, -62), to.timeout.res);
}

test "decodeCompletion skips corrupt CQE via error" {
    const bad_cqe: linux.io_uring_cqe = .{
        .user_data = @as(u64, 0xFF) << OpKindShift,
        .res = 0,
        .flags = 0,
    };
    try testing.expectError(error.UnknownOpKind, decodeCompletion(bad_cqe));
}

test "SendEvent.bufferReleased reports only zero-copy notification release" {
    const tok: FdToken = .{ .slot = 1, .gen = 2 };
    const primary_zc: SendEvent = .{ .token = tok, .res = 16, .more = true, .notif = false };
    const notif_zc: SendEvent = .{ .token = tok, .res = 0, .more = false, .notif = true };
    const copy_send: SendEvent = .{ .token = tok, .res = 16, .more = false, .notif = false };

    try testing.expect(!primary_zc.bufferReleased());
    try testing.expect(notif_zc.bufferReleased());
    try testing.expect(!copy_send.bufferReleased());
}

test "reapCompletions skipped-count observes undecodable CQEs" {
    const tok: FdToken = .{ .slot = 7, .gen = 3 };
    const cqes = [_]linux.io_uring_cqe{
        .{
            .user_data = try encodeUserData(.recv, tok),
            .res = 42,
            .flags = 0,
        },
        .{
            .user_data = @as(u64, 0xFF) << OpKindShift,
            .res = 0,
            .flags = 0,
        },
        .{
            .user_data = try encodeUserData(.timeout, tok),
            .res = -62,
            .flags = 0,
        },
    };

    const Collector = struct {
        seen: u32 = 0,
        fn onCompletion(self: *@This(), c: Completion) void {
            _ = c;
            self.seen += 1;
        }
    };
    var collector = Collector{};
    const stats = dispatchCompletions(&cqes, &collector);
    try testing.expectEqual(@as(u32, 2), stats.processed);
    try testing.expectEqual(@as(u32, 1), stats.skipped);
    try testing.expectEqual(@as(u32, 2), collector.seen);
}

// --- live-ring tests: skip cleanly when io_uring is unavailable -------------

/// Helper: init a baseline ring or skip the test if the environment forbids it.
fn initOrSkip(features: RingFeatures) !Ring {
    if (builtin.os.tag == .linux) {
        return Ring.init(8, features) catch |err| {
            if (isUnsupportedInitError(err)) return error.SkipZigTest;
            return err;
        };
    }
    return error.SkipZigTest;
}

// These tests exercise a live kernel ring; their bodies are comptime-excluded
// off-Linux (where `Ring` is a stub) so the module cross-compiles for all targets.
test "ring init/deinit and nop completion round-trip" {
    if (builtin.os.tag == .linux) {
        var ring = try initOrSkip(RingFeatures.baseline);
        defer ring.deinit();

        const tok: FdToken = .{ .slot = 1, .gen = 1 };
        _ = try ring.inner.nop(try encodeUserData(.other, tok));
        _ = try ring.submitAndWait(1);

        const Collector = struct {
            seen: ?Completion = null,
            fn onCompletion(self: *@This(), c: Completion) void {
                self.seen = c;
            }
        };
        var collector = Collector{};
        var cqes: [4]linux.io_uring_cqe = undefined;
        const stats = try ring.reapCompletions(&cqes, 0, &collector);
        try testing.expectEqual(@as(u32, 1), stats.processed);
        try testing.expectEqual(@as(u32, 0), stats.skipped);
        try testing.expect(collector.seen != null);
        try testing.expect(collector.seen.? == .other);
        try testing.expect(tok.eql(collector.seen.?.other.token));
    }
}

test "submitSend uses copy path and submitSendZc is feature gated" {
    if (builtin.os.tag == .linux) {
        const tok: FdToken = .{ .slot = 5, .gen = 1 };
        const buffer = "hello";

        var disabled: Ring = .{ .inner = undefined, .features = RingFeatures.baseline };
        try testing.expectError(error.FeatureNotEnabled, disabled.submitSendZc(tok, 0, buffer));

        var copy_ring = try initOrSkip(RingFeatures.baseline);
        defer copy_ring.deinit();
        try copy_ring.submitSend(tok, 0, buffer);

        var zc_ring = try initOrSkip(.{ .send_zc = true });
        defer zc_ring.deinit();
        try zc_ring.submitSendZc(tok, 0, buffer);
    }
}

test "submitTimeout fires and decodes as a timeout completion" {
    if (builtin.os.tag == .linux) {
        var ring = try initOrSkip(RingFeatures.baseline);
        defer ring.deinit();

        const tok: FdToken = .{ .slot = 2, .gen = 9 };
        const ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 1_000_000 }; // 1ms
        try ring.submitTimeout(tok, &ts);
        _ = try ring.submitAndWait(1);

        const Collector = struct {
            kind: ?OpKind = null,
            tok: ?FdToken = null,
            fn onCompletion(self: *@This(), c: Completion) void {
                self.kind = std.meta.activeTag(c);
                self.tok = switch (c) {
                    .timeout => |t| t.token,
                    else => null,
                };
            }
        };
        var collector = Collector{};
        const stats = try ring.poll(&collector);
        try testing.expectEqual(@as(u32, 1), stats.processed);
        try testing.expectEqual(@as(u32, 0), stats.skipped);
        try testing.expectEqual(@as(?OpKind, .timeout), collector.kind);
        try testing.expect(collector.tok != null);
        try testing.expect(tok.eql(collector.tok.?));
    }
}

test "exact cancel identity covers connect and a probe caps set drops deferred taskrun" {
    const token = FdToken{ .slot = 3, .gen = 9 };
    inline for (.{ OpKind.accept, .recv, .send, .connect }) |kind| {
        const ud = try exactCancelUserData(kind, token);
        try testing.expectEqual(try encodeUserData(kind, token), ud.target);
        try testing.expectEqual(try encodeUserData(.other, token), ud.completion);
    }
    try testing.expectError(error.InvalidCancelKind, exactCancelUserData(.timeout, token));
    try testing.expectError(error.InvalidCancelKind, exactCancelUserData(.poll, token));

    const connect_cqe: linux.io_uring_cqe = .{
        .user_data = try encodeUserData(.connect, token),
        .res = 0,
        .flags = 0,
    };
    const connected = try decodeCompletion(connect_cqe);
    try testing.expect(connected == .connect);
    try testing.expectEqual(@as(i32, 0), connected.connect.res);
    try testing.expect(token.eql(connected.connect.token));

    const poll_cqe: linux.io_uring_cqe = .{
        .user_data = try encodeUserData(.poll, token),
        .res = 1,
        .flags = linux.IORING_CQE_F_MORE,
    };
    const polled = try decodeCompletion(poll_cqe);
    try testing.expect(polled == .poll);
    try testing.expect(polled.poll.more);
    try testing.expectEqual(@as(i32, 1), polled.poll.res);

    const narrowed = RingFeatures.linux_6_8_fast.narrow(.{ .multishot_accept = true });
    try testing.expect(narrowed.multishot_accept);
    try testing.expect(!narrowed.defer_taskrun);
    try testing.expect(!narrowed.multishot_recv);
    try testing.expect(!narrowed.buf_ring);
    try testing.expect(!narrowed.send_zc);
    try testing.expect(!narrowed.fixed_files);
    try testing.expect(!narrowed.sqpoll);
}

test "prototype ring accepts with CLOEXEC, connects, polls, and cancels" {
    if (builtin.os.tag != .linux) return;
    var ring = try initOrSkip(.{ .defer_taskrun = true });
    defer ring.deinit();
    try testing.expect(ring.features.defer_taskrun);
    try testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try testing.expect((ring.inner.flags & linux.IORING_SETUP_SINGLE_ISSUER) == 0);
    try testing.expect((ring.inner.flags & linux.IORING_SETUP_COOP_TASKRUN) != 0);
    try testing.expect(ring.inner.cq.cqes.len >= min_cq_entries);
    const probed = kernelProbe();
    try testing.expect(probed.accept);
    try testing.expect(probed.poll);
    try testing.expect(ring.accept_multishot);
    try testing.expect(ring.poll_multishot);

    const listener = listenLoopback() orelse return error.SkipZigTest;
    defer _ = linux.close(listener.fd);
    const accept_token: FdToken = .{ .slot = 11, .gen = 2 };
    try ring.submitAccept(accept_token, listener.fd);
    _ = try ring.submit();
    const client = connectLoopback(listener.port) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(client);

    const AcceptSink = struct {
        event: ?AcceptEvent = null,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .accept => |ev| self.event = ev,
                else => {},
            }
        }
    };
    var accept_sink = AcceptSink{};
    var cqes: [8]linux.io_uring_cqe = undefined;
    var spins: u8 = 0;
    while (accept_sink.event == null and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        _ = try ring.reapCompletions(&cqes, 0, &accept_sink);
    }
    const accepted = accept_sink.event orelse return error.TestUnexpectedResult;
    defer {
        if (accepted.res >= 0) _ = linux.close(accepted.res);
    }
    try testing.expect(accept_token.eql(accepted.token));
    try testing.expect(accepted.res >= 0);
    try testing.expect(accepted.more);
    try testing.expect(hasCloexec(accepted.res));
    try ring.submitExactCancel(.accept, accept_token);
    const CancelSink = struct {
        canceled: bool = false,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .accept => |ev| {
                    if (ev.res == -@as(i32, @intFromEnum(linux.E.CANCELED))) {
                        if (!ev.more) self.canceled = true;
                    } else if (ev.res >= 0) {
                        _ = linux.close(ev.res);
                    }
                },
                else => {},
            }
        }
    };
    var cancel_sink = CancelSink{};
    spins = 0;
    while (!cancel_sink.canceled and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        _ = try ring.reapCompletions(&cqes, 0, &cancel_sink);
    }
    try testing.expect(cancel_sink.canceled);

    const connect_fd = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(connect_fd) != .SUCCESS) return error.TestUnexpectedResult;
    const dial: linux.fd_t = @intCast(connect_fd);
    defer _ = linux.close(dial);
    var dial_addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const connect_token: FdToken = .{ .slot = 12, .gen = 2 };
    try ring.submitConnect(connect_token, dial, @ptrCast(&dial_addr), @sizeOf(linux.sockaddr.in));
    const ConnectSink = struct {
        event: ?ConnectEvent = null,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .connect => |ev| self.event = ev,
                else => {},
            }
        }
    };
    var connect_sink = ConnectSink{};
    spins = 0;
    while (connect_sink.event == null and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        _ = try ring.reapCompletions(&cqes, 0, &connect_sink);
    }
    const connected = connect_sink.event orelse return error.TestUnexpectedResult;
    try testing.expect(connect_token.eql(connected.token));
    try testing.expectEqual(@as(i32, 0), connected.res);
    const drained = linux.accept4(listener.fd, null, null, posix.SOCK.CLOEXEC);
    if (posix.errno(drained) != .SUCCESS) return error.TestUnexpectedResult;
    _ = linux.close(@intCast(drained));

    const efd_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    if (posix.errno(efd_rc) != .SUCCESS) return error.TestUnexpectedResult;
    const efd: linux.fd_t = @intCast(efd_rc);
    defer _ = linux.close(efd);
    const poll_token: FdToken = .{ .slot = 14, .gen = 2 };
    try ring.submitPollAdd(poll_token, efd, linux.POLL.IN);
    var one: u64 = 1;
    _ = linux.write(efd, @ptrCast(&one), @sizeOf(u64));
    const PollSink = struct {
        event: ?PollEvent = null,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .poll => |ev| self.event = ev,
                else => {},
            }
        }
    };
    var poll_sink = PollSink{};
    spins = 0;
    while (poll_sink.event == null and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        _ = try ring.reapCompletions(&cqes, 0, &poll_sink);
    }
    const woke = poll_sink.event orelse return error.TestUnexpectedResult;
    try testing.expect(poll_token.eql(woke.token));
    try testing.expect(woke.res > 0);
    try testing.expect(woke.more);
}

test "prototype ring registers one provided buffer and one-shot recvs" {
    if (builtin.os.tag != .linux) return;
    const token: FdToken = .{ .slot = 4, .gen = 2 };
    var disabled: Ring = .{ .inner = undefined, .features = RingFeatures.baseline };
    var none: [0][]u8 = .{};
    try testing.expectError(error.FeatureNotEnabled, disabled.registerProvidedBuffers(3, &none));
    try testing.expectError(error.FeatureNotEnabled, disabled.submitRecvBufRing(token, 0, 3));
    var unregistered: Ring = .{ .inner = undefined, .features = .{ .buf_ring = true } };
    try testing.expectError(error.NotRegistered, unregistered.submitRecvBufRing(token, 0, 3));

    var ring = try initOrSkip(.{ .buf_ring = true });
    defer ring.deinit();
    try testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try testing.expectError(error.EntriesNotInRange, ring.registerProvidedBuffers(3, &none));
    var odd_a: [4]u8 = @splat(1);
    var odd_b: [4]u8 = @splat(2);
    var odd_c: [4]u8 = @splat(3);
    var odd = [_][]u8{ &odd_a, &odd_b, &odd_c };
    try testing.expectError(error.EntriesNotPowerOfTwo, ring.registerProvidedBuffers(3, &odd));
    var empty_buf: [0]u8 = .{};
    var solid: [8]u8 = @splat(4);
    var empties = [_][]u8{ &empty_buf, &solid };
    try testing.expectError(error.EmptyBuffer, ring.registerProvidedBuffers(3, &empties));

    var buf0: [32]u8 = @splat(0xA5);
    var buf1: [32]u8 = @splat(0xA5);
    var slices = [_][]u8{ &buf0, &buf1 };
    ring.registerProvidedBuffers(3, &slices) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    try testing.expectError(error.AlreadyRegistered, ring.registerProvidedBuffers(3, &slices));

    var pair: [2]linux.fd_t = undefined;
    const opened = linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &pair);
    if (posix.errno(opened) != .SUCCESS) return error.TestUnexpectedResult;
    defer {
        _ = linux.close(pair[0]);
        _ = linux.close(pair[1]);
    }
    try testing.expectError(error.NotRegistered, ring.submitRecvBufRing(token, pair[1], 9));
    const payload = "ring-buf";
    const wrote = linux.write(pair[0], payload, payload.len);
    if (posix.errno(wrote) != .SUCCESS or wrote != payload.len) return error.TestUnexpectedResult;
    try ring.submitRecvBufRing(token, pair[1], 3);
    _ = try ring.submitAndWait(1);

    const Sink = struct {
        event: ?RecvEvent = null,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .recv => |ev| self.event = ev,
                else => {},
            }
        }
    };
    var sink = Sink{};
    var cqes: [4]linux.io_uring_cqe = undefined;
    const stats = try ring.reapCompletions(&cqes, 0, &sink);
    try testing.expectEqual(@as(u32, 1), stats.processed);
    try testing.expectEqual(@as(u32, 0), stats.skipped);
    const got = sink.event orelse return error.TestUnexpectedResult;
    try testing.expect(token.eql(got.token));
    try testing.expectEqual(@as(i32, payload.len), got.res);
    try testing.expect(!got.more);
    const id = got.buffer_id orelse return error.TestUnexpectedResult;
    try testing.expect(id < 2);
    const chosen = if (id == 0) buf0[0..payload.len] else buf1[0..payload.len];
    try testing.expectEqualSlices(u8, payload, chosen);
}

test "prototype ring multishot recv replenishes a provided buffer" {
    if (builtin.os.tag != .linux) return;
    const token: FdToken = .{ .slot = 5, .gen = 2 };
    var no_multi: Ring = .{ .inner = undefined, .features = .{ .buf_ring = true } };
    var no_buf: Ring = .{ .inner = undefined, .features = .{ .multishot_recv = true } };
    var bare: Ring = .{ .inner = undefined, .features = .{ .multishot_recv = true, .buf_ring = true } };
    var scratch: [4]u8 = @splat(1);
    var disabled: Ring = .{ .inner = undefined, .features = .{} };
    try testing.expectError(error.FeatureNotEnabled, disabled.replenishProvidedBuffer(&scratch, 0));
    try testing.expectError(error.FeatureNotEnabled, no_multi.submitRecvMultishot(token, 0, 1));
    try testing.expectError(error.FeatureNotEnabled, no_buf.submitRecvMultishot(token, 0, 1));
    try testing.expectError(error.NotRegistered, bare.submitRecvMultishot(token, 0, 1));
    try testing.expectError(error.NotRegistered, bare.replenishProvidedBuffer(&scratch, 0));

    var ring = try initOrSkip(.{ .buf_ring = true, .multishot_recv = true });
    defer ring.deinit();
    try testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    var storage: [32]u8 = @splat(0xA5);
    var slices = [_][]u8{&storage};
    ring.registerProvidedBuffers(1, &slices) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    const pair = try openStreamPair();
    defer closePair(pair);
    try testing.expectError(error.NotRegistered, ring.submitRecvMultishot(token, pair[1], 9));
    try ring.submitRecvMultishot(token, pair[1], 1);
    try writeAll(pair[0], "one!");
    const first = try reapRecv(&ring, token);
    try testing.expect(token.eql(first.token));
    try testing.expectEqual(@as(i32, 4), first.res);
    try testing.expect(first.more);
    const id = first.buffer_id orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 0), id);
    try testing.expectEqualSlices(u8, "one!", storage[0..4]);
    @memset(storage[0..], 0xA5);
    try ring.replenishProvidedBuffer(&storage, id);
    try writeAll(pair[0], "two!");
    const second = try reapRecv(&ring, token);
    try testing.expectEqual(@as(i32, 4), second.res);
    try testing.expect(second.more);
    try testing.expectEqual(@as(?u16, id), second.buffer_id);
    try testing.expectEqualSlices(u8, "two!", storage[0..4]);
    try ring.submitExactCancel(.recv, token);
    const canceled = try reapRecv(&ring, token);
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), canceled.res);
    try testing.expect(!canceled.more);
}

test "prototype ring zero-copy send releases the buffer" {
    if (builtin.os.tag != .linux) return;
    const token: FdToken = .{ .slot = 6, .gen = 2 };
    var ring = try initOrSkip(.{ .send_zc = true });
    defer ring.deinit();
    try testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    const listener = listenLoopback() orelse return error.SkipZigTest;
    defer _ = linux.close(listener.fd);
    const client = connectLoopback(listener.port) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(client);
    const accepted_rc = linux.accept4(listener.fd, null, null, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK);
    if (posix.errno(accepted_rc) != .SUCCESS) return error.TestUnexpectedResult;
    const accepted: linux.fd_t = @intCast(accepted_rc);
    defer _ = linux.close(accepted);
    const enable: u32 = 1;
    _ = linux.setsockopt(client, posix.SOL.SOCKET, linux.SO.ZEROCOPY, std.mem.asBytes(&enable), @sizeOf(u32));
    const payload = "zc-send";
    try ring.submitSendZc(token, client, payload);

    const Sink = struct {
        sent: ?SendEvent = null,
        released: ?SendEvent = null,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .send => |ev| {
                    if (ev.bufferReleased()) {
                        self.released = ev;
                    } else if (self.sent == null) {
                        self.sent = ev;
                    }
                },
                else => {},
            }
        }
    };
    var sink = Sink{};
    var cqes: [8]linux.io_uring_cqe = undefined;
    var spins: u8 = 0;
    while ((sink.sent == null or sink.released == null) and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        _ = try ring.reapCompletions(&cqes, 0, &sink);
    }
    const sent = sink.sent orelse return error.TestUnexpectedResult;
    const released = sink.released orelse return error.TestUnexpectedResult;
    try testing.expect(token.eql(sent.token));
    try testing.expectEqual(@as(i32, payload.len), sent.res);
    try testing.expect(!sent.bufferReleased());
    try testing.expect(released.bufferReleased());
    try testing.expectEqual(@as(i32, 0), released.res);

    var got: [16]u8 = @splat(0);
    var n: usize = 0;
    var reads: u8 = 0;
    while (reads < 8) : (reads += 1) {
        const rc = linux.read(accepted, @ptrCast(&got), payload.len);
        if (posix.errno(rc) == .SUCCESS) {
            n = rc;
            break;
        }
        if (posix.errno(rc) != .AGAIN) return error.TestUnexpectedResult;
        std.Thread.yield() catch {};
    }
    try testing.expectEqual(payload.len, n);
    try testing.expectEqualSlices(u8, payload, got[0..payload.len]);
}

test "prototype ring sends through a fixed file index" {
    if (builtin.os.tag != .linux) return;
    const send_token: FdToken = .{ .slot = 8, .gen = 2 };
    const recv_token: FdToken = .{ .slot = 9, .gen = 2 };
    var disabled: Ring = .{ .inner = undefined, .features = RingFeatures.baseline };
    var none: [0]linux.fd_t = .{};
    var scratch: [1]u8 = .{0};
    try testing.expectError(error.FeatureNotEnabled, disabled.registerFixedFiles(&none));
    try testing.expectError(error.FeatureNotEnabled, disabled.submitSendFixed(send_token, 0, "x"));
    try testing.expectError(error.FeatureNotEnabled, disabled.submitRecvFixed(recv_token, 0, &scratch));
    var unregistered: Ring = .{ .inner = undefined, .features = .{ .fixed_files = true } };
    try testing.expectError(error.NotRegistered, unregistered.submitSendFixed(send_token, 0, "x"));

    var ring = try initOrSkip(.{ .fixed_files = true });
    defer ring.deinit();
    try testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try testing.expectError(error.EntriesNotInRange, ring.registerFixedFiles(&none));
    const pair = try openStreamPair();
    defer closePair(pair);
    ring.registerFixedFiles(&pair) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    try testing.expectError(error.AlreadyRegistered, ring.registerFixedFiles(&pair));
    try testing.expectError(error.FileIndexOutOfRange, ring.submitSendFixed(send_token, 2, "x"));

    const payload = "fixed";
    var buf: [16]u8 = @splat(0xA5);
    try ring.submitSendFixed(send_token, 0, payload);
    try ring.submitRecvFixed(recv_token, 1, &buf);
    const Sink = struct {
        sent: ?SendEvent = null,
        got: ?RecvEvent = null,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .send => |ev| {
                    if (self.sent == null) self.sent = ev;
                },
                .recv => |ev| {
                    if (self.got == null) self.got = ev;
                },
                else => {},
            }
        }
    };
    var sink = Sink{};
    var cqes: [8]linux.io_uring_cqe = undefined;
    var spins: u8 = 0;
    while ((sink.sent == null or sink.got == null) and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        _ = try ring.reapCompletions(&cqes, 0, &sink);
    }
    const sent = sink.sent orelse return error.TestUnexpectedResult;
    const got = sink.got orelse return error.TestUnexpectedResult;
    try testing.expect(send_token.eql(sent.token));
    try testing.expect(recv_token.eql(got.token));
    try testing.expectEqual(@as(i32, payload.len), sent.res);
    try testing.expectEqual(@as(i32, payload.len), got.res);
    try testing.expect(!got.more);
    try testing.expectEqualSlices(u8, payload, buf[0..payload.len]);
}

test "prototype rings boot a message onto a full completion queue" {
    if (builtin.os.tag != .linux) return;
    var source = try initOrSkip(.{});
    defer source.deinit();
    var target = try initOrSkip(.{});
    defer target.deinit();
    try testing.expect(source.inner.cq.cqes.len >= min_cq_entries);
    try testing.expect(target.inner.cq.cqes.len >= min_cq_entries);
    try testing.expect((source.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try testing.expect((source.inner.flags & linux.IORING_SETUP_COOP_TASKRUN) != 0);
    try Ring.bootMsgRing(&source, &target);
}

fn openStreamPair() ![2]linux.fd_t {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var pair: [2]linux.fd_t = undefined;
    const opened = linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &pair);
    if (posix.errno(opened) != .SUCCESS) return error.TestUnexpectedResult;
    return pair;
}

fn closePair(pair: [2]linux.fd_t) void {
    if (comptime builtin.os.tag != .linux) return;
    _ = linux.close(pair[0]);
    _ = linux.close(pair[1]);
}

fn writeAll(fd: linux.fd_t, payload: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return;
    const wrote = linux.write(fd, payload.ptr, payload.len);
    if (posix.errno(wrote) != .SUCCESS or wrote != payload.len) return error.TestUnexpectedResult;
}

fn reapRecv(ring: *Ring, token: FdToken) !RecvEvent {
    if (comptime builtin.os.tag != .linux) return error.TestUnexpectedResult;
    const Sink = struct {
        token: FdToken,
        event: ?RecvEvent = null,
        fn onCompletion(self: *@This(), c: Completion) void {
            switch (c) {
                .recv => |ev| {
                    if (self.event == null and self.token.eql(ev.token)) self.event = ev;
                },
                else => {},
            }
        }
    };
    var sink = Sink{ .token = token };
    var cqes: [8]linux.io_uring_cqe = undefined;
    var spins: u8 = 0;
    while (sink.event == null and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        _ = try ring.reapCompletions(&cqes, 0, &sink);
    }
    if (sink.event) |event| return event;
    return error.TestUnexpectedResult;
}

fn listenLoopback() ?struct { fd: linux.fd_t, port: u16 } {
    if (comptime builtin.os.tag != .linux) return null;
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
    if (comptime builtin.os.tag != .linux) return null;
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
    if (comptime builtin.os.tag != .linux) return false;
    const flags = linux.fcntl(fd, posix.F.GETFD, 0);
    return posix.errno(flags) == .SUCCESS and (flags & posix.FD_CLOEXEC) != 0;
}

test {
    testing.refAllDecls(@This());
}
