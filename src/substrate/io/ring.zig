// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unfinished Ringlane io_uring prototype — not the production backend.
//!
//! The live daemon ring lives inline in `src/daemon/server.zig`. Do not adopt
//! this module as a drop-in: `OpKind` has no `.connect` / `.poll` / cancel
//! (Helix quiesce is unimplementable on it), `narrow()` is not a kernel probe,
//! `buf_ring.registerAll` never registers with the kernel, and accept flags
//! are `0` (the daemon passes `SOCK.CLOEXEC` to avoid split-brain after
//! execve). Multishot receive and provided-buffer rings stay out of 0.7.
//!
//! Kept as a design sketch and a home for the pure user_data / FdToken /
//! RingFeatures tests. The `Reactor` seam (`src/substrate/reactor.zig`) does
//! not dispatch here.
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
const linux = std.os.linux;
// io_uring is a Linux-only fast path; `void` off-Linux so the pure helpers in
// this file (user_data codec, FdToken, RingFeatures, CQE decode) stay portable.
const IoUring = if (builtin.os.tag == .linux) linux.IoUring else void;

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

    /// linux_6_1_safe persona: multishot accept/recv + buf_ring + fixed files +
    /// defer_taskrun. The production default tier from planning/05.
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
    /// closed). Pure: callers feed it the result of a runtime probe. Keeping it
    /// separate from the probe itself makes the narrowing logic testable without
    /// a kernel.
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
        .other => .{ .other = .{ .token = ud.token, .res = cqe.res, .flags = cqe.flags } },
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

/// io_uring-backed reactor core. Thin wrapper over `std.os.linux.IoUring` that
/// adds typed submission helpers and typed completion decoding. One `Ring` per
/// shard is the intended deployment shape (planning/01 SQ policy).
pub const Ring = if (builtin.os.tag == .linux) struct {
    inner: IoUring,
    features: RingFeatures,

    /// Set up a ring with `entries` SQ slots (power of two, 1..32768) using the
    /// setup flags derived from `features`. Returns the same errors as
    /// `IoUring.init`; in restricted environments those satisfy
    /// `isUnsupportedInitError` and should be treated as a skip.
    pub fn init(entries: u16, features: RingFeatures) !Ring {
        const inner = try IoUring.init(entries, features.setupFlags());
        return .{ .inner = inner, .features = features };
    }

    pub fn deinit(self: *Ring) void {
        self.inner.deinit();
    }

    /// Flush queued SQEs to the kernel. Returns the number submitted.
    pub fn submit(self: *Ring) !u32 {
        return self.inner.submit();
    }

    /// Submit queued SQEs and block until at least `wait_nr` completions exist.
    pub fn submitAndWait(self: *Ring, wait_nr: u32) !u32 {
        return self.inner.submit_and_wait(wait_nr);
    }

    // --- typed submission helpers -----------------------------------------

    /// Arm an accept on `listener_fd` for `token`. Uses multishot accept when
    /// the compiled feature profile allows it, else a one-shot accept. Does not
    /// submit; call `submit` afterwards.
    pub fn submitAccept(self: *Ring, token: FdToken, listener_fd: linux.fd_t) !void {
        const ud = try encodeUserData(.accept, token);
        if (self.features.multishot_accept) {
            _ = try self.inner.accept_multishot(ud, listener_fd, null, null, 0);
        } else {
            _ = try self.inner.accept(ud, listener_fd, null, null, 0);
        }
    }

    /// Arm a recv on `fd` for `token` into a caller-provided buffer. Provided
    /// buffer-ring (buf_ring) recv is gated behind that feature and uses
    /// `submitRecvBufRing` instead. Does not submit.
    pub fn submitRecv(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []u8) !void {
        const ud = try encodeUserData(.recv, token);
        _ = try self.inner.recv(ud, fd, .{ .buffer = buffer }, 0);
    }

    /// Arm a recv on `fd` for `token` selecting a buffer from provided-buffer
    /// ring group `group_id`. Requires the `buf_ring` feature to be compiled in.
    /// Does not submit.
    pub fn submitRecvBufRing(self: *Ring, token: FdToken, fd: linux.fd_t, group_id: u16) !void {
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        const ud = try encodeUserData(.recv, token);
        _ = try self.inner.recv(ud, fd, .{ .buffer_selection = .{ .group_id = group_id, .len = 0 } }, 0);
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

test {
    testing.refAllDecls(@This());
}
