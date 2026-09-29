// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ringlane submission and completion.
//!
//! Linux io_uring only. The production ring lives here; `substrate/io/ring.zig`
//! stays the unfinished prototype and is not this backend.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const IoUring = linux.IoUring;

pub const default_cqe_batch: usize = 256;
pub const max_cqe_batch: usize = 4096;

pub const RingFeatures = struct {
    multishot_accept: bool = false,
    multishot_recv: bool = false,
    buf_ring: bool = false,
    send_zc: bool = false,
    fixed_files: bool = false,
    defer_taskrun: bool = false,
    sqpoll: bool = false,

    pub const baseline: @This() = .{};

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
        .poll => .{ .poll = .{ .token = ud.token, .res = cqe.res } },
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

pub const Ring = struct {
    inner: IoUring,
    features: RingFeatures,

    pub fn init(entries: u16, features: RingFeatures) !Ring {
        return .{ .inner = try IoUring.init(entries, features.setupFlags()), .features = features };
    }

    pub fn deinit(self: *Ring) void {
        self.inner.deinit();
    }

    pub fn submit(self: *Ring) !u32 {
        return self.inner.submit();
    }

    pub fn submitAndWait(self: *Ring, wait_nr: u32) !u32 {
        return self.inner.submit_and_wait(wait_nr);
    }

    pub fn submitAccept(self: *Ring, token: FdToken, listener_fd: linux.fd_t) !void {
        _ = self.features;
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
        _ = try self.inner.accept(try encodeUserData(.accept, token), listener_fd, null, null, posix.SOCK.CLOEXEC);
    }

    pub fn submitRecv(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []u8) !void {
        _ = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer = buffer }, 0);
    }

    pub fn submitConnect(self: *Ring, token: FdToken, fd: linux.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
        _ = try self.inner.connect(try encodeUserData(.connect, token), fd, addr, addrlen);
    }

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

    /// Watch `fd` for readability (single-shot); fires a `.poll` completion.
    /// Used by a reactor to wake on its cross-reactor eventfd (see
    /// reactor_wake.zig) — re-arm after each completion.
    pub fn submitPollAdd(self: *Ring, token: FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        _ = try self.inner.poll_add(try encodeUserData(.poll, token), fd, poll_mask);
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
        _ = try source.inner.submit_and_wait(1);
        var source_cqe: [1]linux.io_uring_cqe = undefined;
        const source_n = try source.inner.copy_cqes(&source_cqe, 0);
        if (source_n != 1 or source_cqe[0].res != 0) return error.Unexpected;
        if (source_cqe[0].user_data != try encodeUserData(.other, token)) return error.Unexpected;
        _ = try target.inner.submit_and_wait(1);
        var target_cqe: [1]linux.io_uring_cqe = undefined;
        const target_n = try target.inner.copy_cqes(&target_cqe, 0);
        if (target_n != 1 or target_cqe[0].res != 1) return error.Unexpected;
        if (target_cqe[0].user_data != posted) return error.Unexpected;
    }
};

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

    var ring = Ring.init(32, .{}) catch |err| {
        if (isUnsupportedInitError(err)) {
            std.debug.print("GAP-X2 branch=ringlane submission and completion moved; baseline ring init refused with a listed error\n", .{});
            return;
        }
        return err;
    };
    defer ring.deinit();
    try std.testing.expectEqual(@as(u32, 0), try ring.submit());
    std.debug.print("GAP-X2 branch=ringlane submission and completion moved out of server.zig and the codec still round-trips\n", .{});
}
