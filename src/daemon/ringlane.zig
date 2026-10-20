// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ringlane submission and completion.
//!
//! Linux io_uring only. The production ring lives here. `substrate/io/ring.zig`
//! is the same shape of prototype and is not this backend.
//!
//! The live ring probes multishot accept and multishot wake-poll, sizes the
//! completion queue for a full reactor batch, and arms cooperative task-work.
//! `IORING_SETUP_DEFER_TASKRUN` and `IORING_SETUP_SINGLE_ISSUER` are never
//! requested. When a provided-buffer group is installed, multishot recv selects
//! from that group. The daemon copies those bytes into the connection buffer
//! before parse or a Helix snapshot, then replenishes the slice. Zero-copy send
//! keeps the send buffer until `IORING_CQE_F_NOTIF`. Copy recv and copy send
//! stay available for kTLS and for a ring with no group. Fixed files are
//! implemented here and are not used on the connection path: registration idles
//! the ring, and Helix inherits raw fds. `buf_ring.registerAll` stays pure.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const IoUring = linux.IoUring;
const buf_ring = @import("../substrate/io/buf_ring.zig");

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
    /// Set only when the kernel selected a provided buffer. A copy recv leaves
    /// this null so the caller buffer is the payload.
    buffer_id: ?u16 = null,
};

pub const SendEvent = struct {
    token: FdToken,
    res: i32,
    more: bool,
    notif: bool,

    /// True only on the zero-copy notification that releases the send buffer.
    pub fn bufferReleased(self: SendEvent) bool {
        return self.notif;
    }
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

/// Upper 16 bits of the CQE flags are a provided-buffer id only when
/// `IORING_CQE_F_BUFFER` is set. A copy completion must stay null.
fn providedBufferId(cqe: linux.io_uring_cqe) ?u16 {
    if ((cqe.flags & linux.IORING_CQE_F_BUFFER) == 0) return null;
    return @intCast(cqe.flags >> linux.IORING_CQE_BUFFER_SHIFT);
}

fn decodeCompletion(cqe: linux.io_uring_cqe) error{UnknownOpKind}!Completion {
    const ud = try decodeUserData(cqe.user_data);
    const more = (cqe.flags & linux.IORING_CQE_F_MORE) != 0;
    return switch (ud.kind) {
        .other => .{ .other = {} },
        .accept => .{ .accept = .{ .token = ud.token, .res = cqe.res, .more = more } },
        .recv => .{ .recv = .{
            .token = ud.token,
            .res = cqe.res,
            .more = more,
            .buffer_id = providedBufferId(cqe),
        } },
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

/// Provided-buffer group size for `clients` connections. Multishot recv can
/// take a second buffer before userspace replenishes, so the group is at least
/// twice the connection cap, rounded up to a power of two, and never above the
/// kernel's provided-buffer ceiling.
pub fn bufferGroupCount(clients: u32) u16 {
    const doubled: u32 = if (clients > (std.math.maxInt(u32) / 2)) std.math.maxInt(u32) else clients * 2;
    const want: u32 = if (doubled < 2) 2 else doubled;
    var rounded: u32 = 1;
    while (rounded < want) {
        if (rounded >= buf_ring.max_buffer_count) return buf_ring.max_buffer_count;
        rounded <<= 1;
    }
    if (rounded > buf_ring.max_buffer_count) return buf_ring.max_buffer_count;
    return @intCast(rounded);
}

pub const Ring = struct {
    inner: IoUring,
    features: RingFeatures,
    accept_multishot: bool = false,
    poll_multishot: bool = false,
    provided: ?buf_ring.LiveBufRing = null,
    provided_len: u32 = 0,
    provided_group: u16 = 0,
    fixed_count: u32 = 0,
    /// Caller-owned slice table, or the table owned by `pool_allocator`.
    external_slices: ?[][]u8 = null,
    pool_mem: ?[]u8 = null,
    pool_slices: ?[][]u8 = null,
    pool_allocator: ?std.mem.Allocator = null,

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
        if (comptime builtin.os.tag == .linux) {
            if (self.provided) |*live| live.deinit();
        }
        self.provided = null;
        self.provided_len = 0;
        self.provided_group = 0;
        if (self.fixed_count != 0) {
            self.inner.unregister_files() catch {};
            self.fixed_count = 0;
        }
        self.inner.deinit();
        const allocator = self.pool_allocator;
        if (self.pool_slices) |slices| {
            if (allocator) |alloc| alloc.free(slices);
            self.pool_slices = null;
        }
        if (self.pool_mem) |mem| {
            if (allocator) |alloc| alloc.free(mem);
            self.pool_mem = null;
        }
        self.pool_allocator = null;
        self.external_slices = null;
    }

    pub fn hasProvidedGroup(self: *const Ring) bool {
        return self.provided != null;
    }

    pub fn providedGroup(self: *const Ring) u16 {
        return self.provided_group;
    }

    pub fn providedSlice(self: *const Ring, buffer_id: u16) ?[]u8 {
        const slices = self.external_slices orelse return null;
        if (buffer_id >= slices.len) return null;
        return slices[buffer_id];
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

    /// One-shot copy into the caller buffer. The kernel writes `buffer`, and
    /// the matching CQE releases it. Multishot and provided-buffer recv use
    /// `submitRecvMultishot` so a Helix snapshot never aliases pool memory.
    pub fn submitRecv(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []u8) !void {
        _ = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer = buffer }, 0);
    }

    pub fn submitConnect(self: *Ring, token: FdToken, fd: linux.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
        _ = try self.inner.connect(try encodeUserData(.connect, token), fd, addr, addrlen);
    }

    /// Copy send. The one completion releases `buffer`. A zero-copy send is
    /// `submitSendZc` and stays owned until the notification CQE.
    pub fn submitSend(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        _ = try self.inner.send(try encodeUserData(.send, token), fd, buffer, 0);
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
    /// One group per ring. `buffers` must stay live until each selected buffer
    /// is replenished or the ring is torn down. `buffers.len` is a non-zero
    /// power of two no larger than `buf_ring.max_buffer_count`.
    pub fn registerProvidedBuffers(self: *Ring, group_id: u16, buffers: [][]u8) !void {
        if (comptime builtin.os.tag != .linux) return error.FeatureNotEnabled;
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        if (self.provided != null) return error.AlreadyRegistered;
        if (buffers.len == 0 or buffers.len > buf_ring.max_buffer_count) return error.EntriesNotInRange;
        if (!std.math.isPowerOfTwo(buffers.len)) return error.EntriesNotPowerOfTwo;
        const cap = try bufferCap(buffers);
        const entries: u16 = @intCast(buffers.len);
        if (comptime builtin.os.tag == .linux) {
            var live = try buf_ring.LiveBufRing.init(&self.inner, entries, group_id);
            errdefer live.deinit();
            for (buffers, 0..) |buffer, id| {
                try live.publish(buffer, @intCast(id));
            }
            self.provided = live;
            self.provided_len = cap;
            self.provided_group = group_id;
            self.external_slices = buffers;
        }
    }

    /// Allocate `count` buffers of `stride` bytes, register them as one group,
    /// and free them from `Ring.deinit`. A failed install leaves the ring on
    /// the copy path.
    pub fn installOwnedBuffers(
        self: *Ring,
        allocator: std.mem.Allocator,
        count: u16,
        stride: usize,
        group_id: u16,
    ) !void {
        if (comptime builtin.os.tag != .linux) return error.FeatureNotEnabled;
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        if (self.provided != null or self.pool_allocator != null) return error.AlreadyRegistered;
        if (count == 0 or count > buf_ring.max_buffer_count) return error.EntriesNotInRange;
        if (!std.math.isPowerOfTwo(count)) return error.EntriesNotPowerOfTwo;
        if (stride == 0 or stride > std.math.maxInt(u32)) return error.BufferTooLarge;
        const bytes_len = std.math.mul(usize, count, stride) catch return error.BufferTooLarge;
        const bytes = try allocator.alloc(u8, bytes_len);
        errdefer allocator.free(bytes);
        const slices = try allocator.alloc([]u8, count);
        errdefer allocator.free(slices);
        for (slices, 0..) |*slot, index| {
            const start = index * stride;
            slot.* = bytes[start..][0..stride];
        }
        try self.registerProvidedBuffers(group_id, slices);
        self.pool_mem = bytes;
        self.pool_slices = slices;
        self.pool_allocator = allocator;
    }

    /// Publish one used buffer back into the registered group. `buffer` must
    /// be the slice the kernel selected for `buffer_id`.
    pub fn replenishProvidedBuffer(self: *Ring, buffer: []u8, buffer_id: u16) !void {
        if (comptime builtin.os.tag != .linux) return error.FeatureNotEnabled;
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        if (comptime builtin.os.tag == .linux) {
            if (self.provided) |*live| {
                try live.publish(buffer, buffer_id);
                return;
            }
        }
        return error.NotRegistered;
    }

    fn groupMatches(self: *const Ring, group_id: u16) bool {
        if (comptime builtin.os.tag != .linux) return false;
        if (comptime builtin.os.tag == .linux) {
            const live = self.provided orelse return false;
            return live.group_id == group_id;
        }
        return false;
    }

    /// Arm a one-shot recv that selects from the registered group.
    pub fn submitRecvBufRing(self: *Ring, token: FdToken, fd: linux.fd_t, group_id: u16) !void {
        if (!self.features.buf_ring) return error.FeatureNotEnabled;
        if (self.provided == null or !self.groupMatches(group_id)) return error.NotRegistered;
        _ = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer_selection = .{
            .group_id = group_id,
            .len = self.provided_len,
        } }, 0);
    }

    /// Arm a multishot recv that keeps selecting from the registered group.
    /// Each data completion keeps `more` set until cancel, close, or an empty
    /// group. Does not submit.
    pub fn submitRecvMultishot(self: *Ring, token: FdToken, fd: linux.fd_t, group_id: u16) !void {
        if (!self.features.multishot_recv or !self.features.buf_ring) return error.FeatureNotEnabled;
        if (self.provided == null or !self.groupMatches(group_id)) return error.NotRegistered;
        const sqe = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer_selection = .{
            .group_id = group_id,
            .len = self.provided_len,
        } }, 0);
        sqe.ioprio |= linux.IORING_RECV_MULTISHOT;
    }

    /// Install one fixed file table. Later submits address a slot by index.
    /// Not used for accepted connections: the call waits for the ring to idle,
    /// and a Helix successor receives the raw fd.
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

    pub fn submitSendFixed(self: *Ring, token: FdToken, index: u32, buffer: []const u8) !void {
        const fd = try self.fixedFd(index);
        const sqe = try self.inner.send(try encodeUserData(.send, token), fd, buffer, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;
    }

    pub fn submitRecvFixed(self: *Ring, token: FdToken, index: u32, buffer: []u8) !void {
        const fd = try self.fixedFd(index);
        const sqe = try self.inner.recv(try encodeUserData(.recv, token), fd, .{ .buffer = buffer }, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;
    }

    /// Queue a zero-copy send. `buffer` stays owned until the notification CQE.
    pub fn submitSendZc(self: *Ring, token: FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        if (!self.features.send_zc) return error.FeatureNotEnabled;
        _ = try self.inner.send_zc(try encodeUserData(.send, token), fd, buffer, 0, 0);
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
            try std.testing.expect(ev.bufferReleased());
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
            try std.testing.expectEqual(@as(?u16, null), ev.buffer_id);
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

test "ringlane buffer group count is two connections rounded up and capped" {
    try std.testing.expectEqual(@as(u16, 2), bufferGroupCount(0));
    try std.testing.expectEqual(@as(u16, 2), bufferGroupCount(1));
    try std.testing.expectEqual(@as(u16, 2048), bufferGroupCount(1024));
    try std.testing.expectEqual(buf_ring.max_buffer_count, bufferGroupCount(20_000));
    try std.testing.expectEqual(buf_ring.max_buffer_count, bufferGroupCount(std.math.maxInt(u32)));
}

test "ringlane provided buffers, zero-copy send, and fixed files" {
    if (comptime builtin.os.tag != .linux) return;
    const recv_token = FdToken{ .slot = 4, .gen = 2 };
    var disabled: Ring = .{ .inner = undefined, .features = .{} };
    var none: [0][]u8 = .{};
    try std.testing.expectError(error.FeatureNotEnabled, disabled.registerProvidedBuffers(1, &none));
    try std.testing.expectError(error.FeatureNotEnabled, disabled.submitRecvBufRing(recv_token, 0, 1));
    try std.testing.expectError(error.FeatureNotEnabled, disabled.submitRecvMultishot(recv_token, 0, 1));
    try std.testing.expectError(error.FeatureNotEnabled, disabled.submitSendZc(recv_token, 0, "x"));
    var no_files: [0]linux.fd_t = .{};
    try std.testing.expectError(error.FeatureNotEnabled, disabled.registerFixedFiles(&no_files));
    var unregistered: Ring = .{ .inner = undefined, .features = .{ .buf_ring = true, .multishot_recv = true, .fixed_files = true } };
    try std.testing.expectError(error.NotRegistered, unregistered.submitRecvMultishot(recv_token, 0, 1));
    try std.testing.expectError(error.NotRegistered, unregistered.submitSendFixed(recv_token, 0, "x"));

    var ring = Ring.init(32, .{ .buf_ring = true, .multishot_recv = true, .send_zc = true, .fixed_files = true }) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    defer ring.deinit();
    try std.testing.expect((ring.inner.flags & linux.IORING_SETUP_DEFER_TASKRUN) == 0);
    try std.testing.expect((ring.inner.flags & linux.IORING_SETUP_SINGLE_ISSUER) == 0);
    try std.testing.expectError(error.EntriesNotInRange, ring.registerProvidedBuffers(1, &none));
    var odd_a: [4]u8 = @splat(1);
    var odd_b: [4]u8 = @splat(2);
    var odd_c: [4]u8 = @splat(3);
    var odd = [_][]u8{ &odd_a, &odd_b, &odd_c };
    try std.testing.expectError(error.EntriesNotPowerOfTwo, ring.registerProvidedBuffers(1, &odd));

    var storage: [32]u8 = @splat(0xA5);
    var slices = [_][]u8{&storage};
    ring.registerProvidedBuffers(1, &slices) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    try std.testing.expect(ring.hasProvidedGroup());
    try std.testing.expectEqual(@as(u16, 1), ring.providedGroup());
    const pair = linuxSocketPair() orelse return error.SkipZigTest;
    defer closeFdPair(pair);
    try std.testing.expectError(error.NotRegistered, ring.submitRecvMultishot(recv_token, pair[1], 9));
    try ring.submitRecvMultishot(recv_token, pair[1], 1);
    try writeFdAll(pair[0], "one!");
    const first = try reapOneRecv(&ring, recv_token);
    try std.testing.expectEqual(@as(i32, 4), first.res);
    try std.testing.expect(first.more);
    const id = first.buffer_id orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 0), id);
    try std.testing.expectEqualSlices(u8, "one!", storage[0..4]);
    const view = ring.providedSlice(id) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "one!", view[0..4]);
    @memset(storage[0..], 0xA5);
    try ring.replenishProvidedBuffer(view, id);
    try writeFdAll(pair[0], "two!");
    const second = try reapOneRecv(&ring, recv_token);
    try std.testing.expectEqual(@as(i32, 4), second.res);
    try std.testing.expect(second.more);
    try std.testing.expectEqual(@as(?u16, id), second.buffer_id);
    try std.testing.expectEqualSlices(u8, "two!", storage[0..4]);
    try ring.submitExactCancel(.recv, recv_token);
    const canceled = try reapOneRecv(&ring, recv_token);
    try std.testing.expect(isErrno(canceled.res, .CANCELED));
    try std.testing.expect(!canceled.more);

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
    const send_token = FdToken{ .slot = 6, .gen = 2 };
    try ring.submitSendZc(send_token, client, payload);
    const sent = try reapSendPair(&ring, send_token);
    try std.testing.expectEqual(@as(i32, payload.len), sent.bytes.res);
    try std.testing.expect(!sent.bytes.bufferReleased());
    try std.testing.expect(sent.bytes.more);
    try std.testing.expect(sent.released.bufferReleased());
    try std.testing.expectEqual(@as(i32, 0), sent.released.res);
    var got: [16]u8 = @splat(0);
    var n: usize = 0;
    var reads: u8 = 0;
    while (reads < 8) : (reads += 1) {
        const rc = linux.read(accepted, got[0..].ptr, payload.len);
        if (posix.errno(rc) == .SUCCESS) {
            n = rc;
            break;
        }
        if (posix.errno(rc) != .AGAIN) return error.TestUnexpectedResult;
        std.Thread.yield() catch {};
    }
    try std.testing.expectEqual(payload.len, n);
    try std.testing.expectEqualSlices(u8, payload, got[0..payload.len]);

    try std.testing.expectError(error.EntriesNotInRange, ring.registerFixedFiles(&no_files));
    ring.registerFixedFiles(&pair) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    try std.testing.expectError(error.AlreadyRegistered, ring.registerFixedFiles(&pair));
    try std.testing.expectError(error.FileIndexOutOfRange, ring.submitSendFixed(send_token, 2, "x"));
    const fixed_send = FdToken{ .slot = 8, .gen = 2 };
    const fixed_recv = FdToken{ .slot = 9, .gen = 2 };
    var fixed_buf: [16]u8 = @splat(0xA5);
    try ring.submitSendFixed(fixed_send, 0, "fixed");
    try ring.submitRecvFixed(fixed_recv, 1, &fixed_buf);
    const fixed = try reapFixedExchange(&ring, fixed_send, fixed_recv);
    try std.testing.expectEqual(@as(i32, 5), fixed.send.res);
    try std.testing.expectEqual(@as(i32, 5), fixed.recv.res);
    try std.testing.expect(!fixed.recv.more);
    try std.testing.expectEqualSlices(u8, "fixed", fixed_buf[0..5]);

    var owned = Ring.init(8, .{ .buf_ring = true }) catch |err| {
        if (isUnsupportedInitError(err)) return error.SkipZigTest;
        return err;
    };
    defer owned.deinit();
    try owned.installOwnedBuffers(std.testing.allocator, bufferGroupCount(2), 32, 7);
    try std.testing.expect(owned.hasProvidedGroup());
    try std.testing.expectEqual(@as(u16, 4), bufferGroupCount(2));
    try std.testing.expect(owned.providedSlice(0) != null);
    try std.testing.expect(owned.providedSlice(3) != null);
    try std.testing.expect(owned.providedSlice(4) == null);
}

const SendPair = struct { bytes: SendEvent, released: SendEvent };
const FixedExchange = struct { send: SendEvent, recv: RecvEvent };

fn linuxSocketPair() ?[2]linux.fd_t {
    if (comptime builtin.os.tag != .linux) return null;
    var pair: [2]linux.fd_t = undefined;
    const opened = linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &pair);
    if (posix.errno(opened) != .SUCCESS) return null;
    return pair;
}

fn closeFdPair(pair: [2]linux.fd_t) void {
    if (comptime builtin.os.tag != .linux) return;
    _ = linux.close(pair[0]);
    _ = linux.close(pair[1]);
}

fn writeFdAll(fd: linux.fd_t, payload: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return;
    const wrote = linux.write(fd, payload.ptr, payload.len);
    if (posix.errno(wrote) != .SUCCESS or wrote != payload.len) return error.TestUnexpectedResult;
}

fn reapOneRecv(ring: *Ring, token: FdToken) !RecvEvent {
    const Sink = struct {
        token: FdToken,
        event: ?RecvEvent = null,
        fn onCompletion(self: *@This(), completion: Completion) void {
            switch (completion) {
                .recv => |ev| {
                    if (self.event == null and ev.token.slot == self.token.slot and ev.token.gen == self.token.gen) {
                        self.event = ev;
                    }
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
        try ring.reapCompletions(&cqes, 0, &sink);
    }
    return sink.event orelse error.TestUnexpectedResult;
}

fn reapSendPair(ring: *Ring, token: FdToken) !SendPair {
    const Sink = struct {
        token: FdToken,
        sent: ?SendEvent = null,
        released: ?SendEvent = null,
        fn onCompletion(self: *@This(), completion: Completion) void {
            switch (completion) {
                .send => |ev| {
                    if (ev.token.slot != self.token.slot or ev.token.gen != self.token.gen) return;
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
    var sink = Sink{ .token = token };
    var cqes: [8]linux.io_uring_cqe = undefined;
    var spins: u8 = 0;
    while ((sink.sent == null or sink.released == null) and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        try ring.reapCompletions(&cqes, 0, &sink);
    }
    return .{
        .bytes = sink.sent orelse return error.TestUnexpectedResult,
        .released = sink.released orelse return error.TestUnexpectedResult,
    };
}

fn reapFixedExchange(ring: *Ring, send_token: FdToken, recv_token: FdToken) !FixedExchange {
    const Sink = struct {
        send_token: FdToken,
        recv_token: FdToken,
        sent: ?SendEvent = null,
        got: ?RecvEvent = null,
        fn onCompletion(self: *@This(), completion: Completion) void {
            switch (completion) {
                .send => |ev| {
                    if (self.sent == null and ev.token.slot == self.send_token.slot and ev.token.gen == self.send_token.gen) {
                        self.sent = ev;
                    }
                },
                .recv => |ev| {
                    if (self.got == null and ev.token.slot == self.recv_token.slot and ev.token.gen == self.recv_token.gen) {
                        self.got = ev;
                    }
                },
                else => {},
            }
        }
    };
    var sink = Sink{ .send_token = send_token, .recv_token = recv_token };
    var cqes: [8]linux.io_uring_cqe = undefined;
    var spins: u8 = 0;
    while ((sink.sent == null or sink.got == null) and spins < 8) : (spins += 1) {
        _ = try ring.submitAndWait(1);
        try ring.reapCompletions(&cqes, 0, &sink);
    }
    return .{
        .send = sink.sent orelse return error.TestUnexpectedResult,
        .recv = sink.got orelse return error.TestUnexpectedResult,
    };
}
