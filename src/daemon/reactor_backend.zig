// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Full-daemon reactor contract. Linux keeps the exact production Ringlane
//! type; BSD translates native one-shot operations to its typed completions.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const ringlane = @import("ringlane.zig");
const io_backend = @import("io_backend.zig");

pub const Ring = if (builtin.os.tag == .linux) ringlane.Ring else PortableRing;
pub const CompletionBuffer = if (builtin.os.tag == .linux) linux.io_uring_cqe else io_backend.Reaped;

const PortableRing = struct {
    backend: io_backend.IoBackend,
    features: ringlane.RingFeatures,
    ready: [32]io_backend.Reaped = undefined,
    ready_n: usize = 0,
    dispatching: ?[]const io_backend.Reaped = null,
    dispatch_index: usize = 0,

    pub fn init(entries: u16, features: ringlane.RingFeatures) !PortableRing {
        if (comptime builtin.os.tag != .openbsd and builtin.os.tag != .freebsd and
            builtin.os.tag != .netbsd and builtin.os.tag != .dragonfly) return error.Unsupported;
        // Linux acceleration flags cannot silently claim support on kqueue.
        if (features.multishot_accept or features.multishot_recv or features.buf_ring or
            features.send_zc or features.fixed_files or features.defer_taskrun or features.sqpoll)
            return error.Unsupported;
        var backend = try io_backend.IoBackend.openOwned(.kqueue, entries, .{});
        errdefer backend.deinit();
        try backend.requireAll();
        try backend.useStreamCompletions();
        if (!backend.opImplemented(.connect)) return error.Unsupported;
        return .{ .backend = backend, .features = features };
    }

    pub fn deinit(self: *PortableRing) void {
        self.backend.deinit();
        self.ready_n = 0;
    }

    pub fn submit(self: *PortableRing) !u32 {
        return self.backend.submit();
    }

    pub fn submitAndWait(self: *PortableRing, wait_nr: u32) !u32 {
        if (wait_nr > self.ready.len) return error.Unsupported;
        const n = try self.submit();
        while (self.ready_n < wait_nr) {
            const got = try self.backend.reap(self.ready[self.ready_n..], 1000);
            self.ready_n += got;
        }
        return n;
    }

    pub fn submitAccept(self: *PortableRing, token: ringlane.FdToken, fd: i32) !void {
        _ = try ringlane.encodeUserData(.accept, token);
        try self.backend.accept(token, fd);
    }

    pub fn submitRecv(self: *PortableRing, token: ringlane.FdToken, fd: i32, buffer: []u8) !void {
        _ = try ringlane.encodeUserData(.recv, token);
        try self.backend.recv(token, fd, buffer);
    }

    pub fn submitSend(self: *PortableRing, token: ringlane.FdToken, fd: i32, buffer: []const u8) !void {
        _ = try ringlane.encodeUserData(.send, token);
        try self.backend.send(token, fd, buffer);
    }

    pub fn submitConnect(self: *PortableRing, token: ringlane.FdToken, fd: i32, addr: *const std.posix.sockaddr, addrlen: std.posix.socklen_t) !void {
        _ = try ringlane.encodeUserData(.connect, token);
        try self.backend.connect(token, fd, addr, addrlen);
    }

    pub fn submitExactCancel(self: *PortableRing, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        _ = try ringlane.Ring.exactCancelUserData(kind, token);
        for (self.ready[0..self.ready_n]) |done| {
            if (opKind(done.op) == kind and done.token.slot == token.slot and done.token.gen == token.gen) return;
        }
        if (self.dispatching) |batch| {
            for (batch[self.dispatch_index + 1 ..]) |done| {
                if (opKind(done.op) == kind and done.token.slot == token.slot and done.token.gen == token.gen) return;
            }
        }
        try self.backend.cancel(kind, token);
    }

    pub fn submitTimeout(self: *PortableRing, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        _ = try ringlane.encodeUserData(.timeout, token);
        try self.backend.timeout(token, ts);
    }

    pub fn submitPollAdd(self: *PortableRing, token: ringlane.FdToken, fd: i32, mask: u32) !void {
        _ = try ringlane.encodeUserData(.poll, token);
        try self.backend.poll(token, fd, mask);
    }

    pub fn reapCompletions(self: *PortableRing, out: []CompletionBuffer, wait_nr: u32, handler: anytype) !void {
        return self.reapPortableCompletions(out, wait_nr, handler);
    }

    fn reapPortableCompletions(self: *PortableRing, out: []io_backend.Reaped, wait_nr: u32, handler: anytype) !void {
        if (out.len == 0) return;
        if (wait_nr > out.len) return error.Unsupported;
        var n: usize = @min(out.len, self.ready_n);
        @memcpy(out[0..n], self.ready[0..n]);
        std.mem.copyForwards(io_backend.Reaped, self.ready[0 .. self.ready_n - n], self.ready[n..self.ready_n]);
        self.ready_n -= n;
        if (n == 0 or n < wait_nr) {
            n += try self.backend.reap(out[n..], if (wait_nr == 0) 0 else 1000);
            while (n < wait_nr) n += try self.backend.reap(out[n..], 1000);
        }
        // Copy the complete native batch before dispatch. A handler can cancel
        // later operations without changing outcomes already owned by this batch.
        self.dispatching = out[0..n];
        defer self.dispatching = null;
        for (out[0..n], 0..) |done, i| {
            self.dispatch_index = i;
            handler.onCompletion(toCompletion(done));
        }
    }

    /// Linux's MSG_RING handshake validates a Linux-specific acceleration.
    /// Kqueue needs no ring-to-ring messages; cross-reactor wakes use socketpair.
    pub fn bootMsgRing(_: *PortableRing, _: *PortableRing) !void {}
};

fn opKind(op: io_backend.Op) ringlane.OpKind {
    return switch (op) {
        .accept => .accept,
        .recv => .recv,
        .send => .send,
        .connect => .connect,
        .poll => .poll,
        .timeout => .timeout,
        .cancel => .other,
    };
}

/// Full daemon handlers consume Ringlane's errno namespace. Native values such
/// as BSD EAGAIN=35 and ECANCELED=89 must never masquerade as Linux errno values.
fn canonicalResult(result: i32) i32 {
    if (result >= 0 or builtin.os.tag == .linux) return result;
    const magnitude = -@as(i64, result);
    inline for (@typeInfo(linux.E).@"enum".field_names, @typeInfo(linux.E).@"enum".field_values) |name, value| {
        if (@hasField(std.posix.E, name)) {
            const native_value = @intFromEnum(@field(std.posix.E, name));
            if (magnitude == native_value) return -@as(i32, @intCast(value));
        }
    }
    return -@as(i32, @intFromEnum(linux.E.IO));
}

fn toCompletion(done: io_backend.Reaped) ringlane.Completion {
    const result = canonicalResult(done.result);
    return switch (done.op) {
        .accept => .{ .accept = .{ .token = done.token, .res = result, .more = false } },
        .recv => .{ .recv = .{ .token = done.token, .res = result, .more = false } },
        .send => .{ .send = .{ .token = done.token, .res = result, .more = false, .notif = false } },
        .connect => .{ .connect = .{ .token = done.token, .res = result } },
        .poll => .{ .poll = .{ .token = done.token, .res = result } },
        .timeout => .{ .timeout = {} },
        .cancel => .{ .other = {} },
    };
}

test "reactor facade preserves original cancellation identity and canonical errors" {
    const token = ringlane.FdToken{ .slot = 13, .gen = 7 };
    const recv = toCompletion(.{ .op = .recv, .token = token, .result = -@as(i32, @intFromEnum(std.posix.E.CANCELED)) }).recv;
    try std.testing.expectEqual(token, recv.token);
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), recv.res);
    try std.testing.expect(!recv.more);
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.AGAIN)), canonicalResult(-@as(i32, @intFromEnum(std.posix.E.AGAIN))));
    if (comptime builtin.os.tag == .linux) try std.testing.expect(Ring == ringlane.Ring);
}

test "reactor facade keeps later copied original completions in cancellation custody" {
    var ring = PortableRing{ .backend = io_backend.IoBackend.closed(.kqueue, 8), .features = .{} };
    defer ring.deinit();
    const token = ringlane.FdToken{ .slot = 6, .gen = 3 };
    ring.ready[0] = .{ .op = .recv, .token = token, .result = 0 };
    ring.ready[1] = .{ .op = .send, .token = token, .result = 2 };
    ring.ready_n = 2;
    const Sink = struct {
        ring: *PortableRing,
        token: ringlane.FdToken,
        n: usize = 0,
        cancel_failed: bool = false,
        pub fn onCompletion(self: *@This(), _: ringlane.Completion) void {
            if (self.n == 0) self.ring.submitExactCancel(.send, self.token) catch {
                self.cancel_failed = true;
            };
            self.n += 1;
        }
    };
    var sink = Sink{ .ring = &ring, .token = token };
    // This exercises the BSD implementation even on a Linux development host.
    var scratch: [2]io_backend.Reaped = undefined;
    try ring.reapPortableCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(@as(usize, 2), sink.n);
    try std.testing.expect(!sink.cancel_failed);
    try std.testing.expect(ring.dispatching == null);
    try std.testing.expectError(error.MissingOp, ring.submitExactCancel(.send, token));
}
