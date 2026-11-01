// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux Helix handoff transport: sealed memfd arena and SCM_RIGHTS fd passing.
//!
//! The supervisor and workers exchange state through one sealed memfd and pass
//! client/listener descriptors over an AF_UNIX SOCK_SEQPACKET control socket.
//! Linux syscall paths are gated at runtime; non-Linux targets compile and
//! return `error.Unsupported`.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub const max_fds_per_message: usize = 253;

const f_add_seals: i32 = 1033;
const f_seal_seal: u32 = 0x0001;
const f_seal_shrink: u32 = 0x0002;
const f_seal_grow: u32 = 0x0004;
const f_seal_write: u32 = 0x0008;
const scm_rights: i32 = 0x01;
const msg_ctrunc: u32 = 0x08;
const msg_trunc: u32 = 0x20;

pub const Error = error{
    Unsupported,
    MemfdCreateFailed,
    WriteFailed,
    SealFailed,
    SocketPairFailed,
    SendFailed,
    RecvFailed,
    EmptyFdBatch,
    ControlTruncated,
    PayloadTruncated,
    InvalidControl,
    MissingRights,
    TooManyFds,
} || Allocator.Error;

pub const Fd = linux.fd_t;

pub const Arena = struct {
    fd: Fd = -1,
    size: usize = 0,
    sealed: bool = false,

    pub fn create(name: []const u8) Error!Arena {
        if (builtin.os.tag != .linux) return error.Unsupported;
        var zname: [64]u8 = undefined;
        const len = @min(name.len, zname.len - 1);
        @memcpy(zname[0..len], name[0..len]);
        zname[len] = 0;

        const rc = linux.memfd_create(@ptrCast(&zname), linux.MFD.CLOEXEC | linux.MFD.ALLOW_SEALING);
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .fd = @intCast(rc) },
            else => return error.MemfdCreateFailed,
        }
    }

    pub fn writeAll(self: *Arena, bytes: []const u8) Error!void {
        if (builtin.os.tag != .linux) return error.Unsupported;
        if (self.sealed) return error.SealFailed;
        var written: usize = 0;
        while (written < bytes.len) {
            const rc = linux.write(self.fd, bytes.ptr + written, bytes.len - written);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) return error.WriteFailed;
                    written += n;
                },
                .INTR => continue,
                else => return error.WriteFailed,
            }
        }
        self.size += written;
    }

    pub fn seal(self: *Arena) Error!void {
        if (builtin.os.tag != .linux) return error.Unsupported;
        const seals = f_seal_seal | f_seal_shrink | f_seal_grow | f_seal_write;
        const rc = linux.fcntl(self.fd, f_add_seals, seals);
        switch (linux.errno(rc)) {
            .SUCCESS => self.sealed = true,
            else => return error.SealFailed,
        }
    }

    pub fn close(self: *Arena) void {
        if (builtin.os.tag == .linux and self.fd >= 0) {
            _ = linux.close(self.fd);
        }
        self.* = .{};
    }
};

pub const SocketPair = struct {
    supervisor: Fd,
    worker: Fd,

    pub fn close(self: *SocketPair) void {
        if (builtin.os.tag == .linux) {
            if (self.supervisor >= 0) _ = linux.close(self.supervisor);
            if (self.worker >= 0) _ = linux.close(self.worker);
        }
        self.* = .{ .supervisor = -1, .worker = -1 };
    }
};

pub fn socketPair() Error!SocketPair {
    if (builtin.os.tag != .linux) return error.Unsupported;
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds);
    switch (linux.errno(rc)) {
        .SUCCESS => return .{ .supervisor = fds[0], .worker = fds[1] },
        else => return error.SocketPairFailed,
    }
}

pub fn fdBatchCount(fd_count: usize) usize {
    if (fd_count == 0) return 0;
    return (fd_count + max_fds_per_message - 1) / max_fds_per_message;
}

pub fn batchLen(fd_count: usize, batch_index: usize) usize {
    const start = batch_index * max_fds_per_message;
    if (start >= fd_count) return 0;
    return @min(max_fds_per_message, fd_count - start);
}

pub fn sendFdBatches(socket_fd: Fd, fds: []const Fd, payload: []const u8) Error!usize {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (fds.len == 0) return error.EmptyFdBatch;

    var sent_batches: usize = 0;
    var index: usize = 0;
    while (index < fds.len) {
        const take = @min(max_fds_per_message, fds.len - index);
        try sendFdBatch(socket_fd, fds[index .. index + take], payload);
        sent_batches += 1;
        index += take;
    }
    return sent_batches;
}

pub fn sendFdBatch(socket_fd: Fd, fds: []const Fd, payload: []const u8) Error!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (fds.len == 0) return error.EmptyFdBatch;
    if (fds.len > max_fds_per_message) return error.TooManyFds;

    var empty_payload = [_]u8{0};
    const body = if (payload.len == 0) empty_payload[0..] else payload;
    var iov = std.posix.iovec_const{ .base = body.ptr, .len = body.len };

    var control: [controlSpace(max_fds_per_message)]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    @memset(&control, 0);
    const fd_bytes = std.mem.sliceAsBytes(fds);
    const used = controlSpace(fds.len);
    const hdr: *linux.cmsghdr = @ptrCast(&control);
    hdr.* = .{
        .len = controlLen(fd_bytes.len),
        .level = linux.SOL.SOCKET,
        .type = scm_rights,
    };
    @memcpy(control[alignCmsg(@sizeOf(linux.cmsghdr)) .. alignCmsg(@sizeOf(linux.cmsghdr)) + fd_bytes.len], fd_bytes);

    const msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &control,
        .controllen = used,
        .flags = 0,
    };

    const rc = linux.sendmsg(socket_fd, &msg, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .INTR => return try sendFdBatch(socket_fd, fds, payload),
        else => return error.SendFailed,
    }
}

pub const ReceivedBatch = struct {
    bytes: []u8,
    fds: []Fd,

    pub fn deinit(self: *ReceivedBatch, allocator: Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.fds);
        self.* = .{ .bytes = &.{}, .fds = &.{} };
    }
};

pub fn recvFdBatch(allocator: Allocator, socket_fd: Fd, max_payload: usize) Error!ReceivedBatch {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const body = try allocator.alloc(u8, @max(1, max_payload));
    errdefer allocator.free(body);

    var iov = std.posix.iovec{ .base = body.ptr, .len = body.len };
    var control: [controlSpace(max_fds_per_message)]u8 align(@alignOf(linux.cmsghdr)) = undefined;
    @memset(&control, 0);

    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };

    const rc = while (true) {
        msg.controllen = control.len;
        msg.flags = 0;
        const result = linux.recvmsg(socket_fd, &msg, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break result,
            .INTR => continue,
            else => return error.RecvFailed,
        }
    };
    // Once recvmsg succeeds, every complete SCM_RIGHTS descriptor belongs to
    // this function, even if later validation/allocation fails. Keep that
    // ownership in a bounded stack array until the successful return.
    var owned: [max_fds_per_message]Fd = undefined;
    var owned_len: usize = 0;
    errdefer for (owned[0..owned_len]) |fd| {
        _ = linux.close(fd);
    };
    const control_len: usize = @min(msg.controllen, control.len);
    var offset: usize = 0;
    var headers: usize = 0;
    var invalid = msg.controllen > control.len;
    while (offset < control_len) {
        if (control_len - offset < @sizeOf(linux.cmsghdr)) {
            invalid = true;
            break;
        }
        const hdr: *const linux.cmsghdr = @ptrCast(@alignCast(control[offset..].ptr));
        const remaining = control_len - offset;
        if (hdr.len < controlLen(0)) {
            invalid = true;
            break;
        }
        const available = @min(hdr.len, remaining);
        if (hdr.level == linux.SOL.SOCKET and hdr.type == scm_rights) {
            const data_bytes = available - controlLen(0);
            const whole = data_bytes / @sizeOf(Fd);
            for (0..whole) |i| {
                var fd: Fd = undefined;
                const at = offset + controlLen(0) + i * @sizeOf(Fd);
                @memcpy(std.mem.asBytes(&fd), control[at..][0..@sizeOf(Fd)]);
                if (owned_len == owned.len) {
                    _ = linux.close(fd);
                    invalid = true;
                } else {
                    owned[owned_len] = fd;
                    owned_len += 1;
                }
            }
            if (data_bytes % @sizeOf(Fd) != 0) invalid = true;
        } else invalid = true;
        headers += 1;
        if (hdr.len > remaining) {
            invalid = true;
            break;
        }
        const aligned = alignCmsg(hdr.len);
        if (aligned > remaining) {
            if (hdr.len != remaining) invalid = true;
            break;
        }
        offset += aligned;
    }
    if (msg.flags & msg_ctrunc != 0) return error.ControlTruncated;
    if (msg.flags & msg_trunc != 0 or rc > body.len) return error.PayloadTruncated;
    if (invalid or headers > 1) return error.InvalidControl;
    if (headers != 1 or owned_len == 0) return error.MissingRights;
    const fds = try allocator.dupe(Fd, owned[0..owned_len]);
    errdefer allocator.free(fds);
    const bytes = try allocator.realloc(body, @intCast(rc));
    return .{ .bytes = bytes, .fds = fds };
}

fn alignCmsg(len: usize) usize {
    return std.mem.alignForward(usize, len, @sizeOf(usize));
}

fn controlLen(data_len: usize) usize {
    return alignCmsg(@sizeOf(linux.cmsghdr)) + data_len;
}

fn controlSpace(fd_count: usize) usize {
    return alignCmsg(@sizeOf(linux.cmsghdr)) + alignCmsg(fd_count * @sizeOf(Fd));
}

test "SCM_RIGHTS batches respect the 253 fd kernel limit" {
    try std.testing.expectEqual(@as(usize, 0), fdBatchCount(0));
    try std.testing.expectEqual(@as(usize, 1), fdBatchCount(1));
    try std.testing.expectEqual(@as(usize, 1), fdBatchCount(max_fds_per_message));
    try std.testing.expectEqual(@as(usize, 2), fdBatchCount(max_fds_per_message + 1));
    try std.testing.expectEqual(max_fds_per_message, batchLen(300, 0));
    try std.testing.expectEqual(@as(usize, 47), batchLen(300, 1));
}

test "control message sizing is aligned and monotonic" {
    const zero = controlSpace(0);
    const one = controlSpace(1);
    const many = controlSpace(max_fds_per_message);
    try std.testing.expect(zero >= @sizeOf(linux.cmsghdr));
    try std.testing.expect(one > zero);
    try std.testing.expect(many > one);
    try std.testing.expectEqual(@as(usize, 0), zero % @sizeOf(usize));
}

test "linux socketpair can pass a memfd descriptor" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var sockets = try socketPair();
    defer sockets.close();

    var arena = try Arena.create("helix-test");
    defer arena.close();
    try arena.writeAll("capsule");
    try arena.seal();

    const fds = [_]Fd{arena.fd};
    try std.testing.expectEqual(@as(usize, 1), try sendFdBatches(sockets.supervisor, &fds, "arena"));

    var recv = try recvFdBatch(allocator, sockets.worker, 16);
    defer {
        for (recv.fds) |fd| _ = linux.close(fd);
        recv.deinit(allocator);
    }

    try std.testing.expect(std.mem.eql(u8, recv.bytes, "arena"));
    try std.testing.expectEqual(@as(usize, 1), recv.fds.len);
}

const HandoffNoResizeTestAllocator = struct {
    backing: Allocator,
    fn allocator(self: *HandoffNoResizeTestAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = Allocator.noResize, .remap = Allocator.noRemap, .free = free } };
    }
    fn alloc(raw: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(raw));
        return self.backing.rawAlloc(len, alignment, ra);
    }
    fn free(raw: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.backing.rawFree(memory, alignment, ra);
    }
};
fn handoffTestPipe() ![2]Fd {
    var pipe: [2]Fd = undefined;
    if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true, .NONBLOCK = true })) != .SUCCESS) return error.TestPipeFailed;
    return pipe;
}
fn handoffExpectPipeEof(read_fd: Fd) !void {
    var byte: [1]u8 = undefined;
    const rc = linux.read(read_fd, &byte, 1);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try std.testing.expectEqual(@as(usize, 0), rc);
}

test "handoff received rights allocation failures close kernel descriptors" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var successful = false;
    for (0..64) |index| {
        var sockets = try socketPair();
        const pipe = try handoffTestPipe();
        defer _ = linux.close(pipe[0]);
        try sendFdBatch(sockets.supervisor, &.{pipe[1]}, "ok");
        _ = linux.close(pipe[1]);
        var no_resize = HandoffNoResizeTestAllocator{ .backing = std.testing.allocator };
        var failing = std.testing.FailingAllocator.init(no_resize.allocator(), .{ .fail_index = index });
        if (recvFdBatch(failing.allocator(), sockets.worker, 64)) |value| {
            var result = value;
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqualStrings("ok", result.bytes);
            try std.testing.expectEqual(@as(usize, 1), result.fds.len);
            for (result.fds) |fd| _ = linux.close(fd);
            result.deinit(failing.allocator());
            successful = true;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
        }
        sockets.close();
        try handoffExpectPipeEof(pipe[0]);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (successful) break;
    }
    try std.testing.expect(successful);
}

test "handoff truncated payload closes received rights" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var sockets = try socketPair();
    defer sockets.close();
    const pipe = try handoffTestPipe();
    defer _ = linux.close(pipe[0]);
    try sendFdBatch(sockets.supervisor, &.{pipe[1]}, "oversized");
    _ = linux.close(pipe[1]);
    try std.testing.expectError(error.PayloadTruncated, recvFdBatch(std.testing.allocator, sockets.worker, 2));
    sockets.close();
    try handoffExpectPipeEof(pipe[0]);
}

test "handoff extra or truncated ancillary closes received rights" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]bool{ false, true }) |truncated| {
        var sockets = try socketPair();
        defer sockets.close();
        const enabled: u32 = 1;
        const set = linux.setsockopt(sockets.worker, linux.SOL.SOCKET, linux.SO.PASSCRED, std.mem.asBytes(&enabled), @sizeOf(u32));
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(set));
        const pipe = try handoffTestPipe();
        defer _ = linux.close(pipe[0]);
        var writes: [max_fds_per_message]Fd = undefined;
        const count: usize = if (truncated) max_fds_per_message else 1;
        writes[0] = pipe[1];
        for (writes[1..count]) |*fd| {
            const rc = linux.dup(pipe[1]);
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
            fd.* = @intCast(rc);
        }
        try sendFdBatch(sockets.supervisor, writes[0..count], "x");
        for (writes[0..count]) |fd| _ = linux.close(fd);
        if (truncated) {
            try std.testing.expectError(error.ControlTruncated, recvFdBatch(std.testing.allocator, sockets.worker, 8));
        } else {
            try std.testing.expectError(error.InvalidControl, recvFdBatch(std.testing.allocator, sockets.worker, 8));
        }
        sockets.close();
        try handoffExpectPipeEof(pipe[0]);
    }
}

test "handoff receives maximum real rights with independent descriptor ownership" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var sockets = try socketPair();
    defer sockets.close();
    const pipe = try handoffTestPipe();
    defer _ = linux.close(pipe[0]);
    var writes: [max_fds_per_message]Fd = @splat(-1);
    writes[0] = pipe[1];
    defer for (writes) |fd| {
        if (fd >= 0) _ = linux.close(fd);
    };
    for (writes[1..]) |*fd| {
        const result = linux.dup(pipe[1]);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(result));
        fd.* = @intCast(result);
    }
    try sendFdBatch(sockets.supervisor, &writes, "maximum batch");
    for (&writes) |*fd| {
        _ = linux.close(fd.*);
        fd.* = -1;
    }
    var received = try recvFdBatch(std.testing.allocator, sockets.worker, 64);
    defer {
        for (received.fds) |fd| if (fd >= 0) {
            _ = linux.close(fd);
        };
        received.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings("maximum batch", received.bytes);
    try std.testing.expectEqual(max_fds_per_message, received.fds.len);
    const byte = [_]u8{0x5a};
    for (received.fds, 0..) |fd, i| {
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.fcntl(fd, std.posix.F.GETFD, 0)));
        for (received.fds[0..i]) |earlier| try std.testing.expect(fd != earlier);
        try std.testing.expectEqual(@as(usize, 1), linux.write(fd, &byte, byte.len));
    }
    var data: [max_fds_per_message]u8 = undefined;
    const n = linux.read(pipe[0], &data, data.len);
    try std.testing.expectEqual(@as(usize, max_fds_per_message), n);
    try std.testing.expect(std.mem.allEqual(u8, &data, byte[0]));
    for (received.fds) |*fd| {
        _ = linux.close(fd.*);
        fd.* = -1;
    }
    sockets.close();
    try handoffExpectPipeEof(pipe[0]);
}
