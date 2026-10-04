// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-reactor wakeup primitive for the sharded multi-reactor model.
//!
//! In the sharded design each reactor owns its own io_uring and spends most of
//! its life blocked in `io_uring_enter` waiting for completions. When reactor A
//! enqueues a cross-shard delivery into reactor B's mailbox (see
//! `shard.zig` `Mailboxes`), B may be asleep and would never notice the queued
//! work until some unrelated completion happened to fire. `ReactorWake` closes
//! that gap with a kernel `eventfd` on Linux or a socket wake on other kernels:
//!
//!   * Each reactor owns exactly one `ReactorWake`.
//!   * The owning reactor registers `wake.fd()` for a read in its io_uring (a
//!     POLL/READ SQE). The read stays pending until someone writes the eventfd.
//!   * Any thread (a *different* reactor) calls `wake(target)` after pushing
//!     into the target's mailbox. The write makes the registered read complete,
//!     so the target reactor's loop runs, drains the eventfd, and then drains
//!     its mailbox.
//!
//! A `WakeSet(num_shards)` holds one `ReactorWake` per shard so any reactor can
//! address any other by shard index: `set.wake(target_shard)` /
//! `set.fd(target_shard)`.
//!
//! Flag choice: the eventfd is created with `EFD.NONBLOCK` and *without*
//! `EFD.SEMAPHORE`. The non-semaphore counter semantics are deliberate — many
//! `wake()` writes coalesce into a single non-zero counter, and one `drain()`
//! read clears it to zero. That matches the desired "there is work, go look"
//! edge: the reactor does not care *how many* deliveries are pending, only that
//! it must rescan its mailbox. `NONBLOCK` keeps both `wake()` and `drain()` from
//! ever blocking the caller, which is mandatory: `wake()` runs on a foreign
//! reactor thread and `drain()` runs on the io_uring loop, neither of which may
//! stall. (Semaphore mode would force one read per write and is the wrong fit.)
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const io_backend = @import("io_backend.zig");

const invalid_windows_socket = std.math.maxInt(usize);
const windows_would_block = 10035;
const windows_interrupted = 10004;
const windows_fionbio: u32 = 0x8004667e;

const WindowsSockAddr4 = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

comptime {
    if (@sizeOf(WindowsSockAddr4) != 16) @compileError("Windows sockaddr_in must be 16 bytes");
}

extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
extern "ws2_32" fn WSASocketW(address_family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
extern "ws2_32" fn bind(socket: usize, addr: *const WindowsSockAddr4, namelen: i32) callconv(.winapi) i32;
extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;
extern "ws2_32" fn getsockname(socket: usize, addr: *WindowsSockAddr4, namelen: *i32) callconv(.winapi) i32;
extern "ws2_32" fn getpeername(socket: usize, addr: *WindowsSockAddr4, namelen: *i32) callconv(.winapi) i32;
extern "ws2_32" fn connect(socket: usize, addr: *const WindowsSockAddr4, namelen: i32) callconv(.winapi) i32;
extern "ws2_32" fn accept(socket: usize, addr: ?*anyopaque, namelen: ?*i32) callconv(.winapi) usize;
extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
extern "ws2_32" fn recv(socket: usize, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
extern "ws2_32" fn send(socket: usize, buf: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;

/// Single-owner cross-reactor wakeup handle wrapping an eventfd or socket pair.
pub const ReactorWake = struct {
    /// Pollable read descriptor. Owned and closed by this `ReactorWake`.
    handle: linux.fd_t,
    write_handle: linux.fd_t = -1,
    /// Windows keeps the raw SOCKETs for nonblocking send/drain; `handle` is
    /// the opaque IOCP descriptor registered for AFD poll operations.
    windows_read_socket: usize = invalid_windows_socket,
    windows_write_socket: usize = invalid_windows_socket,
    windows_wsa_started: bool = false,

    /// The 8-byte payload `wake()` writes. Any non-zero value works; `1` keeps
    /// the counter from overflowing in practice (`UINT64_MAX - 1` writes would
    /// be required to saturate, far beyond any realistic backlog).
    const wake_token: u64 = 1;

    /// Create a nonblocking wake endpoint with no pending signal.
    pub fn init() error{ReactorWakeUnsupported}!ReactorWake {
        if (comptime builtin.os.tag != .linux) {
            if (comptime builtin.os.tag == .windows) return initWindows();
            if (comptime builtin.os.tag != .openbsd and builtin.os.tag != .freebsd and
                builtin.os.tag != .netbsd and builtin.os.tag != .dragonfly) return error.ReactorWakeUnsupported;
            var sockets: [2]std.c.fd_t = undefined;
            if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &sockets) != 0) return error.ReactorWakeUnsupported;
            errdefer {
                for (sockets) |sock| _ = std.c.close(sock);
            }
            for (sockets) |sock| {
                const flags = std.c.fcntl(sock, @as(c_int, 3), @as(c_int, 0));
                if (flags < 0 or std.c.fcntl(sock, @as(c_int, 4), flags | @as(c_int, 4)) < 0)
                    return error.ReactorWakeUnsupported;
                const fdflags = std.c.fcntl(sock, @as(c_int, 1), @as(c_int, 0));
                if (fdflags < 0 or std.c.fcntl(sock, @as(c_int, 2), fdflags | @as(c_int, 1)) < 0)
                    return error.ReactorWakeUnsupported;
            }
            return .{ .handle = sockets[0], .write_handle = sockets[1] };
        }
        const rc = linux.eventfd(0, linux.EFD.NONBLOCK | linux.EFD.CLOEXEC);
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .handle = @intCast(rc) },
            // ENOSYS (no eventfd2), EMFILE/ENFILE (fd exhaustion), ENOMEM, or
            // EINVAL (bad flags) all mean we cannot stand up the primitive.
            else => return error.ReactorWakeUnsupported,
        }
    }

    fn initWindows() error{ReactorWakeUnsupported}!ReactorWake {
        if (comptime builtin.os.tag != .windows) return error.ReactorWakeUnsupported;
        var startup: [408]u8 = @splat(0);
        if (WSAStartup(0x0202, &startup) != 0) return error.ReactorWakeUnsupported;
        errdefer _ = WSACleanup();

        const listener = WSASocketW(2, 1, 6, null, 0, 1); // AF_INET, SOCK_STREAM, IPPROTO_TCP, OVERLAPPED
        if (listener == invalid_windows_socket) return error.ReactorWakeUnsupported;
        defer _ = closesocket(listener);
        var address = WindowsSockAddr4{
            .family = 2,
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
            .zero = @splat(0),
        };
        if (bind(listener, &address, @sizeOf(WindowsSockAddr4)) != 0 or
            listen(listener, 1) != 0) return error.ReactorWakeUnsupported;
        var address_len: i32 = @sizeOf(WindowsSockAddr4);
        if (getsockname(listener, &address, &address_len) != 0 or address_len != @sizeOf(WindowsSockAddr4))
            return error.ReactorWakeUnsupported;

        var writer = WSASocketW(2, 1, 6, null, 0, 1);
        if (writer == invalid_windows_socket) return error.ReactorWakeUnsupported;
        errdefer {
            if (writer != invalid_windows_socket) _ = closesocket(writer);
        }
        if (connect(writer, &address, @sizeOf(WindowsSockAddr4)) != 0) return error.ReactorWakeUnsupported;
        var reader = accept(listener, null, null);
        if (reader == invalid_windows_socket) return error.ReactorWakeUnsupported;
        errdefer {
            if (reader != invalid_windows_socket) _ = closesocket(reader);
        }
        // A different local process must not be able to seize the ephemeral
        // listener and leave this wake path attached to the wrong peer.
        var writer_local: WindowsSockAddr4 = undefined;
        var reader_peer: WindowsSockAddr4 = undefined;
        var writer_local_len: i32 = @sizeOf(WindowsSockAddr4);
        var reader_peer_len: i32 = @sizeOf(WindowsSockAddr4);
        if (getsockname(writer, &writer_local, &writer_local_len) != 0 or
            getpeername(reader, &reader_peer, &reader_peer_len) != 0 or
            writer_local_len != @sizeOf(WindowsSockAddr4) or
            reader_peer_len != @sizeOf(WindowsSockAddr4) or
            writer_local.family != reader_peer.family or
            writer_local.addr != reader_peer.addr or
            writer_local.port != reader_peer.port) return error.ReactorWakeUnsupported;
        var nonblocking: u32 = 1;
        if (ioctlsocket(reader, windows_fionbio, &nonblocking) != 0 or
            ioctlsocket(writer, windows_fionbio, &nonblocking) != 0) return error.ReactorWakeUnsupported;

        const wake_fd = io_backend.adoptWindowsSocket(reader) catch return error.ReactorWakeUnsupported;
        const read_socket = reader;
        reader = invalid_windows_socket;
        const write_socket = writer;
        writer = invalid_windows_socket;
        return .{
            .handle = wake_fd,
            .windows_read_socket = read_socket,
            .windows_write_socket = write_socket,
            .windows_wsa_started = true,
        };
    }

    /// Close the underlying wake handles. Idempotent only if not called twice.
    pub fn deinit(self: *ReactorWake) void {
        if (comptime builtin.os.tag != .linux) {
            if (comptime builtin.os.tag == .windows) {
                io_backend.closeSocket(self.handle);
                if (self.windows_write_socket != invalid_windows_socket) _ = closesocket(self.windows_write_socket);
                if (self.windows_wsa_started) _ = WSACleanup();
                self.handle = -1;
                self.windows_read_socket = invalid_windows_socket;
                self.windows_write_socket = invalid_windows_socket;
                self.windows_wsa_started = false;
                return;
            }
            _ = std.c.close(self.handle);
            _ = std.c.close(self.write_handle);
            self.handle = -1;
            self.write_handle = -1;
            return;
        }
        _ = linux.close(self.handle);
        self.handle = -1;
    }

    /// Pollable read descriptor to register with the owning reactor.
    pub fn fd(self: ReactorWake) linux.fd_t {
        return self.handle;
    }

    /// Wake the owning reactor by writing the eventfd or socket. Safe to call from
    /// ANY thread and idempotent-ish: repeated calls before a `drain()` simply
    /// accumulate into the same non-zero counter. `EAGAIN` (the counter is at
    /// its max and would block) is ignored — readiness is already pending, so a
    /// dropped increment changes nothing. All other errnos are ignored too: a
    /// failed wake must never propagate up the foreign reactor's hot path.
    pub fn wake(self: ReactorWake) void {
        if (comptime builtin.os.tag != .linux) {
            if (comptime builtin.os.tag == .windows) {
                const byte = [_]u8{1};
                while (send(self.windows_write_socket, &byte, 1, 0) < 0) {
                    if (WSAGetLastError() != windows_interrupted) break;
                }
                return;
            }
            const byte = [_]u8{1};
            while (std.c.send(self.write_handle, &byte, 1, std.c.MSG.NOSIGNAL) < 0) {
                if (std.c._errno().* != @as(c_int, @intFromEnum(std.posix.E.INTR))) break;
            }
            return;
        }
        const bytes = std.mem.asBytes(&wake_token);
        const rc = linux.write(self.handle, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            // SUCCESS: counter incremented, registered read will complete.
            // AGAIN: counter saturated, readiness already pending — fine.
            // Anything else: best-effort, swallow rather than crash the caller.
            else => {},
        }
    }

    /// Clear wake readiness after a poll completion, before rescanning the
    /// mailbox. Linux drains its eventfd counter in one read; socket backends
    /// drain a bounded number of bytes and leave any remainder readable.
    pub fn drain(self: ReactorWake) void {
        if (comptime builtin.os.tag != .linux) {
            if (comptime builtin.os.tag == .windows) {
                var bytes: [512]u8 = undefined;
                for (0..64) |_| {
                    const rc = recv(self.windows_read_socket, &bytes, bytes.len, 0);
                    if (rc > 0) continue;
                    if (rc < 0 and WSAGetLastError() == windows_interrupted) continue;
                    break;
                }
                return;
            }
            var bytes: [512]u8 = undefined;
            // Bound work under continuous producers; remaining bytes preserve
            // level readiness when the owning reactor rearms its poll.
            for (0..64) |_| {
                const rc = std.c.recv(self.handle, &bytes, bytes.len, 0);
                if (rc > 0) continue;
                if (rc < 0 and std.c._errno().* == @as(c_int, @intFromEnum(std.posix.E.INTR))) continue;
                break;
            }
            return;
        }
        var scratch: u64 = 0;
        const bytes = std.mem.asBytes(&scratch);
        const rc = linux.read(self.handle, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            // SUCCESS: counter cleared to zero.
            // AGAIN: nothing buffered — benign, the read was a no-op.
            // Anything else: best-effort, swallow.
            else => {},
        }
    }
};

/// One `ReactorWake` per shard so any reactor can wake any other by index.
/// `num_shards` is comptime: the mesh's shard count is fixed at boot, so the
/// backing array is sized exactly with no allocation (unmanaged by construction).
pub fn WakeSet(comptime num_shards: usize) type {
    return struct {
        const Self = @This();

        /// Index `i` is shard `i`'s wakeup handle.
        wakes: [num_shards]ReactorWake,

        /// Create one wake endpoint per shard. On partial failure every handle created
        /// so far is closed before returning, so no fd leaks on the error path.
        pub fn init() error{ReactorWakeUnsupported}!Self {
            var wakes: [num_shards]ReactorWake = undefined;
            var made: usize = 0;
            errdefer for (wakes[0..made]) |*w| w.deinit();
            while (made < num_shards) : (made += 1) {
                wakes[made] = try ReactorWake.init();
            }
            return .{ .wakes = wakes };
        }

        /// Close every shard's eventfd.
        pub fn deinit(self: *Self) void {
            for (&self.wakes) |*w| w.deinit();
        }

        /// The descriptor shard `shard` registers for its native poll.
        pub fn fd(self: Self, shard: usize) linux.fd_t {
            return self.wakes[shard].fd();
        }

        /// Wake the reactor owning `shard`. Callable from any thread.
        pub fn wake(self: Self, shard: usize) void {
            self.wakes[shard].wake();
        }

        /// Drain shard `shard`'s readiness; called by that shard's reactor.
        pub fn drain(self: Self, shard: usize) void {
            self.wakes[shard].drain();
        }
    };
}

const testing = std.testing;

test "wake increments the eventfd counter and drain clears it" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var w = ReactorWake.init() catch return error.SkipZigTest;
    defer w.deinit();

    w.wake();

    // Read the fd directly: non-semaphore mode returns the full counter.
    var counter: u64 = 0;
    const bytes = std.mem.asBytes(&counter);
    const rc = linux.read(w.fd(), bytes.ptr, bytes.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(@as(u64, 1), counter);
}

test "multiple wakes coalesce into a single drainable counter" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var w = ReactorWake.init() catch return error.SkipZigTest;
    defer w.deinit();

    w.wake();
    w.wake();
    w.wake();

    var counter: u64 = 0;
    const bytes = std.mem.asBytes(&counter);
    const rc = linux.read(w.fd(), bytes.ptr, bytes.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    // Three single-token writes sum in the kernel counter; one read drains all.
    try testing.expectEqual(@as(u64, 3), counter);
}

test "drain on an empty wake endpoint is a tolerated no-op" {
    var w = ReactorWake.init() catch return error.SkipZigTest;
    defer w.deinit();

    // Counter is zero; drain must not crash and must leave the fd usable.
    w.drain();
    w.wake();
    w.drain();
}

test "Windows reactor wake reaches IOCP poll and drains without blocking" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var wake = try ReactorWake.init();
    defer wake.deinit();
    var backend = try io_backend.IoBackend.openOwned(.iocp, 32, .{});
    defer {
        // An error after arming POLL must retire its kernel request before the
        // wake socket can be closed by the earlier defer.
        backend.quiesce() catch @panic("Windows wake poll could not be drained");
        backend.deinit();
    }
    const token = @import("ringlane.zig").FdToken{ .slot = 7, .gen = 3 };
    try backend.poll(token, wake.fd(), linux.POLL.IN);
    _ = try backend.submit();
    const Worker = struct {
        fn run(target: *ReactorWake) void {
            for (0..3) |_| target.wake();
        }
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&wake});
    thread.join();
    var events: [2]io_backend.Reaped = undefined;
    const count = try backend.reap(&events, 2000);
    try testing.expect(count >= 1);
    try testing.expectEqual(io_backend.Op.poll, events[0].op);
    try testing.expectEqual(token, events[0].token);
    try testing.expect(events[0].result > 0);
    try testing.expect((events[0].result & @as(i32, linux.POLL.IN)) != 0);
    wake.drain();
    var byte: [1]u8 = undefined;
    try testing.expectEqual(@as(i32, -1), recv(wake.windows_read_socket, &byte, 1, 0));
    try testing.expectEqual(@as(i32, windows_would_block), WSAGetLastError());
}

test "wake from another thread is observed by the owning reactor" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var w = ReactorWake.init() catch return error.SkipZigTest;
    defer w.deinit();

    const Worker = struct {
        fn run(target: *ReactorWake) void {
            target.wake();
        }
    };

    const thread = std.Thread.spawn(.{}, Worker.run, .{&w}) catch return error.SkipZigTest;
    thread.join();

    // The fd is NONBLOCK; the cross-thread write must already be visible. Poll
    // the counter to assert the wake was observed without blocking the loop.
    var counter: u64 = 0;
    const bytes = std.mem.asBytes(&counter);
    var attempts: usize = 0;
    while (attempts < 1000) : (attempts += 1) {
        const rc = linux.read(w.fd(), bytes.ptr, bytes.len);
        if (linux.errno(rc) == .SUCCESS) break;
    }
    try testing.expectEqual(@as(u64, 1), counter);
}

test "WakeSet routes wake and drain per shard" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const num_shards = 4;
    var set = WakeSet(num_shards).init() catch return error.SkipZigTest;
    defer set.deinit();

    // Wake only shard 2; every fd must be distinct and only shard 2 ready.
    set.wake(2);

    var counter: u64 = 0;
    const bytes = std.mem.asBytes(&counter);

    // Shard 0 has nothing pending: a nonblocking read returns EAGAIN.
    const empty_rc = linux.read(set.fd(0), bytes.ptr, bytes.len);
    try testing.expectEqual(linux.E.AGAIN, linux.errno(empty_rc));

    // Shard 2 carries the wake token.
    const ready_rc = linux.read(set.fd(2), bytes.ptr, bytes.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(ready_rc));
    try testing.expectEqual(@as(u64, 1), counter);

    // drain() on shard 2 (already cleared above) stays benign.
    set.drain(2);
}

test "WakeSet exposes one distinct fd per shard" {
    const num_shards = 3;
    var set = WakeSet(num_shards).init() catch return error.SkipZigTest;
    defer set.deinit();

    var seen: [num_shards]linux.fd_t = undefined;
    for (0..num_shards) |i| seen[i] = set.fd(i);
    for (0..num_shards) |i| {
        for (i + 1..num_shards) |j| {
            try testing.expect(seen[i] != seen[j]);
        }
    }
}

test "BSD reactor wake: thread wake readiness coalesces without blocking or fd leaks" {
    if (comptime builtin.os.tag != .openbsd and builtin.os.tag != .freebsd and
        builtin.os.tag != .netbsd and builtin.os.tag != .dragonfly) return error.SkipZigTest;
    var wake = try ReactorWake.init();
    defer wake.deinit();
    for ([_]i32{ wake.handle, wake.write_handle }) |fd| {
        try testing.expect(std.c.fcntl(fd, @as(c_int, 1), @as(c_int, 0)) & 1 != 0);
        try testing.expect(std.c.fcntl(fd, @as(c_int, 3), @as(c_int, 0)) & 4 != 0);
    }
    const Worker = struct {
        fn run(target: *ReactorWake) void {
            for (0..32768) |_| target.wake();
        }
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&wake});
    thread.join();
    var byte: [1]u8 = undefined;
    try testing.expectEqual(@as(isize, 1), std.c.recv(wake.fd(), &byte, 1, 0));
    wake.drain();
    try testing.expectEqual(@as(isize, -1), std.c.recv(wake.fd(), &byte, 1, 0));
    try testing.expectEqual(@as(c_int, @intFromEnum(std.posix.E.AGAIN)), std.c._errno().*);
    wake.wake();
    try testing.expectEqual(@as(isize, 1), std.c.recv(wake.fd(), &byte, 1, 0));
}
