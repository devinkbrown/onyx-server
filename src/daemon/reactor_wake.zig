// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-reactor wakeup primitive for the sharded multi-reactor model.
//!
//! In the sharded design each reactor owns its own io_uring and spends most of
//! its life blocked in `io_uring_enter` waiting for completions. When reactor A
//! enqueues a cross-shard delivery into reactor B's mailbox (see
//! `shard.zig` `Mailboxes`), B may be asleep and would never notice the queued
//! work until some unrelated completion happened to fire. `ReactorWake` closes
//! that gap with a kernel `eventfd`:
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

/// Single-owner cross-reactor wakeup handle wrapping one `eventfd`.
pub const ReactorWake = struct {
    /// The eventfd. Owned by this `ReactorWake`; closed in `deinit`.
    handle: linux.fd_t,
    write_handle: linux.fd_t = -1,

    /// The 8-byte payload `wake()` writes. Any non-zero value works; `1` keeps
    /// the counter from overflowing in practice (`UINT64_MAX - 1` writes would
    /// be required to saturate, far beyond any realistic backlog).
    const wake_token: u64 = 1;

    /// Create a nonblocking, non-semaphore eventfd with the counter at zero.
    pub fn init() error{ReactorWakeUnsupported}!ReactorWake {
        if (comptime builtin.os.tag != .linux) {
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

    /// Close the underlying eventfd. Idempotent only if not called twice.
    pub fn deinit(self: *ReactorWake) void {
        if (comptime builtin.os.tag != .linux) {
            // Windows has no socketpair/eventfd mapping yet; init() already
            // reports ReactorWakeUnsupported there, so this is unreachable.
            if (comptime builtin.os.tag == .windows) return;
            _ = std.c.close(self.handle);
            _ = std.c.close(self.write_handle);
            self.handle = -1;
            self.write_handle = -1;
            return;
        }
        _ = linux.close(self.handle);
        self.handle = -1;
    }

    /// The eventfd to register for a read in the owning reactor's io_uring.
    pub fn fd(self: ReactorWake) linux.fd_t {
        return self.handle;
    }

    /// Wake the owning reactor by writing the eventfd counter. Safe to call from
    /// ANY thread and idempotent-ish: repeated calls before a `drain()` simply
    /// accumulate into the same non-zero counter. `EAGAIN` (the counter is at
    /// its max and would block) is ignored — readiness is already pending, so a
    /// dropped increment changes nothing. All other errnos are ignored too: a
    /// failed wake must never propagate up the foreign reactor's hot path.
    pub fn wake(self: ReactorWake) void {
        if (comptime builtin.os.tag != .linux) {
            // Windows has no socketpair/eventfd mapping yet; init() already
            // reports ReactorWakeUnsupported there, so this is unreachable.
            if (comptime builtin.os.tag == .windows) return;
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

    /// Clear the eventfd readiness. Called by the owning reactor after its
    /// registered read completion fires, before it rescans its mailbox. A single
    /// read drains the whole accumulated counter to zero (non-semaphore mode).
    /// `EAGAIN` is tolerated — a spurious drain (counter already zero) is benign.
    pub fn drain(self: ReactorWake) void {
        if (comptime builtin.os.tag != .linux) {
            // Windows has no socketpair/eventfd mapping yet; init() already
            // reports ReactorWakeUnsupported there, so this is unreachable.
            if (comptime builtin.os.tag == .windows) return;
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

        /// Create one eventfd per shard. On partial failure every handle created
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

        /// The eventfd shard `shard` registers for a read in its own io_uring.
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

test "drain on an empty eventfd is a tolerated no-op" {
    // eventfd/socketpair wake has no Winsock mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var w = ReactorWake.init() catch return error.SkipZigTest;
    defer w.deinit();

    // Counter is zero; drain must not crash and must leave the fd usable.
    w.drain();
    w.wake();
    w.drain();
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
