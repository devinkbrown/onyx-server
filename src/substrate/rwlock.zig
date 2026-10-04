// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Writer-preferring spin reader-writer lock.
//!
//! The daemon's world projection (channels, nicks, memberships) is read on every
//! lookup and written only on join/part/nick/mode changes, so a reader-writer
//! lock lets the future multi-reactor model run lookups concurrently while
//! serialising the rare mutation. Writer-preferring so a steady stream of
//! readers can't starve a pending mutation.
//!
//! Spin-based (cooperative `Thread.yield`) per the project's no-`std.Thread.Mutex`
//! discipline — built only on `std.atomic`. Non-recursive; a thread holding the
//! write lock must not re-enter. With one reactor (num_shards = 1) the lock is
//! always uncontended, so the single-thread fast path is a couple of atomics.

const std = @import("std");
const builtin = @import("builtin");

/// Bit 31 of `state` marks the write lock held; bits 0..30 count active readers.
const writer_bit: u32 = 1 << 31;

pub const RwLock = struct {
    /// writer_bit | reader_count.
    state: std.atomic.Value(u32) = .init(0),
    /// Pending writers; readers defer while this is non-zero (writer preference).
    writers_waiting: std.atomic.Value(u32) = .init(0),
    exclusive_owner: std.atomic.Value(std.Thread.Id) = .init(0),
    exclusive_owner_valid: std.atomic.Value(bool) = .init(false),
    exclusive_generation: std.atomic.Value(u64) = .init(0),
    exclusive_generation_exhausted: std.atomic.Value(bool) = .init(false),

    pub fn init() RwLock {
        return .{};
    }

    /// Acquire shared (read) access. Multiple readers may hold it at once.
    pub fn lockShared(self: *RwLock) void {
        while (true) {
            // Defer to any waiting writer so writers cannot be starved.
            if (self.writers_waiting.load(.acquire) != 0) {
                std.Thread.yield() catch {};
                continue;
            }
            const s = self.state.load(.monotonic);
            if (s & writer_bit != 0) {
                std.Thread.yield() catch {};
                continue;
            }
            if (self.state.cmpxchgWeak(s, s + 1, .acquire, .monotonic) == null) return;
        }
    }

    pub fn unlockShared(self: *RwLock) void {
        _ = self.state.fetchSub(1, .release);
    }

    /// Acquire exclusive (write) access. Blocks until no readers or writer hold it.
    pub fn lockExclusive(self: *RwLock) void {
        _ = self.writers_waiting.fetchAdd(1, .acquire);
        while (self.state.cmpxchgWeak(0, writer_bit, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
        _ = self.writers_waiting.fetchSub(1, .release);
        self.recordExclusiveOwner();
    }

    pub fn unlockExclusive(self: *RwLock) void {
        self.exclusive_owner_valid.store(false, .release);
        self.state.store(0, .release);
    }

    /// Non-blocking write acquire; true if taken (only when fully unlocked).
    pub fn tryLockExclusive(self: *RwLock) bool {
        if (self.state.cmpxchgStrong(0, writer_bit, .acquire, .monotonic) != null) return false;
        self.recordExclusiveOwner();
        return true;
    }

    /// Validates this actual lock's current exclusive caller. This does not
    /// acquire the lock or extend a scope beyond unlock; callers must bind the
    /// original lock privately before using it as a World-lane prerequisite.
    pub fn requireExclusiveHeldByCurrentThread(self: *const RwLock) error{ExclusiveLockNotHeldByCaller}!void {
        if (!self.exclusive_owner_valid.load(.acquire) or
            self.exclusive_owner.load(.monotonic) != currentCaller() or
            self.state.load(.acquire) != writer_bit)
            return error.ExclusiveLockNotHeldByCaller;
    }

    /// Diagnostic for this actual acquisition. A private source-issued scope
    /// must retain it together with its original lock and creator; the number
    /// alone supplies no authority or caller lifetime proof.
    pub fn captureExclusiveAcquisitionForCurrentThread(self: *const RwLock) error{ ExclusiveLockNotHeldByCaller, ExclusiveAcquisitionExhausted }!u64 {
        try self.requireExclusiveHeldByCurrentThread();
        if (self.exclusive_generation_exhausted.load(.acquire)) return error.ExclusiveAcquisitionExhausted;
        return self.exclusive_generation.load(.monotonic);
    }

    pub fn requireExclusiveAcquisitionByCurrentThread(self: *const RwLock, original: u64) error{ ExclusiveLockNotHeldByCaller, ExclusiveAcquisitionExhausted, ExclusiveAcquisitionChanged }!void {
        const current = try self.captureExclusiveAcquisitionForCurrentThread();
        if (original == 0 or original != current) return error.ExclusiveAcquisitionChanged;
    }

    /// Cold cleanup diagnostic only. The source must first validate its
    /// privately issued, previously valid scope and original creator/owner.
    /// Exhaustion proves an acquisition occurred after every valid capture,
    /// even when the counter cannot advance beyond its final value. This does
    /// not permit admission, ordinary abort, or resetting the counter.
    pub fn requireExclusiveAcquisitionInterruptedByCurrentThread(self: *const RwLock, original: u64) error{ ExclusiveLockNotHeldByCaller, InvalidExclusiveAcquisition, ExclusiveAcquisitionNotInterrupted }!void {
        try self.requireExclusiveHeldByCurrentThread();
        const current = self.exclusive_generation.load(.monotonic);
        if (original == 0 or original > current) return error.InvalidExclusiveAcquisition;
        if (original == current and !self.exclusive_generation_exhausted.load(.acquire))
            return error.ExclusiveAcquisitionNotInterrupted;
    }

    fn currentCaller() std.Thread.Id {
        if (builtin.single_threaded) return 0;
        return std.Thread.getCurrentId();
    }

    fn recordExclusiveOwner(self: *RwLock) void {
        const previous = self.exclusive_generation.load(.monotonic);
        if (previous == std.math.maxInt(u64)) {
            // Ordinary mutual exclusion still works, but source scopes cannot
            // certify another acquisition by wrapping or repeating a number.
            self.exclusive_generation_exhausted.store(true, .monotonic);
        } else {
            self.exclusive_generation.store(previous + 1, .monotonic);
        }
        self.exclusive_owner.store(currentCaller(), .monotonic);
        self.exclusive_owner_valid.store(true, .release);
    }
};

test "exclusive caller requires the actual original write lock and clears on unlock" {
    var lock = RwLock.init();
    var foreign = RwLock.init();
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, lock.requireExclusiveHeldByCurrentThread());
    lock.lockShared();
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, lock.requireExclusiveHeldByCurrentThread());
    lock.unlockShared();
    lock.lockExclusive();
    try lock.requireExclusiveHeldByCurrentThread();
    const first = try lock.captureExclusiveAcquisitionForCurrentThread();
    try lock.requireExclusiveAcquisitionByCurrentThread(first);
    try std.testing.expectError(error.ExclusiveAcquisitionNotInterrupted, lock.requireExclusiveAcquisitionInterruptedByCurrentThread(first));
    try std.testing.expectError(error.InvalidExclusiveAcquisition, lock.requireExclusiveAcquisitionInterruptedByCurrentThread(0));
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, foreign.requireExclusiveHeldByCurrentThread());
    try std.testing.expect(!lock.tryLockExclusive());
    try lock.requireExclusiveHeldByCurrentThread();
    try lock.requireExclusiveAcquisitionByCurrentThread(first);
    lock.unlockExclusive();
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, lock.requireExclusiveHeldByCurrentThread());
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, lock.requireExclusiveAcquisitionInterruptedByCurrentThread(first));
    try std.testing.expect(lock.tryLockExclusive());
    try lock.requireExclusiveHeldByCurrentThread();
    try std.testing.expectError(error.ExclusiveAcquisitionChanged, lock.requireExclusiveAcquisitionByCurrentThread(first));
    const second = try lock.captureExclusiveAcquisitionForCurrentThread();
    try std.testing.expect(second > first);
    try lock.requireExclusiveAcquisitionByCurrentThread(second);
    try lock.requireExclusiveAcquisitionInterruptedByCurrentThread(first);
    try std.testing.expectError(error.InvalidExclusiveAcquisition, lock.requireExclusiveAcquisitionInterruptedByCurrentThread(second + 1));
    lock.unlockExclusive();
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, lock.requireExclusiveHeldByCurrentThread());
}

test "exclusive acquisition exhausts without wrapping while real mutual exclusion remains usable" {
    var lock = RwLock.init();
    // Seed the unreachable-in-a-test boundary while unlocked, then execute the
    // real acquire, unlock, and try-acquire paths that must enforce it.
    lock.exclusive_generation.store(std.math.maxInt(u64) - 1, .monotonic);
    lock.lockExclusive();
    const last = try lock.captureExclusiveAcquisitionForCurrentThread();
    try std.testing.expectEqual(std.math.maxInt(u64), last);
    try lock.requireExclusiveAcquisitionByCurrentThread(last);
    try std.testing.expectError(error.ExclusiveAcquisitionNotInterrupted, lock.requireExclusiveAcquisitionInterruptedByCurrentThread(last));
    lock.unlockExclusive();
    try std.testing.expect(lock.tryLockExclusive());
    try lock.requireExclusiveHeldByCurrentThread();
    try std.testing.expectError(error.ExclusiveAcquisitionExhausted, lock.captureExclusiveAcquisitionForCurrentThread());
    try std.testing.expectError(error.ExclusiveAcquisitionExhausted, lock.requireExclusiveAcquisitionByCurrentThread(last));
    try lock.requireExclusiveAcquisitionInterruptedByCurrentThread(last);
    try std.testing.expectEqual(std.math.maxInt(u64), lock.exclusive_generation.load(.monotonic));
    lock.unlockExclusive();
    lock.lockExclusive();
    try lock.requireExclusiveHeldByCurrentThread();
    try std.testing.expectError(error.ExclusiveAcquisitionExhausted, lock.captureExclusiveAcquisitionForCurrentThread());
    try lock.requireExclusiveAcquisitionInterruptedByCurrentThread(last);
    lock.unlockExclusive();
}

const CallerProbe = struct {
    lock: *RwLock,
    acquire: bool,
    accepted: bool = false,
    done: std.Io.Event = .unset,

    fn run(self: *CallerProbe) void {
        if (self.acquire) {
            if (!self.lock.tryLockExclusive()) {
                self.done.set(std.testing.io);
                return;
            }
        }
        self.lock.requireExclusiveHeldByCurrentThread() catch {
            if (self.acquire) self.lock.unlockExclusive();
            self.done.set(std.testing.io);
            return;
        };
        self.accepted = true;
        if (self.acquire) self.lock.unlockExclusive();
        self.done.set(std.testing.io);
    }

    fn awaitAndJoin(self: *CallerProbe, thread: std.Thread) void {
        const deadline = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(5000) });
        self.done.waitTimeout(std.testing.io, .{ .deadline = deadline }) catch
            @panic("exclusive caller probe did not return within its original deadline");
        thread.join();
    }
};

test "exclusive caller refuses a foreign actual thread then admits its real acquisition" {
    if (builtin.single_threaded) return error.SkipZigTest;
    var lock = RwLock.init();
    lock.lockExclusive();
    var held = true;
    defer if (held) lock.unlockExclusive();
    var foreign = CallerProbe{ .lock = &lock, .acquire = false };
    const other = try std.Thread.spawn(.{}, CallerProbe.run, .{&foreign});
    foreign.awaitAndJoin(other);
    try std.testing.expect(!foreign.accepted);
    try lock.requireExclusiveHeldByCurrentThread();
    lock.unlockExclusive();
    held = false;
    var successor = CallerProbe{ .lock = &lock, .acquire = true };
    const next = try std.Thread.spawn(.{}, CallerProbe.run, .{&successor});
    successor.awaitAndJoin(next);
    try std.testing.expect(successor.accepted);
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, lock.requireExclusiveHeldByCurrentThread());
}

test "single-thread: shared and exclusive acquire/release" {
    var lock = RwLock.init();
    lock.lockShared();
    lock.lockShared();
    lock.unlockShared();
    lock.unlockShared();
    lock.lockExclusive();
    // While write-held, a try-acquire must fail.
    try std.testing.expect(!lock.tryLockExclusive());
    lock.unlockExclusive();
    try std.testing.expect(lock.tryLockExclusive());
    lock.unlockExclusive();
}

const Hammer = struct {
    lock: *RwLock,
    counter: *u64,
    iters: u64,

    fn writer(ctx: *Hammer) void {
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.lock.lockExclusive();
            ctx.counter.* += 1; // protected critical section
            ctx.lock.unlockExclusive();
        }
    }

    fn reader(ctx: *Hammer) void {
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.lock.lockShared();
            // Read under the shared lock; value is monotonic so a torn read can't
            // exceed the final total.
            std.mem.doNotOptimizeAway(ctx.counter.*);
            ctx.lock.unlockShared();
        }
    }
};

test "concurrent writers see no lost updates under contention" {
    var lock = RwLock.init();
    var counter: u64 = 0;
    const writers = 4;
    const readers = 4;
    const iters: u64 = 5000;

    var ctx = Hammer{ .lock = &lock, .counter = &counter, .iters = iters };
    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();

    for (0..writers) |_| {
        threads[spawned] = std.Thread.spawn(.{}, Hammer.writer, .{&ctx}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |_| {
        threads[spawned] = std.Thread.spawn(.{}, Hammer.reader, .{&ctx}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    // No lost updates: every write-locked increment landed.
    try std.testing.expectEqual(writers * iters, counter);
    try std.testing.expectEqual(writers * iters, lock.exclusive_generation.load(.monotonic));
}
