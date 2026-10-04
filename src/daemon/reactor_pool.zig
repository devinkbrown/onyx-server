// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Worker-thread harness for the sharded-reactor model.
//!
//! The target architecture (see docs/planning/24-multithreading.md) runs N OS
//! threads, each owning its own io_uring reactor and a disjoint slice of the
//! connection table. `ReactorPool` is the thread-lifecycle primitive of that
//! design: it spawns one thread per shard, binds each to its shard index, runs
//! a caller-provided loop, and joins them all on stop.
//!
//! It is deliberately *generic* — it knows nothing about the IRC server, the
//! reactor, or io_uring. `server.zig` later hands it a closure that binds its
//! per-shard reactor and runs the io_uring loop; here we only own spawn/join.
//! The degenerate `count == 1` case is a single worker (the single-reactor
//! model), so the same code path covers both topologies.
//!
//! Stopping is cooperative: a shared `*RunFlag` (an atomic bool) is the only
//! control channel. The caller clears it; each worker observes the clear at the
//! top of its loop and returns; `join` then reaps every thread. No thread is
//! ever detached, so there are no leaks.

const std = @import("std");
const shard = @import("shard.zig");
pub const runtime_start_gate = @import("runtime_start_gate.zig");

/// Cooperative stop signal shared by the pool owner and every worker. The owner
/// stores `false` to request shutdown; workers poll it and return when cleared.
pub const RunFlag = std.atomic.Value(bool);
/// Source-owned policy shared by the runtime inventory and actual pool spawn.
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};

/// A pool of worker threads, one per shard, each running the same caller-bound
/// loop function with a distinct shard index. `Context` is the (thread-shared)
/// value handed to every worker; it must be safe to read from all workers.
pub fn ReactorPool(comptime Context: type) type {
    return struct {
        const Self = @This();

        /// The (thread-shared) value type handed to every worker. Exposed so the
        /// type is anchored at struct scope and callers can name it.
        pub const ContextType = Context;

        allocator: std.mem.Allocator,
        /// Backing storage for the worker handles; freed by `deinit`. Stays
        /// allocated across `join` so `deinit` can reclaim it exactly once.
        threads: []std.Thread = &.{},
        /// Whether the workers have already been reaped (so `join`/`deinit`
        /// never double-join). Managed count becomes zero after owner joins/detach.
        joined: bool = true,
        /// Shared startup owns handles in Control, never in `threads`. This
        /// pool retains only observations; actual View outlives detach.
        shared: ?struct {
            view: *const runtime_start_gate.View,
            owner: *const anyopaque,
            count: usize,
        } = null,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        /// Legacy handles are joined here. Managed storage must first be
        /// detached after the actual runtime owner joins all its workers.
        pub fn deinit(self: *Self) void {
            if (self.shared != null) @panic("managed pool requires owner join and detach before deinit");
            self.join();
            self.allocator.free(self.threads);
            self.threads = &.{};
            self.shared = null;
        }

        /// Spawn `count` worker threads. Each thread calls
        /// `workerFn(ctx, shard_index, run)` with its own shard index in
        /// `0..count`. `count` must be in `1..=shard.max_shards`. On a spawn
        /// failure, every already-spawned thread is joined and the error is
        /// returned, leaving the pool empty.
        pub fn start(
            self: *Self,
            shard_count: usize,
            ctx: Context,
            run: *RunFlag,
            comptime workerFn: fn (Context, u12, *RunFlag) void,
        ) !void {
            std.debug.assert(shard_count >= 1 and shard_count <= shard.max_shards);
            if (self.shared != null or self.threads.len != 0) return error.AlreadyStarted;

            const threads = try self.allocator.alloc(std.Thread, shard_count);
            errdefer self.allocator.free(threads);

            const Runner = struct {
                /// Thread entry: bind the worker to its shard index and run.
                fn entry(c: Context, idx: u12, r: *RunFlag) void {
                    workerFn(c, idx, r);
                }
            };

            var spawned: usize = 0;
            errdefer {
                // A later spawn failed: stop and reap the threads already up so
                // we never leak a running thread.
                run.store(false, .release);
                for (threads[0..spawned]) |t| t.join();
            }
            while (spawned < shard_count) : (spawned += 1) {
                const idx: u12 = @intCast(spawned);
                threads[spawned] = try std.Thread.spawn(.{}, Runner.entry, .{ ctx, idx, run });
            }

            self.threads = threads;
            self.joined = false;
        }

        /// Prepare this pool under the one runtime-wide barrier. Every slot is
        /// checked before the first spawn. No callback, RunFlag mutation or
        /// local release occurs here; main awaits/releases the complete Gate.
        /// Actual spawn failure cancels and joins ALL candidate owners, not
        /// only this pool, before any borrowed context can be destroyed.
        pub fn prepareDormant(
            self: *Self,
            control: *runtime_start_gate.Control,
            view: *const runtime_start_gate.View,
            slots: []const runtime_start_gate.Slot,
            ctx: Context,
            run: *RunFlag,
            comptime workerFn: fn (Context, u12, *RunFlag) void,
        ) !void {
            if (@typeInfo(Context) != .pointer) @compileError("dormant pool borrows a stable actual owner pointer");
            try control.requireView(view);
            if (self.shared != null or self.threads.len != 0) return error.AlreadyStarted;
            if (slots.len == 0 or slots.len > shard.max_shards) return error.InvalidShardCount;
            if (view.inspect().phase != .preparing) return error.NotPreparing;
            const owner: *const anyopaque = @ptrCast(ctx);
            for (slots, 0..) |slot, i| {
                try view.requireSlot(slot, .reactor, @intCast(i), owner, dormant_spawn_options);
                const status = try view.inspectSlot(slot);
                if (status.spawned) return error.AlreadySpawned;
            }
            const Runner = struct {
                const Borrow = struct { ctx: Context, index: u12, run: *RunFlag };
                fn entry(borrow: Borrow) void {
                    workerFn(borrow.ctx, borrow.index, borrow.run);
                }
            };
            self.shared = .{ .view = view, .owner = owner, .count = slots.len };
            self.joined = false;
            errdefer {
                control.cancelAllAndJoin();
                self.detachAfterJoined() catch unreachable;
            }
            for (slots, 0..) |slot, i| {
                try control.spawn(slot, Runner.Borrow, .{ .ctx = ctx, .index = @intCast(i), .run = run }, Runner.entry, dormant_spawn_options);
            }
        }

        /// Proves only these reactor slots parked. Runtime readiness additionally
        /// requires View.requireAllParked and every configured resource owner.
        pub fn requireParked(self: *const Self) !void {
            const shared = self.shared orelse return error.NotDormant;
            for (0..shared.count) |i| {
                try shared.view.requireSlotParked(try shared.view.slot(.reactor, @intCast(i), shared.owner));
            }
        }

        /// Join every worker thread. Returns once all have exited; the caller is
        /// responsible for having cleared the `RunFlag` so workers can finish.
        /// Idempotent: a second call (or a call on an empty pool) is a no-op.
        /// Only the legacy lane joins here; managed callers use owner Control
        /// then detachAfterJoined. Backing storage remains until deinit.
        pub fn join(self: *Self) void {
            if (self.shared != null) @panic("managed pool handles belong exclusively to runtime Control");
            if (self.joined) return;
            for (self.threads) |t| t.join();
            self.joined = true;
        }

        /// Observe actual owner joins without borrowing handle or cancellation
        /// authority. A canceled unspawned row has no handle to retire.
        pub fn detachAfterJoined(self: *Self) !void {
            const shared = self.shared orelse return;
            for (0..shared.count) |i| {
                const slot = try shared.view.slot(.reactor, @intCast(i), shared.owner);
                try shared.view.requireSlotJoined(slot);
            }
            self.shared = null;
            self.joined = true;
        }

        /// Owned legacy count, or borrowed managed rows until successful detach.
        pub fn count(self: *const Self) usize {
            return if (self.joined) 0 else if (self.shared) |shared| shared.count else self.threads.len;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Shared fixture: per-shard work counters plus a per-shard "seen" marker so a
/// test can prove every shard index was bound exactly once.
const Harness = struct {
    /// Incremented by the worker on each loop iteration until `run` clears.
    counters: [shard.max_shards]std.atomic.Value(u64) =
        @splat(std.atomic.Value(u64).init(0)),
    /// Set once when shard `i` first runs; a second set is a duplicate index.
    seen: [shard.max_shards]std.atomic.Value(u32) =
        @splat(std.atomic.Value(u32).init(0)),
    /// Counts any duplicate shard index observed across all workers.
    duplicate_index: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn worker(self: *Harness, idx: u12, run: *RunFlag) void {
        // Claim this shard index; a non-zero prior value means a collision.
        if (self.seen[idx].swap(1, .acq_rel) != 0) {
            _ = self.duplicate_index.fetchAdd(1, .acq_rel);
        }
        while (run.load(.acquire)) {
            _ = self.counters[idx].fetchAdd(1, .acq_rel);
            std.Thread.yield() catch {};
        }
    }

    /// Spin until shard `idx` has made progress, so the test only clears `run`
    /// after the worker has actually started looping.
    fn waitProgress(self: *Harness, idx: u12) void {
        while (self.counters[idx].load(.acquire) == 0) std.Thread.yield() catch {};
    }
};

test "start(1) runs a single worker that stops when the flag clears" {
    const allocator = testing.allocator;
    var harness = Harness{};
    var run = RunFlag.init(true);

    var pool = ReactorPool(*Harness).init(allocator);
    defer pool.deinit();

    pool.start(1, &harness, &run, Harness.worker) catch return error.SkipZigTest;
    try testing.expectEqual(@as(usize, 1), pool.count());

    harness.waitProgress(0);
    run.store(false, .release);
    pool.join();

    try testing.expectEqual(@as(usize, 0), pool.count());
    try testing.expect(harness.counters[0].load(.acquire) > 0);
    try testing.expectEqual(@as(u32, 1), harness.seen[0].load(.acquire));
    try testing.expectEqual(@as(u32, 0), harness.duplicate_index.load(.acquire));
}

test "start(4) binds shard indices 0..3 exactly once and joins cleanly" {
    const allocator = testing.allocator;
    const workers = 4;
    var harness = Harness{};
    var run = RunFlag.init(true);

    var pool = ReactorPool(*Harness).init(allocator);
    defer pool.deinit();

    pool.start(workers, &harness, &run, Harness.worker) catch return error.SkipZigTest;
    try testing.expectEqual(@as(usize, workers), pool.count());

    // Let every worker reach its loop, then signal a cooperative stop.
    var i: u12 = 0;
    while (i < workers) : (i += 1) harness.waitProgress(i);
    run.store(false, .release);
    pool.join();

    try testing.expectEqual(@as(usize, 0), pool.count());
    // Each shard index 0..3 was observed exactly once; none beyond was touched.
    try testing.expectEqual(@as(u32, 0), harness.duplicate_index.load(.acquire));
    i = 0;
    while (i < workers) : (i += 1) {
        try testing.expectEqual(@as(u32, 1), harness.seen[i].load(.acquire));
        try testing.expect(harness.counters[i].load(.acquire) > 0);
    }
    try testing.expectEqual(@as(u32, 0), harness.seen[workers].load(.acquire));
}

test "deinit joins workers even without an explicit join" {
    const allocator = testing.allocator;
    var harness = Harness{};
    var run = RunFlag.init(true);

    var pool = ReactorPool(*Harness).init(allocator);
    pool.start(2, &harness, &run, Harness.worker) catch return error.SkipZigTest;
    harness.waitProgress(0);
    // Clear the flag and let deinit reap the threads (no explicit join call).
    run.store(false, .release);
    pool.deinit();
    try testing.expectEqual(@as(usize, 0), pool.count());
}

fn finishGate(gate: runtime_start_gate.Created) void {
    if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
    gate.control.destroyJoined();
}

fn startupDeadline() std.Io.Clock.Timestamp {
    return .fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
const DormantHarness = struct {
    seen: [4]std.atomic.Value(u32) = @splat(.init(0)),
    companion: std.atomic.Value(u32) = .init(0),
    published: u32 = 0,
    bad_publication: std.atomic.Value(bool) = .init(false),
    fn worker(self: *@This(), index: u12, run: *RunFlag) void {
        if (self.published != 19 or !run.load(.acquire)) self.bad_publication.store(true, .release);
        _ = self.seen[index].fetchAdd(1, .acq_rel);
    }
    fn other(self: *@This()) void {
        if (self.published != 19) self.bad_publication.store(true, .release);
        _ = self.companion.fetchAdd(1, .acq_rel);
    }
};

test "dormant pool and companion share one release and one handle owner" {
    const gate_mod = runtime_start_gate;
    var h: DormantHarness = .{};
    var run = RunFlag.init(true);
    const specs = [_]gate_mod.ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &h },
        .{ .kind = .reactor, .instance = 1, .owner_identity = &h },
        .{ .kind = .mail, .instance = 0, .owner_identity = &h },
    };
    const gate = try gate_mod.create(testing.allocator, testing.io, &specs);
    defer finishGate(gate);
    var pool = ReactorPool(*DormantHarness).init(testing.allocator);
    defer {
        if (pool.shared != null) {
            if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
            pool.detachAfterJoined() catch unreachable;
        }
        pool.deinit();
    }
    const slots = [_]gate_mod.Slot{ try gate.view.slot(.reactor, 0, &h), try gate.view.slot(.reactor, 1, &h) };
    try pool.prepareDormant(gate.control, gate.view, &slots, &h, &run, DormantHarness.worker);
    try testing.expectEqual(@as(usize, 0), pool.threads.len);
    try testing.expectError(error.Incomplete, gate.view.requireAllParked());
    const mail = try gate.view.slot(.mail, 0, &h);
    try gate.control.spawn(mail, *DormantHarness, &h, DormantHarness.other, .{});
    try gate.control.awaitAllParked(startupDeadline());
    try pool.requireParked();
    for (&h.seen) |*seen| try testing.expectEqual(@as(u32, 0), seen.load(.acquire));
    try testing.expectEqual(@as(u32, 0), h.companion.load(.acquire));
    try testing.expectError(error.AlreadyStarted, pool.start(1, &h, &run, DormantHarness.worker));
    h.published = 19;
    gate.control.releaseAll();
    gate.control.joinAll();
    try pool.detachAfterJoined();
    try pool.detachAfterJoined();
    try testing.expectEqual(@as(usize, 3), gate.view.inspect().joined);
    try testing.expectEqual(@as(usize, 0), pool.count());
    try testing.expectEqual(@as(u32, 1), h.seen[0].load(.acquire));
    try testing.expectEqual(@as(u32, 1), h.seen[1].load(.acquire));
    try testing.expectEqual(@as(u32, 0), h.seen[2].load(.acquire));
    try testing.expectEqual(@as(u32, 1), h.companion.load(.acquire));
    try testing.expect(!h.bad_publication.load(.acquire));
}

test "dormant pool kth spawn failure cancels prior companion without changing OLD run flag" {
    const gate_mod = runtime_start_gate;
    var h: DormantHarness = .{};
    var run = RunFlag.init(true);
    const specs = [_]gate_mod.ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &h },
        .{ .kind = .reactor, .instance = 1, .owner_identity = &h },
        .{ .kind = .mail, .instance = 0, .owner_identity = &h },
    };
    const gate = try gate_mod.create(testing.allocator, testing.io, &specs);
    defer finishGate(gate);
    gate_mod.Fixture.failSpawn(gate.control, 2);
    try gate.control.spawn(try gate.view.slot(.mail, 0, &h), *DormantHarness, &h, DormantHarness.other, .{});
    var pool = ReactorPool(*DormantHarness).init(testing.allocator);
    defer {
        if (pool.shared != null) {
            if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
            pool.detachAfterJoined() catch unreachable;
        }
        pool.deinit();
    }
    const slots = [_]gate_mod.Slot{ try gate.view.slot(.reactor, 0, &h), try gate.view.slot(.reactor, 1, &h) };
    try testing.expectError(error.SystemResources, pool.prepareDormant(gate.control, gate.view, &slots, &h, &run, DormantHarness.worker));
    try testing.expectEqual(gate_mod.Phase.canceled, gate.view.inspect().phase);
    try testing.expectEqual(@as(usize, 2), gate.view.inspect().joined);
    try testing.expectEqual(@as(usize, 0), pool.count());
    try testing.expect(run.load(.acquire));
    try testing.expectEqual(@as(u32, 0), h.companion.load(.acquire));
    for (&h.seen) |*seen| try testing.expectEqual(@as(u32, 0), seen.load(.acquire));
}

test "dormant pool validates whole slot set then owner cancels before managed detach" {
    const gate_mod = runtime_start_gate;
    var h: DormantHarness = .{};
    var run = RunFlag.init(true);
    const specs = [_]gate_mod.ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &h },
        .{ .kind = .reactor, .instance = 1, .owner_identity = &h },
    };
    const gate = try gate_mod.create(testing.allocator, testing.io, &specs);
    defer finishGate(gate);
    var pool = ReactorPool(*DormantHarness).init(testing.allocator);
    defer {
        if (pool.shared != null) {
            if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
            pool.detachAfterJoined() catch unreachable;
        }
        pool.deinit();
    }
    const a = try gate.view.slot(.reactor, 0, &h);
    const b = try gate.view.slot(.reactor, 1, &h);
    try testing.expectError(error.InvalidSlot, pool.prepareDormant(gate.control, gate.view, &.{ a, a }, &h, &run, DormantHarness.worker));
    try testing.expectEqual(@as(usize, 0), gate.view.inspect().spawned);
    try testing.expectEqual(@as(usize, 0), pool.count());
    try testing.expectError(error.InvalidShardCount, pool.prepareDormant(gate.control, gate.view, &.{}, &h, &run, DormantHarness.worker));
    try pool.prepareDormant(gate.control, gate.view, &.{ a, b }, &h, &run, DormantHarness.worker);
    try gate.control.awaitAllParked(startupDeadline());
    try testing.expectError(error.NotJoined, pool.detachAfterJoined());
    gate.control.cancelAllAndJoin();
    try pool.detachAfterJoined();
    pool.deinit();
    try testing.expectEqual(gate_mod.Phase.canceled, gate.view.inspect().phase);
    try testing.expectEqual(@as(usize, 2), gate.view.inspect().joined);
    try testing.expect(run.load(.acquire));
    for (&h.seen) |*seen| try testing.expectEqual(@as(u32, 0), seen.load(.acquire));
}

test "managed pool rejects foreign control before storing view or spawning any row" {
    const gate_mod = runtime_start_gate;
    var h: DormantHarness = .{};
    var run = RunFlag.init(true);
    const specs = [_]gate_mod.ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &h },
        .{ .kind = .reactor, .instance = 1, .owner_identity = &h },
    };
    const gate = try gate_mod.create(testing.allocator, testing.io, &specs);
    defer finishGate(gate);
    const other = try gate_mod.create(testing.allocator, testing.io, &specs);
    defer finishGate(other);
    var pool = ReactorPool(*DormantHarness).init(testing.allocator);
    defer pool.deinit();
    const slots = [_]gate_mod.Slot{ try gate.view.slot(.reactor, 0, &h), try gate.view.slot(.reactor, 1, &h) };
    try testing.expectError(error.InvalidGate, pool.prepareDormant(other.control, gate.view, &slots, &h, &run, DormantHarness.worker));
    try testing.expect(pool.shared == null);
    try testing.expect(pool.joined);
    try testing.expectEqual(@as(usize, 0), pool.threads.len);
    try testing.expectEqual(@as(usize, 0), gate.view.inspect().spawned);
    try testing.expectEqual(@as(usize, 0), other.view.inspect().spawned);
    try testing.expectEqual(gate_mod.Phase.preparing, gate.view.inspect().phase);
    try testing.expectEqual(gate_mod.Phase.preparing, other.view.inspect().phase);
    try testing.expect(run.load(.acquire));
    for (&h.seen) |*seen| try testing.expectEqual(@as(u32, 0), seen.load(.acquire));
}

test "managed pool refuses later slot policy mismatch before any spawn or pool mutation" {
    const gate_mod = runtime_start_gate;
    const wrong_options = [_]std.Thread.SpawnConfig{
        .{ .stack_size = 2 * 1024 * 1024 },
        .{ .allocator = testing.allocator },
    };
    for (wrong_options) |wrong| {
        var h: DormantHarness = .{};
        var run = RunFlag.init(true);
        const specs = [_]gate_mod.ParticipantSpec{
            .{ .kind = .reactor, .instance = 0, .owner_identity = &h, .options = dormant_spawn_options },
            .{ .kind = .reactor, .instance = 1, .owner_identity = &h, .options = wrong },
        };
        const gate = try gate_mod.create(testing.allocator, testing.io, &specs);
        defer finishGate(gate);
        var pool = ReactorPool(*DormantHarness).init(testing.allocator);
        defer {
            if (pool.shared != null) {
                gate.control.cancelAllAndJoin();
                pool.detachAfterJoined() catch unreachable;
            }
            pool.deinit();
        }
        const slots = [_]gate_mod.Slot{ try gate.view.slot(.reactor, 0, &h), try gate.view.slot(.reactor, 1, &h) };
        try testing.expectError(error.InvalidOptions, pool.prepareDormant(gate.control, gate.view, &slots, &h, &run, DormantHarness.worker));
        try testing.expect(pool.shared == null);
        try testing.expect(pool.joined);
        try testing.expectEqual(@as(usize, 0), pool.threads.len);
        try testing.expectEqual(@as(usize, 0), gate.view.inspect().spawned);
        try testing.expectEqual(@as(usize, 0), gate.view.inspect().arrived);
        try testing.expectEqual(@as(usize, 0), gate.view.inspect().joined);
        try testing.expectEqual(gate_mod.Phase.preparing, gate.view.inspect().phase);
        try testing.expect(run.load(.acquire));
        for (&h.seen) |*seen| try testing.expectEqual(@as(u32, 0), seen.load(.acquire));
    }
}

test {
    testing.refAllDecls(@This());
}
