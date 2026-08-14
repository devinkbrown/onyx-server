// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime-sized cross-shard delivery fabric for the multi-reactor daemon.
//!
//! This is the live, allocator-backed counterpart of the `cross_shard_smoke.zig`
//! capstone test. That test wires three lock-free primitives together by hand at
//! comptime-fixed sizes (`Mailboxes(...)`, `WakeSet(...)`, `DeliverPool(...)`);
//! the real daemon decides its shard count at boot from the host's core count,
//! so the *number* of mailboxes and wake fds must be a runtime value. This struct
//! bundles, per shard:
//!
//!   * one lock-free MPMC inbox (`BoundedMpmc(DeliverMsg, capacity)`),
//!   * one cross-reactor wake eventfd (`ReactorWake`), and
//!   * one pooled-buffer allocator (`DeliverPool(pool_slots)`) sized so a single
//!     shard's pool can fill that shard's inbox (`pool_slots == capacity`).
//!
//! The per-shard pool is the key sizing decision. A shard's `DeliverBuf`s are
//! ALWAYS acquired for, and released by, that one owning reactor, so giving each
//! shard its own pool makes the total buffer budget scale with the runtime shard
//! count (`num_shards * pool_slots`) instead of a single fixed 256. With one
//! shared pool a broadcast to a channel whose cross-shard recipients out-number
//! the pool silently exhausted it; per-shard pools collapse pool exhaustion into
//! the single, COUNTED inbox-full back-pressure signal (`dropped`).
//!
//! The element types are comptime-fixed in size, but the *count* of inboxes,
//! wakes, and pools is runtime: all three live as heap slices of length
//! `num_shards`. Each pool is ~1MB, so the pool slice is heap-allocated once
//! (~`num_shards` MB total). Everything inside is lock-free; the only allocation
//! happens at `init` and the only deallocation at `deinit`.
//!
//! Usage mirrors the smoke test, just behind a reusable runtime-sized struct:
//!   * a sender copies bytes via `acquire`, addresses a `DeliverMsg`, hands it off
//!     with `sendTo(target_shard, msg)`, then pokes `wake(target_shard)`;
//!   * the owning reactor registers `wakeFd(shard)` for a read in its io_uring,
//!     and on readiness calls `drainWake(shard)` then `drain(shard, out)`,
//!     consuming each `DeliverMsg` and `release`-ing its buffer back to the pool.
//!
//! IMPORTANT — the live daemon does NOT use this fabric's own wake fds. It uses
//! the inbox + pool handoff (`acquire`/`sendTo`/`drain`/`release`) but wakes the
//! owning reactor through that reactor's OWN `Reactor.wake` eventfd, which its
//! io_uring loop already arms a poll on, rather than through `wake`/`wakeFd`/
//! `drainWake` here (see `enqueueDeliveryMaybeCloseEx` in server.zig: "We
//! deliberately do not use the fabric's own wake fds"). The per-shard `wakes`
//! slice therefore exists only so this fabric is a self-contained, independently
//! testable primitive: it lets the smoke test and this module's own tests drive
//! the full acquire→sendTo→wake→drainWake→drain→release handshake — including the
//! eventfd wake — without standing up a whole `LinuxServer`. Do not read the
//! `wakeFd`-registration steps above as the daemon's live wake contract.
//!
//! Linux-only: the wake fds are kernel eventfds and `ReactorWake.init()` may fail
//! with `error.ReactorWakeUnsupported`, which `init` propagates.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const queue = @import("../substrate/queue.zig");
const shard = @import("shard.zig");
const reactor_wake = @import("reactor_wake.zig");
const deliver_handle = @import("deliver_handle.zig");
const client = @import("client.zig");
const session_drop_tx = @import("session_drop_tx.zig");

pub const ClientId = client.ClientId;
pub const DeliverBuf = deliver_handle.DeliverBuf;
pub const DeliverMsg = deliver_handle.DeliverMsg;
pub const SessionDropControl = session_drop_tx.Control;

const ReactorWake = reactor_wake.ReactorWake;

/// Shared, runtime-sized cross-shard delivery fabric. Owns one inbox + one wake
/// eventfd per shard and one shared pooled-buffer allocator. Thread-safe for the
/// documented access pattern: any thread may `acquire`/`release`/`sendTo`/`wake`;
/// only the owning reactor calls `drain`/`drainWake` for its own shard.
pub const ReactorFabric = struct {
    /// Per-shard mailbox depth (messages). Comptime: the MPMC ring needs a fixed,
    /// power-of-two capacity. Only the shard *count* is runtime.
    pub const capacity: usize = 256;
    /// Per-shard pool size (buffers), ~1MB each. Comptime for the same reason.
    /// Held == `capacity` so a shard's pool can exactly fill its inbox: when the
    /// inbox has room a buffer is always available, so pool exhaustion never drops
    /// independently of an inbox-full — the two back-pressure signals coincide.
    pub const pool_slots: usize = capacity;

    const Mailbox = queue.BoundedMpmc(DeliverMsg, capacity);
    const ControlMailbox = queue.BoundedMpmc(SessionDropControl, capacity);
    const Pool = deliver_handle.DeliverPool(pool_slots);

    allocator: std.mem.Allocator,
    /// One MPMC inbox per shard; index `i` is shard `i`'s inbox. Heap slice sized
    /// to the runtime shard count.
    inboxes: []Mailbox,
    /// Dedicated transaction-control path. It never borrows delivery buffers or
    /// shares delivery back-pressure, so a full chat fan-out cannot silently
    /// discard a lifecycle commit/reject control.
    controls: []ControlMailbox,
    /// One wake eventfd per shard; index `i` is shard `i`'s wake handle.
    wakes: []ReactorWake,
    /// One pooled-buffer allocator per shard; index `i` backs shard `i`'s handoffs.
    /// A buffer is acquired for a target shard from `pools[target]` and released
    /// back to the SAME pool by that shard's owning reactor. Heap slice sized to
    /// the runtime shard count (~`num_shards` MB total).
    pools: []Pool,
    /// Monotonic count of cross-shard messages DROPPED under sustained inbox/pool
    /// back-pressure. Non-zero means a fan-out shed load rather than block the
    /// reactor; surfaced by the daemon so a silent drop can never hide.
    dropped: std.atomic.Value(u64) = .init(0),
    /// Monotonic failed control admissions. A miss must wake or periodically
    /// rescan the authoritative journal; it never implies terminal failure and
    /// never poisons a client or asks one to duplicate a live transaction.
    control_miss: std.atomic.Value(u64) = .init(0),

    /// Build a fabric for `num_shards` shards (>= 1, <= `shard.max_shards`).
    ///
    /// Allocates the inbox slice, the wake slice, and the shared pool, then stands
    /// up one eventfd per shard. On any partial failure every resource already
    /// created — including every eventfd opened so far — is released, so neither
    /// memory nor file descriptors leak on the error path.
    pub fn init(allocator: std.mem.Allocator, num_shards: usize) !ReactorFabric {
        std.debug.assert(num_shards >= 1);
        std.debug.assert(num_shards <= shard.max_shards);

        const inboxes = try allocator.alloc(Mailbox, num_shards);
        errdefer allocator.free(inboxes);
        for (inboxes) |*ib| ib.* = Mailbox.init();

        const controls = try allocator.alloc(ControlMailbox, num_shards);
        errdefer allocator.free(controls);
        for (controls) |*ib| ib.* = ControlMailbox.init();

        const wakes = try allocator.alloc(ReactorWake, num_shards);
        errdefer allocator.free(wakes);

        // Stand up one eventfd per shard. Track how many succeeded so the errdefer
        // closes exactly those (and no uninitialized handles) if a later one fails.
        var made: usize = 0;
        errdefer for (wakes[0..made]) |*w| w.deinit();
        while (made < num_shards) : (made += 1) {
            wakes[made] = try ReactorWake.init();
        }

        const pools = try allocator.alloc(Pool, num_shards);
        errdefer allocator.free(pools);
        for (pools) |*p| p.* = Pool.init();

        return .{
            .allocator = allocator,
            .inboxes = inboxes,
            .controls = controls,
            .wakes = wakes,
            .pools = pools,
        };
    }

    /// Release every resource: free the per-shard pools, close every wake eventfd,
    /// then free the heap slices. After this the fabric is unusable.
    pub fn deinit(self: *ReactorFabric) void {
        self.allocator.free(self.pools);
        for (self.wakes) |*w| w.deinit();
        self.allocator.free(self.wakes);
        self.allocator.free(self.inboxes);
        self.allocator.free(self.controls);
        self.* = undefined;
    }

    /// The number of shards this fabric was sized for.
    pub fn numShards(self: *const ReactorFabric) usize {
        return self.inboxes.len;
    }

    /// Copy `bytes_in` into a `DeliverBuf` drawn from `target`'s pool, returning
    /// null if that pool is momentarily exhausted or `bytes_in` exceeds the
    /// per-buffer maximum. The buffer MUST be handed to `target` and released by
    /// `target`'s owning reactor. Callable from any thread.
    pub fn acquire(self: *ReactorFabric, target: u12, bytes_in: []const u8) ?*DeliverBuf {
        return self.pools[target].acquire(bytes_in);
    }

    /// Drop one reference to a buffer acquired for `target`, returning it to that
    /// shard's pool when the last reference is released. Called by `target`'s
    /// owning reactor (or the sender undoing a failed handoff to `target`).
    pub fn release(self: *ReactorFabric, target: u12, buf: *DeliverBuf) void {
        self.pools[target].release(buf);
    }

    /// The bytes a `DeliverBuf` currently holds. Pool-independent (reads the
    /// buffer directly), so no target shard is needed.
    pub fn bytes(_: *ReactorFabric, buf: *const DeliverBuf) []const u8 {
        return buf.data[0..buf.len];
    }

    /// Record `n` cross-shard messages dropped under back-pressure. Returns the
    /// count observed BEFORE this call so a caller can rate-limit its logging.
    pub fn recordDrop(self: *ReactorFabric, n: u64) u64 {
        return self.dropped.fetchAdd(n, .monotonic);
    }

    /// Total cross-shard messages dropped under back-pressure since init.
    pub fn droppedCount(self: *const ReactorFabric) u64 {
        return self.dropped.load(.monotonic);
    }

    pub fn recordControlMiss(self: *ReactorFabric) u64 {
        return self.control_miss.fetchAdd(1, .monotonic);
    }

    pub fn controlMissCount(self: *const ReactorFabric) u64 {
        return self.control_miss.load(.monotonic);
    }

    /// Enqueue `msg` for the reactor owning `target`. Returns false if that inbox
    /// is full (caller decides: drop, retry, or back-pressure). Callable from any
    /// thread (MPMC). Does NOT wake the target — call `wake` after a successful
    /// handoff so a sleeping reactor notices.
    pub fn sendTo(self: *ReactorFabric, target: u12, msg: DeliverMsg) bool {
        return self.inboxes[target].push(msg);
    }

    /// Drain up to `out.len` messages from `target`'s inbox into `out`, returning
    /// the count written. Called only by that shard's owning reactor.
    pub fn drain(self: *ReactorFabric, target: u12, out: []DeliverMsg) usize {
        return self.inboxes[target].popBatch(out);
    }

    /// Enqueue a self-contained session-drop transaction control. No borrowed
    /// pointers or credential slices cross this boundary.
    pub fn sendControlTo(self: *ReactorFabric, target: u12, control: SessionDropControl) bool {
        if (self.controls[target].push(control)) return true;
        _ = self.recordControlMiss();
        return false;
    }

    /// Drain controls addressed to this owner shard. The owner validates every
    /// generational target and transaction id before acting.
    pub fn drainControls(self: *ReactorFabric, target: u12, out: []SessionDropControl) usize {
        return self.controls[target].popBatch(out);
    }

    /// Poke the wake eventfd of the reactor owning `target` so its io_uring loop
    /// runs and rescans its inbox. Callable from any thread; best-effort.
    pub fn wake(self: *ReactorFabric, target: u12) void {
        self.wakes[target].wake();
    }

    /// Clear `target`'s wake eventfd readiness; called by that shard's reactor
    /// before it rescans its inbox.
    pub fn drainWake(self: *ReactorFabric, target: u12) void {
        self.wakes[target].drain();
    }

    /// The eventfd shard `target` registers for a read in its own io_uring.
    pub fn wakeFd(self: *const ReactorFabric, target: u12) linux.fd_t {
        return self.wakes[target].fd();
    }
};

const testing = std.testing;

test "single-shard fabric round-trips one delivery and reclaims its buffer" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var fabric = ReactorFabric.init(testing.allocator, 1) catch |err| switch (err) {
        error.ReactorWakeUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer fabric.deinit();

    try testing.expectEqual(@as(usize, 1), fabric.numShards());

    // Acquire → bytes → hand off → drainWake → drain → bytes → release, shard 0.
    const buf = fabric.acquire(0, "PRIVMSG #zig :hello\r\n") orelse return error.TestExpectedEqual;
    try testing.expectEqualStrings("PRIVMSG #zig :hello\r\n", fabric.bytes(buf));

    const msg = DeliverMsg{ .to = .{ .shard = 0, .slot = 3, .gen = 1 }, .buf = buf };
    try testing.expect(fabric.sendTo(0, msg));
    fabric.wake(0);

    var out: [4]DeliverMsg = undefined;
    fabric.drainWake(0);
    const n = fabric.drain(0, &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].to.eql(.{ .shard = 0, .slot = 3, .gen = 1 }));
    try testing.expectEqualStrings("PRIVMSG #zig :hello\r\n", fabric.bytes(out[0].buf));
    fabric.release(0, out[0].buf);
}

test "fabric routes deliveries only to the addressed shard" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var fabric = ReactorFabric.init(testing.allocator, 4) catch |err| switch (err) {
        error.ReactorWakeUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer fabric.deinit();

    const buf1 = fabric.acquire(1, "one") orelse return error.TestExpectedEqual;
    const buf3 = fabric.acquire(3, "three") orelse return error.TestExpectedEqual;

    try testing.expect(fabric.sendTo(1, .{ .to = .{ .shard = 1, .slot = 5, .gen = 1 }, .buf = buf1 }));
    try testing.expect(fabric.sendTo(3, .{ .to = .{ .shard = 3, .slot = 6, .gen = 1 }, .buf = buf3 }));

    var out: [8]DeliverMsg = undefined;
    // Shards 0 and 2 are empty; 1 and 3 hold exactly one each.
    try testing.expectEqual(@as(usize, 0), fabric.drain(0, &out));
    try testing.expectEqual(@as(usize, 0), fabric.drain(2, &out));

    const n1 = fabric.drain(1, &out);
    try testing.expectEqual(@as(usize, 1), n1);
    try testing.expectEqualStrings("one", fabric.bytes(out[0].buf));
    fabric.release(1, out[0].buf);

    const n3 = fabric.drain(3, &out);
    try testing.expectEqual(@as(usize, 1), n3);
    try testing.expectEqualStrings("three", fabric.bytes(out[0].buf));
    fabric.release(3, out[0].buf);
}

/// One consumer reactor stand-in: sleeps in poll() on its wake fd, drains the
/// eventfd then its inbox, copies + releases each buffer, and records per-seq
/// arrival so the test can detect drops, duplicates, or misrouting.
const TestReactor = struct {
    fabric: *ReactorFabric,
    shard_id: u12,
    expected: usize,
    received: usize = 0,
    /// seen[seq] guards against duplicate delivery of a sequence number.
    seen: [per_shard]bool = @splat(false),
    /// Set on misrouting, a malformed payload, an out-of-range seq, or a dup.
    corrupt: bool = false,

    const per_shard = 1500;

    fn run(self: *TestReactor) void {
        var pfd = [_]std.posix.pollfd{.{
            .fd = self.fabric.wakeFd(self.shard_id),
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        var out: [64]DeliverMsg = undefined;
        // Bounded so a wiring bug fails the test instead of hanging forever.
        var idle_polls: usize = 0;
        while (self.received < self.expected) {
            _ = std.posix.poll(&pfd, 100) catch break;
            // Drain the eventfd before the inbox: a wake that lands after this
            // drain but before a later push re-arms readiness, so none is lost.
            self.fabric.drainWake(self.shard_id);

            const n = self.fabric.drain(self.shard_id, &out);
            if (n == 0) {
                idle_polls += 1;
                if (idle_polls > 200) break; // ~20s without progress: give up.
                continue;
            }
            idle_polls = 0;
            for (out[0..n]) |msg| self.consume(msg);
        }
    }

    fn consume(self: *TestReactor, msg: DeliverMsg) void {
        defer self.fabric.release(self.shard_id, msg.buf);
        if (msg.to.shard != self.shard_id) {
            self.corrupt = true;
            return;
        }
        const payload = self.fabric.bytes(msg.buf);
        // Payload is "<shard>:<seq>" — re-derive and check it round-tripped.
        var it = std.mem.splitScalar(u8, payload, ':');
        const sh = std.fmt.parseInt(u12, it.first(), 10) catch {
            self.corrupt = true;
            return;
        };
        const seq = std.fmt.parseInt(usize, it.rest(), 10) catch {
            self.corrupt = true;
            return;
        };
        if (sh != self.shard_id or seq >= per_shard or self.seen[seq]) {
            self.corrupt = true;
            return;
        }
        self.seen[seq] = true;
        self.received += 1;
    }
};

/// Cross-shard sender: produces `total` deliveries split evenly between the two
/// shards, retrying on pool exhaustion and inbox back-pressure exactly as the
/// live fan-out path will.
fn produce(fabric: *ReactorFabric, num_shards: u12, per_shard: usize) void {
    const total = per_shard * num_shards;
    var line: [32]u8 = undefined;
    var seqs = [_]usize{ 0, 0 };
    var produced: usize = 0;
    while (produced < total) : (produced += 1) {
        const target: u12 = @intCast(produced % num_shards);
        const seq = seqs[target];
        seqs[target] += 1;
        const payload = std.fmt.bufPrint(&line, "{d}:{d}", .{ target, seq }) catch unreachable;

        // Acquire a pooled buffer (copies the bytes), retrying if in-flight
        // deliveries momentarily drained the pool.
        const buf = while (true) {
            if (fabric.acquire(target, payload)) |b| break b;
            std.Thread.yield() catch {};
        };
        const msg = DeliverMsg{ .to = .{ .shard = target, .slot = @intCast(seq), .gen = 1 }, .buf = buf };
        // Hand off + wake, retrying on a full inbox.
        while (!fabric.sendTo(target, msg)) std.Thread.yield() catch {};
        fabric.wake(target);
    }
}

test "two reactors deliver cross-shard through the fabric exactly once with no buffer leak" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const num_shards: u12 = 2;
    const per_shard = TestReactor.per_shard;

    var fabric = ReactorFabric.init(testing.allocator, num_shards) catch |err| switch (err) {
        error.ReactorWakeUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer fabric.deinit();

    var reactors: [num_shards]TestReactor = undefined;
    for (0..num_shards) |i| {
        reactors[i] = .{ .fabric = &fabric, .shard_id = @intCast(i), .expected = per_shard };
    }

    var threads: [num_shards]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..num_shards) |i| {
        threads[i] = std.Thread.spawn(.{}, TestReactor.run, .{&reactors[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }

    // Drive the producer on this thread once both reactors are armed.
    produce(&fabric, num_shards, per_shard);

    for (threads[0..spawned]) |t| t.join();

    for (&reactors) |*r| {
        try testing.expect(!r.corrupt);
        try testing.expectEqual(@as(usize, per_shard), r.received);
    }

    // Every handed-off buffer must be back in its shard's pool: for each shard,
    // drain that pool to exhaustion and confirm exactly the full slot count is
    // reclaimable (no handoff leak, and per-shard pools stayed independent).
    for (0..num_shards) |i| {
        const sid: u12 = @intCast(i);
        var reclaimed: usize = 0;
        var pinned: ?*DeliverBuf = null;
        while (fabric.acquire(sid, "x")) |b| {
            reclaimed += 1;
            if (reclaimed > ReactorFabric.pool_slots) {
                pinned = b;
                break;
            }
        }
        if (pinned) |b| fabric.release(sid, b);
        try testing.expectEqual(@as(usize, ReactorFabric.pool_slots), reclaimed);
    }
}

test "fabric per-shard pools scale the buffer budget with shard count" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const num_shards: u12 = 3;
    var fabric = ReactorFabric.init(testing.allocator, num_shards) catch |err| switch (err) {
        error.ReactorWakeUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer fabric.deinit();

    // Draining ONE shard's pool to exhaustion must not touch any other shard's
    // pool: the budget is per-shard, so total capacity scales as
    // num_shards * pool_slots rather than a single fixed 256.
    var held: [ReactorFabric.pool_slots]*DeliverBuf = undefined;
    for (0..ReactorFabric.pool_slots) |i| {
        held[i] = fabric.acquire(0, "x") orelse return error.TestExpectedEqual;
    }
    // Shard 0 is now exhausted...
    try testing.expectEqual(@as(?*DeliverBuf, null), fabric.acquire(0, "x"));
    // ...but shards 1 and 2 are untouched and each yields a full pool.
    var others: usize = 0;
    for ([_]u12{ 1, 2 }) |sid| {
        var got: usize = 0;
        while (fabric.acquire(sid, "y")) |b| {
            got += 1;
            if (got > ReactorFabric.pool_slots) {
                fabric.release(sid, b);
                break;
            }
        }
        try testing.expectEqual(ReactorFabric.pool_slots, got);
        others += got;
    }
    try testing.expectEqual(@as(usize, 2 * ReactorFabric.pool_slots), others);

    for (held) |b| fabric.release(0, b);
}

test "fabric drop counter accumulates and is observable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var fabric = ReactorFabric.init(testing.allocator, 2) catch |err| switch (err) {
        error.ReactorWakeUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer fabric.deinit();

    try testing.expectEqual(@as(u64, 0), fabric.droppedCount());
    // recordDrop returns the count observed BEFORE the add (for rate-limited logs).
    try testing.expectEqual(@as(u64, 0), fabric.recordDrop(1));
    try testing.expectEqual(@as(u64, 1), fabric.recordDrop(3));
    try testing.expectEqual(@as(u64, 4), fabric.droppedCount());
}

test "session controls are isolated from delivery pressure and count full admission misses" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fabric = ReactorFabric.init(testing.allocator, 2) catch |err| switch (err) {
        error.ReactorWakeUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer fabric.deinit();

    // A saturated delivery inbox must not consume the independent control ring.
    var held: [ReactorFabric.capacity]*DeliverBuf = undefined;
    for (&held) |*slot| {
        slot.* = fabric.acquire(0, "x") orelse return error.TestExpectedEqual;
        try testing.expect(fabric.sendTo(0, .{ .to = .{ .shard = 0, .slot = 1, .gen = 1 }, .buf = slot.* }));
    }
    const control = SessionDropControl.init(.{ .slot_plus_one = 1, .generation = 1 }) orelse return error.TestExpectedEqual;
    try testing.expect(fabric.sendControlTo(0, control));

    // Control fullness is independently observable and never poisons/drops a
    // delivery.
    for (1..ReactorFabric.capacity) |_| try testing.expect(fabric.sendControlTo(0, control));
    try testing.expect(!fabric.sendControlTo(0, control));
    try testing.expectEqual(@as(u64, 1), fabric.controlMissCount());

    var controls: [ReactorFabric.capacity]SessionDropControl = undefined;
    try testing.expectEqual(ReactorFabric.capacity, fabric.drainControls(0, &controls));
    var messages: [ReactorFabric.capacity]DeliverMsg = undefined;
    try testing.expectEqual(ReactorFabric.capacity, fabric.drain(0, &messages));
    for (messages) |msg| fabric.release(0, msg.buf);
}

test "session controls route only to their addressed shard" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fabric = ReactorFabric.init(testing.allocator, 3) catch |err| switch (err) {
        error.ReactorWakeUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer fabric.deinit();

    const control = SessionDropControl.init(.{ .slot_plus_one = 1, .generation = 1 }) orelse return error.TestExpectedEqual;
    try testing.expect(fabric.sendControlTo(2, control));
    var none: [1]SessionDropControl = undefined;
    try testing.expectEqual(@as(usize, 0), fabric.drainControls(0, &none));
    try testing.expectEqual(@as(usize, 0), fabric.drainControls(1, &none));
    var received: [1]SessionDropControl = undefined;
    try testing.expectEqual(@as(usize, 1), fabric.drainControls(2, &received));
}
