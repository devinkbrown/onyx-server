// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lock-free substrate queues.
//!
//! These queues are allocation-free and keep their storage inline. The MPMC
//! queue uses Dmitry Vyukov's bounded ring algorithm with per-slot sequence
//! counters, while the SPSC queue uses the simpler one-producer/one-consumer
//! acquire/release ring.
const std = @import("std");

pub const cache_line_bytes: usize = 64;

fn assertPowerOfTwo(comptime capacity: usize) void {
    comptime {
        std.debug.assert(capacity > 0);
        std.debug.assert(std.math.isPowerOfTwo(capacity));
    }
}

fn signedDiff(a: usize, b: usize) isize {
    return @as(isize, @bitCast(a -% b));
}

/// Whether a position precedes an exclusive cut, within half the counter range.
pub fn precedesCut(position: usize, cut: usize) bool {
    return signedDiff(position, cut) < 0;
}

/// Bounded multi-producer, multi-consumer queue.
///
/// Capacity must be a non-zero power of two. Push returns `false` when the ring
/// is full; pop returns `null` when it is empty.
pub fn BoundedMpmc(comptime T: type, comptime capacity: usize) type {
    assertPowerOfTwo(capacity);

    return struct {
        const Self = @This();
        const Counter = std.atomic.Value(usize);
        const mask = capacity - 1;
        const slot_alignment = if (@alignOf(T) > cache_line_bytes) @alignOf(T) else cache_line_bytes;

        const Slot = struct {
            seq: Counter align(slot_alignment) = .init(0),
            item: T = undefined,
        };

        head: Counter align(cache_line_bytes) = .init(0),
        tail: Counter align(cache_line_bytes) = .init(0),
        slots: [capacity]Slot align(slot_alignment) = initSlots(),

        pub fn init() Self {
            return .{};
        }

        /// Observe queued or producer-claimed positions, including unpublished
        /// slots. This is not a quiescence barrier: callers must externally
        /// synchronize producers and consumers and account for work already popped.
        pub fn hasPending(self: *const Self) bool {
            const head = self.head.load(.acquire);
            const tail = self.tail.load(.acquire);
            return head != tail;
        }

        pub const Positioned = struct { position: usize, item: T };

        /// Exclusive producer claim watermark. A claim may not be published yet.
        pub fn captureCut(self: *const Self) usize {
            return self.tail.load(.acquire);
        }

        /// Counters are ordered modulo usize; keep a cut alive for less than
        /// half the counter range. This reports dequeue, not completed custody.
        pub fn consumedThrough(self: *const Self, cut: usize) bool {
            return signedDiff(self.head.load(.acquire), cut) >= 0;
        }

        /// Pop only a position preceding cut. An unpublished head returns null
        /// immediately. Concurrent consumers must obey the same cut discipline.
        pub fn popThrough(self: *Self, cut: usize) ?Positioned {
            var pos = self.head.load(.monotonic);
            while (precedesCut(pos, cut)) {
                const slot = &self.slots[pos & mask];
                const seq = slot.seq.load(.acquire);
                const diff = signedDiff(seq, pos +% 1);
                if (diff == 0) {
                    if (self.head.cmpxchgWeak(pos, pos +% 1, .monotonic, .monotonic)) |actual| {
                        pos = actual;
                        continue;
                    }
                    const item = slot.item;
                    slot.seq.store(pos +% capacity, .release);
                    return .{ .position = pos, .item = item };
                }
                if (diff < 0) return null;
                pos = self.head.load(.monotonic);
            }
            return null;
        }

        pub fn push(self: *Self, item: T) bool {
            var pos = self.tail.load(.monotonic);

            while (true) {
                const slot = &self.slots[pos & mask];
                const seq = slot.seq.load(.acquire);
                const diff = signedDiff(seq, pos);

                if (diff == 0) {
                    if (self.tail.cmpxchgWeak(pos, pos +% 1, .monotonic, .monotonic)) |actual| {
                        pos = actual;
                        continue;
                    }

                    slot.item = item;
                    slot.seq.store(pos +% 1, .release);
                    return true;
                }

                if (diff < 0) return false;
                pos = self.tail.load(.monotonic);
            }
        }

        pub fn pop(self: *Self) ?T {
            var pos = self.head.load(.monotonic);

            while (true) {
                const slot = &self.slots[pos & mask];
                const seq = slot.seq.load(.acquire);
                const diff = signedDiff(seq, pos +% 1);

                if (diff == 0) {
                    if (self.head.cmpxchgWeak(pos, pos +% 1, .monotonic, .monotonic)) |actual| {
                        pos = actual;
                        continue;
                    }

                    const item = slot.item;
                    slot.seq.store(pos +% capacity, .release);
                    return item;
                }

                if (diff < 0) return null;
                pos = self.head.load(.monotonic);
            }
        }

        pub fn popBatch(self: *Self, out: []T) usize {
            var count: usize = 0;
            while (count < out.len) : (count += 1) {
                out[count] = self.pop() orelse break;
            }
            return count;
        }

        fn initSlots() [capacity]Slot {
            var slots: [capacity]Slot = undefined;
            for (&slots, 0..) |*slot, i| {
                slot.* = .{ .seq = .init(i), .item = undefined };
            }
            return slots;
        }
    };
}

/// Single-producer, single-consumer ring queue.
///
/// Capacity must be a non-zero power of two. The producer owns `tail`, the
/// consumer owns `head`, and acquire/release ordering publishes item writes.
pub fn Spsc(comptime T: type, comptime capacity: usize) type {
    assertPowerOfTwo(capacity);

    return struct {
        const Self = @This();
        const Counter = std.atomic.Value(usize);
        const mask = capacity - 1;
        const slot_alignment = if (@alignOf(T) > cache_line_bytes) @alignOf(T) else cache_line_bytes;

        head: Counter align(cache_line_bytes) = .init(0),
        tail: Counter align(cache_line_bytes) = .init(0),
        slots: [capacity]T align(slot_alignment) = undefined,

        pub fn init() Self {
            return .{};
        }

        pub fn push(self: *Self, item: T) bool {
            const tail = self.tail.load(.monotonic);
            const head = self.head.load(.acquire);
            if (tail -% head == capacity) return false;

            self.slots[tail & mask] = item;
            self.tail.store(tail +% 1, .release);
            return true;
        }

        pub fn pop(self: *Self) ?T {
            const head = self.head.load(.monotonic);
            const tail = self.tail.load(.acquire);
            if (head == tail) return null;

            const item = self.slots[head & mask];
            self.head.store(head +% 1, .release);
            return item;
        }
    };
}

test "mpmc cut stops at unpublished claim and excludes later positions across wrap" {
    var q = BoundedMpmc(u32, 4).init();
    const start = std.math.maxInt(usize) - 1;
    q.head.store(start, .monotonic);
    q.tail.store(start, .monotonic);
    for (0..4) |i| {
        const pos = start +% i;
        q.slots[pos & 3].seq.store(pos, .monotonic);
    }
    try std.testing.expect(q.push(1));
    const hole = q.tail.load(.monotonic);
    try std.testing.expect(q.tail.cmpxchgStrong(hole, hole +% 1, .monotonic, .monotonic) == null);
    const cut = q.captureCut();
    try std.testing.expectEqual(@as(usize, 0), cut);
    try std.testing.expect(q.push(3));
    const first = q.popThrough(cut).?;
    try std.testing.expectEqual(start, first.position);
    try std.testing.expectEqual(@as(u32, 1), first.item);
    try std.testing.expect(q.popThrough(cut) == null);
    try std.testing.expect(!q.consumedThrough(cut));
    q.slots[hole & 3].item = 2;
    q.slots[hole & 3].seq.store(hole +% 1, .release);
    const second = q.popThrough(cut).?;
    try std.testing.expectEqual(hole, second.position);
    try std.testing.expectEqual(@as(u32, 2), second.item);
    try std.testing.expect(q.consumedThrough(cut));
    try std.testing.expect(q.popThrough(cut) == null);
    try std.testing.expectEqual(@as(?u32, 3), q.pop());
}

test "mpmc pending includes a claimed unpublished slot" {
    var q = BoundedMpmc(u32, 4).init();
    try std.testing.expect(!q.hasPending());
    try std.testing.expect(q.push(7));
    try std.testing.expect(q.hasPending());
    try std.testing.expectEqual(@as(?u32, 7), q.pop());
    try std.testing.expect(!q.hasPending());

    // Reproduce push's successful tail claim before publishing the slot.
    const pos = q.tail.load(.monotonic);
    try std.testing.expect(q.tail.cmpxchgStrong(pos, pos +% 1, .monotonic, .monotonic) == null);
    try std.testing.expect(q.hasPending());
    try std.testing.expectEqual(@as(?u32, null), q.pop());
    q.slots[pos & 3].item = 9;
    q.slots[pos & 3].seq.store(pos +% 1, .release);
    try std.testing.expectEqual(@as(?u32, 9), q.pop());
    try std.testing.expect(!q.hasPending());
}

test "mpmc single-threaded fifo correctness" {
    var q = BoundedMpmc(u32, 8).init();

    try std.testing.expect(q.push(10));
    try std.testing.expect(q.push(20));
    try std.testing.expect(q.push(30));

    try std.testing.expectEqual(@as(?u32, 10), q.pop());
    try std.testing.expectEqual(@as(?u32, 20), q.pop());
    try std.testing.expectEqual(@as(?u32, 30), q.pop());
    try std.testing.expectEqual(@as(?u32, null), q.pop());
}

test "mpmc full and empty behavior" {
    var q = BoundedMpmc(usize, 4).init();

    try std.testing.expectEqual(@as(?usize, null), q.pop());
    try std.testing.expect(q.push(0));
    try std.testing.expect(q.push(1));
    try std.testing.expect(q.push(2));
    try std.testing.expect(q.push(3));
    try std.testing.expect(!q.push(4));

    try std.testing.expectEqual(@as(?usize, 0), q.pop());
    try std.testing.expect(q.push(4));

    for (1..5) |expected| {
        try std.testing.expectEqual(@as(?usize, expected), q.pop());
    }
    try std.testing.expectEqual(@as(?usize, null), q.pop());
}

test "mpmc wraps past capacity" {
    var q = BoundedMpmc(usize, 4).init();

    for (0..32) |i| {
        try std.testing.expect(q.push(i));
        try std.testing.expectEqual(@as(?usize, i), q.pop());
    }

    for (0..4) |i| try std.testing.expect(q.push(i));
    for (0..2) |i| try std.testing.expectEqual(@as(?usize, i), q.pop());
    try std.testing.expect(q.push(4));
    try std.testing.expect(q.push(5));
    try std.testing.expect(!q.push(6));

    for (2..6) |expected| {
        try std.testing.expectEqual(@as(?usize, expected), q.pop());
    }
    try std.testing.expectEqual(@as(?usize, null), q.pop());
}

test "spsc single-threaded fifo correctness" {
    var q = Spsc(u32, 8).init();

    try std.testing.expect(q.push(1));
    try std.testing.expect(q.push(2));
    try std.testing.expect(q.push(3));

    try std.testing.expectEqual(@as(?u32, 1), q.pop());
    try std.testing.expectEqual(@as(?u32, 2), q.pop());
    try std.testing.expectEqual(@as(?u32, 3), q.pop());
    try std.testing.expectEqual(@as(?u32, null), q.pop());
}

test "spsc full empty and wrap-around" {
    var q = Spsc(usize, 4).init();

    try std.testing.expectEqual(@as(?usize, null), q.pop());
    for (0..4) |i| try std.testing.expect(q.push(i));
    try std.testing.expect(!q.push(4));

    for (0..2) |i| try std.testing.expectEqual(@as(?usize, i), q.pop());
    try std.testing.expect(q.push(4));
    try std.testing.expect(q.push(5));
    try std.testing.expect(!q.push(6));

    for (2..6) |expected| {
        try std.testing.expectEqual(@as(?usize, expected), q.pop());
    }
    try std.testing.expectEqual(@as(?usize, null), q.pop());
}

test "mpmc multi-threaded stress has no loss or duplication" {
    const producers = 2;
    const consumers = 2;
    const per_producer = 4096;
    const total = producers * per_producer;
    const Queue = BoundedMpmc(usize, 128);
    const AtomicU8 = std.atomic.Value(u8);
    const AtomicUsize = std.atomic.Value(usize);
    const AtomicU64 = std.atomic.Value(u64);

    const Context = struct {
        queue: Queue = Queue.init(),
        produced: AtomicUsize = .init(0),
        consumed: AtomicUsize = .init(0),
        sum: AtomicU64 = .init(0),
        seen: [total]AtomicU8 = initSeen(),

        fn initSeen() [total]AtomicU8 {
            return @as([total]AtomicU8, @splat(AtomicU8.init(0)));
        }

        fn producer(ctx: *@This(), producer_id: usize) void {
            const base = producer_id * per_producer;
            for (0..per_producer) |i| {
                const value = base + i;
                while (!ctx.queue.push(value)) {
                    std.Thread.yield() catch {};
                }
                _ = ctx.produced.fetchAdd(1, .release);
            }
        }

        fn consumer(ctx: *@This()) void {
            while (ctx.consumed.load(.acquire) < total) {
                if (ctx.queue.pop()) |value| {
                    std.debug.assert(value < total);
                    _ = ctx.seen[value].fetchAdd(1, .monotonic);
                    _ = ctx.sum.fetchAdd(@as(u64, @intCast(value)), .monotonic);
                    _ = ctx.consumed.fetchAdd(1, .release);
                } else {
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    var ctx: Context = .{};
    var producer_threads: [producers]std.Thread = undefined;
    var consumer_threads: [consumers]std.Thread = undefined;

    for (&producer_threads, 0..) |*thread, producer_id| {
        thread.* = std.Thread.spawn(.{}, Context.producer, .{ &ctx, producer_id }) catch {
            return error.SkipZigTest;
        };
    }
    for (&consumer_threads) |*thread| {
        thread.* = std.Thread.spawn(.{}, Context.consumer, .{&ctx}) catch {
            return error.SkipZigTest;
        };
    }

    for (&producer_threads) |thread| thread.join();
    for (&consumer_threads) |thread| thread.join();

    try std.testing.expectEqual(@as(usize, total), ctx.produced.load(.acquire));
    try std.testing.expectEqual(@as(usize, total), ctx.consumed.load(.acquire));

    const expected_sum = @as(u64, total - 1) * @as(u64, total) / 2;
    try std.testing.expectEqual(expected_sum, ctx.sum.load(.acquire));

    for (&ctx.seen) |*seen| {
        try std.testing.expectEqual(@as(u8, 1), seen.load(.acquire));
    }
}
