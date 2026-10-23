// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: source owner.

const seedOwnerForCensus = @import("test_fixture.zig").seedOwnerForCensus;
const std = @import("std");
const familyIndex = @import("contracts.zig").familyIndex;
const AllocatorObservation = @import("source_owner.zig").AllocatorObservation;
const observeAllocator = @import("source_owner.zig").observeAllocator;
const OwnedCapacityDescriptor = @import("source_owner.zig").OwnedCapacityDescriptor;
const ReadIterator = @import("source_owner.zig").ReadIterator;
const ReadLease = @import("source_owner.zig").ReadLease;
const StoreExclusive = @import("source_owner.zig").StoreExclusive;
const StoreOwnerBacking = @import("source_owner.zig").StoreOwnerBacking;
const StoreResourceOwner = @import("source_owner.zig").StoreResourceOwner;
const createStoreResourceOwner = @import("source_owner.zig").createStoreResourceOwner;
const createStoreResourceOwnerWithCounter = @import("source_owner.zig").createStoreResourceOwnerWithCounter;
const destroyStoreResourceOwner = @import("source_owner.zig").destroyStoreResourceOwner;
const ownerBacking = @import("source_owner.zig").ownerBacking;
const reserveStoreLifetime = @import("source_owner.zig").reserveStoreLifetime;
const coldFixtureAbsoluteDirectory = @import("tests_custody.zig").coldFixtureAbsoluteDirectory;
const openTestStore = @import("tests_support.zig").openTestStore;
const readWalForTest = @import("tests_support.zig").readWalForTest;

pub const StoreOwnerObserver = struct {
    const Allocation = struct { ptr: usize, len: usize, alignment: usize, seen: bool = false };
    backend: std.mem.Allocator = std.testing.allocator,
    records: [512]?Allocation = @splat(null),
    calls: usize = 0,
    frees: usize = 0,
    fail_at: usize = std.math.maxInt(usize),
    pub fn allocator(self: *StoreOwnerObserver) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *StoreOwnerObserver = @ptrCast(@alignCast(ctx));
        const call = self.calls;
        self.calls += 1;
        if (call == self.fail_at) return null;
        const ptr = self.backend.rawAlloc(len, alignment, address) orelse return null;
        for (&self.records) |*slot| if (slot.* == null) {
            slot.* = .{ .ptr = @intFromPtr(ptr), .len = len, .alignment = alignment.toByteUnits() };
            return ptr;
        };
        @panic("observer fixture capacity exhausted");
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *StoreOwnerObserver = @ptrCast(@alignCast(ctx));
        for (&self.records) |*slot| if (slot.*) |record| if (record.ptr == @intFromPtr(bytes.ptr)) {
            std.debug.assert(record.len == bytes.len and record.alignment == alignment.toByteUnits());
            self.backend.rawFree(bytes, alignment, address);
            slot.* = null;
            self.frees += 1;
            return;
        };
        @panic("wrong original allocator received free");
    }
    fn mark(self: *StoreOwnerObserver, d: OwnedCapacityDescriptor) !void {
        try std.testing.expectEqualDeep(observeAllocator(self.allocator()), d.original_allocator);
        for (&self.records) |*slot| if (slot.*) |*record| if (record.ptr == d.locator) {
            try std.testing.expect(!record.seen);
            try std.testing.expectEqual(record.len, d.requested_bytes);
            try std.testing.expectEqual(record.alignment, d.alignment);
            record.seen = true;
            return;
        };
        return error.MissingOriginalAllocation;
    }
    pub fn checkAll(self: *const StoreOwnerObserver, seen: bool) !void {
        for (self.records) |slot| if (slot) |record| {
            if (!seen) return error.LeakedOriginalAllocation;
            try std.testing.expect(record.seen);
        };
    }
};

test "STORE source owner complete census heterogeneous original contexts and disk inert" {
    for ([_]usize{ 2, 64 }) |feed_capacity| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var meta: StoreOwnerObserver = .{};
        var payload: StoreOwnerObserver = .{};
        const owner = try createStoreResourceOwner(meta.allocator(), payload.allocator(), std.testing.io, tmp.dir, "owner.wal", .{ .changefeed_capacity = feed_capacity }, false);
        var destroyed = false;
        defer if (!destroyed) destroyStoreResourceOwner(owner) catch unreachable;
        try seedOwnerForCensus(owner);
        const s = &ownerBacking(owner).store;
        try std.testing.expect(s.maps[familyIndex(.nicks)].map.slots.len != 0);
        try std.testing.expectEqual(@as(u32, 0), s.maps[familyIndex(.nicks)].map.count());
        try std.testing.expect(s.maps[familyIndex(.nicks)].map.tombstones != 0);
        try std.testing.expect(s.retirement_count != 0);
        if (feed_capacity == 64) try std.testing.expect(s.changefeed.count < s.changefeed.entries.len);
        const before = try readWalForTest(tmp, "owner.wal");
        defer std.testing.allocator.free(before);
        const meta_calls = meta.calls;
        const payload_calls = payload.calls;
        const meta_frees = meta.frees;
        const payload_frees = payload.frees;
        meta.fail_at = meta.calls;
        payload.fail_at = payload.calls;
        const exclusive = try owner.tryAcquireExclusive();
        const state = try exclusive.sourceState();
        try std.testing.expect(state.owned_wal_descriptor and !state.owned_staged_descriptor);
        try std.testing.expectEqual(@as(u64, 1), state.source.owner_revision);
        const cursor = try exclusive.catalog();
        try std.testing.expectError(error.LeaseChildren, exclusive.finish());
        var kinds: [@typeInfo(@FieldType(OwnedCapacityDescriptor, "kind")).@"enum".field_names.len]usize = @splat(0);
        while (try cursor.next()) |d| {
            try std.testing.expectEqualDeep(state.source, d.source);
            try std.testing.expect(d.requested_bytes > 0);
            kinds[@backingInt(d.kind)] += 1;
            if (std.meta.eql(d.original_allocator, observeAllocator(meta.allocator()))) try meta.mark(d) else try payload.mark(d);
        }
        try meta.checkAll(true);
        try payload.checkAll(true);
        for ([_]@FieldType(OwnedCapacityDescriptor, "kind"){ .owner_box, .wal_path, .snapshot_path, .table_backing, .live_key, .live_value, .feed_ring, .feed_key, .retired_bytes, .retired_table }) |kind| try std.testing.expect(kinds[@backingInt(kind)] != 0);
        if (feed_capacity == 2) {
            try std.testing.expect(kinds[@backingInt(@as(@FieldType(OwnedCapacityDescriptor, "kind"), .retired_key))] != 0);
            try std.testing.expect(kinds[@backingInt(@as(@FieldType(OwnedCapacityDescriptor, "kind"), .retired_value))] != 0);
        }
        try cursor.finish();
        try std.testing.expectError(error.InvalidLease, cursor.next());
        try exclusive.finish();
        try std.testing.expectEqual(meta_calls, meta.calls);
        try std.testing.expectEqual(payload_calls, payload.calls);
        try std.testing.expectEqual(meta_frees, meta.frees);
        try std.testing.expectEqual(payload_frees, payload.frees);
        const after = try readWalForTest(tmp, "owner.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try destroyStoreResourceOwner(owner);
        destroyed = true;
        try meta.checkAll(false);
        try payload.checkAll(false);
        // Borrowed directory/Io/backend remain independently live after teardown.
        const file = try tmp.dir.createFile(std.testing.io, "still-borrowed", .{});
        file.close(std.testing.io);
    }
}

test "STORE source owner read iterator feed real pins copied finish slot reuse and exhaustion" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "pins.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    try ownerBacking(owner).store.put(.props, "key", "value");
    const a = try owner.borrowRead();
    const copied = a;
    try std.testing.expectEqualStrings("value", (try a.get(.props, "key")).?);
    try std.testing.expectEqualStrings("key", (try a.changeAt(0)).?.key);
    const iter = try a.iterate(.props);
    try std.testing.expectEqualStrings("value", (try iter.next()).?.value);
    try std.testing.expectError(error.LeaseChildren, copied.finish());
    try std.testing.expectError(error.Busy, owner.tryAcquireExclusive());
    try std.testing.expectError(error.Busy, destroyStoreResourceOwner(owner));
    try iter.finish();
    try a.finish();
    const b = try owner.borrowRead();
    try std.testing.expectEqual(a.slot, b.slot);
    try std.testing.expectError(error.InvalidLease, copied.finish());
    try std.testing.expectError(error.InvalidLease, iter.next());
    try std.testing.expectEqualStrings("value", (try b.get(.props, "key")).?);
    try b.finish();
    const x = try owner.tryAcquireExclusive();
    const xc = x;
    const c = try x.catalog();
    const cc = c;
    try std.testing.expectError(error.LeaseChildren, xc.finish());
    try std.testing.expectError(error.Busy, owner.borrowRead());
    try c.finish();
    const c2 = try x.catalog();
    try std.testing.expectEqual(c.slot, c2.slot);
    try std.testing.expectError(error.InvalidLease, cc.finish());
    try c2.finish();
    try x.finish();
    const x2 = try owner.tryAcquireExclusive();
    try std.testing.expectError(error.InvalidLease, xc.finish());
    try x2.finish();
    ownerBacking(owner).next_serial = std.math.maxInt(u64) - 1;
    const last = try owner.borrowRead();
    try std.testing.expectError(error.IdentityExhausted, last.iterate(.props));
    try std.testing.expectEqualStrings("value", (try last.get(.props, "key")).?);
    try last.finish();
    try std.testing.expectError(error.IdentityExhausted, owner.borrowRead());
    try std.testing.expectError(error.IdentityExhausted, owner.tryAcquireExclusive());
}

test "STORE source owner actual ordinary candidates and staged promotion custody preserved" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const s = &ownerBacking(owner).store;
    var put = try s.preparePut(.props, "key", "one");
    try std.testing.expectError(error.SourceCustodyActive, owner.tryAcquireExclusive());
    try std.testing.expect(s.active_prepared != null);
    try std.testing.expectError(error.SourceCustodyActive, destroyStoreResourceOwner(owner));
    put.abort();
    const x = try owner.tryAcquireExclusive();
    try x.finish();
    var batch = try s.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "key", .value = "two" }});
    try std.testing.expectError(error.SourceCustodyActive, owner.tryAcquireExclusive());
    try std.testing.expect(s.active_batch != null);
    try std.testing.expectError(error.SourceCustodyActive, destroyStoreResourceOwner(owner));
    try batch.commit();
    const y = try owner.tryAcquireExclusive();
    try y.finish();
    const readonly = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", .{}, true);
    defer destroyStoreResourceOwner(readonly) catch unreachable;
    try std.testing.expectError(error.SourceCustodyActive, readonly.tryAcquireExclusive());
    try ownerBacking(readonly).store.preparePromotion();
    try std.testing.expectError(error.SourceCustodyActive, readonly.tryAcquireExclusive());
    try std.testing.expect(ownerBacking(readonly).store.staged_write_file != null);
    try std.testing.expectError(error.SourceCustodyActive, destroyStoreResourceOwner(readonly));
    try ownerBacking(readonly).store.releaseReadHandleForPreparedPromotion();
    ownerBacking(readonly).store.promotePrepared();
    const z = try readonly.tryAcquireExclusive();
    try z.finish();
}

test "STORE source owner fresh lifetime same backing address rejects stale and cross source tokens" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [@sizeOf(StoreOwnerBacking) + @alignOf(StoreOwnerBacking)]u8 align(@alignOf(StoreOwnerBacking)) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    const first = try createStoreResourceOwner(fixed.allocator(), std.testing.allocator, std.testing.io, tmp.dir, "reuse.wal", .{}, false);
    const old = try first.borrowRead();
    try old.finish();
    const ptr = @intFromPtr(first);
    try destroyStoreResourceOwner(first);
    fixed.reset();
    const next = try createStoreResourceOwner(fixed.allocator(), std.testing.allocator, std.testing.io, tmp.dir, "reuse.wal", .{}, false);
    defer destroyStoreResourceOwner(next) catch unreachable;
    try std.testing.expectEqual(ptr, @intFromPtr(next));
    const current = try next.borrowRead();
    try std.testing.expect(current.lifetime != old.lifetime);
    try std.testing.expectError(error.InvalidLease, old.finish());
    const foreign = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "foreign.wal", .{}, false);
    defer destroyStoreResourceOwner(foreign) catch unreachable;
    var wrong = current;
    wrong.owner = foreign;
    try std.testing.expectError(error.InvalidLease, wrong.finish());
    try current.finish();
    var counter: std.atomic.Value(u64) = .init(std.math.maxInt(u64) - 1);
    try std.testing.expectEqual(std.math.maxInt(u64) - 1, try reserveStoreLifetime(&counter));
    try std.testing.expectError(error.IdentityExhausted, reserveStoreLifetime(&counter));
}

pub fn storeOwnerAllocationScenario(a: std.mem.Allocator) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Factory effects scoped separately; this existing readonly cut does no disk
    // maintenance on allocation failure, and preserves all actual original rows.
    {
        var store = try openTestStore(tmp, "owner-oom.wal");
        defer store.deinit();
        try store.put(.props, "old", "intact");
    }
    const before = try readWalForTest(tmp, "owner-oom.wal");
    defer std.testing.allocator.free(before);
    defer {
        const after = readWalForTest(tmp, "owner-oom.wal") catch unreachable;
        defer std.testing.allocator.free(after);
        std.testing.expectEqualSlices(u8, before, after) catch unreachable;
    }
    const owner = try createStoreResourceOwner(a, a, std.testing.io, tmp.dir, "owner-oom.wal", .{}, true);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const r = try owner.borrowRead();
    try std.testing.expectEqualStrings("intact", (try r.get(.props, "old")).?);
    try r.finish();
}

test "STORE source owner exhaustive constructor OOM original ownership and retry" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, storeOwnerAllocationScenario, .{});
}

pub const StoreOwnerThreadRace = struct {
    owner: *StoreResourceOwner,
    phase: std.atomic.Value(u32) = .init(0),
    cancel: std.atomic.Value(bool) = .init(false),
    failures: std.atomic.Value(u32) = .init(0),
    fn wait(self: *StoreOwnerThreadRace, expected: u32) !void {
        const deadline = std.Io.Clock.awake.now(std.testing.io).nanoseconds + 10 * std.time.ns_per_s;
        while (self.phase.load(.acquire) != expected) {
            if (self.cancel.load(.acquire)) return error.ThreadCancelled;
            if (std.Io.Clock.awake.now(std.testing.io).nanoseconds >= deadline) return error.ThreadDeadline;
            std.atomic.spinLoopHint();
        }
    }
    fn reader(self: *StoreOwnerThreadRace) void {
        var held: ?ReadLease = self.owner.borrowRead() catch blk: {
            _ = self.failures.fetchAdd(1, .monotonic);
            break :blk null;
        };
        defer if (held) |r| r.finish() catch {
            _ = self.failures.fetchAdd(1, .monotonic);
        };
        self.phase.store(1, .release);
        self.wait(2) catch return;
        if (held) |r| {
            r.finish() catch {
                _ = self.failures.fetchAdd(1, .monotonic);
            };
            held = null;
        }
        self.phase.store(3, .release);
        self.wait(4) catch return;
        if (self.owner.borrowRead()) |unexpected| {
            _ = self.failures.fetchAdd(1, .monotonic);
            unexpected.finish() catch {
                _ = self.failures.fetchAdd(1, .monotonic);
            };
        } else |err| {
            if (err != error.Busy) _ = self.failures.fetchAdd(1, .monotonic);
        }
        self.phase.store(5, .release);
    }
};

pub fn storeOwnerThreadScenario(initial_refusal: bool, exclusive_refusal: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "threads.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const initial = if (initial_refusal) try owner.tryAcquireExclusive() else null;
    defer if (initial) |x| x.finish() catch unreachable;
    var race: StoreOwnerThreadRace = .{ .owner = owner };
    const thread = try std.Thread.spawn(.{}, StoreOwnerThreadRace.reader, .{&race});
    // Every test exit releases the worker from any handshake and joins BEFORE
    // source destruction. Monotonic deadline reports fixture failure only.
    defer {
        race.cancel.store(true, .release);
        thread.join();
    }
    try race.wait(1);
    const rejected = owner.tryAcquireExclusive();
    race.phase.store(2, .release);
    try race.wait(3);
    const obstructing_read = if (exclusive_refusal) try owner.borrowRead() else null;
    defer if (obstructing_read) |r| r.finish() catch unreachable;
    const accepted = owner.tryAcquireExclusive();
    defer if (accepted) |x| x.finish() catch unreachable else |_| {};
    race.phase.store(4, .release);
    try race.wait(5);
    if (race.failures.load(.acquire) != 0) return error.ThreadScenarioFailure;
    if (accepted) |_| {} else |_| return error.ThreadScenarioFailure;
    try std.testing.expectError(error.Busy, rejected);
}

test "STORE source owner synchronized real read exclusion admission across two threads" {
    try storeOwnerThreadScenario(false, false);
    try std.testing.expectError(error.ThreadScenarioFailure, storeOwnerThreadScenario(true, false));
    try std.testing.expectError(error.ThreadScenarioFailure, storeOwnerThreadScenario(false, true));
}

test "STORE source owner bounded read child slots and last exclusive cleanup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "slots.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    var reads: [16]ReadLease = undefined;
    for (&reads) |*r| r.* = try owner.borrowRead();
    try std.testing.expectError(error.Capacity, owner.borrowRead());
    var iters: [16]ReadIterator = undefined;
    for (&iters) |*it| it.* = try reads[0].iterate(.accounts);
    try std.testing.expectError(error.Capacity, reads[0].iterate(.props));
    try std.testing.expectError(error.LeaseChildren, reads[0].finish());
    for (iters) |it| try it.finish();
    for (reads) |r| try r.finish();
    ownerBacking(owner).next_serial = std.math.maxInt(u64) - 2;
    const x = try owner.tryAcquireExclusive();
    const c = try x.catalog();
    try std.testing.expectError(error.IdentityExhausted, x.catalog());
    try std.testing.expectError(error.LeaseChildren, x.finish());
    try std.testing.expect((try c.next()) != null);
    try c.finish();
    try x.finish();
}

test "STORE source owner exhausted factory refuses backend IO and observes actual cwd sentinel" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var observer: StoreOwnerObserver = .{};
    var counter: std.atomic.Value(u64) = .init(std.math.maxInt(u64));
    try std.testing.expectError(error.IdentityExhausted, createStoreResourceOwnerWithCounter(observer.allocator(), observer.allocator(), std.testing.io, tmp.dir, "not-created.wal", .{}, false, &counter));
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "not-created.wal", .{}));
    const absolute = try coldFixtureAbsoluteDirectory(&tmp, ".");
    defer std.testing.allocator.free(absolute);
    const path = try std.fs.path.join(std.testing.allocator, &.{ absolute, "cwd-owner.wal" });
    defer std.testing.allocator.free(path);
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, .cwd(), path, .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const x = try owner.tryAcquireExclusive();
    try std.testing.expectEqual(std.Io.Dir.cwd().handle, (try x.sourceState()).borrowed_directory);
    try x.finish();
}

pub const StoreOwnerFinishRace = struct {
    token: union(enum) { read: ReadLease, exclusive: StoreExclusive },
    ready: std.atomic.Value(u32) = .init(0),
    start: std.atomic.Value(bool) = .init(false),
    cancel: std.atomic.Value(bool) = .init(false),
    success: std.atomic.Value(u32) = .init(0),
    refused: std.atomic.Value(u32) = .init(0),
    other: std.atomic.Value(u32) = .init(0),
    fn worker(self: *StoreOwnerFinishRace) void {
        _ = self.ready.fetchAdd(1, .release);
        const deadline = std.Io.Clock.awake.now(std.testing.io).nanoseconds + 10 * std.time.ns_per_s;
        while (!self.start.load(.acquire)) {
            if (self.cancel.load(.acquire)) return;
            if (std.Io.Clock.awake.now(std.testing.io).nanoseconds >= deadline) {
                _ = self.other.fetchAdd(1, .monotonic);
                return;
            }
            std.atomic.spinLoopHint();
        }
        const result = switch (self.token) {
            .read => |r| r.finish(),
            .exclusive => |x| x.finish(),
        };
        if (result) |_| {
            _ = self.success.fetchAdd(1, .monotonic);
        } else |err| {
            if (err == error.InvalidLease) _ = self.refused.fetchAdd(1, .monotonic) else _ = self.other.fetchAdd(1, .monotonic);
        }
    }
};

test "STORE source owner concurrent double finish one winner then fresh slot cannot be cleared" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "double.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    for ([_]bool{ false, true }) |exclusive| {
        var race: StoreOwnerFinishRace = .{ .token = if (exclusive) .{ .exclusive = try owner.tryAcquireExclusive() } else .{ .read = try owner.borrowRead() } };
        var threads: [2]std.Thread = undefined;
        var spawned: usize = 0;
        defer {
            race.cancel.store(true, .release);
            for (threads[0..spawned]) |t| t.join();
            // If a fixture deadline/creation failure occurred, end the original
            // source ticket explicitly; stale finish is harmless after a winner.
            switch (race.token) {
                .read => |r| r.finish() catch {},
                .exclusive => |x| x.finish() catch {},
            }
        }
        for (&threads) |*t| {
            t.* = try std.Thread.spawn(.{}, StoreOwnerFinishRace.worker, .{&race});
            spawned += 1;
        }
        const deadline = std.Io.Clock.awake.now(std.testing.io).nanoseconds + 10 * std.time.ns_per_s;
        while (race.ready.load(.acquire) != 2) {
            if (std.Io.Clock.awake.now(std.testing.io).nanoseconds >= deadline) return error.ThreadDeadline;
            std.atomic.spinLoopHint();
        }
        race.start.store(true, .release);
        for (threads) |t| t.join();
        spawned = 0;
        try std.testing.expectEqual(@as(u32, 1), race.success.load(.acquire));
        try std.testing.expectEqual(@as(u32, 1), race.refused.load(.acquire));
        try std.testing.expectEqual(@as(u32, 0), race.other.load(.acquire));
        if (exclusive) {
            const fresh = try owner.tryAcquireExclusive();
            try std.testing.expectError(error.InvalidLease, race.token.exclusive.finish());
            try std.testing.expectError(error.Busy, owner.borrowRead());
            try fresh.finish();
        } else {
            const fresh = try owner.borrowRead();
            try std.testing.expectError(error.InvalidLease, race.token.read.finish());
            try std.testing.expectError(error.Busy, owner.tryAcquireExclusive());
            try fresh.finish();
        }
    }
}

test "STORE source owner independent metadata payload OOM observers retry with unchanged WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "domains.wal");
        defer seed.deinit();
        try seed.put(.props, "old", "complete");
    }
    const before = try readWalForTest(tmp, "domains.wal");
    defer std.testing.allocator.free(before);
    for ([_]bool{ false, true }) |metadata_fail| {
        var indices: usize = 0;
        while (true) : (indices += 1) {
            var meta: StoreOwnerObserver = .{};
            var payload: StoreOwnerObserver = .{};
            if (metadata_fail) meta.fail_at = indices else payload.fail_at = indices;
            const result = createStoreResourceOwner(meta.allocator(), payload.allocator(), std.testing.io, tmp.dir, "domains.wal", .{}, true);
            if (result) |owner| {
                try destroyStoreResourceOwner(owner);
                try meta.checkAll(false);
                try payload.checkAll(false);
                break;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try meta.checkAll(false);
                try payload.checkAll(false);
                meta.fail_at = std.math.maxInt(usize);
                payload.fail_at = std.math.maxInt(usize);
                const retry = try createStoreResourceOwner(meta.allocator(), payload.allocator(), std.testing.io, tmp.dir, "domains.wal", .{}, true);
                const r = try retry.borrowRead();
                try std.testing.expectEqualStrings("complete", (try r.get(.props, "old")).?);
                try r.finish();
                try destroyStoreResourceOwner(retry);
                try meta.checkAll(false);
                try payload.checkAll(false);
            }
            const after = try readWalForTest(tmp, "domains.wal");
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
        }
        std.debug.print("StoreOwner constructor metadata_domain={any} exhaustive_allocation_indices={d}\n", .{ metadata_fail, indices });
        try std.testing.expect(indices != 0);
    }
}
