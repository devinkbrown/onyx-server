// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: table.

const std = @import("std");
const OwnedMutation = @import("changefeed.zig").OwnedMutation;
const BatchMutation = @import("contracts.zig").BatchMutation;
const Family = @import("contracts.zig").Family;
const StoreError = @import("contracts.zig").StoreError;
const familyIndex = @import("contracts.zig").familyIndex;
const max_batch_mutations = @import("contracts.zig").max_batch_mutations;
const OroStore = @import("engine.zig").OroStore;
const PreparedBatch = @import("engine.zig").PreparedBatch;
const PreparedPut = @import("engine.zig").PreparedPut;
const KvTable = @import("table.zig").KvTable;
const openTestStore = @import("tests_support.zig").openTestStore;
const readWalForTest = @import("tests_support.zig").readWalForTest;

test "STORE KvTable causal prepare growth OOM preserves OLD backing and capacity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize), .resize_fail_index = 0 });
    var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "kvtable-growth-causal.wal");
    defer store.deinit();
    const map = &store.maps[0].map;
    try map.ensureUnusedCapacity(1);
    var index: usize = 0;
    while (index < 6) : (index += 1) {
        var buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&buf, "old-{d}", .{index});
        try store.put(.accounts, key, "unchanged");
    }
    const old_capacity = map.capacity();
    const old_backing = map.slots.ptr;
    const old_wal = store.wal_offset;
    const old_seq = store.next_seq;
    const old_feed = store.changeCount();
    failing.fail_index = failing.alloc_index + 1;
    try std.testing.expectError(error.OutOfMemory, store.preparePut(.accounts, "new-key", "candidate"));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(@as(u32, 6), map.count());
    try std.testing.expect(store.get(.accounts, "new-key") == null);
    index = 0;
    while (index < 6) : (index += 1) {
        var buf: [32]u8 = undefined;
        try std.testing.expectEqualStrings("unchanged", store.get(.accounts, try std.fmt.bufPrint(&buf, "old-{d}", .{index})).?);
    }
    try std.testing.expectEqual(old_wal, store.wal_offset);
    try std.testing.expectEqual(old_seq, store.next_seq);
    try std.testing.expectEqual(old_feed, store.changeCount());
    std.debug.print("KvTable actual causal capacity before={d} after={d}; backing unchanged={}\n", .{ old_capacity, map.capacity(), old_backing == map.slots.ptr });
    try std.testing.expectEqual(old_capacity, map.capacity());
    try std.testing.expect(old_backing == map.slots.ptr);
}

pub fn tableTestPut(table: *KvTable, key: []const u8, value: []const u8) !void {
    const gop = try table.getOrPut(key);
    gop.key_ptr.* = key;
    gop.value_ptr.* = @constCast(value);
}

pub fn tableTestCollisions(storage: [][32]u8, keys: [][]const u8, bucket: usize) !void {
    var trial: usize = 0;
    var found: usize = 0;
    while (found < keys.len) : (trial += 1) {
        var buffer: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&buffer, "collision-{d}", .{trial});
        if (KvTable.keyHash(key) & 7 != bucket) continue;
        @memcpy(storage[found][0..key.len], key);
        keys[found] = storage[found][0..key.len];
        found += 1;
    }
}

test "STORE KvTable private wrap collision tombstone sparse FINAL preserves surviving OLD slots" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    var storage: [8][32]u8 = undefined;
    var keys: [8][]const u8 = undefined;
    try tableTestCollisions(&storage, &keys, 7);
    for (keys[0..4]) |key| try tableTestPut(&table, key, "OLD");
    const backing = table.slots.ptr;
    const survivor = table.getEntry(keys[2]).?.key_ptr;
    var plan = try table.prepare(&.{ .{ .key = keys[0], .value = null }, .{ .key = keys[3], .value = @constCast("new") }, .{ .key = keys[4], .value = @constCast("added") }, .{ .key = keys[5], .value = @constCast("last") } }, std.math.maxInt(u64));
    defer plan.abort();
    try std.testing.expect(plan.replacement == null);
    try std.testing.expect(plan.patch_count <= 4);
    try std.testing.expectEqualStrings("OLD", table.get(keys[0]).?);
    try plan.validate();
    try std.testing.expect(plan.publish() == null);
    try std.testing.expect(table.slots.ptr == backing);
    try std.testing.expect(table.getEntry(keys[2]).?.key_ptr == survivor);
    try std.testing.expect(table.get(keys[0]) == null);
    try std.testing.expectEqualStrings("added", table.get(keys[4]).?);
    try std.testing.expectEqualStrings("new", table.get(keys[3]).?);
    try std.testing.expectEqual(@as(u32, 5), table.count());
    try std.testing.expectError(StoreError.InvalidTablePlan, plan.validate());
}

test "STORE KvTable private repeated key retains OLD slot and final fit avoids transient growth" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f" };
    for (keys) |key| try tableTestPut(&table, key, "OLD");
    const old_slot = table.getEntry("a").?.key_ptr;
    var plan = try table.prepare(&.{ .{ .key = "a", .value = null }, .{ .key = "temporary", .value = @constCast("scratch") }, .{ .key = "a", .value = @constCast("FINAL") }, .{ .key = "temporary", .value = null }, .{ .key = "b", .value = @constCast("second") } }, std.math.maxInt(u64));
    defer plan.abort();
    try std.testing.expect(plan.replacement == null);
    try std.testing.expectEqual(@as(u32, 6), plan.final_count);
    try plan.validate();
    try std.testing.expect(plan.publish() == null);
    try std.testing.expect(table.getEntry("a").?.key_ptr == old_slot);
    try std.testing.expectEqualStrings("FINAL", table.get("a").?);
    try std.testing.expect(table.get("temporary") == null);
    try std.testing.expectEqual(@as(u32, 8), table.capacity());
}

test "STORE KvTable private detached growth and pressure rebuild abort exact OLD then retry" {
    for ([_]bool{ false, true }) |pressure| {
        var table = KvTable.init(std.testing.allocator);
        defer table.deinit();
        const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f" };
        for (keys) |key| try tableTestPut(&table, key, "OLD");
        if (pressure) for (keys[0..5]) |key| {
            _ = table.remove(key);
        };
        const old = try std.testing.allocator.dupe(KvTable.Slot, table.slots);
        defer std.testing.allocator.free(old);
        const ptr = table.slots.ptr;
        const edits = [_]KvTable.Edit{ .{ .key = "g", .value = @constCast("NEW") }, .{ .key = "h", .value = @constCast("NEW2") } };
        var plan = try table.prepare(&edits, std.math.maxInt(u64));
        try std.testing.expect(plan.replacement != null);
        try std.testing.expectEqual(@as(usize, if (pressure) 8 else 16), plan.replacement.?.len);
        plan.abort();
        try std.testing.expect(table.slots.ptr == ptr);
        for (old, table.slots) |before, after| try std.testing.expect(KvTable.slotSame(before, after));
        var retry = try table.prepare(&edits, std.math.maxInt(u64));
        defer retry.abort();
        try retry.validate();
        const retired = retry.publish().?;
        try std.testing.expect(retired.ptr == ptr);
        table.allocator.free(retired); // source-owned caller's declared finish
        try std.testing.expectEqualStrings("NEW", table.get("g").?);
        try std.testing.expectEqualStrings("OLD", table.get("f").?);
        try std.testing.expect(retry.work.probes > 0 and retry.work.rows > 0 and retry.work.rebuilt_bytes > 0);
    }
}

test "STORE KvTable private stale wrong index key value scalar and detached tamper refuse" {
    for (0..7) |kind| {
        var table = KvTable.init(std.testing.allocator);
        defer table.deinit();
        try tableTestPut(&table, "a", "OLD");
        var value = [_]u8{'X'};
        var plan = try table.prepare(&.{.{ .key = "a", .value = &value }}, std.math.maxInt(u64));
        defer plan.abort();
        switch (kind) {
            0 => plan.patches[0].index = (plan.patches[0].index + 1) % table.capacity(),
            1 => plan.final_count += 1,
            2 => value[0] = 'Y',
            3 => plan.expected_revision += 1,
            4 => plan.patches[0].after.key = "other",
            5 => {
                try tableTestPut(&table, "b", "foreign");
            },
            6 => plan.patch_count = KvTable.max_edits + 1,
            else => unreachable,
        }
        try std.testing.expectError(StoreError.InvalidTablePlan, plan.validate());
        try std.testing.expectEqualStrings("OLD", table.get("a").?);
    }
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    var edits: [8]KvTable.Edit = undefined;
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h" };
    for (keys, 0..) |key, i| edits[i] = .{ .key = key, .value = @constCast("NEW") };
    var plan = try table.prepare(&edits, std.math.maxInt(u64));
    defer plan.abort();
    for (plan.replacement.?) |*slot| if (slot.state == .used) {
        slot.hash ^= 1;
        break;
    };
    try std.testing.expectError(StoreError.InvalidTablePlan, plan.validate());
    try std.testing.expectEqual(@as(u32, 0), table.count());
}

test "STORE KvTable private work overflow malformed load and revision exhaustion are bounded" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    try tableTestPut(&table, "a", "OLD");
    const ptr = table.slots.ptr;
    try std.testing.expectError(StoreError.TableWorkExceeded, table.prepare(&.{.{ .key = "b", .value = @constCast("new") }}, 0));
    var work: KvTable.Work = .{ .total = std.math.maxInt(u64) };
    try std.testing.expectError(StoreError.TableWorkExceeded, work.charge(&work.rows, 1));
    table.tombstones = table.capacity();
    try std.testing.expectError(StoreError.InvalidTablePlan, table.prepare(&.{.{ .key = "b", .value = null }}, std.math.maxInt(u64)));
    table.tombstones = 0;
    table.revision = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, table.prepare(&.{.{ .key = "b", .value = null }}, std.math.maxInt(u64)));
    try std.testing.expect(table.slots.ptr == ptr);
    try std.testing.expectEqualStrings("OLD", table.get("a").?);
}

pub fn tablePreparedOomScenario(allocator: std.mem.Allocator) !void {
    var table = KvTable.init(allocator);
    defer table.deinit();
    for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
    const ptr = table.slots.ptr;
    var plan = table.prepare(&.{.{ .key = "g", .value = @constCast("NEW") }}, std.math.maxInt(u64)) catch |err| {
        try std.testing.expect(table.slots.ptr == ptr);
        try std.testing.expectEqual(@as(u32, 8), table.capacity());
        try std.testing.expectEqualStrings("OLD", table.get("a").?);
        return err;
    };
    defer plan.abort();
    try plan.validate();
    if (plan.publish()) |retired| allocator.free(retired);
    try std.testing.expectEqualStrings("NEW", table.get("g").?);
}

test "STORE KvTable private exhaustive OOM rollback and actual armed publication" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, tablePreparedOomScenario, .{});
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var table = KvTable.init(failing.allocator());
    defer table.deinit();
    for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
    var plan = try table.prepare(&.{.{ .key = "g", .value = @constCast("NEW") }}, std.math.maxInt(u64));
    defer plan.abort();
    try plan.validate();
    const allocs = failing.alloc_index;
    const frees = failing.deallocations;
    failing.fail_index = allocs;
    const retired = plan.publish().?;
    try std.testing.expectEqual(allocs, failing.alloc_index);
    try std.testing.expectEqual(frees, failing.deallocations);
    failing.allocator().free(retired);
    try std.testing.expectEqualStrings("NEW", table.get("g").?);
}

test "STORE KvTable ordinary deterministic differential lookup delete iterator and tombstone reuse" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    var reference = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer reference.deinit();
    var storage: [128][32]u8 = undefined;
    var keys: [128][]const u8 = undefined;
    for (&storage, 0..) |*buffer, i| keys[i] = try std.fmt.bufPrint(buffer, "key-{d}", .{i});
    const values = [_][]const u8{ "one", "two", "three", "four" };
    var random = std.Random.DefaultPrng.init(0x5a179eb22);
    for (0..4000) |_| {
        const index = random.random().uintLessThan(usize, keys.len);
        if (random.random().boolean()) {
            const value = values[random.random().uintLessThan(usize, values.len)];
            try tableTestPut(&table, keys[index], value);
            try reference.put(keys[index], value);
        } else try std.testing.expectEqual(reference.remove(keys[index]), table.remove(keys[index]));
        try std.testing.expectEqual(reference.count(), table.count());
        var seen: usize = 0;
        var iterator = table.iterator();
        while (iterator.next()) |entry| {
            seen += 1;
            try std.testing.expectEqualStrings(reference.get(entry.key_ptr.*).?, entry.value_ptr.*);
        }
        try std.testing.expectEqual(@as(usize, table.count()), seen);
        for (keys) |key| {
            if (reference.get(key)) |value| try std.testing.expectEqualStrings(value, table.get(key).?) else try std.testing.expect(table.get(key) == null);
        }
    }
}

test "STORE KvTable private 5001 population sparse preparation has no full table census" {
    const storage = try std.testing.allocator.alloc([32]u8, 5001);
    defer std.testing.allocator.free(storage);
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    for (storage, 0..) |*buffer, i| try tableTestPut(&table, try std.fmt.bufPrint(buffer, "population-{d}", .{i}), "OLD");
    var target: [32]u8 = undefined;
    var plan = try table.prepare(&.{.{ .key = try std.fmt.bufPrint(&target, "population-{d}", .{2500}), .value = @constCast("FINAL") }}, std.math.maxInt(u64));
    defer plan.abort();
    try std.testing.expect(plan.replacement == null);
    try std.testing.expectEqual(@as(u64, 0), plan.work.rows);
    try std.testing.expectEqual(@as(u64, 0), plan.work.rebuilt_bytes);
    try std.testing.expect(plan.work.probes <= table.capacity());
    try plan.validate();
    try std.testing.expect(plan.publish() == null);
    try std.testing.expectEqualStrings("FINAL", table.get("population-2500").?);
    std.debug.print("KvTable5001 slot_bytes={d} backing_bytes={d} prepare probes={d} comparisons={d} rows={d} bytes={d}\n", .{ @sizeOf(KvTable.Slot), table.slots.len * @sizeOf(KvTable.Slot), plan.work.probes, plan.work.comparisons, plan.work.rows, plan.work.bytes });
}

test "STORE KvTable prepared batch all allocation failures preserve exact OLD tables and retry" {
    var fail_offset: usize = 0;
    while (fail_offset < 100) : (fail_offset += 1) {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize), .resize_fail_index = 0 });
        var store = try OroStore.openWithConfig(failing.allocator(), std.testing.io, tmp.dir, "table-batch-oom.wal", .{ .changefeed_capacity = 1 });
        defer store.deinit();
        const affected_families = [_]Family{ .accounts, .nicks, .props, .vhosts };
        for (affected_families) |family| for (0..6) |i| {
            var buffer: [32]u8 = undefined;
            try store.put(family, try std.fmt.bufPrint(&buffer, "OLD-{d}", .{i}), "OLD-value");
        };
        var copies: [4][]KvTable.Slot = undefined;
        var pointers: [4][*]KvTable.Slot = undefined;
        var revisions: [4]u64 = undefined;
        for (affected_families, 0..) |family, i| {
            const table = &store.maps[familyIndex(family)].map;
            copies[i] = try std.testing.allocator.dupe(KvTable.Slot, table.slots);
            pointers[i] = table.slots.ptr;
            revisions[i] = table.revision;
        }
        defer for (copies) |copy| std.testing.allocator.free(copy);
        const old_wal = try readWalForTest(tmp, "table-batch-oom.wal");
        defer std.testing.allocator.free(old_wal);
        const old_offset = store.wal_offset;
        const old_seq = store.next_seq;
        const old_change = store.changeAt(0).?;
        var edits: [4]BatchMutation = undefined;
        for (affected_families, 0..) |family, i| edits[i] = .{ .family = family, .kind = .put, .key = "NEW", .value = "candidate" };
        failing.fail_index = failing.alloc_index + fail_offset;
        if (store.prepareBatch(&edits)) |value| {
            var prepared = value;
            defer prepared.abort();
            const allocations = failing.alloc_index;
            const deallocations = failing.deallocations;
            failing.fail_index = allocations;
            try prepared.commit();
            try std.testing.expectEqual(allocations, failing.alloc_index);
            try std.testing.expectEqual(deallocations, failing.deallocations);
            for (affected_families) |family| try std.testing.expectEqualStrings("candidate", store.get(family, "NEW").?);
            try std.testing.expectEqual(old_seq + 4, store.next_seq);
            std.debug.print("KvTable batch exhaustive candidate allocation indices={d}\n", .{fail_offset});
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expect(store.active_batch == null);
            for (affected_families, 0..) |family, i| {
                const table = &store.maps[familyIndex(family)].map;
                try std.testing.expect(table.slots.ptr == pointers[i]);
                try std.testing.expectEqual(revisions[i], table.revision);
                try std.testing.expectEqual(@as(u32, 8), table.capacity());
                try std.testing.expectEqual(@as(u32, 6), table.count());
                for (copies[i], table.slots) |before, after| try std.testing.expect(KvTable.slotSame(before, after));
                try std.testing.expect(store.get(family, "NEW") == null);
                try std.testing.expectEqualStrings("OLD-value", store.get(family, "OLD-3").?);
            }
            try std.testing.expectEqual(old_offset, store.wal_offset);
            try std.testing.expectEqual(old_seq, store.next_seq);
            try std.testing.expectEqualStrings(old_change.key, store.changeAt(0).?.key);
            try std.testing.expectEqualStrings(old_change.value.?, store.changeAt(0).?.value.?);
            const after_wal = try readWalForTest(tmp, "table-batch-oom.wal");
            defer std.testing.allocator.free(after_wal);
            try std.testing.expectEqualSlices(u8, old_wal, after_wal);
            var retry = try store.prepareBatch(&edits);
            defer retry.abort();
            try retry.commit();
            for (affected_families) |family| try std.testing.expectEqualStrings("candidate", store.get(family, "NEW").?);
        }
    }
    return error.TestUnexpectedResult;
}

test "STORE KvTable private repeated validation consumes original finite allowance including rebuild" {
    for ([_]bool{ false, true }) |grow| {
        var table = KvTable.init(std.testing.allocator);
        defer table.deinit();
        for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
        const edits = [_]KvTable.Edit{.{ .key = if (grow) "g" else "a", .value = @constCast("candidate") }};
        var measured = try table.prepare(&edits, std.math.maxInt(u64));
        const prepared_work = measured.work.total;
        try measured.validate();
        const validate_work = measured.work.total - prepared_work;
        try std.testing.expect(validate_work > 0);
        if (grow) try std.testing.expect(measured.work.rows >= table.capacity());
        measured.abort();
        var bounded = try table.prepare(&edits, prepared_work + validate_work);
        defer bounded.abort();
        try bounded.validate();
        try std.testing.expectEqual(bounded.work.limit, bounded.work.total);
        try std.testing.expectError(StoreError.TableWorkExceeded, bounded.validate());
        try std.testing.expectEqual(@as(u32, 6), table.count());
        try std.testing.expectEqual(@as(u32, 8), table.capacity());
        try std.testing.expectEqualStrings("OLD", table.get("a").?);
    }
}

test "STORE KvTable prepared put and batch forged candidates refuse before WAL and normal retry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "forged-table.wal");
    defer store.deinit();
    try store.put(.props, "OLD", "value");
    const before = try readWalForTest(tmp, "forged-table.wal");
    defer std.testing.allocator.free(before);
    const seq = store.next_seq;
    var put = try store.preparePut(.props, "NEW", "candidate");
    defer put.abort();
    const original = store.active_prepared.?.value.?;
    store.active_prepared.?.value = original[0 .. original.len - 1];
    try std.testing.expectError(StoreError.InvalidTablePlan, put.commit());
    store.active_prepared.?.value = original;
    const put_plan = &store.active_prepared.?.table_plan.?;
    put_plan.seal[0] ^= 1;
    try std.testing.expectError(StoreError.InvalidTablePlan, put.commit());
    put_plan.seal[0] ^= 1;
    put.abort();
    var batch = try store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "NEW", .value = "candidate" }});
    defer batch.abort();
    const batch_key = store.active_batch.?.entries[0].key.?;
    store.active_batch.?.entries[0].key = batch_key[0 .. batch_key.len - 1];
    try std.testing.expectError(StoreError.InvalidTablePlan, batch.commit());
    store.active_batch.?.entries[0].key = batch_key;
    store.active_batch.?.entries[0].old_value = @constCast("forged-retirement");
    try std.testing.expectError(StoreError.InvalidTablePlan, batch.commit());
    store.active_batch.?.entries[0].old_value = null;
    const after = try readWalForTest(tmp, "forged-table.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expect(!store.preparedWritesPoisoned());
    try std.testing.expect(store.get(.props, "NEW") == null);
    try batch.commit();
    try std.testing.expectEqualStrings("candidate", store.get(.props, "NEW").?);
}

test "STORE KvTable ordinary revision exhaustion refuses mutation before WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "revision-table.wal");
    defer store.deinit();
    try store.put(.props, "OLD", "value");
    const table = &store.maps[familyIndex(.props)].map;
    const revision = table.revision;
    table.revision = std.math.maxInt(u64);
    defer table.revision = revision;
    const before = try readWalForTest(tmp, "revision-table.wal");
    defer std.testing.allocator.free(before);
    try std.testing.expectError(StoreError.SequenceExhausted, store.put(.props, "NEW", "value"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.delete(.props, "OLD"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.preparePut(.props, "NEW", "value"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&.{.{ .family = .props, .kind = .delete, .key = "OLD" }}));
    const after = try readWalForTest(tmp, "revision-table.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualStrings("value", store.get(.props, "OLD").?);
    try std.testing.expect(store.get(.props, "NEW") == null);
}

pub fn tableLocatorCustodyScenario(batch_mode: bool, key_mode: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "locator-custody.wal");
    defer store.deinit();
    for (0..6) |i| {
        var buffer: [16]u8 = undefined;
        try store.put(.props, try std.fmt.bufPrint(&buffer, "old-{d}", .{i}), "OLD");
    }
    const before = try readWalForTest(tmp, "locator-custody.wal");
    defer std.testing.allocator.free(before);
    var put: PreparedPut = undefined;
    var batch: PreparedBatch = undefined;
    if (batch_mode) batch = try store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "NEW", .value = "candidate" }}) else put = try store.preparePut(.props, "NEW", "candidate");
    defer if (batch_mode) batch.abort() else put.abort();
    const plan = if (batch_mode) &store.active_batch.?.table_plans[familyIndex(.props)].? else &store.active_prepared.?.table_plan.?;
    var candidate: *KvTable.Slot = undefined;
    for (plan.replacement.?) |*slot| if (slot.state == .used and std.mem.eql(u8, slot.key, "NEW")) {
        candidate = slot;
        break;
    };
    const original: []const u8 = if (key_mode) candidate.key else candidate.value;
    const twin = try std.testing.allocator.dupe(u8, original);
    var transferred = false;
    defer if (!transferred) std.testing.allocator.free(twin);
    if (key_mode) candidate.key = twin else candidate.value = twin;
    const result = if (batch_mode) batch.commit() else put.commit();
    if (result) |_| {
        // OLD control really adopted the twin. Explicitly release the now-lost
        // original; Store.deinit owns the adopted twin, not the test's defer.
        transferred = true;
        std.testing.allocator.free(original);
        std.debug.print("KvTable locator causal batch={any}: equal-byte foreign pointer adopted across WAL\n", .{batch_mode});
        return error.TestUnexpectedResult;
    } else |err| {
        if (key_mode) candidate.key = original else candidate.value = @constCast(original);
        try std.testing.expectEqual(StoreError.InvalidTablePlan, err);
    }
    const after = try readWalForTest(tmp, "locator-custody.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expect(store.get(.props, "NEW") == null);
    if (batch_mode) try batch.commit() else try put.commit();
    try std.testing.expectEqualStrings("candidate", store.get(.props, "NEW").?);
}

test "STORE KvTable review causal put detached equal bytes foreign locator refuses before WAL" {
    try tableLocatorCustodyScenario(false, false);
}

test "STORE KvTable review causal batch detached equal bytes foreign locator refuses before WAL" {
    try tableLocatorCustodyScenario(true, false);
}

test "STORE KvTable review causal finite rebuild budget refuses before backend allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var table = KvTable.init(failing.allocator());
    defer table.deinit();
    for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
    const ptr = table.slots.ptr;
    const allocations = failing.alloc_index;
    try std.testing.expectError(StoreError.TableWorkExceeded, table.prepare(&.{.{ .key = "g", .value = @constCast("candidate") }}, 128));
    try std.testing.expect(table.slots.ptr == ptr);
    try std.testing.expectEqual(@as(u32, 6), table.count());
    try std.testing.expectEqualStrings("OLD", table.get("a").?);
    std.debug.print("KvTable budget causal beforealloc={d} afteralloc={d}\n", .{ allocations, failing.alloc_index });
    try std.testing.expectEqual(allocations, failing.alloc_index);
    var retry = try table.prepare(&.{.{ .key = "g", .value = @constCast("candidate") }}, std.math.maxInt(u64));
    defer retry.abort();
    try retry.validate();
}

pub fn tablePreparedRevisionBoundary(batch_mode: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "revision-boundary.wal", .{ .max_wal_bytes = 2000, .changefeed_capacity = 0 });
    defer store.deinit();
    const large: [850]u8 = @splat(42);
    const candidate: [200]u8 = @splat(17);
    try store.put(.props, "OLD", &large);
    const table = &store.maps[familyIndex(.props)].map;
    const old_revision = table.revision;
    table.revision = std.math.maxInt(u64);
    defer table.revision = old_revision;
    const before = try readWalForTest(tmp, "revision-boundary.wal");
    defer std.testing.allocator.free(before);
    const epoch = store.wal_epoch;
    const offset = store.wal_offset;
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "revision-boundary.wal.snap", .{}));
    if (batch_mode) try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "NEW", .value = &candidate }})) else try std.testing.expectError(StoreError.SequenceExhausted, store.preparePut(.props, "NEW", &candidate));
    const after = try readWalForTest(tmp, "revision-boundary.wal");
    defer std.testing.allocator.free(after);
    std.debug.print("KvTable revision boundary batch={any}: WAL before={d} after={d}\n", .{ batch_mode, before.len, after.len });
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualDeep(epoch, store.wal_epoch);
    try std.testing.expectEqual(offset, store.wal_offset);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "revision-boundary.wal.snap", .{}));
}

test "STORE KvTable review causal prepared put revision exhaustion refuses before compaction" {
    try tablePreparedRevisionBoundary(false);
}

test "STORE KvTable review causal prepared batch revision exhaustion refuses before compaction" {
    try tablePreparedRevisionBoundary(true);
}

test "STORE KvTable detached put equal bytes foreign KEY locator refuses before WAL" {
    try tableLocatorCustodyScenario(false, true);
}

test "STORE KvTable detached batch equal bytes foreign KEY locator refuses before WAL" {
    try tableLocatorCustodyScenario(true, true);
}

test "STORE KvTable batch later affected family revision refuses before threshold maintenance" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "later-revision.wal", .{ .max_wal_bytes = 2000, .changefeed_capacity = 0 });
    defer store.deinit();
    const large: [850]u8 = @splat(42);
    const candidate: [200]u8 = @splat(17);
    try store.put(.props, "OLD", &large);
    try store.put(.accounts, "healthy", "OLD");
    const table = &store.maps[familyIndex(.props)].map;
    const old_revision = table.revision;
    table.revision = std.math.maxInt(u64);
    defer table.revision = old_revision;
    const before = try readWalForTest(tmp, "later-revision.wal");
    defer std.testing.allocator.free(before);
    const epoch = store.wal_epoch;
    const offset = store.wal_offset;
    const seq = store.next_seq;
    const mutations = [_]BatchMutation{
        .{ .family = .accounts, .kind = .put, .key = "NEW", .value = "healthy-candidate" },
        .{ .family = .props, .kind = .put, .key = "NEW", .value = &candidate },
    };
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "later-revision.wal.snap", .{}));
    try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&mutations));
    const after = try readWalForTest(tmp, "later-revision.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualDeep(epoch, store.wal_epoch);
    try std.testing.expectEqual(offset, store.wal_offset);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expect(store.active_batch == null);
    try std.testing.expect(store.get(.accounts, "NEW") == null);
    try std.testing.expect(store.get(.props, "NEW") == null);
    try std.testing.expectEqualStrings("OLD", store.get(.accounts, "healthy").?);
    try std.testing.expectEqualSlices(u8, &large, store.get(.props, "OLD").?);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "later-revision.wal.snap", .{}));
    table.revision = old_revision;
    var retry = try store.prepareBatch(&mutations);
    defer retry.abort();
    try retry.commit();
    try std.testing.expectEqualStrings("healthy-candidate", store.get(.accounts, "NEW").?);
    try std.testing.expectEqualSlices(u8, &candidate, store.get(.props, "NEW").?);
}

test "STORE KvTable selector causal changed PUT kind refuses before WAL and retirement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "selector-kind.wal", .{ .changefeed_capacity = 0 });
    defer store.deinit();
    try store.put(.props, "OLD", "old-value");
    const old_key = store.maps[familyIndex(.props)].map.getEntry("OLD").?.key_ptr.*;
    const before = try readWalForTest(tmp, "selector-kind.wal");
    defer std.testing.allocator.free(before);
    const seq = store.next_seq;
    var ticket = try store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "OLD", .value = "new-value" }});
    defer ticket.abort();
    store.active_batch.?.entries[0].kind = .delete;
    if (ticket.commit()) |_| {
        // The OLD control leaves this table-owned key wrongly scheduled for
        // reclamation. Remove only that retirement so the real accepted commit
        // can be observed without turning the fixture into a double-free.
        var removed: usize = 0;
        var i: usize = 0;
        while (i < store.retirement_count) {
            const is_live_key = switch (store.retirements[i].?) {
                .bytes => |bytes| bytes.ptr == old_key.ptr and bytes.len == old_key.len,
                else => false,
            };
            if (is_live_key) {
                removed += 1;
                store.retirement_count -= 1;
                store.retirements[i] = store.retirements[store.retirement_count];
                store.retirements[store.retirement_count] = null;
            } else i += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), removed);
        try std.testing.expectEqualStrings("new-value", store.get(.props, "OLD").?);
        try std.testing.expectEqual(seq + 1, store.next_seq);
        std.debug.print("KvTable selector causal: changed kind committed and scheduled one live OLD key for retirement\n", .{});
        return error.TestUnexpectedResult;
    } else |err| {
        store.active_batch.?.entries[0].kind = .put;
        try std.testing.expectEqual(StoreError.InvalidTablePlan, err);
    }
    const after = try readWalForTest(tmp, "selector-kind.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expectEqualStrings("old-value", store.get(.props, "OLD").?);
    try ticket.commit();
    try std.testing.expectEqualStrings("new-value", store.get(.props, "OLD").?);
}

test "STORE KvTable selector causal omitted entries refuses before WAL and feed ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "selector-count.wal", .{ .changefeed_capacity = 4 });
    defer store.deinit();
    const before = try readWalForTest(tmp, "selector-count.wal");
    defer std.testing.allocator.free(before);
    const seq = store.next_seq;
    var ticket = try store.prepareBatch(&.{
        .{ .family = .accounts, .kind = .put, .key = "A", .value = "a-value" },
        .{ .family = .props, .kind = .put, .key = "B", .value = "b-value" },
    });
    defer ticket.abort();
    const changes = [_]OwnedMutation{ store.active_batch.?.entries[0].change.?, store.active_batch.?.entries[1].change.? };
    store.active_batch.?.count = 0;
    if (ticket.commit()) |_| {
        // Both map plans consumed key/value ownership. The two independent
        // event allocations were omitted entirely by the shortened selector;
        // free those exact lost allocations, leaving real map ownership intact.
        for (changes) |change| {
            var owned = change;
            owned.deinit(std.testing.allocator);
        }
        try std.testing.expectEqualStrings("a-value", store.get(.accounts, "A").?);
        try std.testing.expectEqualStrings("b-value", store.get(.props, "B").?);
        try std.testing.expectEqual(seq + 2, store.next_seq);
        try std.testing.expectEqual(@as(usize, 0), store.changeCount());
        std.debug.print("KvTable selector causal: count0 committed two rows and omitted two owned events\n", .{});
        return error.TestUnexpectedResult;
    } else |err| {
        store.active_batch.?.count = 2;
        try std.testing.expectEqual(StoreError.InvalidTablePlan, err);
    }
    const after = try readWalForTest(tmp, "selector-count.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expectEqual(@as(usize, 0), store.changeCount());
    try std.testing.expect(store.get(.accounts, "A") == null);
    try std.testing.expect(store.get(.props, "B") == null);
    try ticket.commit();
    try std.testing.expectEqual(@as(usize, 2), store.changeCount());
}

test "STORE KvTable batch bounded selectors complete cross family coverage and duplicate omission refusal" {
    for (0..9) |variant| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "selectors.wal", .{ .changefeed_capacity = 4 });
        defer store.deinit();
        try store.put(.history, "D", "OLD");
        const before = try readWalForTest(tmp, "selectors.wal");
        defer std.testing.allocator.free(before);
        const seq = store.next_seq;
        var ticket = try store.prepareBatch(&.{
            .{ .family = .accounts, .kind = .put, .key = "A", .value = "a" },
            .{ .family = .props, .kind = .put, .key = "B", .value = "b" },
            .{ .family = .props, .kind = .put, .key = "C", .value = "c" },
            .{ .family = .history, .kind = .delete, .key = "D" },
        });
        defer ticket.abort();
        const entries = store.active_batch.?.entries; // All four are initialized.
        switch (variant) {
            0 => store.active_batch.?.count = 0,
            1 => store.active_batch.?.count = max_batch_mutations + 1,
            2 => store.active_batch.?.count = std.math.maxInt(usize),
            3 => store.active_batch.?.count = 3,
            4 => store.active_batch.?.entries[2] = entries[1],
            5 => store.active_batch.?.entries[3] = entries[0],
            6 => store.active_batch.?.entries[3].family = .props,
            7 => store.active_batch.?.entries[3].kind = .put,
            8 => store.active_batch.?.entries[2].kind = .delete,
            else => unreachable,
        }
        const result = ticket.commit();
        // Restore the prepared entry count (four), not the batch capacity:
        // slots past the prepared prefix are uninitialized and must never be
        // walked by abort cleanup.
        store.active_batch.?.count = 4;
        store.active_batch.?.entries = entries;
        try std.testing.expectError(StoreError.InvalidTablePlan, result);
        const after = try readWalForTest(tmp, "selectors.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try std.testing.expectEqual(seq, store.next_seq);
        try std.testing.expectEqual(@as(usize, 1), store.changeCount());
        try std.testing.expectEqualStrings("OLD", store.get(.history, "D").?);
        try std.testing.expect(store.get(.accounts, "A") == null);
        try std.testing.expect(store.get(.props, "B") == null);
        try std.testing.expect(store.get(.props, "C") == null);
        try std.testing.expect(!store.preparedWritesPoisoned());
        try ticket.commit();
        try std.testing.expectEqual(seq + 4, store.next_seq);
        try std.testing.expectEqual(@as(usize, 4), store.changeCount());
        try std.testing.expectEqualStrings("a", store.get(.accounts, "A").?);
        try std.testing.expectEqualStrings("b", store.get(.props, "B").?);
        try std.testing.expectEqualStrings("c", store.get(.props, "C").?);
        try std.testing.expect(store.get(.history, "D") == null);
    }
}
