// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: ordinary.

const EngineAccess = @import("engine.zig").Internal;
const std = @import("std");
const Config = @import("contracts.zig").Config;
const MutationKind = @import("contracts.zig").MutationKind;
const PreparedIoFault = @import("contracts.zig").PreparedIoFault;
const StoreError = @import("contracts.zig").StoreError;
const default_max_record_len = @import("contracts.zig").default_max_record_len;
const familyIndex = @import("contracts.zig").familyIndex;
const OroStore = @import("engine.zig").OroStore;
const KvTable = @import("table.zig").KvTable;
const openTestStore = @import("tests_support.zig").openTestStore;
const readWalForTest = @import("tests_support.zig").readWalForTest;
const writeRecordAt = @import("wal.zig").writeRecordAt;

pub const OrdinaryMutationTest = struct {
    const Mode = enum { insert, grow, replace, delete, absent_delete };
    const seed_keys = [_][]const u8{ "alice", "b", "c", "d", "e", "f" };

    fn key(mode: Mode) []const u8 {
        return switch (mode) {
            .replace, .delete => "alice",
            else => "candidate",
        };
    }

    fn kind(mode: Mode) MutationKind {
        return switch (mode) {
            .delete, .absent_delete => .delete,
            else => .put,
        };
    }

    fn seed(store: *OroStore, mode: Mode) !void {
        for (seed_keys[0..if (mode == .grow) seed_keys.len else 1]) |seed_key|
            try store.put(.accounts, seed_key, "old");
    }

    fn apply(store: *OroStore, mode: Mode) !void {
        switch (kind(mode)) {
            .put => try store.put(.accounts, key(mode), "new"),
            .delete => try store.delete(.accounts, key(mode)),
        }
    }

    fn expectRows(store: *const OroStore, mode: Mode, committed: bool) !void {
        if (mode == .delete and committed) {
            try std.testing.expect(store.get(.accounts, "alice") == null);
        } else {
            try std.testing.expectEqualStrings(if (mode == .replace and committed) "new" else "old", store.get(.accounts, "alice").?);
        }
        if ((mode == .insert or mode == .grow) and committed) {
            try std.testing.expectEqualStrings("new", store.get(.accounts, "candidate").?);
        } else try std.testing.expect(store.get(.accounts, "candidate") == null);
        if (mode == .grow) for (seed_keys[1..]) |seed_key| {
            try std.testing.expectEqualStrings("old", store.get(.accounts, seed_key).?);
        };
        const initial_count: u32 = if (mode == .grow) 6 else 1;
        const final_count = if (!committed) initial_count else switch (mode) {
            .insert, .grow => initial_count + 1,
            .delete => initial_count - 1,
            else => initial_count,
        };
        try std.testing.expectEqual(final_count, store.maps[familyIndex(.accounts)].map.count());
    }

    fn feedDigest(store: *const OroStore) [32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        for (0..store.changeCount()) |i| {
            const change = store.changeAt(i).?;
            KvTable.hashNumber(&h, change.seq);
            KvTable.hashNumber(&h, @backingInt(change.family));
            KvTable.hashNumber(&h, @backingInt(change.kind));
            KvTable.hashNumber(&h, change.key.len);
            h.update(change.key);
            if (change.value) |value| {
                KvTable.hashNumber(&h, value.len);
                h.update(value);
            }
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }

    fn sweep(mode: Mode, feed_capacity: usize) !void {
        var failure_index: usize = 0;
        while (failure_index < 64) : (failure_index += 1) {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            const cfg: Config = .{ .changefeed_capacity = feed_capacity };
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
            var next_sequence: u64 = undefined;
            var failed = false;
            {
                var store = try OroStore.openWithConfig(failing.allocator(), std.testing.io, tmp.dir, "ordinary-oom.wal", cfg);
                defer store.deinit();
                try seed(&store, mode);
                const before_wal = try readWalForTest(tmp, "ordinary-oom.wal");
                defer std.testing.allocator.free(before_wal);
                const before_offset = store.wal_offset;
                const before_seq = store.next_seq;
                const before_feed = feedDigest(&store);
                const before_count = store.changeCount();
                const table = &store.maps[familyIndex(.accounts)].map;
                const before_revision = table.revision;
                const before_slots = table.slots;
                failing.fail_index = failing.alloc_index + failure_index;
                apply(&store, mode) catch |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    try std.testing.expect(failing.has_induced_failure);
                    failing.fail_index = std.math.maxInt(usize);
                    failed = true;
                    try expectRows(&store, mode, false);
                    try std.testing.expect(!store.preparedWritesPoisoned());
                    try std.testing.expect(store.active_prepared == null);
                    try std.testing.expectEqual(before_offset, store.wal_offset);
                    try std.testing.expectEqual(before_seq, store.next_seq);
                    try std.testing.expectEqual(before_count, store.changeCount());
                    try std.testing.expectEqualSlices(u8, &before_feed, &feedDigest(&store));
                    try std.testing.expectEqual(before_revision, table.revision);
                    try std.testing.expectEqual(before_slots.ptr, table.slots.ptr);
                    try std.testing.expectEqual(before_slots.len, table.slots.len);
                    const after_wal = try readWalForTest(tmp, "ordinary-oom.wal");
                    defer std.testing.allocator.free(after_wal);
                    try std.testing.expectEqualSlices(u8, before_wal, after_wal);
                    var reopened = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "ordinary-oom.wal", cfg);
                    defer reopened.deinit();
                    try expectRows(&reopened, mode, false);
                    try std.testing.expectEqual(before_seq, reopened.next_seq);
                    // Retry in the same live store after every rejected index.
                    try apply(&store, mode);
                };
                failing.fail_index = std.math.maxInt(usize);
                try expectRows(&store, mode, true);
                next_sequence = before_seq + 1;
                try std.testing.expectEqual(next_sequence, store.next_seq);
                try std.testing.expectEqual(before_revision + @intFromBool(mode != .absent_delete), table.revision);
                try std.testing.expect(!store.batch_format_required);
                if (feed_capacity == 0) {
                    try std.testing.expectEqual(@as(usize, 0), store.changeCount());
                } else {
                    const change = store.changeAt(store.changeCount() - 1).?;
                    try std.testing.expectEqual(before_seq, change.seq);
                    try std.testing.expectEqual(kind(mode), change.kind);
                    try std.testing.expectEqualStrings(key(mode), change.key);
                    if (kind(mode) == .put) try std.testing.expectEqualStrings("new", change.value.?) else try std.testing.expect(change.value == null);
                }
            }
            // The writer is closed; replay must agree with the successful retry.
            var reopened = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "ordinary-oom.wal", cfg);
            defer reopened.deinit();
            try expectRows(&reopened, mode, true);
            try std.testing.expectEqual(next_sequence, reopened.next_seq);
            if (!failed) {
                try std.testing.expect(failure_index >= 2);
                return;
            }
        }
        return error.TestUnexpectedResult; // The sweep must reach normal success.
    }
};

test "STORE ordinary writes reserve every allocation before durable publication" {
    for (std.enums.values(OrdinaryMutationTest.Mode)) |mode| {
        for ([_]usize{ 0, 1, 4 }) |capacity| try OrdinaryMutationTest.sweep(mode, capacity);
    }
}

test "STORE ordinary write and sync ambiguity poison until close and reopen" {
    const cases = [_]struct { fault: PreparedIoFault, complete: bool }{
        .{ .fault = .{ .write = .failed }, .complete = false },
        .{ .fault = .{ .write = .short }, .complete = false },
        .{ .fault = .{ .sync = true }, .complete = true },
    };
    for (std.enums.values(OrdinaryMutationTest.Mode)) |mode| {
        for (cases) |case| {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var expected_sequence: u64 = undefined;
            {
                var store = try openTestStore(tmp, "ordinary-ambiguous.wal");
                defer store.deinit();
                try OrdinaryMutationTest.seed(&store, mode);
                const before_seq = store.next_seq;
                const before_offset = store.wal_offset;
                const before_feed = OrdinaryMutationTest.feedDigest(&store);
                const before_revision = store.maps[familyIndex(.accounts)].map.revision;
                store.setPreparedIoFault(case.fault);
                try std.testing.expectError(StoreError.IoAmbiguous, OrdinaryMutationTest.apply(&store, mode));
                try std.testing.expect(store.preparedWritesPoisoned());
                try std.testing.expect(store.active_prepared == null);
                try OrdinaryMutationTest.expectRows(&store, mode, false);
                try std.testing.expectEqual(before_seq, store.next_seq);
                try std.testing.expectEqual(before_offset, store.wal_offset);
                try std.testing.expectEqual(before_revision, store.maps[familyIndex(.accounts)].map.revision);
                try std.testing.expectEqualSlices(u8, &before_feed, &OrdinaryMutationTest.feedDigest(&store));
                store.setPreparedIoFault(.{});
                try std.testing.expectError(StoreError.StorePoisoned, store.put(.accounts, "later", "blocked"));
                try std.testing.expectError(StoreError.StorePoisoned, store.delete(.accounts, "alice"));
                try std.testing.expectError(StoreError.StorePoisoned, store.preparePut(.accounts, "later", "blocked"));
                try std.testing.expectError(StoreError.StorePoisoned, store.prepareBatch(&.{.{ .family = .accounts, .kind = .delete, .key = "alice" }}));
                try std.testing.expectError(StoreError.StorePoisoned, store.snapshotAndTruncate());
                expected_sequence = before_seq + @intFromBool(case.complete);
            }
            var reopened = try openTestStore(tmp, "ordinary-ambiguous.wal");
            defer reopened.deinit();
            try std.testing.expect(!reopened.preparedWritesPoisoned());
            try OrdinaryMutationTest.expectRows(&reopened, mode, case.complete);
            try std.testing.expectEqual(expected_sequence, reopened.next_seq);
            try reopened.put(.props, "after-reopen", "accepted");
            try std.testing.expectEqual(expected_sequence + 1, reopened.next_seq);
        }
    }
}

test "STORE ordinary writes retain canonical single-record WAL bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "ordinary-canonical.wal");
    defer store.deinit();
    const initial_offset = store.wal_offset;
    const canonical = try tmp.dir.createFile(std.testing.io, "canonical.wal", .{ .read = true });
    defer canonical.close(std.testing.io);
    var offset: u64 = 0;
    for ([_]MutationKind{ .put, .put, .delete, .delete }) |kind| {
        switch (kind) {
            .put => try store.put(.accounts, "alice", "value"),
            .delete => try store.delete(.accounts, "alice"),
        }
        offset = try writeRecordAt(std.testing.io, canonical, offset, std.testing.allocator, kind, .accounts, "alice", "value", default_max_record_len);
    }
    const actual = try readWalForTest(tmp, "ordinary-canonical.wal");
    defer std.testing.allocator.free(actual);
    const expected = try readWalForTest(tmp, "canonical.wal");
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, actual[@intCast(initial_offset)..]);
    try std.testing.expect(!store.batch_format_required);
    try std.testing.expectEqual(@as(u64, 5), store.next_seq);
    try store.snapshotAndTruncate();
    var reopened = try openTestStore(tmp, "ordinary-canonical.wal");
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u64, 5), reopened.next_seq);
    try std.testing.expect(reopened.get(.accounts, "alice") == null);
    try std.testing.expect(!reopened.batch_format_required);
}

test "STORE ordinary delete publication performs no allocator work" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var store = try OroStore.openWithConfig(failing.allocator(), std.testing.io, tmp.dir, "ordinary-delete-noalloc.wal", .{ .changefeed_capacity = 1 });
    defer store.deinit();
    try store.put(.accounts, "alice", "old");
    for ([_][]const u8{ "alice", "absent" }) |key| {
        var prepared = try EngineAccess.prepareMutation(&store, .accounts, .delete, key, null);
        defer prepared.deinit();
        const allocations = failing.alloc_index;
        const frees = failing.deallocations;
        failing.fail_index = allocations;
        try prepared.commit();
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expectEqual(allocations, failing.alloc_index);
        try std.testing.expectEqual(frees, failing.deallocations);
        try std.testing.expect(store.get(.accounts, key) == null);
    }
}

test "STORE ordinary revision and token generation guards precede WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "ordinary-guards.wal");
    defer store.deinit();
    try store.put(.accounts, "alice", "old");
    const table = &store.maps[familyIndex(.accounts)].map;
    // A planned insertion reserves exactly one revision (no growth/rollback
    // stamps), so it can use the last revision without wrapping.
    table.revision = std.math.maxInt(u64) - 1;
    try store.put(.accounts, "last", "value");
    try std.testing.expectEqual(std.math.maxInt(u64), table.revision);
    try std.testing.expectError(StoreError.SequenceExhausted, store.put(.accounts, "blocked", "value"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.delete(.accounts, "alice"));
    const before_seq = store.next_seq;
    try store.delete(.accounts, "absent");
    try std.testing.expectEqual(before_seq + 1, store.next_seq);
    try std.testing.expectEqual(std.math.maxInt(u64), table.revision);

    const before = try readWalForTest(tmp, "ordinary-guards.wal");
    defer std.testing.allocator.free(before);
    table.revision = 1;
    store.next_prepared_generation = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, store.put(.accounts, "blocked", "value"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.delete(.accounts, "alice"));
    store.next_prepared_generation = 1;
    store.next_seq = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, store.put(.accounts, "blocked", "value"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.delete(.accounts, "alice"));
    const after = try readWalForTest(tmp, "ordinary-guards.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}
