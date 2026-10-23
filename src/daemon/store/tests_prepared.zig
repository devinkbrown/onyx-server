// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: prepared.

const EngineAccess = @import("engine.zig").Internal;
const std = @import("std");
const PreparedIoFault = @import("contracts.zig").PreparedIoFault;
const StoreError = @import("contracts.zig").StoreError;
const default_max_record_len = @import("contracts.zig").default_max_record_len;
const meta_kind_snapshot_coverage = @import("contracts.zig").meta_kind_snapshot_coverage;
const record_header_len = @import("contracts.zig").record_header_len;
const snapshot_coverage_slot_len = @import("contracts.zig").snapshot_coverage_slot_len;
const wal_epoch_payload_len = @import("contracts.zig").wal_epoch_payload_len;
const OroStore = @import("engine.zig").OroStore;
const findRecordPayloadByKind = @import("tests_support.zig").findRecordPayloadByKind;
const openTestStore = @import("tests_support.zig").openTestStore;
const readWalForTest = @import("tests_support.zig").readWalForTest;
const refreshRecordChecksum = @import("tests_support.zig").refreshRecordChecksum;
const rewriteTestFile = @import("tests_support.zig").rewriteTestFile;
const checksum = @import("wal.zig").checksum;
const writeNextSeqRecordAt = @import("wal.zig").writeNextSeqRecordAt;
const writeRecordAt = @import("wal.zig").writeRecordAt;
const writeU32 = @import("wal.zig").writeU32;

test "STORE prepared put reserves then commits insert and replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "prepared-roundtrip.wal");
    defer store.deinit();

    var insert = try store.preparePut(.accounts, "alice", "v1");
    defer insert.deinit();
    try std.testing.expect(store.family(.accounts).get("alice") == null);
    try std.testing.expectEqual(@as(usize, 0), store.changeCount());
    try insert.commit();
    try std.testing.expectEqualStrings("v1", store.family(.accounts).get("alice").?);
    try std.testing.expectEqual(@as(usize, 1), store.changeCount());
    try std.testing.expectEqual(@as(u64, 2), store.next_seq);
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, insert.commit());

    var replace = try store.preparePut(.accounts, "alice", "v2");
    defer replace.deinit();
    try std.testing.expectEqualStrings("v1", store.family(.accounts).get("alice").?);
    try replace.commit();
    try std.testing.expectEqualStrings("v2", store.family(.accounts).get("alice").?);
    try std.testing.expectEqual(@as(usize, 2), store.changeCount());
    try std.testing.expectEqual(@as(u64, 3), store.next_seq);
}

test "STORE prepared put abort and deinit are byte inert" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "prepared-abort.wal");
    defer store.deinit();
    try store.family(.accounts).put("alice", "old");
    const before_wal = try readWalForTest(tmp, "prepared-abort.wal");
    defer std.testing.allocator.free(before_wal);
    const before_offset = store.wal_offset;
    const before_seq = store.next_seq;
    const before_changes = store.changeCount();

    var aborted = try store.preparePut(.accounts, "alice", "new");
    aborted.abort();
    aborted.deinit();
    try std.testing.expectEqualStrings("old", store.family(.accounts).get("alice").?);
    try std.testing.expectEqual(before_offset, store.wal_offset);
    const after_abort_wal = try readWalForTest(tmp, "prepared-abort.wal");
    defer std.testing.allocator.free(after_abort_wal);
    try std.testing.expectEqualSlices(u8, before_wal, after_abort_wal);
    try std.testing.expectEqual(before_seq, store.next_seq);
    try std.testing.expectEqual(before_changes, store.changeCount());

    {
        var dropped = try store.preparePut(.accounts, "bob", "never-published");
        dropped.deinit();
    }
    try std.testing.expect(store.family(.accounts).get("bob") == null);
    try std.testing.expectEqual(before_offset, store.wal_offset);
    try std.testing.expectEqual(before_seq, store.next_seq);
    try std.testing.expectEqual(before_changes, store.changeCount());
}

test "STORE prepared lane serializes ordinary and second prepared mutations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "prepared-serial.wal");
    defer store.deinit();

    var held = try store.preparePut(.accounts, "alice", "v1");
    defer held.deinit();
    try std.testing.expectError(StoreError.PreparedMutationActive, store.preparePut(.accounts, "bob", "v2"));
    try std.testing.expectError(StoreError.PreparedMutationActive, store.put(.accounts, "bob", "v2"));
    try std.testing.expectError(StoreError.PreparedMutationActive, store.delete(.accounts, "alice"));
    try held.commit();
    try store.family(.accounts).put("bob", "v2");
    try std.testing.expectEqualStrings("v2", store.family(.accounts).get("bob").?);
}

test "STORE prepared put write and sync ambiguity poison without publication" {
    const FaultCase = struct {
        fault: PreparedIoFault,
        name: []const u8,
    };
    const cases = [_]FaultCase{
        .{ .fault = .{ .write = .failed }, .name = "prepared-failed.wal" },
        .{ .fault = .{ .write = .short }, .name = "prepared-short.wal" },
        .{ .fault = .{ .sync = true }, .name = "prepared-sync.wal" },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, case.name);
        defer store.deinit();
        store.setPreparedIoFault(case.fault);

        var prepared = try store.preparePut(.accounts, "alice", "v1");
        defer prepared.deinit();
        try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expect(store.family(.accounts).get("alice") == null);
        try std.testing.expectEqual(@as(usize, 0), store.changeCount());
        try std.testing.expectEqual(@as(u64, 1), store.next_seq);
        try std.testing.expectError(StoreError.StorePoisoned, store.put(.accounts, "bob", "blocked"));
        try std.testing.expectError(StoreError.StorePoisoned, store.preparePut(.accounts, "bob", "blocked"));
    }
}

test "STORE ambiguous prepared outcomes are resolved only by durable reopen" {
    const FaultCase = struct {
        fault: PreparedIoFault,
        name: []const u8,
        durable: bool,
    };
    const cases = [_]FaultCase{
        .{ .fault = .{ .write = .failed }, .name = "prepared-reopen-failed.wal", .durable = false },
        .{ .fault = .{ .write = .short }, .name = "prepared-reopen-short.wal", .durable = false },
        .{ .fault = .{ .sync = true }, .name = "prepared-reopen-sync.wal", .durable = true },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, case.name);
            defer store.deinit();
            store.setPreparedIoFault(case.fault);
            var prepared = try store.preparePut(.props, "dprop1:snapshot", "snapshot-v1");
            defer prepared.deinit();
            try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
            try std.testing.expect(store.family(.props).get("dprop1:snapshot") == null);
        }
        var reopened = try openTestStore(tmp, case.name);
        defer reopened.deinit();
        if (case.durable) {
            try std.testing.expectEqualStrings("snapshot-v1", reopened.family(.props).get("dprop1:snapshot").?);
        } else {
            try std.testing.expect(reopened.family(.props).get("dprop1:snapshot") == null);
        }
    }
}

test "DPROP prepared put durable reopen matches successful publication" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "dprop1-reopen.wal");
        defer store.deinit();
        var prepared = try store.preparePut(.props, "dprop1:snapshot", "snapshot-v1");
        defer prepared.deinit();
        try prepared.commit();
    }
    var reopened = try openTestStore(tmp, "dprop1-reopen.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("snapshot-v1", reopened.family(.props).get("dprop1:snapshot").?);
    // Changefeed is intentionally process-local; durable reopen proves the
    // reported committed value, while a fresh feed starts empty.
    try std.testing.expectEqual(@as(usize, 0), reopened.changeCount());
}

test "DPROP prepared admission compacts before commit when projected WAL is due" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "dprop1-compact.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer store.deinit();
    var prepared = try store.preparePut(.props, "dprop1:snapshot", "snapshot-v1");
    defer prepared.deinit();
    try prepared.commit();
    try std.testing.expectEqualStrings("snapshot-v1", store.family(.props).get("dprop1:snapshot").?);
    var reopened = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "dprop1-compact.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer reopened.deinit();
    try std.testing.expectEqualStrings("snapshot-v1", reopened.family(.props).get("dprop1:snapshot").?);
}

test "STORE prepared put enforces record and WAL capacity before admission" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "prepared-limits.wal",
        .{ .max_record_bytes = 16, .max_wal_bytes = 128 },
    );
    defer store.deinit();
    try std.testing.expectError(StoreError.RecordTooLarge, store.preparePut(.accounts, "alice", "0123456789abcdef"));
    try std.testing.expectEqual(@as(u64, 1), store.next_seq);
    try std.testing.expectEqual(@as(usize, 0), store.changeCount());
}

test "STORE prepared put reserves every allocation atomically" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var store = try OroStore.open(allocator, std.testing.io, tmp.dir, "prepared-oom.wal");
            defer store.deinit();
            try store.family(.accounts).put("stable", "before");
            const before_wal = try readWalForTest(tmp, "prepared-oom.wal");
            defer std.testing.allocator.free(before_wal);
            const before_offset = store.wal_offset;
            const before_seq = store.next_seq;
            const before_changes = store.changeCount();

            var prepared = store.preparePut(.accounts, "candidate", "value") catch |err| {
                if (err != error.OutOfMemory) return err;
                try std.testing.expectEqualStrings("before", store.family(.accounts).get("stable").?);
                try std.testing.expect(store.family(.accounts).get("candidate") == null);
                try std.testing.expectEqual(before_offset, store.wal_offset);
                const after_wal = try readWalForTest(tmp, "prepared-oom.wal");
                defer std.testing.allocator.free(after_wal);
                try std.testing.expectEqualSlices(u8, before_wal, after_wal);
                try std.testing.expectEqual(before_seq, store.next_seq);
                try std.testing.expectEqual(before_changes, store.changeCount());
                return err;
            };
            defer prepared.deinit();
            try prepared.commit();
            try std.testing.expectEqualStrings("value", store.family(.accounts).get("candidate").?);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "STORE prepared token owns stable key after caller mutation and free" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "prepared-stable-key.wal");
    const caller_key = try std.testing.allocator.dupe(u8, "stable-key");
    var prepared = try store.preparePut(.accounts, caller_key, "value");
    @memset(@constCast(caller_key), 'x');
    std.testing.allocator.free(caller_key);
    try prepared.commit();
    prepared.deinit();
    try std.testing.expectEqualStrings("value", store.family(.accounts).get("stable-key").?);
    store.deinit();

    var reopened = try openTestStore(tmp, "prepared-stable-key.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("value", reopened.family(.accounts).get("stable-key").?);
}

test "STORE copied and stale prepared tokens cannot affect a newer reservation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "prepared-generation.wal");
    defer store.deinit();

    var first = try store.preparePut(.accounts, "first", "one");
    var copied = first;
    try copied.commit();
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, first.commit());

    var second = try store.preparePut(.accounts, "second", "two");
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, copied.commit());
    first.abort();
    try std.testing.expect(store.family(.accounts).get("second") == null);
    try second.commit();
    try std.testing.expectEqualStrings("one", store.family(.accounts).get("first").?);
    try std.testing.expectEqualStrings("two", store.family(.accounts).get("second").?);
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, copied.commit());
    copied.deinit();
    first.deinit();
    second.deinit();
}

test "STORE prepared publication performs no allocator work" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "prepared-no-alloc.wal");
    defer store.deinit();

    var prepared = try store.preparePut(.accounts, "alice", "v1");
    const allocs_before = failing.alloc_index;
    const frees_before = failing.deallocations;
    try prepared.commit();
    try std.testing.expectEqual(allocs_before, failing.alloc_index);
    try std.testing.expectEqual(frees_before, failing.deallocations);
    prepared.deinit();
}

test "STORE prepared sequence exhaustion is rejected before WAL I/O" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "prepared-seq-exhausted.wal");
    defer store.deinit();
    try store.family(.accounts).put("seed", "v");
    const before_wal = try readWalForTest(tmp, "prepared-seq-exhausted.wal");
    defer std.testing.allocator.free(before_wal);
    store.next_seq = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, store.preparePut(.accounts, "alice", "v1"));
    const after_wal = try readWalForTest(tmp, "prepared-seq-exhausted.wal");
    defer std.testing.allocator.free(after_wal);
    try std.testing.expectEqualSlices(u8, before_wal, after_wal);
}

test "STORE prepared admission compacts projected WAL before append" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "prepared-projected.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer store.deinit();
    try store.family(.accounts).put("seed", "0123456789012345678901234567890123456789");
    try std.testing.expect(store.wal_offset < 128);
    var prepared = try store.preparePut(.accounts, "next", "0123456789012345678901234567890123456789");
    defer prepared.deinit();
    // Candidate projected size crossed half the hard cap, so compaction ran
    // before the token was admitted. The fresh WAL epoch header is the only
    // prefix left before the candidate reservation.
    try std.testing.expectEqual(@as(u64, record_header_len + wal_epoch_payload_len), store.wal_offset);
    try prepared.commit();
    try std.testing.expect(store.wal_offset <= 256);

    var too_small = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "prepared-too-small.wal",
        .{ .max_wal_bytes = 32 },
    );
    defer too_small.deinit();
    try std.testing.expectError(StoreError.RecordTooLarge, too_small.preparePut(.accounts, "key", "01234567890123456789"));
}

test "STORE snapshot truncate faults never permit stale append" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "prepared-truncate-faults.wal");
        defer store.deinit();
        try store.family(.accounts).put("seed", "v");
        const before_offset = store.wal_offset;

        store.setPreparedIoFault(.{ .snapshot_sync = true });
        try std.testing.expectError(StoreError.SnapshotSyncFailed, store.snapshotAndTruncate());
        try std.testing.expectEqual(before_offset, store.wal_offset);
        store.setPreparedIoFault(.{});
        try store.family(.accounts).put("after-snapshot-fault", "v");

        store.setPreparedIoFault(.{ .wal_truncate = .failed });
        try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectError(StoreError.StorePoisoned, store.put(.accounts, "after-truncate-fault", "v"));
        try std.testing.expectError(StoreError.StorePoisoned, store.preparePut(.accounts, "blocked", "v"));
    }
    var reopened = try openTestStore(tmp, "prepared-truncate-faults.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("seed").?);
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("after-snapshot-fault").?);
    try reopened.family(.accounts).put("after-reopen", "v");
}

test "STORE short prepared write reopens and ordinary append remains valid" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "prepared-short-recover.wal");
        store.setPreparedIoFault(.{ .write = .short });
        var prepared = try store.preparePut(.accounts, "torn", "value");
        try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
        prepared.deinit();
        store.deinit();
    }
    var reopened = try openTestStore(tmp, "prepared-short-recover.wal");
    try std.testing.expect(reopened.family(.accounts).get("torn") == null);
    try reopened.family(.accounts).put("ordinary", "after-reopen");
    try std.testing.expectEqualStrings("after-reopen", reopened.family(.accounts).get("ordinary").?);
    reopened.deinit();
}

test "STORE covered snapshot recovery preserves exact sequence across truncate faults" {
    const FaultCase = struct {
        fault: PreparedIoFault,
        name: []const u8,
    };
    const cases = [_]FaultCase{
        .{ .fault = .{ .wal_truncate = .failed }, .name = "coverage-truncate-failed.wal" },
        .{ .fault = .{ .wal_truncate = .short }, .name = "coverage-truncate-short.wal" },
        .{ .fault = .{ .wal_sync = true }, .name = "coverage-wal-sync.wal" },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, case.name);
            try store.family(.accounts).put("seed", "v1");
            try std.testing.expectEqual(@as(u64, 2), store.next_seq);
            store.setPreparedIoFault(case.fault);
            try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
            store.deinit();
        }
        var reopened = try openTestStore(tmp, case.name);
        defer reopened.deinit();
        try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
        try std.testing.expectEqualStrings("v1", reopened.family(.accounts).get("seed").?);
        try reopened.family(.accounts).put("after-recovery", "v2");
        try std.testing.expectEqual(@as(u64, 3), reopened.next_seq);
        try std.testing.expectEqual(@as(u64, 2), reopened.changeAt(0).?.seq);
    }
}

test "STORE covered snapshot mismatch is fatal for shorter WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "coverage-shorter.wal");
        try store.family(.accounts).put("seed", "v");
        try store.snapshotAndTruncate();
        store.deinit();
    }
    var wal = try tmp.dir.openFile(std.testing.io, "coverage-shorter.wal", .{ .mode = .read_write, .allow_directory = false });
    try wal.setLength(std.testing.io, 4);
    wal.close(std.testing.io);
    try std.testing.expectError(
        StoreError.SnapshotCoverageMismatch,
        OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "coverage-shorter.wal"),
    );
}

test "STORE covered snapshot mismatch is fatal for digest and epoch changes" {
    const Case = enum { digest, epoch };
    for ([_]Case{ .digest, .epoch }) |which| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, if (which == .digest) "coverage-digest.wal" else "coverage-epoch.wal");
            try store.family(.accounts).put("seed", "v");
            try store.snapshotAndTruncate();
            store.deinit();
        }
        const name = if (which == .digest) "coverage-digest.wal" else "coverage-epoch.wal";
        if (which == .digest) {
            var snap = try tmp.dir.readFileAlloc(std.testing.io, "coverage-digest.wal.snap", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(snap);
            const kind_index = findRecordPayloadByKind(snap, meta_kind_snapshot_coverage).?;
            snap[kind_index + 3 + snapshot_coverage_slot_len + 24] ^= 0x01;
            refreshRecordChecksum(snap, kind_index);
            try rewriteTestFile(tmp, "coverage-digest.wal.snap", snap);
        } else {
            var wal = try tmp.dir.readFileAlloc(std.testing.io, name, std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(wal);
            wal[record_header_len + 1] ^= 0x01;
            refreshRecordChecksum(wal, record_header_len);
            try rewriteTestFile(tmp, name, wal);
        }
        try std.testing.expectError(
            StoreError.SnapshotCoverageMismatch,
            OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name),
        );
    }
}

test "STORE legacy snapshot without coverage replays WAL from zero" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "legacy-coverage.wal");
        try store.family(.accounts).put("legacy", "v");
        try store.snapshotAndTruncate();
        store.deinit();
    }
    var snap = try tmp.dir.readFileAlloc(std.testing.io, "legacy-coverage.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(snap);
    const kind_index = findRecordPayloadByKind(snap, meta_kind_snapshot_coverage).?;
    try rewriteTestFile(tmp, "legacy-coverage.wal.snap", snap[0 .. kind_index - record_header_len]);

    var reopened = try openTestStore(tmp, "legacy-coverage.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("legacy").?);
    try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
}

test "STORE empty WAL crash window recovers rotated coverage epoch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "coverage-empty-crash.wal");
        try store.family(.accounts).put("seed", "v");
        try store.snapshotAndTruncate();
        store.deinit();
    }
    var wal = try tmp.dir.openFile(std.testing.io, "coverage-empty-crash.wal", .{ .mode = .read_write, .allow_directory = false });
    try wal.setLength(std.testing.io, 0);
    wal.close(std.testing.io);

    var reopened = try openTestStore(tmp, "coverage-empty-crash.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("v", reopened.family(.accounts).get("seed").?);
    try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
    try reopened.family(.accounts).put("after-crash", "v2");
    try std.testing.expectEqual(@as(u64, 3), reopened.next_seq);
    try std.testing.expectEqual(@as(u64, 2), reopened.changeAt(0).?.seq);
}

test "STORE genuine headerless WAL survives snapshot truncate failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var wal = try tmp.dir.createFile(std.testing.io, "coverage-legacy-headerless.wal", .{ .truncate = true, .read = true });
        defer wal.close(std.testing.io);
        const end = try writeRecordAt(
            std.testing.io,
            wal,
            0,
            std.testing.allocator,
            .put,
            .accounts,
            "key",
            "1234",
            default_max_record_len,
        );
        // payload_header_len + key.len + value.len deliberately equals the
        // epoch payload width; the kind byte must still identify legacy data.
        try std.testing.expectEqual(@as(u64, record_header_len + wal_epoch_payload_len), end);
        try wal.sync(std.testing.io);
    }
    {
        var store = try openTestStore(tmp, "coverage-legacy-headerless.wal");
        try std.testing.expectEqualStrings("1234", store.family(.accounts).get("key").?);
        try std.testing.expectEqual(@as(u64, 2), store.next_seq);
        store.setPreparedIoFault(.{ .wal_truncate = .failed });
        try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
        store.deinit();
    }
    var reopened = try openTestStore(tmp, "coverage-legacy-headerless.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("1234", reopened.family(.accounts).get("key").?);
    try std.testing.expectEqual(@as(u64, 2), reopened.next_seq);
    try reopened.family(.accounts).put("after", "recovery");
    try std.testing.expectEqual(@as(u64, 3), reopened.next_seq);
}

test "STORE checksum-valid zero-length record is rejected without panic" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var record: [record_header_len]u8 = undefined;
    writeU32(record[0..4], 0);
    writeU32(record[4..8], checksum(""));
    try rewriteTestFile(tmp, "zero-payload.wal", &record);
    try std.testing.expectError(
        StoreError.BadRecord,
        OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "zero-payload.wal"),
    );
}

test "STORE torn equal-width legacy tail is not misclassified as epoch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var wal = try tmp.dir.createFile(std.testing.io, "legacy-torn-equal-width.wal", .{ .truncate = true, .read = true });
    const end = try writeRecordAt(
        std.testing.io,
        wal,
        0,
        std.testing.allocator,
        .put,
        .accounts,
        "key",
        "1234",
        default_max_record_len,
    );
    try std.testing.expectEqual(@as(u64, record_header_len + wal_epoch_payload_len), end);
    var bad_checksum: [4]u8 = undefined;
    writeU32(&bad_checksum, 0);
    try wal.writePositionalAll(std.testing.io, &bad_checksum, 4);
    try wal.sync(std.testing.io);
    wal.close(std.testing.io);

    var reopened = try openTestStore(tmp, "legacy-torn-equal-width.wal");
    defer reopened.deinit();
    try std.testing.expect(reopened.family(.accounts).get("key") == null);
    try std.testing.expectEqual(@as(u64, 0), reopened.wal_offset);
}

test "STORE ordinary sequence exhaustion is pre-WAL and byte inert" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "ordinary-sequence-exhausted.wal");
    defer store.deinit();
    const before = try readWalForTest(tmp, "ordinary-sequence-exhausted.wal");
    defer std.testing.allocator.free(before);

    store.next_seq = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, store.put(.accounts, "put", "v"));
    const after_put = try readWalForTest(tmp, "ordinary-sequence-exhausted.wal");
    defer std.testing.allocator.free(after_put);
    try std.testing.expectEqualSlices(u8, before, after_put);
    try std.testing.expectError(StoreError.SequenceExhausted, store.delete(.accounts, "delete"));
    const after_delete = try readWalForTest(tmp, "ordinary-sequence-exhausted.wal");
    defer std.testing.allocator.free(after_delete);
    try std.testing.expectEqualSlices(u8, before, after_delete);
}

test "STORE replay sequence exhaustion fails cleanly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "replay-sequence-exhausted.wal");
        try EngineAccess.ensureWal(&store);
        const file = store.wal_file.?;
        var offset = store.wal_offset;
        offset = try writeNextSeqRecordAt(std.testing.io, file, offset, std.testing.allocator, std.math.maxInt(u64));
        const record_offset = offset;
        offset = try writeRecordAt(
            std.testing.io,
            file,
            offset,
            std.testing.allocator,
            .put,
            .accounts,
            "replay",
            "value",
            store.cfg.max_record_bytes,
        );
        try file.sync(std.testing.io);
        store.wal_offset = offset;
        try std.testing.expect(offset > record_offset);
        store.deinit();
    }
    try std.testing.expectError(
        StoreError.SequenceExhausted,
        OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "replay-sequence-exhausted.wal"),
    );
}

test "STORE prepared replacement retires all four slots without publication allocation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var store = try OroStore.openWithConfig(
        failing.allocator(),
        std.testing.io,
        tmp.dir,
        "prepared-four-retirements.wal",
        .{ .changefeed_capacity = 1 },
    );
    defer store.deinit();
    try store.family(.accounts).put("alice", "old");

    var prepared = try store.preparePut(.accounts, "alice", "new");
    const allocs_before = failing.alloc_index;
    const frees_before = failing.deallocations;
    try prepared.commit();
    try std.testing.expectEqual(allocs_before, failing.alloc_index);
    try std.testing.expectEqual(frees_before, failing.deallocations);
    try std.testing.expectEqual(@as(usize, 4), store.retirement_count);
    try std.testing.expectEqualStrings("new", store.family(.accounts).get("alice").?);

    var next = try store.preparePut(.accounts, "bob", "next");
    try std.testing.expectEqual(@as(usize, 0), store.retirement_count);
    next.abort();
    prepared.deinit();
}

test "native Helix read-only store stages without disk mutations and promotes only after commit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var parent = try openTestStore(tmp, "native-stage.wal");
    defer parent.deinit();
    try parent.put(.accounts, "alice", "original");
    const before = try readWalForTest(tmp, "native-stage.wal");
    defer allocator.free(before);
    // Force the normal boot compaction threshold below the existing size.
    var staged = try OroStore.openReadOnlyWithConfig(allocator, io, tmp.dir, "native-stage.wal", .{ .max_wal_bytes = before.len + 1 });
    defer staged.deinit();
    try std.testing.expect(staged.isReadOnly());
    try std.testing.expectEqualStrings("original", staged.get(.accounts, "alice").?);
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.put(.accounts, "alice", "changed"));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.delete(.accounts, "alice"));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.preparePut(.accounts, "alice", "prepared"));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.snapshotAndTruncate());
    try staged.preparePromotion();
    try std.testing.expect(staged.isReadOnly());
    const still = try readWalForTest(tmp, "native-stage.wal");
    defer allocator.free(still);
    try std.testing.expectEqualSlices(u8, before, still);
    staged.promotePrepared();
    try std.testing.expect(!staged.isReadOnly());
    try staged.put(.accounts, "alice", "committed");
    var reopened = try openTestStore(tmp, "native-stage.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("committed", reopened.get(.accounts, "alice").?);
}

test "native Helix read-only store refuses torn WAL without repair and detects parent changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    var parent = try openTestStore(tmp, "native-torn.wal");
    defer parent.deinit();
    try parent.put(.accounts, "alice", "first");
    var staged = try OroStore.openReadOnlyWithConfig(allocator, std.testing.io, tmp.dir, "native-torn.wal", .{});
    defer staged.deinit();
    try parent.put(.accounts, "bob", "later");
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, staged.preparePromotion());
    const wal = parent.wal_file.?;
    try wal.writePositionalAll(std.testing.io, "torn", parent.wal_offset);
    const before = try readWalForTest(tmp, "native-torn.wal");
    defer allocator.free(before);
    try std.testing.expectError(StoreError.BadRecord, OroStore.openReadOnlyWithConfig(allocator, std.testing.io, tmp.dir, "native-torn.wal", .{}));
    const after = try readWalForTest(tmp, "native-torn.wal");
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectError(error.FileNotFound, OroStore.openReadOnlyWithConfig(allocator, std.testing.io, tmp.dir, "absent.wal", .{}));
}
