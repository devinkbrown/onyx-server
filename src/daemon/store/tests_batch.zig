// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: batch.

const std = @import("std");
const BatchMutation = @import("contracts.zig").BatchMutation;
const MutationKind = @import("contracts.zig").MutationKind;
const PreparedIoFault = @import("contracts.zig").PreparedIoFault;
const StoreError = @import("contracts.zig").StoreError;
const default_max_record_len = @import("contracts.zig").default_max_record_len;
const meta_kind_batch = @import("contracts.zig").meta_kind_batch;
const meta_kind_batch_format = @import("contracts.zig").meta_kind_batch_format;
const payload_header_len = @import("contracts.zig").payload_header_len;
const record_header_len = @import("contracts.zig").record_header_len;
const OroStore = @import("engine.zig").OroStore;
const findRecordPayloadByKind = @import("tests_support.zig").findRecordPayloadByKind;
const openTestStore = @import("tests_support.zig").openTestStore;
const readWalForTest = @import("tests_support.zig").readWalForTest;
const refreshRecordChecksum = @import("tests_support.zig").refreshRecordChecksum;
const rewriteTestFile = @import("tests_support.zig").rewriteTestFile;
const readU32 = @import("wal.zig").readU32;

pub const test_policy_batch = [_]BatchMutation{
    .{ .family = .props, .kind = .put, .key = "tot\x00alice", .value = "NEWSECRET" },
    .{ .family = .props, .kind = .delete, .key = "sessiontokacct:alice" },
    .{ .family = .props, .kind = .put, .key = "new-key", .value = "new-value" },
};

pub fn seedPolicyBatch(store: *OroStore) !void {
    try store.put(.props, "tot\x00alice", "OLDSECRET");
    try store.put(.props, "sessiontokacct:alice", "old-token-hash");
}

pub fn expectPolicyBatch(store: *OroStore, committed: bool) !void {
    try std.testing.expectEqualStrings(if (committed) "NEWSECRET" else "OLDSECRET", store.get(.props, "tot\x00alice").?);
    if (committed) {
        try std.testing.expect(store.get(.props, "sessiontokacct:alice") == null);
        try std.testing.expectEqualStrings("new-value", store.get(.props, "new-key").?);
    } else {
        try std.testing.expectEqualStrings("old-token-hash", store.get(.props, "sessiontokacct:alice").?);
        try std.testing.expect(store.get(.props, "new-key") == null);
    }
}

test "STORE batch reserves OOM atomically and retries every allocation" {
    var successes: usize = 0;
    var failures: usize = 0;
    for (0..64) |fail_offset| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize), .resize_fail_index = 0 });
        var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "batch-oom.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        const before = try readWalForTest(tmp, "batch-oom.wal");
        defer std.testing.allocator.free(before);
        const next_seq = store.next_seq;
        const offset = store.wal_offset;
        const change_count = store.changeCount();
        const secret_ptr = store.get(.props, "tot\x00alice").?.ptr;
        const token_ptr = store.get(.props, "sessiontokacct:alice").?.ptr;
        failing.fail_index = failing.alloc_index + fail_offset;
        var prepared = store.prepareBatch(&test_policy_batch) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
            try expectPolicyBatch(&store, false);
            try std.testing.expectEqual(secret_ptr, store.get(.props, "tot\x00alice").?.ptr);
            try std.testing.expectEqual(token_ptr, store.get(.props, "sessiontokacct:alice").?.ptr);
            try std.testing.expectEqual(next_seq, store.next_seq);
            try std.testing.expectEqual(offset, store.wal_offset);
            try std.testing.expectEqual(change_count, store.changeCount());
            try std.testing.expect(store.active_batch == null);
            const after = try readWalForTest(tmp, "batch-oom.wal");
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            failing.fail_index = std.math.maxInt(usize);
            var retry = try store.prepareBatch(&test_policy_batch);
            defer retry.deinit();
            try retry.commit();
            try expectPolicyBatch(&store, true);
            continue;
        };
        defer prepared.deinit();
        const allocations = failing.alloc_index;
        const frees = failing.deallocations;
        // The first non-failing reservation must commit even with allocations
        // and frees prohibited immediately after prepare.
        failing.fail_index = failing.alloc_index;
        try prepared.commit();
        try std.testing.expectEqual(allocations, failing.alloc_index);
        try std.testing.expectEqual(frees, failing.deallocations);
        try expectPolicyBatch(&store, true);
        try std.testing.expectEqual(next_seq + test_policy_batch.len, store.next_seq);
        successes += 1;
        break;
    }
    try std.testing.expect(failures > 0);
    try std.testing.expectEqual(@as(usize, 1), successes);
}

test "STORE batch write ambiguity publishes nothing and reopen resolves the whole group" {
    const faults = [_]PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } };
    for (faults, 0..) |fault, i| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var next_seq: u64 = undefined;
        {
            var store = try openTestStore(tmp, "batch-fault.wal");
            defer store.deinit();
            try seedPolicyBatch(&store);
            next_seq = store.next_seq;
            const change_count = store.changeCount();
            var prepared = try store.prepareBatch(&test_policy_batch);
            defer prepared.deinit();
            store.setPreparedIoFault(fault);
            try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
            try std.testing.expect(store.preparedWritesPoisoned());
            try expectPolicyBatch(&store, false);
            try std.testing.expectEqual(next_seq, store.next_seq);
            try std.testing.expectEqual(change_count, store.changeCount());
            try std.testing.expectError(StoreError.StorePoisoned, store.prepareBatch(&test_policy_batch));
            try std.testing.expectError(StoreError.StorePoisoned, store.delete(.props, "tot\x00alice"));
        }
        var reopened = try openTestStore(tmp, "batch-fault.wal");
        defer reopened.deinit();
        try expectPolicyBatch(&reopened, i == 2);
        try std.testing.expectEqual(next_seq + (if (i == 2) @as(u64, test_policy_batch.len) else @as(u64, 0)), reopened.next_seq);
        if (i != 2) {
            var retry = try reopened.prepareBatch(&test_policy_batch);
            defer retry.deinit();
            try retry.commit();
            try expectPolicyBatch(&reopened, true);
        }
    }
}

test "STORE batch every torn append prefix reopens to whole prior policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var append_offset: usize = undefined;
    const bytes = block: {
        var store = try openTestStore(tmp, "batch-complete.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        append_offset = @intCast(store.wal_offset);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
        break :block try readWalForTest(tmp, "batch-complete.wal");
    };
    defer std.testing.allocator.free(bytes);
    for (append_offset..bytes.len) |cut| {
        try rewriteTestFile(tmp, "batch-torn.wal", bytes[0..cut]);
        var reopened = try openTestStore(tmp, "batch-torn.wal");
        defer reopened.deinit();
        try expectPolicyBatch(&reopened, false);
        var retry = try reopened.prepareBatch(&test_policy_batch);
        defer retry.deinit();
        try retry.commit();
        try expectPolicyBatch(&reopened, true);
    }
}

test "STORE batch strict EOF decode rejects checksum-valid malformed components" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const original = block: {
        var store = try openTestStore(tmp, "batch-valid.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var prepared = try store.prepareBatch(&test_policy_batch);
        defer prepared.deinit();
        try prepared.commit();
        break :block try readWalForTest(tmp, "batch-valid.wal");
    };
    defer std.testing.allocator.free(original);
    const payload_start = findRecordPayloadByKind(original, meta_kind_batch).?;
    const first_part = payload_start + 3 + 4;
    const second_part = first_part + readU32(original[payload_start + 3 ..][0..4]) + 4;
    const cases = [_]struct { offset: usize, value: u8, expected: StoreError }{
        .{ .offset = payload_start + 1, .value = 2, .expected = StoreError.BadRecord },
        .{ .offset = payload_start + 2, .value = 0, .expected = StoreError.BadRecord },
        .{ .offset = payload_start + 2, .value = 4, .expected = StoreError.BadRecord },
        .{ .offset = second_part, .value = 6, .expected = StoreError.UnknownRecordKind },
        .{ .offset = second_part + 1, .value = 99, .expected = StoreError.UnknownFamily },
        .{ .offset = second_part + 6, .value = 0, .expected = StoreError.BadRecord },
    };
    for (cases) |case| {
        const damaged = try std.testing.allocator.dupe(u8, original);
        defer std.testing.allocator.free(damaged);
        damaged[case.offset] = case.value;
        refreshRecordChecksum(damaged, payload_start);
        try rewriteTestFile(tmp, "batch-bad.wal", damaged);
        try std.testing.expectError(case.expected, openTestStore(tmp, "batch-bad.wal"));
        const after = try readWalForTest(tmp, "batch-bad.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, damaged, after);
    }
}

/// The pre-batch reader accepts ordinary mutations and metadata, tolerates an
/// unknown WAL record only at exact EOF, and never tolerates snapshot errors.
pub fn legacyBatchFormatRejected(bytes: []const u8, snapshot: bool) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (bytes.len - offset < record_header_len) return false;
        const len: usize = readU32(bytes[offset..][0..4]);
        const end = offset + record_header_len + len;
        if (end > bytes.len or len == 0) return false;
        const kind = bytes[offset + record_header_len];
        if (kind == meta_kind_batch_format or kind == meta_kind_batch)
            return snapshot or end != bytes.len;
        offset = end;
    }
    return false;
}

test "STORE batch mandatory format guard refuses downgrade before and after compaction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-guard.wal");
    defer store.deinit();
    try seedPolicyBatch(&store);
    var prepared = try store.prepareBatch(&test_policy_batch);
    defer prepared.deinit();
    try prepared.commit();
    const wal = try readWalForTest(tmp, "batch-guard.wal");
    defer std.testing.allocator.free(wal);
    try std.testing.expect(legacyBatchFormatRejected(wal, false));
    try store.snapshotAndTruncate();
    const snapshot = try readWalForTest(tmp, "batch-guard.wal.snap");
    defer std.testing.allocator.free(snapshot);
    try std.testing.expect(legacyBatchFormatRejected(snapshot, true));
    var reopened = try openTestStore(tmp, "batch-guard.wal");
    defer reopened.deinit();
    try expectPolicyBatch(&reopened, true);
    try std.testing.expect(reopened.batch_format_required);
    try std.testing.expectEqual(store.next_seq, reopened.next_seq);
}

test "STORE batch rejects duplicate keys and capacity sequence exhaustion before I/O" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-limits.wal");
    defer store.deinit();
    const duplicate = [_]BatchMutation{
        .{ .family = .props, .kind = .put, .key = "same", .value = "a" },
        .{ .family = .props, .kind = .delete, .key = "same" },
    };
    const before = try readWalForTest(tmp, "batch-limits.wal");
    defer std.testing.allocator.free(before);
    try std.testing.expectError(StoreError.BadRecord, store.prepareBatch(&duplicate));
    store.cfg.max_record_bytes = 12;
    try std.testing.expectError(StoreError.RecordTooLarge, store.prepareBatch(&test_policy_batch));
    store.cfg.max_record_bytes = default_max_record_len;
    store.next_seq = std.math.maxInt(u64) - 1;
    try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&test_policy_batch));
    const after = try readWalForTest(tmp, "batch-limits.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "STORE batch copied reservations abort without touching newer ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-copy.wal");
    defer store.deinit();
    try seedPolicyBatch(&store);
    var first = try store.prepareBatch(&test_policy_batch);
    var copied = first;
    first.abort();
    try expectPolicyBatch(&store, false);
    var next = try store.prepareBatch(&test_policy_batch);
    defer next.deinit();
    copied.abort();
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, copied.commit());
    try std.testing.expectError(StoreError.PreparedMutationActive, store.preparePut(.props, "other", "v"));
    try std.testing.expectError(StoreError.PreparedMutationActive, store.put(.props, "other", "v"));
    try next.commit();
    try expectPolicyBatch(&store, true);
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, next.commit());
}

test "STORE batch four deletes retire bounded feed evictions without allocator work" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var store = try OroStore.openWithConfig(failing.allocator(), std.testing.io, tmp.dir, "batch-retire.wal", .{ .changefeed_capacity = 1 });
    defer store.deinit();
    const operations = [_]BatchMutation{
        .{ .family = .props, .kind = .delete, .key = "a" },
        .{ .family = .props, .kind = .delete, .key = "b" },
        .{ .family = .accounts, .kind = .delete, .key = "a" },
        .{ .family = .accounts, .kind = .delete, .key = "b" },
    };
    for (operations) |operation| try store.put(operation.family, operation.key, "value");
    const seq = store.next_seq;
    var batch = try store.prepareBatch(&operations);
    defer batch.deinit();
    const allocation_count = failing.alloc_index;
    const free_count = failing.deallocations;
    failing.fail_index = allocation_count;
    try batch.commit();
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(free_count, failing.deallocations);
    try std.testing.expectEqual(@as(usize, 17), store.retirement_count);
    try std.testing.expectEqual(seq + operations.len, store.next_seq);
    try std.testing.expectEqual(seq + operations.len - 1, store.changeAt(0).?.seq);
    try std.testing.expectEqual(MutationKind.delete, store.changeAt(0).?.kind);
    for (operations) |operation| try std.testing.expect(store.get(operation.family, operation.key) == null);
    failing.fail_index = std.math.maxInt(usize);
    var retry = try store.preparePut(.props, "after-retirement", "safe");
    defer retry.deinit();
    try retry.commit();
    try std.testing.expectEqualStrings("safe", store.get(.props, "after-retirement").?);
}

test "STORE batch read-only staged replay refuses mutation without WAL change" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "batch-readonly.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
    }
    const before = try readWalForTest(tmp, "batch-readonly.wal");
    defer std.testing.allocator.free(before);
    var staged = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "batch-readonly.wal", .{});
    defer staged.deinit();
    try expectPolicyBatch(&staged, true);
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.prepareBatch(&test_policy_batch));
    const after = try readWalForTest(tmp, "batch-readonly.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "STORE batch durable replay allocation failures clean up without rewriting WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "batch-replay-oom.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
    }
    const before = try readWalForTest(tmp, "batch-replay-oom.wal");
    defer std.testing.allocator.free(before);
    const ReplaySweep = struct {
        fn run(allocator: std.mem.Allocator, dir: std.testing.TmpDir) !void {
            var store = try OroStore.open(allocator, std.testing.io, dir.dir, "batch-replay-oom.wal");
            defer store.deinit();
            try expectPolicyBatch(&store, true);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ReplaySweep.run, .{tmp});
    const after = try readWalForTest(tmp, "batch-replay-oom.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "STORE batch owns caller bytes and publishes each component sequence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-owned.wal");
    defer store.deinit();
    var key = [_]u8{ 'k', 'e', 'y' };
    var value = [_]u8{ 'v', 'a', 'l', 'u', 'e' };
    const operations = [_]BatchMutation{
        .{ .family = .props, .kind = .put, .key = &key, .value = &value },
        .{ .family = .accounts, .kind = .put, .key = "account", .value = "raw-account-row" },
        .{ .family = .props, .kind = .delete, .key = "absent" },
    };
    var batch = try store.prepareBatch(&operations);
    defer batch.deinit();
    @memset(&key, 'x');
    @memset(&value, 'x');
    try batch.commit();
    try std.testing.expectEqualStrings("value", store.get(.props, "key").?);
    for (0..operations.len) |i| {
        const change = store.changeAt(i).?;
        try std.testing.expectEqual(@as(u64, @intCast(i)) + 1, change.seq);
        try std.testing.expectEqual(operations[i].family, change.family);
        try std.testing.expectEqual(operations[i].kind, change.kind);
    }
    try std.testing.expectEqualStrings("key", store.changeAt(0).?.key);
    try std.testing.expectEqualStrings("value", store.changeAt(0).?.value.?);
    var reopened = try openTestStore(tmp, "batch-owned.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("value", reopened.get(.props, "key").?);
    try std.testing.expectEqualStrings("raw-account-row", reopened.get(.accounts, "account").?);
    try std.testing.expectEqual(@as(u64, 4), reopened.next_seq);
}

test "STORE batch replay rejects duplicate keys before applying a valid earlier component" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const operations = [_]BatchMutation{
        .{ .family = .props, .kind = .put, .key = "one", .value = "replacement" },
        .{ .family = .props, .kind = .delete, .key = "two" },
    };
    const bytes = block: {
        var store = try openTestStore(tmp, "batch-duplicate.wal");
        defer store.deinit();
        var batch = try store.prepareBatch(&operations);
        defer batch.deinit();
        try batch.commit();
        break :block try readWalForTest(tmp, "batch-duplicate.wal");
    };
    defer std.testing.allocator.free(bytes);
    const start = findRecordPayloadByKind(bytes, meta_kind_batch).?;
    const second = start + 3 + 4 + readU32(bytes[start + 3 ..][0..4]) + 4;
    @memcpy(bytes[second + payload_header_len ..][0..3], "one");
    refreshRecordChecksum(bytes, start);
    try rewriteTestFile(tmp, "batch-duplicate.wal", bytes);
    try std.testing.expectError(StoreError.BadRecord, openTestStore(tmp, "batch-duplicate.wal"));
    const after = try readWalForTest(tmp, "batch-duplicate.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, bytes, after);
}

pub fn expectMalformedBatchOuterFailsClosed(read_only: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = block: {
        var store = try openTestStore(tmp, "batch-outer.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
        break :block try readWalForTest(tmp, "batch-outer.wal");
    };
    defer std.testing.allocator.free(bytes);
    const start = findRecordPayloadByKind(bytes, meta_kind_batch).?;
    bytes[start] = 0xFF;
    refreshRecordChecksum(bytes, start);
    try rewriteTestFile(tmp, "batch-outer.wal", bytes);
    const result = if (read_only)
        OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "batch-outer.wal", .{})
    else
        openTestStore(tmp, "batch-outer.wal");
    var opened = result catch |err| {
        try std.testing.expectEqual(StoreError.UnknownRecordKind, err);
        const after = try readWalForTest(tmp, "batch-outer.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, bytes, after);
        return;
    };
    opened.deinit();
    return error.TestUnexpectedResult;
}

test "STORE batch unknown outer kind fails ordinary reopen without rewriting WAL" {
    try expectMalformedBatchOuterFailsClosed(false);
}

test "STORE batch unknown outer kind fails read-only reopen without rewriting WAL" {
    try expectMalformedBatchOuterFailsClosed(true);
}

test "mesh presence hot promotion releases read descriptor before no IO activation" {
    // Raw-fd fcntl has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var parent = try openTestStore(tmp, "hot-promotion.wal");
    defer parent.deinit();
    try parent.put(.props, "original", "retained");
    try std.testing.expectError(StoreError.ReadOnlyStore, parent.releaseReadHandleForPreparedPromotion());
    var staged = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-promotion.wal", .{});
    defer staged.deinit();
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.releaseReadHandleForPreparedPromotion());
    const read_fd = staged.wal_file.?.handle;
    try staged.preparePromotion();
    const writer_fd = staged.staged_write_file.?.handle;
    try staged.releaseReadHandleForPreparedPromotion();
    try std.testing.expect(staged.isReadOnly());
    try std.testing.expect(staged.wal_file == null);
    try std.testing.expectEqual(writer_fd, staged.staged_write_file.?.handle);
    try std.testing.expectEqual(std.posix.E.BADF, std.posix.errno(std.posix.system.fcntl(read_fd, std.posix.F.GETFD, @as(i32, 0))));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.releaseReadHandleForPreparedPromotion());
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.put(.props, "forbidden", "before barrier"));
    const before = try readWalForTest(tmp, "hot-promotion.wal");
    defer std.testing.allocator.free(before);
    staged.promotePrepared();
    try std.testing.expect(!staged.isReadOnly());
    try std.testing.expect(staged.staged_write_file == null);
    try std.testing.expectEqual(writer_fd, staged.wal_file.?.handle);
    const after = try readWalForTest(tmp, "hot-promotion.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}
