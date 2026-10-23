// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: complete epoch.

const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const ColdPublicationFault = @import("checkpoint.zig").ColdPublicationFault;
const ColdRecoveryStage = @import("checkpoint.zig").ColdRecoveryStage;
const validateColdPreparedWal = @import("checkpoint.zig").validateColdPreparedWal;
const BatchMutation = @import("contracts.zig").BatchMutation;
const cold_epoch_record_len = @import("contracts.zig").cold_epoch_record_len;
const OroStore = @import("engine.zig").OroStore;
const encodeColdSnapshot = @import("engine.zig").encodeColdSnapshot;
const coldOpenParent = @import("native_files.zig").coldOpenParent;

pub fn seedCompleteEpoch(dir: std.Io.Dir) !void {
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
    defer store.deinit();
    try store.put(.props, "old", "original durable job");
}

pub const complete_epoch_mutations = [_]BatchMutation{
    .{ .family = .props, .kind = .put, .key = "outcome", .value = "original failure" },
    .{ .family = .props, .kind = .put, .key = "disposition", .value = "terminal" },
};

test "cold complete epoch prepares synced full successor before publication and never rewrites after replacement" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var stage = try ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
    defer stage.deinit();
    const old_next = stage.view().next_seq;
    var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
    defer ticket.abort();
    const owned = stage.backing.?;
    const plan = owned.plan.?;
    try std.testing.expect(plan.complete_epoch and plan.rotate);
    try std.testing.expect(plan.coverage != null);
    try std.testing.expectEqual(@as(u64, cold_epoch_record_len), plan.coverage.?.slots[1].covered_len);
    try validateColdPreparedWal(owned);
    try std.testing.expectEqual(@as(u64, cold_epoch_record_len + owned.store.active_batch.?.record.?.len), (try plan.writer.stat(std.testing.io)).size);
    const before = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try std.testing.expectEqualSlices(u8, original, before);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
    // Arm the ordinary append fault AND allocator after all preparation. Any
    // post-publication append or allocation makes this actual commit fail.
    stage.setPreparedIoFault(.{ .write = .failed, .sync = true });
    failing.fail_index = failing.alloc_index;
    try ticket.commit();
    try std.testing.expect(!failing.has_induced_failure);
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqual(old_next + 2, published.next_seq);
    try std.testing.expectEqualStrings("original durable job", published.get(.props, "old").?);
    try std.testing.expectEqualStrings("original failure", published.get(.props, "outcome").?);
    try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
    var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
    defer restart.deinit();
    try std.testing.expectEqual(old_next + 2, restart.view().next_seq);
    try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
    try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
}

test "cold complete epoch publication errors cold-select whole OLD or whole NEW batch" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]ColdPublicationFault{ .snapshot_replace, .snapshot_dir_sync, .wal_replace, .wal_dir_sync }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var old_next: u64 = undefined;
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer stage.deinit();
            old_next = stage.view().next_seq;
            var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
            defer ticket.abort();
            try validateColdPreparedWal(stage.backing.?);
            stage.setPublicationFault(fault);
            try std.testing.expectError(error.IoAmbiguous, ticket.commit());
            try std.testing.expect(stage.backing.?.consumed);
            try std.testing.expect(stage.view().preparedWritesPoisoned());
            try std.testing.expect(stage.backing.?.store.active_batch == null);
            try std.testing.expect(stage.backing.?.plan.?.complete_record != null);
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqualStrings("original durable job", restart.view().get(.props, "old").?);
        if (fault == .wal_dir_sync) {
            try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
            try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
            try std.testing.expectEqual(old_next + 2, restart.view().next_seq);
        } else {
            try std.testing.expect(restart.view().get(.props, "outcome") == null);
            try std.testing.expect(restart.view().get(.props, "disposition") == null);
            try std.testing.expectEqual(old_next, restart.view().next_seq);
        }
        try std.testing.expectEqual(restart.backing.?.wal.bytes.len, restart.backing.?.valid_end);
    }
}

test "cold complete epoch rejects every truncated prepared successor before namespace publication and permits exact retry" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var prefix: usize = 0;
    while (true) : (prefix += 1) {
        var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
        defer stage.deinit();
        var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
        defer ticket.abort();
        const owned = stage.backing.?;
        const plan = &owned.plan.?;
        const packet = owned.store.active_batch.?.record.?;
        const length = cold_epoch_record_len + packet.len;
        try std.testing.expect(prefix < length);
        try plan.writer.setLength(std.testing.io, prefix);
        try plan.writer.sync(std.testing.io);
        try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
        try std.testing.expect(!owned.consumed);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, original, after);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
        if (prefix + 1 == length) {
            try plan.writer.writePositionalAll(std.testing.io, &plan.epoch, 0);
            try plan.writer.writePositionalAll(std.testing.io, packet, cold_epoch_record_len);
            try plan.writer.sync(std.testing.io);
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
            break;
        }
    }
}

test "cold complete epoch refuses unknown torn transcript without repair or temporary publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const file = try tmp.dir.openFile(std.testing.io, "complete.wal", .{ .mode = .read_write });
    defer file.close(std.testing.io);
    const size = (try file.stat(std.testing.io)).size;
    try file.writePositionalAll(std.testing.io, &.{ 0xAB, 0xCD, 0xEF }, size);
    try file.sync(std.testing.io);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
    defer stage.deinit();
    try std.testing.expect(stage.backing.?.valid_end < stage.backing.?.wal.bytes.len);
    try std.testing.expectError(error.SnapshotCoverageMismatch, stage.prepareCompleteBatch(&complete_epoch_mutations));
    try std.testing.expect(stage.backing.?.plan == null and stage.backing.?.store.active_batch == null);
    const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, original, after);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
}

test "cold complete epoch every allocation failure preserves original files and successful retry commits without allocation" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var candidate = ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
        if (candidate) |*stage| {
            defer stage.deinit();
            if (stage.prepareCompleteBatch(&complete_epoch_mutations)) |prepared| {
                var ticket = prepared;
                defer ticket.abort();
                try std.testing.expect(!failing.has_induced_failure);
                failing.fail_index = failing.alloc_index;
                stage.setPreparedIoFault(.{ .write = .failed, .sync = true });
                try ticket.commit();
                try std.testing.expect(!failing.has_induced_failure);
                var published = stage.takeCommittedStore();
                defer published.deinit();
                try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
                break;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(stage.backing.?.plan == null and stage.backing.?.store.active_batch == null);
                try std.testing.expectEqualStrings("original durable job", stage.view().get(.props, "old").?);
            }
        } else |err| try std.testing.expectEqual(error.OutOfMemory, err);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, original, after);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
    }
}

test "cold complete epoch selected empty WAL and repeated successors preserve prior rows and sequence" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        if (empty) {
            var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer store.deinit();
            try store.snapshotAndTruncate();
            try store.snapshotAndTruncate();
            try store.wal_file.?.setLength(std.testing.io, 0);
            try store.wal_file.?.sync(std.testing.io);
        }
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var original_next: u64 = undefined;
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer stage.deinit();
            original_next = stage.view().next_seq;
            try std.testing.expectEqual(empty, stage.backing.?.selected_epoch != null);
            var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
            defer ticket.abort();
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqual(original_next + 2, published.next_seq);
            try std.testing.expectEqualStrings("original durable job", published.get(.props, "old").?);
        }
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer stage.deinit();
            try std.testing.expectEqual(original_next + 2, stage.view().next_seq);
            try std.testing.expectEqualStrings("terminal", stage.view().get(.props, "disposition").?);
            var ticket = try stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "later", .value = "another actual transition" }});
            defer ticket.abort();
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqual(original_next + 3, published.next_seq);
            try std.testing.expectEqualStrings("later", published.changeAt(0).?.key);
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqual(original_next + 3, restart.view().next_seq);
        try std.testing.expectEqualStrings("original durable job", restart.view().get(.props, "old").?);
        try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
        try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
        try std.testing.expectEqualStrings("another actual transition", restart.view().get(.props, "later").?);
    }
}

test "cold complete epoch same-length private file and independent packet witness tamper refuse before publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
    defer ticket.abort();
    const owned = stage.backing.?;
    const plan = &owned.plan.?;
    const position = (try plan.writer.stat(std.testing.io)).size - 1;
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try plan.writer.readPositionalAll(std.testing.io, &byte, position));
    const saved = byte[0];
    byte[0] ^= 1;
    try plan.writer.writePositionalAll(std.testing.io, &byte, position);
    try plan.writer.sync(std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expect(!owned.consumed);
    byte[0] = saved;
    try plan.writer.writePositionalAll(std.testing.io, &byte, position);
    try plan.writer.sync(std.testing.io);
    plan.complete_record.?[0] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expect(!owned.consumed);
    plan.complete_record.?[0] ^= 1;
    const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, original, after);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
    try ticket.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
}

test "cold complete epoch byte identical foreign prepared names refuse before publication and preserve foreign custody" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |replace_snapshot| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(original);
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var old_next: u64 = undefined;
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer stage.deinit();
            old_next = stage.view().next_seq;
            var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
            defer ticket.abort();
            const atomic = if (replace_snapshot) stage.backing.?.plan.?.snapshot_atomic.? else stage.backing.?.plan.?.wal_atomic.?;
            const name = std.fmt.hex(atomic.file_basename_hex);
            const expected = try atomic.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(expected);
            const original_identity = try cold_identity.statRegular(atomic.file.handle);
            const foreign = try atomic.dir.createFile(std.testing.io, "complete-foreign", .{ .read = true });
            defer foreign.close(std.testing.io);
            try foreign.writePositionalAll(std.testing.io, expected, 0);
            try foreign.sync(std.testing.io);
            const foreign_identity = try cold_identity.statRegular(foreign.handle);
            try std.testing.expect(!std.meta.eql(original_identity, foreign_identity));
            try atomic.dir.rename("complete-foreign", atomic.dir, &name, std.testing.io);
            try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
            try std.testing.expect(!stage.backing.?.consumed);
            try std.testing.expect(!stage.view().preparedWritesPoisoned());
            try std.testing.expectEqual(old_next, stage.view().next_seq);
            try std.testing.expectEqual(@as(usize, 0), stage.view().changeCount());
            const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, original, after);
            try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
            ticket.abort();
            const survivor = try atomic.dir.openFile(std.testing.io, &name, .{});
            defer survivor.close(std.testing.io);
            try std.testing.expectEqualDeep(foreign_identity, try cold_identity.statRegular(survivor.handle));
            const actual = try atomic.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(actual);
            try std.testing.expectEqualSlices(u8, expected, actual);
        }
        var retry = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
        defer retry.deinit();
        var ticket = try retry.prepareCompleteBatch(&complete_epoch_mutations);
        defer ticket.abort();
        try ticket.commit();
        var result = retry.takeCommittedStore();
        defer result.deinit();
        try std.testing.expectEqual(old_next + 2, result.next_seq);
        try std.testing.expectEqual(@as(usize, 2), result.changeCount());
        try std.testing.expectEqualStrings("outcome", result.changeAt(0).?.key);
        try std.testing.expectEqualStrings("disposition", result.changeAt(1).?.key);
    }
}

test "cold complete epoch fault recovery retries OLD once and clean NEW promotion pieces never duplicate sequence or feed" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        for ([_]ColdPublicationFault{ .snapshot_replace, .snapshot_dir_sync, .wal_replace, .wal_dir_sync }) |fault| {
            // An empty selected epoch reuses its existing snapshot: only WAL
            // publication seams exist. Do not claim injected snapshot failures.
            if (empty and (fault == .snapshot_replace or fault == .snapshot_dir_sync)) continue;
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            try seedCompleteEpoch(tmp.dir);
            if (empty) {
                var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
                defer seed.deinit();
                try seed.snapshotAndTruncate();
                try seed.snapshotAndTruncate();
                try seed.wal_file.?.setLength(std.testing.io, 0);
                try seed.wal_file.?.sync(std.testing.io);
            }
            const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
            defer lease.close(std.testing.io);
            try cold_identity.reaffirmExclusive(lease.handle);
            var old_next: u64 = undefined;
            {
                var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                defer stage.deinit();
                old_next = stage.view().next_seq;
                var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
                defer ticket.abort();
                stage.setPublicationFault(fault);
                try std.testing.expectError(error.IoAmbiguous, ticket.commit());
                try std.testing.expect(stage.backing.?.consumed and stage.view().preparedWritesPoisoned());
                try std.testing.expectEqual(old_next, stage.view().next_seq);
                try std.testing.expectEqual(@as(usize, 0), stage.view().changeCount());
            }
            {
                var fresh = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                defer fresh.deinit();
                try fresh.validate();
                try std.testing.expectEqual(fresh.backing.?.wal.bytes.len, fresh.backing.?.valid_end);
                if (fault != .wal_dir_sync) {
                    try std.testing.expectEqual(old_next, fresh.view().next_seq);
                    try std.testing.expect(fresh.view().get(.props, "outcome") == null);
                    var ticket = try fresh.prepareCompleteBatch(&complete_epoch_mutations);
                    defer ticket.abort();
                    try ticket.commit();
                    var result = fresh.takeCommittedStore();
                    defer result.deinit();
                    try std.testing.expectEqual(old_next + 2, result.next_seq);
                    try std.testing.expectEqual(@as(usize, 2), result.changeCount());
                } else {
                    // This exercises the mechanical strict-readonly/promotion
                    // pieces, not a domain-authenticated Mail adoption receipt.
                    try std.testing.expectEqual(old_next + 2, fresh.view().next_seq);
                    try std.testing.expectEqualStrings("original failure", fresh.view().get(.props, "outcome").?);
                    try std.testing.expectEqualStrings("terminal", fresh.view().get(.props, "disposition").?);
                    var clean = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                    defer clean.deinit();
                    try std.testing.expectEqualDeep(fresh.backing.?.wal.identity, try cold_identity.statRegular(clean.wal_file.?.handle));
                    try std.testing.expectEqual(fresh.view().next_seq, clean.next_seq);
                    try clean.preparePromotion();
                    try clean.staged_write_file.?.sync(std.testing.io);
                    const parent = try coldOpenParent(std.testing.io, tmp.dir, "complete.wal");
                    defer parent.close(std.testing.io);
                    try parent.sync(std.testing.io);
                    try fresh.validate();
                    const before_feed = clean.changeCount();
                    try clean.releaseReadHandleForPreparedPromotion();
                    clean.promotePrepared();
                    try std.testing.expect(!clean.isReadOnly());
                    try std.testing.expectEqual(old_next + 2, clean.next_seq);
                    try std.testing.expectEqual(before_feed, clean.changeCount());
                    const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
                    defer std.testing.allocator.free(after);
                    try std.testing.expectEqualSlices(u8, fresh.backing.?.wal.bytes, after);
                    const snapshot = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal.snap", std.testing.allocator, .unlimited);
                    defer std.testing.allocator.free(snapshot);
                    try std.testing.expectEqualSlices(u8, fresh.backing.?.snapshot.?.bytes, snapshot);
                }
            }
            var verify = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer verify.deinit();
            try std.testing.expectEqual(old_next + 2, verify.view().next_seq);
            try std.testing.expectEqualStrings("original durable job", verify.view().get(.props, "old").?);
            try std.testing.expectEqualStrings("original failure", verify.view().get(.props, "outcome").?);
            try std.testing.expectEqualStrings("terminal", verify.view().get(.props, "disposition").?);
        }
    }
}

test "cold complete epoch empty capture skips invalid coverage slot and rejects unauthenticated epoch without effects" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |invalid_both| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        var old_next: u64 = undefined;
        {
            var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer seed.deinit();
            old_next = seed.next_seq;
            try seed.snapshotAndTruncate();
            try seed.snapshotAndTruncate();
            var coverage = seed.snapshot_coverage.?;
            coverage.slots[0].digest[0] ^= 1;
            if (invalid_both) coverage.slots[1].digest[0] ^= 1;
            const bytes = try encodeColdSnapshot(&seed, &coverage);
            defer std.testing.allocator.free(bytes);
            const snapshot = try tmp.dir.createFile(std.testing.io, "complete.wal.snap", .{ .truncate = true });
            defer snapshot.close(std.testing.io);
            try snapshot.writePositionalAll(std.testing.io, bytes, 0);
            try snapshot.sync(std.testing.io);
            try seed.wal_file.?.setLength(std.testing.io, 0);
            try seed.wal_file.?.sync(std.testing.io);
        }
        const original_snapshot = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(original_snapshot);
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        if (invalid_both) {
            try std.testing.expectError(error.SnapshotCoverageMismatch, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 }));
            const wal = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(wal);
            try std.testing.expectEqual(@as(usize, 0), wal.len);
        } else {
            {
                var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                defer stage.deinit();
                try std.testing.expectEqual(@as(usize, 1), stage.backing.?.selected_epoch.?);
                var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
                defer ticket.abort();
                try std.testing.expect(stage.backing.?.plan.?.snapshot_atomic == null);
                try ticket.commit();
                var result = stage.takeCommittedStore();
                defer result.deinit();
                try std.testing.expectEqual(old_next + 2, result.next_seq);
                try std.testing.expectEqual(@as(usize, 2), result.changeCount());
            }
            var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer restart.deinit();
            try std.testing.expectEqual(old_next + 2, restart.view().next_seq);
            try std.testing.expectEqualStrings("original durable job", restart.view().get(.props, "old").?);
            try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
            try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
        }
        const after_snapshot = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after_snapshot);
        try std.testing.expectEqualSlices(u8, original_snapshot, after_snapshot);
    }
}
