// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: checkpoint.

const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const ColdPublicationFault = @import("checkpoint.zig").ColdPublicationFault;
const ColdRecoveryStage = @import("checkpoint.zig").ColdRecoveryStage;
const FirstProvisionStage = @import("checkpoint.zig").FirstProvisionStage;
const cold_epoch_record_len = @import("contracts.zig").cold_epoch_record_len;
const OroStore = @import("engine.zig").OroStore;
const encodeColdSnapshot = @import("engine.zig").encodeColdSnapshot;
const deinitColdAtomic = @import("native_files.zig").deinitColdAtomic;
const makeColdAtomicReadable = @import("native_files.zig").makeColdAtomicReadable;
const validateColdAtomicName = @import("native_files.zig").validateColdAtomicName;
const openTestStore = @import("tests_support.zig").openTestStore;
const coldDigest = @import("wal.zig").coldDigest;
const coldEpoch = @import("wal.zig").coldEpoch;

test "cold recovery causal substituted temporary must never become authoritative snapshot" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "temp-custody.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(42);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "temp-custody.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "temp-custody.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const atomic = stage.backing.?.plan.?.snapshot_atomic.?;
    const name = std.fmt.hex(atomic.file_basename_hex);
    const foreign = try atomic.dir.createFile(std.testing.io, "foreign", .{ .read = true });
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try atomic.dir.rename("foreign", atomic.dir, &name, std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    // Refusal must precede ANY authoritative rename, not merely detect it later.
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "temp-custody.wal.snap", .{}));
    ticket.abort();
    const survivor = try atomic.dir.openFile(std.testing.io, &name, .{});
    survivor.close(std.testing.io);
}

pub fn coldRecoveryAllocationScenario(allocator: std.mem.Allocator, empty_covered: bool) !void {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-oom.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(21);
        try seed.put(.props, "old", &large);
        if (empty_covered) {
            try seed.snapshotAndTruncate();
            try seed.snapshotAndTruncate();
            try seed.wal_file.?.setLength(std.testing.io, 0);
            try seed.wal_file.?.sync(std.testing.io);
        }
    }
    const lease = try tmp.dir.createFile(std.testing.io, "cold-oom.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    const before = try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const snapshot = if (empty_covered) try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal.snap", std.testing.allocator, .unlimited) else null;
    defer if (snapshot) |bytes| std.testing.allocator.free(bytes);
    coldRecoveryAttempt(allocator, tmp, lease) catch |err| {
        if (err == error.OutOfMemory) {
            const after = try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            if (snapshot) |bytes| {
                const actual = try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal.snap", std.testing.allocator, .unlimited);
                defer std.testing.allocator.free(actual);
                try std.testing.expectEqualSlices(u8, bytes, actual);
            } else try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "cold-oom.wal.snap", .{}));
            try cold_identity.reaffirmExclusive(lease.handle);
            try coldRecoveryAttempt(std.testing.allocator, tmp, lease);
        }
        return err;
    };
}

pub fn coldRecoveryAttempt(allocator: std.mem.Allocator, tmp: std.testing.TmpDir, lease: std.Io.File) !void {
    var stage = try ColdRecoveryStage.open(allocator, std.testing.io, tmp.dir, "cold-oom.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    const before_seq = stage.view().next_seq;
    if (stage.backing.?.selected_epoch) |chosen| {
        // Repeated compaction legitimately permits two complete epochs for
        // the SAME old maps. Preserve encoded-order FIRST valid selection.
        try std.testing.expectEqual(@as(usize, 0), chosen);
        const coverage = stage.view().snapshot_coverage.?;
        try std.testing.expectEqual(@as(usize, 2), coverage.count);
        for (coverage.slots[0..2]) |slot| {
            const epoch = coldEpoch(slot.epoch);
            try std.testing.expectEqual(@as(u64, cold_epoch_record_len), slot.covered_len);
            try std.testing.expectEqualDeep(slot.digest, coldDigest(&epoch));
        }
    }
    var plan = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "whole" }});
    defer plan.abort();
    const identity = stage.backing.?.plan.?.writer_identity;
    try plan.commit();
    try std.testing.expectError(error.PreparedAlreadyConsumed, plan.commit());
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqual(before_seq + 1, published.next_seq);
    try std.testing.expectEqualDeep(identity, try cold_identity.statRegular(published.wal_file.?.handle));
    try std.testing.expectEqualStrings("whole", published.get(.props, "new").?);
    var restarted = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "cold-oom.wal", .{ .changefeed_capacity = 0 });
    defer restarted.deinit();
    try std.testing.expectEqualStrings("whole", restarted.get(.props, "new").?);
    try std.testing.expectEqualSlices(u8, published.get(.props, "old").?, restarted.get(.props, "old").?);
}

test "cold recovery exhaustive OOM retry preserves near limit and dual epoch empty cuts" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| try std.testing.checkAllAllocationFailures(std.testing.allocator, coldRecoveryAllocationScenario, .{empty});
}

test "cold recovery receipt detects same length overwrite before publication and retries" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "receipt.wal");
        defer store.deinit();
        try store.put(.props, "old", "before");
    }
    const lease = try tmp.dir.createFile(std.testing.io, "receipt.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "receipt.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    var plan = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "after" }});
    defer plan.abort();
    const file = try tmp.dir.openFile(std.testing.io, "receipt.wal", .{ .mode = .read_write });
    defer file.close(std.testing.io);
    var changed = try std.testing.allocator.dupe(u8, stage.backing.?.wal.bytes);
    defer std.testing.allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    try file.writePositionalAll(std.testing.io, changed, 0);
    try std.testing.expectError(error.SnapshotCoverageMismatch, plan.commit());
    const observed = try tmp.dir.readFileAlloc(std.testing.io, "receipt.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(observed);
    try std.testing.expectEqualSlices(u8, changed, observed);
    try file.writePositionalAll(std.testing.io, stage.backing.?.wal.bytes, 0);
    var wrong = plan;
    wrong.generation += 1;
    try std.testing.expectError(error.PreparedAlreadyConsumed, wrong.commit());
    try plan.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("after", published.get(.props, "new").?);
}

test "cold recovery refuses substituted WAL temp before snapshot and leaves foreign name on abort" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "wal-temp.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(42);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "wal-temp.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "wal-temp.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const atomic = stage.backing.?.plan.?.wal_atomic.?;
    const name = std.fmt.hex(atomic.file_basename_hex);
    const foreign = try atomic.dir.createFile(std.testing.io, "foreign", .{ .read = true });
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try atomic.dir.rename("foreign", atomic.dir, &name, std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "wal-temp.wal.snap", .{}));
    ticket.abort();
    const survivor = try atomic.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(survivor);
    try std.testing.expectEqualStrings("FOREIGN", survivor);
}

test "cold recovery private receipt and prepared cut reject scalar row packet epoch coverage tampering" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "tamper.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(42);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "tamper.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "tamper.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const owned = stage.backing.?;
    owned.valid_end -= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.valid_end += 1;
    owned.store.next_seq += 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.store.next_seq -= 1;
    owned.selected_epoch = 0;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.selected_epoch = null;
    owned.store.active_batch.?.record.?[10] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.store.active_batch.?.record.?[10] ^= 1;
    owned.store.active_batch.?.entries[0].value.?[0] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.store.active_batch.?.entries[0].value.?[0] ^= 1;
    owned.plan.?.epoch[24] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.plan.?.epoch[24] ^= 1;
    owned.plan.?.coverage.?.slots[1].digest[0] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.plan.?.coverage.?.slots[1].digest[0] ^= 1;
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "tamper.wal.snap", .{}));
    try ticket.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
}

test "cold recovery publication faults poison owned stage and restart whole old or new cut" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        for (0..7) |fault_index| {
            if (empty and fault_index < 2) continue; // Existing snapshot has no new install.
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            {
                var seed = try openTestStore(tmp, "phases.wal");
                defer seed.deinit();
                const large: [1000]u8 = @splat(42);
                try seed.put(.props, "old", &large);
                if (empty) {
                    try seed.snapshotAndTruncate();
                    try seed.snapshotAndTruncate();
                    try seed.wal_file.?.setLength(std.testing.io, 0);
                }
            }
            const lease = try tmp.dir.createFile(std.testing.io, "phases.wal.lock", .{ .read = true });
            defer lease.close(std.testing.io);
            try cold_identity.reaffirmExclusive(lease.handle);
            {
                var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "phases.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
                defer stage.deinit();
                var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
                defer ticket.abort();
                switch (fault_index) {
                    0 => stage.setPublicationFault(.snapshot_replace),
                    1 => stage.setPublicationFault(.snapshot_dir_sync),
                    2 => stage.setPublicationFault(.wal_replace),
                    3 => stage.setPublicationFault(.wal_dir_sync),
                    4 => stage.setPreparedIoFault(.{ .write = .failed }),
                    5 => stage.setPreparedIoFault(.{ .write = .short }),
                    else => stage.setPreparedIoFault(.{ .sync = true }),
                }
                try std.testing.expectError(error.IoAmbiguous, ticket.commit());
                try std.testing.expect(stage.view().preparedWritesPoisoned());
                try std.testing.expect(!stage.backing.?.committed);
                try std.testing.expectError(error.PreparedAlreadyConsumed, ticket.commit());
            }
            var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "phases.wal", lease, .{ .changefeed_capacity = 0 });
            defer restart.deinit();
            try std.testing.expectEqual(@as(u64, if (fault_index == 6) 3 else 2), restart.view().next_seq);
            if (fault_index == 6) try std.testing.expectEqualStrings("cut", restart.view().get(.props, "new").?) else try std.testing.expect(restart.view().get(.props, "new") == null);
            try std.testing.expectEqual(@as(usize, 1000), restart.view().get(.props, "old").?.len);
            var retry = try restart.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "retry", .value = "whole" }});
            defer retry.abort();
            try retry.commit();
            var published = restart.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("whole", published.get(.props, "retry").?);
        }
    }
}

test "cold recovery first provisioning commit has no allocations and refuses a raced existing WAL" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |race| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const lease = try tmp.dir.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var stage = try FirstProvisionStage.init(failing.allocator(), std.testing.io, tmp.dir, "first.wal", lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "initial", .value = "whole" }});
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "first.wal", .{}));
        if (race) {
            const foreign = try tmp.dir.createFile(std.testing.io, "first.wal", .{});
            defer foreign.close(std.testing.io);
            try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
        }
        failing.fail_index = failing.alloc_index;
        if (race) {
            try std.testing.expectError(error.PathAlreadyExists, stage.commit());
            const bytes = try tmp.dir.readFileAlloc(std.testing.io, "first.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(bytes);
            try std.testing.expectEqualStrings("FOREIGN", bytes);
        } else {
            try stage.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("whole", published.get(.props, "initial").?);
        }
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "cold recovery ordered epoch choice skips invalid first slot and rejects no valid slot" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |invalid_both| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var seed = try openTestStore(tmp, "ordered.wal");
            defer seed.deinit();
            try seed.put(.props, "old", "cut");
            try seed.snapshotAndTruncate();
            try seed.snapshotAndTruncate();
            var coverage = seed.snapshot_coverage.?;
            coverage.slots[0].digest[0] ^= 1;
            if (invalid_both) coverage.slots[1].digest[0] ^= 1;
            const bytes = try encodeColdSnapshot(&seed, &coverage);
            defer std.testing.allocator.free(bytes);
            const snapshot = try tmp.dir.createFile(std.testing.io, "ordered.wal.snap", .{ .truncate = true });
            defer snapshot.close(std.testing.io);
            try snapshot.writePositionalAll(std.testing.io, bytes, 0);
            try snapshot.sync(std.testing.io);
            try seed.wal_file.?.setLength(std.testing.io, 0);
            try seed.wal_file.?.sync(std.testing.io);
        }
        const lease = try tmp.dir.createFile(std.testing.io, "ordered.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        if (invalid_both) {
            try std.testing.expectError(error.SnapshotCoverageMismatch, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "ordered.wal", lease, .{ .changefeed_capacity = 0 }));
        } else {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "ordered.wal", lease, .{ .changefeed_capacity = 0 });
            defer stage.deinit();
            try std.testing.expectEqual(@as(usize, 1), stage.backing.?.selected_epoch.?);
            try std.testing.expectEqualStrings("cut", stage.view().get(.props, "old").?);
            var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "next", .value = "cut" }});
            defer ticket.abort();
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("cut", published.get(.props, "next").?);
        }
    }
}

test "cold recovery tolerated tail truncate failures preserve valid predecessor and retry" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]ColdPublicationFault{ .truncate, .truncate_sync }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var seed = try openTestStore(tmp, "tail.wal");
            defer seed.deinit();
            try seed.put(.props, "old", "cut");
            try seed.wal_file.?.writePositionalAll(std.testing.io, &.{ 0, 0, 0 }, seed.wal_offset);
            try seed.wal_file.?.sync(std.testing.io);
        }
        const lease = try tmp.dir.createFile(std.testing.io, "tail.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "tail.wal", lease, .{ .changefeed_capacity = 0 });
            defer stage.deinit();
            var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
            defer ticket.abort();
            try std.testing.expect(!stage.backing.?.plan.?.rotate);
            stage.setPublicationFault(fault);
            if (fault == .truncate) try std.testing.expectError(error.TruncateFailed, ticket.commit()) else try std.testing.expectError(error.IoAmbiguous, ticket.commit());
            try std.testing.expect(stage.view().preparedWritesPoisoned());
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "tail.wal", lease, .{ .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqualStrings("cut", restart.view().get(.props, "old").?);
        try std.testing.expect(restart.view().get(.props, "new") == null);
        var ticket = try restart.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "whole" }});
        defer ticket.abort();
        try ticket.commit();
        var published = restart.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqualStrings("whole", published.get(.props, "new").?);
    }
}

test "cold recovery wrong owner cannot commit or abort another same generation stage" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "owner.wal");
        defer seed.deinit();
        try seed.put(.props, "old", "cut");
    }
    const lease = try tmp.dir.createFile(std.testing.io, "owner.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var first = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "owner.wal", lease, .{ .changefeed_capacity = 0 });
    defer first.deinit();
    var second = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "owner.wal", lease, .{ .changefeed_capacity = 0 });
    defer second.deinit();
    var a = try first.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "a", .value = "cut" }});
    defer a.abort();
    var b = try second.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "b", .value = "cut" }});
    defer b.abort();
    try std.testing.expectEqual(a.generation, b.generation);
    a.stage = &second;
    try std.testing.expectError(error.PreparedAlreadyConsumed, a.commit());
    a.abort();
    try std.testing.expect(second.backing.?.plan != null);
    a.stage = &first;
    b.abort();
    try a.commit();
    var published = first.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("cut", published.get(.props, "a").?);
    try std.testing.expect(published.get(.props, "b") == null);
}

test "cold recovery commit performs no allocation after prepared snapshot epoch packet and maps" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var seed = try openTestStore(tmp, "noalloc.wal");
            defer seed.deinit();
            const large: [1000]u8 = @splat(42);
            try seed.put(.props, "old", &large);
            if (empty) {
                try seed.snapshotAndTruncate();
                try seed.snapshotAndTruncate();
                try seed.wal_file.?.setLength(std.testing.io, 0);
            }
        }
        const lease = try tmp.dir.createFile(std.testing.io, "noalloc.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var stage = try ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "noalloc.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 4 });
        defer stage.deinit();
        var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "whole" }});
        defer ticket.abort();
        const allocations = failing.allocations;
        failing.fail_index = failing.alloc_index;
        try ticket.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqual(allocations, failing.allocations);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqualStrings("whole", published.get(.props, "new").?);
        try std.testing.expectEqualStrings("new", published.changeAt(published.changeCount() - 1).?.key);
    }
}

test "cold recovery abort named provisioning temporary never unlinks a substituted foreign inode" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Named-temp behavior is used by native BSD provisioning. Exercise it on
    // Linux too rather than vacuously skipping because Linux uses O_TMPFILE.
    var atomic = try tmp.dir.createFileAtomic(std.testing.io, "initial.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const identity = try cold_identity.statRegular(atomic.file.handle);
    const name = std.fmt.hex(atomic.file_basename_hex);
    const foreign = try tmp.dir.createFile(std.testing.io, "foreign", .{});
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try tmp.dir.rename("foreign", atomic.dir, &name, std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, validateColdAtomicName(std.testing.io, &atomic, identity));
    deinitColdAtomic(std.testing.io, &atomic, identity);
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("FOREIGN", bytes);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "initial.wal", .{}));
}
