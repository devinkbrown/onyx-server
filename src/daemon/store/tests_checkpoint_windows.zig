// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: checkpoint windows.

const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const cold_runtime = @import("../os_runtime.zig");
const ColdPublicationFault = @import("checkpoint.zig").ColdPublicationFault;
const ColdRecoveryStage = @import("checkpoint.zig").ColdRecoveryStage;
const FirstProvisionStage = @import("checkpoint.zig").FirstProvisionStage;
const coldCutDigest = @import("checkpoint.zig").coldCutDigest;
const validateColdPreparedWal = @import("checkpoint.zig").validateColdPreparedWal;
const BatchMutation = @import("contracts.zig").BatchMutation;
const StoreError = @import("contracts.zig").StoreError;
const cold_epoch_record_len = @import("contracts.zig").cold_epoch_record_len;
const record_header_len = @import("contracts.zig").record_header_len;
const OroStore = @import("engine.zig").OroStore;
const GetCurrentProcess = @import("native_files.zig").GetCurrentProcess;
const openColdExisting = @import("native_files.zig").openColdExisting;
const validateColdPreparedFile = @import("native_files.zig").validateColdPreparedFile;
const openTestStore = @import("tests_support.zig").openTestStore;
const readWalForTest = @import("tests_support.zig").readWalForTest;
const coldEpoch = @import("wal.zig").coldEpoch;

test "Windows first provision init holds a private lease without publishing files" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try lease.sync(std.testing.io);
    {
        var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        try std.testing.expect(stage.store.?.isReadOnly());
        try std.testing.expectError(StoreError.PreparedAlreadyConsumed, stage.commit());
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
    }
    try cold_identity.reaffirmExclusive(lease.handle);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
    var marker: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try lease.readPositionalAll(std.testing.io, &marker, 0));
    try std.testing.expectEqual(@as(u8, 'L'), marker[0]);
}

test "Windows first provision preparation keeps bytes on a held private temp until abort" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    var live = true;
    defer if (live) stage.deinit();
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const atomic = stage.atomic.?;
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    const writer = stage.store.?.wal_file.?;
    try std.testing.expect(stage.store.?.isReadOnly());
    try std.testing.expectEqualDeep(stage.atomic_identity.?, try cold_identity.statRegular(writer.handle));
    try std.testing.expectEqualDeep(stage.atomic_identity.?, try cold_identity.statRegular(atomic.file.handle));
    try std.testing.expectEqual(stage.store.?.active_batch.?.final_wal_offset, (try writer.stat(std.testing.io)).size);
    var epoch: [cold_epoch_record_len]u8 = undefined;
    try std.testing.expectEqual(epoch.len, try writer.readPositionalAll(std.testing.io, &epoch, 0));
    try std.testing.expectEqualSlices(u8, &stage.epoch, &epoch);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
    stage.deinit();
    live = false;
    try cold_identity.reaffirmExclusive(lease.handle);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
}

test "Windows first provision commit publishes held WAL and cold recovery replays it" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var stage = try FirstProvisionStage.init(failing.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const temp_name = std.fmt.hex(stage.atomic.?.file_basename_hex);
    failing.fail_index = failing.alloc_index;
    try stage.commit();
    failing.fail_index = std.math.maxInt(usize);
    var published = stage.takeCommittedStore();
    stage.deinit();
    try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
    try std.testing.expect(published.private_windows_files);
    try cold_runtime.requireExistingPrivateFileHandleWindows(published.wal_file.?);
    var transfer = try published.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    transfer.deinit();
    try published.put(.props, "later", "still safe");
    try published.snapshotAndTruncate();
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    published.deinit();
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    var cold = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    defer cold.deinit();
    try cold.validate();
    try std.testing.expectEqualStrings("cut", cold.view().get(.props, "new").?);
    try std.testing.expectEqualStrings("still safe", cold.view().get(.props, "later").?);
}

test "Windows first provision commit refuses a raced WAL without replacing it" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const temp_name = std.fmt.hex(stage.atomic.?.file_basename_hex);
    const foreign = try private.createFile(std.testing.io, "first.wal", .{});
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try std.testing.expectError(error.PathAlreadyExists, stage.commit());
    try std.testing.expect(stage.store.?.preparedWritesPoisoned());
    stage.deinit();
    const bytes = try private.readFileAlloc(std.testing.io, "first.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("FOREIGN", bytes);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    orphan.close(std.testing.io);
}

test "Windows first provision commit revalidates lease and snapshot before publish" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    var stage_live = true;
    errdefer if (stage_live) stage.deinit();
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const reopened = try openColdExisting(std.testing.io, private, "first.wal.lock", .read_write);
    stage.lease = reopened;
    try std.testing.expectError(error.WouldBlock, stage.commit());
    stage.lease = lease;
    reopened.close(std.testing.io);
    const snapshot = try private.createFile(std.testing.io, "first.wal.snap", .{});
    snapshot.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.commit());
    try private.deleteFile(std.testing.io, "first.wal.snap");
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    try stage.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    stage.deinit();
    stage_live = false;
    try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
}

test "Windows first provision commit poisons on a full temp identity mismatch" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    var live = true;
    defer if (live) stage.deinit();
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const temp_name = std.fmt.hex(stage.atomic.?.file_basename_hex);
    stage.atomic_identity.?.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.commit());
    try std.testing.expect(stage.store.?.preparedWritesPoisoned());
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    stage.atomic_identity.?.inode_high ^= 1;
    stage.deinit();
    live = false;
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
}

test "Windows first provision preparation refuses a reopened lease before temp creation" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    const reopened = try openColdExisting(std.testing.io, private, "first.wal.lock", .read_write);
    defer reopened.close(std.testing.io);
    stage.lease = reopened;
    try std.testing.expectError(error.WouldBlock, stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }}));
    try std.testing.expect(stage.atomic == null);
    try std.testing.expect(stage.store.?.active_batch == null);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
}

test "Windows first provision preparation allocation failures are inert and retryable" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    const mutations: []const BatchMutation = &.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }};
    var control = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var successful = try FirstProvisionStage.init(control.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    const before = control.alloc_index;
    try successful.prepareBatch(mutations);
    const allocation_count = control.alloc_index - before;
    successful.deinit();
    try std.testing.expect(allocation_count > 0);
    for (0..allocation_count) |offset| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
        var stage = try FirstProvisionStage.init(failing.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
        failing.fail_index = failing.alloc_index + offset;
        try std.testing.expectError(error.OutOfMemory, stage.prepareBatch(mutations));
        try std.testing.expect(stage.atomic == null);
        try std.testing.expect(stage.store.?.active_batch == null);
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        failing.fail_index = std.math.maxInt(usize);
        try stage.prepareBatch(mutations);
        try std.testing.expect(stage.atomic != null);
        stage.deinit();
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        try cold_identity.reaffirmExclusive(lease.handle);
    }
}

test "Windows first provision init rejects a broad parent with a private lease" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const created = try cold_runtime.createPrivateExclusiveWindows(tmp.dir, "first.wal.lock");
    created.close(std.testing.io);
    const lease = try openColdExisting(std.testing.io, tmp.dir, "first.wal.lock", .read_write);
    defer lease.close(std.testing.io);
    try cold_runtime.requireInheritedPrivateFileWindows(lease);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(error.InsecurePermissions, FirstProvisionStage.init(std.testing.allocator, std.testing.io, tmp.dir, "first.wal", lease, .{}));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "first.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "first.wal.snap", .read_only));
}

test "Windows first provision init rejects unlocked lease and leaves no namespace" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(error.WouldBlock, FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{}));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
}

test "Windows first provision init allocation failures leave only the held marker" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var control = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    {
        var stage = try FirstProvisionStage.init(control.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
        stage.deinit();
    }
    for (0..control.alloc_index) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, FirstProvisionStage.init(failing.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 }));
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
        try cold_identity.reaffirmExclusive(lease.handle);
    }
}

test "Windows cold recovery opens a captured read-only view and leaves preparation inert" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-read.wal");
        defer seed.deinit();
        try seed.put(.props, "original", "durable");
    }
    const before = try readWalForTest(tmp, "cold-read.wal");
    defer std.testing.allocator.free(before);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-read.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-read.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    try stage.validate();
    try std.testing.expect(stage.view().isReadOnly());
    try std.testing.expectEqualStrings("durable", stage.view().get(.props, "original").?);
    const mutation: BatchMutation = .{ .family = .props, .kind = .put, .key = "new", .value = "forbidden" };
    try std.testing.expectError(error.InsecurePermissions, stage.prepareBatch(&.{mutation}));
    try std.testing.expectError(error.InsecurePermissions, stage.prepareCompleteBatch(&.{mutation}));
    try std.testing.expect(stage.backing.?.plan == null);
    try std.testing.expect(stage.backing.?.store.active_batch == null);
    try stage.validate();
    const after = try readWalForTest(tmp, "cold-read.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "cold-read.wal.snap", .read_only));
}

test "Windows cold recovery detects high identity and namespace or byte tampering" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-tamper.wal");
        defer seed.deinit();
        try seed.put(.props, "original", "durable");
    }
    const original = try readWalForTest(tmp, "cold-tamper.wal");
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-tamper.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-tamper.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    const owned = stage.backing.?;
    const digest = owned.cut_digest;
    owned.wal.identity.inode_high ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &digest, &try coldCutDigest(owned)));
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
    owned.wal.identity.inode_high ^= 1;
    try stage.validate();

    const writer = try openColdExisting(std.testing.io, tmp.dir, "cold-tamper.wal", .read_write);
    try writer.writePositionalAll(std.testing.io, "X", 0);
    writer.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
    const restore = try openColdExisting(std.testing.io, tmp.dir, "cold-tamper.wal", .read_write);
    try restore.writePositionalAll(std.testing.io, original[0..1], 0);
    restore.close(std.testing.io);
    try stage.validate();

    try tmp.dir.rename("cold-tamper.wal", tmp.dir, "moved.wal", std.testing.io);
    const replacement = try tmp.dir.createFile(std.testing.io, "cold-tamper.wal", .{ .read = true });
    try replacement.writePositionalAll(std.testing.io, original, 0);
    replacement.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
}

test "Windows cold recovery allocation failures preserve the existing WAL" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-oom-read.wal");
        defer seed.deinit();
        try seed.put(.props, "original", "durable");
    }
    const before = try readWalForTest(tmp, "cold-oom-read.wal");
    defer std.testing.allocator.free(before);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-oom-read.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var result = ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "cold-oom-read.wal", lease, .{ .changefeed_capacity = 0 });
        if (result) |*stage| {
            defer stage.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try stage.validate();
            try std.testing.expectEqualStrings("durable", stage.view().get(.props, "original").?);
            break;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
        }
        const after = try readWalForTest(tmp, "cold-oom-read.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "cold-oom-read.wal.snap", .read_only));
    }
    try std.testing.expect(index > 0);
}

test "Windows cold recovery replays a covered snapshot and retains an unknown WAL tail" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-covered.wal");
        defer seed.deinit();
        try seed.put(.props, "covered", "snapshot state");
        try seed.snapshotAndTruncate();
        try seed.put(.props, "later", "WAL state");
    }
    const good_wal = try readWalForTest(tmp, "cold-covered.wal");
    defer std.testing.allocator.free(good_wal);
    const writer = try openColdExisting(std.testing.io, tmp.dir, "cold-covered.wal", .read_write);
    try writer.writePositionalAll(std.testing.io, "unknown tail", good_wal.len);
    writer.close(std.testing.io);
    const before = try readWalForTest(tmp, "cold-covered.wal");
    defer std.testing.allocator.free(before);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-covered.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-covered.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    try stage.validate();
    try std.testing.expectEqualStrings("snapshot state", stage.view().get(.props, "covered").?);
    try std.testing.expectEqualStrings("WAL state", stage.view().get(.props, "later").?);
    try std.testing.expectEqual(@as(u64, good_wal.len), stage.backing.?.valid_end);
    const after = try readWalForTest(tmp, "cold-covered.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    const snapshot = &stage.backing.?.snapshot.?;
    snapshot.identity.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
    snapshot.identity.inode_high ^= 1;
    try stage.validate();
    const snapshot_writer = try openColdExisting(std.testing.io, tmp.dir, "cold-covered.wal.snap", .read_write);
    try snapshot_writer.writePositionalAll(std.testing.io, "X", 0);
    snapshot_writer.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
}

test "Windows complete cold recovery publishes held private successors" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    {
        var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
        defer seed.deinit();
        try seed.put(.props, "old", "captured");
        try seed.snapshotAndTruncate();
        try seed.put(.props, "later", "held WAL");
    }
    const before = try private.readFileAlloc(std.testing.io, "state.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const snapshot_before = try private.readFileAlloc(std.testing.io, "state.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(snapshot_before);
    const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    {
        var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        var ordinary = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "prepared" }});
        ordinary.abort();
        var prepared = try stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "prepared" }});
        defer prepared.abort();
        const plan = &stage.backing.?.plan.?;
        const wal_temp = std.fmt.hex(plan.wal_atomic.?.file_basename_hex);
        const snapshot_temp = std.fmt.hex(plan.snapshot_atomic.?.file_basename_hex);
        try cold_runtime.requireExistingPrivateFileHandleWindows(plan.wal_atomic.?.file);
        try cold_runtime.requireExistingPrivateFileHandleWindows(plan.snapshot_atomic.?.file);
        try validateColdPreparedWal(stage.backing.?);
        try validateColdPreparedFile(std.testing.io, plan.snapshot_atomic.?.file, plan.snapshot_bytes.?, plan.snapshot_identity.?);
        try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_write));
        try stage.validate();
        const before_cut = try private.readFileAlloc(std.testing.io, "state.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before_cut);
        try std.testing.expectEqualSlices(u8, before, before_cut);
        try prepared.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expect(published.private_windows_files);
        try std.testing.expectEqualStrings("captured", published.get(.props, "old").?);
        try std.testing.expectEqualStrings("held WAL", published.get(.props, "later").?);
        try std.testing.expectEqualStrings("prepared", published.get(.props, "new").?);
        try cold_runtime.requireExistingPrivateFileHandleWindows(published.wal_file.?);
        var transfer = try published.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
        transfer.deinit();
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &wal_temp, .read_only));
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &snapshot_temp, .read_only));
        try published.put(.props, "after", "live writer");
        try published.snapshotAndTruncate();
    }
    const snapshot_after = try private.readFileAlloc(std.testing.io, "state.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(snapshot_after);
    try std.testing.expect(!std.mem.eql(u8, snapshot_before, snapshot_after));
    const private_snapshot = try cold_runtime.openExistingPrivateWindows(private, "state.wal.snap", .verify_only);
    private_snapshot.close(std.testing.io);
    var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
    defer restart.deinit();
    try std.testing.expectEqualStrings("captured", restart.view().get(.props, "old").?);
    try std.testing.expectEqualStrings("held WAL", restart.view().get(.props, "later").?);
    try std.testing.expectEqualStrings("prepared", restart.view().get(.props, "new").?);
    try std.testing.expectEqualStrings("live writer", restart.view().get(.props, "after").?);
}

test "Windows complete cold recovery selects covered empty WAL without replacing snapshot" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    {
        var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
        defer seed.deinit();
        try seed.put(.props, "old", "captured");
        try seed.snapshotAndTruncate();
        try seed.wal_file.?.setLength(std.testing.io, 0);
        try seed.wal_file.?.sync(std.testing.io);
    }
    const snapshot_before = try private.readFileAlloc(std.testing.io, "state.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(snapshot_before);
    const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    {
        var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        try std.testing.expect(stage.backing.?.selected_epoch != null);
        var prepared = try stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "prepared" }});
        defer prepared.abort();
        try std.testing.expect(stage.backing.?.plan.?.snapshot_atomic == null);
        try prepared.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqualStrings("captured", published.get(.props, "old").?);
        try std.testing.expectEqualStrings("prepared", published.get(.props, "new").?);
    }
    const snapshot_after = try private.readFileAlloc(std.testing.io, "state.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(snapshot_after);
    try std.testing.expectEqualSlices(u8, snapshot_before, snapshot_after);
    var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
    defer restart.deinit();
    try std.testing.expectEqualStrings("captured", restart.view().get(.props, "old").?);
    try std.testing.expectEqualStrings("prepared", restart.view().get(.props, "new").?);
}

test "Windows complete cold recovery rejects a permissive snapshot before capture" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    {
        var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
        defer seed.deinit();
        try seed.put(.props, "old", "captured");
        try seed.snapshotAndTruncate();
        try seed.wal_file.?.setLength(std.testing.io, 0);
        try seed.wal_file.?.sync(std.testing.io);
    }
    const snapshot_bytes = try private.readFileAlloc(std.testing.io, "state.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(snapshot_bytes);
    try private.deleteFile(std.testing.io, "state.wal.snap");
    const permissive = try private.createFile(std.testing.io, "state.wal.snap", .{ .read = true });
    try permissive.writePositionalAll(std.testing.io, snapshot_bytes, 0);
    try permissive.sync(std.testing.io);
    permissive.close(std.testing.io);
    try std.testing.expectError(error.InsecurePermissions, cold_runtime.openExistingPrivateWindows(private, "state.wal.snap", .verify_only));
    const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(error.InsecurePermissions, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 }));
    const unchanged = try private.readFileAlloc(std.testing.io, "state.wal.snap", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(unchanged);
    try std.testing.expectEqualSlices(u8, snapshot_bytes, unchanged);
}

test "Windows cold recovery checks nested private parent before captured WAL bytes" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    {
        var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
        defer seed.deinit();
        try seed.put(.props, "old", "captured");
    }
    const original = try private.readFileAlloc(std.testing.io, "state.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    try private.deleteFile(std.testing.io, "state.wal");
    const permissive = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try permissive.writePositionalAll(std.testing.io, original, 0);
    try permissive.sync(std.testing.io);
    permissive.close(std.testing.io);
    try std.testing.expectError(error.InsecurePermissions, cold_runtime.openExistingPrivateWindows(private, "state.wal", .verify_only));
    const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(error.InsecurePermissions, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", lease, .{ .changefeed_capacity = 0 }));
}

test "Windows ordinary cold recovery retires unknown WAL tail through whole successor" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |fault_before_wal| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
        defer private.close(std.testing.io);
        {
            var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
            defer seed.deinit();
            try seed.put(.props, "old", "accepted");
        }
        const writer = try openColdExisting(std.testing.io, private, "state.wal", .read_write);
        const end = (try writer.stat(std.testing.io)).size;
        try writer.writePositionalAll(std.testing.io, "unknown tail", end);
        try writer.sync(std.testing.io);
        writer.close(std.testing.io);
        const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
        try lease.writePositionalAll(std.testing.io, "L", 0);
        if (fault_before_wal) {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
            defer stage.deinit();
            try std.testing.expect(stage.backing.?.valid_end < stage.backing.?.wal.bytes.len);
            try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "recovered" }}));
            var prepared = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "recovered" }});
            defer prepared.abort();
            try std.testing.expect(stage.backing.?.plan.?.complete_epoch);
            stage.setPublicationFault(.wal_replace);
            try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
        }
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
            defer stage.deinit();
            try std.testing.expectEqualStrings("accepted", stage.view().get(.props, "old").?);
            try std.testing.expect(stage.view().get(.props, "new") == null);
            try std.testing.expect(stage.backing.?.valid_end < stage.backing.?.wal.bytes.len);
            var prepared = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "recovered" }});
            defer prepared.abort();
            try prepared.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("accepted", published.get(.props, "old").?);
            try std.testing.expectEqualStrings("recovered", published.get(.props, "new").?);
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqualStrings("accepted", restart.view().get(.props, "old").?);
        try std.testing.expectEqualStrings("recovered", restart.view().get(.props, "new").?);
        try std.testing.expectEqual(restart.backing.?.wal.bytes.len, restart.backing.?.valid_end);
    }
}

test "Windows ordinary cold recovery replaces malformed first record without an old snapshot" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |truncated_epoch| {
        for ([_]ColdPublicationFault{ .wal_replace, .wal_dir_sync }) |fault| {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
            defer private.close(std.testing.io);
            const epoch = coldEpoch(@splat(7));
            const malformed: []const u8 = if (truncated_epoch) epoch[0 .. record_header_len + 1] else "partial";
            const file = try cold_runtime.createPrivateExclusiveWindows(private, "state.wal");
            try file.writePositionalAll(std.testing.io, malformed, 0);
            try file.sync(std.testing.io);
            file.close(std.testing.io);
            const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
            defer lease.close(std.testing.io);
            try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
            try lease.writePositionalAll(std.testing.io, "L", 0);
            {
                var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
                defer stage.deinit();
                try std.testing.expectEqual(@as(u64, 0), stage.backing.?.valid_end);
                try std.testing.expect(!stage.view().wal_epoch_known);
                try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "recovered" }}));
                var prepared = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "recovered" }});
                defer prepared.abort();
                try std.testing.expect(stage.backing.?.plan.?.snapshot_atomic == null);
                stage.setPublicationFault(fault);
                try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
            }
            {
                var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
                defer restart.deinit();
                if (fault == .wal_replace) {
                    try std.testing.expect(restart.view().get(.props, "new") == null);
                    try std.testing.expectEqual(@as(u64, 0), restart.backing.?.valid_end);
                    var retry = try restart.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "recovered" }});
                    defer retry.abort();
                    try retry.commit();
                    var published = restart.takeCommittedStore();
                    defer published.deinit();
                    try std.testing.expectEqualStrings("recovered", published.get(.props, "new").?);
                } else {
                    try std.testing.expectEqualStrings("recovered", restart.view().get(.props, "new").?);
                }
            }
            var final = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
            defer final.deinit();
            try std.testing.expectEqualStrings("recovered", final.view().get(.props, "new").?);
            try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "state.wal.snap", .read_only));
        }
    }
}

test "Windows complete cold recovery publication faults restart on whole old or new epoch" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    for ([_]ColdPublicationFault{ .snapshot_replace, .snapshot_dir_sync, .wal_replace, .wal_dir_sync }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
        defer private.close(std.testing.io);
        {
            var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
            defer seed.deinit();
            try seed.put(.props, "old", "captured");
        }
        const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
        try lease.writePositionalAll(std.testing.io, "L", 0);
        var old_next: u64 = undefined;
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
            defer stage.deinit();
            old_next = stage.view().next_seq;
            var prepared = try stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "prepared" }});
            defer prepared.abort();
            stage.setPublicationFault(fault);
            try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
            try std.testing.expect(stage.backing.?.consumed);
            try std.testing.expect(stage.view().preparedWritesPoisoned());
            try std.testing.expect(stage.backing.?.store.active_batch == null);
            try std.testing.expect(stage.backing.?.plan.?.complete_record != null);
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqualStrings("captured", restart.view().get(.props, "old").?);
        if (fault == .wal_dir_sync) {
            try std.testing.expectEqualStrings("prepared", restart.view().get(.props, "new").?);
            try std.testing.expectEqual(old_next + 1, restart.view().next_seq);
        } else {
            try std.testing.expect(restart.view().get(.props, "new") == null);
            try std.testing.expectEqual(old_next, restart.view().next_seq);
        }
        try std.testing.expectEqual(restart.backing.?.wal.bytes.len, restart.backing.?.valid_end);
    }
}

test "Windows complete cold recovery refuses tampered held successor before publication" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    {
        var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
        defer seed.deinit();
        try seed.put(.props, "old", "captured");
    }
    const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    var prepared = try stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "prepared" }});
    defer prepared.abort();
    const plan = &stage.backing.?.plan.?;
    const end = (try plan.writer.stat(std.testing.io)).size - 1;
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try plan.writer.readPositionalAll(std.testing.io, &byte, end));
    const original = byte[0];
    byte[0] ^= 1;
    try plan.writer.writePositionalAll(std.testing.io, &byte, end);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, prepared.commit());
    try std.testing.expect(!stage.backing.?.consumed);
    byte[0] = original;
    try plan.writer.writePositionalAll(std.testing.io, &byte, end);
    try plan.writer.sync(std.testing.io);
    try prepared.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("prepared", published.get(.props, "new").?);
}

test "Windows complete cold recovery preparation allocation failures retry without publication" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    {
        var seed = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/state.wal", .{});
        defer seed.deinit();
        try seed.put(.props, "old", "captured");
    }
    const before = try private.readFileAlloc(std.testing.io, "state.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const lease = try private.createFile(std.testing.io, "state.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    const mutations: []const BatchMutation = &.{.{ .family = .props, .kind = .put, .key = "new", .value = "prepared" }};
    var control = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var success = try ColdRecoveryStage.open(control.allocator(), std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
    const start = control.alloc_index;
    var successful = try success.prepareCompleteBatch(mutations);
    const allocation_count = control.alloc_index - start;
    successful.abort();
    success.deinit();
    try std.testing.expect(allocation_count > 0);
    for (0..allocation_count) |offset| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
        var stage = try ColdRecoveryStage.open(failing.allocator(), std.testing.io, private, "state.wal", lease, .{ .changefeed_capacity = 0 });
        failing.fail_index = failing.alloc_index + offset;
        try std.testing.expectError(error.OutOfMemory, stage.prepareCompleteBatch(mutations));
        try std.testing.expect(stage.backing.?.plan == null);
        try std.testing.expect(stage.backing.?.store.active_batch == null);
        failing.fail_index = std.math.maxInt(usize);
        var retry = try stage.prepareCompleteBatch(mutations);
        retry.abort();
        stage.deinit();
        try cold_identity.reaffirmExclusive(lease.handle);
        const after = try private.readFileAlloc(std.testing.io, "state.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "state.wal.snap", .read_only));
        const listing = try private.openDir(std.testing.io, ".", .{ .iterate = true });
        defer listing.close(std.testing.io);
        var entries = listing.iterate();
        var count: usize = 0;
        while (try entries.next(std.testing.io)) |entry| {
            try std.testing.expect(std.mem.eql(u8, entry.name, "state.wal") or std.mem.eql(u8, entry.name, "state.wal.lock"));
            count += 1;
        }
        try std.testing.expectEqual(@as(usize, 2), count);
    }
}
