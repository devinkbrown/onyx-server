// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: windows store.

const std = @import("std");
const cold_runtime = @import("../os_runtime.zig");
const StoreError = @import("contracts.zig").StoreError;
const OroStore = @import("engine.zig").OroStore;
const DuplicateHandle = @import("native_files.zig").DuplicateHandle;
const GetCurrentProcess = @import("native_files.zig").GetCurrentProcess;
const GetCurrentProcessId = @import("native_files.zig").GetCurrentProcessId;
const WindowsWalDescriptor = @import("native_files.zig").WindowsWalDescriptor;
const windowsWalWitness = @import("native_files.zig").windowsWalWitness;

test "Windows private account store rejects broad parent before creating WAL" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "broad", .default_dir);
    // A normal temp directory inherits the ordinary user profile ACL. Give
    // the gate an explicit private SDDL in the positive test below.
    const result = OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "broad/accounts.wal", .{});
    if (result) |store| {
        var unexpected = store;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.InsecurePermissions, err);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "broad/accounts.wal", .{}));
}

test "Windows private directory handle pins file creation across path replacement" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    try cold_runtime.protectEmptyDirectoryWindows(std.testing.io, tmp.dir, "private");
    const pinned = try cold_runtime.openPrivateDirectoryWindows(std.testing.io, tmp.dir, "private");
    defer pinned.close(std.testing.io);
    try tmp.dir.rename("private", tmp.dir, "moved", std.testing.io);
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    const file = try pinned.createFile(std.testing.io, "bound.txt", .{});
    file.close(std.testing.io);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "private/bound.txt", .{}));
    const bound = try tmp.dir.openFile(std.testing.io, "moved/bound.txt", .{});
    bound.close(std.testing.io);
}

test "Windows private account store protects WAL and compacted snapshot across restart" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Match production setup: the private inheritable DACL is present at
    // directory creation, which can yield a child DACL without the AI flag.
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    try cold_runtime.requirePrivateDirectoryWindows(std.testing.io, tmp.dir, "private/accounts.wal");
    {
        const broad_snapshot = try tmp.dir.createFile(std.testing.io, "broad.snap", .{ .read = true });
        broad_snapshot.close(std.testing.io);
    }
    try tmp.dir.rename("broad.snap", tmp.dir, "private/accounts.wal.snap", std.testing.io);

    {
        var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
        defer store.deinit();
        try store.put(.accounts, "alice", "secret account state");
        try store.snapshotAndTruncate();
        const backup_bytes = try store.readPrivateSnapshotAllocWindows(std.testing.allocator, 512 * 1024 * 1024);
        defer std.testing.allocator.free(backup_bytes);
        try std.testing.expect(std.mem.indexOf(u8, backup_bytes, "secret account state") != null);
    }
    {
        const wal = try cold_runtime.openExistingPrivateWindows(tmp.dir, "private/accounts.wal", .verify_only);
        wal.close(std.testing.io);
        const snapshot = try cold_runtime.openExistingPrivateWindows(tmp.dir, "private/accounts.wal.snap", .verify_only);
        snapshot.close(std.testing.io);
    }
    var recovered = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer recovered.deinit();
    try std.testing.expectEqualStrings("secret account state", recovered.get(.accounts, "alice").?);
    try recovered.put(.accounts, "bob", "second persisted account");
}

test "Windows private compaction publishes snapshot before injected WAL refusal" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    {
        var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
        defer store.deinit();
        try store.put(.accounts, "alice", "retained");
        const length: usize = @intCast(store.wal_offset);
        const before = try std.testing.allocator.alloc(u8, length);
        defer std.testing.allocator.free(before);
        try std.testing.expectEqual(length, try store.wal_file.?.readPositionalAll(std.testing.io, before, 0));
        store.setPreparedIoFault(.{ .wal_sync = true });
        try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectEqual(@as(u64, length), (try store.wal_file.?.stat(std.testing.io)).size);
        const after = try std.testing.allocator.alloc(u8, length);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqual(length, try store.wal_file.?.readPositionalAll(std.testing.io, after, 0));
        try std.testing.expectEqualSlices(u8, before, after);
    }
    var reopened = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer reopened.deinit();
    try std.testing.expectEqualStrings("retained", reopened.get(.accounts, "alice").?);
}

test "Windows private held WAL replay returns exact row and rejects a torn tail" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/mail.wal", .{});
    defer store.deinit();
    try store.put(.props, "baseline", "snapshot row");
    try store.snapshotAndTruncate();
    try store.put(.props, "mailfail:1", "ConnectFailed recipient");
    const exact = (try store.replayHeldPrivateWindowsValueAlloc(std.testing.allocator, .props, "mailfail:1")) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(exact);
    try std.testing.expectEqualStrings("ConnectFailed recipient", exact);
    const baseline = (try store.replayHeldPrivateWindowsValueAlloc(std.testing.allocator, .props, "baseline")) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(baseline);
    try std.testing.expectEqualStrings("snapshot row", baseline);
    try store.wal_file.?.writePositionalAll(std.testing.io, &.{ 1, 2, 3 }, store.wal_offset);
    try std.testing.expectError(StoreError.BadRecord, store.replayHeldPrivateWindowsValueAlloc(std.testing.allocator, .props, "mailfail:1"));
}

test "Windows private account store refuses a retained reader before ACL remediation" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    try cold_runtime.protectEmptyDirectoryWindows(std.testing.io, tmp.dir, "private");
    {
        const broad = try tmp.dir.createFile(std.testing.io, "broad.wal", .{ .read = true });
        broad.close(std.testing.io);
    }
    try tmp.dir.rename("broad.wal", tmp.dir, "private/accounts.wal", std.testing.io);
    const reader = try tmp.dir.openFile(std.testing.io, "private/accounts.wal", .{ .mode = .read_only });
    try std.testing.expectError(error.FileBusy, OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}));
    reader.close(std.testing.io);
    var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    store.deinit();
    const secured = try cold_runtime.openExistingPrivateWindows(tmp.dir, "private/accounts.wal", .verify_only);
    secured.close(std.testing.io);
}

test "Windows private account store rejects a WAL file reparse point" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    try cold_runtime.protectEmptyDirectoryWindows(std.testing.io, tmp.dir, "private");
    const target = try tmp.dir.createFile(std.testing.io, "broad.wal", .{});
    target.close(std.testing.io);
    tmp.dir.symLink(std.testing.io, "../broad.wal", "private/accounts.wal", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.InsecurePermissions, OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}));
}

test "Windows transferred private WAL stages read-only and promotes the held HANDLE after parent release" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var parent = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    var parent_live = true;
    defer if (parent_live) parent.deinit();
    try parent.put(.accounts, "alice", "retained");

    var transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer transfer.deinit();
    var descriptor = transfer.release();
    defer descriptor.deinitReceived();
    var stage = try OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &descriptor);
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    try std.testing.expectEqual(@as(usize, 0), descriptor.handle);
    try std.testing.expect(stage.isReadOnly());
    try std.testing.expectEqualStrings("retained", stage.get(.accounts, "alice").?);
    try std.testing.expectError(StoreError.ReadOnlyStore, stage.put(.accounts, "alice", "too early"));
    try std.testing.expectError(StoreError.ReadOnlyStore, stage.preparePut(.accounts, "alice", "too early"));
    try stage.preparePromotion();
    try stage.releaseReadHandleForPreparedPromotion();
    try std.testing.expect(stage.isReadOnly());
    try std.testing.expectError(StoreError.ReadOnlyStore, stage.put(.accounts, "alice", "still early"));

    parent.deinit();
    parent_live = false;
    stage.promotePrepared();
    try stage.put(.accounts, "bob", "after commit");
    stage.deinit();
    stage_live = false;
    var recovered = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer recovered.deinit();
    try std.testing.expectEqualStrings("retained", recovered.get(.accounts, "alice").?);
    try std.testing.expectEqualStrings("after commit", recovered.get(.accounts, "bob").?);
}

test "Windows transferred private WAL rejects wrong file, directory, length, and aborts without changing parent" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    const other = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "other");
    other.close(std.testing.io);
    var parent = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer parent.deinit();
    try parent.put(.accounts, "alice", "before");
    var foreign = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/foreign.wal", .{});
    defer foreign.deinit();
    try foreign.put(.accounts, "mallory", "foreign");

    var wrong_file_transfer = try foreign.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer wrong_file_transfer.deinit();
    var wrong_file = wrong_file_transfer.release();
    defer wrong_file.deinitReceived();
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &wrong_file));
    try std.testing.expectEqual(@as(usize, 0), wrong_file.handle);

    var wrong_dir_transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer wrong_dir_transfer.deinit();
    var wrong_dir = wrong_dir_transfer.release();
    defer wrong_dir.deinitReceived();
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "other/accounts.wal", .{}, &wrong_dir));
    try std.testing.expectEqual(@as(usize, 0), wrong_dir.handle);

    var wrong_length_transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer wrong_length_transfer.deinit();
    var wrong_length = wrong_length_transfer.release();
    defer wrong_length.deinitReceived();
    wrong_length.witness.length += 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &wrong_length));
    try std.testing.expectEqual(@as(usize, 0), wrong_length.handle);

    var read_only_handle: usize = 0;
    const process = GetCurrentProcess();
    try std.testing.expect(DuplicateHandle(process, @intFromPtr(parent.wal_file.?.handle), process, &read_only_handle, 0x8000_0000, 0, 0) != 0);
    var read_only = WindowsWalDescriptor{ .handle = read_only_handle, .destination_pid = GetCurrentProcessId(), .witness = try windowsWalWitness(std.testing.io, parent.wal_file.?, parent.dir, parent.wal_path) };
    defer read_only.deinitReceived();
    try std.testing.expectError(error.PermissionDenied, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &read_only));
    try std.testing.expectEqual(@as(usize, 0), read_only.handle);

    var abort_transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer abort_transfer.deinit();
    var abort_descriptor = abort_transfer.release();
    defer abort_descriptor.deinitReceived();
    var stage = try OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &abort_descriptor);
    try parent.put(.accounts, "bob", "parent survived");
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.preparePromotion());
    stage.deinit();
    try parent.put(.accounts, "charlie", "still writing");
    try std.testing.expectEqualStrings("still writing", parent.get(.accounts, "charlie").?);
}

test "Windows transferred private WAL allocation failures close candidate custody and leave parent bytes intact" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var parent = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer parent.deinit();
    try parent.put(.accounts, "alice", "unchanged");
    const size: usize = @intCast(parent.wal_offset);
    const before = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(before);
    const after = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqual(size, try parent.wal_file.?.readPositionalAll(std.testing.io, before, 0));

    var completed = false;
    for (0..128) |fail_index| {
        var transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
        defer transfer.deinit();
        var descriptor = transfer.release();
        defer descriptor.deinitReceived();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        const result = OroStore.openTransferredPrivateWindowsWithConfig(failing.allocator(), std.testing.io, tmp.dir, "private/accounts.wal", .{}, &descriptor);
        if (result) |opened| {
            var stage = opened;
            try std.testing.expect(stage.isReadOnly());
            try std.testing.expectEqualStrings("unchanged", stage.get(.accounts, "alice").?);
            stage.deinit();
            completed = true;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
        try std.testing.expectEqual(@as(usize, 0), descriptor.handle);
        try std.testing.expectEqual(@as(u64, size), parent.wal_offset);
        try std.testing.expectEqual(size, try parent.wal_file.?.readPositionalAll(std.testing.io, after, 0));
        try std.testing.expectEqualSlices(u8, before, after);
        if (completed) break;
    }
    try std.testing.expect(completed);
    try parent.put(.accounts, "bob", "parent remained writable");
}
