// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: native windows.

const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const cold_runtime = @import("../os_runtime.zig");
const ColdRecoveryStage = @import("checkpoint.zig").ColdRecoveryStage;
const FirstProvisionStage = @import("checkpoint.zig").FirstProvisionStage;
const StoreError = @import("contracts.zig").StoreError;
const CreateHardLinkW = @import("native_files.zig").CreateHardLinkW;
const coldDirectoryIdentity = @import("native_files.zig").coldDirectoryIdentity;
const deinitColdAtomic = @import("native_files.zig").deinitColdAtomic;
const makeColdAtomicReadable = @import("native_files.zig").makeColdAtomicReadable;
const openColdAtomicWindows = @import("native_files.zig").openColdAtomicWindows;
const openColdExisting = @import("native_files.zig").openColdExisting;
const renameHeldColdAtomicWindows = @import("native_files.zig").renameHeldColdAtomicWindows;
const validateColdLease = @import("native_files.zig").validateColdLease;
const validateColdParent = @import("native_files.zig").validateColdParent;
const windowsColdAtomicIdentity = @import("native_files.zig").windowsColdAtomicIdentity;

test "Windows cold existing file modes preserve bytes on open and permit writes" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const created = try tmp.dir.createFile(std.testing.io, "existing.wal", .{ .read = true });
    try created.writePositionalAll(std.testing.io, "before", 0);
    created.close(std.testing.io);

    const reader = try openColdExisting(std.testing.io, tmp.dir, "existing.wal", .read_only);
    defer reader.close(std.testing.io);
    try std.testing.expect(reader.flags.nonblocking);
    var bytes: [6]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 6), try reader.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("before", &bytes);

    const writer = try openColdExisting(std.testing.io, tmp.dir, "existing.wal", .read_write);
    defer writer.close(std.testing.io);
    try std.testing.expect(writer.flags.nonblocking);
    try std.testing.expectEqual(@as(u64, 6), (try writer.stat(std.testing.io)).size);
    try writer.writePositionalAll(std.testing.io, "after!", 0);
    try std.testing.expectEqual(@as(usize, 6), try reader.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("after!", &bytes);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "missing.wal", .read_write));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "missing.wal", .{}));
}

test "Windows cold directory identity is stable and types are checked" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try tmp.dir.createDir(std.testing.io, "other", .default_dir);
    const regular = try tmp.dir.createFile(std.testing.io, "plain", .{});
    regular.close(std.testing.io);
    const first = try openColdExisting(std.testing.io, tmp.dir, "state", .directory);
    defer first.close(std.testing.io);
    const second = try openColdExisting(std.testing.io, tmp.dir, "state", .directory);
    defer second.close(std.testing.io);
    const other = try openColdExisting(std.testing.io, tmp.dir, "other", .directory);
    defer other.close(std.testing.io);
    try std.testing.expect(first.flags.nonblocking);
    try std.testing.expectEqualDeep(try coldDirectoryIdentity(first.handle), try coldDirectoryIdentity(second.handle));
    try std.testing.expect(!std.meta.eql(try coldDirectoryIdentity(first.handle), try coldDirectoryIdentity(other.handle)));
    try std.testing.expectError(error.NotDir, openColdExisting(std.testing.io, tmp.dir, "plain", .directory));
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "state", .read_only));
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "state", .read_write));
}

test "Windows cold existing refuses file and directory reparse points" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target = try tmp.dir.createFile(std.testing.io, "target.wal", .{});
    target.close(std.testing.io);
    try tmp.dir.createDir(std.testing.io, "target-dir", .default_dir);
    tmp.dir.symLink(std.testing.io, "target.wal", "file-link.wal", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "file-link.wal", .read_only));
    tmp.dir.symLink(std.testing.io, "target-dir", "dir-link", .{ .is_directory = true }) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.NotDir, openColdExisting(std.testing.io, tmp.dir, "dir-link", .directory));
}

test "Windows cold existing refuses hardlink alias" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target = try tmp.dir.createFile(std.testing.io, "target.wal", .{});
    target.close(std.testing.io);
    const target_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/target.wal", .{&tmp.sub_path});
    defer std.testing.allocator.free(target_path);
    const alias_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/alias.wal", .{&tmp.sub_path});
    defer std.testing.allocator.free(alias_path);
    const target_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, target_path);
    defer std.testing.allocator.free(target_w);
    const alias_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, alias_path);
    defer std.testing.allocator.free(alias_w);
    try std.testing.expect(CreateHardLinkW(alias_w.ptr, target_w.ptr, null) != 0);
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "alias.wal", .read_only));
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "target.wal", .read_write));
}

test "Windows cold existing rejects alternate data streams without changing base file" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const created = try tmp.dir.createFile(std.testing.io, "target.wal", .{});
    try created.writePositionalAll(std.testing.io, "base", 0);
    created.close(std.testing.io);
    const absolute = try tmp.dir.realPathFileAlloc(std.testing.io, "target.wal", std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const accepted = try openColdExisting(std.testing.io, .cwd(), absolute, .read_only);
    accepted.close(std.testing.io);
    const stream = try std.fmt.allocPrint(std.testing.allocator, "{s}:alternate", .{absolute});
    defer std.testing.allocator.free(stream);
    try std.testing.expectError(error.BadPathName, openColdExisting(std.testing.io, tmp.dir, "target.wal:alternate", .read_only));
    try std.testing.expectError(error.BadPathName, openColdExisting(std.testing.io, .cwd(), stream, .read_write));
    try std.testing.expectError(error.BadPathName, openColdExisting(std.testing.io, tmp.dir, "missing.wal:alternate", .read_write));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "missing.wal", .{}));
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "target.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("base", bytes);
}

test "Windows cold parent validation binds held and configured directories before effects" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try tmp.dir.createDir(std.testing.io, "foreign", .default_dir);
    const held = try openColdExisting(std.testing.io, tmp.dir, "state", .directory);
    defer held.close(std.testing.io);
    const wrong = try openColdExisting(std.testing.io, tmp.dir, "foreign", .directory);
    defer wrong.close(std.testing.io);
    const expected = try coldDirectoryIdentity(held.handle);
    try validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, expected, null);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", wrong, expected, null));
    var foreign_atomic = try tmp.dir.createFileAtomic(std.testing.io, "foreign/custody.wal", .{ .replace = true });
    defer foreign_atomic.deinit(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, expected, &foreign_atomic));
    var wrong_high = expected;
    wrong_high.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, wrong_high, null));
    try tmp.dir.rename("state", tmp.dir, "previous", std.testing.io);
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, expected, null));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "state/custody.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "previous/custody.wal", .read_only));
}

test "Windows cold lease accepts only the local locked marker handle at its path" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try tmp.dir.createFile(std.testing.io, "custody.wal.lock", .{ .read = true });
    defer owner.close(std.testing.io);
    try std.testing.expect(try owner.tryLock(std.testing.io, .exclusive));
    try owner.writePositionalAll(std.testing.io, "L", 0);
    const identity = try cold_identity.statRegular(owner.handle);
    try validateColdLease(std.testing.io, tmp.dir, owner, "custody.wal.lock", identity);
    try std.testing.expectError(error.InsecurePermissions, FirstProvisionStage.init(std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", owner, .{}));
    try std.testing.expectError(error.FileNotFound, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", owner, .{}));
    const reopened = try openColdExisting(std.testing.io, tmp.dir, "custody.wal.lock", .read_write);
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, validateColdLease(std.testing.io, tmp.dir, reopened, "custody.wal.lock", identity));
    const foreign = try tmp.dir.createFile(std.testing.io, "foreign.wal.lock", .{ .read = true });
    defer foreign.close(std.testing.io);
    try foreign.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdLease(std.testing.io, tmp.dir, owner, "foreign.wal.lock", identity));
    var wrong_high = identity;
    wrong_high.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdLease(std.testing.io, tmp.dir, owner, "custody.wal.lock", wrong_high));
    var marker: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try owner.readPositionalAll(std.testing.io, &marker, 0));
    try std.testing.expectEqual(@as(u8, 'L'), marker[0]);
}

test "Windows cold lease rejects an unlocked marker without changing it" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const unlocked = try tmp.dir.createFile(std.testing.io, "unlocked.wal.lock", .{ .read = true });
    defer unlocked.close(std.testing.io);
    try unlocked.writePositionalAll(std.testing.io, "L", 0);
    const identity = try cold_identity.statRegular(unlocked.handle);
    try std.testing.expectError(error.WouldBlock, validateColdLease(std.testing.io, tmp.dir, unlocked, "unlocked.wal.lock", identity));
    var marker: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try unlocked.readPositionalAll(std.testing.io, &marker, 0));
    try std.testing.expectEqual(@as(u8, 'L'), marker[0]);
}

test "Windows private cold atomic becomes readable and duplicate survives original close" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const identity = try cold_identity.statRegular(atomic.file.handle);
    const name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "private record", 0);
    const copy = try cold_runtime.duplicateFile(atomic.file);
    try std.testing.expectEqualDeep(identity, try cold_identity.statRegular(copy.handle));
    atomic.file.close(std.testing.io);
    atomic.file_open = false;
    var bytes: [14]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try copy.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("private record", &bytes);
    copy.close(std.testing.io);
    deinitColdAtomic(std.testing.io, &atomic, identity);
    try std.testing.expectError(error.FileNotFound, private.openFile(std.testing.io, &name, .{}));
    try std.testing.expectError(error.FileNotFound, private.openFile(std.testing.io, "state.wal", .{}));
}

test "Windows cold atomic abort removes own write-only temp before readable reopen" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const name = std.fmt.hex(atomic.file_basename_hex);
    deinitColdAtomic(std.testing.io, &atomic, null);
    try std.testing.expectError(error.FileNotFound, private.openFile(std.testing.io, &name, .{}));
}

test "Windows cold atomic refuses broad parent before secret bytes" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var atomic = try tmp.dir.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const name = std.fmt.hex(atomic.file_basename_hex);
    try std.testing.expectError(error.InsecurePermissions, makeColdAtomicReadable(std.testing.io, &atomic));
    deinitColdAtomic(std.testing.io, &atomic, null);
    // A failed private-parent proof deliberately leaves only an empty temp;
    // std's name-based cleanup is forbidden on this path.
    const empty = try tmp.dir.openFile(std.testing.io, &name, .{});
    defer empty.close(std.testing.io);
    try std.testing.expectEqual(@as(u64, 0), (try empty.stat(std.testing.io)).size);
}

test "Windows cold atomic abort preserves a substituted foreign name" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const identity = try cold_identity.statRegular(atomic.file.handle);
    const name = std.fmt.hex(atomic.file_basename_hex);
    atomic.file.close(std.testing.io);
    atomic.file_open = false;
    try private.rename(&name, private, "owned-away", std.testing.io);
    const foreign = try private.createFile(std.testing.io, &name, .{});
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    deinitColdAtomic(std.testing.io, &atomic, identity);
    const bytes = try private.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("FOREIGN", bytes);
}

test "Windows cold atomic nofollow reopen rejects a substituted reparse name" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const identity = try windowsColdAtomicIdentity(atomic.file.handle);
    defer deinitColdAtomic(std.testing.io, &atomic, identity);
    const name = std.fmt.hex(atomic.file_basename_hex);
    atomic.file.close(std.testing.io);
    atomic.file_open = false;
    try private.rename(&name, private, "owned-away", std.testing.io);
    private.symLink(std.testing.io, "owned-away", &name, .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.NotRegular, openColdAtomicWindows(std.testing.io, &atomic));
    const owned = try private.openFile(std.testing.io, "owned-away", .{});
    owned.close(std.testing.io);
}

test "Windows cold atomic failed readable reopen leaves no foreign deletion" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const name = std.fmt.hex(atomic.file_basename_hex);
    const copy = try cold_runtime.duplicateFile(atomic.file);
    try std.testing.expectError(error.FileBusy, makeColdAtomicReadable(std.testing.io, &atomic));
    try std.testing.expect(!atomic.file_exists);
    copy.close(std.testing.io);
    deinitColdAtomic(std.testing.io, &atomic, null);
    const orphan = try private.openFile(std.testing.io, &name, .{});
    orphan.close(std.testing.io);
}

test "Windows held cold atomic rename publishes exact file and retains exclusive duplicate" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    const writer = try cold_runtime.duplicateFile(atomic.file);
    try renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, false);
    try std.testing.expect(!atomic.file_exists);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    try writer.writePositionalAll(std.testing.io, "!", 3);
    writer.close(std.testing.io);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(installed.handle));
    var bytes: [4]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try installed.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("NEW!", &bytes);
}

test "Windows held cold atomic rename requires a write-through source handle" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const file_id = try windowsColdAtomicIdentity(atomic.file.handle);
    defer deinitColdAtomic(std.testing.io, &atomic, file_id);
    try std.testing.expectError(error.Unsupported, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, false));
    try std.testing.expect(atomic.file_exists);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "state.wal", .read_only));
}

test "Windows held cold atomic replacement keeps old destination handle readable" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const old = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try old.writePositionalAll(std.testing.io, "OLD", 0);
    old.close(std.testing.io);
    const old_reader = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer old_reader.close(std.testing.io);
    const old_id = try cold_identity.statRegular(old_reader.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    const writer = try cold_runtime.duplicateFile(atomic.file);
    try renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true);
    try std.testing.expect(!atomic.file_exists);
    var old_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(old_bytes.len, try old_reader.readPositionalAll(std.testing.io, &old_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &old_bytes);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    writer.close(std.testing.io);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(installed.handle));
    try std.testing.expect(!std.meta.eql(old_id, try cold_identity.statRegular(installed.handle)));
    var bytes: [3]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try installed.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("NEW", &bytes);
}

test "Windows held cold atomic replacement refuses an exclusive old destination" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const seed = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try seed.writePositionalAll(std.testing.io, "OLD", 0);
    seed.close(std.testing.io);
    const old = try cold_runtime.openExistingPrivateWindows(private, "state.wal", .remediate);
    var old_open = true;
    defer if (old_open) old.close(std.testing.io);
    const old_id = try cold_identity.statRegular(old.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    var atomic_open = true;
    defer if (atomic_open) deinitColdAtomic(std.testing.io, &atomic, file_id);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    try std.testing.expectError(StoreError.IoAmbiguous, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true));
    try std.testing.expect(!atomic.file_exists);
    var old_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(old_bytes.len, try old.readPositionalAll(std.testing.io, &old_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &old_bytes);
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    atomic_open = false;
    old.close(std.testing.io);
    old_open = false;
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(old_id, try cold_identity.statRegular(installed.handle));
    var new_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(new_bytes.len, try installed.readPositionalAll(std.testing.io, &new_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &new_bytes);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    defer orphan.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(orphan.handle));
}

test "Windows held cold atomic replacement accepts a read-only delete-share destination" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const seed = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try seed.writePositionalAll(std.testing.io, "OLD", 0);
    seed.close(std.testing.io);
    const old = try openColdExisting(std.testing.io, private, "state.wal", .read_only_share_delete);
    var old_open = true;
    defer if (old_open) old.close(std.testing.io);
    const old_id = try cold_identity.statRegular(old.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    var atomic_open = true;
    defer if (atomic_open) deinitColdAtomic(std.testing.io, &atomic, file_id);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    try renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true);
    var old_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(old_bytes.len, try old.readPositionalAll(std.testing.io, &old_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &old_bytes);
    try std.testing.expect(!std.meta.eql(old_id, file_id));
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    atomic_open = false;
    old.close(std.testing.io);
    old_open = false;
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(installed.handle));
    var new_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(new_bytes.len, try installed.readPositionalAll(std.testing.io, &new_bytes, 0));
    try std.testing.expectEqualStrings("NEW", &new_bytes);
}

test "Windows held cold atomic rename refuses collision and wrong preconditions" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const foreign = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "foreign");
    defer foreign.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const wrong_parent = try openColdExisting(std.testing.io, foreign, ".", .directory);
    defer wrong_parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const old = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try old.writePositionalAll(std.testing.io, "OLD", 0);
    old.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "wrong.wal", parent, parent_id, file_id, true));
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", wrong_parent, parent_id, file_id, true));
    var wrong_id = file_id;
    wrong_id.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, wrong_id, true));
    try std.testing.expect(atomic.file_exists);
    try std.testing.expectError(error.PathAlreadyExists, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, false));
    try std.testing.expect(!atomic.file_exists);
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    const old_bytes = try private.readFileAlloc(std.testing.io, "state.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(old_bytes);
    try std.testing.expectEqualStrings("OLD", old_bytes);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    defer orphan.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(orphan.handle));
}

test "Windows held cold atomic failed rename leaves safe orphan" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    try private.createDir(std.testing.io, "state.wal", .default_dir);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "SECRET", 0);
    try std.testing.expectError(StoreError.IoAmbiguous, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true));
    try std.testing.expect(!atomic.file_exists);
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    const destination = try openColdExisting(std.testing.io, private, "state.wal", .directory);
    destination.close(std.testing.io);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    defer orphan.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(orphan.handle));
}
