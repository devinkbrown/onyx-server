// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: compaction.

const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const cold_runtime = @import("../os_runtime.zig");
const PreparedIoFault = @import("contracts.zig").PreparedIoFault;
const OroStore = @import("engine.zig").OroStore;
const coldDirectoryIdentity = @import("native_files.zig").coldDirectoryIdentity;
const coldOpenParent = @import("native_files.zig").coldOpenParent;
const cold_posix = @import("native_files.zig").cold_posix;
const openColdExisting = @import("native_files.zig").openColdExisting;
const coldFixtureAbsoluteDirectory = @import("tests_custody.zig").coldFixtureAbsoluteDirectory;
const openTestStore = @import("tests_support.zig").openTestStore;

pub const PublicationSyncWitness = struct {
    expected: cold_identity.Identity,
    original: *const fn (?*anyopaque, std.Io.File) std.Io.File.SyncError!void,
    seen: usize = 0,
    mismatch: bool = false,
    retarget_dir: ?std.Io.Dir = null,
    retarget_when: enum { none, snapshot_sync, directory_sync } = .none,
    retargeted: bool = false,
    failing: ?*std.testing.FailingAllocator = null,
    publication_allocs: ?usize = null,
};
threadlocal var publication_sync_witness: ?*PublicationSyncWitness = null;

pub fn observePublicationSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    const witness = publication_sync_witness.?;
    const directory = if (coldDirectoryIdentity(file.handle)) |identity| block: {
        witness.seen += 1;
        if (witness.failing) |failing| if (witness.publication_allocs == null) {
            witness.publication_allocs = failing.alloc_index;
            failing.fail_index = failing.alloc_index;
        };
        witness.mismatch = witness.mismatch or !std.meta.eql(witness.expected, identity);
        break :block true;
    } else |_| false;
    if (!witness.retargeted and (if (directory) witness.retarget_when == .directory_sync else witness.retarget_when == .snapshot_sync)) {
        const dir = witness.retarget_dir.?;
        dir.rename("state", dir, "previous", std.testing.io) catch return error.Unexpected;
        dir.createDir(std.testing.io, "state", .default_dir) catch return error.Unexpected;
        witness.retargeted = true;
    }
    return witness.original(userdata, file);
}

pub fn genericCompactionParentScenario(absolute: bool) !void {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    const parent_path = try coldFixtureAbsoluteDirectory(&tmp, "state");
    defer std.testing.allocator.free(parent_path);
    const absolute_path = try std.fs.path.join(std.testing.allocator, &.{ parent_path, "ordinary.wal" });
    defer std.testing.allocator.free(absolute_path);
    const path = if (absolute) absolute_path else "state/ordinary.wal";
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, path);
    defer store.deinit();
    try store.put(.props, "old", "cut");
    const parent = try coldOpenParent(std.testing.io, tmp.dir, path);
    defer parent.close(std.testing.io);
    var witness: PublicationSyncWitness = .{ .expected = try coldDirectoryIdentity(parent.handle), .original = std.testing.io.vtable.fileSync };
    var vtable = std.testing.io.vtable.*;
    vtable.fileSync = observePublicationSync;
    publication_sync_witness = &witness;
    defer publication_sync_witness = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try store.snapshotAndTruncate();
    try std.testing.expectEqual(@as(usize, 2), witness.seen);
    try std.testing.expect(!witness.mismatch);
    try std.testing.expectEqualStrings("cut", store.get(.props, "old").?);
}

test "retained v2 causal ordinary compaction syncs actual relative destination parent" {
    try genericCompactionParentScenario(false);
}

test "retained v2 causal ordinary compaction syncs actual absolute destination parent" {
    try genericCompactionParentScenario(true);
}

pub fn genericCompactionRetargetScenario(after_snapshot: bool) !void {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "state/retarget.wal");
    defer store.deinit();
    try store.put(.props, "old", "accepted");
    const before = try tmp.dir.readFileAlloc(std.testing.io, "state/retarget.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const parent = try coldOpenParent(std.testing.io, tmp.dir, store.wal_path);
    defer parent.close(std.testing.io);
    var witness: PublicationSyncWitness = .{ .expected = try coldDirectoryIdentity(parent.handle), .original = std.testing.io.vtable.fileSync, .retarget_dir = tmp.dir, .retarget_when = if (after_snapshot) .directory_sync else .snapshot_sync };
    var vtable = std.testing.io.vtable.*;
    vtable.fileSync = observePublicationSync;
    publication_sync_witness = &witness;
    defer publication_sync_witness = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try std.testing.expectError(if (after_snapshot) error.IoAmbiguous else error.SnapshotCoverageMismatch, store.snapshotAndTruncate());
    try std.testing.expect(witness.retargeted);
    try std.testing.expect(!witness.mismatch);
    try std.testing.expectEqual(after_snapshot, store.preparedWritesPoisoned());
    const retained_wal = try tmp.dir.readFileAlloc(std.testing.io, "previous/retarget.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(retained_wal);
    try std.testing.expectEqualSlices(u8, before, retained_wal);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "state/retarget.wal", .read_only));
    try tmp.dir.deleteDir(std.testing.io, "state");
    try tmp.dir.rename("previous", tmp.dir, "state", std.testing.io);
    store.io = std.testing.io;
    if (!after_snapshot) try store.snapshotAndTruncate();
    var reopened = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "state/retarget.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("accepted", reopened.get(.props, "old").?);
}

test "retained v2 ordinary compaction parent retarget before snapshot publication preserves WAL and retries" {
    try genericCompactionRetargetScenario(false);
}

test "retained v2 ordinary compaction parent retarget after snapshot sync preserves WAL and poisons" {
    try genericCompactionRetargetScenario(true);
}

pub fn liveCompactionAllocationScenario(allocator: std.mem.Allocator, existing_snapshot: bool) !void {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "live-oom.wal");
    defer store.deinit();
    try store.put(.props, "accepted", "before");
    if (existing_snapshot) {
        try store.snapshotAndTruncate();
        try store.put(.props, "second", "retained");
    }
    const seq = store.next_seq;
    const offset = store.wal_offset;
    const before = try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const snapshot = if (existing_snapshot) try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal.snap", std.testing.allocator, .unlimited) else null;
    defer if (snapshot) |bytes| std.testing.allocator.free(bytes);
    const identity = try cold_identity.statRegular(store.wal_file.?.handle);
    store.allocator = allocator;
    defer store.allocator = std.testing.allocator;
    store.snapshotAndTruncate() catch |err| {
        store.allocator = std.testing.allocator;
        if (err == error.OutOfMemory) {
            try std.testing.expect(!store.preparedWritesPoisoned());
            try std.testing.expectEqual(seq, store.next_seq);
            try std.testing.expectEqual(offset, store.wal_offset);
            try std.testing.expectEqualDeep(identity, try cold_identity.statRegular(store.wal_file.?.handle));
            const after = try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            if (snapshot) |bytes| {
                const actual = try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal.snap", std.testing.allocator, .unlimited);
                defer std.testing.allocator.free(actual);
                try std.testing.expectEqualSlices(u8, bytes, actual);
            } else try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "live-oom.wal.snap", .read_only));
            try store.snapshotAndTruncate();
            try std.testing.expectEqual(seq, store.next_seq);
            try std.testing.expectEqualStrings("before", store.get(.props, "accepted").?);
            var reopened = try openTestStore(tmp, "live-oom.wal");
            defer reopened.deinit();
            try std.testing.expectEqual(seq, reopened.next_seq);
            try std.testing.expectEqualStrings("before", reopened.get(.props, "accepted").?);
        }
        return err;
    };
    store.allocator = std.testing.allocator;
    try std.testing.expectEqual(seq, store.next_seq);
}

test "retained v2 live atomic compaction exhaustive OOM preserves old cut and retries" {
    // Scenario is a skip-stub where cold_posix is false; checkAllAllocationFailures needs a real OOM-capable fn.
    if (comptime !cold_posix) return error.SkipZigTest;
    for ([_]bool{ false, true }) |snapshot| try std.testing.checkAllAllocationFailures(std.testing.allocator, liveCompactionAllocationScenario, .{snapshot});
}

test "retained v2 live atomic compaction allocates nothing after snapshot publication and moves exact writer" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "live-armed.wal");
    defer store.deinit();
    try store.put(.props, "accepted", "before");
    const old = std.Io.File{ .handle = try cold_runtime.duplicate(store.wal_file.?.handle), .flags = store.wal_file.?.flags };
    defer old.close(std.testing.io);
    const old_size = (try old.stat(std.testing.io)).size;
    const old_identity = try cold_identity.statRegular(old.handle);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const parent = try coldOpenParent(std.testing.io, tmp.dir, store.wal_path);
    defer parent.close(std.testing.io);
    var witness: PublicationSyncWitness = .{ .expected = try coldDirectoryIdentity(parent.handle), .original = std.testing.io.vtable.fileSync, .failing = &failing };
    var vtable = std.testing.io.vtable.*;
    vtable.fileSync = observePublicationSync;
    publication_sync_witness = &witness;
    defer publication_sync_witness = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    store.allocator = failing.allocator();
    defer store.allocator = std.testing.allocator;
    try store.snapshotAndTruncate();
    try std.testing.expectEqual(witness.publication_allocs.?, failing.alloc_index);
    try std.testing.expect(!std.meta.eql(old_identity, try cold_identity.statRegular(store.wal_file.?.handle)));
    try std.testing.expectEqual(@as(u64, 25), store.wal_offset);
    store.allocator = std.testing.allocator;
    store.io = std.testing.io;
    try store.put(.props, "after", "new writer");
    try std.testing.expectEqual(old_size, (try old.stat(std.testing.io)).size);
    var reopened = try openTestStore(tmp, "live-armed.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("new writer", reopened.get(.props, "after").?);
}

test "retained v2 live atomic compaction all publication ambiguities poison and recover exact logical cut" {
    if (comptime !cold_posix) return error.SkipZigTest;
    const Boundary = @FieldType(PreparedIoFault, "compaction_boundary");
    for ([_]Boundary{ .after_snapshot_replace, .after_snapshot_dir_sync, .after_wal_replace, .after_wal_dir_sync }) |boundary| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "live-fault.wal");
        defer store.deinit();
        try store.put(.props, "accepted", "before");
        const seq = store.next_seq;
        const old_identity = try cold_identity.statRegular(store.wal_file.?.handle);
        const old_size = store.wal_offset;
        store.setPreparedIoFault(.{ .compaction_boundary = boundary });
        try std.testing.expectError(error.IoAmbiguous, store.snapshotAndTruncate());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectEqual(seq, store.next_seq);
        try std.testing.expectEqualStrings("before", store.get(.props, "accepted").?);
        try std.testing.expectEqualDeep(old_identity, try cold_identity.statRegular(store.wal_file.?.handle));
        try std.testing.expectEqual(old_size, (try store.wal_file.?.stat(std.testing.io)).size);
        try std.testing.expectError(error.StorePoisoned, store.preparePut(.props, "forbidden", "append"));
        var reopened = try openTestStore(tmp, "live-fault.wal");
        defer reopened.deinit();
        try std.testing.expectEqual(seq, reopened.next_seq);
        try std.testing.expectEqualStrings("before", reopened.get(.props, "accepted").?);
        try reopened.put(.props, "retry", "valid");
    }
}

test "retained v2 hot safe acquisition refuses WAL snapshot and promotion symlinks without mutation" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "hot-links.wal");
        defer seed.deinit();
        try seed.put(.props, "accepted", "value");
        try seed.snapshotAndTruncate();
    }
    const before = try tmp.dir.readFileAlloc(std.testing.io, "hot-links.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try tmp.dir.rename("hot-links.wal", tmp.dir, "actual.wal", std.testing.io);
    try tmp.dir.symLink(std.testing.io, "actual.wal", "hot-links.wal", .{});
    try std.testing.expectError(error.SymLinkLoop, OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-links.wal", .{}));
    try tmp.dir.deleteFile(std.testing.io, "hot-links.wal");
    try tmp.dir.rename("actual.wal", tmp.dir, "hot-links.wal", std.testing.io);
    try tmp.dir.rename("hot-links.wal.snap", tmp.dir, "actual.snap", std.testing.io);
    try tmp.dir.symLink(std.testing.io, "actual.snap", "hot-links.wal.snap", .{});
    try std.testing.expectError(error.SymLinkLoop, OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-links.wal", .{}));
    try tmp.dir.deleteFile(std.testing.io, "hot-links.wal.snap");
    try tmp.dir.rename("actual.snap", tmp.dir, "hot-links.wal.snap", std.testing.io);
    var stage = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-links.wal", .{});
    defer stage.deinit();
    try tmp.dir.rename("hot-links.wal", tmp.dir, "actual.wal", std.testing.io);
    try tmp.dir.symLink(std.testing.io, "actual.wal", "hot-links.wal", .{});
    try std.testing.expectError(error.SymLinkLoop, stage.preparePromotion());
    try std.testing.expect(stage.staged_write_file == null);
    const after = try tmp.dir.readFileAlloc(std.testing.io, "actual.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try tmp.dir.deleteFile(std.testing.io, "hot-links.wal");
    try tmp.dir.rename("actual.wal", tmp.dir, "hot-links.wal", std.testing.io);
    try stage.preparePromotion();
}

pub const HotReplayRetarget = struct {
    dir: std.Io.Dir,
    original: *const fn (?*anyopaque, std.Io.File) std.Io.File.StatError!std.Io.File.Stat,
    changed: bool = false,
};
threadlocal var hot_replay_retarget: ?*HotReplayRetarget = null;

pub fn retargetHotWalOnFirstStat(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.StatError!std.Io.File.Stat {
    const witness = hot_replay_retarget.?;
    const stat = try witness.original(userdata, file);
    if (!witness.changed) {
        witness.dir.rename("held.wal", witness.dir, "original.wal", std.testing.io) catch return error.Unexpected;
        witness.dir.rename("foreign.wal", witness.dir, "held.wal", std.testing.io) catch return error.Unexpected;
        witness.changed = true;
    }
    return stat;
}

test "retained v2 hot replay reads original held WAL and promotion refuses namespace retarget" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var original = try openTestStore(tmp, "held.wal");
        defer original.deinit();
        try original.put(.props, "cut", "accepted");
        var foreign = try openTestStore(tmp, "foreign.wal");
        defer foreign.deinit();
        try foreign.put(.props, "cut", "foreign");
    }
    var witness: HotReplayRetarget = .{ .dir = tmp.dir, .original = std.testing.io.vtable.fileStat };
    var vtable = std.testing.io.vtable.*;
    vtable.fileStat = retargetHotWalOnFirstStat;
    hot_replay_retarget = &witness;
    defer hot_replay_retarget = null;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var stage = try OroStore.openReadOnlyWithConfig(std.testing.allocator, io, tmp.dir, "held.wal", .{});
    defer stage.deinit();
    try std.testing.expect(witness.changed);
    try std.testing.expectEqualStrings("accepted", stage.get(.props, "cut").?);
    try std.testing.expectError(error.SnapshotCoverageMismatch, stage.preparePromotion());
    try std.testing.expect(stage.staged_write_file == null);
}

pub const LiveTempReplacement = struct {
    original_create: *const fn (?*anyopaque, std.Io.Dir, []const u8, std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic,
    original_sync: *const fn (?*anyopaque, std.Io.File) std.Io.File.SyncError!void,
    snapshot: ?std.Io.File.Atomic = null,
    snapshot_identity: ?cold_identity.Identity = null,
    substituted: bool = false,
};
threadlocal var live_temp_replacement: ?*LiveTempReplacement = null;

pub fn observeLiveAtomic(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, options: std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic {
    const witness = live_temp_replacement.?;
    const file = try witness.original_create(userdata, dir, path, options);
    if (std.mem.endsWith(u8, path, ".snap")) {
        witness.snapshot = file;
        witness.snapshot_identity = cold_identity.statRegular(file.file.handle) catch return error.Unexpected;
    }
    return file;
}

pub fn replaceLiveSnapshotTemp(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    const witness = live_temp_replacement.?;
    try witness.original_sync(userdata, file);
    if (!witness.substituted and witness.snapshot != null and std.meta.eql(witness.snapshot_identity.?, cold_identity.statRegular(file.handle) catch return)) {
        const atomic = witness.snapshot.?;
        const name = std.fmt.hex(atomic.file_basename_hex);
        const foreign = atomic.dir.createFile(std.testing.io, "replacement", .{ .read = true }) catch return error.Unexpected;
        defer foreign.close(std.testing.io);
        foreign.writePositionalAll(std.testing.io, "FOREIGN", 0) catch return error.Unexpected;
        atomic.dir.rename("replacement", atomic.dir, &name, std.testing.io) catch return error.Unexpected;
        witness.substituted = true;
    }
}

test "retained v2 live compaction refuses substituted snapshot temp and preserves foreign name" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "live-temp.wal");
    defer store.deinit();
    try store.put(.props, "cut", "accepted");
    const before = try tmp.dir.readFileAlloc(std.testing.io, "live-temp.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    var witness: LiveTempReplacement = .{ .original_create = std.testing.io.vtable.dirCreateFileAtomic, .original_sync = std.testing.io.vtable.fileSync };
    var vtable = std.testing.io.vtable.*;
    vtable.dirCreateFileAtomic = observeLiveAtomic;
    vtable.fileSync = replaceLiveSnapshotTemp;
    live_temp_replacement = &witness;
    defer live_temp_replacement = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try std.testing.expectError(error.SnapshotCoverageMismatch, store.snapshotAndTruncate());
    try std.testing.expect(witness.substituted);
    try std.testing.expect(!store.preparedWritesPoisoned());
    const name = std.fmt.hex(witness.snapshot.?.file_basename_hex);
    const survivor = try tmp.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(survivor);
    try std.testing.expectEqualStrings("FOREIGN", survivor);
    const after = try tmp.dir.readFileAlloc(std.testing.io, "live-temp.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "live-temp.wal.snap", .read_only));
}
