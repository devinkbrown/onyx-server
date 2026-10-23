// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: custody.

const EngineAccess = @import("engine.zig").Internal;
const std = @import("std");
const cold_identity = @import("../mesh_presence_lease.zig");
const ColdRecoveryStage = @import("checkpoint.zig").ColdRecoveryStage;
const FirstProvisionStage = @import("checkpoint.zig").FirstProvisionStage;
const OroStore = @import("engine.zig").OroStore;
const ColdFile = @import("native_files.zig").ColdFile;
const coldDirectoryIdentity = @import("native_files.zig").coldDirectoryIdentity;
const coldOpenParent = @import("native_files.zig").coldOpenParent;
const cold_posix = @import("native_files.zig").cold_posix;
const deinitColdAtomic = @import("native_files.zig").deinitColdAtomic;
const openColdExisting = @import("native_files.zig").openColdExisting;
const validateColdAtomicName = @import("native_files.zig").validateColdAtomicName;
const validateColdLease = @import("native_files.zig").validateColdLease;
const openTestStore = @import("tests_support.zig").openTestStore;

/// testing.tmpDir owns `.zig-cache/tmp/<sub_path>` relative to the current
/// process directory. Native BSD has getcwd but no SDK descriptor-realpath
/// implementation. Derive that documented path, then prove it names the SAME
/// full directory identity as the held fixture before using it in any test.
pub fn coldFixtureAbsoluteDirectory(tmp: *const std.testing.TmpDir, sub_path: []const u8) ![]u8 {
    if (comptime !cold_posix) {
        const resolved = try tmp.dir.realPathFileAlloc(std.testing.io, sub_path, std.testing.allocator);
        defer std.testing.allocator.free(resolved);
        return std.testing.allocator.dupe(u8, resolved);
    }
    const cwd = try std.process.currentPathAlloc(std.testing.io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    const path = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".zig-cache", "tmp", &tmp.sub_path, sub_path });
    errdefer std.testing.allocator.free(path);
    const held = try openColdExisting(std.testing.io, tmp.dir, sub_path, .directory);
    defer held.close(std.testing.io);
    const named = try openColdExisting(std.testing.io, .cwd(), path, .directory);
    defer named.close(std.testing.io);
    try std.testing.expectEqualDeep(try coldDirectoryIdentity(held.handle), try coldDirectoryIdentity(named.handle));
    return path;
}

pub fn coldParentDirectoryScenario(first: bool, absolute: bool) !void {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    const parent = try coldFixtureAbsoluteDirectory(&tmp, "state");
    defer std.testing.allocator.free(parent);
    const path = if (absolute) try std.mem.concat(std.testing.allocator, u8, &.{ parent, "/parent.wal" }) else try std.testing.allocator.dupe(u8, "state/parent.wal");
    defer std.testing.allocator.free(path);
    const lock_path = try std.mem.concat(std.testing.allocator, u8, &.{ path, ".lock" });
    defer std.testing.allocator.free(lock_path);
    const lease = try tmp.dir.createFile(std.testing.io, lock_path, .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    if (first) {
        var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, tmp.dir, path, lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
        const atomic = stage.atomic.?;
        const actual_parent = try atomic.dir.openFile(std.testing.io, std.fs.path.dirname(atomic.dest_sub_path) orelse ".", .{ .allow_directory = true });
        defer actual_parent.close(std.testing.io);
        try std.testing.expectEqualDeep(try coldDirectoryIdentity(actual_parent.handle), try coldDirectoryIdentity(stage.directory.handle));
        try stage.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
    } else {
        {
            var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, path, .{ .changefeed_capacity = 0 });
            defer seed.deinit();
            const large: [1000]u8 = @splat(42);
            try seed.put(.props, "old", &large);
        }
        var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, path, lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
        defer stage.deinit();
        var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
        defer ticket.abort();
        const plan = stage.backing.?.plan.?;
        const actual_parent = try plan.snapshot_atomic.?.dir.openFile(std.testing.io, ".", .{ .allow_directory = true });
        defer actual_parent.close(std.testing.io);
        try std.testing.expectEqualDeep(try coldDirectoryIdentity(actual_parent.handle), try coldDirectoryIdentity(plan.directory.handle));
        try ticket.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
    }
}

test "retained v2 causal first provisioning syncs actual relative destination parent" {
    try coldParentDirectoryScenario(true, false);
}

test "retained v2 causal first provisioning syncs actual absolute destination parent" {
    try coldParentDirectoryScenario(true, true);
}

test "retained v2 causal cold compaction syncs actual relative destination parent" {
    try coldParentDirectoryScenario(false, false);
}

test "retained v2 causal cold compaction syncs actual absolute destination parent" {
    try coldParentDirectoryScenario(false, true);
}

pub fn coldFifoScenario(kind: enum { wal, snapshot, temporary, revalidation, lock, parent, regular_control, temporary_control, hot_wal, hot_snapshot, promotion, snapshot_replay }) !void {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try coldFixtureAbsoluteDirectory(&tmp, ".");
    defer std.testing.allocator.free(parent);
    var atomic: ?std.Io.File.Atomic = null;
    defer if (atomic) |*file| deinitColdAtomic(std.testing.io, file, null);
    var captured: ?ColdFile = null;
    defer if (captured) |*file| file.deinit(std.testing.allocator, std.testing.io);
    var hot_store: ?OroStore = null;
    defer if (hot_store) |*store| store.deinit();
    if (kind == .hot_snapshot or kind == .snapshot_replay or kind == .promotion) {
        var seeded = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "fifo.wal");
        try seeded.put(.props, "control", "value");
        if (kind == .snapshot_replay) {
            try seeded.snapshotAndTruncate();
            hot_store = seeded;
        } else seeded.deinit();
        if (kind == .promotion) hot_store = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "fifo.wal", .{});
    }
    var held_lease: ?std.Io.File = null;
    defer if (held_lease) |file| file.close(std.testing.io);
    var name_buffer: [16]u8 = undefined;
    const name: []const u8 = if (kind == .temporary or kind == .temporary_control) block: {
        atomic = try tmp.dir.createFileAtomic(std.testing.io, "fifo.wal", .{ .replace = true });
        name_buffer = std.fmt.hex(atomic.?.file_basename_hex);
        if (kind == .temporary) try atomic.?.dir.deleteFile(std.testing.io, &name_buffer);
        break :block &name_buffer;
    } else if (kind == .snapshot or kind == .hot_snapshot or kind == .snapshot_replay) "fifo.wal.snap" else if (kind == .lock) "fifo.wal.lock" else "fifo.wal";
    if (kind == .revalidation or kind == .lock) {
        const file = try tmp.dir.createFile(std.testing.io, name, .{ .read = true });
        if (kind == .lock) {
            held_lease = file;
            try cold_identity.reaffirmExclusive(file.handle);
        } else {
            try file.writePositionalAll(std.testing.io, "old", 0);
            file.close(std.testing.io);
            captured = try ColdFile.capture(std.testing.allocator, std.testing.io, tmp.dir, name, 1024);
        }
        try tmp.dir.deleteFile(std.testing.io, name);
    }
    if (kind == .regular_control) {
        const file = try tmp.dir.createFile(std.testing.io, name, .{ .read = true });
        try file.writePositionalAll(std.testing.io, "control", 0);
        file.close(std.testing.io);
    }
    if (kind == .promotion or kind == .snapshot_replay) try tmp.dir.deleteFile(std.testing.io, name);
    const path = try std.fs.path.join(std.testing.allocator, &.{ parent, name });
    defer std.testing.allocator.free(path);
    if (kind != .regular_control and kind != .temporary_control) {
        const made = try std.process.run(std.testing.allocator, std.testing.io, .{ .argv = &.{ "mkfifo", path } });
        defer std.testing.allocator.free(made.stdout);
        defer std.testing.allocator.free(made.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, made.term);
    }
    const pid: std.posix.pid_t = if (comptime os == .linux) block: {
        const result = std.os.linux.fork();
        if (std.os.linux.errno(result) != .SUCCESS) return error.TestUnexpectedResult;
        break :block @intCast(result);
    } else std.posix.system.fork();
    if (pid < 0) return error.TestUnexpectedResult;
    if (pid == 0) {
        // Fresh single-threaded I/O; never inherit testing I/O worker locks.
        var child_backend: std.Io.Threaded = .init_single_threaded;
        const child_io = child_backend.io();
        const expected: anyerror = if (kind == .temporary) error.SnapshotCoverageMismatch else if (kind == .parent) error.NotDir else error.NotRegular;
        const refused = if (kind == .temporary or kind == .temporary_control) block: {
            validateColdAtomicName(child_io, &atomic.?, cold_identity.statRegular(atomic.?.file.handle) catch coldFifoExit(12)) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .revalidation) block: {
            captured.?.validate(child_io, tmp.dir, name) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .lock) block: {
            validateColdLease(child_io, tmp.dir, held_lease.?, name, cold_identity.statRegular(held_lease.?.handle) catch coldFifoExit(12)) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .parent) block: {
            const file = coldOpenParent(child_io, tmp.dir, "fifo.wal/child") catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            file.close(child_io);
            break :block false;
        } else if (kind == .hot_wal or kind == .hot_snapshot) block: {
            var store = OroStore.openReadOnlyWithConfig(std.heap.page_allocator, child_io, tmp.dir, "fifo.wal", .{ .changefeed_capacity = 0 }) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            store.deinit();
            break :block false;
        } else if (kind == .promotion) block: {
            hot_store.?.io = child_io;
            hot_store.?.preparePromotion() catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .snapshot_replay) block: {
            hot_store.?.io = child_io;
            _ = EngineAccess.replayFile(&hot_store.?, name, .snapshot, 0) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else block: {
            var file = ColdFile.capture(std.heap.page_allocator, child_io, tmp.dir, name, 1024) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            file.deinit(std.heap.page_allocator, child_io);
            break :block false;
        };
        const control = kind == .regular_control or kind == .temporary_control;
        coldFifoExit(if (refused != control) 0 else 13);
    }
    var status: i32 = 0;
    var reaped = false;
    defer if (!reaped) coldFifoKillReap(pid);
    var finished = false;
    for (0..100) |_| {
        const result = if (comptime os == .linux) @as(isize, @bitCast(std.os.linux.wait4(pid, &status, std.posix.W.NOHANG, null))) else std.posix.system.waitpid(pid, &status, std.posix.W.NOHANG);
        if (result == pid) {
            finished = true;
            reaped = true;
            break;
        }
        if (result < 0) {
            if ((if (comptime @import("builtin").os.tag == .linux) std.os.linux.errno(@as(usize, @bitCast(result))) else std.posix.errno(result)) == .INTR) continue;
            return error.TestUnexpectedResult;
        }
        try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    }
    if (!finished) {
        coldFifoKillReap(pid);
        reaped = true;
        // Avoid cleanup reopening the hostile FIFO through the old validator.
        if (atomic) |*file| file.file_exists = false;
        return error.TestUnexpectedResult;
    }
    // On successful bounded refusal, cleanup itself must safely inspect and
    // preserve the foreign FIFO name rather than blocking or unlinking it.
    try std.testing.expectEqual(@as(i32, 0), status);
    if (kind == .temporary) {
        deinitColdAtomic(std.testing.io, &atomic.?, null);
        atomic = null;
        try std.testing.expectEqual(std.Io.File.Kind.named_pipe, (try tmp.dir.statFile(std.testing.io, name, .{ .follow_symlinks = false })).kind);
    }
}

pub fn coldFifoExit(code: u8) noreturn {
    if (comptime @import("builtin").os.tag == .linux) std.os.linux.exit(code);
    std.posix.system._exit(code);
}

test "retained v2 causal FIFO WAL capture is bounded" {
    try coldFifoScenario(.wal);
}

test "retained v2 causal FIFO snapshot capture is bounded" {
    try coldFifoScenario(.snapshot);
}

test "retained v2 causal FIFO substituted temporary refusal is bounded" {
    try coldFifoScenario(.temporary);
}

test "cold recovery actual directory custody rejects replaced parent before publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    {
        var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "state/custody.wal", .{ .changefeed_capacity = 0 });
        defer seed.deinit();
        const large: [1000]u8 = @splat(41);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "state/custody.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "state/custody.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    try tmp.dir.rename("state", tmp.dir, "previous", std.testing.io);
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try std.testing.expectError(error.FileNotFound, ticket.commit());
    try std.testing.expect(!stage.backing.?.consumed);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "state/custody.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "previous/custody.wal.snap", .read_only));
    // Restore the exact configured parent and retry this still-owned ticket.
    try tmp.dir.deleteDir(std.testing.io, "state");
    try tmp.dir.rename("previous", tmp.dir, "state", std.testing.io);
    try ticket.commit();
    var result = stage.takeCommittedStore();
    defer result.deinit();
    try std.testing.expectEqualStrings("cut", result.get(.props, "new").?);
}

test "cold recovery held directory descriptor retarget refuses before publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "retarget.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(40);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "retarget.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "retarget.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const plan = &stage.backing.?.plan.?;
    const held = plan.directory;
    try tmp.dir.createDir(std.testing.io, "foreign", .default_dir);
    const wrong = try openColdExisting(std.testing.io, tmp.dir, "foreign", .directory);
    defer wrong.close(std.testing.io);
    plan.directory = wrong;
    errdefer if (stage.backing.?.plan) |*still_owned| {
        still_owned.directory = held;
    };
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expect(!stage.backing.?.consumed);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "retarget.wal.snap", .read_only));
    plan.directory = held;
    try ticket.commit();
    var result = stage.takeCommittedStore();
    defer result.deinit();
    try std.testing.expectEqualStrings("cut", result.get(.props, "new").?);
}

test "retained v2 causal FIFO configured transcript revalidation is bounded" {
    try coldFifoScenario(.revalidation);
}

test "retained v2 causal FIFO configured lease revalidation is bounded" {
    try coldFifoScenario(.lock);
}

test "retained v2 causal FIFO destination parent acquisition is bounded" {
    try coldFifoScenario(.parent);
}

pub fn coldFifoKillReap(pid: std.posix.pid_t) void {
    const os = @import("builtin").os.tag;
    if (comptime os == .linux) {
        _ = std.os.linux.kill(pid, .KILL);
    } else {
        _ = std.posix.system.kill(pid, std.posix.SIG.KILL);
    }
    var status: i32 = 0;
    while (true) {
        const result = if (comptime os == .linux) @as(isize, @bitCast(std.os.linux.wait4(pid, &status, 0, null))) else std.posix.system.waitpid(pid, &status, 0);
        if (result == pid) return;
        if (result < 0 and (if (comptime @import("builtin").os.tag == .linux) std.os.linux.errno(@as(usize, @bitCast(result))) else std.posix.errno(result)) == .INTR) continue;
        return;
    }
}

test "retained v2 causal FIFO protocol regular child control" {
    try coldFifoScenario(.regular_control);
    try coldFifoScenario(.temporary_control);
}

test "retained v2 causal FIFO hot read only WAL refusal is bounded" {
    try coldFifoScenario(.hot_wal);
}

test "retained v2 causal FIFO hot read only snapshot refusal is bounded" {
    try coldFifoScenario(.hot_snapshot);
}

test "retained v2 causal FIFO hot prepared promotion refusal is bounded" {
    try coldFifoScenario(.promotion);
}

test "retained v2 causal FIFO snapshot replay refusal is bounded" {
    try coldFifoScenario(.snapshot_replay);
}
