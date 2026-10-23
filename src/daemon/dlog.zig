// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operational daemon logging. One line: route boot/runtime notices to stderr in
//! a real daemon, but stay SILENT under `zig test`.
//!
//! Why silent in tests: zig 0.16's `--listen=-` test runner reads the test
//! binary's stderr, and ANY stderr output from a test (even a single line) makes
//! `zig build test` print a spurious "failed command" — the step and the whole
//! build still succeed (verified: `--summary all` reports success, every test
//! passes, the process exits 0), but the noise is misleading. Daemon code that
//! booted real servers in threaded tests flooded stderr with these notices, so
//! the default test run always showed it. Suppressing operational logs in test
//! builds keeps the output clean without changing production behaviour.

const std = @import("std");
const builtin = @import("builtin");

/// Print an operational log line to stderr, or nothing when running under a test
/// binary. Same signature as `std.debug.print`.
pub fn log(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    std.debug.print(fmt, args);
}

pub const PersistentError = error{
    UnsupportedLogPlatform,
    InvalidLogPath,
    LogOpenFailed,
    LogSymlink,
    LogStatFailed,
    LogNotRegular,
    LogPermissions,
    LogRedirectFailed,
};

/// Validate the sink without replacing stderr. This may create the configured
/// file, but never truncates existing contents or follows its final symlink.
pub fn preflightPersistent(io: std.Io, path: []const u8) PersistentError!void {
    _ = io;
    if (comptime builtin.os.tag != .linux) return error.UnsupportedLogPlatform;
    const fd = try openPersistentAt(std.os.linux.AT.FDCWD, path);
    _ = std.os.linux.close(fd);
}

/// Call before starting worker threads, on cold boot and every Helix successor.
/// Validate everything before the atomic descriptor swap. On failure the caller
/// must retain inherited stderr and continue adoption of live client state.
pub fn configurePersistent(io: std.Io, path: []const u8) PersistentError!void {
    _ = io;
    if (comptime builtin.os.tag != .linux) return error.UnsupportedLogPlatform;
    const linux = std.os.linux;
    const fd = try openPersistentAt(linux.AT.FDCWD, path);
    errdefer _ = linux.close(fd);
    try redirectDescriptor(fd, 2);
    // openat may have filled a previously closed stderr descriptor itself.
    if (fd != 2) _ = linux.close(fd);
}

fn openPersistentAt(directory: i32, path: []const u8) PersistentError!i32 {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedLogPlatform;
    const linux = std.os.linux;
    if (path.len == 0 or path.len >= 4096 or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidLogPath;
    var path_buf: [4096]u8 = undefined;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z = path_buf[0..path.len :0];
    const fd: i32 = while (true) {
        // NONBLOCK prevents a substituted FIFO from hanging before stat.
        const result = linux.openat(directory, path_z, .{
            .ACCMODE = .WRONLY,
            .APPEND = true,
            .CREAT = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
            .NONBLOCK = true,
        }, 0o600);
        switch (linux.errno(result)) {
            .SUCCESS => break @intCast(result),
            .INTR => continue,
            .LOOP => return error.LogSymlink,
            else => return error.LogOpenFailed,
        }
    };
    errdefer _ = linux.close(fd);
    var stat: linux.Statx = std.mem.zeroes(linux.Statx);
    while (true) {
        switch (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
            .TYPE = true,
            .MODE = true,
            .UID = true,
            .NLINK = true,
        }, &stat))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.LogStatFailed,
        }
    }
    if (!stat.mask.TYPE or !stat.mask.MODE or !stat.mask.UID or !stat.mask.NLINK)
        return error.LogStatFailed;
    if ((stat.mode & linux.S.IFMT) != linux.S.IFREG) return error.LogNotRegular;
    // Refuse shared, hard-linked, or foreign-owned files instead of chmodding
    // an operator typo. Only the final opened inode is trusted, never its name.
    if (stat.uid != linux.geteuid() or stat.nlink != 1 or (stat.mode & 0o7777) != 0o600)
        return error.LogPermissions;
    return fd;
}

fn redirectDescriptor(source: i32, target: i32) PersistentError!void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedLogPlatform;
    const linux = std.os.linux;
    while (true) {
        const result = if (source == target)
            linux.fcntl(source, linux.F.SETFD, 0)
        else
            linux.dup3(source, target, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return,
            .INTR => continue,
            else => return error.LogRedirectFailed,
        }
    }
}

test "persistent logging preserves append contents and private permissions" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const first = try openPersistentAt(tmp.dir.handle, "daemon.log");
    try std.testing.expectEqual(@as(usize, 6), linux.write(first, "first\n", 6));
    _ = linux.close(first);
    const second = try openPersistentAt(tmp.dir.handle, "daemon.log");
    defer _ = linux.close(second);
    try std.testing.expectEqual(@as(usize, 7), linux.write(second, "second\n", 7));
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "daemon.log", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("first\nsecond\n", contents);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.fchmod(second, 0o644)));
    try std.testing.expectError(error.LogPermissions, openPersistentAt(tmp.dir.handle, "daemon.log"));
}

test "persistent logging rejects symlinks hardlinks nonregular files and malformed paths" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const original = try openPersistentAt(tmp.dir.handle, "original.log");
    defer _ = linux.close(original);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlinkat("original.log", tmp.dir.handle, "symlink.log")));
    try std.testing.expectError(error.LogSymlink, openPersistentAt(tmp.dir.handle, "symlink.log"));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.linkat(tmp.dir.handle, "original.log", tmp.dir.handle, "hardlink.log", 0)));
    try std.testing.expectError(error.LogPermissions, openPersistentAt(tmp.dir.handle, "hardlink.log"));
    try std.testing.expectError(error.LogNotRegular, openPersistentAt(linux.AT.FDCWD, "/dev/null"));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mknodat(tmp.dir.handle, "fifo.log", linux.S.IFIFO | 0o600, 0)));
    try std.testing.expectError(error.LogOpenFailed, openPersistentAt(tmp.dir.handle, "fifo.log"));
    try std.testing.expectError(error.InvalidLogPath, openPersistentAt(tmp.dir.handle, ""));
    try std.testing.expectError(error.InvalidLogPath, openPersistentAt(tmp.dir.handle, "prefix\x00suffix"));
}

test "persistent logging descriptor swap survives exec and handles identical descriptors" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const source = try openPersistentAt(tmp.dir.handle, "source.log");
    defer _ = linux.close(source);
    const target = try openPersistentAt(tmp.dir.handle, "target.log");
    defer _ = linux.close(target);
    // Exercise the same atomic swap on a private fd; never alter test stderr.
    try redirectDescriptor(source, target);
    try std.testing.expectEqual(@as(usize, 0), linux.fcntl(target, linux.F.GETFD, 0));
    try std.testing.expectEqual(@as(usize, 7), linux.write(target, "target\n", 7));
    try redirectDescriptor(source, source);
    try std.testing.expectEqual(@as(usize, 0), linux.fcntl(source, linux.F.GETFD, 0));
    try std.testing.expectError(error.LogRedirectFailed, redirectDescriptor(source, -1));
    try std.testing.expectEqual(@as(usize, 7), linux.write(source, "source\n", 7));
    const contents = try tmp.dir.readFileAlloc(std.testing.io, "source.log", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("target\nsource\n", contents);
}
