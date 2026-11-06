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
const credential_redaction = @import("credential_redaction.zig");

/// Bound on one raw formatted log line. Every `log` call formats into a fixed
/// stack buffer, so the operational-log path never allocates.
const format_scratch_bytes: usize = 2048;

/// Redacted output capacity: markers may be longer than the spans they
/// replace, so leave headroom above the raw scratch.
const redacted_line_bytes: usize = format_scratch_bytes + 512;

/// Appended when a line was cut, either because the raw formatted text
/// exceeded `format_scratch_bytes` or because its redacted form exceeded the
/// output buffer.
pub const truncated_marker = "<log line truncated>";

/// Format `args` with `fmt`, scrub every recognized bearer credential (see
/// `credential_redaction`), and return the result written into `out`.
///
/// The raw text exists only in a local scratch buffer that is wiped before
/// return, so crash dumps of this frame do not retain it. An oversize line
/// keeps only its whole fields (`credential_redaction.trimPartialField`), so
/// a credential cut by the scratch bound is dropped rather than judged
/// without its tail; a redacted line too long for `out` is cut only inside a
/// non-secret gap or a marker. A cut line ends with `truncated_marker` (plus
/// the format's own trailing newline, if any). Returns an empty slice when
/// `out` cannot even hold the marker.
pub fn formatForLog(out: []u8, comptime fmt: []const u8, args: anytype) []const u8 {
    const marker = comptime if (std.mem.endsWith(u8, fmt, "\n")) truncated_marker ++ "\n" else truncated_marker;
    var scratch: [format_scratch_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var w: std.Io.Writer = .fixed(&scratch);
    const complete = if (w.print(fmt, args)) |_| true else |_| false;
    const raw = if (complete) w.buffered() else credential_redaction.trimPartialField(w.buffered());
    if (complete) {
        const full = credential_redaction.redactInto(raw, out);
        if (full.len < out.len) return full;
    }
    if (out.len < marker.len) return out[0..0];
    const body = credential_redaction.redactInto(raw, out[0 .. out.len - marker.len]);
    @memcpy(out[body.len..][0..marker.len], marker);
    return out[0 .. body.len + marker.len];
}

/// Print an operational log line to stderr, or nothing when running under a
/// test binary. Same signature as `std.debug.print`. The line passes through
/// `formatForLog` first, so bearer credentials never reach stderr or the
/// persistent log file that replaces it (`configurePersistent`).
pub fn log(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    var out: [redacted_line_bytes]u8 = undefined;
    std.debug.print("{s}", .{formatForLog(&out, fmt, args)});
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

test "persistent logging redacts a bearer canary before it reaches the sink" {
    var out: [redacted_line_bytes]u8 = undefined;
    const canary = "sst_0123456789abcdef0123456789abcdef";
    const safe = formatForLog(&out, "resume attempt token={s} for {s} via AUTHENTICATE {s}\n", .{ canary, "alice", "YWxpY2UAYWxpY2UAcHc=" });
    try std.testing.expectEqualStrings("resume attempt token=<redacted> for alice via AUTHENTICATE <redacted>\n", safe);
    try std.testing.expect(std.mem.indexOf(u8, safe, canary) == null);
    const notice = formatForLog(&out, ":{s} NOTICE {s} :SESSION TOKEN {s}\r\n", .{ "srv", "alice", "srm2l.0123456789abcdef0123456789abcdef.00000000000000a1" });
    try std.testing.expectEqualStrings(":srv NOTICE alice :SESSION TOKEN <redacted>\r\n", notice);
}

test "persistent logging passes non-secret lines through byte-identical" {
    var out: [redacted_line_bytes]u8 = undefined;
    const safe = formatForLog(&out, "onyx-server: reactor {d} accepted connection from {s}\n", .{ 0, "198.51.100.7" });
    try std.testing.expectEqualStrings("onyx-server: reactor 0 accepted connection from 198.51.100.7\n", safe);
}

test "persistent logging truncates oversize lines without exposing a cut credential" {
    var out: [redacted_line_bytes]u8 = undefined;
    const pad: [format_scratch_bytes - 20]u8 = @splat('x');
    const hex = "fedcba9876543210fedcba9876543210";
    // The raw cut lands inside the token's hex run, inside a PASS value and
    // inside an AUTHENTICATE payload that begins like a mechanism name.
    const cases = [_]struct { tail: []const u8, kept: []const u8 }{
        .{ .tail = " sst_" ++ hex, .kept = " " },
        .{ .tail = "\nPASS " ++ hex, .kept = "\nPASS " },
        .{ .tail = " AUTHENTICATE PLAIN" ++ hex, .kept = " AUTHENTICATE " },
    };
    for (cases) |case| {
        const safe = formatForLog(&out, "{s}{s} after\n", .{ &pad, case.tail });
        try std.testing.expectEqualStrings(&pad, safe[0..pad.len]);
        try std.testing.expectEqualStrings(case.kept, safe[pad.len .. safe.len - truncated_marker.len - 1]);
        try std.testing.expect(std.mem.endsWith(u8, safe, truncated_marker ++ "\n"));
        try std.testing.expect(std.mem.indexOf(u8, safe, "fedcba") == null);
        try std.testing.expect(std.mem.indexOf(u8, safe, "PLAIN") == null);
    }
    // Without a trailing newline in the format, none is invented; a cut line
    // with no field separator at all keeps only the marker.
    const plain = formatForLog(&out, "{s} {s}", .{ &pad, &pad });
    try std.testing.expectEqualStrings(pad ++ " " ++ truncated_marker, plain);
    try std.testing.expectEqualStrings(truncated_marker, formatForLog(&out, "{s}{s}", .{ &pad, &pad }));
}

test "persistent logging fails closed when the redacted output buffer is too small" {
    const canary = "sst_00112233445566778899aabbccddeeff";
    // The cut lands inside the replacement marker, never inside the token.
    var small: [truncated_marker.len + 1 + 8]u8 = undefined;
    const cut = formatForLog(&small, "token={s} and a longer tail\n", .{canary});
    try std.testing.expectEqualStrings("token=<r" ++ truncated_marker ++ "\n", cut);
    var tiny: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), formatForLog(&tiny, "PASS {s}", .{canary}).len);
}
