// SPDX-License-Identifier: AGPL-3.0-or-later
//! Linux foreground maintenance custody. The reviewed daemon remains the final
//! authority for live state and application readiness.
const std = @import("std");
const linux = std.os.linux;
const types = @import("setup_maintenance_types.zig");
const onyx = @import("onyx_server");
const backup = onyx.daemon.backup_set;
const live = onyx.daemon.helix.live;
const Allocator = std.mem.Allocator;
const Fd = linux.fd_t;
const Digest = [32]u8;
const max_image = 512 * 1024 * 1024;

fn close(fd: Fd) void {
    if (fd >= 0) _ = linux.close(fd);
}
fn openAt(dir: Fd, path: []const u8, flags: linux.O, mode: u32) !Fd {
    const z = try std.posix.toPosixPath(path);
    const result = linux.openat(dir, &z, flags, mode);
    if (linux.errno(result) != .SUCCESS) return error.CustodyUnavailable;
    return @intCast(result);
}
fn trustedDirectoryInfo(st: linux.Statx, uid: u32) bool {
    return st.mode & std.posix.S.IFMT == std.posix.S.IFDIR and
        onyx.service_identity_preflight.trustedDirectory(st.uid, st.mode, uid);
}
fn requireTrustedDirectory(fd: Fd) !void {
    if (!trustedDirectoryInfo(try statFd(fd), linux.geteuid())) return error.InsecureDirectory;
}
// Resolve every component through a retained directory descriptor. Each parent
// must be root/current-UID owned and not writable by others, except a root-owned
// sticky parent whose next entry is separately checked. Never follow symlinks.
fn openSafeAt(dir: Fd, path: []const u8, flags: linux.O) !Fd {
    if (path.len == 0) return error.CustodyUnavailable;
    const absolute = std.fs.path.isAbsolute(path);
    var current: Fd = if (absolute)
        try openAt(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0)
    else if (dir == linux.AT.FDCWD)
        try openAt(linux.AT.FDCWD, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0)
    else
        dir;
    var owned = absolute or dir == linux.AT.FDCWD;
    errdefer if (owned) close(current);
    try requireTrustedDirectory(current);
    var parts = std.mem.tokenizeScalar(u8, path, '/');
    var component = parts.next() orelse {
        if (!absolute or !flags.DIRECTORY) return error.CustodyUnavailable;
        return current;
    };
    while (true) {
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.CustodyUnavailable;
        const next = parts.next();
        if (next == null) {
            var final_flags = flags;
            final_flags.NOFOLLOW = true;
            const result = try openAt(current, component, final_flags, 0);
            errdefer close(result);
            if (flags.DIRECTORY) try requireTrustedDirectory(result);
            if (owned) close(current);
            return result;
        }
        const child = try openAt(current, component, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        errdefer close(child);
        try requireTrustedDirectory(child);
        if (owned) close(current);
        current = child;
        owned = true;
        component = next.?;
    }
}

fn openSafe(path: []const u8, flags: linux.O) !Fd {
    if (!std.fs.path.isAbsolute(path)) return error.AbsolutePathRequired;
    return openSafeAt(linux.AT.FDCWD, path, flags);
}
fn statFd(fd: Fd) !linux.Statx {
    var st: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &st);
    if (linux.errno(rc) != .SUCCESS or !st.mask.TYPE or !st.mask.MODE or !st.mask.UID or !st.mask.GID or !st.mask.INO or !st.mask.SIZE or !st.mask.NLINK or !st.mask.MTIME or !st.mask.CTIME) return error.CustodyUnavailable;
    return st;
}
fn sameFile(a: linux.Statx, b: linux.Statx) bool {
    return a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and a.ino == b.ino and a.size == b.size and a.uid == b.uid and a.gid == b.gid and a.mode == b.mode and a.nlink == b.nlink;
}
fn sameDirectory(a: linux.Statx, b: linux.Statx) bool {
    return a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and a.ino == b.ino and a.uid == b.uid and a.gid == b.gid and a.mode == b.mode;
}
fn sameUnchanged(a: linux.Statx, b: linux.Statx) bool {
    return sameFile(a, b) and a.mtime.sec == b.mtime.sec and a.mtime.nsec == b.mtime.nsec and a.ctime.sec == b.ctime.sec and a.ctime.nsec == b.ctime.nsec;
}
fn manifestMatches(parsed: Digest, bound: Digest) bool {
    return std.crypto.timing_safe.eql(Digest, parsed, bound);
}
fn privateDir(fd: Fd) !void {
    const st = try statFd(fd);
    if (st.uid != linux.geteuid() or st.mode & std.posix.S.IFMT != std.posix.S.IFDIR or st.mode & 0o7777 != 0o700) return error.InsecureDirectory;
}
fn checkCwdPath(procfd: Fd, expected: linux.Statx) !void {
    var path: [linux.PATH_MAX]u8 = undefined;
    const n = linux.readlinkat(procfd, "cwd", &path, path.len);
    if (linux.errno(n) != .SUCCESS or n == 0 or n >= path.len) return error.CustodyUnavailable;
    const fd = try openSafe(path[0..n], .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer close(fd);
    if (!sameDirectory(try statFd(fd), expected)) return error.ProcessChanged;
}
fn privateFile(fd: Fd, executable: bool) !void {
    const st = try statFd(fd);
    if (st.uid != linux.geteuid() or st.mode & std.posix.S.IFMT != std.posix.S.IFREG or st.mode & 0o022 != 0 or st.nlink != 1 or st.size == 0 or st.size > max_image or (executable and st.mode & 0o100 == 0) or (!executable and st.mode & 0o7777 != 0o400 and st.mode & 0o7777 != 0o600)) return error.InsecureFile;
}
fn privateEvidenceInfo(st: linux.Statx, uid: u32, allow_empty: bool) bool {
    return st.uid == uid and st.mode & std.posix.S.IFMT == std.posix.S.IFREG and
        (st.mode & 0o7777 == 0o400 or st.mode & 0o7777 == 0o600) and
        st.nlink == 1 and (allow_empty or st.size > 0) and st.size <= max_image;
}
fn requireEvidence(fd: Fd, expected: linux.Statx, allow_empty: bool) !void {
    const actual = try statFd(fd);
    if (!privateEvidenceInfo(actual, linux.geteuid(), allow_empty) or !sameUnchanged(actual, expected)) return error.FileChanged;
}
fn hashFd(fd: Fd, limit: usize) !Digest {
    const before = try statFd(fd);
    if (before.size > limit) return error.FileTooLarge;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [16384]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: usize = 0;
    while (offset < before.size) {
        const wanted = @min(buffer.len, before.size - offset);
        const n = linux.pread(fd, &buffer, wanted, @intCast(offset));
        if (linux.errno(n) != .SUCCESS or n == 0 or n > wanted) return error.ReadFailed;
        hasher.update(buffer[0..n]);
        offset += n;
    }
    const after = try statFd(fd);
    if (!sameUnchanged(before, after)) return error.FileChanged;
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}
fn readSmall(fd: Fd, out: []u8) ![]const u8 {
    var total: usize = 0;
    while (total < out.len) {
        const n = linux.read(fd, out.ptr + total, out.len - total);
        if (linux.errno(n) != .SUCCESS) return error.ReadFailed;
        if (n == 0) return out[0..total];
        total += n;
    }
    return error.InputTooLarge;
}
fn openProc(procfd: Fd, name: []const u8) !Fd {
    return openAt(procfd, name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
}
fn startTime(procfd: Fd) !u64 {
    const fd = try openProc(procfd, "stat");
    defer close(fd);
    var storage: [4096]u8 = undefined;
    const value = try readSmall(fd, &storage);
    const close_paren = std.mem.lastIndexOfScalar(u8, value, ')') orelse return error.InvalidProcess;
    if (close_paren + 2 >= value.len or value[close_paren + 1] != ' ') return error.InvalidProcess;
    var fields = std.mem.tokenizeScalar(u8, value[close_paren + 2 ..], ' ');
    for (0..20) |i| {
        const item = fields.next() orelse return error.InvalidProcess;
        if (i == 19) return std.fmt.parseInt(u64, item, 10) catch error.InvalidProcess;
    }
    return error.InvalidProcess;
}
fn credentialsDigest(procfd: Fd) !Digest {
    const fd = try openProc(procfd, "status");
    defer close(fd);
    var storage: [16384]u8 = undefined;
    const value = try readSmall(fd, &storage);
    var lines = std.mem.splitScalar(u8, value, '\n');
    const names = [_][]const u8{ "Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:", "NoNewPrivs:", "Seccomp:" };
    var seen: u16 = 0;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "Seccomp_filters:")) {
            hasher.update(line);
            hasher.update(&.{0});
        }
        for (names, 0..) |name, i| {
            if (!std.mem.startsWith(u8, line, name)) continue;
            const bit = @as(u16, 1) << @intCast(i);
            if (seen & bit != 0) return error.InvalidProcess;
            seen |= bit;
            hasher.update(line);
            hasher.update(&.{0});
            if (i < 2) {
                var fields = std.mem.tokenizeAny(u8, line[name.len..], " \t");
                for (0..4) |_| {
                    const part = fields.next() orelse return error.InvalidProcess;
                    const id = std.fmt.parseInt(u32, part, 10) catch return error.InvalidProcess;
                    if (id != (if (i == 0) linux.geteuid() else linux.getegid())) return error.IdentityMismatch;
                }
                if (fields.next() != null) return error.InvalidProcess;
            }
        }
    }
    if (seen != (@as(u16, 1) << names.len) - 1) return error.InvalidProcess;
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

fn requireLive(pidfd: Fd) !void {
    var rows = [_]linux.pollfd{.{ .fd = pidfd, .events = linux.POLL.IN, .revents = 0 }};
    const result = linux.poll(&rows, 1, 0);
    if (linux.errno(result) != .SUCCESS or result != 0 or rows[0].revents != 0) return error.ProcessExited;
}
fn copyFd(src: Fd, dir: Fd, name: []const u8, mode: u32, limit: usize) !Fd {
    const before = try statFd(src);
    if (before.size == 0 or before.size > limit) return error.FileTooLarge;
    const out = try openAt(dir, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, mode);
    errdefer close(out);
    var buffer: [16384]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var offset: usize = 0;
    while (offset < before.size) {
        const wanted = @min(buffer.len, before.size - offset);
        const n = linux.pread(src, &buffer, wanted, @intCast(offset));
        if (linux.errno(n) != .SUCCESS or n == 0 or n > wanted) return error.ReadFailed;
        var written: usize = 0;
        while (written < n) {
            const part = linux.write(out, buffer[written..n].ptr, n - written);
            if (linux.errno(part) != .SUCCESS or part == 0 or part > n - written) return error.WriteFailed;
            written += part;
        }
        offset += n;
    }
    if (!sameUnchanged(before, try statFd(src)) or linux.errno(linux.fsync(out)) != .SUCCESS) return error.FileChanged;
    return out;
}
fn readOwned(allocator: Allocator, fd: Fd, max: usize) ![]u8 {
    const st = try statFd(fd);
    if (st.size > max) return error.FileTooLarge;
    const data = try allocator.alloc(u8, @intCast(st.size));
    errdefer allocator.free(data);
    var pos: usize = 0;
    while (pos < data.len) {
        const n = linux.pread(fd, data.ptr + pos, data.len - pos, @intCast(pos));
        if (linux.errno(n) != .SUCCESS or n == 0 or n > data.len - pos) return error.ReadFailed;
        pos += n;
    }
    if (!sameUnchanged(st, try statFd(fd))) return error.FileChanged;
    return data;
}
fn fsync(fd: Fd) !void {
    if (linux.errno(linux.fsync(fd)) != .SUCCESS) return error.SyncFailed;
}

// Helper output can contain configuration text. Wipe the entire allocation on
// release, including partial outputs and allocator-growth failure paths.
pub const WipingAllocator = struct {
    parent: Allocator,
    pub fn allocator(self: *WipingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = Allocator.noResize, .remap = Allocator.noRemap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        return self.parent.rawAlloc(len, alignment, ra);
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, bytes);
        self.parent.rawFree(bytes, alignment, ra);
    }
};

/// Live configuration bytes for the maintenance config editor, under the same
/// custody rules as review: absolute, trusted ancestry, no symlink, private
/// single-link regular file, bounded, unchanged while read. The review binding
/// later hashes the file again; callers must compare digests before trusting.
pub fn readLiveConfig(allocator: Allocator, path: []const u8) ![]u8 {
    const fd = try openSafe(path, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
    defer close(fd);
    try privateFile(fd, false);
    return readOwned(allocator, fd, onyx.daemon.config_format.max_config_bytes);
}

/// Saved candidate custody: same file rules as the live configuration and
/// exactly the saved digest. Drift is an error, never a silent re-read.
pub fn requireCandidate(allocator: Allocator, path: []const u8, sha256: Digest) !void {
    var wipe: WipingAllocator = .{ .parent = allocator };
    const a = wipe.allocator();
    const bytes = try readLiveConfig(a, path);
    defer a.free(bytes);
    var actual: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (!std.crypto.timing_safe.eql(Digest, actual, sha256)) return error.CandidateChanged;
}

/// Publish a reviewed candidate as a NEW private 0600 file inside a trusted
/// directory (no symlink components, not writable by others). Never replaces
/// an existing path; the live configuration is never a target of this call.
/// Names reserved for maintenance recovery custody are refused.
pub fn saveCandidate(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const name = std.fs.path.basename(path);
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or !std.mem.endsWith(u8, path, name) or
        std.mem.startsWith(u8, name, ".onyx-maintenance")) return error.InvalidCandidatePath;
    const parent = std.fs.path.dirname(path) orelse return error.AbsolutePathRequired;
    const dir = try openSafe(parent, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    defer close(dir);
    try @import("setup_workflow.zig").publish(io, .{ .handle = dir }, name, bytes);
}

const StaticResolver = struct {
    io: std.Io,
    cwd: std.Io.Dir,
    env_seen: bool = false,
    file_hash: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    file_count: usize = 0,
    file_bytes: usize = 0,
    fn env(ctx: ?*anyopaque, _: Allocator, _: []const u8) anyerror![]const u8 {
        const self: *StaticResolver = @ptrCast(@alignCast(ctx.?));
        self.env_seen = true;
        return error.EnvironmentNotAttested;
    }
    fn record(self: *StaticResolver, path: []const u8, metadata: linux.Statx, digest: Digest) void {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, @intCast(path.len), .big);
        self.file_hash.update(&length);
        self.file_hash.update(path);
        self.file_hash.update(std.mem.asBytes(&metadata.dev_major));
        self.file_hash.update(std.mem.asBytes(&metadata.dev_minor));
        self.file_hash.update(std.mem.asBytes(&metadata.ino));
        self.file_hash.update(std.mem.asBytes(&metadata.uid));
        self.file_hash.update(std.mem.asBytes(&metadata.gid));
        self.file_hash.update(std.mem.asBytes(&metadata.mode));
        self.file_hash.update(std.mem.asBytes(&metadata.nlink));
        self.file_hash.update(std.mem.asBytes(&metadata.size));
        self.file_hash.update(&digest);
    }
    fn openReference(self: *StaticResolver, path: []const u8) !Fd {
        const fd = try openSafeAt(self.cwd.handle, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true });
        errdefer close(fd);
        const info = try statFd(fd);
        if ((info.uid != 0 and info.uid != linux.geteuid()) or info.mode & std.posix.S.IFMT != std.posix.S.IFREG or info.mode & 0o022 != 0 or info.nlink != 1 or info.size > 1 << 20) return error.InsecureFile;
        if (self.file_count >= 64 or info.size > (4 << 20) - self.file_bytes) return error.ReferenceLimit;
        self.file_count += 1;
        self.file_bytes += @intCast(info.size);
        return fd;
    }
    fn secretReference(self: *StaticResolver, path: []const u8) !void {
        const fd = try self.openReference(path);
        defer close(fd);
        const info = try statFd(fd);
        const sum = try hashFd(fd, 1 << 20);
        if (!sameUnchanged(info, try statFd(fd))) return error.FileChanged;
        self.record(path, info, sum);
    }
    fn file(ctx: ?*anyopaque, allocator: Allocator, path: []const u8) anyerror![]const u8 {
        const self: *StaticResolver = @ptrCast(@alignCast(ctx.?));
        const fd = try self.openReference(path);
        defer close(fd);
        const info = try statFd(fd);
        const bytes = try readOwned(allocator, fd, 1 << 20);
        errdefer allocator.free(bytes);
        var sum: Digest = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &sum, .{});
        if (!sameUnchanged(info, try statFd(fd))) return error.FileChanged;
        self.record(path, info, sum);
        return bytes;
    }
};

pub const Session = struct {
    allocator: Allocator,
    io: std.Io,
    selection: types.Selection,
    pidfd: Fd = -1,
    procfd: Fd = -1,
    exe_dir: Fd = -1,
    current_fd: Fd = -1,
    config_fd: Fd = -1,
    target_fd: Fd = -1,
    backup_dir: Fd = -1,
    manifest_fd: Fd = -1,
    snapshot_fd: Fd = -1,
    scratch_fd: Fd = -1,
    staged_manifest_fd: Fd = -1,
    staged_snapshot_fd: Fd = -1,
    staged_config_fd: Fd = -1,
    drill_wal_fd: Fd = -1,
    drill_snap_fd: Fd = -1,
    cwd_fd: Fd = -1,
    mount_ns_fd: Fd = -1,
    root_fd: Fd = -1,
    exe_path: []u8 = &.{},
    exe_name: []u8 = &.{},
    snapshot_name: []u8 = &.{},
    previous_path: []u8 = &.{},
    journal_path: []u8 = &.{},
    staged_backup_path: []u8 = &.{},
    staged_config_path: []u8 = &.{},
    drill_path: []u8 = &.{},
    cmdline: []u8 = &.{},
    initial: ?types.Binding = null,
    current_info: linux.Statx = undefined,
    config_info: linux.Statx = undefined,
    target_info: linux.Statx = undefined,
    manifest_info: linux.Statx = undefined,
    snapshot_info: linux.Statx = undefined,
    staged_manifest_info: linux.Statx = undefined,
    staged_snapshot_info: linux.Statx = undefined,
    staged_config_info: linux.Statx = undefined,
    drill_wal_info: linux.Statx = undefined,
    drill_snap_info: linux.Statx = undefined,
    cwd_info: linux.Statx = undefined,
    mount_ns_info: linux.Statx = undefined,
    root_info: linux.Statx = undefined,
    snapshot_digest: Digest = @splat(0),
    parsed_manifest_digest: Digest = @splat(0),
    drill_wal_digest: Digest = @splat(0),
    drill_snap_digest: Digest = @splat(0),
    privilege_digest: Digest = @splat(0),
    scratch_created: bool = false,
    strict_identity: bool = false,
    static_passed: bool = false,
    backup_passed: bool = false,
    backup_generated_at: i64 = 0,
    last_wall: i64 = 0,
    identity_digest: ?Digest = null,

    pub fn open(allocator: Allocator, io: std.Io, selection: types.Selection) !Session {
        if (linux.getuid() != linux.geteuid() or linux.getgid() != linux.getegid()) return error.IdentityMismatch;
        if (selection.pid <= 0 or !std.fs.path.isAbsolute(selection.config) or !std.fs.path.isAbsolute(selection.target) or !std.fs.path.isAbsolute(selection.backup_dir) or !std.fs.path.isAbsolute(selection.restore_into)) return error.InvalidSelection;
        var self: Session = .{ .allocator = allocator, .io = io, .selection = .{ .pid = selection.pid, .config = "", .target = "", .backup_dir = "", .restore_into = "" } };
        errdefer self.deinit();
        self.selection.config = try allocator.dupe(u8, selection.config);
        self.selection.target = try allocator.dupe(u8, selection.target);
        self.selection.backup_dir = try allocator.dupe(u8, selection.backup_dir);
        self.selection.restore_into = try allocator.dupe(u8, selection.restore_into);
        const result = linux.pidfd_open(selection.pid, 0);
        if (linux.errno(result) != .SUCCESS) return error.ProcessUnavailable;
        self.pidfd = @intCast(result);
        try requireLive(self.pidfd);
        var procbuf: [64]u8 = undefined;
        const procpath = try std.fmt.bufPrint(&procbuf, "/proc/{d}", .{selection.pid});
        self.procfd = try openSafe(procpath, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        self.privilege_digest = try credentialsDigest(self.procfd);
        const cmdfd = try openProc(self.procfd, "cmdline");
        defer close(cmdfd);
        var cmd_storage: [8192]u8 = undefined;
        const cmd = try readSmall(cmdfd, &cmd_storage);
        if (cmd.len == 0 or cmd[cmd.len - 1] != 0) return error.InvalidProcess;
        self.cmdline = try allocator.dupe(u8, cmd);
        var args = std.mem.splitScalar(u8, cmd[0 .. cmd.len - 1], 0);
        const executable = args.next() orelse return error.InvalidProcess;
        if (!std.fs.path.isAbsolute(executable)) return error.AbsolutePathRequired;
        const first = args.next() orelse return error.InvalidProcess;
        self.strict_identity = std.mem.eql(u8, first, live.strict_existing_identity_arg);
        const config = if (std.mem.eql(u8, first, "--supervisor")) blk: {
            const value = args.next() orelse return error.InvalidProcess;
            if (args.next()) |extra| {
                if (!std.mem.eql(u8, extra, live.strict_existing_identity_arg)) return error.ProcessArgumentsMismatch;
                self.strict_identity = true;
            }
            break :blk value;
        } else if (self.strict_identity) args.next() orelse return error.InvalidProcess else first;
        if (!std.mem.eql(u8, config, self.selection.config) or args.next() != null) return error.ProcessArgumentsMismatch;
        self.exe_path = try allocator.dupe(u8, executable);
        self.exe_name = try allocator.dupe(u8, std.fs.path.basename(executable));
        const dirname = std.fs.path.dirname(executable) orelse return error.InvalidProcess;
        self.previous_path = try std.fs.path.join(allocator, &.{ dirname, ".onyx-maintenance-previous" });
        self.journal_path = try std.fs.path.join(allocator, &.{ dirname, ".onyx-maintenance-journal" });
        self.staged_backup_path = try std.fs.path.join(allocator, &.{ selection.restore_into, "input" });
        self.staged_config_path = try std.fs.path.join(allocator, &.{ selection.restore_into, "config.toml" });
        self.drill_path = try std.fs.path.join(allocator, &.{ selection.restore_into, "drill" });
        self.exe_dir = try openSafe(dirname, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        try privateDir(self.exe_dir);
        self.current_fd = try openAt(self.exe_dir, self.exe_name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        try privateFile(self.current_fd, true);
        const exe = try openAt(self.procfd, "exe", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        defer close(exe);
        self.current_info = try statFd(self.current_fd);
        if (!sameFile(self.current_info, try statFd(exe))) return error.ExecutableMismatch;
        self.cwd_fd = try openAt(self.procfd, "cwd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        self.cwd_info = try statFd(self.cwd_fd);
        try checkCwdPath(self.procfd, self.cwd_info);
        self.mount_ns_fd = try openAt(self.procfd, "ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        self.mount_ns_info = try statFd(self.mount_ns_fd);
        const own_ns = try openAt(linux.AT.FDCWD, "/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        defer close(own_ns);
        if (!sameDirectory(self.mount_ns_info, try statFd(own_ns))) return error.NamespaceMismatch;
        self.root_fd = try openAt(self.procfd, "root", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        self.root_info = try statFd(self.root_fd);
        const own_root = try openSafe("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        defer close(own_root);
        if (!sameDirectory(self.root_info, try statFd(own_root))) return error.NamespaceMismatch;
        self.config_fd = try openSafe(selection.config, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
        try privateFile(self.config_fd, false);
        self.config_info = try statFd(self.config_fd);
        self.target_fd = try openSafe(selection.target, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true });
        try privateFile(self.target_fd, true);
        self.target_info = try statFd(self.target_fd);
        self.backup_dir = try openSafe(selection.backup_dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        try privateDir(self.backup_dir);
        self.manifest_fd = try openAt(self.backup_dir, "latest.json", .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        try privateFile(self.manifest_fd, false);
        self.manifest_info = try statFd(self.manifest_fd);
        const manifest = try readOwned(allocator, self.manifest_fd, 1 << 20);
        defer allocator.free(manifest);
        if (!sameUnchanged(self.manifest_info, try statFd(self.manifest_fd))) return error.FileChanged;
        std.crypto.hash.sha2.Sha256.hash(manifest, &self.parsed_manifest_digest, .{});
        const verified = try backup.verify(allocator, manifest);
        defer verified.deinit(allocator);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, manifest, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidBackupTime;
        const generated = parsed.value.object.get("generated_at") orelse return error.InvalidBackupTime;
        if (generated != .integer or generated.integer <= 0) return error.InvalidBackupTime;
        self.backup_generated_at = generated.integer;
        self.snapshot_name = try allocator.dupe(u8, verified.accounts_name);
        self.snapshot_fd = try openAt(self.backup_dir, self.snapshot_name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        try privateFile(self.snapshot_fd, false);
        self.snapshot_info = try statFd(self.snapshot_fd);
        self.snapshot_digest = try hashFd(self.snapshot_fd, backup.max_backup_file_bytes);
        try requireLive(self.pidfd);
        return self;
    }

    pub fn deinit(self: *Session) void {
        close(self.drill_snap_fd);
        close(self.drill_wal_fd);
        close(self.staged_config_fd);
        close(self.staged_snapshot_fd);
        close(self.staged_manifest_fd);
        close(self.scratch_fd);
        close(self.root_fd);
        close(self.mount_ns_fd);
        close(self.cwd_fd);
        close(self.snapshot_fd);
        close(self.manifest_fd);
        close(self.backup_dir);
        close(self.target_fd);
        close(self.config_fd);
        close(self.current_fd);
        close(self.exe_dir);
        close(self.procfd);
        close(self.pidfd);
        for ([_][]const u8{ self.selection.config, self.selection.target, self.selection.backup_dir, self.selection.restore_into, self.exe_path, self.exe_name, self.snapshot_name, self.previous_path, self.journal_path, self.staged_backup_path, self.staged_config_path, self.drill_path, self.cmdline }) |value| if (value.len != 0) self.allocator.free(value);
        self.* = undefined;
    }

    pub fn bind(self: *Session) !types.Binding {
        if (self.initial) |value| return value;
        try requireLive(self.pidfd);
        if (!std.crypto.timing_safe.eql(Digest, try credentialsDigest(self.procfd), self.privilege_digest)) return error.IdentityMismatch;
        const binding: types.Binding = .{
            .pid = self.selection.pid,
            .uid = linux.geteuid(),
            .start_ticks = try startTime(self.procfd),
            .exe_device = (@as(u64, self.current_info.dev_major) << 32) | self.current_info.dev_minor,
            .exe_inode = self.current_info.ino,
            .current_sha256 = try hashFd(self.current_fd, max_image),
            .config_sha256 = try hashFd(self.config_fd, max_image),
            .target_sha256 = try hashFd(self.target_fd, max_image),
            .backup_manifest_sha256 = try hashFd(self.manifest_fd, 1 << 20),
        };
        if (!manifestMatches(binding.backup_manifest_sha256, self.parsed_manifest_digest)) return error.FileChanged;
        self.initial = binding;
        try self.revalidate(binding);
        return binding;
    }

    fn checkProcess(self: *Session, binding: types.Binding) !void {
        try requireLive(self.pidfd);
        if (!std.crypto.timing_safe.eql(Digest, try credentialsDigest(self.procfd), self.privilege_digest)) return error.IdentityMismatch;
        if (try startTime(self.procfd) != binding.start_ticks) return error.ProcessChanged;
        const proc_exe = try openAt(self.procfd, "exe", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        defer close(proc_exe);
        if (!sameFile(try statFd(proc_exe), self.current_info) or !std.crypto.timing_safe.eql(Digest, try hashFd(proc_exe, max_image), binding.current_sha256)) return error.ProcessChanged;
        const cwd = try openAt(self.procfd, "cwd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        defer close(cwd);
        if (!sameDirectory(try statFd(cwd), self.cwd_info)) return error.ProcessChanged;
        try checkCwdPath(self.procfd, self.cwd_info);
        const mount_ns = try openAt(self.procfd, "ns/mnt", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        defer close(mount_ns);
        const root = try openAt(self.procfd, "root", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        defer close(root);
        if (!sameDirectory(try statFd(mount_ns), self.mount_ns_info) or !sameDirectory(try statFd(root), self.root_info)) return error.NamespaceMismatch;
        const cmdfd = try openProc(self.procfd, "cmdline");
        defer close(cmdfd);
        var buf: [8192]u8 = undefined;
        if (!std.mem.eql(u8, try readSmall(cmdfd, &buf), self.cmdline)) return error.ProcessChanged;
        try requireLive(self.pidfd);
    }
    fn checkInputs(self: *Session, binding: types.Binding, current_path: bool) !void {
        try privateDir(self.exe_dir);
        try privateDir(self.backup_dir);
        const dir = try openSafe(std.fs.path.dirname(self.exe_path).?, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        defer close(dir);
        if (!sameDirectory(try statFd(dir), try statFd(self.exe_dir))) return error.FileChanged;
        if (current_path) {
            const pathfd = try openAt(dir, self.exe_name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
            defer close(pathfd);
            if (!sameFile(try statFd(pathfd), self.current_info)) return error.FileChanged;
        }
        const config = try openSafe(self.selection.config, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true });
        defer close(config);
        const target = try openSafe(self.selection.target, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true });
        defer close(target);
        const backup_dir = try openSafe(self.selection.backup_dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        defer close(backup_dir);
        if (!sameDirectory(try statFd(backup_dir), try statFd(self.backup_dir))) return error.FileChanged;
        const manifest = try openAt(backup_dir, "latest.json", .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        defer close(manifest);
        const snapshot = try openAt(backup_dir, self.snapshot_name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        defer close(snapshot);
        if (!sameFile(try statFd(config), self.config_info) or !sameFile(try statFd(target), self.target_info) or !sameFile(try statFd(manifest), self.manifest_info) or !sameFile(try statFd(snapshot), self.snapshot_info)) return error.FileChanged;
        if (!std.crypto.timing_safe.eql(Digest, try hashFd(config, max_image), binding.config_sha256) or !std.crypto.timing_safe.eql(Digest, try hashFd(target, max_image), binding.target_sha256) or !std.crypto.timing_safe.eql(Digest, try hashFd(manifest, 1 << 20), binding.backup_manifest_sha256) or !std.crypto.timing_safe.eql(Digest, try hashFd(snapshot, backup.max_backup_file_bytes), self.snapshot_digest)) return error.FileChanged;
        if (self.backup_passed) try self.checkStagedBackup(binding);
    }
    fn checkStagedBackup(self: *Session, binding: types.Binding) !void {
        const root = try openSafe(self.selection.restore_into, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        defer close(root);
        try privateDir(root);
        if (!sameDirectory(try statFd(root), try statFd(self.scratch_fd))) return error.FileChanged;
        const input = try openAt(root, "input", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(input);
        try privateDir(input);
        const manifest = try openAt(input, "latest.json", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(manifest);
        const snapshot = try openAt(input, self.snapshot_name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(snapshot);
        const config = try openAt(root, "config.toml", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(config);
        try requireEvidence(manifest, self.staged_manifest_info, false);
        try requireEvidence(self.staged_manifest_fd, self.staged_manifest_info, false);
        try requireEvidence(snapshot, self.staged_snapshot_info, false);
        try requireEvidence(self.staged_snapshot_fd, self.staged_snapshot_info, false);
        try requireEvidence(config, self.staged_config_info, false);
        try requireEvidence(self.staged_config_fd, self.staged_config_info, false);
        if (!std.crypto.timing_safe.eql(Digest, try hashFd(manifest, 1 << 20), binding.backup_manifest_sha256) or !std.crypto.timing_safe.eql(Digest, try hashFd(snapshot, backup.max_backup_file_bytes), self.snapshot_digest) or !std.crypto.timing_safe.eql(Digest, try hashFd(config, max_image), binding.config_sha256)) return error.FileChanged;
        const drill = try openAt(root, "drill", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(drill);
        try privateDir(drill);
        const wal = try openAt(drill, "restored.wal", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(wal);
        const snap = try openAt(drill, "restored.wal.snap", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(snap);
        try requireEvidence(wal, self.drill_wal_info, true);
        try requireEvidence(self.drill_wal_fd, self.drill_wal_info, true);
        try requireEvidence(snap, self.drill_snap_info, false);
        try requireEvidence(self.drill_snap_fd, self.drill_snap_info, false);
        if (!std.crypto.timing_safe.eql(Digest, try hashFd(wal, backup.max_backup_file_bytes), self.drill_wal_digest) or !std.crypto.timing_safe.eql(Digest, try hashFd(snap, backup.max_backup_file_bytes), self.drill_snap_digest)) return error.FileChanged;
    }
    fn checkIdentityFile(self: *Session) !?Digest {
        var resolver: StaticResolver = .{ .io = self.io, .cwd = .{ .handle = self.cwd_fd } };
        var wipe: WipingAllocator = .{ .parent = self.allocator };
        const a = wipe.allocator();
        const text = try readOwned(a, self.config_fd, onyx.daemon.config_format.max_config_bytes);
        defer a.free(text);
        var doc = try onyx.proto.toml.parse(a, text);
        defer doc.deinit(a);
        const configured = doc.getString("node.secret_key");
        if (configured) |raw| {
            if (std.mem.startsWith(u8, raw, "@file:")) try resolver.secretReference(raw[6..]);
        } else {
            const key_path = try onyx.daemon.node_keyfile.derivePath(a, self.selection.config);
            defer a.free(key_path);
            try resolver.secretReference(key_path);
        }
        const owner = onyx.service_identity_preflight.loadPreparedBoot(self.allocator, self.io, resolver.cwd, self.selection.config, .{ .port = 0 }, .{ .ctx = &resolver, .env = StaticResolver.env, .file = StaticResolver.file }) catch |err| {
            if (resolver.env_seen) return null;
            if (err == error.OutOfMemory) return err;
            return error.StaticIdentityRefused;
        };
        defer owner.deinit();
        const prepared = if (owner.identity) |*value| value else return error.StaticIdentityRefused;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&prepared.node.sign_kp.public_key);
        hasher.update(&prepared.node.realm);
        var references_digest: Digest = undefined;
        defer std.crypto.secureZero(u8, &references_digest);
        resolver.file_hash.final(&references_digest);
        hasher.update(&references_digest);
        var result: Digest = undefined;
        hasher.final(&result);
        return result;
    }
    fn checkedBackupAge(self: *Session) !types.BackupChecks {
        var ts: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.clock_gettime(linux.CLOCK.REALTIME, &ts)) != .SUCCESS or ts.sec <= 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return error.ClockUnavailable;
        const now = std.math.cast(i64, ts.sec) orelse return error.ClockUnavailable;
        if (now < self.last_wall) return error.ClockRegressed;
        self.last_wall = now;
        const result: types.BackupChecks = .{ .generated_at_unix = self.backup_generated_at, .observed_at_unix = now, .restore_drill = .passed };
        if (!result.fresh()) return error.BackupStaleOrFuture;
        return result;
    }
    pub fn revalidate(self: *Session, binding: types.Binding) !void {
        if (self.initial == null or !std.meta.eql(self.initial.?, binding) or
            !manifestMatches(binding.backup_manifest_sha256, self.parsed_manifest_digest)) return error.BindingMismatch;
        _ = try self.checkedBackupAge();
        try self.checkProcess(binding);
        try self.checkInputs(binding, true);
        if (self.identity_digest) |expected| {
            const current = (try self.checkIdentityFile()) orelse return error.IdentityChanged;
            if (!std.crypto.timing_safe.eql(Digest, current, expected)) return error.IdentityChanged;
        }
        try requireLive(self.pidfd);
    }
    const Probe = union(enum) {
        live_config,
        identity,
        /// Saved maintenance candidate, checked against the live file.
        candidate: []const u8,
    };
    fn targetPreflight(self: *Session, binding: types.Binding, probe: Probe) !bool {
        try self.revalidate(binding);
        var fd_path_buf: [64]u8 = undefined;
        const fd_path = try std.fmt.bufPrint(&fd_path_buf, "/proc/self/fd/{d}", .{self.target_fd});
        const config_argv = [_][]const u8{ fd_path, "--check-config", self.selection.config, "--against", self.selection.config };
        const identity_argv = [_][]const u8{ fd_path, "--check-service-identity", self.selection.config };
        const candidate_argv = [_][]const u8{ fd_path, "--check-config", if (probe == .candidate) probe.candidate else "", "--against", self.selection.config };
        var environment = std.process.Environ.Map.init(self.allocator);
        defer environment.deinit();
        const deadline = (std.Io.Timeout{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } }).toDeadline(self.io);
        var child = try std.process.spawn(self.io, .{
            .argv = switch (probe) {
                .live_config => &config_argv,
                .identity => &identity_argv,
                .candidate => &candidate_argv,
            },
            .cwd = .{ .dir = .{ .handle = self.cwd_fd } },
            .environ_map = &environment,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        defer {
            if (child.id) |pid| while (linux.errno(linux.kill(pid, .KILL)) == .INTR) {};
            child.kill(self.io);
        }
        child.stdin.?.close(self.io);
        child.stdin = null;
        var wipe: WipingAllocator = .{ .parent = self.allocator };
        var storage: std.Io.File.MultiReader.Buffer(2) = undefined;
        var output: std.Io.File.MultiReader = undefined;
        output.init(wipe.allocator(), self.io, storage.toStreams(), &.{ child.stdout.?, child.stderr.? });
        defer output.deinit();
        while (output.fill(64, deadline)) |_| {
            if (output.reader(0).buffered().len > 4096 or output.reader(1).buffered().len > 4096) return error.StreamTooLong;
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => return err,
        }
        try output.checkAnyError();
        if (output.reader(0).buffered().len > 4096 or output.reader(1).buffered().len > 4096) return error.StreamTooLong;
        while (true) {
            const remaining = deadline.deadline.durationFromNow(self.io).raw.nanoseconds;
            if (remaining <= 0) return error.Timeout;
            var status: linux.siginfo_t = std.mem.zeroes(linux.siginfo_t);
            switch (linux.errno(linux.waitid(.PID, child.id.?, &status, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT, null))) {
                .SUCCESS => if (status.fields.common.first.piduid.pid != 0) break,
                .INTR => continue,
                else => return error.ProbeWaitFailed,
            }
            try std.Io.sleep(self.io, .{ .nanoseconds = @min(remaining, 10 * std.time.ns_per_ms) }, .awake);
        }
        const term = try child.wait(self.io);
        try self.revalidate(binding);
        return term.success();
    }
    pub fn checkStatic(self: *Session) !types.StaticChecks {
        self.static_passed = false;
        self.identity_digest = null;
        const binding = self.initial orelse return error.BindingMissing;
        try self.revalidate(binding);
        // Config and identity can depend on the selected daemon's environment.
        // The controller's environment is not an acceptable substitute.
        const current_capable = try live.probeUpgradeExecutableFdWithBootPolicy(self.allocator, self.io, self.current_fd, .{ .strict_existing_identity = self.strict_identity });
        try self.revalidate(binding);
        const target_capable = try live.probeUpgradeExecutableFdWithBootPolicy(self.allocator, self.io, self.target_fd, .{ .strict_existing_identity = self.strict_identity });
        try self.revalidate(binding);
        const capable = current_capable and target_capable;
        const identity = self.checkIdentityFile() catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return .{ .current_capabilities = if (current_capable) .passed else .refused, .target_capabilities = if (target_capable) .passed else .refused, .candidate_config = .unavailable, .existing_identity = .refused, .environment_bound = false },
        };
        self.identity_digest = identity;
        try self.revalidate(binding);
        if (identity == null) return .{ .current_capabilities = if (current_capable) .passed else .refused, .target_capabilities = if (target_capable) .passed else .refused, .candidate_config = .unavailable, .existing_identity = .unavailable, .environment_bound = false };
        const config_ok = try self.targetPreflight(binding, .live_config);
        const identity_ok = try self.targetPreflight(binding, .identity);
        self.static_passed = capable and config_ok and identity_ok;
        try self.revalidate(binding);
        return .{ .current_capabilities = if (current_capable) .passed else .refused, .target_capabilities = if (target_capable) .passed else .refused, .candidate_config = if (config_ok) .passed else .refused, .existing_identity = if (identity_ok) .passed else .refused, .environment_bound = false };
    }
    /// Ask the selected target executable to validate a saved maintenance
    /// candidate as a successor of the live file (`--check-config <candidate>
    /// --against <live>`, which includes the Helix listener guard). Runs only
    /// after environment-independent static checks passed; otherwise the
    /// result is `unavailable`, never a pass. The candidate must hold private
    /// custody and the exact saved digest before and after the probe.
    pub fn checkCandidate(self: *Session, path: []const u8, sha256: Digest) !types.Check {
        const binding = self.initial orelse return error.BindingMissing;
        if (!self.static_passed) return .unavailable;
        try requireCandidate(self.allocator, path, sha256);
        const ok = try self.targetPreflight(binding, .{ .candidate = path });
        try requireCandidate(self.allocator, path, sha256);
        return if (ok) .passed else .refused;
    }
    pub fn checkBackup(self: *Session) !types.BackupChecks {
        const binding = self.initial orelse return error.BindingMissing;
        try self.revalidate(binding);
        if (self.scratch_created) return error.ScratchAlreadyUsed;
        const parent_path = std.fs.path.dirname(self.selection.restore_into) orelse return error.InvalidSelection;
        const name = std.fs.path.basename(self.selection.restore_into);
        const parent = try openSafe(parent_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
        defer close(parent);
        try privateDir(parent);
        const z = try std.posix.toPosixPath(name);
        if (linux.errno(linux.mkdirat(parent, &z, 0o700)) != .SUCCESS) return error.ScratchUnavailable;
        self.scratch_created = true;
        try fsync(parent);
        self.scratch_fd = try openAt(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        try privateDir(self.scratch_fd);
        if (linux.errno(linux.mkdirat(self.scratch_fd, "input", 0o700)) != .SUCCESS) return error.ScratchUnavailable;
        const input = try openAt(self.scratch_fd, "input", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(input);
        const copied_manifest = try copyFd(self.manifest_fd, input, "latest.json", 0o600, 1 << 20);
        close(copied_manifest);
        const copied_snapshot = try copyFd(self.snapshot_fd, input, self.snapshot_name, 0o600, backup.max_backup_file_bytes);
        close(copied_snapshot);
        const copied_config = try copyFd(self.config_fd, self.scratch_fd, "config.toml", 0o600, max_image);
        close(copied_config);
        self.staged_config_fd = try openAt(self.scratch_fd, "config.toml", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        if (!std.crypto.timing_safe.eql(Digest, try hashFd(self.staged_config_fd, max_image), binding.config_sha256)) return error.FileChanged;
        const check_manifest = try openAt(input, "latest.json", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        self.staged_manifest_fd = check_manifest;
        const check_snapshot = try openAt(input, self.snapshot_name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        self.staged_snapshot_fd = check_snapshot;
        if (!std.crypto.timing_safe.eql(Digest, try hashFd(check_manifest, 1 << 20), binding.backup_manifest_sha256) or !std.crypto.timing_safe.eql(Digest, try hashFd(check_snapshot, backup.max_backup_file_bytes), self.snapshot_digest)) return error.FileChanged;
        var input_path: [80]u8 = undefined;
        var output_path: [80]u8 = undefined;
        const source = try std.fmt.bufPrint(&input_path, "/proc/self/fd/{d}/input", .{self.scratch_fd});
        const dest = try std.fmt.bufPrint(&output_path, "/proc/self/fd/{d}/drill", .{self.scratch_fd});
        try fsync(input);
        if (linux.errno(linux.mkdirat(self.scratch_fd, "drill", 0o700)) != .SUCCESS) return error.ScratchUnavailable;
        try fsync(self.scratch_fd);
        try backup.restoreDrill(self.allocator, self.io, source, dest);
        const drill = try openAt(self.scratch_fd, "drill", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(drill);
        try privateDir(drill);
        self.drill_wal_fd = try openAt(drill, "restored.wal", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        self.drill_snap_fd = try openAt(drill, "restored.wal.snap", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        for ([_]Fd{ self.drill_wal_fd, self.drill_snap_fd }) |fd| {
            const metadata = try statFd(fd);
            if (metadata.uid != linux.geteuid() or metadata.mode & std.posix.S.IFMT != std.posix.S.IFREG or metadata.nlink != 1) return error.InsecureFile;
            if (linux.errno(linux.fchmod(fd, 0o600)) != .SUCCESS) return error.WriteFailed;
            try fsync(fd);
        }
        self.drill_wal_digest = try hashFd(self.drill_wal_fd, backup.max_backup_file_bytes);
        self.drill_snap_digest = try hashFd(self.drill_snap_fd, backup.max_backup_file_bytes);
        self.staged_manifest_info = try statFd(self.staged_manifest_fd);
        self.staged_snapshot_info = try statFd(self.staged_snapshot_fd);
        self.staged_config_info = try statFd(self.staged_config_fd);
        self.drill_wal_info = try statFd(self.drill_wal_fd);
        self.drill_snap_info = try statFd(self.drill_snap_fd);
        try fsync(drill);
        try fsync(self.scratch_fd);
        try self.revalidate(binding);
        self.backup_passed = true;
        errdefer self.backup_passed = false;
        try self.checkStagedBackup(binding);
        return try self.checkedBackupAge();
    }

    fn requireAbsent(dir: Fd, name: [:0]const u8) !void {
        var st: linux.Statx = std.mem.zeroes(linux.Statx);
        const rc = linux.statx(dir, name.ptr, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st);
        if (linux.errno(rc) != .NOENT) return error.RecoveryPathUnavailable;
    }
    pub fn recoveryReferences(self: *Session) !types.RecoveryRefs {
        if (!self.backup_passed) return error.BackupNotVerified;
        try self.checkStagedBackup(self.initial orelse return error.BindingMissing);
        try requireAbsent(self.exe_dir, ".onyx-maintenance-previous");
        try requireAbsent(self.exe_dir, ".onyx-maintenance-journal");
        return self.references();
    }
    fn references(self: *const Session) types.RecoveryRefs {
        return .{ .runtime_executable = self.exe_path, .previous_artifact = self.previous_path, .journal = self.journal_path, .verified_backup = self.staged_backup_path, .configuration_backup = self.staged_config_path, .restore_drill = self.drill_path };
    }
    fn previousRetained(self: *Session, binding: types.Binding) bool {
        const fd = openAt(self.exe_dir, ".onyx-maintenance-previous", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch return false;
        defer close(fd);
        const info = statFd(fd) catch return false;
        if (!sameFile(info, self.current_info)) return false;
        const sum = hashFd(fd, max_image) catch return false;
        return std.crypto.timing_safe.eql(Digest, sum, binding.current_sha256);
    }
    fn afterExchange(self: *Session, binding: types.Binding, new_info: linux.Statx) !void {
        _ = try self.checkedBackupAge();
        try fsync(self.exe_dir);
        try self.checkProcess(binding);
        try self.checkInputs(binding, false);
        if (self.identity_digest) |expected| {
            const current = (try self.checkIdentityFile()) orelse return error.IdentityChanged;
            if (!std.crypto.timing_safe.eql(Digest, current, expected)) return error.IdentityChanged;
        }
        if (!self.previousRetained(binding)) return error.FileChanged;
        const replacement = try openAt(self.exe_dir, self.exe_name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(replacement);
        if (!sameFile(try statFd(replacement), new_info) or !std.crypto.timing_safe.eql(Digest, try hashFd(replacement, max_image), binding.target_sha256)) return error.FileChanged;
        try requireLive(self.pidfd);
    }
    pub fn apply(self: *Session, binding: types.Binding) !types.ActionResult {
        if (!self.static_passed or !self.backup_passed) return error.MaintenanceNotReviewed;
        const refs = try self.recoveryReferences();
        try self.revalidate(binding);
        const lock = try openAt(self.exe_dir, ".onyx-maintenance.lock", .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
        defer close(lock);
        const lock_info = try statFd(lock);
        if (lock_info.uid != linux.geteuid() or lock_info.mode & std.posix.S.IFMT != std.posix.S.IFREG or lock_info.mode & 0o7777 != 0o600 or lock_info.nlink != 1) return error.InsecureFile;
        if (linux.errno(linux.flock(lock, std.posix.LOCK.EX | std.posix.LOCK.NB)) != .SUCCESS) return error.MaintenanceBusy;
        try self.revalidate(binding);
        const journal = try openAt(self.exe_dir, ".onyx-maintenance-journal", .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
        defer close(journal);
        var journal_buf: [512]u8 = undefined;
        const bytes = try std.fmt.bufPrint(&journal_buf, "prepared pid={d} start={d} backup_generated_at={d} backup_max_age_seconds={d} current={s} target={s} config={s} backup_manifest={s} backup_snapshot={s}\n", .{ binding.pid, binding.start_ticks, self.backup_generated_at, types.default_backup_max_age_seconds, std.fmt.bytesToHex(binding.current_sha256, .lower), std.fmt.bytesToHex(binding.target_sha256, .lower), std.fmt.bytesToHex(binding.config_sha256, .lower), std.fmt.bytesToHex(binding.backup_manifest_sha256, .lower), std.fmt.bytesToHex(self.snapshot_digest, .lower) });
        var journal_digest: Digest = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &journal_digest, .{});
        var checksum_buf: [90]u8 = undefined;
        const checksum = try std.fmt.bufPrint(&checksum_buf, "sha256={s}\n", .{std.fmt.bytesToHex(journal_digest, .lower)});
        var pos: usize = 0;
        while (pos < bytes.len) {
            const n = linux.write(journal, bytes[pos..].ptr, bytes.len - pos);
            if (linux.errno(n) != .SUCCESS or n == 0 or n > bytes.len - pos) return error.WriteFailed;
            pos += n;
        }
        pos = 0;
        while (pos < checksum.len) {
            const n = linux.write(journal, checksum[pos..].ptr, checksum.len - pos);
            if (linux.errno(n) != .SUCCESS or n == 0 or n > checksum.len - pos) return error.WriteFailed;
            pos += n;
        }
        try fsync(journal);
        try fsync(self.exe_dir);
        const staged_write = try copyFd(self.target_fd, self.exe_dir, ".onyx-maintenance-previous", 0o700, max_image);
        if (linux.errno(linux.fchmod(staged_write, 0o700)) != .SUCCESS) {
            close(staged_write);
            return error.WriteFailed;
        }
        fsync(staged_write) catch |err| {
            close(staged_write);
            return err;
        };
        close(staged_write);
        const staged = try openAt(self.exe_dir, ".onyx-maintenance-previous", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer close(staged);
        try privateFile(staged, true);
        const new_info = try statFd(staged);
        if (!std.crypto.timing_safe.eql(Digest, try hashFd(staged, max_image), binding.target_sha256)) return error.FileChanged;
        try self.revalidate(binding);
        try fsync(self.exe_dir);
        const name = try std.posix.toPosixPath(self.exe_name);
        if (linux.errno(linux.renameat2(self.exe_dir, &name, self.exe_dir, ".onyx-maintenance-previous", .{ .EXCHANGE = true })) != .SUCCESS) return error.ExchangeFailed;
        // Never auto-rollback after replacement: the process may have exec'd
        // independently, and any post-cut failure must report retained custody.
        self.afterExchange(binding, new_info) catch return .{ .outcome = .replacement_committed_signal_not_sent, .previous_artifact_retained = self.previousRetained(binding), .recovery_refs = refs };
        if (linux.errno(linux.pidfd_send_signal(self.pidfd, .USR2, null, 0)) != .SUCCESS) return .{ .outcome = .signal_attempt_outcome_unknown, .previous_artifact_retained = self.previousRetained(binding), .recovery_refs = refs };
        for (0..30) |_| {
            var pollrows = [_]linux.pollfd{.{ .fd = self.pidfd, .events = linux.POLL.IN, .revents = 0 }};
            const state = linux.poll(&pollrows, 1, 100);
            if (linux.errno(state) != .SUCCESS) break;
            if (state != 0 and pollrows[0].revents & (linux.POLL.IN | linux.POLL.HUP) != 0) return .{ .outcome = .predecessor_exited, .previous_artifact_retained = self.previousRetained(binding), .recovery_refs = refs };
            if (state != 0 or pollrows[0].revents != 0) break;
            const current = openAt(self.procfd, "exe", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch continue;
            const observed = statFd(current) catch {
                close(current);
                continue;
            };
            close(current);
            if (sameFile(observed, new_info)) return .{ .outcome = .exec_observed, .previous_artifact_retained = self.previousRetained(binding), .recovery_refs = refs };
        }
        return .{ .outcome = .signal_sent_outcome_unknown, .previous_artifact_retained = self.previousRetained(binding), .recovery_refs = refs };
    }
};

test "maintenance directory custody ignores mutable directory size but not security identity" {
    const t = std.testing;
    var a: linux.Statx = std.mem.zeroes(linux.Statx);
    a.dev_major = 1;
    a.dev_minor = 2;
    a.ino = 3;
    a.uid = 4;
    a.gid = 5;
    a.mode = 0o40700;
    a.size = 4096;
    a.nlink = 2;
    var b = a;
    b.size += 4096;
    b.nlink += 1;
    try t.expect(sameDirectory(a, b));
    try t.expect(!sameFile(a, b));
    b.mode = 0o40755;
    try t.expect(!sameDirectory(a, b));
    b = a;
    b.ino += 1;
    try t.expect(!sameDirectory(a, b));
    b = a;
    b.uid += 1;
    try t.expect(!sameDirectory(a, b));
}

test "maintenance ancestry trusts owned protected directories and root sticky parents only" {
    const t = std.testing;
    var st: linux.Statx = std.mem.zeroes(linux.Statx);
    st.uid = 0;
    st.mode = 0o40755;
    try t.expect(trustedDirectoryInfo(st, 1234));
    st.mode = 0o41777;
    try t.expect(trustedDirectoryInfo(st, 1234));
    st.mode = 0o40777;
    try t.expect(!trustedDirectoryInfo(st, 1234));
    st.uid = 1234;
    st.mode = 0o40700;
    try t.expect(trustedDirectoryInfo(st, 1234));
    st.mode = 0o41777;
    try t.expect(!trustedDirectoryInfo(st, 1234));
    st.uid = 2222;
    st.mode = 0o40700;
    try t.expect(!trustedDirectoryInfo(st, 1234));
    st.uid = 1234;
    st.mode = 0o100600;
    try t.expect(!trustedDirectoryInfo(st, 1234));
}

test "maintenance retained evidence requires private owner mode and single link including empty WAL" {
    const t = std.testing;
    var st: linux.Statx = std.mem.zeroes(linux.Statx);
    st.uid = 1234;
    st.mode = 0o100600;
    st.nlink = 1;
    st.size = 0;
    try t.expect(privateEvidenceInfo(st, 1234, true));
    try t.expect(!privateEvidenceInfo(st, 1234, false));
    st.size = 1;
    try t.expect(privateEvidenceInfo(st, 1234, false));
    st.mode = 0o100400;
    try t.expect(privateEvidenceInfo(st, 1234, false));
    st.mode = 0o100644;
    try t.expect(!privateEvidenceInfo(st, 1234, false));
    st.mode = 0o100600;
    st.nlink = 2;
    try t.expect(!privateEvidenceInfo(st, 1234, false));
    st.nlink = 1;
    st.uid = 2222;
    try t.expect(!privateEvidenceInfo(st, 1234, false));
    st.uid = 1234;
    st.mode = 0o120600;
    try t.expect(!privateEvidenceInfo(st, 1234, false));
}

test "maintenance manifest binding rejects same-length rewritten parsed contents" {
    const t = std.testing;
    const parsed = "{\"generated_at\":100,\"name\":\"a\"}";
    const rewritten = "{\"generated_at\":900,\"name\":\"b\"}";
    try t.expectEqual(parsed.len, rewritten.len);
    var parsed_digest: Digest = undefined;
    var rewritten_digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(parsed, &parsed_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(rewritten, &rewritten_digest, .{});
    try t.expect(manifestMatches(parsed_digest, parsed_digest));
    try t.expect(!manifestMatches(parsed_digest, rewritten_digest));
}

test "maintenance live config read keeps custody and refuses broad symlinked or linked files" {
    const t = std.testing;
    const workflow = @import("setup_workflow.zig");
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const a = t.allocator;
    const parent = try tmp.dir.realPathFileAlloc(t.io, ".", a);
    defer a.free(parent);
    const path = try std.fs.path.join(a, &.{ parent, "config.toml" });
    defer a.free(path);
    try workflow.publish(t.io, tmp.dir, "config.toml", "[listen]\nirc = 6680\n");
    // Ancestry outside this test's control (for example a group-writable
    // home) is legitimately refused; the private-file rules still apply.
    const bytes = readLiveConfig(a, path) catch |err| switch (err) {
        error.CustodyUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer a.free(bytes);
    try t.expectEqualStrings("[listen]\nirc = 6680\n", bytes);
    try t.expectError(error.AbsolutePathRequired, readLiveConfig(a, "config.toml"));
    try tmp.dir.symLink(t.io, "config.toml", "link.toml", .{});
    const link = try std.fs.path.join(a, &.{ parent, "link.toml" });
    defer a.free(link);
    if (readLiveConfig(a, link)) |unexpected| {
        a.free(unexpected);
        return error.TestExpectedError;
    } else |_| {}
    try tmp.dir.hardLink("config.toml", tmp.dir, "hard.toml", t.io, .{});
    try t.expectError(error.InsecureFile, readLiveConfig(a, path));
    try tmp.dir.deleteFile(t.io, "hard.toml");
    try tmp.dir.setFilePermissions(t.io, "config.toml", .fromMode(0o644), .{});
    try t.expectError(error.InsecureFile, readLiveConfig(a, path));

    // Saved candidates are new private files and never replace a path.
    const saved = try std.fs.path.join(a, &.{ parent, "candidate.toml" });
    defer a.free(saved);
    try saveCandidate(t.io, saved, "[listen]\nirc = 7000\n");
    try t.expectError(error.PathAlreadyExists, saveCandidate(t.io, saved, "replacement"));
    try t.expectError(error.PathAlreadyExists, saveCandidate(t.io, path, "replacement"));
    const stat = try tmp.dir.statFile(t.io, "candidate.toml", .{});
    try t.expectEqual(@as(u32, 0o600), @as(u32, @intCast(stat.permissions.toMode() & 0o7777)));
    try t.expectError(error.InvalidCandidatePath, saveCandidate(t.io, "/", "x"));
    const reserved = try std.fs.path.join(a, &.{ parent, ".onyx-maintenance-previous" });
    defer a.free(reserved);
    try t.expectError(error.InvalidCandidatePath, saveCandidate(t.io, reserved, "x"));

    // Candidate custody binds the exact saved digest; replay of other bytes fails.
    var want: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash("[listen]\nirc = 7000\n", &want, .{});
    try requireCandidate(a, saved, want);
    var other: Digest = want;
    other[0] ^= 1;
    try t.expectError(error.CandidateChanged, requireCandidate(a, saved, other));
    try tmp.dir.setFilePermissions(t.io, "candidate.toml", .fromMode(0o640), .{});
    try t.expectError(error.InsecureFile, requireCandidate(a, saved, want));
}
