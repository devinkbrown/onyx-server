// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux kernel operations the daemon actually uses.
//! Listener sockets get TCP_FASTOPEN, TCP_USER_TIMEOUT, and SO_INCOMING_CPU.
//! The process path also uses pidfd, close_range, openat2 RESOLVE flags,
//! landlock, and a seccomp denylist. A missing operation is an error.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

/// Pending TFO handshakes the listener will accept. Set before listen.
pub const fastopen_queue: u32 = 256;
/// Unacked data abort, in milliseconds. Idle clients are not affected.
pub const user_timeout_ms: u32 = 30_000;

/// CPU index for SO_INCOMING_CPU. Shards spread across the machine's CPUs;
/// a one-CPU host stays on CPU 0.
pub fn shardIncomingCpu(shard_id: u12) u32 {
    const n = std.Thread.getCpuCount() catch 1;
    const cpus: usize = if (n == 0) 1 else n;
    return @intCast(@as(usize, shard_id) % cpus);
}

pub fn applyListenerOptions(fd: linux.fd_t) error{ PermissionDenied, Unexpected }!void {
    try setU32(fd, linux.IPPROTO.TCP, linux.TCP.FASTOPEN, fastopen_queue);
    try setU32(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, user_timeout_ms);
    try setU32(fd, posix.SOL.SOCKET, linux.SO.INCOMING_CPU, 0);
}

pub fn setIncomingCpu(fd: linux.fd_t, cpu: u32) error{ PermissionDenied, Unexpected }!void {
    try setU32(fd, posix.SOL.SOCKET, linux.SO.INCOMING_CPU, cpu);
}

pub fn readU32Option(fd: linux.fd_t, level: i32, optname: u32) error{Unexpected}!u32 {
    var val: u32 = 0;
    var len: posix.socklen_t = @sizeOf(u32);
    const rc = linux.getsockopt(fd, level, optname, @ptrCast(&val), &len);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return val;
}

fn setU32(fd: linux.fd_t, level: i32, optname: u32, value: u32) error{ PermissionDenied, Unexpected }!void {
    var stored = value;
    const rc = linux.setsockopt(fd, level, optname, @ptrCast(&stored), @sizeOf(u32));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}

pub const resolve_no_magiclinks: u64 = 0x02;
pub const resolve_beneath: u64 = 0x08;

/// Count of openat2 calls that passed RESOLVE_BENEATH. The certificate reader
/// increments this for a regular file contained in its parent directory.
pub var beneath_open_count: usize = 0;

const abi1_access: u64 = (1 << 13) - 1;

const OpenHow = extern struct {
    flags: u64,
    mode: u64,
    resolve: u64,
};

pub fn openSelfPidfd() error{Unexpected}!linux.fd_t {
    const rc = linux.pidfd_open(linux.getpid(), 0);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return @intCast(rc);
}

/// Close `fds` with one close_range when they are a contiguous span above
/// stdio. A non-contiguous span is closed one fd at a time and reports false.
pub fn closeOwnedFdSpan(fds: []const linux.fd_t) error{Unexpected}!bool {
    if (fds.len == 0) return false;
    var min_fd: linux.fd_t = fds[0];
    var max_fd: linux.fd_t = fds[0];
    for (fds) |fd| {
        if (fd < 3) return error.Unexpected;
        if (fd < min_fd) min_fd = fd;
        if (fd > max_fd) max_fd = fd;
    }
    const span: usize = @intCast(max_fd - min_fd + 1);
    if (span != fds.len) {
        for (fds) |fd| _ = linux.close(fd);
        return false;
    }
    const flags: linux.CLOSE_RANGE = .{ .UNSHARE = false, .CLOEXEC = false };
    const rc = linux.close_range(min_fd, max_fd, flags);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return true;
}

pub const ReadError = error{
    FileNotFound,
    AccessDenied,
    FileTooBig,
    Unexpected,
    NameTooLong,
    OutOfMemory,
};

/// Read `path` through openat2. A regular final component uses
/// RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS. A normal symlink is followed with
/// RESOLVE_NO_MAGICLINKS so a certificate path may point outside its directory.
pub fn readFileResolved(allocator: std.mem.Allocator, path: []const u8, max_len: usize) ReadError![]u8 {
    if (path.len == 0 or path.len >= linux.PATH_MAX) return error.NameTooLong;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or base.len >= linux.NAME_MAX) return error.NameTooLong;
    const parent = std.fs.path.dirname(path) orelse ".";
    var parent_z: [linux.PATH_MAX]u8 = undefined;
    if (parent.len >= parent_z.len) return error.NameTooLong;
    @memcpy(parent_z[0..parent.len], parent);
    parent_z[parent.len] = 0;
    var base_z: [linux.NAME_MAX]u8 = undefined;
    @memcpy(base_z[0..base.len], base);
    base_z[base.len] = 0;

    const dirfd = try openAt2(linux.AT.FDCWD, parent_z[0..parent.len :0], .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0, resolve_no_magiclinks);
    defer _ = linux.close(dirfd);

    var link_buf: [8]u8 = undefined;
    const link_rc = linux.readlinkat(dirfd, base_z[0..base.len :0], &link_buf, link_buf.len);
    const resolve: u64 = switch (posix.errno(link_rc)) {
        .INVAL => blk: {
            beneath_open_count += 1;
            break :blk resolve_beneath | resolve_no_magiclinks;
        },
        .SUCCESS => resolve_no_magiclinks,
        .NOENT => return error.FileNotFound,
        else => return error.Unexpected,
    };
    const fd = try openAt2(dirfd, base_z[0..base.len :0], .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0, resolve);
    defer _ = linux.close(fd);
    return readFdBounded(allocator, fd, max_len);
}

fn openAt2(dirfd: linux.fd_t, path: [*:0]const u8, flags: linux.O, mode: u64, resolve: u64) ReadError!linux.fd_t {
    var how = OpenHow{ .flags = @as(u32, @bitCast(flags)), .mode = mode, .resolve = resolve };
    const rc = linux.syscall4(
        .openat2,
        @as(u32, @bitCast(dirfd)),
        @intFromPtr(path),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    );
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .NOENT => error.FileNotFound,
        .ACCES, .PERM, .LOOP, .XDEV => error.AccessDenied,
        .NAMETOOLONG => error.NameTooLong,
        else => error.Unexpected,
    };
}

fn readFdBounded(allocator: std.mem.Allocator, fd: linux.fd_t, max_len: usize) ReadError![]u8 {
    const buf = try allocator.alloc(u8, max_len);
    errdefer allocator.free(buf);
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = linux.read(fd, buf[filled..].ptr, buf.len - filled);
        switch (posix.errno(n)) {
            .SUCCESS => {
                if (n == 0) break;
                filled += n;
            },
            .INTR => continue,
            else => return error.Unexpected,
        }
    }
    if (filled == buf.len) {
        var extra: [1]u8 = undefined;
        const n = linux.read(fd, &extra, 1);
        switch (posix.errno(n)) {
            .SUCCESS => if (n != 0) return error.FileTooBig,
            .INTR => return error.FileTooBig,
            else => return error.Unexpected,
        }
    }
    if (filled == buf.len) return buf;
    return allocator.realloc(buf, filled) catch return error.OutOfMemory;
}

const LandlockRulesetAttr = extern struct {
    handled_access_fs: u64,
};

const LandlockPathBeneath = extern struct {
    allowed_access: u64,
    parent_fd: i32,
};

pub const SandboxDir = struct {
    fd: linux.fd_t,
    allowed: u64,
};

pub fn restrictFilesystem(dirs: []const SandboxDir) error{Unexpected}!void {
    // landlock_restrict_self returns EPERM unless no_new_privs is set or the
    // caller holds CAP_SYS_ADMIN. The bit is irreversible and stays in this
    // process, which is the forked proof or the long-running main path.
    const no_new = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    if (posix.errno(no_new) != .SUCCESS) return error.Unexpected;
    const abi = landlockAbi() catch return error.Unexpected;
    if (abi < 1) return error.Unexpected;
    var attr = LandlockRulesetAttr{ .handled_access_fs = abi1_access };
    const ruleset_rc = linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), @sizeOf(LandlockRulesetAttr), 0);
    if (posix.errno(ruleset_rc) != .SUCCESS) return error.Unexpected;
    const ruleset: linux.fd_t = @intCast(ruleset_rc);
    defer _ = linux.close(ruleset);
    for (dirs) |dir| {
        if ((dir.allowed & ~abi1_access) != 0) return error.Unexpected;
        var rule = LandlockPathBeneath{ .allowed_access = dir.allowed, .parent_fd = dir.fd };
        const add = linux.syscall4(.landlock_add_rule, @as(u32, @bitCast(ruleset)), 1, @intFromPtr(&rule), 0);
        if (posix.errno(add) != .SUCCESS) return error.Unexpected;
    }
    const restricted = linux.syscall2(.landlock_restrict_self, @as(u32, @bitCast(ruleset)), 0);
    if (posix.errno(restricted) != .SUCCESS) return error.Unexpected;
}

fn landlockAbi() error{Unexpected}!u64 {
    const rc = linux.syscall3(.landlock_create_ruleset, 0, 0, 1);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return rc;
}

const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

const bpf_ld_w_abs: u16 = 0x20;
const bpf_jmp_jeq_k: u16 = 0x15;
const bpf_ret_k: u16 = 0x06;
const seccomp_ret_allow: u32 = 0x7fff0000;
const seccomp_ret_errno_eperm: u32 = 0x00050001;

fn bpfStmt(code: u16, k: u32) SockFilter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn bpfJump(code: u16, k: u32, jt: u8, jf: u8) SockFilter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

/// Default-allow filter that returns EPERM for ptrace, reboot, kexec_load,
/// init_module, delete_module, and swapon. Requires NO_NEW_PRIVS.
pub fn installSyscallDenylist() error{Unexpected}!void {
    const arch: u32 = switch (builtin.cpu.arch) {
        .x86_64 => 0xC000003E,
        .aarch64 => 0xC00000B7,
        .arm, .thumb => 0x40000028,
        .riscv64 => 0xC00000F3,
        else => 0,
    };
    const denied = [_]u32{
        @intCast(@intFromEnum(linux.SYS.ptrace)),
        @intCast(@intFromEnum(linux.SYS.reboot)),
        @intCast(@intFromEnum(linux.SYS.kexec_load)),
        @intCast(@intFromEnum(linux.SYS.init_module)),
        @intCast(@intFromEnum(linux.SYS.delete_module)),
        @intCast(@intFromEnum(linux.SYS.swapon)),
    };
    var filters: [3 + 1 + denied.len * 2 + 1]SockFilter = undefined;
    var n: usize = 0;
    if (arch != 0) {
        filters[n] = bpfStmt(bpf_ld_w_abs, 4);
        n += 1;
        filters[n] = bpfJump(bpf_jmp_jeq_k, arch, 1, 0);
        n += 1;
        filters[n] = bpfStmt(bpf_ret_k, seccomp_ret_allow);
        n += 1;
    }
    filters[n] = bpfStmt(bpf_ld_w_abs, 0);
    n += 1;
    for (denied) |nr| {
        filters[n] = bpfJump(bpf_jmp_jeq_k, nr, 0, 1);
        n += 1;
        filters[n] = bpfStmt(bpf_ret_k, seccomp_ret_errno_eperm);
        n += 1;
    }
    filters[n] = bpfStmt(bpf_ret_k, seccomp_ret_allow);
    n += 1;

    const no_new = linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    if (posix.errno(no_new) != .SUCCESS) return error.Unexpected;
    var prog = SockFprog{ .len = @intCast(n), .filter = &filters };
    const rc = linux.syscall3(.seccomp, linux.SECCOMP.SET_MODE_FILTER, 0, @intFromPtr(&prog));
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
}

const standard_read_dirs = [_][:0]const u8{
    "/proc", "/dev",  "/sys", "/etc",  "/usr", "/lib", "/lib64",
    "/bin",  "/sbin", "/opt", "/boot", "/nix", "/gnu", "/root",
};

const standard_write_dirs = [_][:0]const u8{
    "/tmp", "/run", "/var", "/home", "/srv", "/data", "/mnt", "/media",
};

/// Landlock allowlist for the directories the daemon reads and writes, then
/// the syscall denylist. Called from main on the long-running path.
pub fn installDaemonSandbox(config_path: ?[]const u8) error{Unexpected}!void {
    var fds: [32]linux.fd_t = undefined;
    var dirs: [32]SandboxDir = undefined;
    var count: usize = 0;
    errdefer {
        for (fds[0..count]) |fd| _ = linux.close(fd);
    }

    for (standard_read_dirs) |path| {
        if (count >= dirs.len) break;
        const fd = openDirPath(path) orelse continue;
        fds[count] = fd;
        dirs[count] = .{ .fd = fd, .allowed = (1 << 0) | (1 << 2) | (1 << 3) };
        count += 1;
    }
    for (standard_write_dirs) |path| {
        if (count >= dirs.len) break;
        const fd = openDirPath(path) orelse continue;
        fds[count] = fd;
        dirs[count] = .{ .fd = fd, .allowed = abi1_access };
        count += 1;
    }
    var cwd_buf: [linux.PATH_MAX]u8 = undefined;
    const cwd_rc = linux.getcwd(&cwd_buf, cwd_buf.len);
    if (posix.errno(cwd_rc) == .SUCCESS and count < dirs.len) {
        const cwd = std.mem.sliceTo(&cwd_buf, 0);
        if (openDirPath(cwd_buf[0..cwd.len :0])) |fd| {
            fds[count] = fd;
            dirs[count] = .{ .fd = fd, .allowed = abi1_access };
            count += 1;
        }
    }
    if (config_path) |path| {
        if (std.fs.path.dirname(path)) |parent| {
            if (parent.len < linux.PATH_MAX and count < dirs.len) {
                var parent_z: [linux.PATH_MAX]u8 = undefined;
                @memcpy(parent_z[0..parent.len], parent);
                parent_z[parent.len] = 0;
                if (openDirPath(parent_z[0..parent.len :0])) |fd| {
                    fds[count] = fd;
                    dirs[count] = .{ .fd = fd, .allowed = abi1_access };
                    count += 1;
                }
            }
        }
    }
    if (count == 0) return error.Unexpected;
    try restrictFilesystem(dirs[0..count]);
    for (fds[0..count]) |fd| _ = linux.close(fd);
    count = 0;
    try installSyscallDenylist();
}

fn openDirPath(path: [*:0]const u8) ?linux.fd_t {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const rc = linux.openat(linux.AT.FDCWD, path, flags, 0);
    if (posix.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

/// Forked proof of the landlock ruleset and the seccomp denylist. Exit 0 is
/// the passing child. The parent is not sandboxed.
pub fn sandboxChildStatus() u8 {
    var dir_buf: [80]u8 = undefined;
    const dir = std.fmt.bufPrintSentinel(&dir_buf, "/tmp/onyx-x3-ll-{d}", .{linux.getpid()}, 0) catch return 2;
    if (posix.errno(linux.mkdir(dir.ptr, 0o700)) != .SUCCESS) return 2;
    var file_buf: [96]u8 = undefined;
    const file_path = std.fmt.bufPrintSentinel(&file_buf, "{s}/inside", .{dir}, 0) catch return 2;
    const created = linux.openat(linux.AT.FDCWD, file_path.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o644);
    if (posix.errno(created) != .SUCCESS) return 2;
    const created_fd: linux.fd_t = @intCast(created);
    const wrote = linux.write(created_fd, "ok".ptr, 2);
    _ = linux.close(created_fd);
    if (posix.errno(wrote) != .SUCCESS) return 2;

    const dirfd = openDirPath(dir.ptr) orelse return 9;
    restrictFilesystem(&.{.{ .fd = dirfd, .allowed = (1 << 2) | (1 << 3) }}) catch {
        _ = linux.close(dirfd);
        return 3;
    };
    _ = linux.close(dirfd);

    const inside = openAt2(linux.AT.FDCWD, file_path.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0, resolve_no_magiclinks) catch return 4;
    _ = linux.close(inside);
    if (openAt2(linux.AT.FDCWD, "/etc/hostname", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0, resolve_no_magiclinks)) |outside| {
        _ = linux.close(outside);
        return 5;
    } else |_| {}

    installSyscallDenylist() catch return 6;
    const closed = linux.close(-1);
    if (posix.errno(closed) != .BADF) return 7;
    const traced = linux.syscall4(.ptrace, 0, 0, 0, 0);
    if (posix.errno(traced) != .PERM) return 8;
    return 0;
}
