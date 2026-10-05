// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kernel confinement for the OS that actually has the call.
//! FreeBSD limits a listening socket with Capsicum and sets SO_REUSEPORT_LB,
//! which is not Linux SO_REUSEPORT. OpenBSD unveils a directory list and
//! pledges the daemon. Windows assigns the process to a job that dies on an
//! unhandled exception. A Helix successor inherits that job. Any other
//! OS, a closed fd, or a kernel status other than success returns MissingOp.
//! This host does not execute those calls. FreeBSD kernel TLS is
//! `setsockopt(IPPROTO_TCP, TCP_TXTLS_ENABLE)` with `struct tls_enable`.
//! Windows RIO is not this module.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{MissingOp};

/// FreeBSD load-balancing reuse. Linux SO_REUSEPORT is a different option.
pub const so_reuseport_lb: u32 = 0x00010000;
pub const sol_socket: i32 = 0xffff;

/// FreeBSD 14 `netinet/tcp.h`. Linux `SOL_TLS` / `TLS_TX` is a different option.
pub const ipproto_tcp: i32 = 6;
pub const tcp_txtls_enable: i32 = 39;
pub const tcp_txtls_mode: i32 = 40;
pub const tcp_rxtls_enable: i32 = 41;
pub const tcp_rxtls_mode: i32 = 42;
pub const tcp_tls_mode_sw: i32 = 1;

/// FreeBSD 14 `opencrypto/cryptodev.h` and `sys/ktls.h`.
pub const crypto_aes_nist_gcm_16: i32 = 25;
pub const crypto_chacha20_poly1305: i32 = 41;
pub const tls_major_ver_one: u8 = 3;
pub const tls_minor_ver_three: u8 = 4;
pub const tls_1_3_iv_len: i32 = 12;

pub const TlsDirection = enum { tx, rx };

/// Userspace `struct tls_enable` from FreeBSD 14 `sys/ktls.h`.
pub const TlsEnable = extern struct {
    cipher_key: ?[*]const u8,
    iv: ?[*]const u8,
    auth_key: ?[*]const u8,
    cipher_algorithm: i32,
    cipher_key_len: i32,
    iv_len: i32,
    auth_algorithm: i32,
    auth_key_len: i32,
    flags: i32,
    tls_vmajor: u8,
    tls_vminor: u8,
    rec_seq: [8]u8,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(TlsEnable) != 64) {
        @compileError("FreeBSD struct tls_enable is 64 bytes on 64-bit");
    }
}

pub const kernel_tls_anchor: *const @TypeOf(enableKernelTls) = &enableKernelTls;
pub const sys_cap_enter: u32 = 516;
pub const sys_cap_getmode: u32 = 517;
pub const sys_cap_rights_limit: u32 = 533;

pub const job_basic_limit_class: u32 = 2;
/// `JobObjectExtendedLimitInformation`. Kill-on-close is rejected
/// (`STATUS_INVALID_PARAMETER`, 0xC000000D) on the basic class.
pub const job_extended_limit_class: u32 = 9;
pub const job_limit_die_on_unhandled: u32 = 0x00000400;
pub const job_limit_kill_on_close: u32 = 0x00002000;

pub const daemon_pledge = "stdio rpath wpath cpath inet dns";
/// Full runtime promises include the transactional Helix candidate process
/// and descriptor transport. Paths remain independently restricted by unveil.
pub const runtime_pledge = "stdio rpath wpath cpath inet unix dns proc exec sendfd recvfd fattr flock getpw";
pub const RuntimeAccess = struct { path: [:0]const u8, perms: [:0]const u8 };
pub const unveil_paths = [_]struct { path: [:0]const u8, perms: [:0]const u8 }{
    .{ .path = "/etc", .perms = "r" },
    .{ .path = "/usr", .perms = "r" },
    .{ .path = "/var", .perms = "rwc" },
    .{ .path = "/tmp", .perms = "rwc" },
};

fn capRight(comptime idx: u6, bit: u64) u64 {
    return (@as(u64, 1) << (57 + idx)) | bit;
}

pub const cap_read = capRight(0, 0x0000000000000001);
pub const cap_write = capRight(0, 0x0000000000000002);
pub const cap_seek = capRight(0, 0x0000000000000004) | 0x0000000000000008;
pub const cap_fcntl = capRight(0, 0x0000000000008000);
pub const cap_fstat = capRight(0, 0x0000000000080000);
pub const cap_accept = capRight(0, 0x0000000020000000);
pub const cap_bind = capRight(0, 0x0000000040000000);
pub const cap_getpeername = capRight(0, 0x0000000100000000);
pub const cap_getsockname = capRight(0, 0x0000000200000000);
pub const cap_getsockopt = capRight(0, 0x0000000400000000);
pub const cap_listen = capRight(0, 0x0000000800000000);
pub const cap_peeloff = capRight(0, 0x0000001000000000);
pub const cap_setsockopt = capRight(0, 0x0000002000000000);
pub const cap_shutdown = capRight(0, 0x0000004000000000);
pub const cap_event = capRight(1, 0x0000000000000020);
/// FreeBSD `CAP_KQUEUE_EVENT` / `CAP_KQUEUE_CHANGE`. `kevent` on a kqueue
/// descriptor needs both. `CAP_EVENT` only covers poll on an ordinary fd.
pub const cap_kqueue_event = capRight(1, 0x0000000000000040);
pub const cap_kqueue_change = capRight(1, 0x0000000000100000);

pub const Rights = extern struct {
    words: [2]u64,
};

fn rightsFrom(index0: u64, index1: u64) Rights {
    return .{
        .words = .{
            capRight(0, 0) | index0,
            capRight(1, 0) | index1,
        },
    };
}

pub fn listenerRights() Rights {
    return rightsFrom(
        cap_read | cap_write | cap_fcntl | cap_fstat | cap_accept | cap_bind |
            cap_getpeername | cap_getsockname | cap_getsockopt | cap_listen |
            cap_peeloff | cap_setsockopt | cap_shutdown,
        cap_event,
    );
}

pub fn stdioRights() Rights {
    return rightsFrom(cap_read | cap_write | cap_seek | cap_fcntl | cap_fstat, cap_event);
}

/// Listener rights plus the two kqueue bits `kevent` checks.
pub fn kqueueRights() Rights {
    const base = listenerRights();
    return .{
        .words = .{
            base.words[0],
            base.words[1] | cap_kqueue_event | cap_kqueue_change,
        },
    };
}

const SockaddrIn6 = extern struct {
    len: u8,
    family: u8,
    port: u16,
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

comptime {
    if (@sizeOf(SockaddrIn6) != 28) @compileError("FreeBSD sockaddr_in6 is 28 bytes");
}

const JobBasicLimit = extern struct {
    per_process_user_time: i64,
    per_job_user_time: i64,
    limit_flags: u32,
    minimum_working_set: usize,
    maximum_working_set: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(JobBasicLimit) != 64) {
        @compileError("JOBOBJECT_BASIC_LIMIT_INFORMATION is 64 bytes on 64-bit");
    }
}

const IoCounters = extern struct {
    read_operation: u64,
    write_operation: u64,
    other_operation: u64,
    read_transfer: u64,
    write_transfer: u64,
    other_transfer: u64,
};

const JobExtendedLimit = extern struct {
    basic: JobBasicLimit,
    io: IoCounters,
    process_memory: usize,
    job_memory: usize,
    peak_process: usize,
    peak_job: usize,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(JobExtendedLimit) != 144) {
        @compileError("JOBOBJECT_EXTENDED_LIMIT_INFORMATION is 144 bytes on 64-bit");
    }
}

/// Install FreeBSD kernel TLS on one direction. AES-GCM (16-byte tag, 16 or
/// 32 byte key) and ChaCha20-Poly1305 (32 byte key) are the TLS 1.3 suites
/// this daemon already offloads. The 12-byte IV is the TLS 1.3 static write
/// IV. Any other cipher, a short IV, a closed fd, or any OS other than
/// FreeBSD returns MissingOp before `setsockopt`.
pub fn enableKernelTls(
    fd: i32,
    direction: TlsDirection,
    cipher_algorithm: i32,
    key: []const u8,
    iv: []const u8,
    rec_seq: [8]u8,
) Error!void {
    if (fd < 0) return error.MissingOp;
    if (iv.len != tls_1_3_iv_len) return error.MissingOp;
    const key_ok = switch (cipher_algorithm) {
        crypto_aes_nist_gcm_16 => key.len == 16 or key.len == 32,
        crypto_chacha20_poly1305 => key.len == 32,
        else => false,
    };
    if (!key_ok) return error.MissingOp;
    if (comptime builtin.os.tag != .freebsd) return error.MissingOp;
    var enable = TlsEnable{
        .cipher_key = key.ptr,
        .iv = iv.ptr,
        .auth_key = null,
        .cipher_algorithm = cipher_algorithm,
        .cipher_key_len = @intCast(key.len),
        .iv_len = tls_1_3_iv_len,
        .auth_algorithm = 0,
        .auth_key_len = 0,
        .flags = 0,
        .tls_vmajor = tls_major_ver_one,
        .tls_vminor = tls_minor_ver_three,
        .rec_seq = rec_seq,
    };
    const opt: i32 = switch (direction) {
        .tx => tcp_txtls_enable,
        .rx => tcp_rxtls_enable,
    };
    if (setsockopt(fd, ipproto_tcp, opt, &enable, @sizeOf(TlsEnable)) != 0) return error.MissingOp;
}

pub fn applyReusePortLb(fd: i32) Error!void {
    if (comptime builtin.os.tag != .freebsd) return error.MissingOp;
    if (fd < 0) return error.MissingOp;
    var yes: i32 = 1;
    if (setsockopt(fd, sol_socket, @intCast(so_reuseport_lb), &yes, 4) != 0) return error.MissingOp;
}

pub fn createLoadBalanceListener(port: u16) Error!i32 {
    if (comptime builtin.os.tag != .freebsd) return error.MissingOp;
    const fd = socket(28, 1, 6);
    if (fd < 0) return error.MissingOp;
    errdefer _ = close(fd);
    try applyReusePortLb(fd);
    var addr = SockaddrIn6{
        .len = 28,
        .family = 28,
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = @splat(0),
        .scope_id = 0,
    };
    if (bind(fd, &addr, 28) != 0) return error.MissingOp;
    if (listen(fd, 128) != 0) return error.MissingOp;
    const rights = listenerRights();
    if (cap_rights_limit(fd, &rights) != 0) return error.MissingOp;
    return fd;
}

pub fn enterDaemonCapsicum(fds: []const i32) Error!void {
    if (comptime builtin.os.tag != .freebsd) return error.MissingOp;
    if (fds.len == 0) {
        freebsdTypecheck(fds.len);
        return error.MissingOp;
    }
    const rights = kqueueRights();
    for (fds) |fd| {
        if (fd < 0) return error.MissingOp;
        if (cap_rights_limit(fd, &rights) != 0) return error.MissingOp;
    }
    // stdout/stderr stay writable after cap_enter so the listen banner and
    // libc logging do not die with ENOTCAPABLE. Skip an fd already limited
    // above, and skip one that is not open.
    const stdio = stdioRights();
    var stdio_fd: i32 = 0;
    while (stdio_fd < 3) : (stdio_fd += 1) {
        var listed = false;
        for (fds) |fd| {
            if (fd == stdio_fd) listed = true;
        }
        if (listed) continue;
        if (fcntl(stdio_fd, 1) < 0) continue;
        if (cap_rights_limit(stdio_fd, &stdio) != 0) return error.MissingOp;
    }
    if (cap_enter() != 0) return error.MissingOp;
    var mode: u32 = 0;
    if (cap_getmode(&mode) != 0) return error.MissingOp;
    if (mode == 0) return error.MissingOp;
}

fn freebsdTypecheck(n: usize) void {
    if (comptime builtin.os.tag != .freebsd) return;
    if (n != 0) {
        const fd = createLoadBalanceListener(1) catch return;
        if (cap_enter() != 0) {
            _ = close(fd);
            return;
        }
        var mode: u32 = 0;
        _ = cap_getmode(&mode);
    }
}

pub fn pledgeDaemonPaths() Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.MissingOp;
    if (daemon_pledge.len == 0) return error.MissingOp;
    for (unveil_paths) |row| {
        if (row.path.len == 0 or row.perms.len == 0) return error.MissingOp;
        if (unveil(row.path.ptr, row.perms.ptr) != 0) return error.MissingOp;
    }
    if (unveil(null, null) != 0) return error.MissingOp;
    if (pledge(daemon_pledge, null) != 0) return error.MissingOp;
}

/// The caller resolves and validates the complete configured path set before
/// this irreversible confinement boundary. No global home-directory allowance.
pub fn pledgeRuntimePaths(paths: []const RuntimeAccess) Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.MissingOp;
    if (paths.len == 0) return error.MissingOp;
    for (paths) |row| {
        if (row.path.len == 0 or row.path[0] != '/' or row.perms.len == 0) return error.MissingOp;
        if (unveil(row.path.ptr, row.perms.ptr) != 0) return error.MissingOp;
    }
    if (unveil(null, null) != 0) return error.MissingOp;
    if (pledge(runtime_pledge, runtime_pledge) != 0) return error.MissingOp;
}

/// An authenticated native Helix successor inherits the predecessor's locked
/// unveil map across fork and exec. It cannot reinstall or widen that map.
/// Call only in the private successor path after validating its control channel.
pub fn pledgeInheritedRuntime() Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.MissingOp;
    if (pledge(runtime_pledge, runtime_pledge) != 0) return error.MissingOp;
}

pub fn assignDaemonJob() Error!void {
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    const windows = std.os.windows;
    const current: windows.HANDLE = @ptrFromInt(std.math.maxInt(usize));
    var in_job: i32 = 0;
    if (IsProcessInJob(current, null, &in_job) == 0) return error.MissingOp;
    // CreateProcess inherits the predecessor's job chain. Reusing it avoids
    // nesting one permanent job per successful Helix generation.
    if (in_job != 0) return;
    var job: windows.HANDLE = undefined;
    const created = NtCreateJobObject(&job, windows.ACCESS_MASK.Specific.JobObject.ALL_ACCESS, null);
    if (created != .SUCCESS) {
        std.debug.print("onyx-server: NtCreateJobObject status=0x{x}\n", .{@intFromEnum(created)});
        return error.MissingOp;
    }
    // Build 22621 rejects the basic class and the combined flags with
    // STATUS_INVALID_PARAMETER. Try the documented flag sets, then assign
    // even if every limit write is refused: a job with default limits still
    // contains the process. An already contained process returned above,
    // including a Helix successor and a WinPE process.
    var limits = std.mem.zeroes(JobExtendedLimit);
    const flag_sets = [_]u32{
        job_limit_die_on_unhandled,
        0,
    };
    var applied = false;
    for (flag_sets) |flags| {
        limits.basic.limit_flags = flags;
        const set = NtSetInformationJobObject(job, job_extended_limit_class, &limits, @sizeOf(JobExtendedLimit));
        if (set == .SUCCESS) {
            std.debug.print("onyx-server: job limit flags=0x{x} applied\n", .{flags});
            applied = true;
            break;
        }
        std.debug.print("onyx-server: job limit flags=0x{x} status=0x{x}\n", .{ flags, @intFromEnum(set) });
    }
    if (!applied) std.debug.print("onyx-server: job limits left at the kernel default\n", .{});
    const assigned = NtAssignProcessToJobObject(job, current);
    if (assigned != .SUCCESS) {
        std.debug.print("onyx-server: NtAssignProcessToJobObject status=0x{x}\n", .{@intFromEnum(assigned)});
        _ = NtClose(job);
        var raced_in_job: i32 = 0;
        if (IsProcessInJob(current, null, &raced_in_job) != 0 and raced_in_job != 0) {
            std.debug.print("onyx-server: process is already in a windows job\n", .{});
            return;
        }
        return error.MissingOp;
    }
    // Keep the job open for process lifetime. Kill-on-close is deliberately
    // absent: after Helix COMMIT the predecessor exits while its successor
    // serves the same live sockets.
    return;
}

extern "c" fn socket(domain: i32, sock_type: i32, protocol: i32) i32;
extern "c" fn setsockopt(sockfd: i32, level: i32, optname: i32, optval: ?*const anyopaque, optlen: u32) i32;
extern "c" fn bind(sockfd: i32, addr: *const SockaddrIn6, addrlen: u32) i32;
extern "c" fn listen(sockfd: i32, backlog: i32) i32;
extern "c" fn close(fd: i32) i32;
extern "c" fn cap_enter() i32;
extern "c" fn cap_getmode(modep: *u32) i32;
extern "c" fn cap_rights_limit(fd: i32, rights: *const Rights) i32;
extern "c" fn fcntl(fd: i32, cmd: i32) i32;
extern "c" fn pledge(promises: ?[*:0]const u8, execpromises: ?[*:0]const u8) i32;
extern "c" fn unveil(path: ?[*:0]const u8, permissions: ?[*:0]const u8) i32;

// OpenBSD 7.9 unistd.h/socket.h. These three target OS entrypoints are absent
// from this SDK's std.c; keep them at the existing required-libc boundary.
extern "c" fn getgroups(count: c_int, groups: ?[*]std.posix.gid_t) c_int;
extern "c" fn getrtable() c_int;
extern "c" fn closefrom(first: c_int) c_int;

pub const ContextError = error{ Unsupported, GroupBufferTooSmall, ObservationFailed, DescriptorClosureFailed };

pub fn openBsdGroups(storage: []std.posix.gid_t) ContextError![]std.posix.gid_t {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    const count = getgroups(0, null);
    if (count < 0) return error.ObservationFailed;
    if (@as(usize, @intCast(count)) > storage.len) return error.GroupBufferTooSmall;
    if (count == 0) return storage[0..0];
    const got = getgroups(count, storage.ptr);
    if (got < 0 or got > count) return error.ObservationFailed;
    return storage[0..@intCast(got)];
}

pub fn openBsdRoutingTable() ContextError!u32 {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    const table = getrtable();
    if (table < 0) return error.ObservationFailed;
    return @intCast(table);
}

/// Intended for the single-threaded, pre-exec child. Preserve descriptors below
/// first, including the one explicitly authorized private service channel.
pub fn openBsdCloseFrom(first: c_int) ContextError!void {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    if (first < 0) return error.DescriptorClosureFailed;
    while (true) {
        switch (std.posix.errno(closefrom(first))) {
            .SUCCESS, .BADF => return,
            .INTR => continue,
            else => return error.DescriptorClosureFailed,
        }
    }
}

extern "ntdll" fn NtCreateJobObject(
    JobHandle: *std.os.windows.HANDLE,
    DesiredAccess: std.os.windows.ACCESS_MASK,
    ObjectAttributes: ?*const anyopaque,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtSetInformationJobObject(
    JobHandle: std.os.windows.HANDLE,
    JobInformationClass: u32,
    JobInformation: *const JobExtendedLimit,
    JobInformationLength: u32,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtAssignProcessToJobObject(
    JobHandle: std.os.windows.HANDLE,
    ProcessHandle: std.os.windows.HANDLE,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "kernel32" fn IsProcessInJob(
    ProcessHandle: std.os.windows.HANDLE,
    JobHandle: ?std.os.windows.HANDLE,
    Result: *i32,
) callconv(.winapi) i32;

extern "ntdll" fn NtClose(Handle: std.os.windows.HANDLE) callconv(.winapi) std.os.windows.NTSTATUS;

test "GAP-X3 FreeBSD Capsicum and SO_REUSEPORT_LB, OpenBSD pledge, and a Windows job fail closed" {
    const linux = std.os.linux;
    const posix = std.posix;

    try std.testing.expectEqual(@as(u32, 0x00010000), so_reuseport_lb);
    try std.testing.expect(so_reuseport_lb != linux.SO.REUSEPORT);
    try std.testing.expectEqual(@as(u32, 516), sys_cap_enter);
    try std.testing.expectEqual(@as(u32, 533), sys_cap_rights_limit);
    try std.testing.expect(std.mem.indexOf(u8, daemon_pledge, "inet") != null);
    try std.testing.expect(unveil_paths.len == 4);
    try std.testing.expect(job_limit_kill_on_close == 0x2000);
    try std.testing.expect(job_limit_die_on_unhandled == 0x400);
    try std.testing.expectEqual(@as(u32, 9), job_extended_limit_class);
    if (@sizeOf(usize) == 8) try std.testing.expectEqual(@as(usize, 144), @sizeOf(JobExtendedLimit));

    const listener = listenerRights();
    try std.testing.expectEqual(cap_accept, listener.words[0] & cap_accept);
    try std.testing.expectEqual(cap_listen, listener.words[0] & cap_listen);
    try std.testing.expectEqual(cap_bind, listener.words[0] & cap_bind);
    try std.testing.expectEqual(cap_event, listener.words[1] & cap_event);
    try std.testing.expectEqual(@as(u64, 0), listener.words[0] >> 62);
    const stdio = stdioRights();
    const kq = kqueueRights();
    try std.testing.expectEqual(cap_kqueue_event, kq.words[1] & cap_kqueue_event);
    try std.testing.expectEqual(cap_kqueue_change, kq.words[1] & cap_kqueue_change);
    try std.testing.expectEqual(cap_event, kq.words[1] & cap_event);
    try std.testing.expectEqual(cap_accept, kq.words[0] & cap_accept);
    try std.testing.expectEqual(cap_read, stdio.words[0] & cap_read);
    try std.testing.expectEqual(cap_write, stdio.words[0] & cap_write);
    const cap_low: u64 = 0x01ffffffffffffff;
    try std.testing.expectEqual(@as(u64, 0), stdio.words[0] & cap_accept & cap_low);

    // This tail probes off-target refusal with Linux syscalls. Calling the
    // supported OpenBSD pledge (or FreeBSD Capsicum) here would irreversibly
    // confine the shared test runner. Native confinement is exercised in the
    // isolated fork/exec sandbox probe instead.
    if (comptime builtin.os.tag != .linux) return;

    try std.testing.expectError(error.MissingOp, applyReusePortLb(-1));
    try std.testing.expectError(error.MissingOp, createLoadBalanceListener(0));
    try std.testing.expectError(error.MissingOp, enterDaemonCapsicum(&.{}));
    try std.testing.expectError(error.MissingOp, enterDaemonCapsicum(&.{0}));
    try std.testing.expectError(error.MissingOp, pledgeDaemonPaths());
    try std.testing.expectError(error.MissingOp, assignDaemonJob());

    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) == .SUCCESS) {
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        try std.testing.expectError(error.MissingOp, applyReusePortLb(fd));
        var val: u32 = 1;
        var len: posix.socklen_t = @sizeOf(u32);
        const got = linux.getsockopt(fd, posix.SOL.SOCKET, linux.SO.REUSEPORT, @ptrCast(&val), &len);
        try std.testing.expect(posix.errno(got) == .SUCCESS);
        try std.testing.expectEqual(@as(u32, 0), val);
    }

    std.debug.print("GAP-X3 branch=freebsd capsicum and SO_REUSEPORT_LB, openbsd pledge and unveil, windows job confinement; this host did not execute them; windows RIO stays unmet\n", .{});
}

test "GAP-X3 FreeBSD kernel TLS fails closed off FreeBSD" {
    try std.testing.expectEqual(@as(i32, 39), tcp_txtls_enable);
    try std.testing.expectEqual(@as(i32, 41), tcp_rxtls_enable);
    try std.testing.expectEqual(@as(i32, 25), crypto_aes_nist_gcm_16);
    try std.testing.expectEqual(@as(i32, 41), crypto_chacha20_poly1305);
    try std.testing.expectEqual(@as(u8, 3), tls_major_ver_one);
    try std.testing.expectEqual(@as(u8, 4), tls_minor_ver_three);
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(TlsEnable));

    const key16: [16]u8 = @splat(0x11);
    const key32: [32]u8 = @splat(0x22);
    const iv: [12]u8 = @splat(0x33);
    const seq = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 };

    try std.testing.expectError(error.MissingOp, enableKernelTls(0, .tx, crypto_aes_nist_gcm_16, &key16, &iv, seq));
    try std.testing.expectError(error.MissingOp, enableKernelTls(0, .rx, crypto_aes_nist_gcm_16, &key32, &iv, seq));
    try std.testing.expectError(error.MissingOp, enableKernelTls(0, .tx, crypto_chacha20_poly1305, &key32, &iv, seq));
    try std.testing.expectError(error.MissingOp, enableKernelTls(-1, .tx, crypto_aes_nist_gcm_16, &key16, &iv, seq));
    try std.testing.expectError(error.MissingOp, enableKernelTls(0, .tx, crypto_aes_nist_gcm_16, &key16, iv[0..4], seq));
    try std.testing.expectError(error.MissingOp, enableKernelTls(0, .tx, 0, &key16, &iv, seq));
    try std.testing.expectError(error.MissingOp, enableKernelTls(0, .tx, crypto_chacha20_poly1305, &key16, &iv, seq));
    std.mem.doNotOptimizeAway(kernel_tls_anchor);

    std.debug.print("GAP-X3 branch=freebsd kernel TLS uses TCP_TXTLS_ENABLE and struct tls_enable; this host did not execute setsockopt; windows RIO stays unmet\n", .{});
}
