// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kernel confinement for the OS that actually has the call.
//! FreeBSD limits a listening socket with Capsicum and sets SO_REUSEPORT_LB,
//! which is not Linux SO_REUSEPORT. OpenBSD unveils a directory list and
//! pledges the daemon. Windows assigns the process to a job that dies on an
//! unhandled exception and is killed when the job handle closes. Any other
//! OS, a closed fd, or a kernel status other than success returns MissingOp.
//! This host does not execute those calls. FreeBSD kernel TLS and Windows
//! RIO are not this module.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{MissingOp};

/// FreeBSD load-balancing reuse. Linux SO_REUSEPORT is a different option.
pub const so_reuseport_lb: u32 = 0x00010000;
pub const sol_socket: i32 = 0xffff;
pub const sys_cap_enter: u32 = 516;
pub const sys_cap_getmode: u32 = 517;
pub const sys_cap_rights_limit: u32 = 533;

pub const job_basic_limit_class: u32 = 2;
pub const job_limit_die_on_unhandled: u32 = 0x00000400;
pub const job_limit_kill_on_close: u32 = 0x00002000;

pub const daemon_pledge = "stdio rpath wpath cpath inet dns";
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
    const rights = listenerRights();
    for (fds) |fd| {
        if (fd < 0) return error.MissingOp;
        if (cap_rights_limit(fd, &rights) != 0) return error.MissingOp;
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

pub fn assignDaemonJob() Error!void {
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    const windows = std.os.windows;
    var job: windows.HANDLE = undefined;
    const created = NtCreateJobObject(&job, windows.ACCESS_MASK.Specific.JobObject.ALL_ACCESS, null);
    if (created != .SUCCESS) return error.MissingOp;
    var limits = std.mem.zeroes(JobBasicLimit);
    limits.limit_flags = job_limit_die_on_unhandled | job_limit_kill_on_close;
    const set = NtSetInformationJobObject(job, job_basic_limit_class, &limits, @sizeOf(JobBasicLimit));
    if (set != .SUCCESS) {
        _ = NtClose(job);
        return error.MissingOp;
    }
    const current: windows.HANDLE = @ptrFromInt(std.math.maxInt(usize));
    const assigned = NtAssignProcessToJobObject(job, current);
    if (assigned != .SUCCESS) {
        _ = NtClose(job);
        return error.MissingOp;
    }
    // The job stays open. Closing it would kill this process.
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
extern "c" fn pledge(promises: ?[*:0]const u8, execpromises: ?[*:0]const u8) i32;
extern "c" fn unveil(path: ?[*:0]const u8, permissions: ?[*:0]const u8) i32;

extern "ntdll" fn NtCreateJobObject(
    JobHandle: *std.os.windows.HANDLE,
    DesiredAccess: std.os.windows.ACCESS_MASK,
    ObjectAttributes: ?*const anyopaque,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtSetInformationJobObject(
    JobHandle: std.os.windows.HANDLE,
    JobInformationClass: u32,
    JobInformation: *const JobBasicLimit,
    JobInformationLength: u32,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtAssignProcessToJobObject(
    JobHandle: std.os.windows.HANDLE,
    ProcessHandle: std.os.windows.HANDLE,
) callconv(.winapi) std.os.windows.NTSTATUS;

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

    const listener = listenerRights();
    try std.testing.expectEqual(cap_accept, listener.words[0] & cap_accept);
    try std.testing.expectEqual(cap_listen, listener.words[0] & cap_listen);
    try std.testing.expectEqual(cap_bind, listener.words[0] & cap_bind);
    try std.testing.expectEqual(cap_event, listener.words[1] & cap_event);
    try std.testing.expectEqual(@as(u64, 0), listener.words[0] >> 62);
    const stdio = stdioRights();
    try std.testing.expectEqual(cap_read, stdio.words[0] & cap_read);
    try std.testing.expectEqual(cap_write, stdio.words[0] & cap_write);
    const cap_low: u64 = 0x01ffffffffffffff;
    try std.testing.expectEqual(@as(u64, 0), stdio.words[0] & cap_accept & cap_low);

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

    std.debug.print("GAP-X3 branch=freebsd capsicum and SO_REUSEPORT_LB, openbsd pledge and unveil, windows job kill-on-close; this host did not execute them; freebsd kernel tls and windows RIO stay unmet\n", .{});
}
