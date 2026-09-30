// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exec-first OpenBSD successor negotiation. The fork child performs only
//! async-signal-safe target calls before exec; every service fd stays CLOEXEC.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const platform = @import("../../substrate/platform.zig");
const runtime = @import("../os_runtime.zig");
const control = @import("native_control.zig");
const exchange = @import("native_exchange.zig");
pub const candidate_arg = "--helix-native-successor-v1";
pub const capability = "onyx-native-helix-v1;strict-capsules;indexed-rights;encrypted-arena;inert-ready;commit-owner";
pub const Error = exchange.Error || std.mem.Allocator.Error || error{ ForkFailed, InvalidCandidate, RandomSourceFailed };
pub const Process = struct {
    pid: i32 = -1,
    fd: i32 = -1,
    identity: exchange.Identity,
    committed: bool = false,
    /// Kill and reap an uncommitted candidate before the predecessor resumes.
    pub fn deinit(self: *Process) void {
        if (comptime builtin.os.tag != .openbsd) return;
        runtime.close(self.fd);
        self.fd = -1;
        if (self.pid > 0 and !self.committed) {
            _ = sys.kill(self.pid, posix.SIG.KILL);
            while (true) {
                const rc = sys.waitpid(self.pid, null, 0);
                if (posix.errno(rc) != .INTR) break;
            }
        }
        self.pid = -1;
    }
    pub fn spawn(allocator: std.mem.Allocator, executable: []const u8, config: ?[]const u8, environ: ?std.process.Environ, generation: u64, deadline: i64) Error!Process {
        if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
        if (executable.len == 0 or executable[0] != '/') return error.InvalidCandidate;
        var pair = try control.Pair.init();
        defer pair.deinit();
        var identity: exchange.Identity = .{ .generation = generation, .upgrade_id = undefined };
        try platform.fillOsEntropy(&identity.upgrade_id);
        const executable_z = try allocator.dupeSentinel(u8, executable, 0);
        defer allocator.free(executable_z);
        const config_z = try allocator.dupeSentinel(u8, config orelse "", 0);
        defer allocator.free(config_z);
        var fd_buffer: [32]u8 = undefined;
        var pid_buffer: [32]u8 = undefined;
        var generation_buffer: [32]u8 = undefined;
        var id_buffer: [33]u8 = undefined;
        const fd_arg = std.fmt.bufPrintSentinel(&fd_buffer, "{d}", .{pair.child}, 0) catch return error.InvalidCandidate;
        const parent_arg = std.fmt.bufPrintSentinel(&pid_buffer, "{d}", .{platform.currentPid()}, 0) catch return error.InvalidCandidate;
        const generation_arg = std.fmt.bufPrintSentinel(&generation_buffer, "{d}", .{generation}, 0) catch return error.InvalidCandidate;
        const id_arg = std.fmt.bufPrintSentinel(&id_buffer, "{x}", .{identity.upgrade_id}, 0) catch return error.InvalidCandidate;
        const argv = [_:null]?[*:0]const u8{ executable_z.ptr, candidate_arg, fd_arg.ptr, parent_arg.ptr, generation_arg.ptr, id_arg.ptr, config_z.ptr };
        var environment = if (environ) |existing| try std.process.Environ.createPosixBlock(existing, allocator, .{ .zig_progress_fd = -1 }) else null;
        defer if (environment) |*block| block.deinit(allocator);
        const empty_env = [_:null]?[*:0]const u8{};
        const env: [*:null]const ?[*:0]const u8 = if (environment) |block| block.slice.ptr else &empty_env;
        const child_fd = pair.child;
        const parent_fd = pair.parent;
        const pid = sys.fork();
        if (pid < 0) return error.ForkFailed;
        if (pid == 0) {
            // Prebuilt argv/env only. Do not allocate/log/unwind inherited Zig
            // state or call mutex-bearing cleanup in this multithreaded child.
            _ = sys.close(parent_fd);
            if (sys.fcntl(child_fd, posix.F.SETFD, @as(c_int, 0)) != 0) sys._exit(127);
            _ = sys.execve(executable_z.ptr, &argv, env);
            sys._exit(127);
        }
        runtime.close(pair.child);
        pair.child = -1;
        var process: Process = .{ .pid = pid, .fd = pair.parent, .identity = identity };
        pair.parent = -1;
        errdefer process.deinit();
        const hello: exchange.Header = .{ .kind = .hello, .identity = identity, .index = 0, .total = 1 };
        try exchange.send(process.fd, hello, capability, &.{}, deadline);
        var reply = try exchange.receive(process.fd, .{ .kind = .capabilities, .identity = identity, .index = 0, .total = 1 }, deadline);
        defer reply.deinit();
        if (reply.fd_count != 0 or !std.mem.eql(u8, reply.bytes()[exchange.header_len..], capability)) return error.InvalidCandidate;
        return process;
    }
};

/// Validate the inherited private control channel and the actual predecessor
/// relationship before acknowledging this executed image's complete contract.
pub fn accept(fd: i32, parent_pid: i32, identity: exchange.Identity, deadline: i64) Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    if (fd < 3 or parent_pid <= 0 or sys.getppid() != parent_pid) return error.InvalidCandidate;
    if ((runtime.socketType(fd) catch return error.InvalidCandidate) != posix.SOCK.SEQPACKET) return error.InvalidCandidate;
    runtime.setCloexec(fd, true) catch return error.InvalidCandidate;
    runtime.setNonblocking(fd) catch return error.InvalidCandidate;
    var hello = try exchange.receive(fd, .{ .kind = .hello, .identity = identity, .index = 0, .total = 1 }, deadline);
    defer hello.deinit();
    if (hello.fd_count != 0 or !std.mem.eql(u8, hello.bytes()[exchange.header_len..], capability)) return error.InvalidCandidate;
    try exchange.send(fd, .{ .kind = .capabilities, .identity = identity, .index = 0, .total = 1 }, capability, &.{}, deadline);
}
