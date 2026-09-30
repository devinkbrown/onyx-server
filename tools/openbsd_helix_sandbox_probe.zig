// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native VM evidence: execpromises must permit the successor's sandbox install.
const std = @import("std");
const root = @import("onyx_server");
const sys = std.posix.system;
const posix = std.posix;
const runtime = root.daemon.os_runtime;
const control = root.daemon.helix.native_control;
const paths = [_]root.daemon.kernel_other.RuntimeAccess{
    .{ .path = "/tmp", .perms = "rwcx" },
    .{ .path = "/usr", .perms = "rx" },
    .{ .path = "/etc", .perms = "r" },
    .{ .path = "/dev", .perms = "r" },
};
pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    const exe = args.next() orelse return error.MissingExecutable;
    if (args.next()) |arg| {
        if (!std.mem.eql(u8, arg, "--candidate")) return error.InvalidArgument;
        const fd = try std.fmt.parseInt(i32, args.next() orelse return error.MissingDescriptor, 10);
        try runtime.setCloexec(fd, true);
        try root.daemon.kernel_other.pledgeInheritedRuntime();
        // The exec'd successor retains the exact locked view. A path outside
        // the parent's /tmp,/usr,/etc,/dev map remains inaccessible.
        try std.testing.expectError(error.Unexpected, runtime.openReadZ("/bin/sh"));
        try control.send(fd, "EXEC SANDBOX READY", &.{});
        runtime.close(fd);
        return;
    }
    var pair = try control.Pair.init();
    defer pair.deinit();
    var fd_buffer: [32]u8 = undefined;
    const fd_arg = try std.fmt.bufPrintSentinel(&fd_buffer, "{d}", .{pair.child}, 0);
    const exe_z = try init.gpa.dupeSentinel(u8, exe, 0);
    defer init.gpa.free(exe_z);
    const argv = [_:null]?[*:0]const u8{ exe_z.ptr, "--candidate", fd_arg.ptr };
    const env = [_:null]?[*:0]const u8{};
    try runtime.setCloexec(pair.child, false);
    try root.daemon.kernel_other.pledgeRuntimePaths(&paths);
    const pid = sys.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        // No allocations or Zig I/O between fork and immediate exec.
        _ = sys.close(pair.parent);
        _ = sys.execve(exe_z.ptr, &argv, &env);
        sys._exit(127);
    }
    runtime.close(pair.child);
    pair.child = -1;
    var poll = [_]posix.pollfd{.{ .fd = pair.parent, .events = posix.POLL.IN, .revents = 0 }};
    if (sys.poll(&poll, 1, 5000) != 1) {
        _ = sys.kill(pid, posix.SIG.KILL);
        _ = sys.waitpid(pid, null, 0);
        return error.CandidateTimeout;
    }
    var message = try control.receive(pair.parent);
    defer message.deinit();
    var status: c_int = 0;
    if (sys.waitpid(pid, &status, 0) != pid or status != 0) return error.CandidateFailed;
    if (!std.mem.eql(u8, message.bytes(), "EXEC SANDBOX READY")) return error.WrongHandshake;
    std.debug.print("PASS native fork-exec successor sandbox handshake\n", .{});
}
