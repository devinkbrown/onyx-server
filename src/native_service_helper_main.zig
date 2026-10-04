// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Separate non-setuid service helper. Management accepts one root-protected
//! canonical policy file; private child mode accepts exactly one inherited FD.
const std = @import("std");
const helper = @import("daemon/native_service_helper.zig");
const service = @import("daemon/native_service.zig");
const platform = @import("substrate/platform.zig");

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next(); // su deliberately supplies the login-decorated argv0.
    const mode = args.next() orelse return error.InvalidArguments;
    if (std.mem.eql(u8, mode, helper.child_arg)) {
        const fd = try std.fmt.parseInt(i32, args.next() orelse return error.InvalidArguments, 10);
        if (fd != 3 or args.next() != null) return error.InvalidArguments;
        try helper.runChild(init.gpa, init.io, fd, init.minimal.environ, platform.monotonicMillis() + 30_000);
    }
    const action = std.meta.stringToEnum(helper.Action, mode) orelse return error.InvalidArguments;
    if (!std.mem.eql(u8, args.next() orelse return error.InvalidArguments, "--policy")) return error.InvalidArguments;
    const path = try service.Path.init(args.next() orelse return error.InvalidArguments);
    var timeout: u31 = 30_000;
    if (args.next()) |option| {
        if (!std.mem.eql(u8, option, "--timeout-ms")) return error.InvalidArguments;
        timeout = try std.fmt.parseInt(u31, args.next() orelse return error.InvalidArguments, 10);
        if (timeout == 0 or args.next() != null) return error.InvalidArguments;
    }
    const deadline = platform.monotonicMillis() + timeout;
    const spec = try helper.loadSpec(path, deadline);
    const outcome = try helper.runRoot(init.gpa, init.io, action, spec, deadline);
    switch (outcome) {
        .pending => return error.OutcomeUnknown,
        .not_running => if (action != .stop) return error.NotRunning,
        .current, .status => |state| std.debug.print("{s} generation={d}\n", .{ @tagName(state.phase), state.generation }),
        .configured => std.debug.print("configuration validated\n", .{}),
        .stopped => std.debug.print("stopped\n", .{}),
    }
}
