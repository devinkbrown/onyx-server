// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test runner for the actual host-presentation Helix exec/adopt path.
const std = @import("std");
const server = @import("host_presentation_test_root").daemon.server;
const live = @import("host_presentation_test_root").daemon.helix.live;
pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("host-presentation-helper: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}
fn run(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next() orelse return error.BadArguments;
    if (std.mem.eql(u8, mode, live.upgrade_capability_arg)) {
        if (args.next() != null) return error.BadArguments;
        const line = live.upgrade_capability_advertisement ++ "\n";
        const result = std.os.linux.write(1, line.ptr, line.len);
        if (std.os.linux.errno(result) != .SUCCESS or result != line.len) return error.OutputFailed;
        return;
    }
    if (args.next() != null) return error.BadArguments;
    if (!std.mem.eql(u8, mode, "source") and !std.mem.eql(u8, mode, "source-unknown") and !std.mem.eql(u8, mode, "--supervisor")) return error.BadArguments;
    try server.HostPresentationExecFixture.run(init.gpa, init.io, mode);
}
