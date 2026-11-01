// SPDX-License-Identifier: AGPL-3.0-or-later
//! Thin runner: fixture data and actor ownership remain inside real Core.
const std = @import("std");
const tested = @import("session_retry_test_root");
const live = tested.daemon.helix.live;
pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("session-retry-helper error={s}\n", .{@errorName(err)});
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
        const text = live.upgrade_capability_advertisement ++ "\n";
        const n = std.os.linux.write(1, text.ptr, text.len);
        if (std.os.linux.errno(n) != .SUCCESS or n != text.len) return error.OutputFailed;
        return;
    }
    const successor = std.mem.eql(u8, mode, "--supervisor");
    const is_source = std.mem.eql(u8, mode, "source") or std.mem.eql(u8, mode, "publication-source");
    const is_peer = std.mem.eql(u8, mode, "peer") or std.mem.eql(u8, mode, "publication-peer");
    if (!successor and !is_source and !is_peer) return error.BadArguments;
    const peer_port = if (successor) blk: {
        if (args.next() != null) return error.BadArguments;
        const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, "retry-peer-port", init.gpa, .limited(8));
        defer init.gpa.free(bytes);
        break :blk try std.fmt.parseInt(u16, bytes, 10);
    } else blk: {
        const raw = args.next() orelse return error.BadArguments;
        if (args.next() != null) return error.BadArguments;
        const port = try std.fmt.parseInt(u16, raw, 10);
        if (is_source) try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "retry-peer-port", .data = raw });
        break :blk port;
    };
    if (peer_port == 0) return error.BadArguments;
    try tested.daemon.server.SessionRetryExecFixture.run(init.gpa, init.io, mode, peer_port);
}
