// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test runner for the real configured-issuer production exec/adopt path.
const std = @import("std");
const server = @import("issuer_production_test_root").daemon.server;
const live = @import("issuer_production_test_root").daemon.helix.live;
pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("issuer-production-helper: {s}\n", .{@errorName(err)});
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
        const refused: ?[]u8 = std.Io.Dir.cwd().readFileAlloc(init.io, "issuer-refuse-capability", init.gpa, .limited(1)) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (refused) |bytes| init.gpa.free(bytes);
        const line = if (refused != null) live.predecessor_issuer_upgrade_capability_token ++ "\n" else live.upgrade_capability_advertisement ++ "\n";
        const result = std.os.linux.write(1, line.ptr, line.len);
        if (std.os.linux.errno(result) != .SUCCESS or result != line.len) return error.OutputFailed;
        return;
    }
    const cut_arg = args.next();
    if (args.next() != null) return error.BadArguments;
    const cut_mode = std.mem.eql(u8, mode, "source-adopt-cut");
    const census = std.mem.eql(u8, mode, "source-adopt-census");
    if (cut_mode) {
        const raw = cut_arg orelse return error.BadArguments;
        if (try std.fmt.parseInt(usize, raw, 10) >= 4096) return error.BadArguments;
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "issuer-adopt-cut", .data = raw });
    } else if (cut_arg != null) return error.BadArguments;
    if (census) try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "issuer-adopt-cut", .data = "census" });
    if (!std.mem.eql(u8, mode, "source") and !std.mem.eql(u8, mode, "source-refuse") and !std.mem.eql(u8, mode, "--supervisor") and !cut_mode and !census) return error.BadArguments;
    if (std.mem.eql(u8, mode, "source-refuse")) try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "issuer-refuse-capability", .data = "1" });
    try server.IssuerProductionExecFixture.run(init.gpa, init.io, mode);
}
