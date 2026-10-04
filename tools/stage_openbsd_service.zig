// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Build-host permission finalizer for the selected OpenBSD install artifacts.
//! File creation umask must not make the helper unusable by its nonroot su child.
const std = @import("std");

fn setMode(io: std.Io, prefix: []const u8, relative: []const u8, mode: u16) !void {
    if (comptime !@hasDecl(std.Io.File.Permissions, "fromMode")) return error.UnsupportedPermissions;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = if (relative.len == 0) prefix else try std.fmt.bufPrint(&buffer, "{s}/{s}", .{ prefix, relative });
    try std.Io.Dir.cwd().setFilePermissions(io, path, .fromMode(mode), .{ .follow_symlinks = false });
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const kind = args.next() orelse return error.InvalidArguments;
    const prefix = args.next() orelse return error.InvalidArguments;
    if (args.next() != null or !std.fs.path.isAbsolute(prefix)) return error.InvalidArguments;
    const package = std.mem.eql(u8, kind, "package");
    const assets = package or std.mem.eql(u8, kind, "assets");
    const policy = std.mem.eql(u8, kind, "policy");
    if (!assets and !policy and !std.mem.eql(u8, kind, "helper")) return error.InvalidArguments;
    try setMode(init.io, prefix, "", 0o755);
    try setMode(init.io, prefix, "libexec", 0o755);
    if (!policy) try setMode(init.io, prefix, "libexec/onyx-server-helper", 0o755);
    if (policy or assets) try setMode(init.io, prefix, "libexec/onyx-server-policy", 0o755);
    if (assets) {
        for ([_][]const u8{ "etc", "etc/rc.d", "etc/onyx-server" }) |directory| try setMode(init.io, prefix, directory, 0o755);
        try setMode(init.io, prefix, "etc/rc.d/onyx_server", 0o755);
        try setMode(init.io, prefix, "etc/onyx-server/onyx-server.reference.toml", 0o644);
    }
    if (package) {
        try setMode(init.io, prefix, "bin", 0o755);
        try setMode(init.io, prefix, "bin/onyx-server", 0o755);
    }
}
