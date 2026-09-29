// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Holds that stay closed until their own Accept says otherwise.
//! GAP-V7: FEC and the congestion modules beside it have no daemon caller.
//! Section 12: armor `enc`, a second WAL, WEBIRC/identd/STARTTLS, and the
//! prototype ring stay out of the live daemon.

const std = @import("std");
const store_mod = @import("store.zig");
const manifest = @import("modules/manifest.zig");
const stub_cmds = @import("../cli/stub_cmds.zig");
const common = @import("../cli/common.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;

const fec_files = [_][]const u8{
    "src/substrate/raptorq.zig",
    "src/substrate/reed_solomon.zig",
    "src/substrate/red_fec.zig",
    "src/substrate/media_epoch_key.zig",
    "src/substrate/bbr.zig",
    "src/substrate/cc_cubic.zig",
    "src/substrate/l4s.zig",
};

const family_names = [_][]const u8{
    "accounts",
    "nicks",
    "chanregs",
    "bans",
    "memos",
    "vhosts",
    "props",
    "history",
};

fn fileContains(io: std.Io, path: []const u8, needle: []const u8, allocator: Allocator) !bool {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(20 << 20));
    defer allocator.free(text);
    return std.mem.indexOf(u8, text, needle) != null;
}

fn scanDaemonImports(io: std.Io, dir: std.Io.Dir, allocator: Allocator, hits: *usize) !void {
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind == .directory) {
            var child = try dir.openDir(io, entry.name, .{ .iterate = true });
            defer child.close(io);
            try scanDaemonImports(io, child, allocator, hits);
            continue;
        }
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
        if (std.mem.eql(u8, entry.name, "gap_holds.zig")) continue;
        const text = try dir.readFileAlloc(io, entry.name, allocator, .limited(20 << 20));
        defer allocator.free(text);
        for (fec_files) |path| {
            const base = std.fs.path.basename(path);
            if (std.mem.indexOf(u8, text, base) != null) hits.* += 1;
        }
        if (std.mem.indexOf(u8, text, "identd") != null) hits.* += 1;
    }
}

test "GAP-C5 FEC stays unwired and section 12 symbols stay absent" {
    const io = testing.io;
    for (fec_files) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, testing.allocator, .limited(1 << 20));
        testing.allocator.free(text);
    }

    var daemon = try std.Io.Dir.cwd().openDir(io, "src/daemon", .{ .iterate = true });
    defer daemon.close(io);
    var hits: usize = 0;
    try scanDaemonImports(io, daemon, testing.allocator, &hits);
    try testing.expectEqual(@as(usize, 0), hits);

    try testing.expect(!try fileContains(io, "src/daemon/server.zig", "io/ring.zig", testing.allocator));
    try testing.expect(try fileContains(io, "src/substrate/io/ring.zig", "not the production backend", testing.allocator));

    const names = @typeInfo(store_mod.Family).@"enum".field_names;
    try testing.expectEqual(family_names.len, names.len);
    for (family_names, names) |name, field| {
        try testing.expectEqualStrings(name, field);
    }
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().openFile(io, "src/daemon/second_wal.zig", .{ .mode = .read_only }));

    try testing.expect(manifest.Live.lookupCommand("WEBIRC") == null);
    try testing.expect(manifest.Live.lookupCommand("STARTTLS") == null);
    try testing.expect(manifest.Live.lookupCommand("IDENT") == null);

    var aw = common.Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try testing.expectError(error.NotImplemented, stub_cmds.run("enc", &aw.writer));
    try testing.expect(std.mem.indexOf(u8, aw.written(), "openssl-enc-compatible format") != null);
    try testing.expect(try fileContains(io, "src/cli/armor_main.zig", "error.NotImplemented => std.process.exit(3)", testing.allocator));

    std.debug.print("GAP-C5 branch=FEC modules stay unwired until a measured GAP-V3 signal; section 12 symbols stay absent\n", .{});
}
