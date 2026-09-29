// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Holds that stay closed until their own Accept says otherwise.
//! GAP-V7: FEC and the congestion modules beside it have no daemon caller.
//! Section 12: armor `enc`, a second WAL, WEBIRC/identd/STARTTLS, and the
//! prototype ring stay out of the live daemon. The section 13 remainder is
//! the live fleet and the kernels this host does not execute.

const std = @import("std");
const builtin = @import("builtin");
const store_mod = @import("store.zig");
const manifest = @import("modules/manifest.zig");
const config_format = @import("config_format.zig");
const io_backend = @import("io_backend.zig");
const kernel_other = @import("kernel_other.zig");

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

    try testing.expect(try fileContains(io, "src/cli/stub_cmds.zig", "openssl-enc-compatible format", testing.allocator));
    try testing.expect(try fileContains(io, "src/cli/armor_main.zig", "error.NotImplemented => std.process.exit(3)", testing.allocator));

    std.debug.print("GAP-C5 branch=FEC modules stay unwired until a measured GAP-V3 signal; section 12 symbols stay absent\n", .{});
}

test "section 13 remainder stays unwitnessed on this host" {
    // These refusals are the Linux host's view. A FreeBSD or Windows run would
    // take the real syscall path and must not be reported as "not executed".
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var defaults = try config_format.parseToml(
        testing.allocator,
        "[node]\nid = 1\n[listen]\nirc = 6680\n",
        .{},
    );
    defer defaults.deinit(testing.allocator);
    try testing.expect(defaults.mesh.relay_v2_authoring == .compat);
    try testing.expect(!defaults.oper_ocg2.projection_enabled);
    try testing.expect(!defaults.oper_ocg2.minting_enabled);
    try testing.expect(!defaults.media.dtls13);
    try testing.expect(!defaults.io.defer_taskrun);
    try testing.expect(defaults.tls.ktls == .off);

    const key: [16]u8 = @splat(0x11);
    const iv: [12]u8 = @splat(0x22);
    const seq: [8]u8 = @splat(0);
    try testing.expectError(error.MissingOp, kernel_other.enableKernelTls(
        0,
        .tx,
        kernel_other.crypto_aes_nist_gcm_16,
        &key,
        &iv,
        seq,
    ));
    try testing.expectError(error.MissingOp, kernel_other.pledgeDaemonPaths());
    try testing.expectError(error.MissingOp, kernel_other.assignDaemonJob());
    try testing.expectError(error.MissingOp, io_backend.IoBackend.openOwned(.iocp, 32, .{}));
    try testing.expectError(error.MissingOp, io_backend.IoBackend.openOwned(.kqueue, 32, .{}));
    try testing.expectError(error.MissingOp, io_backend.loadRegisteredIo(1));
    try testing.expectError(error.Unsupported, io_backend.refusePortableReactor(.windows, 32));
    try testing.expectError(error.Unsupported, io_backend.refusePortableReactor(.freebsd, 32));
    try testing.expectError(error.Unsupported, io_backend.refusePortableReactor(.openbsd, 32));

    var daemon = try std.Io.Dir.cwd().openDir(testing.io, "src/daemon", .{ .iterate = true });
    defer daemon.close(testing.io);
    var hits: usize = 0;
    try scanDaemonImports(testing.io, daemon, testing.allocator, &hits);
    try testing.expectEqual(@as(usize, 0), hits);

    std.debug.print("section 13 remainder branch=no further in-repo witnessable Accept; live IDENTIFY and live relay_v2_authoring=active stay unmet; FreeBSD kqueue, Windows IOCP, FreeBSD kernel TLS, OpenBSD pledge, and Windows RIO were not executed; commit 838ee337 does not close GAP-X3; GAP-K1 stays in the client repo; GAP-V7 stays a hold; section 12 and GAP-N stay unbuilt; headings stay unmarked; roadmap not closed\n", .{});
}
