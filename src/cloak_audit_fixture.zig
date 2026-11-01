// SPDX-License-Identifier: AGPL-3.0-or-later
//! Acceptance helper only. No production CLI flag, config or live state.
//! Fixed synthetic keys; artifacts never go to stdout/stderr.
const std = @import("std");
const builtin = @import("builtin");
const cloak = @import("proto/cloak.zig");
const access = @import("proto/ircx_access_store.zig");
const access_codec = @import("daemon/helix/access_checkpoint.zig");
const saccess = @import("proto/ircx_saccess.zig");
const saccess_codec = @import("daemon/helix/saccess_checkpoint.zig");
const cli = @import("cli/cloak_audit_cmd.zig");

fn write(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
}

fn oldHost(storage: []u8, key: *const cloak.SecretKey, formula: cli.RawWitness, address: []const u8) ![]const u8 {
    const options = cloak.Options{ .suffix = "onyx" };
    return switch (formula.formula) {
        .opaque_v2 => cloak.cloakOpaque(storage, key, address, options),
        .opaque_epoch_v2 => cloak.cloakOpaqueEpoch(storage, key, address, 7, options),
        .opaque_v3 => cloak.cloakOpaqueV3(storage, key, address, options),
        .opaque_epoch_v3 => cloak.cloakOpaqueEpochV3(storage, key, address, 7, options),
        .opaque_epoch_v4 => cloak.cloakOpaqueEpochV4(storage, key, address, 7, 86_400, options),
        .unsupported => error.InvalidFixture,
    };
}

fn generate(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    var old_key = cloak.SecretKey.init(@splat(0x6a));
    old_key.bytes[0] = 0;
    old_key.bytes[1] = 0x80;
    old_key.bytes[2] = 0xff;
    defer old_key.wipe();
    var target_key = cloak.SecretKey.init(@splat(0x6b));
    target_key.bytes[0] = 0xff;
    target_key.bytes[1] = 0x80;
    target_key.bytes[2] = 0;
    defer target_key.wipe();
    var old_hex = std.fmt.bytesToHex(old_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &old_hex);
    var target_hex = std.fmt.bytesToHex(target_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &target_hex);
    var wrong_hex: [64]u8 = @splat('1');
    defer std.crypto.secureZero(u8, &wrong_hex);
    const address = "203.0.113.9";
    const target = cli.RawTarget{ .key_hex = &target_hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
    var source = access.AccessStore.init(a);
    defer source.deinit();
    source.now_seconds = 100;
    source.local_node = 9;
    source.max_entries = 31;
    source.max_tombstones = 19;
    source.tombstone_ttl_seconds = 271;
    var rows: std.ArrayList(cli.RawWitness) = .empty;
    defer rows.deinit(a);
    const formulas = [_]@FieldType(cli.RawWitness, "formula"){ .opaque_v2, .opaque_epoch_v2, .opaque_v3, .opaque_epoch_v3, .opaque_epoch_v4 };
    for (0..12) |index| {
        const formula = if (index < 5) formulas[index] else .opaque_epoch_v3;
        var row = cli.RawWitness{
            .row = index,
            .expected_mask = "pending",
            .formula = formula,
            .key_hex = &old_hex,
            .address = address,
            .suffix = "onyx",
            .epoch = switch (formula) {
                .opaque_v2, .opaque_v3 => null,
                else => 7,
            },
            .cadence = if (formula == .opaque_epoch_v4) 86_400 else null,
        };
        var storage: [253]u8 = undefined;
        const host = if (index == 7) "*.opq.onyx" else if (index == 10)
            try cloak.cloakOpaqueEpochV4(&storage, &target_key, address, 90, 1_209_600, .{ .suffix = "onyx" })
        else
            try oldHost(&storage, &old_key, row, address);
        const mask = try std.fmt.allocPrint(a, "N{d}*!User?@{s}", .{ index, host });
        defer a.free(mask);
        const issuer = try std.fmt.allocPrint(a, "private-issuer-{d}", .{index});
        defer a.free(issuer);
        const channel = if (index % 2 == 0) "#zRoom" else "#ARoom";
        const duration: ?u64 = switch (index % 3) {
            0 => null,
            1 => 0,
            else => 30,
        };
        try source.add(channel, .deny, mask, issuer, duration);
        row.expected_mask = source.entries.items[index].mask;
        if (index == 5) row.key_hex = &wrong_hex;
        if (index == 8) row.formula = .unsupported;
        if (index == 9) row.address = "not-an-address";
        if (index == 10) {
            row.formula = .opaque_epoch_v4;
            row.key_hex = &target_hex;
            row.epoch = 90;
            row.cadence = 1_209_600;
        }
        if (index == 11) row.expected_mask = "different-mask";
        if (index != 6 and index != 7) try rows.append(a, row);
    }
    try source.add("#Retired", .grant, "*!retired@old.example", "private-retired-issuer", 17);
    if (!try source.remove("#Retired", .grant, "*!retired@old.example")) return error.InvalidFixture;
    const input = try access_codec.encode(a, &source);
    defer a.free(input);
    try write(io, dir, "access.input", input);
    var expected = try access_codec.decode(a, input);
    defer expected.deinit();
    for (expected.entries.items[0..5]) |*entry| {
        const at = std.mem.lastIndexOfScalar(u8, entry.mask, '@') orelse return error.InvalidFixture;
        var storage: [253]u8 = undefined;
        const host = try cloak.cloakOpaqueEpochV4(&storage, &target_key, address, 90, 1_209_600, .{ .suffix = "onyx" });
        const mask = try std.fmt.allocPrint(a, "{s}{s}", .{ entry.mask[0 .. at + 1], host });
        a.free(entry.mask);
        entry.mask = mask;
    }
    const output = try access_codec.encode(a, &expected);
    defer a.free(output);
    if (std.mem.eql(u8, input, output)) return error.VacuousFixture;
    try write(io, dir, "access.expected", output);
    const document = try std.json.Stringify.valueAlloc(a, cli.Document{ .version = 1, .target = target, .witnesses = rows.items }, .{});
    defer {
        std.crypto.secureZero(u8, document);
        a.free(document);
    }
    try write(io, dir, "access.witness", document);
    const missing = try std.json.Stringify.valueAlloc(a, cli.Document{ .version = 1, .target = target, .witnesses = &.{} }, .{});
    defer {
        std.crypto.secureZero(u8, missing);
        a.free(missing);
    }
    try write(io, dir, "access.missing", missing);
    var server = saccess.ServerAccessStore.initWith(a, 23);
    defer server.deinit();
    try server.add(.{ .entry_type = .deny, .mask = "*!private@old.opq.onyx", .duration = 9, .reason = "private-reason" });
    try server.add(.{ .entry_type = .grant, .mask = "*!other@second.example", .duration = 0, .reason = "" });
    try server.add(.{ .entry_type = .deny, .mask = "*!third@third.example", .duration = null, .reason = null });
    const sbytes = try saccess_codec.encode(a, &server);
    defer a.free(sbytes);
    try write(io, dir, "saccess.input", sbytes);
    try write(io, dir, "saccess.witness", "{\"version\":1,\"target\":null,\"witnesses\":[]}");
}

pub fn main(init: std.process.Init) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const path = args.next() orelse return error.InvalidArguments;
    if (!std.fs.path.isAbsolute(path) or args.next() != null) return error.InvalidArguments;
    const dir = try std.Io.Dir.openDirAbsolute(init.io, path, .{ .follow_symlinks = false });
    defer dir.close(init.io);
    var info: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
    while (true) switch (std.os.linux.errno(std.os.linux.statx(dir.handle, "", std.os.linux.AT.EMPTY_PATH, .{ .UID = true, .MODE = true, .TYPE = true }, &info))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.InvalidFixtureDirectory,
    };
    if (!info.mask.UID or !info.mask.MODE or !info.mask.TYPE or info.uid != std.os.linux.geteuid() or info.mode & 0o7777 != 0o700 or info.mode & std.posix.S.IFMT != std.posix.S.IFDIR) return error.InvalidFixtureDirectory;
    generate(init.gpa, init.io, dir) catch {
        std.debug.print("cloak-audit fixture: generation refused\n", .{});
        std.process.exit(1);
    };
}
