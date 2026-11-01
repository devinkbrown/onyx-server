// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Synthetic acceptance fixture only; never installed and never uses audit logic
//! to construct the expected output. No secrets or checkpoint data to stdout.
const std = @import("std");
const cloak = @import("proto/cloak.zig");
const cli = @import("cli/cloak_audit_cmd.zig");
const akick = @import("daemon/svc_akick.zig");
const akcodec = @import("daemon/helix/akick_checkpoint.zig");
const ward = @import("daemon/warden.zig");
const wardcodec = @import("daemon/helix/ward_checkpoint.zig");
const old_hex = "7171717171717171717171717171717171717171717171717171717171717171";
const new_hex = "7272727272727272727272727272727272727272727272727272727272727272";
const address = "203.0.113.9";
fn write(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const f = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, bytes);
    try f.sync(io);
}
fn masks(a: std.mem.Allocator, new: bool) ![2][]u8 {
    var key = cloak.SecretKey.init(@splat(if (new) 0x72 else 0x71));
    defer key.wipe();
    var host_buf: [253]u8 = undefined;
    const host = if (new)
        try cloak.cloakOpaqueEpochV4(&host_buf, &key, address, 90, 1_209_600, .{ .suffix = "onyx" })
    else
        try cloak.cloakOpaqueEpochV3(&host_buf, &key, address, 7, .{ .suffix = "onyx" });
    const one = try std.fmt.allocPrint(a, "nick*!u@{s}", .{host});
    errdefer a.free(one);
    const two = try std.fmt.allocPrint(a, "n?ck!u@{s}", .{host});
    return .{ one, two };
}
fn generate(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    const old = try masks(a, false);
    defer for (old) |value| a.free(value);
    const new = try masks(a, true);
    defer for (new) |value| a.free(value);
    for ([_]bool{ false, true }) |replacement| {
        const m = if (replacement) new else old;
        var store = akick.AkickStore.initCapacity(a, 7);
        defer store.deinit();
        try store.checkpointEnsureChannel("#empty");
        try store.add("#expired", "*!*@expired.example", "expired", "IssuerE", -42, -1);
        try store.add("#z", m[0], "first", "IssuerA", -42, 100);
        try store.add("#z", m[1], "second", "IssuerB", 4, null);
        try store.add("#z", "account:operator*", "account", "IssuerC", 5, null);
        const bytes = try akcodec.encode(a, &store);
        defer a.free(bytes);
        try write(io, dir, if (replacement) "akick.expected" else "akick.input", bytes);
        var registry = ward.Registry.init(a, .{ .max_wards = 9, .max_pattern = 256, .max_reason = 111, .max_setter = 63 });
        defer registry.deinit();
        try registry.add(.{ .match = .mask, .pattern = m[0], .scope = .mesh, .action = .quarantine, .reason = "first", .set_by = "IssuerA", .created_ms = -42, .expires_ms = 100 });
        try registry.add(.{ .match = .mask, .pattern = m[1], .scope = .node, .action = .refuse, .reason = "second", .set_by = "IssuerB", .created_ms = 4 });
        try registry.add(.{ .match = .account, .pattern = "operator*", .action = .require_auth, .reason = "account", .created_ms = 5 });
        try registry.add(.{ .match = .address, .pattern = "198.51.100.0/24", .action = .expel, .reason = "address", .created_ms = 6 });
        try registry.add(.{ .match = .host, .pattern = "expired.example", .reason = "expired", .created_ms = -42, .expires_ms = -1 });
        const wbytes = try wardcodec.encode(a, &registry);
        defer a.free(wbytes);
        try write(io, dir, if (replacement) "ward.expected" else "ward.input", wbytes);
    }
    for ([_][]const u8{ "akick", "ward" }) |kind| {
        const first: usize = if (std.mem.eql(u8, kind, "akick")) 1 else 0;
        var rows = [_]cli.RawWitness{
            .{ .row = first, .expected_mask = old[0], .formula = .opaque_epoch_v3, .key_hex = old_hex, .address = address, .suffix = "onyx", .epoch = 7, .cadence = null },
            .{ .row = first + 1, .expected_mask = old[1], .formula = .opaque_epoch_v3, .key_hex = old_hex, .address = address, .suffix = "onyx", .epoch = 7, .cadence = null },
        };
        const doc = try std.json.Stringify.valueAlloc(a, cli.Document{ .version = 1, .target = .{ .key_hex = new_hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 }, .witnesses = &rows }, .{});
        defer {
            std.crypto.secureZero(u8, doc);
            a.free(doc);
        }
        try write(io, dir, if (first == 1) "akick.witness" else "ward.witness", doc);
    }
}
fn check(condition: bool) !void {
    if (!condition) return error.InvalidProof;
}
fn verifyAk(a: std.mem.Allocator, bytes: []const u8, masks_: [2][]u8) !void {
    for ([_]i64{ 99, 100, 101 }) |now| {
        var store = try akcodec.decode(a, bytes);
        defer store.deinit();
        try check(store.max_per_channel == 7 and store.channels.contains("#empty"));
        var m: [512]u8 = undefined;
        const at = std.mem.lastIndexOfScalar(u8, masks_[0], '@').?;
        const candidate = try std.fmt.bufPrint(&m, "nick!u@{s}", .{masks_[0][at + 1 ..]});
        const hit = store.matchOnJoinWithCloak("#z", candidate, null, now, null) orelse return error.InvalidProof;
        try check(std.mem.eql(u8, hit.reason, if (now < 100) "first" else "second"));
        var wrong: [512]u8 = undefined;
        const wrong_nick = try std.fmt.bufPrint(&wrong, "other!u@{s}", .{masks_[0][at + 1 ..]});
        try check(store.matchOnJoinWithCloak("#z", wrong_nick, null, now, null) == null);
        const wrong_ident = try std.fmt.bufPrint(&wrong, "nick!wrong@{s}", .{masks_[0][at + 1 ..]});
        try check(store.matchOnJoinWithCloak("#z", wrong_ident, null, now, null) == null);
        try check(store.matchOnJoinWithCloak("#z", "nick!u@other.example", null, now, null) == null);
        try check(std.mem.eql(u8, (store.matchOnJoinWithCloak("#z", "x!u@invalid", "operator42", now, null) orelse return error.InvalidProof).reason, "account"));
        try check(store.matchOnJoinWithCloak("#expired", "x!u@expired.example", null, now, null) == null);
    }
    for ([_]i64{ -2, -1, 0 }) |now| {
        var store = try akcodec.decode(a, bytes);
        defer store.deinit();
        const hit = store.matchOnJoinWithCloak("#expired", "x!u@expired.example", null, now, null);
        if (now < -1) try check(hit != null and std.mem.eql(u8, hit.?.reason, "expired")) else try check(hit == null);
    }
}
fn verifyWard(a: std.mem.Allocator, bytes: []const u8, masks_: [2][]u8) !void {
    for ([_]i64{ 99, 100, 101 }) |now| {
        // Fresh decode for each check: Warden prunes expired rows on check.
        const Check = struct {
            fn run(alloc: std.mem.Allocator, image: []const u8, facets: ward.Facets, when: i64, reason: ?[]const u8, action: ward.Action, scope: ward.Scope) !void {
                var registry = try wardcodec.decode(alloc, image);
                defer registry.deinit();
                try check(registry.params.max_wards == 9 and registry.params.max_reason == 111);
                const hit = registry.check(facets, when);
                if (reason) |wanted| {
                    const found = hit orelse return error.InvalidProof;
                    try check(std.mem.eql(u8, found.reason, wanted) and found.action == action and found.scope == scope);
                } else try check(hit == null);
            }
        };
        var m: [512]u8 = undefined;
        const at = std.mem.lastIndexOfScalar(u8, masks_[0], '@').?;
        const host = masks_[0][at + 1 ..];
        const candidate = try std.fmt.bufPrint(&m, "nick!u@{s}", .{host});
        try Check.run(a, bytes, .{ .mask = candidate }, now, if (now < 100) "first" else "second", if (now < 100) .quarantine else .refuse, if (now < 100) .mesh else .node);
        var wrong: [512]u8 = undefined;
        const wrong_nick = try std.fmt.bufPrint(&wrong, "other!u@{s}", .{host});
        try Check.run(a, bytes, .{ .mask = wrong_nick }, now, null, .refuse, .node);
        const wrong_ident = try std.fmt.bufPrint(&wrong, "nick!wrong@{s}", .{host});
        try Check.run(a, bytes, .{ .mask = wrong_ident }, now, null, .refuse, .node);
        try Check.run(a, bytes, .{ .mask = "nick!u@other.example" }, now, null, .refuse, .node);
        try Check.run(a, bytes, .{ .account = "operator42" }, now, "account", .require_auth, .node);
        try Check.run(a, bytes, .{ .address = "198.51.100.9" }, now, "address", .expel, .node);
        try Check.run(a, bytes, .{ .address = "192.0.2.9" }, now, null, .refuse, .node);
        try Check.run(a, bytes, .{ .host = "expired.example" }, now, null, .refuse, .node);
    }
    for ([_]i64{ -2, -1, 0 }) |now| {
        var registry = try wardcodec.decode(a, bytes);
        defer registry.deinit();
        const hit = registry.check(.{ .host = "expired.example" }, now);
        if (now < -1) try check(hit != null and std.mem.eql(u8, hit.?.reason, "expired")) else try check(hit == null);
    }
}
fn verify(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    const old = try masks(a, false);
    defer for (old) |value| a.free(value);
    const new = try masks(a, true);
    defer for (new) |value| a.free(value);
    for ([_][]const u8{ "akick", "ward" }) |kind| {
        const input_name = try std.fmt.allocPrint(a, "{s}.input", .{kind});
        defer a.free(input_name);
        const output_name = try std.fmt.allocPrint(a, "{s}.output", .{kind});
        defer a.free(output_name);
        const expected_name = try std.fmt.allocPrint(a, "{s}.expected", .{kind});
        defer a.free(expected_name);
        const input = try dir.readFileAlloc(io, input_name, a, .limited(8 * 1024 * 1024));
        defer a.free(input);
        const output = try dir.readFileAlloc(io, output_name, a, .limited(8 * 1024 * 1024));
        defer a.free(output);
        const expected = try dir.readFileAlloc(io, expected_name, a, .limited(8 * 1024 * 1024));
        defer a.free(expected);
        try check(!std.mem.eql(u8, input, output) and std.mem.eql(u8, expected, output));
        if (std.mem.eql(u8, kind, "akick")) {
            try verifyAk(a, input, old);
            try verifyAk(a, output, new);
            var undone = try akcodec.decode(a, output);
            defer undone.deinit();
            const list = undone.channels.getPtr("#z") orelse return error.InvalidProof;
            for (0..2) |i| {
                const copy = try a.dupe(u8, old[i]);
                a.free(list.entries.items[i].mask);
                list.entries.items[i].mask = copy;
                list.entries.items[i].pattern = copy;
            }
            const restored = try akcodec.encode(a, &undone);
            defer a.free(restored);
            try check(std.mem.eql(u8, input, restored));
        } else {
            try verifyWard(a, input, old);
            try verifyWard(a, output, new);
            var undone = try wardcodec.decode(a, output);
            defer undone.deinit();
            for (0..2) |i| {
                const copy = try a.dupe(u8, old[i]);
                a.free(undone.wards.items[i].pattern);
                undone.wards.items[i].pattern = copy;
            }
            const restored = try wardcodec.encode(a, &undone);
            defer a.free(restored);
            try check(std.mem.eql(u8, input, restored));
        }
    }
}
pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next() orelse return error.InvalidArguments;
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
    if (std.mem.eql(u8, mode, "generate")) generate(init.gpa, init.io, dir) catch {
        std.debug.print("policy fixture refused\n", .{});
        std.process.exit(1);
    } else if (std.mem.eql(u8, mode, "verify")) verify(init.gpa, init.io, dir) catch {
        std.debug.print("policy fixture refused\n", .{});
        std.process.exit(1);
    } else return error.InvalidArguments;
}
