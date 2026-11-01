// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private synthetic acceptance fixture. Expected image is built solely from
//! World + checkpoint codec + cloak primitive, never the audit implementation.
const std = @import("std");
const builtin = @import("builtin");
const cloak = @import("proto/cloak.zig");
const cli = @import("cli/cloak_audit_cmd.zig");
const checkpoint = @import("daemon/helix/world_checkpoint.zig");
const world = @import("daemon/world.zig");
const old_hex = "3131313131313131313131313131313131313131313131313131313131313131";
const new_hex = "3232323232323232323232323232323232323232323232323232323232323232";
fn check(value: bool) !void {
    if (!value) return error.InvalidProof;
}
fn write(io: std.Io, dir: std.Io.Dir, name: []const u8, data: []const u8) !void {
    const f = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, data);
    try f.sync(io);
}
const Resolver = struct {
    const Pair = struct { key: u64, nick: []const u8, client: world.ClientId };
    pairs: []const Pair,
    fn resolve(ctx: *anyopaque, id: world.ClientId) ?checkpoint.MemberIdentity {
        const self: *Resolver = @ptrCast(@alignCast(ctx));
        for (self.pairs) |entry| if (entry.client.eql(id)) return .{ .join_key = entry.key, .nick = entry.nick };
        return null;
    }
    fn lookup(ctx: *anyopaque, key: u64) ?world.ClientId {
        const self: *Resolver = @ptrCast(@alignCast(ctx));
        for (self.pairs) |entry| if (entry.key == key) return entry.client;
        return null;
    }
    fn value(self: *Resolver) checkpoint.NickResolver {
        return .{ .context = self, .resolve = resolve, .lookup = lookup };
    }
};
fn client(slot: u20) world.ClientId {
    return .{ .shard = 0, .slot = slot, .gen = 7 };
}
fn auditImage(a: std.mem.Allocator, masks: [4][]const u8, competitor: []const u8) ![]u8 {
    var source = world.World.init(a);
    defer source.deinit();
    try source.initializeCheckpointImage(8, 100, 1_700_000_000);
    const one = client(1);
    const two = client(2);
    const invitee = client(3);
    try source.restoreMember("#Alpha", one, world.MemberModes.fromModes(&.{.op}));
    try source.restoreMember("#Alpha", two, world.MemberModes.fromModes(&.{.voice}));
    try source.restoreMember("#Beta", one, world.MemberModes.fromModes(&.{.founder}));
    try source.addInvite("#Beta", invitee);
    _ = try source.addBan("#Alpha", "$a:operator*", "gap", -7);
    _ = try source.addBan("#Alpha", masks[0], "ban-setter", 11);
    _ = try source.addBan("#Alpha", competitor, "competitor", 12);
    _ = try source.addExempt("#Alpha", masks[1], "exempt-setter", 13);
    _ = try source.addInvex("#Beta", masks[2], "invex-setter", 14);
    _ = try source.addMute("#Beta", masks[3], "mute-setter", 15);
    const pairs = [_]Resolver.Pair{
        .{ .key = 100, .nick = "Shared", .client = one },
        .{ .key = 101, .nick = "Shared", .client = two },
        .{ .key = 102, .nick = "InvitedOnly", .client = invitee },
    };
    var resolver = Resolver{ .pairs = &pairs };
    source.lockRead();
    defer source.unlockRead();
    return checkpoint.encodeLockedResolved(a, &source, resolver.value());
}
fn restoreOnlyMasks(a: std.mem.Allocator, changed: []const u8, before: [4][]const u8, after: [4][]const u8) ![]u8 {
    var decoded = try checkpoint.decode(a, changed);
    defer decoded.deinit();
    const pairs = [_]Resolver.Pair{
        .{ .key = 100, .nick = "Shared", .client = client(1) },
        .{ .key = 101, .nick = "Shared", .client = client(2) },
        .{ .key = 102, .nick = "InvitedOnly", .client = client(3) },
    };
    var resolver = Resolver{ .pairs = &pairs };
    for (decoded.member_expectations) |row| {
        const id = Resolver.lookup(&resolver, row.join_key) orelse return error.MissingClient;
        try decoded.world.restoreMember(row.channel, id, row.modes);
    }
    try decoded.validateAdoptedMembersResolved(&decoded.world, resolver.value());
    try decoded.applyInvitesResolved(&decoded.world, resolver.value());
    try check(try decoded.world.removeBan("#Alpha", after[0]));
    try check(try decoded.world.addBan("#Alpha", before[0], "ban-setter", 11));
    try check(try decoded.world.removeExempt("#Alpha", after[1]));
    try check(try decoded.world.addExempt("#Alpha", before[1], "exempt-setter", 13));
    try check(try decoded.world.removeInvex("#Beta", after[2]));
    try check(try decoded.world.addInvex("#Beta", before[2], "invex-setter", 14));
    try check(try decoded.world.removeMute("#Beta", after[3]));
    try check(try decoded.world.addMute("#Beta", before[3], "mute-setter", 15));
    decoded.world.lockRead();
    defer decoded.world.unlockRead();
    return checkpoint.encodeLockedResolved(a, &decoded.world, resolver.value());
}
const Masks = struct {
    old: [4][]const u8,
    new: [4][]const u8,
    competitor: []const u8,
    fn init(a: std.mem.Allocator) !Masks {
        var old_key = cloak.SecretKey.init(@splat(0x31));
        defer old_key.wipe();
        var new_key = cloak.SecretKey.init(@splat(0x32));
        defer new_key.wipe();
        var old_buf: [253]u8 = undefined;
        var new_buf: [253]u8 = undefined;
        const old_host = try cloak.cloakOpaqueEpochV3(&old_buf, &old_key, "203.0.113.9", 7, .{ .suffix = "onyx" });
        const new_host = try cloak.cloakOpaqueEpochV4(&new_buf, &new_key, "203.0.113.9", 90, 1_209_600, .{ .suffix = "onyx" });
        var old: [4][]const u8 = undefined;
        var new: [4][]const u8 = undefined;
        var used: usize = 0;
        errdefer for (0..used) |i| {
            a.free(old[i]);
            a.free(new[i]);
        };
        for ([_][]const u8{ "ban", "exempt", "invex", "mute" }, 0..) |name, i| {
            const first = try std.fmt.allocPrint(a, "{s}!u@{s}", .{ name, old_host });
            errdefer a.free(first);
            const second = try std.fmt.allocPrint(a, "{s}!u@{s}", .{ name, new_host });
            old[i] = first;
            new[i] = second;
            used += 1;
        }
        const lower = if (std.mem.lessThan(u8, old[0], new[0])) old[0] else new[0];
        const upper = if (std.mem.lessThan(u8, old[0], new[0])) new[0] else old[0];
        const competitor = try std.fmt.allocPrint(a, "{s}~", .{lower});
        errdefer a.free(competitor);
        try check(std.mem.lessThan(u8, lower, competitor) and std.mem.lessThan(u8, competitor, upper));
        return .{ .old = old, .new = new, .competitor = competitor };
    }
    fn deinit(self: Masks, a: std.mem.Allocator) void {
        for (self.old, self.new) |x, y| {
            a.free(x);
            a.free(y);
        }
        a.free(self.competitor);
    }
};
fn witness(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, masks: Masks, collision: bool) !void {
    const competitor = if (collision) masks.new[0] else masks.competitor;
    const first: usize = if (std.mem.lessThan(u8, masks.old[0], competitor)) 1 else 2;
    var rows = [_]cli.RawWitness{
        .{ .row = first, .expected_mask = masks.old[0], .formula = .opaque_epoch_v3, .key_hex = old_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null },
        .{ .row = 3, .expected_mask = masks.old[1], .formula = .opaque_epoch_v3, .key_hex = old_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null },
        .{ .row = 4, .expected_mask = masks.old[2], .formula = .opaque_epoch_v3, .key_hex = old_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null },
        .{ .row = 5, .expected_mask = masks.old[3], .formula = .opaque_epoch_v3, .key_hex = old_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null },
    };
    const doc = try std.json.Stringify.valueAlloc(a, cli.Document{ .version = 1, .target = .{ .key_hex = new_hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 }, .witnesses = &rows }, .{});
    defer {
        std.crypto.secureZero(u8, doc);
        a.free(doc);
    }
    try write(io, dir, if (collision) "world.collision.witness" else "world.witness", doc);
}
fn verifyOrdinals(a: std.mem.Allocator, image: []const u8, masks: Masks) !void {
    var decoded = try checkpoint.decode(a, image);
    defer decoded.deinit();
    const bans = decoded.world.bansOf("#Alpha") orelse return error.InvalidProof;
    const exempts = decoded.world.exemptsOf("#Alpha") orelse return error.InvalidProof;
    const invex = decoded.world.invexOf("#Beta") orelse return error.InvalidProof;
    const mutes = decoded.world.mutesOf("#Beta") orelse return error.InvalidProof;
    try check(bans.len == 3 and exempts.len == 1 and invex.len == 1 and mutes.len == 1);
    const first: usize = if (std.mem.lessThan(u8, masks.old[0], masks.competitor)) 1 else 2;
    try check(std.mem.eql(u8, bans[0].mask, "$a:operator*"));
    try check(std.mem.eql(u8, bans[first].mask, masks.old[0]));
    try check(std.mem.eql(u8, bans[if (first == 1) 2 else 1].mask, masks.competitor));
    try check(std.mem.eql(u8, exempts[0].mask, masks.old[1]));
    try check(std.mem.eql(u8, invex[0].mask, masks.old[2]));
    try check(std.mem.eql(u8, mutes[0].mask, masks.old[3]));
}
fn generate(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    const masks = try Masks.init(a);
    defer masks.deinit(a);
    const input = try auditImage(a, masks.old, masks.competitor);
    defer a.free(input);
    try verifyOrdinals(a, input, masks);
    const expected = try auditImage(a, masks.new, masks.competitor);
    defer a.free(expected);
    const collision = try auditImage(a, masks.old, masks.new[0]);
    defer a.free(collision);
    try check(!std.mem.eql(u8, input, expected));
    try write(io, dir, "world.input", input);
    try write(io, dir, "world.expected", expected);
    try write(io, dir, "world.collision", collision);
    try witness(a, io, dir, masks, false);
    try witness(a, io, dir, masks, true);
}
fn matches(w: *world.World, family: usize, value: []const u8) bool {
    return switch (family) {
        0 => w.isBanned("#Alpha", value),
        1 => w.isExempt("#Alpha", value),
        2 => w.isInvexed("#Beta", value),
        3 => w.isMuted("#Beta", value),
        else => unreachable,
    };
}
fn verifyImage(a: std.mem.Allocator, bytes: []const u8, masks: [4][]const u8) !void {
    var restored = try checkpoint.decode(a, bytes);
    defer restored.deinit();
    try check(restored.world.channelCount() == 2);
    try restored.validateMemberProjection(&.{
        .{ .channel = "#Alpha", .join_key = 100, .nick = "Shared", .modes = world.MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#Alpha", .join_key = 101, .nick = "Shared", .modes = world.MemberModes.fromModes(&.{.voice}) },
        .{ .channel = "#Beta", .join_key = 100, .nick = "Shared", .modes = world.MemberModes.fromModes(&.{.founder}) },
    });
    try check(restored.invite_expectations.len == 1 and restored.invite_expectations[0].join_key == 102 and std.mem.eql(u8, restored.invite_expectations[0].nick, "InvitedOnly"));
    try restored.validateInviteProjection(&.{ .{ .join_key = 100, .nick = "Shared" }, .{ .join_key = 101, .nick = "Shared" }, .{ .join_key = 102, .nick = "InvitedOnly" } });
    for (masks, 0..) |mask, family| {
        const at = std.mem.lastIndexOfScalar(u8, mask, '@') orelse return error.InvalidProof;
        const bang = std.mem.indexOfScalar(u8, mask, '!') orelse return error.InvalidProof;
        var bad: [512]u8 = undefined;
        try check(matches(&restored.world, family, mask));
        const bad_nick = try std.fmt.bufPrint(&bad, "wrong!u@{s}", .{mask[at + 1 ..]});
        try check(!matches(&restored.world, family, bad_nick));
        const bad_ident = try std.fmt.bufPrint(&bad, "{s}!wrong@{s}", .{ mask[0..bang], mask[at + 1 ..] });
        try check(!matches(&restored.world, family, bad_ident));
        const bad_host = try std.fmt.bufPrint(&bad, "{s}!u@invalid.example", .{mask[0..bang]});
        try check(!matches(&restored.world, family, bad_host));
    }
    try check(restored.world.isBannedCtx("#Alpha", .{ .host = "other!u@invalid.example", .account = "operator42" }));
}
fn verify(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    const masks = try Masks.init(a);
    defer masks.deinit(a);
    const input = try dir.readFileAlloc(io, "world.input", a, .limited(8 * 1024 * 1024));
    defer a.free(input);
    const expected = try dir.readFileAlloc(io, "world.expected", a, .limited(8 * 1024 * 1024));
    defer a.free(expected);
    const output = try dir.readFileAlloc(io, "world.output", a, .limited(8 * 1024 * 1024));
    defer a.free(output);
    try check(!std.mem.eql(u8, input, output) and std.mem.eql(u8, expected, output));
    try verifyImage(a, input, masks.old);
    try verifyImage(a, output, masks.new);
    const undone = try restoreOnlyMasks(a, output, masks.old, masks.new);
    defer a.free(undone);
    try check(std.mem.eql(u8, input, undone));
}
pub fn main(init: std.process.Init) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
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
        std.debug.print("World fixture refused\n", .{});
        std.process.exit(1);
    } else if (std.mem.eql(u8, mode, "verify")) verify(init.gpa, init.io, dir) catch {
        std.debug.print("World fixture refused\n", .{});
        std.process.exit(1);
    } else return error.InvalidArguments;
}
