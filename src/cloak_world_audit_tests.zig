// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const bridge = @import("daemon/cloak_world_audit.zig");
const checkpoint = @import("daemon/helix/world_checkpoint.zig");
const world = @import("daemon/world.zig");
const t = std.testing;

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
fn image(a: std.mem.Allocator, inconsistent: bool) ![]u8 {
    var source = world.World.init(a);
    defer source.deinit();
    try source.initializeCheckpointImage(8, 100, 1_700_000_000);
    const first = client(1);
    const second = client(2);
    const invited_only = client(3);
    try source.restoreMember("#Alpha", first, world.MemberModes.fromModes(&.{.op}));
    try source.restoreMember("#Beta", second, world.MemberModes.fromModes(&.{.voice}));
    if (!inconsistent) {
        try source.restoreMember("#Alpha", second, world.MemberModes.fromModes(&.{ .voice, .founder }));
        try source.restoreMember("#Beta", first, world.MemberModes.fromModes(&.{.owner}));
    }
    try source.addInvite("#Beta", invited_only);
    _ = try source.addBan("#Alpha", "z!*@old.example", "set-z", 101);
    _ = try source.addBan("#Alpha", "a!*@old.example", "set-a", 102);
    _ = try source.addExempt("#Alpha", "e!*@old.example", "set-e", 103);
    _ = try source.addInvex("#Beta", "i!*@old.example", "set-i", 104);
    _ = try source.addMute("#Beta", "m!*@old.example", "set-m", 105);
    try source.setTopic("#Alpha", "private topic", "PrivateSetter", 99);
    const pairs = [_]Resolver.Pair{
        .{ .key = 100, .nick = "Shared", .client = first },
        .{ .key = if (inconsistent) 100 else 101, .nick = if (inconsistent) "Different" else "Shared", .client = second },
        .{ .key = 102, .nick = "InvitedOnly", .client = invited_only },
    };
    var resolver = Resolver{ .pairs = &pairs };
    source.lockRead();
    defer source.unlockRead();
    return checkpoint.encodeLockedResolved(a, &source, resolver.value());
}
fn allocation(a: std.mem.Allocator, wire: []const u8) !void {
    const result = try bridge.baseline(a, wire);
    defer a.free(result);
    try t.expectEqualSlices(u8, wire, result);
}

test "cloak World bridge preserves exact relationships and channel list metadata" {
    const a = t.allocator;
    const wire = try image(a, false);
    defer a.free(wire);
    const original = try a.dupe(u8, wire);
    defer a.free(original);
    var before = try checkpoint.decode(a, wire);
    defer before.deinit();
    try t.expectEqual(@as(usize, 4), before.member_expectations.len);
    try t.expectEqual(@as(usize, 1), before.invite_expectations.len);
    try t.expectEqualStrings("InvitedOnly", before.invite_expectations[0].nick);
    const output = try bridge.baseline(a, wire);
    defer a.free(output);
    try t.expectEqualSlices(u8, original, output);
    try t.expectEqualSlices(u8, original, wire);
    var after = try checkpoint.decode(a, output);
    defer after.deinit();
    try t.expectEqual(@as(usize, 4), after.member_expectations.len);
    try t.expectEqual(@as(usize, 1), after.invite_expectations.len);
    try t.expectEqual(@as(usize, 2), after.world.channelCount());
    try t.expectEqual(@as(usize, 2), after.world.bansOf("#Alpha").?.len);
    try t.expectEqual(@as(usize, 1), after.world.exemptsOf("#Alpha").?.len);
    try t.expectEqual(@as(usize, 1), after.world.invexOf("#Beta").?.len);
    try t.expectEqual(@as(usize, 1), after.world.mutesOf("#Beta").?.len);
}

test "cloak World bridge rejects inconsistent nick for one physical key" {
    const a = t.allocator;
    const wire = try image(a, true);
    defer a.free(wire);
    var decoded = try checkpoint.decode(a, wire);
    defer decoded.deinit();
    try t.expectEqual(@as(usize, 2), decoded.member_expectations.len);
    try t.expectError(error.InconsistentRelationIdentity, bridge.baseline(a, wire));
}

test "cloak World bridge rejects bad input without mutation" {
    const a = t.allocator;
    const wire = try image(a, false);
    defer a.free(wire);
    const corrupt = try a.dupe(u8, wire);
    defer a.free(corrupt);
    corrupt[40] ^= 1;
    const before = try a.dupe(u8, corrupt);
    defer a.free(before);
    try t.expectError(error.ChecksumMismatch, bridge.baseline(a, corrupt));
    try t.expectEqualSlices(u8, before, corrupt);
    try t.expectError(error.Truncated, bridge.baseline(a, wire[0 .. wire.len - 1]));
}

test "cloak World bridge remains atomic at every allocation cut" {
    const a = t.allocator;
    const wire = try image(a, false);
    defer a.free(wire);
    const before = try a.dupe(u8, wire);
    defer a.free(before);
    try t.checkAllAllocationFailures(a, allocation, .{wire});
    try t.expectEqualSlices(u8, before, wire);
    try allocation(a, wire);
}

const cloak = @import("proto/cloak.zig");
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
fn checkMatches(a: std.mem.Allocator, wire: []const u8, masks: [4][]const u8) !void {
    var decoded = try checkpoint.decode(a, wire);
    defer decoded.deinit();
    // Literal hosts and exact nick/ident are exercised by World's real matchers.
    try t.expect(decoded.world.isBanned("#Alpha", masks[0]));
    try t.expect(decoded.world.isExempt("#Alpha", masks[1]));
    try t.expect(decoded.world.isInvexed("#Beta", masks[2]));
    try t.expect(decoded.world.isMuted("#Beta", masks[3]));
    try t.expect(!decoded.world.isBanned("#Alpha", "wrong!u@invalid.example"));
    try t.expectEqual(@as(usize, 3), decoded.member_expectations.len);
    try t.expectEqual(@as(usize, 1), decoded.invite_expectations.len);
    try t.expectEqualStrings("InvitedOnly", decoded.invite_expectations[0].nick);
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
    try t.expect(try decoded.world.removeBan("#Alpha", after[0]));
    try t.expect(try decoded.world.addBan("#Alpha", before[0], "ban-setter", 11));
    try t.expect(try decoded.world.removeExempt("#Alpha", after[1]));
    try t.expect(try decoded.world.addExempt("#Alpha", before[1], "exempt-setter", 13));
    try t.expect(try decoded.world.removeInvex("#Beta", after[2]));
    try t.expect(try decoded.world.addInvex("#Beta", before[2], "invex-setter", 14));
    try t.expect(try decoded.world.removeMute("#Beta", after[3]));
    try t.expect(try decoded.world.addMute("#Beta", before[3], "mute-setter", 15));
    decoded.world.lockRead();
    defer decoded.world.unlockRead();
    return checkpoint.encodeLockedResolved(a, &decoded.world, resolver.value());
}
fn auditAlloc(a: std.mem.Allocator, wire: []const u8, witnesses: []const bridge.Witness, target: bridge.Target) !void {
    var plan = try bridge.audit(a, wire, witnesses, target, .{});
    defer plan.deinit();
    try t.expectEqual(@as(usize, 6), plan.reports.len);
}

test "cloak World audit rekeys all four families and retains relationships metadata and ordering" {
    const a = t.allocator;
    var source = cloak.SecretKey.init(@splat(0x31));
    defer source.wipe();
    var target = cloak.SecretKey.init(@splat(0x32));
    defer target.wipe();
    var old_buf: [253]u8 = undefined;
    var new_buf: [253]u8 = undefined;
    const old_host = try cloak.cloakOpaqueEpochV3(&old_buf, &source, "203.0.113.9", 7, .{ .suffix = "onyx" });
    const new_host = try cloak.cloakOpaqueEpochV4(&new_buf, &target, "203.0.113.9", 90, 1_209_600, .{ .suffix = "onyx" });
    const names = [_][]const u8{ "ban", "exempt", "invex", "mute" };
    var old_masks: [4][]const u8 = undefined;
    var new_masks: [4][]const u8 = undefined;
    var initialized: usize = 0;
    defer for (0..initialized) |i| {
        a.free(old_masks[i]);
        a.free(new_masks[i]);
    };
    for (names, 0..) |name, i| {
        const old = try std.fmt.allocPrint(a, "{s}!u@{s}", .{ name, old_host });
        errdefer a.free(old);
        const new = try std.fmt.allocPrint(a, "{s}!u@{s}", .{ name, new_host });
        old_masks[i] = old;
        new_masks[i] = new;
        initialized += 1;
    }
    const lower = if (std.mem.lessThan(u8, old_masks[0], new_masks[0])) old_masks[0] else new_masks[0];
    const upper = if (std.mem.lessThan(u8, old_masks[0], new_masks[0])) new_masks[0] else old_masks[0];
    const competitor = try std.fmt.allocPrint(a, "{s}~", .{lower});
    defer a.free(competitor);
    try t.expect(std.mem.lessThan(u8, lower, competitor) and std.mem.lessThan(u8, competitor, upper));
    const wire = try auditImage(a, old_masks, competitor);
    defer a.free(wire);
    const expected = try auditImage(a, new_masks, competitor);
    defer a.free(expected);
    const saved = try a.dupe(u8, wire);
    defer a.free(saved);
    const first: usize = if (std.mem.lessThan(u8, old_masks[0], competitor)) 1 else 2;
    const source_spec = bridge.Witness{ .row = first, .expected_mask = old_masks[0], .source = .{ .formula = .opaque_epoch_v3, .key = &source, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7 } };
    const witnesses = [_]bridge.Witness{
        source_spec,
        .{ .row = 3, .expected_mask = old_masks[1], .source = source_spec.source },
        .{ .row = 4, .expected_mask = old_masks[2], .source = source_spec.source },
        .{ .row = 5, .expected_mask = old_masks[3], .source = source_spec.source },
    };
    const target_spec: bridge.Target = .{ .key = &target, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
    var plan = try bridge.audit(a, wire, &witnesses, target_spec, .{});
    defer plan.deinit();
    try t.expectEqual(@as(usize, 6), plan.reports.len);
    try t.expectEqualStrings("metadata_gap", plan.reports[0].classification.name());
    for (witnesses) |item| try t.expectEqualStrings("verified_replacement", plan.reports[item.row].classification.name());
    try t.expectEqualStrings("missing_witness", plan.reports[if (first == 1) 2 else 1].classification.name());
    try t.expectEqualSlices(u8, expected, plan.checkpoint);
    try t.expectEqualSlices(u8, saved, wire);
    try checkMatches(a, wire, old_masks);
    try checkMatches(a, plan.checkpoint, new_masks);
    const undone = try restoreOnlyMasks(a, plan.checkpoint, old_masks, new_masks);
    defer a.free(undone);
    try t.expectEqualSlices(u8, wire, undone);
    try t.checkAllAllocationFailures(a, auditAlloc, .{ wire, &witnesses, target_spec });
    try t.expectEqualSlices(u8, saved, wire);
    const collision = try auditImage(a, old_masks, new_masks[0]);
    defer a.free(collision);
    const collision_first: usize = if (std.mem.lessThan(u8, old_masks[0], new_masks[0])) 1 else 2;
    var collision_witness = source_spec;
    collision_witness.row = collision_first;
    try t.expectError(error.DuplicateListEntry, bridge.audit(a, collision, &.{collision_witness}, target_spec, .{}));
    try t.expectError(error.LimitExceeded, bridge.audit(a, wire, &witnesses, target_spec, .{ .max_rows = 5 }));
}
