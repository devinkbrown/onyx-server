// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const audit = @import("daemon/cloak_policy_list_audit.zig");
const shared = @import("daemon/cloak_migration_audit.zig");
const cloak = @import("proto/cloak.zig");
const akick = @import("daemon/svc_akick.zig");
const warden = @import("daemon/warden.zig");
const akick_codec = @import("daemon/helix/akick_checkpoint.zig");
const ward_codec = @import("daemon/helix/ward_checkpoint.zig");
const testing = std.testing;

test {
    _ = audit;
}

fn source(key: *const cloak.SecretKey) shared.Source {
    return .{ .formula = .opaque_epoch_v3, .key = key, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7 };
}
fn target(key: *const cloak.SecretKey) audit.Target {
    return .{ .key = key, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
}
fn oldHost(storage: []u8, key: *const cloak.SecretKey) ![]const u8 {
    return cloak.cloakOpaqueEpochV3(storage, key, source(key).address, 7, .{ .suffix = "onyx" });
}
fn newHost(storage: []u8, key: *const cloak.SecretKey) ![]const u8 {
    return cloak.cloakOpaqueEpochV4(storage, key, source(key).address, 90, 1_209_600, .{ .suffix = "onyx" });
}
fn label(plan: *const audit.Plan, row: usize, expected: []const u8) !void {
    try testing.expectEqualStrings(expected, plan.reports[row].classification.name());
}
fn summaryOnly(plan: *const audit.Plan) !void {
    const Summary = struct {
        count: usize = 0,
        fn emit(self: *@This(), text: []const u8) !void {
            if (std.mem.indexOf(u8, text, "203.0.113") != null or std.mem.indexOf(u8, text, "opq") != null or
                std.mem.indexOf(u8, text, "issuer") != null or std.mem.indexOf(u8, text, "reason") != null or
                std.mem.indexOf(u8, text, "#") != null) return error.PrivateSummaryContent;
            if (!std.mem.startsWith(u8, text, "row=")) return error.InvalidSummary;
            self.count += 1;
        }
    };
    var summary = Summary{};
    try plan.forEachSummary(&summary, Summary.emit);
    try testing.expectEqual(plan.reports.len, summary.count);
}
fn fillAkick(store: *akick.AkickStore, broad: []const u8, narrow: []const u8, other: []const u8) !void {
    try store.checkpointEnsureChannel("#empty");
    try store.add("#z", broad, "first-reason", "FirstIssuer", -42, 99);
    try store.add("#z", "account:alice*", "account-reason", "AccountIssuer", 1, null);
    try store.add("#z", narrow, "second-reason", "SecondIssuer", 17, 200);
    try store.add("#z", other, "other-reason", "ThirdIssuer", 19, null);
    try store.add("#a", "*!u@*.opq.onyx", "expired-reason", "ExpiredIssuer", -50, 0);
}
fn fillWard(registry: *warden.Registry, host: []const u8, mask: []const u8) !void {
    try registry.add(.{ .match = .host, .pattern = host, .scope = .mesh, .action = .quarantine, .reason = "first-reason", .set_by = "FirstIssuer", .created_ms = -42, .expires_ms = 99 });
    try registry.add(.{ .match = .mask, .pattern = mask, .scope = .node, .action = .require_auth, .reason = "second-reason", .set_by = "SecondIssuer", .created_ms = 17, .expires_ms = 200 });
    try registry.add(.{ .match = .account, .pattern = "alice*", .action = .expel, .reason = "account-reason", .set_by = "AccountIssuer", .created_ms = 19 });
    try registry.add(.{ .match = .address, .pattern = "203.0.113.0/24", .action = .refuse, .created_ms = 21 });
    try registry.add(.{ .match = .host, .pattern = "*.opq.onyx", .reason = "expired-reason", .created_ms = -50, .expires_ms = -1 });
    try registry.add(.{ .match = .host, .pattern = "bad@shape", .created_ms = 23 });
    try registry.add(.{ .match = .realname, .pattern = "Example*", .created_ms = 25 });
}
const wardParams = warden.Params{ .max_wards = 9, .max_pattern = 256, .max_reason = 111, .max_setter = 63 };

test "policy list audit: AKCK exact nullable expiry metadata empty channels and first match order" {
    const a = testing.allocator;
    var key = cloak.SecretKey.init(@splat(0x71));
    defer key.wipe();
    var storage: [253]u8 = undefined;
    const host = try oldHost(&storage, &key);
    var broad_storage: [256]u8 = undefined;
    var narrow_storage: [256]u8 = undefined;
    var other_storage: [256]u8 = undefined;
    const broad = try std.fmt.bufPrint(&broad_storage, "n*!u@{s}", .{host});
    const narrow = try std.fmt.bufPrint(&narrow_storage, "nick!u@{s}", .{host});
    const other = try std.fmt.bufPrint(&other_storage, "third!u@{s}", .{host});
    var original = akick.AkickStore.initCapacity(a, 7);
    defer original.deinit();
    try fillAkick(&original, broad, narrow, other);
    const bytes = try akick_codec.encode(a, &original);
    defer a.free(bytes);
    const before = try a.dupe(u8, bytes);
    defer a.free(before);
    const witnesses = [_]audit.Witness{ .{ .row = 1, .expected_mask = broad, .source = source(&key) }, .{ .row = 3, .expected_mask = narrow, .source = source(&key) } };
    var plan = try audit.auditAkick(a, bytes, &witnesses, target(&key), .{});
    defer plan.deinit();
    try label(&plan, 0, "ambiguous_host_glob");
    try label(&plan, 1, "verified_replacement");
    try label(&plan, 2, "account_rule");
    try label(&plan, 3, "verified_replacement");
    try label(&plan, 4, "missing_witness");
    try summaryOnly(&plan);
    var restored = try akick_codec.decode(a, plan.checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 7), restored.max_per_channel);
    try testing.expect(restored.channels.contains("#empty"));
    try testing.expectEqual(@as(usize, 0), restored.count("#empty"));
    try testing.expectEqual(@as(?i64, 0), restored.list("#a")[0].expires_at_ms);
    try testing.expectEqual(@as(?i64, null), restored.list("#z")[1].expires_at_ms);
    try testing.expectEqual(@as(?i64, 99), restored.list("#z")[0].expires_at_ms);
    try testing.expectEqualStrings("FirstIssuer", restored.list("#z")[0].setter);
    try testing.expectEqual(@as(i64, -42), restored.list("#z")[0].added_at_ms);
    // Undo only substituted masks in a detached copy: exact codec equality
    // proves every other field, absent expiry, empty channel and ordering byte.
    const entries = restored.channels.getPtr("#z").?.entries.items;
    for ([_]usize{ 0, 2 }) |i| {
        const owned = try a.dupe(u8, original.list("#z")[i].mask);
        a.free(entries[i].mask);
        entries[i].mask = owned;
        entries[i].pattern = owned;
    }
    const undone = try akick_codec.encode(a, &restored);
    defer a.free(undone);
    try testing.expectEqualSlices(u8, bytes, undone);
    var current_storage: [253]u8 = undefined;
    const current = try newHost(&current_storage, &key);
    var subject_storage: [256]u8 = undefined;
    const subject = try std.fmt.bufPrint(&subject_storage, "nick!u@{s}", .{current});
    var probe_before = try akick_codec.decode(a, bytes);
    defer probe_before.deinit();
    var probe_after = try akick_codec.decode(a, plan.checkpoint);
    defer probe_after.deinit();
    for ([_]i64{ 98, 99 }) |now| {
        const first = probe_before.matchOnJoin("#z", narrow, null, now).?;
        const second = probe_after.matchOnJoin("#z", subject, null, now).?;
        try testing.expectEqualStrings(first.reason, second.reason);
        try testing.expectEqualStrings(if (now == 98) "first-reason" else "second-reason", second.reason);
        try testing.expectEqual(first.expires_at_ms, second.expires_at_ms);
    }
    try testing.expect(probe_after.matchOnJoin("#z", subject, null, 200) == null);
    try testing.expect(probe_after.matchOnJoin("#z", "other!u@unrelated", null, 98) == null);
    try testing.expectEqualStrings("account-reason", probe_after.matchOnJoin("#z", "other!u@unrelated", "alice", 98).?.reason);
    try testing.expectEqualSlices(u8, before, bytes);
    const after = try akick_codec.encode(a, &original);
    defer a.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "policy list audit: WARD all facets scope action signed times parameters and precedence remain exact" {
    const a = testing.allocator;
    var key = cloak.SecretKey.init(@splat(0x72));
    defer key.wipe();
    var host_storage: [253]u8 = undefined;
    const host = try oldHost(&host_storage, &key);
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "Nick!u@{s}", .{host});
    var original = warden.Registry.init(a, wardParams);
    defer original.deinit();
    try fillWard(&original, host, mask);
    const bytes = try ward_codec.encode(a, &original);
    defer a.free(bytes);
    const witnesses = [_]audit.Witness{ .{ .row = 0, .expected_mask = host, .source = source(&key) }, .{ .row = 1, .expected_mask = mask, .source = source(&key) } };
    var plan = try audit.auditWard(a, bytes, &witnesses, target(&key), .{});
    defer plan.deinit();
    try label(&plan, 0, "verified_replacement");
    try label(&plan, 1, "verified_replacement");
    try label(&plan, 2, "non_host_facet");
    try label(&plan, 3, "non_host_facet");
    try label(&plan, 4, "ambiguous_host_glob");
    try label(&plan, 5, "unsupported_mask_shape");
    try label(&plan, 6, "non_host_facet");
    try summaryOnly(&plan);
    var restored = try ward_codec.decode(a, plan.checkpoint);
    defer restored.deinit();
    try testing.expectEqual(wardParams, restored.params);
    try testing.expectEqual(@as(usize, 7), restored.wards.items.len);
    try testing.expectEqual(@as(i64, -1), restored.wards.items[4].expires_ms);
    for (0..2) |i| {
        const owned = try a.dupe(u8, original.wards.items[i].pattern);
        a.free(restored.wards.items[i].pattern);
        restored.wards.items[i].pattern = owned;
    }
    const undone = try ward_codec.encode(a, &restored);
    defer a.free(undone);
    try testing.expectEqualSlices(u8, bytes, undone);
    var current_storage: [253]u8 = undefined;
    const current = try newHost(&current_storage, &key);
    var current_mask_storage: [256]u8 = undefined;
    const current_mask = try std.fmt.bufPrint(&current_mask_storage, "Nick!u@{s}", .{current});
    // check() prunes. Use fresh owned probe images so no audit/source state is
    // consumed by the pre/post enforcement oracle.
    for ([_]i64{ 98, 99, 200 }) |now| {
        var before = try ward_codec.decode(a, bytes);
        defer before.deinit();
        var after = try ward_codec.decode(a, plan.checkpoint);
        defer after.deinit();
        const old_hit = before.check(.{ .host = host, .mask = mask }, now);
        const new_hit = after.check(.{ .host = current, .mask = current_mask }, now);
        if (now == 200) {
            try testing.expect(old_hit == null and new_hit == null);
        } else {
            try testing.expectEqualStrings(old_hit.?.reason, new_hit.?.reason);
            try testing.expectEqual(old_hit.?.scope, new_hit.?.scope);
            try testing.expectEqual(old_hit.?.action, new_hit.?.action);
            try testing.expectEqual(old_hit.?.expires_ms, new_hit.?.expires_ms);
            try testing.expectEqualStrings(if (now == 98) "first-reason" else "second-reason", new_hit.?.reason);
        }
    }
    const after = try ward_codec.encode(a, &original);
    defer a.free(after);
    try testing.expectEqualSlices(u8, bytes, after);
}

test "policy list audit: AKCK replacement collision refuses complete candidate without merging authority" {
    const a = testing.allocator;
    var key = cloak.SecretKey.init(@splat(0x73));
    defer key.wipe();
    var first_storage: [253]u8 = undefined;
    var second_storage: [253]u8 = undefined;
    const first_host = try cloak.cloakOpaque(&first_storage, &key, source(&key).address, .{ .suffix = "onyx" });
    const second_host = try cloak.cloakOpaqueV3(&second_storage, &key, source(&key).address, .{ .suffix = "onyx" });
    var one_storage: [256]u8 = undefined;
    var two_storage: [256]u8 = undefined;
    const one = try std.fmt.bufPrint(&one_storage, "*!u@{s}", .{first_host});
    const two = try std.fmt.bufPrint(&two_storage, "*!u@{s}", .{second_host});
    var store = akick.AkickStore.init(a);
    defer store.deinit();
    try store.add("#room", one, "first", "FirstIssuer", 10, 99);
    try store.add("#room", two, "second", "SecondIssuer", 20, null);
    const bytes = try akick_codec.encode(a, &store);
    defer a.free(bytes);
    var first = source(&key);
    first.formula = .opaque_v2;
    first.epoch = null;
    var second = first;
    second.formula = .opaque_v3;
    const witnesses = [_]audit.Witness{ .{ .row = 0, .expected_mask = one, .source = first }, .{ .row = 1, .expected_mask = two, .source = second } };
    try testing.expectError(error.DuplicateMask, audit.auditAkick(a, bytes, &witnesses, target(&key), .{}));
    const after = try akick_codec.encode(a, &store);
    defer a.free(after);
    try testing.expectEqualSlices(u8, bytes, after);
}

test "policy list audit: WARD replacement collision preserves distinct actions scopes issuer and expiry" {
    const a = testing.allocator;
    var key = cloak.SecretKey.init(@splat(0x74));
    defer key.wipe();
    var one_storage: [253]u8 = undefined;
    var two_storage: [253]u8 = undefined;
    const one = try cloak.cloakOpaque(&one_storage, &key, source(&key).address, .{ .suffix = "onyx" });
    const two = try cloak.cloakOpaqueV3(&two_storage, &key, source(&key).address, .{ .suffix = "onyx" });
    var registry = warden.Registry.init(a, wardParams);
    defer registry.deinit();
    try registry.add(.{ .match = .host, .pattern = one, .scope = .mesh, .action = .expel, .set_by = "FirstIssuer", .expires_ms = 99 });
    try registry.add(.{ .match = .host, .pattern = two, .scope = .node, .action = .require_auth, .set_by = "SecondIssuer", .expires_ms = 0 });
    const bytes = try ward_codec.encode(a, &registry);
    defer a.free(bytes);
    var first = source(&key);
    first.formula = .opaque_v2;
    first.epoch = null;
    var second = first;
    second.formula = .opaque_v3;
    const witnesses = [_]audit.Witness{ .{ .row = 0, .expected_mask = one, .source = first }, .{ .row = 1, .expected_mask = two, .source = second } };
    try testing.expectError(error.DuplicateWard, audit.auditWard(a, bytes, &witnesses, target(&key), .{}));
    const after = try ward_codec.encode(a, &registry);
    defer a.free(after);
    try testing.expectEqualSlices(u8, bytes, after);
}

fn allocationAkick(a: std.mem.Allocator, bytes: []const u8, witness: audit.Witness, key: *const cloak.SecretKey) !void {
    var plan = try audit.auditAkick(a, bytes, &.{witness}, target(key), .{});
    defer plan.deinit();
    try label(&plan, 0, "verified_replacement");
    try akick_codec.validateCheckpoint(plan.checkpoint);
}
fn allocationWard(a: std.mem.Allocator, bytes: []const u8, witness: audit.Witness, key: *const cloak.SecretKey) !void {
    var plan = try audit.auditWard(a, bytes, &.{witness}, target(key), .{});
    defer plan.deinit();
    try label(&plan, 0, "verified_replacement");
    try ward_codec.validateCheckpoint(plan.checkpoint);
}

test "policy list audit: every allocation cut leaves both checkpoint inputs byte exact and permits retry" {
    const a = testing.allocator;
    var key = cloak.SecretKey.init(@splat(0x75));
    defer key.wipe();
    var host_storage: [253]u8 = undefined;
    const host = try oldHost(&host_storage, &key);
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "*!u@{s}", .{host});
    var store = akick.AkickStore.init(a);
    defer store.deinit();
    try store.add("#room", mask, "private-reason", "PrivateIssuer", -42, 99);
    try store.checkpointEnsureChannel("#empty");
    const ak = try akick_codec.encode(a, &store);
    defer a.free(ak);
    const ak_before = try a.dupe(u8, ak);
    defer a.free(ak_before);
    var registry = warden.Registry.init(a, wardParams);
    defer registry.deinit();
    try registry.add(.{ .match = .mask, .pattern = mask, .scope = .mesh, .action = .quarantine, .set_by = "PrivateIssuer", .created_ms = -42, .expires_ms = 99 });
    const ward = try ward_codec.encode(a, &registry);
    defer a.free(ward);
    const ward_before = try a.dupe(u8, ward);
    defer a.free(ward_before);
    const witness = audit.Witness{ .row = 0, .expected_mask = mask, .source = source(&key) };
    try testing.checkAllAllocationFailures(a, allocationAkick, .{ ak, witness, &key });
    try testing.checkAllAllocationFailures(a, allocationWard, .{ ward, witness, &key });
    try testing.expectEqualSlices(u8, ak_before, ak);
    try testing.expectEqualSlices(u8, ward_before, ward);
    const ak_after = try akick_codec.encode(a, &store);
    defer a.free(ak_after);
    const ward_after = try ward_codec.encode(a, &registry);
    defer a.free(ward_after);
    try testing.expectEqualSlices(u8, ak_before, ak_after);
    try testing.expectEqualSlices(u8, ward_before, ward_after);
    try allocationAkick(a, ak, witness, &key);
    try allocationWard(a, ward, witness, &key);
}

test "policy list audit: bounded selectors invalid frames and no witness retain exact inputs" {
    const a = testing.allocator;
    var key = cloak.SecretKey.init(@splat(0x76));
    defer key.wipe();
    var host_storage: [253]u8 = undefined;
    const host = try oldHost(&host_storage, &key);
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "*!u@{s}", .{host});
    var store = akick.AkickStore.init(a);
    defer store.deinit();
    try store.add("#room", mask, "reason", "Issuer", 17, 99);
    const ak = try akick_codec.encode(a, &store);
    defer a.free(ak);
    var registry = warden.Registry.init(a, wardParams);
    defer registry.deinit();
    try registry.add(.{ .match = .host, .pattern = host, .created_ms = 17, .expires_ms = 99 });
    const ward = try ward_codec.encode(a, &registry);
    defer a.free(ward);
    var ap = try audit.auditAkick(a, ak, &.{}, target(&key), .{});
    defer ap.deinit();
    var wp = try audit.auditWard(a, ward, &.{}, target(&key), .{});
    defer wp.deinit();
    try label(&ap, 0, "missing_witness");
    try label(&wp, 0, "missing_witness");
    try testing.expectEqualSlices(u8, ak, ap.checkpoint);
    try testing.expectEqualSlices(u8, ward, wp.checkpoint);
    const witness = audit.Witness{ .row = 0, .expected_mask = mask, .source = source(&key) };
    var outside = witness;
    outside.row = 1;
    try testing.expectError(error.InvalidWitnessOrder, audit.auditAkick(a, ak, &.{ witness, witness }, target(&key), .{}));
    try testing.expectError(error.InvalidWitnessOrder, audit.auditWard(a, ward, &.{ witness, witness }, target(&key), .{}));
    try testing.expectError(error.WitnessOutOfRange, audit.auditAkick(a, ak, &.{outside}, target(&key), .{}));
    try testing.expectError(error.WitnessOutOfRange, audit.auditWard(a, ward, &.{outside}, target(&key), .{}));
    try testing.expectError(error.LimitExceeded, audit.auditAkick(a, ak, &.{}, target(&key), .{ .max_rows = 0 }));
    try testing.expectError(error.LimitExceeded, audit.auditWard(a, ward, &.{}, target(&key), .{ .max_bytes = ward.len - 1 }));
    try testing.expectError(error.LimitExceeded, audit.auditAkick(a, ak, &.{}, target(&key), .{ .max_rows = 4097 }));
    // Inputs fit these byte ceilings, but longer v4 masks make publication
    // exceed them; the entire detached candidate must be discarded.
    try testing.expectError(error.LimitExceeded, audit.auditAkick(a, ak, &.{witness}, target(&key), .{ .max_bytes = ak.len }));
    const host_witness = audit.Witness{ .row = 0, .expected_mask = host, .source = source(&key) };
    try testing.expectError(error.LimitExceeded, audit.auditWard(a, ward, &.{host_witness}, target(&key), .{ .max_bytes = ward.len }));
    try testing.expectError(error.Truncated, audit.auditAkick(a, "AK", &.{}, target(&key), .{}));
    try testing.expectError(error.Truncated, audit.auditWard(a, "WA", &.{}, target(&key), .{}));
}

test "policy list audit: wrong evidence and unsupported shapes cannot alter account or other facet authority" {
    const a = testing.allocator;
    var key = cloak.SecretKey.init(@splat(0x77));
    defer key.wipe();
    var wrong_key = cloak.SecretKey.init(@splat(0x78));
    defer wrong_key.wipe();
    var host_storage: [253]u8 = undefined;
    const host = try oldHost(&host_storage, &key);
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "*!u@{s}", .{host});
    var store = akick.AkickStore.init(a);
    defer store.deinit();
    try store.add("#room", "account:alice*", "reason", "Issuer", 17, null);
    try store.add("#room", host, "bare unsupported", "Issuer", 18, null);
    try store.add("#room", mask, "wrong evidence", "Issuer", 19, null);
    const ak = try akick_codec.encode(a, &store);
    defer a.free(ak);
    var wrong = source(&key);
    wrong.key = &wrong_key;
    const witnesses = [_]audit.Witness{ .{ .row = 0, .expected_mask = "not-the-account", .source = wrong }, .{ .row = 2, .expected_mask = mask, .source = wrong } };
    var plan = try audit.auditAkick(a, ak, &witnesses, target(&key), .{});
    defer plan.deinit();
    try label(&plan, 0, "account_rule");
    try label(&plan, 1, "unsupported_mask_shape");
    try label(&plan, 2, "derivation_mismatch");
    try testing.expectEqualSlices(u8, ak, plan.checkpoint);
    try summaryOnly(&plan);
    var registry = warden.Registry.init(a, wardParams);
    defer registry.deinit();
    try registry.add(.{ .match = .account, .pattern = host });
    try registry.add(.{ .match = .mask, .pattern = host });
    try registry.add(.{ .match = .host, .pattern = host });
    const ward = try ward_codec.encode(a, &registry);
    defer a.free(ward);
    const ward_witnesses = [_]audit.Witness{ .{ .row = 0, .expected_mask = host, .source = source(&key) }, .{ .row = 2, .expected_mask = host, .source = wrong } };
    var ward_plan = try audit.auditWard(a, ward, &ward_witnesses, target(&key), .{});
    defer ward_plan.deinit();
    try label(&ward_plan, 0, "non_host_facet");
    try label(&ward_plan, 1, "unsupported_mask_shape");
    try label(&ward_plan, 2, "derivation_mismatch");
    try testing.expectEqualSlices(u8, ward, ward_plan.checkpoint);
    try summaryOnly(&ward_plan);
}

fn allocationK1(a: std.mem.Allocator, bytes: []const u8) !void {
    var plan = try audit.auditDurableAkickRecord(a, bytes, .{});
    defer plan.deinit();
    try label(&plan, 0, "metadata_gap");
    try testing.expectEqualSlices(u8, bytes, plan.checkpoint);
}

test "policy list audit: durable K1 remains opaque metadata gap without fabricated creation expiry or order" {
    const bytes = "K1|#room|*!u@private.opq.onyx|00000000000000000000000000000000|PrivateIssuer|private-reason";
    const a = testing.allocator;
    var plan = try audit.auditDurableAkickRecord(a, bytes, .{});
    defer plan.deinit();
    try label(&plan, 0, "metadata_gap");
    try testing.expectEqualSlices(u8, bytes, plan.checkpoint);
    try testing.expect(!akick_codec.isCheckpoint(plan.checkpoint));
    try summaryOnly(&plan);
    try testing.checkAllAllocationFailures(a, allocationK1, .{bytes});
    try testing.expectError(error.NotDurableAkickRecord, audit.auditDurableAkickRecord(a, "other", .{}));
    try testing.expectError(error.LimitExceeded, audit.auditDurableAkickRecord(a, bytes, .{ .max_rows = 0 }));
    try testing.expectError(error.LimitExceeded, audit.auditDurableAkickRecord(a, bytes, .{ .max_bytes = bytes.len - 1 }));
}
