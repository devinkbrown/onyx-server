// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const t = std.testing;
const audit = @import("daemon/cloak_durable_audit.zig");
const cloak = @import("proto/cloak.zig");
const warden = @import("daemon/warden.zig");
const akick = @import("daemon/svc_akick.zig");
const saccess = @import("proto/ircx_saccess.zig");

const Evidence = struct {
    source: *const cloak.SecretKey,
    target: *const cloak.SecretKey,
    fn witness(self: Evidence, mask: []const u8) audit.Witness {
        return .{ .row = 0, .expected_mask = mask, .source = .{ .formula = .opaque_epoch_v3, .key = self.source, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7 } };
    }
    fn destination(self: Evidence) audit.Target {
        return .{ .key = self.target, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
    }
};
fn host(out: []u8, key: *const cloak.SecretKey, new: bool) ![]const u8 {
    return if (new) cloak.cloakOpaqueEpochV4(out, key, "203.0.113.9", 90, 1_209_600, .{ .suffix = "onyx" }) else cloak.cloakOpaqueEpochV3(out, key, "203.0.113.9", 7, .{ .suffix = "onyx" });
}
fn checkSummary(plan: *const audit.Plan, expected: []const u8) !void {
    const Capture = struct {
        bytes: [128]u8 = undefined,
        len: usize = 0,
        fn emit(self: *@This(), text: []const u8) !void {
            if (self.len != 0 or text.len > self.bytes.len) return error.InvalidSummary;
            @memcpy(self.bytes[0..text.len], text);
            self.len = text.len;
        }
    };
    var capture = Capture{};
    try plan.forEachSummary(&capture, Capture.emit);
    try t.expectEqualStrings(expected, capture.bytes[0..capture.len]);
}

fn wardMatch(a: std.mem.Allocator, record: []const u8, subject: []const u8, expected: bool, now: i64) !void {
    var it = std.mem.splitScalar(u8, record, '|');
    try t.expectEqualStrings("W1", it.next().?);
    const facet = warden.Match.parse(it.next().?).?;
    const pattern = it.next().?;
    const scope = warden.Scope.parse(it.next().?).?;
    const action = warden.Action.parse(it.next().?).?;
    const created = try std.fmt.parseInt(i64, it.next().?, 10);
    const expiry = try std.fmt.parseInt(i64, it.next().?, 10);
    const issuer = it.next().?;
    const reason = it.next().?;
    try t.expect(it.next() == null);
    var registry = warden.Registry.init(a, .{});
    defer registry.deinit();
    try registry.add(.{ .match = facet, .pattern = pattern, .scope = scope, .action = action, .set_by = issuer, .reason = reason, .created_ms = created, .expires_ms = expiry });
    const found = registry.check(.{ .mask = subject }, now);
    try t.expectEqual(expected, found != null);
    if (found) |value| {
        try t.expectEqual(warden.Scope.mesh, value.scope);
        try t.expectEqual(warden.Action.quarantine, value.action);
        try t.expectEqualStrings("Issuer", value.set_by);
        try t.expectEqualStrings("private reason", value.reason);
        try t.expectEqual(@as(i64, -42), value.created_ms);
        try t.expectEqual(@as(i64, 100), value.expires_ms);
    }
}
fn checkAllocation(a: std.mem.Allocator, bytes: []const u8, witness: audit.Witness, target: audit.Target) !void {
    var plan = try audit.audit(a, .ward_record, bytes, witness, target, .{});
    defer plan.deinit();
    try t.expectEqualStrings("verified_replacement", plan.classification.name());
}

fn gapAllocation(a: std.mem.Allocator, kind: audit.Kind, bytes: []const u8, witness: audit.Witness, target: audit.Target) !void {
    var plan = try audit.audit(a, kind, bytes, witness, target, .{});
    defer plan.deinit();
    try t.expectEqualStrings("metadata_gap", plan.classification.name());
    try t.expectEqualSlices(u8, bytes, plan.record);
}

test "cloak durable W1 exact witnessed replacement preserves all physical metadata" {
    const a = t.allocator;
    var source = cloak.SecretKey.init(@splat(0x31));
    defer source.wipe();
    var target = cloak.SecretKey.init(@splat(0x32));
    defer target.wipe();
    var old_buf: [253]u8 = undefined;
    var new_buf: [253]u8 = undefined;
    const old_host = try host(&old_buf, &source, false);
    const new_host = try host(&new_buf, &target, true);
    const old = try std.fmt.allocPrint(a, "nick*!u@{s}", .{old_host});
    defer a.free(old);
    const new = try std.fmt.allocPrint(a, "nick*!u@{s}", .{new_host});
    defer a.free(new);
    const record = try std.fmt.allocPrint(a, "W1|mask|{s}|mesh|quarantine|-042|0100|Issuer|private reason", .{old});
    defer a.free(record);
    const expected = try std.fmt.allocPrint(a, "W1|mask|{s}|mesh|quarantine|-042|0100|Issuer|private reason", .{new});
    defer a.free(expected);
    const saved = try a.dupe(u8, record);
    defer a.free(saved);
    const e = Evidence{ .source = &source, .target = &target };
    var plan = try audit.audit(a, .ward_record, record, e.witness(old), e.destination(), .{});
    defer plan.deinit();
    try t.expectEqualStrings("verified_replacement", plan.classification.name());
    try t.expectEqual(audit.KeyEffect.rekey_required, plan.key_effect);
    try t.expect(plan.requires_collection_order_proof);
    try checkSummary(&plan, "row=0 classification=verified_replacement key_migration=required order_proof=missing\n");
    try t.expectEqualSlices(u8, expected, plan.record);
    try t.expectEqualSlices(u8, saved, record);
    const old_subject = try std.fmt.allocPrint(a, "nick!u@{s}", .{old_host});
    defer a.free(old_subject);
    const new_subject = try std.fmt.allocPrint(a, "nick!u@{s}", .{new_host});
    defer a.free(new_subject);
    const wrong_nick = try std.fmt.allocPrint(a, "other!u@{s}", .{new_host});
    defer a.free(wrong_nick);
    const wrong_ident = try std.fmt.allocPrint(a, "nick!wrong@{s}", .{new_host});
    defer a.free(wrong_ident);
    try wardMatch(a, record, old_subject, true, 99);
    try wardMatch(a, plan.record, new_subject, true, 99);
    try wardMatch(a, plan.record, new_subject, false, 100);
    try wardMatch(a, plan.record, new_subject, false, 101);
    try wardMatch(a, plan.record, wrong_nick, false, 99);
    try wardMatch(a, plan.record, wrong_ident, false, 99);
    var current_witness = e.witness(new);
    current_witness.source = .{ .formula = .opaque_epoch_v4, .key = &target, .address = "203.0.113.9", .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
    var current = try audit.audit(a, .ward_record, expected, current_witness, e.destination(), .{});
    defer current.deinit();
    try t.expectEqualStrings("already_current", current.classification.name());
    try t.expectEqual(audit.KeyEffect.unchanged, current.key_effect);
    try t.expect(!current.requires_collection_order_proof);
    try t.expectEqualSlices(u8, expected, current.record);
    try checkSummary(&current, "row=0 classification=already_current key_migration=none order_proof=not_needed\n");
    try t.checkAllAllocationFailures(a, checkAllocation, .{ record, e.witness(old), e.destination() });
    try t.expectEqualSlices(u8, saved, record);
}

test "cloak durable K1 and S1 preserve opaque missing expiry and order" {
    const a = t.allocator;
    var source = cloak.SecretKey.init(@splat(0x41));
    defer source.wipe();
    var target = cloak.SecretKey.init(@splat(0x42));
    defer target.wipe();
    var buf: [253]u8 = undefined;
    const old_host = try host(&buf, &source, false);
    const mask = try std.fmt.allocPrint(a, "nick*!u@{s}", .{old_host});
    defer a.free(mask);
    const k = try std.fmt.allocPrint(a, "K1|#Room|{s}|00112233445566778899aabbccddeeff|Issuer|reason", .{mask});
    defer a.free(k);
    const s = try std.fmt.allocPrint(a, "S1|DENY|{s}|00030|reason", .{mask});
    defer a.free(s);
    const e = Evidence{ .source = &source, .target = &target };
    for ([_]audit.Kind{ .akick_record, .saccess_record }, [_][]const u8{ k, s }) |kind, bytes| {
        var plan = try audit.audit(a, kind, bytes, e.witness(mask), e.destination(), .{});
        defer plan.deinit();
        try t.expectEqualStrings("metadata_gap", plan.classification.name());
        try t.expectEqual(audit.KeyEffect.unchanged, plan.key_effect);
        try t.expect(!plan.requires_collection_order_proof);
        try checkSummary(&plan, "row=0 classification=metadata_gap key_migration=none order_proof=not_needed\n");
        try t.expectEqualSlices(u8, bytes, plan.record);
        var gap_only = try audit.audit(a, kind, bytes, null, null, .{});
        defer gap_only.deinit();
        try t.expectEqualStrings("metadata_gap", gap_only.classification.name());
        try t.expectEqual(audit.KeyEffect.unchanged, gap_only.key_effect);
        try t.expect(!gap_only.requires_collection_order_proof);
        try t.expectEqualSlices(u8, bytes, gap_only.record);
        var bad = e.witness(mask);
        bad.source.key = &target;
        var mismatch = try audit.audit(a, kind, bytes, bad, e.destination(), .{});
        defer mismatch.deinit();
        try t.expectEqualStrings("metadata_gap", mismatch.classification.name());
        try t.expectEqualSlices(u8, bytes, mismatch.record);
        try t.checkAllAllocationFailures(a, gapAllocation, .{ kind, bytes, e.witness(mask), e.destination() });
    }
    const candidate = try std.fmt.allocPrint(a, "nick!u@{s}", .{old_host});
    defer a.free(candidate);
    try t.expect(try akick.candidateMatchesWithCloak(mask, candidate, null, null));
    const wrong_nick = try std.fmt.allocPrint(a, "other!u@{s}", .{old_host});
    defer a.free(wrong_nick);
    const wrong_ident = try std.fmt.allocPrint(a, "nick!wrong@{s}", .{old_host});
    defer a.free(wrong_ident);
    try t.expect(!try akick.candidateMatchesWithCloak(mask, wrong_nick, null, null));
    try t.expect(!try akick.candidateMatchesWithCloak(mask, wrong_ident, null, null));
    var store = saccess.ServerAccessStore.init(a);
    defer store.deinit();
    try store.add(.{ .entry_type = .deny, .mask = mask, .duration = 30, .reason = "reason" });
    try t.expect(store.matchHostmask(.deny, candidate) != null);
    try t.expect(store.matchHostmask(.deny, wrong_nick) == null);
    try t.expect(store.matchHostmask(.deny, wrong_ident) == null);
    try t.expect(store.matchHostmask(.deny, "wrong!u@invalid") == null);
}

test "cloak durable wrong or missing provenance leaves record unchanged" {
    const a = t.allocator;
    var source = cloak.SecretKey.init(@splat(0x51));
    defer source.wipe();
    var target = cloak.SecretKey.init(@splat(0x52));
    defer target.wipe();
    var wrong = cloak.SecretKey.init(@splat(0x53));
    defer wrong.wipe();
    var buf: [253]u8 = undefined;
    const old_host = try host(&buf, &source, false);
    const mask = try std.fmt.allocPrint(a, "nick!u@{s}", .{old_host});
    defer a.free(mask);
    const record = try std.fmt.allocPrint(a, "W1|mask|{s}|node|refuse|1|0||", .{mask});
    defer a.free(record);
    const e = Evidence{ .source = &source, .target = &target };
    var missing = try audit.audit(a, .ward_record, record, null, e.destination(), .{});
    defer missing.deinit();
    try t.expectEqualStrings("missing_witness", missing.classification.name());
    try t.expectEqual(audit.KeyEffect.unchanged, missing.key_effect);
    try t.expect(!missing.requires_collection_order_proof);
    try checkSummary(&missing, "row=0 classification=missing_witness key_migration=none order_proof=not_needed\n");
    try t.expectEqualSlices(u8, record, missing.record);
    var bad = e.witness(mask);
    bad.source.key = &wrong;
    var mismatch = try audit.audit(a, .ward_record, record, bad, e.destination(), .{});
    defer mismatch.deinit();
    try t.expectEqualStrings("derivation_mismatch", mismatch.classification.name());
    try t.expectEqual(audit.KeyEffect.unchanged, mismatch.key_effect);
    try t.expect(!mismatch.requires_collection_order_proof);
    try checkSummary(&mismatch, "row=0 classification=derivation_mismatch key_migration=none order_proof=not_needed\n");
    try t.expectEqualSlices(u8, record, mismatch.record);
    const glob = "W1|host|*.opq.onyx|node|refuse|1|0||";
    var ambiguous = try audit.audit(a, .ward_record, glob, null, e.destination(), .{});
    defer ambiguous.deinit();
    try t.expectEqualStrings("ambiguous_host_glob", ambiguous.classification.name());
    try t.expectEqual(audit.KeyEffect.unchanged, ambiguous.key_effect);
    try t.expect(!ambiguous.requires_collection_order_proof);
    try checkSummary(&ambiguous, "row=0 classification=ambiguous_host_glob key_migration=none order_proof=not_needed\n");
    try t.expectEqualSlices(u8, glob, ambiguous.record);
    const nonhost = "W1|account|operator*|node|refuse|1|0||";
    var facet = try audit.audit(a, .ward_record, nonhost, null, e.destination(), .{});
    defer facet.deinit();
    try t.expectEqualStrings("non_host_facet", facet.classification.name());
    try t.expectEqual(audit.KeyEffect.unchanged, facet.key_effect);
    try t.expect(!facet.requires_collection_order_proof);
    try checkSummary(&facet, "row=0 classification=non_host_facet key_migration=none order_proof=not_needed\n");
    try t.expectEqualSlices(u8, nonhost, facet.record);
}

test "cloak durable malformed unsupported bounds and row selectors fail closed" {
    const a = t.allocator;
    var key = cloak.SecretKey.init(@splat(0x61));
    defer key.wipe();
    const e = Evidence{ .source = &key, .target = &key };
    try t.expectError(error.MissingTarget, audit.audit(a, .ward_record, "W1|mask|*!u@h|mesh|refuse|0|0||", null, null, .{}));
    try t.expectError(error.InvalidRecord, audit.audit(a, .akick_record, "K1|#x|*!u@h|bad|issuer|reason", null, e.destination(), .{}));
    try t.expectError(error.InvalidRecord, audit.audit(a, .saccess_record, "S1|DENY|*!u@h|bad|reason", null, e.destination(), .{}));
    try t.expectError(error.InvalidRecord, audit.audit(a, .ward_record, "W1|mask|*!u@h|mesh|refuse|bad|0||", null, e.destination(), .{}));
    try t.expectError(error.UnsupportedRecord, audit.audit(a, .ward_record, "W1|unknown|*!u@h|mesh|refuse|0|0||", null, e.destination(), .{}));
    try t.expectError(error.LimitExceeded, audit.audit(a, .ward_record, "W1|mask|*!u@h|mesh|refuse|0|0||", null, e.destination(), .{ .max_rows = 0 }));
    var witness = e.witness("*!u@h");
    witness.row = 1;
    try t.expectError(error.WitnessOutOfRange, audit.audit(a, .ward_record, "W1|mask|*!u@h|mesh|refuse|0|0||", witness, e.destination(), .{}));
}

test "cloak durable overlapping Warden order changes first action" {
    const a = t.allocator;
    const narrow: warden.Ward = .{ .match = .mask, .pattern = "nick*!u@host.example", .action = .quarantine, .scope = .mesh };
    const broad: warden.Ward = .{ .match = .mask, .pattern = "*!*@host.example", .action = .refuse, .scope = .node };
    var first = warden.Registry.init(a, .{});
    defer first.deinit();
    try first.add(narrow);
    try first.add(broad);
    const subject = warden.Facets{ .mask = "nick123!u@host.example" };
    try t.expectEqual(warden.Action.quarantine, first.check(subject, 10).?.action);
    var reversed = warden.Registry.init(a, .{});
    defer reversed.deinit();
    try reversed.add(broad);
    try reversed.add(narrow);
    try t.expectEqual(warden.Action.refuse, reversed.check(subject, 10).?.action);
}
