// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure offline policy audit. No live Store, network, configuration or clock is
//! consulted. A candidate is a private detached checkpoint, not authorization to
//! publish replacement mesh facts. Unknown historical intent remains unknown.
const std = @import("std");
const cloak = @import("../proto/cloak.zig");
const access = @import("../proto/ircx_access_store.zig");
const access_checkpoint = @import("helix/access_checkpoint.zig");
const saccess_checkpoint = @import("helix/saccess_checkpoint.zig");

pub const Limits = struct {
    max_rows: usize = 4096,
    max_bytes: usize = 8 * 1024 * 1024,
};
pub const Formula = enum { opaque_v2, opaque_epoch_v2, opaque_v3, opaque_epoch_v3, opaque_epoch_v4, unsupported };
/// The caller supplies historical evidence explicitly. These borrowed private
/// fields never enter a report, checkpoint, log, digest or retained cache.
pub const Source = struct {
    formula: Formula,
    key: *const cloak.SecretKey,
    address: []const u8,
    suffix: []const u8,
    epoch: ?u64 = null,
    cadence: ?u64 = null,
};
pub const Target = struct {
    key: *const cloak.SecretKey,
    suffix: []const u8,
    epoch: u64,
    cadence: u64,
};
/// Sorted row ordinals and exact old bytes bind a witness to one input image.
/// Ordinals are audit-local selectors, never authorization identities.
pub const Witness = struct { row: usize, expected_mask: []const u8, source: Source };
pub const Classification = enum {
    verified_replacement,
    already_current,
    missing_witness,
    witness_mismatch,
    ambiguous_host_glob,
    unsupported_formula,
    invalid_witness,
    derivation_mismatch,
    invalid_target,
    replacement_too_long,
    metadata_gap,
};
pub const Report = struct { row: usize, classification: Classification };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    /// Private exact candidate; only an explicit artifact writer may expose it.
    /// ACCESS changes only verified masks; no ADD commands have been replayed.
    checkpoint: []u8,
    reports: []Report,
    pub fn deinit(self: *Plan) void {
        std.crypto.secureZero(u8, self.checkpoint);
        self.allocator.free(self.checkpoint);
        self.allocator.free(self.reports);
        self.* = undefined;
    }
    /// Default report exposes only bounded ordinals and fixed classifications.
    pub fn forEachSummary(self: *const Plan, ctx: anytype, comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void) !void {
        var text: [96]u8 = undefined;
        for (self.reports) |report| {
            const line = try std.fmt.bufPrint(&text, "row={d} classification={s}\n", .{ report.row, @tagName(report.classification) });
            try emit(ctx, line);
        }
    }
};
pub const Error = access_checkpoint.Error || saccess_checkpoint.Error || error{ LimitExceeded, InvalidWitnessOrder, WitnessOutOfRange };

/// Borrowed replacement points only into the caller's output buffer. This
/// host proof alone does not assert that a rule family has issuer/expiry data.
pub const MaskDecision = struct { classification: Classification, replacement: ?[]const u8 = null };
fn deriveSource(out: []u8, source: Source) cloak.CloakError![]const u8 {
    const options: cloak.Options = .{ .suffix = source.suffix };
    return switch (source.formula) {
        .opaque_v2 => if (source.epoch == null and source.cadence == null) cloak.cloakOpaque(out, source.key, source.address, options) else error.InvalidHostname,
        .opaque_v3 => if (source.epoch == null and source.cadence == null) cloak.cloakOpaqueV3(out, source.key, source.address, options) else error.InvalidHostname,
        .opaque_epoch_v2 => if (source.epoch != null and source.cadence == null) cloak.cloakOpaqueEpoch(out, source.key, source.address, source.epoch.?, options) else error.InvalidHostname,
        .opaque_epoch_v3 => if (source.epoch != null and source.cadence == null) cloak.cloakOpaqueEpochV3(out, source.key, source.address, source.epoch.?, options) else error.InvalidHostname,
        .opaque_epoch_v4 => if (source.epoch != null and source.cadence != null) cloak.cloakOpaqueEpochV4(out, source.key, source.address, source.epoch.?, source.cadence.?, options) else error.InvalidHostname,
        .unsupported => error.InvalidHostname,
    };
}
pub fn classifyMask(mask: []const u8, witness: ?Witness, target: Target, replacement: []u8) MaskDecision {
    if (mask.len > 512) return .{ .classification = .replacement_too_long };
    if (target.suffix.len > cloak.max_hostname_len) return .{ .classification = .invalid_target };
    // Only the host may be replaced. Nick/ident wildcards retain their original
    // byte-exact positions; a digest glob is never narrowed to one guessed IP.
    const host_start = if (std.mem.lastIndexOfScalar(u8, mask, '@')) |at| at + 1 else 0;
    const host = mask[host_start..];
    if (std.mem.indexOfAny(u8, host, "*?") != null) return .{ .classification = .ambiguous_host_glob };
    const evidence = witness orelse return .{ .classification = .missing_witness };
    if (!std.mem.eql(u8, evidence.expected_mask, mask)) return .{ .classification = .witness_mismatch };
    if (evidence.source.address.len > 128 or evidence.source.suffix.len > cloak.max_hostname_len)
        return .{ .classification = .invalid_witness };
    if (evidence.source.formula == .unsupported) return .{ .classification = .unsupported_formula };
    var old_storage: [cloak.max_hostname_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &old_storage);
    const old = deriveSource(&old_storage, evidence.source) catch return .{ .classification = .invalid_witness };
    if (!std.ascii.eqlIgnoreCase(old, host)) return .{ .classification = .derivation_mismatch };
    var new_storage: [cloak.max_hostname_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &new_storage);
    const new = cloak.cloakOpaqueEpochV4(&new_storage, target.key, evidence.source.address, target.epoch, target.cadence, .{ .suffix = target.suffix }) catch return .{ .classification = .invalid_target };
    if (std.mem.eql(u8, new, host)) return .{ .classification = .already_current };
    const size = std.math.add(usize, host_start, new.len) catch return .{ .classification = .replacement_too_long };
    if (size > replacement.len or size > access.DEFAULT_MAX_MASK_BYTES) return .{ .classification = .replacement_too_long };
    @memcpy(replacement[0..host_start], mask[0..host_start]);
    @memcpy(replacement[host_start..size], new);
    return .{ .classification = .verified_replacement, .replacement = replacement[0..size] };
}
fn checkLimits(bytes: []const u8, limits: Limits) Error!void {
    if (limits.max_rows > 4096 or limits.max_bytes > access_checkpoint.max_checkpoint_bytes or bytes.len > limits.max_bytes) return error.LimitExceeded;
}
/// Clone through existing typed custody, substitute only exact verified host
/// bytes, then encode with the original expiry/order/issuer/clock fields.
/// Inputs are never mutated. Errors, including identity collisions and every
/// allocation cut, destroy the detached candidate without publishing a prefix.
pub fn auditAccess(allocator: std.mem.Allocator, bytes: []const u8, witnesses: []const Witness, target: Target, limits: Limits) Error!Plan {
    try checkLimits(bytes, limits);
    if (witnesses.len > limits.max_rows) return error.LimitExceeded;
    for (witnesses, 0..) |witness, index| if (index != 0 and witnesses[index - 1].row >= witness.row) return error.InvalidWitnessOrder;
    var candidate = try access_checkpoint.decode(allocator, bytes);
    defer candidate.deinit();
    if (candidate.entries.items.len + candidate.tombstones.items.len > limits.max_rows) return error.LimitExceeded;
    for (witnesses) |witness| if (witness.row >= candidate.entries.items.len) return error.WitnessOutOfRange;
    const reports = try allocator.alloc(Report, candidate.entries.items.len);
    errdefer allocator.free(reports);
    var next: usize = 0;
    for (candidate.entries.items, 0..) |*row, index| {
        const witness: ?Witness = if (next < witnesses.len and witnesses[next].row == index) blk: {
            const current = witnesses[next];
            next += 1;
            break :blk current;
        } else null;
        var replacement: [access.DEFAULT_MAX_MASK_BYTES]u8 = undefined;
        defer std.crypto.secureZero(u8, &replacement);
        const decision = classifyMask(row.mask, witness, target, &replacement);
        reports[index] = .{ .row = index, .classification = decision.classification };
        if (decision.replacement) |mask| {
            const owned = try allocator.dupe(u8, mask);
            allocator.free(row.mask);
            row.mask = owned;
        }
    }
    // Existing codec rejects duplicate replacement identities; never merge
    // rows, overwrite an issuer, or discard a conflicting expiry/order stamp.
    const checkpoint = try access_checkpoint.encode(allocator, &candidate);
    if (checkpoint.len > limits.max_bytes) {
        std.crypto.secureZero(u8, checkpoint);
        allocator.free(checkpoint);
        return error.LimitExceeded;
    }
    return .{ .allocator = allocator, .checkpoint = checkpoint, .reports = reports };
}
/// The current SACCESS schema has no issuer or absolute expiry. Preserve its
/// image byte-for-byte and report that gap, rather than inventing provenance.
pub fn auditSaccess(allocator: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Plan {
    try checkLimits(bytes, limits);
    var candidate = try saccess_checkpoint.decodeOwned(allocator, bytes);
    defer candidate.deinit();
    if (candidate.entries.items.len > limits.max_rows) return error.LimitExceeded;
    const reports = try allocator.alloc(Report, candidate.entries.items.len);
    errdefer allocator.free(reports);
    for (reports, 0..) |*report, index| report.* = .{ .row = index, .classification = .metadata_gap };
    const checkpoint = try allocator.dupe(u8, bytes);
    return .{ .allocator = allocator, .checkpoint = checkpoint, .reports = reports };
}

const testing = std.testing;

test "cloak audit: explicit old formulas verify literal hosts and preserve nick ident scope" {
    var old_key = cloak.SecretKey.init(@splat(0x62));
    defer old_key.wipe();
    var current_key = cloak.SecretKey.init(@splat(0x63));
    defer current_key.wipe();
    const target: Target = .{ .key = &current_key, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
    for ([_]Formula{ .opaque_v2, .opaque_epoch_v2, .opaque_v3, .opaque_epoch_v3, .opaque_epoch_v4 }) |formula| {
        const source: Source = .{
            .formula = formula,
            .key = &old_key,
            .address = "203.0.113.9",
            .suffix = "onyx",
            .epoch = switch (formula) {
                .opaque_epoch_v2, .opaque_epoch_v3, .opaque_epoch_v4 => 7,
                else => null,
            },
            .cadence = if (formula == .opaque_epoch_v4) 86_400 else null,
        };
        var host_storage: [253]u8 = undefined;
        const old = try deriveSource(&host_storage, source);
        var mask_storage: [256]u8 = undefined;
        const mask = try std.fmt.bufPrint(&mask_storage, "N*!User?@{s}", .{old});
        var output: [128]u8 = undefined;
        const result = classifyMask(mask, .{ .row = 0, .expected_mask = mask, .source = source }, target, &output);
        try testing.expectEqual(Classification.verified_replacement, result.classification);
        var expected_storage: [253]u8 = undefined;
        const expected_host = try cloak.cloakOpaqueEpochV4(&expected_storage, &current_key, source.address, target.epoch, target.cadence, .{ .suffix = target.suffix });
        try testing.expectEqualStrings("N*!User?@", result.replacement.?[0..9]);
        try testing.expectEqualStrings(expected_host, result.replacement.?[9..]);
        var current_source = source;
        current_source.formula = .opaque_epoch_v4;
        current_source.key = &current_key;
        current_source.epoch = target.epoch;
        current_source.cadence = target.cadence;
        const unchanged = classifyMask(result.replacement.?, .{ .row = 0, .expected_mask = result.replacement.?, .source = current_source }, target, &mask_storage);
        try testing.expectEqual(Classification.already_current, unchanged.classification);
        try testing.expect(unchanged.replacement == null);
    }
}

test "cloak audit: wrong missing ambiguous unsupported and malformed provenance never changes a mask" {
    const key = cloak.SecretKey.init(@splat(0x64));
    const wrong_key = cloak.SecretKey.init(@splat(0x65));
    const target: Target = .{ .key = &key, .suffix = "onyx", .epoch = 21, .cadence = 1_209_600 };
    var source: Source = .{ .formula = .opaque_epoch_v3, .key = &key, .address = "203.0.113.9", .suffix = "onyx", .epoch = 20 };
    var old_storage: [253]u8 = undefined;
    const old = try deriveSource(&old_storage, source);
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "*!ident@{s}", .{old});
    var output: [128]u8 = undefined;
    const Cases = struct {
        fn unchanged(mask_value: []const u8, witness: ?Witness, destination: Target, expected: Classification, buffer: []u8) !void {
            @memset(buffer, 0xa5);
            const result = classifyMask(mask_value, witness, destination, buffer);
            try testing.expectEqual(expected, result.classification);
            try testing.expect(result.replacement == null);
            try testing.expect(std.mem.allEqual(u8, buffer, 0xa5));
        }
    };
    try Cases.unchanged(mask, null, target, .missing_witness, &output);
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = "different", .source = source }, target, .witness_mismatch, &output);
    var wrong = source;
    wrong.key = &wrong_key;
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = mask, .source = wrong }, target, .derivation_mismatch, &output);
    wrong = source;
    wrong.address = "203.0.113.10";
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = mask, .source = wrong }, target, .derivation_mismatch, &output);
    wrong = source;
    wrong.epoch = 19;
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = mask, .source = wrong }, target, .derivation_mismatch, &output);
    wrong = source;
    wrong.epoch = null;
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = mask, .source = wrong }, target, .invalid_witness, &output);
    wrong = source;
    wrong.formula = .unsupported;
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = mask, .source = wrong }, target, .unsupported_formula, &output);
    wrong = source;
    wrong.address = "not-an-address";
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = mask, .source = wrong }, target, .invalid_witness, &output);
    const glob = "Nick*!ident@*.opq.onyx";
    try Cases.unchanged(glob, .{ .row = 0, .expected_mask = glob, .source = source }, target, .ambiguous_host_glob, &output);
    var invalid_target = target;
    invalid_target.cadence = 0;
    try Cases.unchanged(mask, .{ .row = 0, .expected_mask = mask, .source = source }, invalid_target, .invalid_target, &output);
    // v4 binds cadence: it cannot be changed in the evidence independently of
    // the literal historical token, even with the correct key and address.
    source.formula = .opaque_epoch_v4;
    source.cadence = 86_400;
    const v4 = try deriveSource(&old_storage, source);
    wrong = source;
    wrong.cadence = 1_209_600;
    try Cases.unchanged(v4, .{ .row = 0, .expected_mask = v4, .source = wrong }, target, .derivation_mismatch, &output);
}

fn testSource(key: *const cloak.SecretKey) Source {
    return .{ .formula = .opaque_epoch_v3, .key = key, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7 };
}
fn testTarget(key: *const cloak.SecretKey) Target {
    return .{ .key = key, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
}
fn fillTestStore(store: *access.AccessStore, mask: []const u8) !void {
    store.now_seconds = 100;
    store.local_node = 9;
    try store.add("#First", .deny, mask, "original-issuer", 30);
    try store.add("#Second", .voice, "*!voice@*.opq.onyx", "second-issuer", null);
    try store.add("#Retired", .grant, "*!retired@old.example", "retired-issuer", 17);
    try testing.expect(try store.remove("#Retired", .grant, "*!retired@old.example"));
}

test "cloak audit: ACCESS candidate roundtrips every metadata byte clock tombstone and physical order" {
    const a = testing.allocator;
    const key = cloak.SecretKey.init(@splat(0x66));
    const source = testSource(&key);
    var old_storage: [253]u8 = undefined;
    const old = try deriveSource(&old_storage, source);
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "N*!User?@{s}", .{old});
    var original = access.AccessStore.init(a);
    defer original.deinit();
    try fillTestStore(&original, mask);
    const input = try access_checkpoint.encode(a, &original);
    defer a.free(input);
    const input_copy = try a.dupe(u8, input);
    defer a.free(input_copy);
    var plan = try auditAccess(a, input, &.{.{ .row = 0, .expected_mask = mask, .source = source }}, testTarget(&key), .{});
    defer plan.deinit();
    try testing.expectEqualSlices(u8, input_copy, input);
    try testing.expectEqual(Classification.verified_replacement, plan.reports[0].classification);
    try testing.expectEqual(Classification.ambiguous_host_glob, plan.reports[1].classification);
    var restored = try access_checkpoint.decode(a, plan.checkpoint);
    defer restored.deinit();
    try testing.expect(!std.mem.eql(u8, original.entries.items[0].mask, restored.entries.items[0].mask));
    try testing.expectEqualStrings("N*!User?@", restored.entries.items[0].mask[0..9]);
    try testing.expectEqual(@as(?u64, 130), restored.entries.items[0].expires_at);
    try testing.expectEqual(original.entries.items[0].hlc, restored.entries.items[0].hlc);
    try testing.expectEqual(original.entries.items[0].origin_node, restored.entries.items[0].origin_node);
    try testing.expectEqualStrings("original-issuer", restored.entries.items[0].set_by);
    // Undo only the proposed mask in the detached test copy. Byte-exact codec
    // equality then witnesses ALL other metadata, params and sequence fields.
    const old_mask = try a.dupe(u8, mask);
    a.free(restored.entries.items[0].mask);
    restored.entries.items[0].mask = old_mask;
    const roundtrip = try access_checkpoint.encode(a, &restored);
    defer a.free(roundtrip);
    try testing.expectEqualSlices(u8, input, roundtrip);
    const Summary = struct {
        lines: usize = 0,
        fn emit(self: *@This(), text: []const u8) !void {
            if (std.mem.indexOf(u8, text, "203.0.113") != null or std.mem.indexOf(u8, text, ".opq") != null or std.mem.indexOf(u8, text, "issuer") != null) return error.SecretInDefaultReport;
            self.lines += 1;
        }
    };
    var summary = Summary{};
    try plan.forEachSummary(&summary, Summary.emit);
    try testing.expectEqual(plan.reports.len, summary.lines);
}

fn allocationAudit(a: std.mem.Allocator, bytes: []const u8, mask: []const u8, key: *const cloak.SecretKey) !void {
    var plan = try auditAccess(a, bytes, &.{.{ .row = 0, .expected_mask = mask, .source = testSource(key) }}, testTarget(key), .{});
    defer plan.deinit();
    try testing.expectEqual(Classification.verified_replacement, plan.reports[0].classification);
    try access_checkpoint.validateCheckpoint(plan.checkpoint);
}
test "cloak audit: every allocation cut is input atomic and bounded selectors reject before publication" {
    const a = testing.allocator;
    const key = cloak.SecretKey.init(@splat(0x67));
    var old_storage: [253]u8 = undefined;
    const old = try deriveSource(&old_storage, testSource(&key));
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "*!*@{s}", .{old});
    var source = access.AccessStore.init(a);
    defer source.deinit();
    try fillTestStore(&source, mask);
    const bytes = try access_checkpoint.encode(a, &source);
    defer a.free(bytes);
    const before = try a.dupe(u8, bytes);
    defer a.free(before);
    try testing.checkAllAllocationFailures(a, allocationAudit, .{ bytes, mask, &key });
    try testing.expectEqualSlices(u8, before, bytes);
    const after = try access_checkpoint.encode(a, &source);
    defer a.free(after);
    try testing.expectEqualSlices(u8, before, after);
    const evidence: Witness = .{ .row = 0, .expected_mask = mask, .source = testSource(&key) };
    try testing.expectError(error.InvalidWitnessOrder, auditAccess(a, bytes, &.{ evidence, evidence }, testTarget(&key), .{}));
    var outside = evidence;
    outside.row = 2;
    try testing.expectError(error.WitnessOutOfRange, auditAccess(a, bytes, &.{outside}, testTarget(&key), .{}));
    try testing.expectError(error.LimitExceeded, auditAccess(a, bytes, &.{evidence}, testTarget(&key), .{ .max_rows = 1 }));
    try testing.expectEqualSlices(u8, before, bytes);
}

test "cloak audit: replacement collision refuses the complete candidate without merging rule authority" {
    const a = testing.allocator;
    const key = cloak.SecretKey.init(@splat(0x68));
    var source = access.AccessStore.init(a);
    defer source.deinit();
    var first_storage: [253]u8 = undefined;
    var second_storage: [253]u8 = undefined;
    var first = testSource(&key);
    first.formula = .opaque_v2;
    first.epoch = null;
    var second = first;
    second.formula = .opaque_v3;
    const first_host = try deriveSource(&first_storage, first);
    const second_host = try deriveSource(&second_storage, second);
    var first_mask_storage: [256]u8 = undefined;
    var second_mask_storage: [256]u8 = undefined;
    const one = try std.fmt.bufPrint(&first_mask_storage, "*!*@{s}", .{first_host});
    const two = try std.fmt.bufPrint(&second_mask_storage, "*!*@{s}", .{second_host});
    try source.add("#Room", .grant, one, "issuer-one", 30);
    try source.add("#Room", .grant, two, "issuer-two", 50);
    const bytes = try access_checkpoint.encode(a, &source);
    defer a.free(bytes);
    try testing.expectError(error.DuplicateIdentity, auditAccess(a, bytes, &.{ .{ .row = 0, .expected_mask = one, .source = first }, .{ .row = 1, .expected_mask = two, .source = second } }, testTarget(&key), .{}));
    const after = try access_checkpoint.encode(a, &source);
    defer a.free(after);
    try testing.expectEqualSlices(u8, bytes, after);
}

test "cloak audit: unavailable SACCESS issuer and deadline remain explicitly missing and unchanged" {
    const saccess = @import("../proto/ircx_saccess.zig");
    const a = testing.allocator;
    var source = saccess.ServerAccessStore.init(a);
    defer source.deinit();
    try source.add(.{ .entry_type = .deny, .mask = "*!u@legacy.opq.onyx", .duration = 9, .reason = "original" });
    try source.add(.{ .entry_type = .grant, .mask = "*!v@other.example", .duration = 0, .reason = null });
    const bytes = try saccess_checkpoint.encode(a, &source);
    defer a.free(bytes);
    var plan = try auditSaccess(a, bytes, .{});
    defer plan.deinit();
    try testing.expectEqualSlices(u8, bytes, plan.checkpoint);
    try testing.expectEqual(@as(usize, 2), plan.reports.len);
    for (plan.reports) |report| try testing.expectEqual(Classification.metadata_gap, report.classification);
}
