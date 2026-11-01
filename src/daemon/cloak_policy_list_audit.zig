// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detached checkpoint-only AKICK/WARD audit. No live mutation, ADD replay,
//! matcher/expiry sweep, durable write, World reconstruction or mesh authority.
const std = @import("std");
const shared = @import("cloak_migration_audit.zig");
const akick_codec = @import("helix/akick_checkpoint.zig");
const ward_codec = @import("helix/ward_checkpoint.zig");

pub const Limits = shared.Limits;
pub const Witness = shared.Witness;
pub const Target = shared.Target;
pub const Classification = union(enum) {
    mask: shared.Classification,
    account_rule,
    non_host_facet,
    unsupported_mask_shape,
    metadata_gap,

    pub fn name(self: Classification) []const u8 {
        return switch (self) {
            .mask => |value| @tagName(value),
            else => @tagName(self),
        };
    }
};
pub const Report = struct { row: usize, classification: Classification };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    /// Private candidate only. For durable K1 passthrough, these are the exact
    /// unconverted input record bytes, not a newly constructed AKCK checkpoint.
    checkpoint: []u8,
    reports: []Report,
    pub fn deinit(self: *Plan) void {
        std.crypto.secureZero(u8, self.checkpoint);
        self.allocator.free(self.checkpoint);
        self.allocator.free(self.reports);
        self.* = undefined;
    }
    pub fn forEachSummary(self: *const Plan, ctx: anytype, comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void) !void {
        var storage: [96]u8 = undefined;
        for (self.reports) |row| {
            const line = try std.fmt.bufPrint(&storage, "row={d} classification={s}\n", .{ row.row, row.classification.name() });
            try emit(ctx, line);
        }
    }
};
pub const Error = akick_codec.Error || ward_codec.Error || error{ LimitExceeded, InvalidWitnessOrder, WitnessOutOfRange, NotDurableAkickRecord };

fn limitsCheck(bytes: []const u8, limits: Limits) Error!void {
    if (limits.max_rows > 4096 or limits.max_bytes > 8 * 1024 * 1024 or bytes.len > limits.max_bytes) return error.LimitExceeded;
}
fn witnessOrder(witnesses: []const Witness, limits: Limits) Error!void {
    if (witnesses.len > limits.max_rows) return error.LimitExceeded;
    for (witnesses, 0..) |row, i| if (i != 0 and witnesses[i - 1].row >= row.row) return error.InvalidWitnessOrder;
}
fn witnessRange(witnesses: []const Witness, count: usize) Error!void {
    for (witnesses) |row| if (row.row >= count) return error.WitnessOutOfRange;
}
fn nextWitness(witnesses: []const Witness, next: *usize, index: usize) ?Witness {
    if (next.* < witnesses.len and witnesses[next.*].row == index) {
        const row = witnesses[next.*];
        next.* += 1;
        return row;
    }
    return null;
}
fn fullMask(mask: []const u8) bool {
    const bang = std.mem.indexOfScalar(u8, mask, '!') orelse return false;
    const at = std.mem.indexOfScalar(u8, mask, '@') orelse return false;
    return bang != 0 and at > bang + 1 and at + 1 < mask.len and
        std.mem.indexOfScalar(u8, mask[bang + 1 ..], '!') == null and
        std.mem.indexOfScalar(u8, mask[at + 1 ..], '@') == null;
}
fn finish(a: std.mem.Allocator, checkpoint: []u8, reports: []Report, limits: Limits) Error!Plan {
    if (checkpoint.len > limits.max_bytes) {
        std.crypto.secureZero(u8, checkpoint);
        a.free(checkpoint);
        return error.LimitExceeded;
    }
    return .{ .allocator = a, .checkpoint = checkpoint, .reports = reports };
}
fn channelLess(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}

/// Row ordinals: canonical byte-sorted channel keys, then physical entry order.
/// Only hostmask rows with unambiguous full-mask shape can be substituted.
/// The replacement pattern remains a view of the same owned mask allocation.
pub fn auditAkick(a: std.mem.Allocator, bytes: []const u8, witnesses: []const Witness, target: Target, limits: Limits) Error!Plan {
    try limitsCheck(bytes, limits);
    try witnessOrder(witnesses, limits);
    var candidate = try akick_codec.decode(a, bytes);
    defer candidate.deinit();
    const channels = try a.alloc([]const u8, candidate.channels.count());
    defer a.free(channels);
    var channel_it = candidate.channels.iterator();
    var count: usize = 0;
    var row_count: usize = 0;
    while (channel_it.next()) |kv| {
        channels[count] = kv.key_ptr.*;
        count += 1;
        row_count += kv.value_ptr.entries.items.len;
        if (row_count > limits.max_rows) return error.LimitExceeded;
    }
    std.mem.sort([]const u8, channels, {}, channelLess);
    try witnessRange(witnesses, row_count);
    const reports = try a.alloc(Report, row_count);
    errdefer a.free(reports);
    var index: usize = 0;
    var next: usize = 0;
    for (channels) |channel| {
        const list = candidate.channels.getPtr(channel).?;
        for (list.entries.items) |*entry| {
            const witness = nextWitness(witnesses, &next, index);
            var classification: Classification = undefined;
            if (entry.kind == .account) {
                classification = .account_rule;
            } else if (!fullMask(entry.mask)) {
                classification = .unsupported_mask_shape;
            } else {
                var replacement: [512]u8 = undefined;
                defer std.crypto.secureZero(u8, &replacement);
                const decision = shared.classifyMask(entry.mask, witness, target, &replacement);
                classification = .{ .mask = decision.classification };
                if (decision.replacement) |mask| {
                    const owned = try a.dupe(u8, mask);
                    a.free(entry.mask);
                    entry.mask = owned;
                    entry.pattern = owned;
                }
            }
            reports[index] = .{ .row = index, .classification = classification };
            index += 1;
        }
    }
    // Codec refuses replacement identity collisions; it never coalesces rows.
    return finish(a, try akick_codec.encode(a, &candidate), reports, limits);
}

/// Row ordinals are the Registry's physical first-match order. Do not call
/// Registry.add/check/prune: expired rows and overlapping authority stay exact.
pub fn auditWard(a: std.mem.Allocator, bytes: []const u8, witnesses: []const Witness, target: Target, limits: Limits) Error!Plan {
    try limitsCheck(bytes, limits);
    try witnessOrder(witnesses, limits);
    var candidate = try ward_codec.decode(a, bytes);
    defer candidate.deinit();
    if (candidate.wards.items.len > limits.max_rows) return error.LimitExceeded;
    try witnessRange(witnesses, candidate.wards.items.len);
    const reports = try a.alloc(Report, candidate.wards.items.len);
    errdefer a.free(reports);
    var next: usize = 0;
    for (candidate.wards.items, 0..) |*ward, index| {
        const witness = nextWitness(witnesses, &next, index);
        var classification: Classification = undefined;
        if (ward.match != .host and ward.match != .mask) {
            classification = .non_host_facet;
        } else if ((ward.match == .mask and !fullMask(ward.pattern)) or
            (ward.match == .host and std.mem.indexOfAny(u8, ward.pattern, "!@") != null))
        {
            classification = .unsupported_mask_shape;
        } else {
            var replacement: [512]u8 = undefined;
            defer std.crypto.secureZero(u8, &replacement);
            const decision = shared.classifyMask(ward.pattern, witness, target, &replacement);
            classification = .{ .mask = decision.classification };
            if (decision.replacement) |pattern| {
                const owned = try a.dupe(u8, pattern);
                a.free(ward.pattern);
                ward.pattern = owned;
            }
        }
        reports[index] = .{ .row = index, .classification = classification };
    }
    return finish(a, try ward_codec.encode(a, &candidate), reports, limits);
}

/// Diagnostic passthrough for a caller-selected durable K1 record, NOT a
/// validator for the record's fields or an AKCK conversion. K1 has no creation,
/// absolute expiry or first-match ordinal. Its contents remain opaque and exact;
/// metadata_gap asserts no validity, issuer authority or inferred timestamps.
pub fn auditDurableAkickRecord(a: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Plan {
    try limitsCheck(bytes, limits);
    if (!std.mem.startsWith(u8, bytes, "K1|")) return error.NotDurableAkickRecord;
    if (limits.max_rows == 0) return error.LimitExceeded;
    const reports = try a.alloc(Report, 1);
    errdefer a.free(reports);
    reports[0] = .{ .row = 0, .classification = .metadata_gap };
    return .{ .allocator = a, .checkpoint = try a.dupe(u8, bytes), .reports = reports };
}
