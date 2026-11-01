// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detached raw Services record audit. Never opens a Store, applies a record,
//! invents missing timestamps/order, or converts one format into a checkpoint.
const std = @import("std");
const shared = @import("cloak_migration_audit.zig");
const warden = @import("warden.zig");
const saccess = @import("../proto/ircx_saccess.zig");

pub const Kind = enum { akick_record, ward_record, saccess_record };
pub const Limits = shared.Limits;
pub const Witness = shared.Witness;
pub const Target = shared.Target;
pub const Classification = union(enum) {
    mask: shared.Classification,
    metadata_gap,
    non_host_facet,
    unsupported_mask_shape,
    pub fn name(self: Classification) []const u8 {
        return switch (self) {
            .mask => |value| @tagName(value),
            else => @tagName(self),
        };
    }
};
pub const KeyEffect = enum { unchanged, rekey_required };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    record: []u8,
    classification: Classification,
    key_effect: KeyEffect,
    requires_collection_order_proof: bool,
    pub fn deinit(self: *Plan) void {
        std.crypto.secureZero(u8, self.record);
        self.allocator.free(self.record);
        self.* = undefined;
    }
    pub fn forEachSummary(self: *const Plan, ctx: anytype, comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void) !void {
        var buf: [160]u8 = undefined;
        try emit(ctx, try std.fmt.bufPrint(&buf, "row=0 classification={s} key_migration={s} order_proof={s}\n", .{ self.classification.name(), if (self.key_effect == .rekey_required) "required" else "none", if (self.requires_collection_order_proof) "missing" else "not_needed" }));
    }
};
const Parsed = struct {
    fields: [9][]const u8 = undefined,
    count: usize = 0,
    fn parse(input: []const u8) !Parsed {
        var result: Parsed = .{};
        var iter = std.mem.splitScalar(u8, input, '|');
        while (iter.next()) |field| {
            if (result.count == result.fields.len) return error.InvalidRecord;
            result.fields[result.count] = field;
            result.count += 1;
        }
        return result;
    }
};
fn printable(value: []const u8, max: usize, allow_empty: bool) bool {
    if ((!allow_empty and value.len == 0) or value.len > max) return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f or byte == '|') return false;
    return true;
}
fn validChannel(value: []const u8) bool {
    if (value.len < 2 or value.len > 64 or value[0] != '#') return false;
    for (value) |byte| if (byte <= 0x20 or byte == 0x7f or byte == '|' or byte == ',' or byte == ':') return false;
    return true;
}
fn validAccount(value: []const u8) bool {
    if (value.len == 0 or value.len > 32) return false;
    for (value) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return false;
    return true;
}
fn fullMask(mask: []const u8) bool {
    const bang = std.mem.indexOfScalar(u8, mask, '!') orelse return false;
    const at = std.mem.indexOfScalar(u8, mask, '@') orelse return false;
    return bang != 0 and at > bang + 1 and at + 1 < mask.len and
        std.mem.indexOfScalar(u8, mask[bang + 1 ..], '!') == null and
        std.mem.indexOfScalar(u8, mask[at + 1 ..], '@') == null;
}
fn validate(kind: Kind, input: []const u8) !Parsed {
    const p = try Parsed.parse(input);
    const f = &p.fields;
    switch (kind) {
        .akick_record => {
            if (p.count < 5 or p.count > 6 or !std.mem.eql(u8, f[0], "K1")) return error.InvalidRecord;
            if (!validChannel(f[1]) or !printable(f[2], 160, false) or f[3].len != 32 or !validAccount(f[4])) return error.InvalidRecord;
            for (f[3]) |c| if (!std.ascii.isHex(c)) return error.InvalidRecord;
            if (p.count == 6 and !printable(f[5], 128, true)) return error.InvalidRecord;
        },
        .ward_record => {
            if (p.count < 7 or p.count > 9 or !std.mem.eql(u8, f[0], "W1")) return error.InvalidRecord;
            if (!printable(f[1], 16, false) or !printable(f[2], 256, false) or !printable(f[3], 16, false) or !printable(f[4], 16, false)) return error.InvalidRecord;
            _ = warden.Match.parse(f[1]) orelse return error.UnsupportedRecord;
            _ = warden.Scope.parse(f[3]) orelse return error.UnsupportedRecord;
            _ = warden.Action.parse(f[4]) orelse return error.UnsupportedRecord;
            _ = std.fmt.parseInt(i64, f[5], 10) catch return error.InvalidRecord;
            _ = std.fmt.parseInt(i64, f[6], 10) catch return error.InvalidRecord;
            if (p.count >= 8 and !printable(f[7], 64, true)) return error.InvalidRecord;
            if (p.count >= 9 and !printable(f[8], 512, true)) return error.InvalidRecord;
        },
        .saccess_record => {
            if (p.count < 4 or p.count > 5 or !std.mem.eql(u8, f[0], "S1")) return error.InvalidRecord;
            if (!printable(f[1], 16, false) or !printable(f[2], 256, false)) return error.InvalidRecord;
            _ = saccess.EntryType.parse(f[1]) orelse return error.UnsupportedRecord;
            _ = std.fmt.parseInt(u64, f[3], 10) catch return error.InvalidRecord;
            if (p.count == 5 and !printable(f[4], 512, true)) return error.InvalidRecord;
        },
    }
    return p;
}
/// One record per call. Caller must preserve source collection order and, for
/// a changed W1 value, independently handle its mask-derived durable Store key
/// and prove first-match collection precedence.
/// The returned value is detached diagnostic output and authorizes no write.
pub fn audit(a: std.mem.Allocator, kind: Kind, input: []const u8, witness: ?Witness, target: ?Target, limits: Limits) !Plan {
    if (limits.max_rows == 0 or limits.max_rows > 4096 or limits.max_bytes > 8 * 1024 * 1024 or input.len > limits.max_bytes or input.len > 2048) return error.LimitExceeded;
    if (witness) |w| if (w.row != 0) return error.WitnessOutOfRange;
    if (kind == .ward_record and target == null) return error.MissingTarget;
    const fields = try validate(kind, input);
    var classification: Classification = .metadata_gap;
    var replacement: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &replacement);
    var substitute: ?[]const u8 = null;
    if (kind == .ward_record) {
        const facet = warden.Match.parse(fields.fields[1]).?;
        const mask = fields.fields[2];
        if (facet != .host and facet != .mask) classification = .non_host_facet else if ((facet == .mask and !fullMask(mask)) or (facet == .host and std.mem.indexOfAny(u8, mask, "!@") != null) or mask[0] == '$') classification = .unsupported_mask_shape else {
            const decision = shared.classifyMask(mask, witness, target.?, &replacement);
            classification = .{ .mask = decision.classification };
            if (decision.replacement) |value| {
                if (!printable(value, 256, false)) return error.LimitExceeded;
                substitute = value;
            }
        }
    }
    const output = if (substitute) |value| blk: {
        const old = fields.fields[2];
        const start = @intFromPtr(old.ptr) - @intFromPtr(input.ptr);
        const size = std.math.add(usize, input.len - old.len, value.len) catch return error.LimitExceeded;
        if (size > limits.max_bytes or size > 2048) return error.LimitExceeded;
        const result = try a.alloc(u8, size);
        @memcpy(result[0..start], input[0..start]);
        @memcpy(result[start..][0..value.len], value);
        @memcpy(result[start + value.len ..], input[start + old.len ..]);
        break :blk result;
    } else try a.dupe(u8, input);
    return .{ .allocator = a, .record = output, .classification = classification, .key_effect = if (substitute != null) .rekey_required else .unchanged, .requires_collection_order_proof = substitute != null };
}
