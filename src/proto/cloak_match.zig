// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free policy matching across opaque cloak rotations. Only literal,
//! canonical provenance labels trigger derivation: attacker-controlled epochs
//! never cause history scans. Normal glob matching retains its existing meaning.
const std = @import("std");
const cloak = @import("cloak.zig");
const hostmask = @import("hostmask.zig");

pub const Context = struct {
    key: cloak.SecretKey,
    previous_key: ?cloak.SecretKey = null,
    suffix: []const u8,
    address: []const u8,
};

pub fn match(pattern: []const u8, visible: []const u8, ctx: ?Context) bool {
    return matchImpl(false, pattern, visible, ctx, null);
}

// The counter is compiled out of production calls; test paths count actual derivations.
fn matchImpl(comptime count_work: bool, pattern: []const u8, visible: []const u8, ctx: ?Context, work: ?*usize) bool {
    if (hostmask.matchGlob(pattern, visible)) return true;
    const context = ctx orelse return false;
    // Bound alternate-policy parsing and prefix reconstruction independently of
    // the caller's validation. A hostmask can carry at most 256 prefix bytes.
    if (pattern.len > 512 or visible.len > 512) return false;
    const pat_host = if (std.mem.lastIndexOfScalar(u8, pattern, '@')) |at| pattern[at + 1 ..] else pattern;
    var labels = std.mem.splitScalar(u8, pat_host, '.');
    const digest = labels.next() orelse return false;
    if (digest.len == 0) return false;
    // Stars consume no required token width. A valid glob can therefore be
    // longer than the 32-byte digest while still describing that exact digest.
    var required_width: usize = 0;
    for (digest) |c| switch (std.ascii.toLower(c)) {
        '*' => {},
        '0'...'9', 'a'...'f', '?' => required_width += 1,
        else => return false,
    };
    if (required_width > cloak.wide_token_hex_len) return false;
    const epoch = parseLabel(labels.next() orelse return false, 'e') orelse return false;
    const cadence = parseLabel(labels.next() orelse return false, 'c') orelse return false;
    if (!std.ascii.eqlIgnoreCase(labels.next() orelse return false, "opq4")) return false;
    var suffix_buf: [cloak.max_hostname_len]u8 = undefined;
    const suffix = cloak.normalizeSuffix(&suffix_buf, context.suffix) catch return false;
    if (!std.ascii.eqlIgnoreCase(labels.rest(), suffix)) return false;
    if (alternate(count_work, pattern, visible, &context.key, context.address, epoch, cadence, suffix, work)) return true;
    if (context.previous_key) |key| return alternate(count_work, pattern, visible, &key, context.address, epoch, cadence, suffix, work);
    return false;
}

fn parseLabel(label: []const u8, marker: u8) ?u64 {
    if (label.len < 2 or label.len > 17 or std.ascii.toLower(label[0]) != marker) return null;
    const digits = label[1..];
    if (digits.len > 1 and digits[0] == '0') return null;
    for (digits) |c| if (!std.ascii.isHex(c)) return null;
    return std.fmt.parseInt(u64, digits, 16) catch null;
}

fn alternate(comptime count_work: bool, pattern: []const u8, visible: []const u8, key: *const cloak.SecretKey, address: []const u8, epoch: u64, cadence: u64, suffix: []const u8, work: ?*usize) bool {
    var buf: [512]u8 = undefined;
    const prefix = if (std.mem.lastIndexOfScalar(u8, visible, '@')) |at| visible[0 .. at + 1] else "";
    if (prefix.len > 256) return false;
    @memcpy(buf[0..prefix.len], prefix);
    if (count_work) work.?.* += 1;
    const derived = cloak.cloakOpaqueEpochV4(buf[prefix.len..], key, address, epoch, cadence, .{ .suffix = suffix }) catch return false;
    return hostmask.matchGlob(pattern, buf[0 .. prefix.len + derived.len]);
}

test "cloak continuity preserves literal and wildcard policy across epochs and cadence" {
    const key = cloak.SecretKey.init(@splat(7));
    const ctx: Context = .{ .key = key, .suffix = "Onyx", .address = "203.0.113.9" };
    var old: [253]u8 = undefined;
    var new: [253]u8 = undefined;
    const before = try cloak.cloakOpaqueEpochV4(&old, &key, ctx.address, 9, 86400, .{});
    const after = try cloak.cloakOpaqueEpochV4(&new, &key, ctx.address, 1000, 1209600, .{});
    try std.testing.expect(match(before, after, ctx));
    try std.testing.expect(!match(before, after, null));
    try std.testing.expect(!match(before, after, .{ .key = key, .suffix = "onyx", .address = "203.0.113.10" }));
    const tail = before[32..];
    var wildcard: [253]u8 = undefined;
    const mask = try std.fmt.bufPrint(&wildcard, "*{s}", .{tail});
    try std.testing.expect(match(mask, after, ctx));
    try std.testing.expect(!match("*.e*.c15180.opq4.onyx", after, ctx));
    try std.testing.expect(!match("*.e09.c15180.opq4.onyx", after, ctx));
    try std.testing.expect(!match("*.e9.cffffffffffffffff.opq4.onyx", after, ctx));
}

test "cloak continuity retains nick and user restrictions and previous key scope" {
    const key = cloak.SecretKey.init(@splat(7));
    const old_key = cloak.SecretKey.init(@splat(8));
    var old: [253]u8 = undefined;
    const before = try cloak.cloakOpaqueEpochV4(&old, &old_key, "2001:db8::1", 1, 1209600, .{});
    var mask_buf: [512]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_buf, "nick!user@{s}", .{before});
    const ctx: Context = .{ .key = key, .previous_key = old_key, .suffix = "onyx", .address = "2001:db8::1" };
    try std.testing.expect(match(mask, "Nick!User@current.onyx", ctx));
    try std.testing.expect(!match(mask, "other!User@current.onyx", ctx));
    var no_previous = ctx;
    no_previous.previous_key = null;
    try std.testing.expect(!match(mask, "Nick!User@current.onyx", no_previous));
}

test "cloak continuity cannot authenticate changed metadata or network with original token" {
    const key = cloak.SecretKey.init(@splat(7));
    var old: [253]u8 = undefined;
    var current: [253]u8 = undefined;
    const before = try cloak.cloakOpaqueEpochV4(&old, &key, "203.0.113.9", 9, 1209600, .{});
    const visible = try cloak.cloakOpaqueEpochV4(&current, &key, "203.0.113.9", 10, 1209600, .{});
    const ctx: Context = .{ .key = key, .suffix = "onyx", .address = "203.0.113.9" };
    const epoch_index = std.mem.indexOf(u8, before, ".e9.").? + 2;
    old[epoch_index] = '8';
    try std.testing.expect(!match(before, visible, ctx));
    old[epoch_index] = '9';
    const cadence_index = std.mem.indexOf(u8, before, ".c127500.").? + 2;
    old[cadence_index] = '2';
    try std.testing.expect(!match(before, visible, ctx));
    old[cadence_index] = '1';
    try std.testing.expect(!match(before, visible, .{ .key = key, .suffix = "other", .address = "203.0.113.9" }));
}

test "cloak continuity preserves bounded digest glob semantics across cadence changes" {
    const key = cloak.SecretKey.init(@splat(7));
    const ctx: Context = .{ .key = key, .suffix = "onyx", .address = "203.0.113.9" };
    var old_buf: [253]u8 = undefined;
    var current_buf: [253]u8 = undefined;
    const old = try cloak.cloakOpaqueEpochV4(&old_buf, &key, ctx.address, 9, 86400, .{});
    const current = try cloak.cloakOpaqueEpochV4(&current_buf, &key, ctx.address, 1000, 1209600, .{});
    var pattern_buf: [512]u8 = undefined;
    const leading_star = try std.fmt.bufPrint(&pattern_buf, "*{s}", .{old});
    try std.testing.expect(match(leading_star, old, null));
    try std.testing.expect(match(leading_star, current, ctx));
    try std.testing.expect(!match(leading_star, current, .{ .key = key, .suffix = "onyx", .address = "203.0.113.10" }));
    const repeated = try std.fmt.bufPrint(&pattern_buf, "***{s}***{s}", .{ old[0..32], old[32..] });
    try std.testing.expect(match(repeated, current, ctx));
    const question = try std.fmt.bufPrint(&pattern_buf, "***{s}?***{s}", .{ old[0..31], old[32..] });
    try std.testing.expect(match(question, current, ctx));
    try std.testing.expect(!match(question, current, .{ .key = key, .suffix = "onyx", .address = "203.0.113.10" }));
    const too_many_required = try std.fmt.bufPrint(&pattern_buf, "***{s}?***{s}", .{ old[0..32], old[32..] });
    try std.testing.expect(!match(too_many_required, current, ctx));
    const too_many_literals = try std.fmt.bufPrint(&pattern_buf, "0{s}", .{old});
    try std.testing.expect(!match(too_many_literals, current, ctx));
    const malformed = try std.fmt.bufPrint(&pattern_buf, "*g{s}", .{old});
    try std.testing.expect(!match(malformed, current, ctx));
    const scoped = try std.fmt.bufPrint(&pattern_buf, "Nick!u?er@***{s}***{s}", .{ old[0..32], old[32..] });
    var visible_buf: [512]u8 = undefined;
    try std.testing.expect(match(scoped, try std.fmt.bufPrint(&visible_buf, "Nick!user@{s}", .{current}), ctx));
    try std.testing.expect(!match(scoped, try std.fmt.bufPrint(&visible_buf, "Other!user@{s}", .{current}), ctx));
    try std.testing.expect(!match(scoped, try std.fmt.bufPrint(&visible_buf, "Nick!root@{s}", .{current}), ctx));
}

test "cloak continuity actual historical derivations stay bounded per rule" {
    const key = cloak.SecretKey.init(@splat(7));
    const old_key = cloak.SecretKey.init(@splat(8));
    const ctx: Context = .{ .key = key, .previous_key = old_key, .suffix = "onyx", .address = "203.0.113.9" };
    var visible_buf: [253]u8 = undefined;
    const visible = try cloak.cloakOpaqueEpochV4(&visible_buf, &key, ctx.address, 9, 1209600, .{});
    var primary_buf: [253]u8 = undefined;
    var previous_buf: [253]u8 = undefined;
    const primary = try cloak.cloakOpaqueEpochV4(&primary_buf, &key, ctx.address, 10, 86400, .{});
    const previous = try cloak.cloakOpaqueEpochV4(&previous_buf, &old_key, ctx.address, 10, 86400, .{});
    var work: usize = 0;
    try std.testing.expect(matchImpl(true, primary, visible, ctx, &work));
    try std.testing.expectEqual(@as(usize, 1), work);
    work = 0;
    try std.testing.expect(matchImpl(true, previous, visible, ctx, &work));
    try std.testing.expectEqual(@as(usize, 2), work);
    var no_previous = ctx;
    no_previous.previous_key = null;
    work = 0;
    try std.testing.expect(!matchImpl(true, previous, visible, no_previous, &work));
    try std.testing.expectEqual(@as(usize, 1), work);
    var invalid_address = ctx;
    invalid_address.address = "invalid.example";
    work = 0;
    try std.testing.expect(!matchImpl(true, primary, visible, invalid_address, &work));
    try std.testing.expectEqual(@as(usize, 2), work);
    work = 0;
    try std.testing.expect(matchImpl(true, visible, visible, ctx, &work));
    try std.testing.expectEqual(@as(usize, 0), work);
    for ([_][]const u8{ "*.e*.c15180.opq4.onyx", "*.e00.c15180.opq4.onyx", "*.e10000000000000000.c15180.opq4.onyx", "*.e1.c15180.opq3.onyx", "*.e1.c15180.opq4.other" }) |bad| {
        work = 0;
        try std.testing.expect(!matchImpl(true, bad, visible, ctx, &work));
        try std.testing.expectEqual(@as(usize, 0), work);
    }
    // Every hostile epoch is independent; choose a digest prefix different from
    // both derived keys so the previous-key path is always exercised.
    work = 0;
    for (0..1024) |i| {
        const epoch = std.math.maxInt(u64) - @as(u64, @intCast(i));
        var a_buf: [253]u8 = undefined;
        var b_buf: [253]u8 = undefined;
        const a = try cloak.cloakOpaqueEpochV4(&a_buf, &key, ctx.address, epoch, 86400, .{});
        const b = try cloak.cloakOpaqueEpochV4(&b_buf, &old_key, ctx.address, epoch, 86400, .{});
        var chosen: u8 = '0';
        while (chosen == a[0] or chosen == b[0]) : (chosen += 1) {}
        var pattern_buf: [253]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "{c}{s}", .{ chosen, a[1..] });
        try std.testing.expect(!matchImpl(true, pattern, visible, ctx, &work));
    }
    try std.testing.expectEqual(@as(usize, 2048), work);
}
