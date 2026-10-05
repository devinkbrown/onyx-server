// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical Windows Helix image for the complete live IRCv3 METADATA store.
//! Caller holds the daemon's reactor/World mutation boundary while encoding.
//! Decode creates an independent owner; adoption swaps it only after all
//! fallible validation and allocation have completed.
const std = @import("std");
const metadata_store = @import("../../proto/metadata_store.zig");

const magic = "HXMD";
const version: u16 = 1;
const header_len: usize = 32;
pub const max_target_bytes: usize = 1024;
const target_overhead: usize = 4;
const pair_overhead: usize = 5;
pub const max_snapshot_bytes: usize = header_len + metadata_store.default_max_targets *
    (target_overhead + max_target_bytes + metadata_store.default_max_keys_per_target *
        (pair_overhead + metadata_store.default_max_key + metadata_store.default_max_value));

comptime {
    if (metadata_store.default_max_targets > std.math.maxInt(u16) or
        metadata_store.default_max_keys_per_target > std.math.maxInt(u16) or
        metadata_store.default_max_key > std.math.maxInt(u16) or
        metadata_store.default_max_value > std.math.maxInt(u16) or
        max_target_bytes > std.math.maxInt(u16) or
        metadata_store.default_max_targets * metadata_store.default_max_keys_per_target > std.math.maxInt(u32) or
        max_snapshot_bytes > std.math.maxInt(u32))
        @compileError("Windows METADATA checkpoint exceeds its wire bounds");
}

pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, TooLarge };

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

fn read(bytes: []const u8, pos: *usize, n: usize) error{InvalidSnapshot}![]const u8 {
    if (pos.* > bytes.len or n > bytes.len - pos.*) return error.InvalidSnapshot;
    const result = bytes[pos.*..][0..n];
    pos.* += n;
    return result;
}

fn readU16(bytes: []const u8, pos: *usize) error{InvalidSnapshot}!u16 {
    const pair = try read(bytes, pos, 2);
    return (@as(u16, pair[0]) << 8) | pair[1];
}

fn validValue(value: []const u8) bool {
    return value.len <= metadata_store.default_max_value and std.unicode.utf8ValidateSlice(value);
}

/// Allocation-free, full-image validation used by the whole-handoff relation
/// pass. Strict target/key ordering rejects duplicates and any alternative
/// row order; header policy fields bind the fixed DefaultStore configuration.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    if (bytes.len < header_len or bytes.len > max_snapshot_bytes or !isCheckpoint(bytes) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u16, bytes[6..8], .big) != 0 or
        std.mem.readInt(u16, bytes[10..12], .big) != metadata_store.default_max_targets or
        std.mem.readInt(u16, bytes[12..14], .big) != metadata_store.default_max_keys_per_target or
        std.mem.readInt(u16, bytes[14..16], .big) != metadata_store.default_max_key or
        std.mem.readInt(u16, bytes[16..18], .big) != metadata_store.default_max_value or
        std.mem.readInt(u16, bytes[18..20], .big) != max_target_bytes or
        @as(usize, std.mem.readInt(u32, bytes[24..28], .big)) != bytes.len - header_len or
        std.mem.readInt(u32, bytes[28..32], .big) != 0)
        return error.InvalidSnapshot;
    const target_count: usize = std.mem.readInt(u16, bytes[8..10], .big);
    const row_count: usize = std.mem.readInt(u32, bytes[20..24], .big);
    if (target_count > metadata_store.default_max_targets or
        row_count > target_count * metadata_store.default_max_keys_per_target)
        return error.InvalidSnapshot;
    var pos: usize = header_len;
    var seen_rows: usize = 0;
    var previous_target: ?[]const u8 = null;
    for (0..target_count) |_| {
        const target_len: usize = try readU16(bytes, &pos);
        if (target_len == 0 or target_len > max_target_bytes) return error.InvalidSnapshot;
        const target = try read(bytes, &pos, target_len);
        metadata_store.validateTarget(target) catch return error.InvalidSnapshot;
        if (previous_target) |previous| {
            if (!std.mem.lessThan(u8, previous, target)) return error.InvalidSnapshot;
        }
        previous_target = target;
        const pair_count: usize = try readU16(bytes, &pos);
        if (pair_count > metadata_store.default_max_keys_per_target) return error.InvalidSnapshot;
        seen_rows += pair_count;
        if (seen_rows > row_count) return error.InvalidSnapshot;
        var previous_key: ?[]const u8 = null;
        for (0..pair_count) |_| {
            const visibility_byte = (try read(bytes, &pos, 1))[0];
            _ = std.enums.fromInt(metadata_store.Visibility, visibility_byte) orelse return error.InvalidSnapshot;
            const key_len: usize = try readU16(bytes, &pos);
            if (key_len == 0 or key_len > metadata_store.default_max_key) return error.InvalidSnapshot;
            const key = try read(bytes, &pos, key_len);
            metadata_store.validateKey(key) catch return error.InvalidSnapshot;
            if (previous_key) |previous| {
                if (!std.mem.lessThan(u8, previous, key)) return error.InvalidSnapshot;
            }
            previous_key = key;
            const value_len: usize = try readU16(bytes, &pos);
            if (value_len > metadata_store.default_max_value) return error.InvalidSnapshot;
            const value = try read(bytes, &pos, value_len);
            if (!validValue(value)) return error.InvalidSnapshot;
        }
    }
    if (pos != bytes.len or seen_rows != row_count) return error.InvalidSnapshot;
}

fn addLen(total: *usize, delta: usize) Error!void {
    total.* = std.math.add(usize, total.*, delta) catch return error.TooLarge;
    if (total.* > max_snapshot_bytes) return error.TooLarge;
}

/// The live store contains borrowed map entries. Sort borrowed target names on
/// the stack, sort each target's key views using the owner's public list API,
/// then write only initialized text and visibility tags into an owned image.
pub fn encodeSnapshot(allocator: std.mem.Allocator, store: *const metadata_store.DefaultStore) Error![]u8 {
    var target_buf: [metadata_store.default_max_targets][]const u8 = undefined;
    const targets = store.listTargets(&target_buf) catch return error.InvalidSnapshot;
    if (targets.len != store.countTargets()) return error.InvalidSnapshot;
    var pair_buf: [metadata_store.default_max_keys_per_target]metadata_store.EntryView = undefined;
    var total: usize = header_len;
    var row_count: usize = 0;
    for (targets) |target| {
        if (target.len == 0 or target.len > max_target_bytes) return error.TooLarge;
        metadata_store.validateTarget(target) catch return error.InvalidSnapshot;
        const pairs = store.list(target, &pair_buf) catch return error.InvalidSnapshot;
        if (pairs.len != (store.countKeys(target) catch return error.InvalidSnapshot)) return error.InvalidSnapshot;
        try addLen(&total, target_overhead + target.len);
        row_count += pairs.len;
        for (pairs) |pair| {
            metadata_store.validateKey(pair.key) catch return error.InvalidSnapshot;
            if (!validValue(pair.value)) return error.InvalidSnapshot;
            try addLen(&total, pair_overhead + pair.key.len + pair.value.len);
        }
    }
    const bytes = try allocator.alloc(u8, total);
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u16, bytes[4..6], version, .big);
    std.mem.writeInt(u16, bytes[6..8], 0, .big);
    std.mem.writeInt(u16, bytes[8..10], @intCast(targets.len), .big);
    std.mem.writeInt(u16, bytes[10..12], @intCast(metadata_store.default_max_targets), .big);
    std.mem.writeInt(u16, bytes[12..14], @intCast(metadata_store.default_max_keys_per_target), .big);
    std.mem.writeInt(u16, bytes[14..16], @intCast(metadata_store.default_max_key), .big);
    std.mem.writeInt(u16, bytes[16..18], @intCast(metadata_store.default_max_value), .big);
    std.mem.writeInt(u16, bytes[18..20], @intCast(max_target_bytes), .big);
    std.mem.writeInt(u32, bytes[20..24], @intCast(row_count), .big);
    std.mem.writeInt(u32, bytes[24..28], @intCast(total - header_len), .big);
    std.mem.writeInt(u32, bytes[28..32], 0, .big);
    var pos: usize = header_len;
    for (targets) |target| {
        std.mem.writeInt(u16, bytes[pos..][0..2], @intCast(target.len), .big);
        pos += 2;
        @memcpy(bytes[pos..][0..target.len], target);
        pos += target.len;
        const pairs = store.list(target, &pair_buf) catch unreachable;
        std.mem.writeInt(u16, bytes[pos..][0..2], @intCast(pairs.len), .big);
        pos += 2;
        for (pairs) |pair| {
            bytes[pos] = @intCast(@intFromEnum(pair.visibility));
            pos += 1;
            std.mem.writeInt(u16, bytes[pos..][0..2], @intCast(pair.key.len), .big);
            pos += 2;
            @memcpy(bytes[pos..][0..pair.key.len], pair.key);
            pos += pair.key.len;
            std.mem.writeInt(u16, bytes[pos..][0..2], @intCast(pair.value.len), .big);
            pos += 2;
            @memcpy(bytes[pos..][0..pair.value.len], pair.value);
            pos += pair.value.len;
        }
    }
    std.debug.assert(pos == total);
    return bytes;
}

/// Allocate a wholly independent store. Every target, key, and value is copied
/// before return; a failed decode destroys its partial replacement and leaves
/// the candidate's existing live store untouched.
pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!metadata_store.DefaultStore {
    try validateCheckpoint(bytes);
    var result = metadata_store.DefaultStore.init(allocator);
    errdefer result.deinit();
    var pos: usize = header_len;
    const target_count: usize = std.mem.readInt(u16, bytes[8..10], .big);
    for (0..target_count) |_| {
        const target_len: usize = try readU16(bytes, &pos);
        const target = try read(bytes, &pos, target_len);
        result.ensureTargetForSnapshot(target) catch return error.OutOfMemory;
        const pair_count: usize = try readU16(bytes, &pos);
        for (0..pair_count) |_| {
            const visibility = std.enums.fromInt(metadata_store.Visibility, (try read(bytes, &pos, 1))[0]).?;
            const key_len: usize = try readU16(bytes, &pos);
            const key = try read(bytes, &pos, key_len);
            const value_len: usize = try readU16(bytes, &pos);
            const value = try read(bytes, &pos, value_len);
            _ = result.setWithVisibility(target, key, value, visibility) catch return error.OutOfMemory;
        }
    }
    std.debug.assert(pos == bytes.len);
    return result;
}

test "Windows Helix metadata checkpoint is canonical and independently owned" {
    const allocator = std.testing.allocator;
    var source = metadata_store.DefaultStore.init(allocator);
    defer source.deinit();
    try source.ensureTargetForSnapshot("empty");
    _ = try source.setWithVisibility("bob", "zeta", "last", .secret);
    _ = try source.setWithVisibility("alice", "color", "blå", .members);
    _ = try source.setWithVisibility("bob", "alpha", "first", .public);
    const wire = try encodeSnapshot(allocator, &source);
    defer allocator.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    const expected = try allocator.dupe(u8, wire);
    defer allocator.free(expected);
    var owned = try decodeOwned(allocator, wire);
    defer owned.deinit();
    @memset(wire, 0);
    try std.testing.expectEqual(@as(usize, 3), owned.countTargets());
    try std.testing.expectEqual(@as(usize, 0), try owned.countKeys("empty"));
    try std.testing.expectEqualStrings("blå", (try owned.get("alice", "color")).value);
    try std.testing.expectEqual(metadata_store.Visibility.secret, (try owned.get("bob", "zeta")).visibility);
    const again = try encodeSnapshot(allocator, &owned);
    defer allocator.free(again);
    try std.testing.expectEqualSlices(u8, expected, again);

    var reordered = metadata_store.DefaultStore.init(allocator);
    defer reordered.deinit();
    _ = try reordered.setWithVisibility("bob", "alpha", "first", .public);
    try reordered.ensureTargetForSnapshot("empty");
    _ = try reordered.setWithVisibility("bob", "zeta", "last", .secret);
    _ = try reordered.setWithVisibility("alice", "color", "blå", .members);
    const reordered_wire = try encodeSnapshot(allocator, &reordered);
    defer allocator.free(reordered_wire);
    try std.testing.expectEqualSlices(u8, expected, reordered_wire);
}

test "Windows Helix metadata checkpoint rejects malformed policy order and text without allocation" {
    const allocator = std.testing.allocator;
    var source = metadata_store.DefaultStore.init(allocator);
    defer source.deinit();
    try source.ensureTargetForSnapshot("alice");
    try source.ensureTargetForSnapshot("bravo");
    const wire = try encodeSnapshot(allocator, &source);
    defer allocator.free(wire);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire[0 .. wire.len - 1]));
    var damaged = try allocator.dupe(u8, wire);
    defer allocator.free(damaged);
    damaged[14] ^= 1; // encoded key policy
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(damaged));
    damaged[14] ^= 1;
    const second_target = header_len + (2 + "alice".len + 2);
    @memcpy(damaged[second_target + 2 ..][0..5], "alice");
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(damaged));
    @memcpy(damaged[second_target + 2 ..][0..5], "bravo");
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSnapshot, decodeOwned(failing.allocator(), damaged[0 .. damaged.len - 1]));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);

    var with_value = metadata_store.DefaultStore.init(allocator);
    defer with_value.deinit();
    _ = try with_value.set("a", "key", "x");
    const value_wire = try encodeSnapshot(allocator, &with_value);
    defer allocator.free(value_wire);
    var invalid_text = try allocator.dupe(u8, value_wire);
    defer allocator.free(invalid_text);
    const value_pos = header_len + 2 + 1 + 2 + 1 + 2 + 3 + 2;
    invalid_text[value_pos] = 0xff;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(invalid_text));
    invalid_text[value_pos] = 'x';
    const visibility_pos = header_len + 2 + 1 + 2;
    invalid_text[visibility_pos] = 99;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(invalid_text));
}

fn decodeAllocationCampaign(allocator: std.mem.Allocator, wire: []const u8) !void {
    var decoded = try decodeOwned(allocator, wire);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), decoded.countTargets());
    try std.testing.expectEqualStrings("value", (try decoded.get("alice", "key")).value);
    try std.testing.expectEqual(@as(usize, 0), try decoded.countKeys("empty"));
}

test "Windows Helix metadata checkpoint decode sweeps allocation failures" {
    const allocator = std.testing.allocator;
    var source = metadata_store.DefaultStore.init(allocator);
    defer source.deinit();
    _ = try source.set("alice", "key", "value");
    try source.ensureTargetForSnapshot("empty");
    const wire = try encodeSnapshot(allocator, &source);
    defer allocator.free(wire);
    try std.testing.checkAllAllocationFailures(allocator, decodeAllocationCampaign, .{wire});
}

test "Windows Helix metadata checkpoint refuses an unbounded source target" {
    const allocator = std.testing.allocator;
    var source = metadata_store.DefaultStore.init(allocator);
    defer source.deinit();
    const oversized = try allocator.alloc(u8, max_target_bytes + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'a');
    try source.ensureTargetForSnapshot(oversized);
    try std.testing.expectError(error.TooLarge, encodeSnapshot(allocator, &source));
}
