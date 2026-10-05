// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for IRCX ACCESS policy and replay state. Entry and
//! tombstone array positions are preserved because later mutation is ordered.

const std = @import("std");
const access = @import("../../proto/ircx_access_store.zig");

pub const max_entries: usize = 4096;
pub const max_tombstones: usize = 4096;
pub const max_checkpoint_bytes: usize = 8 * 1024 * 1024;
pub const checkpoint_magic = [_]u8{ 'A', 'C', 'C', 'S' };
pub const checkpoint_version: u8 = 1;
const header_len: usize = 4 + 1 + 3 + 4 + 2 + 2 + 2 + 2 + 8 + 8 + 8 + 8;
const checksum_len: usize = 32;
const entry_min_len: usize = 6 + 1 + 1 + 1 + 8 + 8;
const tombstone_min_len: usize = 3 + 1 + 1 + 8 + 8 + 8;
const checksum_domain = "onyx-access-checkpoint-v1";
const max_identities = max_entries + max_tombstones;
const identity_table_len = max_identities * 2;

comptime {
    if (max_entries > std.math.maxInt(u16) or max_tombstones > std.math.maxInt(u16) or
        max_checkpoint_bytes > std.math.maxInt(u32) or
        identity_table_len & (identity_table_len - 1) != 0)
        @compileError("ACCESS checkpoint exceeds its wire/index bounds");
}

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    DuplicateIdentity,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

const Header = struct {
    entry_count: usize,
    tombstone_count: usize,
    max_entries_value: usize,
    max_tombstones_value: usize,
    tombstone_ttl_seconds: u64,
    now_seconds: u64,
    local_node: u64,
    hlc: u64,
};

const Identity = struct {
    channel: []const u8,
    level: access.Level,
    mask: []const u8,
};

const ParsedEntry = struct {
    channel: []const u8,
    level: access.Level,
    mask: []const u8,
    set_by: []const u8,
    duration: ?u64,
    expires_at: ?u64,
    hlc: u64,
    origin_node: u64,
};

const ParsedTombstone = struct {
    channel: []const u8,
    level: access.Level,
    mask: []const u8,
    hlc: u64,
    origin_node: u64,
    recorded_at: u64,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Validate framing, producer bounds, nullable fields, and unique identities
/// without allocation. An on-stack open-addressed index keeps work linear.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const header = try parseHeader(bytes);
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    var identities: [max_identities]Identity = undefined;
    var table: [identity_table_len]u16 = undefined;
    @memset(&table, 0);
    var seen: usize = 0;
    for (0..header.entry_count) |_| {
        const entry = try readEntry(&reader, header.hlc);
        try insertIdentity(&table, &identities, &seen, .{ .channel = entry.channel, .level = entry.level, .mask = entry.mask });
    }
    for (0..header.tombstone_count) |_| {
        const marker = try readTombstone(&reader, header.hlc);
        try insertIdentity(&table, &identities, &seen, .{ .channel = marker.channel, .level = marker.level, .mask = marker.mask });
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Export the complete physical order and exact clocks. Source state that
/// cannot fit the bounded format fails instead of being truncated.
pub fn encode(allocator: std.mem.Allocator, store: *const access.AccessStore) Error![]u8 {
    const entry_count = store.entries.items.len;
    const tombstone_count = store.tombstones.items.len;
    if (store.max_entries > max_entries or store.max_tombstones > max_tombstones or
        entry_count > store.max_entries or tombstone_count > store.max_tombstones)
        return error.CheckpointTooLarge;
    var total_len: usize = header_len + checksum_len;
    for (store.entries.items) |entry| {
        access.validateCheckpointIdentity(entry.channel, entry.mask) catch return error.InvalidField;
        access.validateCheckpointSetBy(entry.set_by) catch return error.InvalidField;
        if (!validExpiry(entry.duration, entry.expires_at) or entry.hlc > store.hlc) return error.InvalidField;
        try addLen(&total_len, 6 + entry.channel.len + entry.mask.len + entry.set_by.len + 16 +
            (if (entry.duration != null) @as(usize, 8) else 0) +
            (if (entry.expires_at != null) @as(usize, 8) else 0));
    }
    for (store.tombstones.items) |marker| {
        access.validateCheckpointIdentity(marker.channel, marker.mask) catch return error.InvalidField;
        if (marker.hlc > store.hlc) return error.InvalidField;
        try addLen(&total_len, 3 + marker.channel.len + marker.mask.len + 24);
    }

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(checkpoint_version);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(total_len - header_len - checksum_len));
    writer.writeU16(@intCast(entry_count));
    writer.writeU16(@intCast(tombstone_count));
    writer.writeU16(@intCast(store.max_entries));
    writer.writeU16(@intCast(store.max_tombstones));
    writer.writeU64(store.tombstone_ttl_seconds);
    writer.writeU64(store.now_seconds);
    writer.writeU64(store.local_node);
    writer.writeU64(store.hlc);
    for (store.entries.items) |entry| {
        writer.writeByte(@intCast(entry.channel.len));
        writer.writeByte(@intCast(entry.mask.len));
        writer.writeByte(@intCast(entry.set_by.len));
        writer.writeByte(@intFromEnum(entry.level));
        writer.writeByte(@intFromBool(entry.duration != null));
        writer.writeByte(@intFromBool(entry.expires_at != null));
        writer.writeBytes(entry.channel);
        writer.writeBytes(entry.mask);
        writer.writeBytes(entry.set_by);
        if (entry.duration) |value| writer.writeU64(value);
        if (entry.expires_at) |value| writer.writeU64(value);
        writer.writeU64(entry.hlc);
        writer.writeU64(entry.origin_node);
    }
    for (store.tombstones.items) |marker| {
        writer.writeByte(@intCast(marker.channel.len));
        writer.writeByte(@intCast(marker.mask.len));
        writer.writeByte(@intFromEnum(marker.level));
        writer.writeBytes(marker.channel);
        writer.writeBytes(marker.mask);
        writer.writeU64(marker.hlc);
        writer.writeU64(marker.origin_node);
        writer.writeU64(marker.recorded_at);
    }
    std.debug.assert(writer.pos + checksum_len == out.len);
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(out[0..writer.pos], &digest);
    writer.writeBytes(&digest);
    try validateCheckpoint(out);
    return out;
}

/// Construct a detached owner before COMMIT. The caller swaps the whole store
/// and then deinitializes the old one; no writes are replayed during restore.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!access.AccessStore {
    try validateCheckpoint(bytes);
    const header = try parseHeader(bytes);
    var restored = access.AccessStore.init(allocator);
    errdefer restored.deinit();
    restored.max_entries = header.max_entries_value;
    restored.max_tombstones = header.max_tombstones_value;
    restored.tombstone_ttl_seconds = header.tombstone_ttl_seconds;
    restored.now_seconds = header.now_seconds;
    restored.local_node = header.local_node;
    restored.hlc = header.hlc;
    try restored.entries.ensureTotalCapacityPrecise(allocator, header.entry_count);
    try restored.tombstones.ensureTotalCapacityPrecise(allocator, header.tombstone_count);
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (0..header.entry_count) |_| {
        const entry = try readEntry(&reader, header.hlc);
        const channel = try allocator.dupe(u8, entry.channel);
        errdefer allocator.free(channel);
        const mask = try allocator.dupe(u8, entry.mask);
        errdefer allocator.free(mask);
        const set_by = try allocator.dupe(u8, entry.set_by);
        errdefer allocator.free(set_by);
        restored.entries.appendAssumeCapacity(access.CheckpointEntry{
            .channel = channel,
            .level = entry.level,
            .mask = mask,
            .set_by = set_by,
            .duration = entry.duration,
            .expires_at = entry.expires_at,
            .hlc = entry.hlc,
            .origin_node = entry.origin_node,
        });
    }
    for (0..header.tombstone_count) |_| {
        const marker = try readTombstone(&reader, header.hlc);
        const channel = try allocator.dupe(u8, marker.channel);
        errdefer allocator.free(channel);
        const mask = try allocator.dupe(u8, marker.mask);
        errdefer allocator.free(mask);
        restored.tombstones.appendAssumeCapacity(access.CheckpointTombstone{
            .channel = channel,
            .level = marker.level,
            .mask = mask,
            .hlc = marker.hlc,
            .origin_node = marker.origin_node,
            .recorded_at = marker.recorded_at,
        });
    }
    std.debug.assert(reader.remaining() == 0);
    return restored;
}

fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    if (body_len > max_checkpoint_bytes - header_len - checksum_len) return error.CheckpointTooLarge;
    const expected_len = header_len + body_len + checksum_len;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    const header = Header{
        .entry_count = std.mem.readInt(u16, bytes[12..14], .little),
        .tombstone_count = std.mem.readInt(u16, bytes[14..16], .little),
        .max_entries_value = std.mem.readInt(u16, bytes[16..18], .little),
        .max_tombstones_value = std.mem.readInt(u16, bytes[18..20], .little),
        .tombstone_ttl_seconds = std.mem.readInt(u64, bytes[20..28], .little),
        .now_seconds = std.mem.readInt(u64, bytes[28..36], .little),
        .local_node = std.mem.readInt(u64, bytes[36..44], .little),
        .hlc = std.mem.readInt(u64, bytes[44..52], .little),
    };
    if (header.max_entries_value > max_entries or header.max_tombstones_value > max_tombstones or
        header.entry_count > header.max_entries_value or header.tombstone_count > header.max_tombstones_value)
        return error.CheckpointTooLarge;
    if (body_len < header.entry_count * entry_min_len + header.tombstone_count * tombstone_min_len)
        return error.Truncated;
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    const saved: [checksum_len]u8 = bytes[bytes.len - checksum_len ..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, saved)) return error.ChecksumMismatch;
    return header;
}

fn readEntry(reader: *Reader, store_hlc: u64) Error!ParsedEntry {
    const channel_len: usize = try reader.readByte();
    const mask_len: usize = try reader.readByte();
    const set_by_len: usize = try reader.readByte();
    const level = std.enums.fromInt(access.Level, try reader.readByte()) orelse return error.InvalidField;
    const duration_tag = try reader.readByte();
    const expiry_tag = try reader.readByte();
    if (duration_tag > 1 or expiry_tag > 1) return error.InvalidField;
    const channel = try reader.take(channel_len);
    const mask = try reader.take(mask_len);
    const set_by = try reader.take(set_by_len);
    access.validateCheckpointIdentity(channel, mask) catch return error.InvalidField;
    access.validateCheckpointSetBy(set_by) catch return error.InvalidField;
    const duration: ?u64 = if (duration_tag == 1) try reader.readU64() else null;
    const expires_at: ?u64 = if (expiry_tag == 1) try reader.readU64() else null;
    if (!validExpiry(duration, expires_at)) return error.InvalidField;
    const hlc = try reader.readU64();
    const origin_node = try reader.readU64();
    if (hlc > store_hlc) return error.InvalidField;
    return .{ .channel = channel, .level = level, .mask = mask, .set_by = set_by, .duration = duration, .expires_at = expires_at, .hlc = hlc, .origin_node = origin_node };
}

fn readTombstone(reader: *Reader, store_hlc: u64) Error!ParsedTombstone {
    const channel_len: usize = try reader.readByte();
    const mask_len: usize = try reader.readByte();
    const level = std.enums.fromInt(access.Level, try reader.readByte()) orelse return error.InvalidField;
    const channel = try reader.take(channel_len);
    const mask = try reader.take(mask_len);
    access.validateCheckpointIdentity(channel, mask) catch return error.InvalidField;
    const hlc = try reader.readU64();
    const origin_node = try reader.readU64();
    const recorded_at = try reader.readU64();
    if (hlc > store_hlc) return error.InvalidField;
    return .{ .channel = channel, .level = level, .mask = mask, .hlc = hlc, .origin_node = origin_node, .recorded_at = recorded_at };
}

fn validExpiry(duration: ?u64, expires_at: ?u64) bool {
    return (duration != null and duration.? != 0) == (expires_at != null);
}

fn insertIdentity(table: *[identity_table_len]u16, seen: *[max_identities]Identity, count: *usize, identity: Identity) Error!void {
    var slot = identityHash(identity) & (identity_table_len - 1);
    while (table[slot] != 0) : (slot = (slot + 1) & (identity_table_len - 1)) {
        const previous = seen[table[slot] - 1];
        if (previous.level == identity.level and
            std.ascii.eqlIgnoreCase(previous.channel, identity.channel) and
            std.ascii.eqlIgnoreCase(previous.mask, identity.mask))
            return error.DuplicateIdentity;
    }
    seen[count.*] = identity;
    table[slot] = @intCast(count.* + 1);
    count.* += 1;
}

fn identityHash(identity: Identity) usize {
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (identity.channel) |byte| hash = (hash ^ std.ascii.toLower(byte)) *% 0x100_0000_01b3;
    hash = (hash ^ 0xff) *% 0x100_0000_01b3;
    hash = (hash ^ @as(u64, @intFromEnum(identity.level))) *% 0x100_0000_01b3;
    hash = (hash ^ 0xff) *% 0x100_0000_01b3;
    for (identity.mask) |byte| hash = (hash ^ std.ascii.toLower(byte)) *% 0x100_0000_01b3;
    return @intCast(hash);
}

fn addLen(total: *usize, amount: usize) Error!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

fn checkpointChecksum(bytes: []const u8, out: *[checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checksum_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,
    fn writeBytes(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }
    fn writeByte(self: *Writer, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }
    fn writeU16(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .little);
        self.pos += 2;
    }
    fn writeU32(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }
    fn writeU64(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    fn remaining(self: *const Reader) usize {
        return self.bytes.len - self.pos;
    }
    fn take(self: *Reader, len: usize) Error![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const value = self.bytes[self.pos..][0..len];
        self.pos += len;
        return value;
    }
    fn readByte(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
};

test "ACCESS checkpoint preserves ordered entries tombstones owners and clocks" {
    const alloc = std.testing.allocator;
    var source = access.AccessStore.initWith(alloc, 300);
    defer source.deinit();
    source.max_tombstones = 300;
    source.tombstone_ttl_seconds = 123_456;
    source.now_seconds = 100;
    source.local_node = 7;
    try source.add("#Alpha", .voice, "a!u@h", "owner-a", null);
    try source.add("#Zero", .host, "z!u@h", "owner-z", 0);
    try source.add("#Timed", .deny, "t!u@h", "owner-t", 30);
    try std.testing.expect(try source.remove("#Alpha", .voice, "a!u@h"));
    try std.testing.expect(!(try source.remove("#Missing", .grant, "m!u@h")));
    try std.testing.expectEqual(access.ApplyOutcome.applied, try source.applyRemote(.{
        .present = true,
        .channel = "#Remote",
        .level = .grant,
        .mask = "r!u@h",
        .set_by = "peer-owner",
        .duration = 5,
        .hlc = 200_000,
        .origin_node = 9,
    }));
    source.now_seconds = 101;
    source.hlc += 17; // A failed local write can advance the high-water clock.
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    try validateCheckpoint(wire);
    var restored = try decode(alloc, wire);
    defer restored.deinit();
    try std.testing.expectEqual(source.max_entries, restored.max_entries);
    try std.testing.expectEqual(source.max_tombstones, restored.max_tombstones);
    try std.testing.expectEqual(source.tombstone_ttl_seconds, restored.tombstone_ttl_seconds);
    try std.testing.expectEqual(source.now_seconds, restored.now_seconds);
    try std.testing.expectEqual(source.local_node, restored.local_node);
    try std.testing.expectEqual(source.hlc, restored.hlc);
    try std.testing.expectEqual(source.entries.items.len, restored.entries.items.len);
    try std.testing.expectEqual(source.tombstones.items.len, restored.tombstones.items.len);
    for (source.entries.items, restored.entries.items) |a, b| {
        try std.testing.expectEqualStrings(a.channel, b.channel);
        try std.testing.expectEqual(a.level, b.level);
        try std.testing.expectEqualStrings(a.mask, b.mask);
        try std.testing.expectEqualStrings(a.set_by, b.set_by);
        try std.testing.expectEqual(a.duration, b.duration);
        try std.testing.expectEqual(a.expires_at, b.expires_at);
        try std.testing.expectEqual(a.hlc, b.hlc);
        try std.testing.expectEqual(a.origin_node, b.origin_node);
        try std.testing.expect(@intFromPtr(a.channel.ptr) != @intFromPtr(b.channel.ptr));
    }
    for (source.tombstones.items, restored.tombstones.items) |a, b| {
        try std.testing.expectEqualStrings(a.channel, b.channel);
        try std.testing.expectEqual(a.level, b.level);
        try std.testing.expectEqualStrings(a.mask, b.mask);
        try std.testing.expectEqual(a.hlc, b.hlc);
        try std.testing.expectEqual(a.origin_node, b.origin_node);
        try std.testing.expectEqual(a.recorded_at, b.recorded_at);
    }
    try std.testing.expectEqual(@as(?u64, 0), restored.entries.items[0].duration);
    try std.testing.expectEqual(@as(?u64, null), restored.entries.items[0].expires_at);
    const reencoded = try encode(alloc, &restored);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);
    try std.testing.expectEqual(access.ApplyOutcome.stale, try restored.applyRemote(.{
        .present = true,
        .channel = "#alpha",
        .level = .voice,
        .mask = "A!U@H",
        .set_by = "older",
        .hlc = 1,
        .origin_node = 1,
    }));
}

test "ACCESS checkpoint rejects malformed rows and duplicate identities" {
    const alloc = std.testing.allocator;
    var source = access.AccessStore.init(alloc);
    defer source.deinit();
    source.now_seconds = 20;
    try source.add("#A", .voice, "n!u@h", "owner", null);
    try source.add("#B", .voice, "n!u@h", "owner", 10);
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    var bad = try alloc.dupe(u8, wire);
    defer alloc.free(bad);

    try std.testing.expect(!isCheckpoint("wrong"));
    try std.testing.expectError(error.Truncated, validateCheckpoint(wire[0 .. wire.len - 1]));
    bad[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[header_len + 6] = '&';
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));

    const first_row_len = 6 + 2 + "n!u@h".len + "owner".len + 16;
    const second_row = header_len + first_row_len;
    @memcpy(bad, wire);
    bad[second_row + 6 + 1] = 'a'; // same identity ignoring case
    testRechecksum(bad);
    try std.testing.expectError(error.DuplicateIdentity, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[header_len + 4] = 2; // invalid nullable duration tag
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[second_row + 4] = 0; // nonzero duration still has an expiry; malformed layout
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u16, bad[16..18], 1, .little); // only one row allowed by config
    testRechecksum(bad);
    try std.testing.expectError(error.CheckpointTooLarge, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u64, bad[header_len + first_row_len - 16 ..][0..8], source.hlc + 1, .little);
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    const trailing = try alloc.alloc(u8, wire.len + 1);
    defer alloc.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));
}

test "ACCESS checkpoint staged decode is allocation failure atomic" {
    const alloc = std.testing.allocator;
    var source = access.AccessStore.init(alloc);
    defer source.deinit();
    source.now_seconds = 100;
    try source.add("#A", .owner, "a!u@h", "owner-a", 5);
    _ = try source.remove("#Deleted", .deny, "d!u@h");
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, store: *const access.AccessStore) !void {
            const bytes = try encode(allocator, store);
            defer allocator.free(bytes);
            try validateCheckpoint(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, EncodeSweep.run, .{&source});
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var current = access.AccessStore.init(allocator);
            defer current.deinit();
            try current.add("#Keeper", .voice, "k!u@h", "keeper", null);
            var staged = decode(allocator, bytes) catch |err| {
                try std.testing.expectEqualStrings("#Keeper", current.entries.items[0].channel);
                try std.testing.expectEqual(@as(usize, 1), current.entries.items.len);
                return err;
            };
            std.mem.swap(access.AccessStore, &current, &staged);
            staged.deinit();
            try std.testing.expectEqualStrings("#A", current.entries.items[0].channel);
            try std.testing.expectEqual(@as(usize, 1), current.tombstones.items.len);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, DecodeSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}
