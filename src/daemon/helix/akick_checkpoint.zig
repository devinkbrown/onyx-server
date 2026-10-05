// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for the live per-channel AKICK matcher. Channel rows
//! are sorted on wire; entries retain their physical order within each list.

const std = @import("std");
const akick = @import("../svc_akick.zig");

pub const max_channels: usize = 4096;
pub const max_per_channel: usize = 256;
pub const max_channel_bytes: usize = 256;
pub const max_text_bytes: usize = 65_535;
pub const max_checkpoint_bytes: usize = 256 * 1024 * 1024;
pub const checkpoint_magic = [_]u8{ 'A', 'K', 'C', 'K' };
pub const checkpoint_version: u8 = 1;
const header_len: usize = 4 + 1 + 3 + 4 + 2 + 2;
const checksum_len: usize = 32;
const channel_min_len: usize = 2 + 2 + 1;
const entry_min_len: usize = 2 + 2 + 2 + 8 + 1 + 1;
const checksum_domain = "onyx-akick-checkpoint-v1";
const mask_table_len = max_per_channel * 2;

comptime {
    if (max_channels > std.math.maxInt(u16) or max_per_channel > std.math.maxInt(u16) or
        max_channel_bytes > std.math.maxInt(u16) or max_text_bytes > std.math.maxInt(u16) or
        max_checkpoint_bytes > std.math.maxInt(u32) or
        mask_table_len & (mask_table_len - 1) != 0)
        @compileError("AKICK checkpoint exceeds wire/index bounds");
}

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    NonCanonicalOrder,
    DuplicateMask,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

const Header = struct {
    channel_count: usize,
    max_per_channel_value: usize,
};

const ParsedEntry = struct {
    mask: []const u8,
    reason: []const u8,
    setter: []const u8,
    added_at_ms: i64,
    expires_at_ms: ?i64,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Structural validation uses fixed stack storage; no allocation or wall
/// clock is consulted. Empty channel rows are legal and retained.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const header = try parseHeader(bytes);
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    var previous: ?[]const u8 = null;
    for (0..header.channel_count) |_| {
        const channel_len: usize = try reader.readU16();
        const entry_count: usize = try reader.readU16();
        if (channel_len == 0 or channel_len > max_channel_bytes or entry_count > header.max_per_channel_value)
            return error.InvalidField;
        if (entry_count > reader.remaining() / entry_min_len) return error.Truncated;
        const channel = try reader.take(channel_len);
        if (!validChannel(channel)) return error.InvalidField;
        if (previous) |prior| {
            if (!std.mem.lessThan(u8, prior, channel)) return error.NonCanonicalOrder;
        }
        previous = channel;

        var masks: [max_per_channel][]const u8 = undefined;
        var table: [mask_table_len]u16 = undefined;
        @memset(&table, 0);
        for (0..entry_count) |index| {
            const entry = try readEntry(&reader);
            try insertMask(&table, &masks, index, entry.mask);
        }
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Serialize every channel row, including empty ones, and every entry in
/// match order. Source overflow or an inconsistent derived view fails closed.
pub fn encode(allocator: std.mem.Allocator, store: *const akick.AkickStore) Error![]u8 {
    const channel_count = store.channels.count();
    if (channel_count > max_channels or store.max_per_channel > max_per_channel) return error.CheckpointTooLarge;
    var channels: [max_channels][]const u8 = undefined;
    var count: usize = 0;
    var total_len: usize = header_len + checksum_len;
    var it = store.channels.iterator();
    while (it.next()) |kv| {
        const channel = kv.key_ptr.*;
        const entries = kv.value_ptr.entries.items;
        if (!validChannel(channel) or entries.len > store.max_per_channel) return error.InvalidField;
        channels[count] = channel;
        count += 1;
        try addLen(&total_len, 4 + channel.len);
        for (entries) |entry| {
            if (!validEntry(entry)) return error.InvalidField;
            try addLen(&total_len, 2 + 2 + 2 + 8 + 1 +
                (if (entry.expires_at_ms != null) @as(usize, 8) else 0) +
                entry.mask.len + entry.reason.len + entry.setter.len);
        }
    }
    std.mem.sort([]const u8, channels[0..count], {}, lessThan);
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(checkpoint_version);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(total_len - header_len - checksum_len));
    writer.writeU16(@intCast(count));
    writer.writeU16(@intCast(store.max_per_channel));
    for (channels[0..count]) |channel| {
        const list = store.channels.get(channel).?;
        writer.writeU16(@intCast(channel.len));
        writer.writeU16(@intCast(list.entries.items.len));
        writer.writeBytes(channel);
        for (list.entries.items) |entry| {
            writer.writeU16(@intCast(entry.mask.len));
            writer.writeU16(@intCast(entry.reason.len));
            writer.writeU16(@intCast(entry.setter.len));
            writer.writeI64(entry.added_at_ms);
            writer.writeByte(@intFromBool(entry.expires_at_ms != null));
            if (entry.expires_at_ms) |at| writer.writeI64(at);
            writer.writeBytes(entry.mask);
            writer.writeBytes(entry.reason);
            writer.writeBytes(entry.setter);
        }
    }
    std.debug.assert(writer.pos + checksum_len == out.len);
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(out[0..writer.pos], &digest);
    writer.writeBytes(&digest);
    try validateCheckpoint(out);
    return out;
}

/// Build a detached owner before COMMIT. A failed allocation deinitializes all
/// staged channel rows and entries, leaving the live store untouched.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!akick.AkickStore {
    const header = try parseHeader(bytes);
    try validateCheckpoint(bytes);
    var restored = akick.AkickStore.initCapacity(allocator, header.max_per_channel_value);
    errdefer restored.deinit();
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (0..header.channel_count) |_| {
        const channel_len: usize = try reader.readU16();
        const entry_count: usize = try reader.readU16();
        const channel = try reader.take(channel_len);
        restored.checkpointEnsureChannel(channel) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
        for (0..entry_count) |_| {
            const entry = try readEntry(&reader);
            restored.add(channel, entry.mask, entry.reason, entry.setter, entry.added_at_ms, entry.expires_at_ms) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidField,
            };
        }
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
        .channel_count = std.mem.readInt(u16, bytes[12..14], .little),
        .max_per_channel_value = std.mem.readInt(u16, bytes[14..16], .little),
    };
    if (header.channel_count > max_channels or header.max_per_channel_value > max_per_channel)
        return error.CheckpointTooLarge;
    if (body_len < header.channel_count * channel_min_len) return error.Truncated;
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    const saved: [checksum_len]u8 = bytes[bytes.len - checksum_len ..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, saved)) return error.ChecksumMismatch;
    return header;
}

fn readEntry(reader: *Reader) Error!ParsedEntry {
    const mask_len: usize = try reader.readU16();
    const reason_len: usize = try reader.readU16();
    const setter_len: usize = try reader.readU16();
    const added_at_ms = try reader.readI64();
    const expiry_tag = try reader.readByte();
    if (expiry_tag > 1 or mask_len == 0 or mask_len > max_text_bytes or
        reason_len > max_text_bytes or setter_len > max_text_bytes)
        return error.InvalidField;
    const expires_at_ms: ?i64 = if (expiry_tag == 1) try reader.readI64() else null;
    const mask = try reader.take(mask_len);
    const reason = try reader.take(reason_len);
    const setter = try reader.take(setter_len);
    if (!validMask(mask)) return error.InvalidField;
    return .{ .mask = mask, .reason = reason, .setter = setter, .added_at_ms = added_at_ms, .expires_at_ms = expires_at_ms };
}

fn validChannel(channel: []const u8) bool {
    if (channel.len == 0 or channel.len > max_channel_bytes or
        std.mem.trim(u8, channel, " ").len != channel.len) return false;
    for (channel) |byte| if (std.ascii.toLower(byte) != byte) return false;
    return true;
}

fn validMask(mask: []const u8) bool {
    if (mask.len == 0 or mask.len > max_text_bytes or
        std.mem.trim(u8, mask, " ").len != mask.len) return false;
    for (mask) |byte| if (std.ascii.toLower(byte) != byte) return false;
    return !(std.mem.startsWith(u8, mask, akick.account_prefix) and mask.len == akick.account_prefix.len);
}

fn validEntry(entry: akick.Entry) bool {
    if (!validMask(entry.mask) or entry.reason.len > max_text_bytes or entry.setter.len > max_text_bytes) return false;
    const account_mask = std.mem.startsWith(u8, entry.mask, akick.account_prefix);
    const pattern = if (account_mask) entry.mask[akick.account_prefix.len..] else entry.mask;
    if (entry.kind != (if (account_mask) akick.MaskKind.account else akick.MaskKind.hostmask)) return false;
    return entry.pattern.ptr == pattern.ptr and entry.pattern.len == pattern.len;
}

fn insertMask(table: *[mask_table_len]u16, seen: *[max_per_channel][]const u8, count: usize, mask: []const u8) Error!void {
    var slot: usize = @intCast(std.hash.Wyhash.hash(0, mask) & (mask_table_len - 1));
    while (table[slot] != 0) : (slot = (slot + 1) & (mask_table_len - 1)) {
        if (std.mem.eql(u8, seen[table[slot] - 1], mask)) return error.DuplicateMask;
    }
    seen[count] = mask;
    table[slot] = @intCast(count + 1);
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
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
    fn writeI64(self: *Writer, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .little);
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
    fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }
    fn readI64(self: *Reader) Error!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }
};

test "AKICK checkpoint preserves empty channels match order and signed expiry" {
    const alloc = std.testing.allocator;
    var source = akick.AkickStore.initCapacity(alloc, 3);
    defer source.deinit();
    try source.add("#Vacant", "v!u@h", "gone", "setter", 1, null);
    try std.testing.expectEqual(akick.RemoveResult.removed, source.remove("#vacant", "v!u@h"));
    try source.add("#Raid", "*!*@host", "wide", "Oper", -42, null);
    try source.add("#RAID", "bad!*@host", "narrow", "Other", 3, 900);
    try source.add("#Other", "account:alice*", "", "", 7, -1);
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    var restored = try decode(alloc, wire);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 3), restored.max_per_channel);
    try std.testing.expectEqual(@as(usize, 3), restored.channels.count());
    try std.testing.expectEqual(@as(usize, 0), restored.count("#VACANT"));
    const raid = restored.list("#raid");
    try std.testing.expectEqual(@as(usize, 2), raid.len);
    try std.testing.expectEqualStrings("*!*@host", raid[0].mask);
    try std.testing.expectEqualStrings("bad!*@host", raid[1].mask);
    try std.testing.expectEqualStrings("Oper", raid[0].setter);
    try std.testing.expectEqual(@as(i64, -42), raid[0].added_at_ms);
    try std.testing.expectEqual(@as(?i64, null), raid[0].expires_at_ms);
    try std.testing.expectEqual(@as(?i64, 900), raid[1].expires_at_ms);
    try std.testing.expectEqualStrings("wide", restored.matchOnJoin("#raid", "bad!u@host", null, 100).?.reason);
    const other = restored.list("#other");
    try std.testing.expectEqual(akick.MaskKind.account, other[0].kind);
    try std.testing.expectEqualStrings("alice*", other[0].pattern);
    try std.testing.expectEqual(@as(?i64, -1), other[0].expires_at_ms);
    try std.testing.expect(restored.matchOnJoin("#other", "x!u@h", "alice", 0) == null);
    const reencoded = try encode(alloc, &restored);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);
    try std.testing.expect(@intFromPtr(source.list("#raid")[0].mask.ptr) != @intFromPtr(raid[0].mask.ptr));
}

test "AKICK checkpoint rejects malformed rows duplicates and source inconsistency" {
    const alloc = std.testing.allocator;
    var source = akick.AkickStore.init(alloc);
    defer source.deinit();
    try source.add("#A", "a!u@h", "r", "s", 0, null);
    try source.add("#a", "b!u@h", "r", "s", 1, null);
    try source.checkpointEnsureChannel("#b");
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    var bad = try alloc.dupe(u8, wire);
    defer alloc.free(bad);

    try std.testing.expect(!isCheckpoint("wrong"));
    try std.testing.expectError(error.Truncated, validateCheckpoint(wire[0 .. wire.len - 1]));
    bad[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[header_len + 4] = 'x';
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));

    const channel_row = header_len;
    const first_entry = channel_row + 4 + "#a".len;
    const entry_len = 2 + 2 + 2 + 8 + 1 + "a!u@h".len + 1 + 1;
    const second_entry = first_entry + entry_len;
    @memcpy(bad, wire);
    bad[second_entry + 15] = 'a';
    testRechecksum(bad);
    try std.testing.expectError(error.DuplicateMask, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[first_entry + 14] = 2;
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[first_entry + 15] = 'A';
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    const second_channel = second_entry + entry_len;
    @memcpy(bad, wire);
    bad[second_channel + 4 + 1] = 'a';
    testRechecksum(bad);
    try std.testing.expectError(error.NonCanonicalOrder, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u16, bad[14..16], @intCast(max_per_channel + 1), .little);
    testRechecksum(bad);
    try std.testing.expectError(error.CheckpointTooLarge, validateCheckpoint(bad));

    const trailing = try alloc.alloc(u8, wire.len + 1);
    defer alloc.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));

    const entry = &source.channels.getPtr("#a").?.entries.items[0];
    entry.kind = .account;
    try std.testing.expectError(error.InvalidField, encode(alloc, &source));
    entry.kind = .hostmask;
    entry.pattern = entry.mask[1..];
    try std.testing.expectError(error.InvalidField, encode(alloc, &source));
}

test "AKICK checkpoint staged decode is allocation failure atomic" {
    const alloc = std.testing.allocator;
    var source = akick.AkickStore.init(alloc);
    defer source.deinit();
    try source.checkpointEnsureChannel("#empty");
    try source.add("#a", "a!u@h", "reason", "setter", 10, 20);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, store: *const akick.AkickStore) !void {
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
            var current = akick.AkickStore.init(allocator);
            defer current.deinit();
            try current.add("#keeper", "k!u@h", "keep", "setter", 0, null);
            var staged = decode(allocator, bytes) catch |err| {
                try std.testing.expectEqual(@as(usize, 1), current.count("#keeper"));
                return err;
            };
            std.mem.swap(akick.AkickStore, &current, &staged);
            staged.deinit();
            try std.testing.expectEqual(@as(usize, 1), current.count("#a"));
            try std.testing.expectEqual(@as(usize, 0), current.count("#keeper"));
            try std.testing.expect(current.channels.contains("#empty"));
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, DecodeSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}
