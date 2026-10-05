// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact, bounded Helix custody for the daemon's last slowmode send times.
//! The caller owns the decoded map and swaps it only after the whole handoff
//! has validated. Keys are the producer's lowercase `channel\x00nick` bytes.

const std = @import("std");

pub const Map = std.StringHashMapUnmanaged(u64);
pub const max_key_bytes: usize = 512;
pub const max_entries: usize = 1_000_000;
/// Below Helix's 2 GiB arena ceiling, leaving room for other mandatory pieces.
pub const max_checkpoint_bytes: usize = 512 * 1024 * 1024;
pub const checkpoint_magic = [_]u8{ 'S', 'L', 'M', 'D' };
pub const checkpoint_version: u8 = 1;
const header_len: usize = 4 + 1 + 3 + 4 + 4;
const checksum_len: usize = 32;
const row_min_len: usize = 2 + 3 + 8; // at least one channel byte, NUL, one nick byte
const checksum_domain = "onyx-slowmode-checkpoint-v1";

comptime {
    if (max_key_bytes > std.math.maxInt(u16) or max_entries > std.math.maxInt(u32) or
        max_checkpoint_bytes > std.math.maxInt(u32))
        @compileError("slowmode checkpoint exceeds its wire bounds");
}

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    NonCanonicalOrder,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Validate the complete wire image in O(bytes) time and O(1) space.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    if (count > max_entries) return error.CheckpointTooLarge;
    if (body_len > max_checkpoint_bytes - header_len - checksum_len) return error.CheckpointTooLarge;
    const expected_len = header_len + body_len + checksum_len;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    if (count > body_len / row_min_len) return error.Truncated;
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    const saved: [checksum_len]u8 = bytes[bytes.len - checksum_len ..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, saved)) return error.ChecksumMismatch;

    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    var previous: ?[]const u8 = null;
    for (0..count) |_| {
        const key_len: usize = try reader.readU16();
        if (key_len < 3 or key_len > max_key_bytes) return error.InvalidField;
        const key = try reader.take(key_len);
        if (!validKey(key)) return error.InvalidField;
        if (previous) |prior| {
            if (!std.mem.lessThan(u8, prior, key)) return error.NonCanonicalOrder;
        }
        previous = key;
        _ = try reader.readU64();
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Encode the complete map in bytewise key order. Source overflow fails
/// explicitly, never dropping an existing timer.
pub fn encode(allocator: std.mem.Allocator, map: *const Map) Error![]u8 {
    const count = map.count();
    if (count > max_entries) return error.CheckpointTooLarge;
    const keys = try allocator.alloc([]const u8, count);
    defer allocator.free(keys);
    var total_len: usize = header_len + checksum_len;
    var iterator = map.keyIterator();
    var index: usize = 0;
    while (iterator.next()) |key_ptr| {
        const key = key_ptr.*;
        if (!validKey(key)) return error.InvalidField;
        keys[index] = key;
        index += 1;
        try addLen(&total_len, 2 + key.len + 8);
    }
    std.debug.assert(index == count);
    std.mem.sort([]const u8, keys, {}, lessThan);
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(checkpoint_version);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(total_len - header_len - checksum_len));
    writer.writeU32(@intCast(count));
    for (keys) |key| {
        writer.writeU16(@intCast(key.len));
        writer.writeBytes(key);
        writer.writeU64(map.get(key).?);
    }
    std.debug.assert(writer.pos + checksum_len == out.len);
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(out[0..writer.pos], &digest);
    writer.writeBytes(&digest);
    return out;
}

/// Build an independent map. On any error all staged keys are freed and the
/// caller's existing map remains untouched.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Map {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    var result: Map = .empty;
    errdefer deinit(allocator, &result);
    try result.ensureTotalCapacity(allocator, @intCast(count));
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (0..count) |_| {
        const key_len: usize = try reader.readU16();
        const key = try reader.take(key_len);
        const at_ms = try reader.readU64();
        const owned = try allocator.dupe(u8, key);
        errdefer allocator.free(owned);
        result.putAssumeCapacity(owned, at_ms);
    }
    std.debug.assert(reader.remaining() == 0);
    return result;
}

/// Release a decoded map, or any map whose keys were allocated individually
/// with this allocator (as server.zig's producer does).
pub fn deinit(allocator: std.mem.Allocator, map: *Map) void {
    var keys = map.keyIterator();
    while (keys.next()) |key| allocator.free(@constCast(key.*));
    map.deinit(allocator);
    map.* = .empty;
}

fn validKey(key: []const u8) bool {
    if (key.len < 3 or key.len > max_key_bytes) return false;
    if (key[0] != '#' and key[0] != '&') return false;
    const separator = std.mem.indexOfScalar(u8, key, 0) orelse return false;
    if (separator == 0 or separator + 1 == key.len) return false;
    for (key) |byte| {
        if (std.ascii.toLower(byte) != byte) return false;
    }
    return std.mem.indexOfScalar(u8, key[separator + 1 ..], 0) == null;
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

    fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
};

test "slowmode checkpoint round trips exact keys and timestamps" {
    const alloc = std.testing.allocator;
    var source: Map = .empty;
    defer deinit(alloc, &source);
    const keys = [_][]const u8{ "#z\x00zed", "&local\x00nick", "#a\x00\xc3\xa9" };
    const times = [_]u64{ 0, std.math.maxInt(u64), 1_000_000 };
    for (keys, times) |key, at_ms| try source.put(alloc, try alloc.dupe(u8, key), at_ms);
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    var restored = try decode(alloc, wire);
    defer deinit(alloc, &restored);
    for (keys, times) |key, at_ms| try std.testing.expectEqual(@as(?u64, at_ms), restored.get(key));
    const reencoded = try encode(alloc, &restored);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);
    try std.testing.expect(@intFromPtr(source.getKey("#z\x00zed").?.ptr) != @intFromPtr(restored.getKey("#z\x00zed").?.ptr));

    var empty: Map = .empty;
    defer deinit(alloc, &empty);
    const empty_wire = try encode(alloc, &empty);
    defer alloc.free(empty_wire);
    var empty_restored = try decode(alloc, empty_wire);
    defer deinit(alloc, &empty_restored);
    try std.testing.expectEqual(@as(usize, 0), empty_restored.count());
}

test "slowmode checkpoint rejects malformed and noncanonical images" {
    const alloc = std.testing.allocator;
    var map: Map = .empty;
    defer deinit(alloc, &map);
    try map.put(alloc, try alloc.dupe(u8, "#a\x00nick"), 10);
    try map.put(alloc, try alloc.dupe(u8, "#b\x00nick"), 20);
    const wire = try encode(alloc, &map);
    defer alloc.free(wire);
    var bad = try alloc.dupe(u8, wire);
    defer alloc.free(bad);

    try std.testing.expect(!isCheckpoint("wrong"));
    try std.testing.expectError(error.Truncated, validateCheckpoint(wire[0 .. wire.len - 1]));
    bad[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[header_len + 2] = '&';
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));

    const first_row_len = 2 + "#a\x00nick".len + 8;
    @memcpy(bad, wire);
    bad[header_len + first_row_len + 3] = 'a'; // second key becomes first key
    testRechecksum(bad);
    try std.testing.expectError(error.NonCanonicalOrder, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[header_len + 3] = 'A'; // a producer key is lowercase
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[header_len + 4] = 'x'; // missing channel/nick separator
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u16, bad[header_len..][0..2], @intCast(max_key_bytes + 1), .little);
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u32, bad[12..16], @intCast(max_entries + 1), .little);
    testRechecksum(bad);
    try std.testing.expectError(error.CheckpointTooLarge, validateCheckpoint(bad));

    const trailing = try alloc.alloc(u8, wire.len + 1);
    defer alloc.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));

    var too_long: [max_key_bytes + 1]u8 = undefined;
    @memset(&too_long, 'x');
    too_long[0] = '#';
    too_long[1] = 0;
    const owned = try alloc.dupe(u8, &too_long);
    try map.put(alloc, owned, 30);
    try std.testing.expectError(error.InvalidField, encode(alloc, &map));
}

test "slowmode checkpoint encode and staged decode sweep allocation failures" {
    const alloc = std.testing.allocator;
    var source: Map = .empty;
    defer deinit(alloc, &source);
    try source.put(alloc, try alloc.dupe(u8, "#a\x00nick"), 10);
    try source.put(alloc, try alloc.dupe(u8, "#b\x00nick"), 20);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, map: *const Map) !void {
            const bytes = try encode(allocator, map);
            defer allocator.free(bytes);
            try validateCheckpoint(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, EncodeSweep.run, .{&source});
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var current: Map = .empty;
            defer deinit(allocator, &current);
            const owned = try allocator.dupe(u8, "#keep\x00nick");
            current.put(allocator, owned, 99) catch |err| {
                allocator.free(owned);
                return err;
            };
            var staged = decode(allocator, bytes) catch |err| {
                try std.testing.expectEqual(@as(?u64, 99), current.get("#keep\x00nick"));
                return err;
            };
            std.mem.swap(Map, &current, &staged);
            deinit(allocator, &staged);
            try std.testing.expectEqual(@as(?u64, 10), current.get("#a\x00nick"));
            try std.testing.expect(!current.contains("#keep\x00nick"));
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, DecodeSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}
