// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for server-owned services MLOCK policy.
//! Both map keys and specs are owned. Channel key casing is preserved because
//! the live producer stores the incoming spelling, even for registered names.

const std = @import("std");

pub const Map = std.StringHashMapUnmanaged([]u8);
pub const max_channel_bytes: usize = 64;
pub const max_spec_bytes: usize = 128;
pub const max_entries: usize = 1_000_000;
/// Below Helix's 2 GiB arena ceiling, leaving room for other mandatory pieces.
pub const max_checkpoint_bytes: usize = 256 * 1024 * 1024;
pub const checkpoint_magic = [_]u8{ 'M', 'L', 'C', 'K' };
pub const checkpoint_version: u8 = 1;
const header_len: usize = 4 + 1 + 3 + 4 + 4;
const checksum_len: usize = 32;
const row_min_len: usize = 1 + 1 + 2; // key len, spec len, minimum channel name
const checksum_domain = "onyx-mlock-checkpoint-v1";

comptime {
    if (max_channel_bytes > std.math.maxInt(u8) or max_spec_bytes > std.math.maxInt(u8) or
        max_entries > std.math.maxInt(u32) or max_checkpoint_bytes > std.math.maxInt(u32))
        @compileError("MLOCK checkpoint exceeds its wire bounds");
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

/// Validate the complete image in O(bytes) time and O(1) space.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    if (count > max_entries or body_len > max_checkpoint_bytes - header_len - checksum_len) return error.CheckpointTooLarge;
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
        const channel_len: usize = try reader.readByte();
        const spec_len: usize = try reader.readByte();
        if (channel_len < 2 or channel_len > max_channel_bytes or spec_len > max_spec_bytes) return error.InvalidField;
        const channel = try reader.take(channel_len);
        const spec = try reader.take(spec_len);
        if (!validChannel(channel) or !validSpec(spec)) return error.InvalidField;
        if (previous) |prior| {
            if (!std.mem.lessThan(u8, prior, channel)) return error.NonCanonicalOrder;
        }
        previous = channel;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Serialize every policy row in bytewise key order. Empty specs are retained.
pub fn encode(allocator: std.mem.Allocator, map: *const Map) Error![]u8 {
    const count = map.count();
    if (count > max_entries) return error.CheckpointTooLarge;
    const channels = try allocator.alloc([]const u8, count);
    defer allocator.free(channels);
    var total_len: usize = header_len + checksum_len;
    var it = map.iterator();
    var index: usize = 0;
    while (it.next()) |entry| {
        const channel = entry.key_ptr.*;
        const spec = entry.value_ptr.*;
        if (!validChannel(channel) or !validSpec(spec)) return error.InvalidField;
        channels[index] = channel;
        index += 1;
        try addLen(&total_len, 2 + channel.len + spec.len);
    }
    std.debug.assert(index == count);
    std.mem.sort([]const u8, channels, {}, lessThan);
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(checkpoint_version);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(total_len - header_len - checksum_len));
    writer.writeU32(@intCast(count));
    for (channels) |channel| {
        const spec = map.get(channel).?;
        writer.writeByte(@intCast(channel.len));
        writer.writeByte(@intCast(spec.len));
        writer.writeBytes(channel);
        writer.writeBytes(spec);
    }
    std.debug.assert(writer.pos + checksum_len == out.len);
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(out[0..writer.pos], &digest);
    writer.writeBytes(&digest);
    return out;
}

/// Stage a detached map. On error every staged key and value is freed, so the
/// caller can swap only after all other Helix state has passed validation.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Map {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    var result: Map = .empty;
    errdefer deinit(allocator, &result);
    try result.ensureTotalCapacity(allocator, @intCast(count));
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (0..count) |_| {
        const channel_len: usize = try reader.readByte();
        const spec_len: usize = try reader.readByte();
        const channel = try reader.take(channel_len);
        const spec = try reader.take(spec_len);
        const owned_channel = try allocator.dupe(u8, channel);
        errdefer allocator.free(owned_channel);
        const owned_spec = try allocator.dupe(u8, spec);
        errdefer allocator.free(owned_spec);
        result.putAssumeCapacity(owned_channel, owned_spec);
    }
    std.debug.assert(reader.remaining() == 0);
    return result;
}

/// Release a decoded map, or a server MLOCK map with individually owned keys
/// and values allocated from the same allocator.
pub fn deinit(allocator: std.mem.Allocator, map: *Map) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        allocator.free(entry.value_ptr.*);
    }
    map.deinit(allocator);
    map.* = .empty;
}

fn validChannel(channel: []const u8) bool {
    if (channel.len < 2 or channel.len > max_channel_bytes or channel[0] != '#') return false;
    for (channel) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '|' or byte == ',' or byte == ':') return false;
    }
    return true;
}

fn validSpec(spec: []const u8) bool {
    if (spec.len > max_spec_bytes) return false;
    for (spec) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == '|') return false;
    }
    return true;
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

    fn writeU32(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
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
};

test "MLOCK checkpoint round trips mixed-case keys and empty policies" {
    const alloc = std.testing.allocator;
    var source: Map = .empty;
    defer deinit(alloc, &source);
    try putOwned(alloc, &source, "#ChAn", "+nt-k");
    try putOwned(alloc, &source, "#chan", "");
    try putOwned(alloc, &source, "#Other", "+m-s");
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    var restored = try decode(alloc, wire);
    defer deinit(alloc, &restored);
    try std.testing.expectEqual(@as(usize, 3), restored.count());
    try std.testing.expectEqualStrings("+nt-k", restored.get("#ChAn").?);
    try std.testing.expectEqual(@as(usize, 0), restored.get("#chan").?.len);
    try std.testing.expectEqualStrings("+m-s", restored.get("#Other").?);
    try std.testing.expect(@intFromPtr(source.getKey("#ChAn").?.ptr) != @intFromPtr(restored.getKey("#ChAn").?.ptr));
    try std.testing.expect(@intFromPtr(source.get("#ChAn").?.ptr) != @intFromPtr(restored.get("#ChAn").?.ptr));
    const reencoded = try encode(alloc, &restored);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);

    var empty: Map = .empty;
    defer deinit(alloc, &empty);
    const empty_wire = try encode(alloc, &empty);
    defer alloc.free(empty_wire);
    var empty_restored = try decode(alloc, empty_wire);
    defer deinit(alloc, &empty_restored);
    try std.testing.expectEqual(@as(usize, 0), empty_restored.count());
}

test "MLOCK checkpoint rejects malformed rows and order" {
    const alloc = std.testing.allocator;
    var source: Map = .empty;
    defer deinit(alloc, &source);
    try putOwned(alloc, &source, "#A", "+nt");
    try putOwned(alloc, &source, "#B", "");
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    var bad = try alloc.dupe(u8, wire);
    defer alloc.free(bad);

    try std.testing.expect(!isCheckpoint("wrong"));
    try std.testing.expectError(error.Truncated, validateCheckpoint(wire[0 .. wire.len - 1]));
    bad[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[5] = 1;
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[header_len + 2] = '&';
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));

    const second_row = header_len + 2 + "#A".len + "+nt".len;
    @memcpy(bad, wire);
    bad[second_row + 3] = 'A'; // second key becomes first key
    testRechecksum(bad);
    try std.testing.expectError(error.NonCanonicalOrder, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[header_len + 2] = '&';
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[header_len + 2 + "#A".len] = 0; // control byte in spec
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[header_len] = @intCast(max_channel_bytes + 1);
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u32, bad[12..16], @intCast(max_entries + 1), .little);
    testRechecksum(bad);
    try std.testing.expectError(error.CheckpointTooLarge, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u32, bad[8..12], @intCast(max_checkpoint_bytes), .little);
    try std.testing.expectError(error.CheckpointTooLarge, validateCheckpoint(bad));

    const trailing = try alloc.alloc(u8, wire.len + 1);
    defer alloc.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));

    var long_channel: [max_channel_bytes + 1]u8 = undefined;
    @memset(&long_channel, 'x');
    long_channel[0] = '#';
    try putOwned(alloc, &source, &long_channel, "+m");
    try std.testing.expectError(error.InvalidField, encode(alloc, &source));

    var long_spec: [max_spec_bytes + 1]u8 = undefined;
    @memset(&long_spec, 'm');
    var spec_map: Map = .empty;
    defer deinit(alloc, &spec_map);
    try putOwned(alloc, &spec_map, "#valid", &long_spec);
    try std.testing.expectError(error.InvalidField, encode(alloc, &spec_map));
}

test "MLOCK checkpoint encode and staged decode sweep allocation failures" {
    const alloc = std.testing.allocator;
    var source: Map = .empty;
    defer deinit(alloc, &source);
    try putOwned(alloc, &source, "#A", "+nt");
    try putOwned(alloc, &source, "#B", "");
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
            try putOwned(allocator, &current, "#Keeper", "+s");
            var staged = decode(allocator, bytes) catch |err| {
                try std.testing.expectEqualStrings("+s", current.get("#Keeper").?);
                return err;
            };
            std.mem.swap(Map, &current, &staged);
            deinit(allocator, &staged);
            try std.testing.expectEqualStrings("+nt", current.get("#A").?);
            try std.testing.expectEqual(@as(usize, 0), current.get("#B").?.len);
            try std.testing.expect(!current.contains("#Keeper"));
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, DecodeSweep.run, .{wire});
}

fn putOwned(allocator: std.mem.Allocator, map: *Map, channel: []const u8, spec: []const u8) !void {
    const key = try allocator.dupe(u8, channel);
    errdefer allocator.free(key);
    const value = try allocator.dupe(u8, spec);
    errdefer allocator.free(value);
    try map.put(allocator, key, value);
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}
