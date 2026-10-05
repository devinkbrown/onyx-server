// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for ordered Koshi patterns and matcher availability.

const std = @import("std");
const content_filter = @import("../content_filter.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'K', 'O', 'S', 'H' };
pub const max_patterns: usize = 4096;
pub const max_text_bytes: usize = std.math.maxInt(u16);
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error;
const domain = "onyx-content-filter-checkpoint-v1";
const header_len: usize = 20;
const table_len = max_patterns * 2;

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    const limit: usize = std.mem.readInt(u16, bytes[14..16], .little);
    const max_len: usize = std.mem.readInt(u16, bytes[16..18], .little);
    const active = bytes[18];
    if (bytes[19] != 0 or active > 1 or (active == 1 and count == 0)) return error.InvalidField;
    if (limit > max_patterns or count > limit) return error.CheckpointTooLarge;
    if (count > body.len / 3) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var seen: [max_patterns][]const u8 = undefined;
    var table: [table_len]u16 = @splat(0);
    for (0..count) |index| {
        const len: usize = try reader.readU16();
        if (len == 0 or len > max_len) return error.InvalidField;
        const pattern = try reader.take(len);
        try insert(&table, &seen, index, pattern);
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encode(allocator: std.mem.Allocator, source: *const content_filter.ContentFilter) Error![]u8 {
    const patterns = source.list();
    if (source.cfg.max_patterns > max_patterns or source.cfg.max_pattern_len > max_text_bytes or
        patterns.len > source.cfg.max_patterns) return error.CheckpointTooLarge;
    const active = source.automaton != null;
    if (active and patterns.len == 0) return error.InvalidField;
    var size: usize = header_len + wire.checksum_len;
    for (patterns) |pattern| {
        if (pattern.len == 0 or pattern.len > source.cfg.max_pattern_len) return error.InvalidField;
        try wire.addLen(&size, 2 + pattern.len);
    }
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU16(@intCast(patterns.len));
    writer.writeU16(@intCast(source.cfg.max_patterns));
    writer.writeU16(@intCast(source.cfg.max_pattern_len));
    writer.writeByte(@intFromBool(active));
    writer.writeByte(0);
    for (patterns) |pattern| {
        writer.writeU16(@intCast(pattern.len));
        writer.writeBytes(pattern);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

/// A detached ContentFilter; its compiled matcher is rebuilt once if active.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!content_filter.ContentFilter {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    var result = content_filter.ContentFilter.initWithConfig(allocator, .{
        .max_patterns = std.mem.readInt(u16, bytes[14..16], .little),
        .max_pattern_len = std.mem.readInt(u16, bytes[16..18], .little),
    });
    errdefer result.deinit();
    var patterns: [max_patterns][]const u8 = undefined;
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |i| {
        patterns[i] = try reader.take(try reader.readU16());
    }
    try result.restorePatterns(patterns[0..count]);
    if (bytes[18] == 0) {
        if (result.automaton) |*matcher| matcher.deinit();
        result.automaton = null;
    }
    return result;
}

fn insert(table: *[table_len]u16, seen: *[max_patterns][]const u8, index: usize, pattern: []const u8) Error!void {
    var hash: u64 = 0xcbf29ce484222325;
    for (pattern) |byte| {
        hash = (hash ^ std.ascii.toLower(byte)) *% 0x100000001b3;
    }
    var slot: usize = @intCast(hash & (table_len - 1));
    while (table[slot] != 0) : (slot = (slot + 1) & (table_len - 1)) {
        if (std.ascii.eqlIgnoreCase(seen[table[slot] - 1], pattern)) return error.DuplicateEntry;
    }
    seen[index] = pattern;
    table[slot] = @intCast(index + 1);
}

test "KOSH checkpoint retains case, order, limits, and active matching" {
    const alloc = std.testing.allocator;
    var source = content_filter.ContentFilter.initWithConfig(alloc, .{ .max_patterns = 17, .max_pattern_len = 80 });
    defer source.deinit();
    try std.testing.expect(try source.add("Bad Word"));
    try std.testing.expect(try source.add("Second"));
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decode(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqualDeep(source.cfg, restored.cfg);
    try std.testing.expectEqualStrings("Bad Word", restored.list()[0]);
    try std.testing.expect(restored.matches("a bad WORD"));
    const again = try encode(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

test "KOSH checkpoint retains temporarily unavailable matcher" {
    const alloc = std.testing.allocator;
    var source = content_filter.ContentFilter.init(alloc);
    defer source.deinit();
    try std.testing.expect(try source.add("held"));
    if (source.automaton) |*matcher| matcher.deinit();
    source.automaton = null;
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decode(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 1), restored.list().len);
    try std.testing.expect(!restored.matches("held"));
}

test "KOSH checkpoint rejects duplicate and malformed patterns" {
    const alloc = std.testing.allocator;
    var source = content_filter.ContentFilter.init(alloc);
    defer source.deinit();
    _ = try source.add("a");
    _ = try source.add("b");
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    bad[header_len + 3 + 2] = 'A';
    rechecksum(bad);
    try std.testing.expectError(error.DuplicateEntry, validateCheckpoint(bad));
    bad[header_len + 3 + 2] = 'b';
    bad[18] = 2;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
}

test "KOSH checkpoint staged decode sweeps allocation failures" {
    const alloc = std.testing.allocator;
    var source = content_filter.ContentFilter.init(alloc);
    defer source.deinit();
    _ = try source.add("alpha");
    _ = try source.add("beta");
    const Encode = struct {
        fn run(a: std.mem.Allocator, s: *const content_filter.ContentFilter) !void {
            const encoded = try encode(a, s);
            defer a.free(encoded);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Encode.run, .{&source});
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    const Decode = struct {
        fn run(a: std.mem.Allocator, b: []const u8) !void {
            var staged = try decode(a, b);
            defer staged.deinit();
            try std.testing.expect(staged.matches("ALPHA"));
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Decode.run, .{bytes});
}

fn rechecksum(bytes: []u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}
