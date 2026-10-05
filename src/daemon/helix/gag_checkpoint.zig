// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for the ordered IP gag set and its limits.

const std = @import("std");
const gag = @import("../gag_set.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'G', 'A', 'G', 'S' };
pub const max_entries: usize = 4096;
pub const max_ip_bytes: usize = std.math.maxInt(u16);
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error;
const domain = "onyx-gag-checkpoint-v1";
const header_len: usize = 20;
const table_len = max_entries * 2;

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    const limit: usize = std.mem.readInt(u16, bytes[14..16], .little);
    const max_ip: usize = std.mem.readInt(u16, bytes[16..18], .little);
    if (std.mem.readInt(u16, bytes[18..20], .little) != 0) return error.InvalidField;
    if (limit > max_entries or count > limit) return error.CheckpointTooLarge;
    if (count > body.len / 3) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var seen: [max_entries][]const u8 = undefined;
    var table: [table_len]u16 = @splat(0);
    for (0..count) |index| {
        const len: usize = try reader.readU16();
        if (len == 0 or len > max_ip) return error.InvalidField;
        const ip = try reader.take(len);
        try insert(&table, &seen, index, ip);
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encode(allocator: std.mem.Allocator, source: *const gag.GagSet) Error![]u8 {
    if (source.params.max_entries > max_entries or source.params.max_ip > max_ip_bytes or
        source.ips.items.len > source.params.max_entries) return error.CheckpointTooLarge;
    var size: usize = header_len + wire.checksum_len;
    for (source.ips.items) |ip| {
        if (ip.len == 0 or ip.len > source.params.max_ip) return error.InvalidField;
        try wire.addLen(&size, 2 + ip.len);
    }
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU16(@intCast(source.ips.items.len));
    writer.writeU16(@intCast(source.params.max_entries));
    writer.writeU16(@intCast(source.params.max_ip));
    writer.writeU16(0);
    for (source.ips.items) |ip| {
        writer.writeU16(@intCast(ip.len));
        writer.writeBytes(ip);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

/// The result owns every IP. Swap only after all mandatory pieces are staged.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!gag.GagSet {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    var result = gag.GagSet.init(allocator, .{
        .max_entries = std.mem.readInt(u16, bytes[14..16], .little),
        .max_ip = std.mem.readInt(u16, bytes[16..18], .little),
    });
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |_| {
        const ip = try reader.take(try reader.readU16());
        result.add(ip) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
    }
    return result;
}

fn insert(table: *[table_len]u16, seen: *[max_entries][]const u8, index: usize, ip: []const u8) Error!void {
    var hash: u64 = 0xcbf29ce484222325;
    for (ip) |byte| {
        hash = (hash ^ std.ascii.toLower(byte)) *% 0x100000001b3;
    }
    var slot: usize = @intCast(hash & (table_len - 1));
    while (table[slot] != 0) : (slot = (slot + 1) & (table_len - 1)) {
        if (std.ascii.eqlIgnoreCase(seen[table[slot] - 1], ip)) return error.DuplicateEntry;
    }
    seen[index] = ip;
    table[slot] = @intCast(index + 1);
}

test "GAGS checkpoint retains physical order and exact spelling" {
    const alloc = std.testing.allocator;
    var source = gag.GagSet.init(alloc, .{ .max_entries = 17, .max_ip = 80 });
    defer source.deinit();
    try source.add("2001:DB8::1");
    try source.add("192.0.2.5");
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decode(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqualDeep(source.params, restored.params);
    try std.testing.expectEqualStrings("2001:DB8::1", restored.ips.items[0]);
    try std.testing.expectEqualStrings("192.0.2.5", restored.ips.items[1]);
    const again = try encode(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

test "GAGS checkpoint rejects malformed and duplicate rows" {
    const alloc = std.testing.allocator;
    var source = gag.GagSet.init(alloc, .{});
    defer source.deinit();
    try source.add("A");
    try source.add("b");
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    try std.testing.expectError(error.Truncated, validateCheckpoint(bytes[0 .. bytes.len - 1]));
    bad[header_len + 3 + 2] = 'a';
    rechecksum(bad);
    try std.testing.expectError(error.DuplicateEntry, validateCheckpoint(bad));
    bad[header_len + 3 + 2] = 'b';
    bad[header_len] = 0;
    bad[header_len + 1] = 0;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
}

test "GAGS checkpoint encode and detached decode survive allocation failures" {
    const alloc = std.testing.allocator;
    var source = gag.GagSet.init(alloc, .{});
    defer source.deinit();
    try source.add("192.0.2.1");
    try source.add("2001:db8::2");
    const Encode = struct {
        fn run(a: std.mem.Allocator, s: *const gag.GagSet) !void {
            const bytes = try encode(a, s);
            defer a.free(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Encode.run, .{&source});
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    const Decode = struct {
        fn run(a: std.mem.Allocator, b: []const u8) !void {
            var staged = try decode(a, b);
            defer staged.deinit();
            try std.testing.expectEqual(@as(usize, 2), staged.count());
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Decode.run, .{bytes});
}

fn rechecksum(bytes: []u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}
