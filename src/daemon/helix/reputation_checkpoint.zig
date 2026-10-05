// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for undecayed IP reputation rows and decay settings.

const std = @import("std");
const reputation = @import("../ip_reputation.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'I', 'P', 'R', 'P' };
pub const max_entries: usize = 1_000_000;
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error;
const domain = "onyx-ip-reputation-checkpoint-v1";
const header_len: usize = 40;
const row_len: usize = 33;

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    if (count > max_entries) return error.CheckpointTooLarge;
    if (std.mem.readInt(u64, bytes[16..24], .little) == 0) return error.InvalidField;
    if (count > body.len / row_len) return error.Truncated;
    if (body.len != count * row_len) return error.TrailingBytes;
    var reader = wire.Reader{ .bytes = body };
    var prior_tag: u8 = 0;
    var prior_bytes: [16]u8 = undefined;
    for (0..count) |index| {
        const tag = try reader.readByte();
        if (tag != 4 and tag != 6) return error.InvalidField;
        const key = (try reader.take(16))[0..16].*;
        _ = try reader.readU64(); // All f64 bit patterns are live-state values.
        _ = try reader.readU64();
        if (index > 0 and (tag < prior_tag or
            (tag == prior_tag and !std.mem.lessThan(u8, &prior_bytes, &key))))
            return error.NonCanonicalOrder;
        prior_tag = tag;
        prior_bytes = key;
    }
}

pub fn encode(allocator: std.mem.Allocator, source: *const reputation.IpReputation) Error![]u8 {
    const count = source.count();
    if (count > max_entries) return error.CheckpointTooLarge;
    if (source.config.half_life_ms == 0) return error.InvalidField;
    const size = header_len + count * row_len + wire.checksum_len;
    if (size > max_checkpoint_bytes) return error.CheckpointTooLarge;
    const rows = source.dupeRows(allocator) catch return error.OutOfMemory;
    defer allocator.free(rows);
    std.mem.sort(reputation.StoredRow, rows, {}, lessThan);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(count * row_len));
    writer.writeU32(@intCast(count));
    writer.writeU64(source.config.half_life_ms);
    writer.writeU64(@bitCast(source.config.refuse_threshold));
    writer.writeU64(@bitCast(source.config.negligible));
    for (rows) |row| {
        writer.writeByte(row.tag);
        writer.writeBytes(&row.bytes);
        writer.writeU64(@bitCast(row.score));
        writer.writeU64(row.updated_ms);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!reputation.IpReputation {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    var result = reputation.IpReputation.init(allocator, .{
        .half_life_ms = std.mem.readInt(u64, bytes[16..24], .little),
        .refuse_threshold = @bitCast(std.mem.readInt(u64, bytes[24..32], .little)),
        .negligible = @bitCast(std.mem.readInt(u64, bytes[32..40], .little)),
    }) catch return error.InvalidField;
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |_| {
        const tag = try reader.readByte();
        const key: [16]u8 = (try reader.take(16))[0..16].*;
        const score: f64 = @bitCast(try reader.readU64());
        const updated_ms = try reader.readU64();
        result.importRow(.{ .tag = tag, .bytes = key, .score = score, .updated_ms = updated_ms }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
    }
    return result;
}

fn lessThan(_: void, a: reputation.StoredRow, b: reputation.StoredRow) bool {
    if (a.tag != b.tag) return a.tag < b.tag;
    return std.mem.lessThan(u8, &a.bytes, &b.bytes);
}

test "IPRP checkpoint preserves raw f64 bits, clocks, config, and noncanonical IPv4 tails" {
    const alloc = std.testing.allocator;
    var source = try reputation.IpReputation.init(alloc, .{
        .half_life_ms = 12345,
        .refuse_threshold = @bitCast(@as(u64, 0x7ff8_0000_0000_0042)),
        .negligible = -0.0,
    });
    defer source.deinit();
    var tail: [16]u8 = @splat(0);
    tail[0] = 192;
    tail[1] = 0;
    tail[2] = 2;
    tail[3] = 1;
    tail[15] = 99;
    try source.importRow(.{ .tag = 4, .bytes = tail, .score = @bitCast(@as(u64, 0x7ff8_0000_0000_0001)), .updated_ms = 900 });
    try source.importRow(.{ .tag = 6, .bytes = @splat(0xaa), .score = -0.0, .updated_ms = 1 });
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decode(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 2), restored.count());
    try std.testing.expectEqual(@as(u64, 12345), restored.config.half_life_ms);
    try std.testing.expectEqual(@as(u64, @bitCast(source.config.refuse_threshold)), @as(u64, @bitCast(restored.config.refuse_threshold)));
    const again = try encode(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

test "IPRP checkpoint rejects malformed order and zero half-life" {
    const alloc = std.testing.allocator;
    var source = try reputation.IpReputation.init(alloc, .{});
    defer source.deinit();
    try source.importRow(.{ .tag = 4, .bytes = @splat(0), .score = 1, .updated_ms = 0 });
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    bad[16] = 0;
    bad[17] = 0;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    bad[header_len] = 5;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
}

test "IPRP checkpoint staged decode sweeps allocation failures" {
    const alloc = std.testing.allocator;
    var source = try reputation.IpReputation.init(alloc, .{});
    defer source.deinit();
    try source.importRow(.{ .tag = 4, .bytes = @splat(1), .score = 1, .updated_ms = 10 });
    try source.importRow(.{ .tag = 6, .bytes = @splat(2), .score = 2, .updated_ms = 20 });
    const Encode = struct {
        fn run(a: std.mem.Allocator, s: *const reputation.IpReputation) !void {
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
