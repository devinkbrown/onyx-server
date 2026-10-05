// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for per-account abuse scores, including zero scores.

const std = @import("std");
const account_abuse = @import("../account_abuse.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'A', 'B', 'U', 'S' };
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error;
const domain = "onyx-account-abuse-checkpoint-v1";
const header_len: usize = 16;

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

/// Strict bytewise key order doubles as allocation-free duplicate validation.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    if (std.mem.readInt(u16, bytes[14..16], .little) != 0) return error.InvalidField;
    if (count > account_abuse.max_accounts) return error.CheckpointTooLarge;
    if (count > body.len / 6) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var prior: ?[]const u8 = null;
    for (0..count) |_| {
        const len: usize = try reader.readByte();
        if (len == 0 or len > account_abuse.max_account_len) return error.InvalidField;
        _ = try reader.readU32();
        const key = try reader.take(len);
        if (prior) |previous| {
            if (!std.mem.lessThan(u8, previous, key)) return error.NonCanonicalOrder;
        }
        prior = key;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encode(allocator: std.mem.Allocator, source: *const account_abuse.AccountAbuse) Error![]u8 {
    const count = source.count();
    if (count > account_abuse.max_accounts) return error.CheckpointTooLarge;
    const keys = try allocator.alloc([]const u8, count);
    defer allocator.free(keys);
    var size: usize = header_len + wire.checksum_len;
    var it = source.scores.iterator();
    var index: usize = 0;
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        if (key.len == 0 or key.len > account_abuse.max_account_len) return error.InvalidField;
        keys[index] = key;
        index += 1;
        try wire.addLen(&size, 1 + 4 + key.len);
    }
    std.debug.assert(index == count);
    std.mem.sort([]const u8, keys, {}, lessThan);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU16(@intCast(count));
    writer.writeU16(0);
    for (keys) |key| {
        writer.writeByte(@intCast(key.len));
        writer.writeU32(source.scores.get(key).?);
        writer.writeBytes(key);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!account_abuse.AccountAbuse {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    var result = account_abuse.AccountAbuse.init(allocator);
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |_| {
        const len: usize = try reader.readByte();
        const score = try reader.readU32();
        const key = try reader.take(len);
        result.importScore(key, score) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
    }
    return result;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

test "ABUS checkpoint preserves mixed-case keys and zero scores" {
    const alloc = std.testing.allocator;
    var source = account_abuse.AccountAbuse.init(alloc);
    defer source.deinit();
    try source.importScore("zero", 0);
    try source.importScore("Alpha", 0xffff_ffff);
    try source.importScore("alpha", 7);
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decode(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 3), restored.count());
    try std.testing.expectEqual(@as(u32, 0), restored.score("zero"));
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), restored.score("Alpha"));
    try std.testing.expectEqual(@as(u32, 7), restored.score("alpha"));
    const again = try encode(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

test "ABUS checkpoint rejects malformed key order and checksum" {
    const alloc = std.testing.allocator;
    var source = account_abuse.AccountAbuse.init(alloc);
    defer source.deinit();
    try source.importScore("a", 1);
    try source.importScore("b", 2);
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    try std.testing.expectError(error.Truncated, validateCheckpoint(bytes[0 .. bytes.len - 1]));
    bad[header_len + 6 + 5] = 'a';
    rechecksum(bad);
    try std.testing.expectError(error.NonCanonicalOrder, validateCheckpoint(bad));
    bad[header_len + 6 + 5] = 'b';
    bad[header_len + 1] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));
}

test "ABUS checkpoint encode and decode sweep allocations" {
    const alloc = std.testing.allocator;
    var source = account_abuse.AccountAbuse.init(alloc);
    defer source.deinit();
    try source.importScore("a", 0);
    try source.importScore("b", 2);
    const Encode = struct {
        fn run(a: std.mem.Allocator, s: *const account_abuse.AccountAbuse) !void {
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
