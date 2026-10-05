// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for ordered, possibly expired shun policy.

const std = @import("std");
const shun = @import("../shun.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'S', 'H', 'U', 'N' };
pub const max_shuns: usize = 1024;
pub const max_text_bytes: usize = std.math.maxInt(u16);
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error;
const domain = "onyx-shun-checkpoint-v1";
const header_len: usize = 24;
const table_len = max_shuns * 2;

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    const params = readParams(bytes);
    if (std.mem.readInt(u16, bytes[22..24], .little) != 0) return error.InvalidField;
    if (params.max_shuns > max_shuns or count > params.max_shuns) return error.CheckpointTooLarge;
    if (count > body.len / 23) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var seen: [max_shuns][]const u8 = undefined;
    var table: [table_len]u16 = @splat(0);
    for (0..count) |index| {
        const row = try readRow(&reader, params);
        try insert(&table, &seen, index, row.mask);
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encode(allocator: std.mem.Allocator, source: *const shun.ShunList) Error![]u8 {
    const params = source.params;
    if (params.max_shuns > max_shuns or params.max_mask > max_text_bytes or
        params.max_reason > max_text_bytes or params.max_setter > max_text_bytes or
        source.shuns.items.len > params.max_shuns) return error.CheckpointTooLarge;
    var size: usize = header_len + wire.checksum_len;
    for (source.shuns.items) |row| {
        if (row.mask.len == 0 or row.mask.len > params.max_mask or row.reason.len > params.max_reason or
            row.set_by.len > params.max_setter) return error.InvalidField;
        try wire.addLen(&size, 22 + row.mask.len + row.reason.len + row.set_by.len);
    }
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU16(@intCast(source.shuns.items.len));
    writer.writeU16(@intCast(params.max_shuns));
    writer.writeU16(@intCast(params.max_mask));
    writer.writeU16(@intCast(params.max_reason));
    writer.writeU16(@intCast(params.max_setter));
    writer.writeU16(0);
    for (source.shuns.items) |row| {
        writer.writeU16(@intCast(row.mask.len));
        writer.writeU16(@intCast(row.reason.len));
        writer.writeU16(@intCast(row.set_by.len));
        writer.writeI64(row.created_ms);
        writer.writeI64(row.expires_ms);
        writer.writeBytes(row.mask);
        writer.writeBytes(row.reason);
        writer.writeBytes(row.set_by);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!shun.ShunList {
    try validateCheckpoint(bytes);
    const count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    const params = readParams(bytes);
    var result = shun.ShunList.init(allocator, params);
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |_| {
        const row = try readRow(&reader, params);
        result.add(row) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
    }
    return result;
}

fn readParams(bytes: []const u8) shun.Params {
    return .{
        .max_shuns = std.mem.readInt(u16, bytes[14..16], .little),
        .max_mask = std.mem.readInt(u16, bytes[16..18], .little),
        .max_reason = std.mem.readInt(u16, bytes[18..20], .little),
        .max_setter = std.mem.readInt(u16, bytes[20..22], .little),
    };
}

fn readRow(reader: *wire.Reader, params: shun.Params) Error!shun.Shun {
    const mask_len: usize = try reader.readU16();
    const reason_len: usize = try reader.readU16();
    const setter_len: usize = try reader.readU16();
    if (mask_len == 0 or mask_len > params.max_mask or reason_len > params.max_reason or
        setter_len > params.max_setter) return error.InvalidField;
    const created_ms = try reader.readI64();
    const expires_ms = try reader.readI64();
    return .{
        .mask = try reader.take(mask_len),
        .reason = try reader.take(reason_len),
        .set_by = try reader.take(setter_len),
        .created_ms = created_ms,
        .expires_ms = expires_ms,
    };
}

fn insert(table: *[table_len]u16, seen: *[max_shuns][]const u8, index: usize, mask: []const u8) Error!void {
    var slot: usize = @intCast(std.hash.Wyhash.hash(0, mask) & (table_len - 1));
    while (table[slot] != 0) : (slot = (slot + 1) & (table_len - 1)) {
        if (std.mem.eql(u8, seen[table[slot] - 1], mask)) return error.DuplicateEntry;
    }
    seen[index] = mask;
    table[slot] = @intCast(index + 1);
}

test "SHUN checkpoint retains order, expiry, and exact text" {
    const alloc = std.testing.allocator;
    var source = shun.ShunList.init(alloc, .{ .max_shuns = 5, .max_mask = 300, .max_reason = 13, .max_setter = 9 });
    defer source.deinit();
    try source.add(.{ .mask = "Bad!*@*", .reason = "r", .set_by = "Op", .created_ms = -8, .expires_ms = 2 });
    try source.add(.{ .mask = "bad!*@*", .reason = "", .set_by = "", .created_ms = 5, .expires_ms = 0 });
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decode(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqualDeep(source.params, restored.params);
    try std.testing.expectEqual(@as(usize, 2), restored.count());
    try std.testing.expectEqualStrings("Bad!*@*", restored.shuns.items[0].mask);
    try std.testing.expectEqual(@as(i64, -8), restored.shuns.items[0].created_ms);
    try std.testing.expectEqual(@as(i64, 2), restored.shuns.items[0].expires_ms);
    try std.testing.expectEqualStrings("bad!*@*", restored.shuns.items[1].mask);
    const again = try encode(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

test "SHUN checkpoint rejects malformed and duplicate masks" {
    const alloc = std.testing.allocator;
    var source = shun.ShunList.init(alloc, .{});
    defer source.deinit();
    try source.add(.{ .mask = "a", .reason = "", .set_by = "", .created_ms = 0 });
    try source.add(.{ .mask = "b", .reason = "", .set_by = "", .created_ms = 0 });
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    try std.testing.expectError(error.Truncated, validateCheckpoint(bytes[0 .. bytes.len - 1]));
    bad[header_len + 23 + 22] = 'a';
    rechecksum(bad);
    try std.testing.expectError(error.DuplicateEntry, validateCheckpoint(bad));
    bad[header_len + 23 + 22] = 'b';
    bad[header_len] = 0;
    bad[header_len + 1] = 0;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
}

test "SHUN checkpoint staged decode sweeps allocation failures" {
    const alloc = std.testing.allocator;
    var source = shun.ShunList.init(alloc, .{});
    defer source.deinit();
    try source.add(.{ .mask = "one", .reason = "reason", .set_by = "oper", .created_ms = 1 });
    try source.add(.{ .mask = "two", .reason = "", .set_by = "", .created_ms = 2 });
    const Encode = struct {
        fn run(a: std.mem.Allocator, s: *const shun.ShunList) !void {
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
