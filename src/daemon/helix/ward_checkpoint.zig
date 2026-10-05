// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for Warden policy. Physical Ward order is retained:
//! Registry.check returns the first active matching row.

const std = @import("std");
const warden = @import("../warden.zig");

pub const max_wards: usize = 4096;
pub const max_text_bytes: usize = 65_535;
pub const max_checkpoint_bytes: usize = 256 * 1024 * 1024;
pub const checkpoint_magic = [_]u8{ 'W', 'A', 'R', 'D' };
pub const checkpoint_version: u8 = 1;
const header_len: usize = 4 + 1 + 3 + 4 + 2 + 2 + 2 + 2 + 2 + 2;
const checksum_len: usize = 32;
const row_min_len: usize = 3 + 2 + 2 + 2 + 8 + 8 + 1;
const checksum_domain = "onyx-ward-checkpoint-v1";
const identity_table_len = max_wards * 2;

comptime {
    if (max_wards > std.math.maxInt(u16) or max_text_bytes > std.math.maxInt(u16) or
        max_checkpoint_bytes > std.math.maxInt(u32) or
        identity_table_len & (identity_table_len - 1) != 0)
        @compileError("WARD checkpoint exceeds wire/index bounds");
}

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    DuplicateWard,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

const Header = struct {
    count: usize,
    params: warden.Params,
};

const Identity = struct {
    match: warden.Match,
    pattern: []const u8,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Full structural and duplicate validation in bounded stack space. Expired
/// rows are retained; the successor must see the same state and clock inputs.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const header = try parseHeader(bytes);
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    var identities: [max_wards]Identity = undefined;
    var table: [identity_table_len]u16 = undefined;
    @memset(&table, 0);
    for (0..header.count) |index| {
        const ward = try readWard(&reader, header.params);
        try insertIdentity(&table, &identities, index, .{ .match = ward.match, .pattern = ward.pattern });
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Export every policy row and all Registry limits. A source beyond the wire
/// or arena bound fails explicitly; no active ban is silently dropped.
pub fn encode(allocator: std.mem.Allocator, registry: *const warden.Registry) Error![]u8 {
    const params = registry.params;
    const count = registry.wards.items.len;
    if (params.max_wards > max_wards or params.max_pattern > max_text_bytes or
        params.max_reason > max_text_bytes or params.max_setter > max_text_bytes or
        count > params.max_wards)
        return error.CheckpointTooLarge;
    var total_len: usize = header_len + checksum_len;
    for (registry.wards.items) |ward| {
        if (ward.pattern.len == 0 or ward.pattern.len > params.max_pattern or
            ward.reason.len > params.max_reason or ward.set_by.len > params.max_setter)
            return error.InvalidField;
        try addLen(&total_len, 3 + 2 + 2 + 2 + 8 + 8 + ward.pattern.len + ward.reason.len + ward.set_by.len);
    }
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(checkpoint_version);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(total_len - header_len - checksum_len));
    writer.writeU16(@intCast(count));
    writer.writeU16(@intCast(params.max_wards));
    writer.writeU16(@intCast(params.max_pattern));
    writer.writeU16(@intCast(params.max_reason));
    writer.writeU16(@intCast(params.max_setter));
    writer.writeU16(0);
    for (registry.wards.items) |ward| {
        writer.writeByte(@intFromEnum(ward.match));
        writer.writeByte(@intFromEnum(ward.scope));
        writer.writeByte(@intFromEnum(ward.action));
        writer.writeU16(@intCast(ward.pattern.len));
        writer.writeU16(@intCast(ward.reason.len));
        writer.writeU16(@intCast(ward.set_by.len));
        writer.writeI64(ward.created_ms);
        writer.writeI64(ward.expires_ms);
        writer.writeBytes(ward.pattern);
        writer.writeBytes(ward.reason);
        writer.writeBytes(ward.set_by);
    }
    std.debug.assert(writer.pos + checksum_len == out.len);
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(out[0..writer.pos], &digest);
    writer.writeBytes(&digest);
    try validateCheckpoint(out);
    return out;
}

/// Detached, owned Registry for pre-COMMIT staging and a no-fail whole-store
/// swap. Failed allocations deinitialize the staged rows only.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!warden.Registry {
    const header = try parseHeader(bytes);
    try validateCheckpoint(bytes);
    var restored = warden.Registry.init(allocator, header.params);
    errdefer restored.deinit();
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (0..header.count) |_| {
        const ward = try readWard(&reader, header.params);
        restored.add(ward) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
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
    if (std.mem.readInt(u16, bytes[22..24], .little) != 0) return error.InvalidField;
    const header = Header{
        .count = std.mem.readInt(u16, bytes[12..14], .little),
        .params = .{
            .max_wards = std.mem.readInt(u16, bytes[14..16], .little),
            .max_pattern = std.mem.readInt(u16, bytes[16..18], .little),
            .max_reason = std.mem.readInt(u16, bytes[18..20], .little),
            .max_setter = std.mem.readInt(u16, bytes[20..22], .little),
        },
    };
    if (header.params.max_wards > max_wards or header.count > header.params.max_wards)
        return error.CheckpointTooLarge;
    if (body_len < header.count * row_min_len) return error.Truncated;
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    const saved: [checksum_len]u8 = bytes[bytes.len - checksum_len ..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, saved)) return error.ChecksumMismatch;
    return header;
}

fn readWard(reader: *Reader, params: warden.Params) Error!warden.Ward {
    const match = std.enums.fromInt(warden.Match, try reader.readByte()) orelse return error.InvalidField;
    const scope = std.enums.fromInt(warden.Scope, try reader.readByte()) orelse return error.InvalidField;
    const action = std.enums.fromInt(warden.Action, try reader.readByte()) orelse return error.InvalidField;
    const pattern_len: usize = try reader.readU16();
    const reason_len: usize = try reader.readU16();
    const setter_len: usize = try reader.readU16();
    if (pattern_len == 0 or pattern_len > params.max_pattern or
        reason_len > params.max_reason or setter_len > params.max_setter)
        return error.InvalidField;
    const created_ms = try reader.readI64();
    const expires_ms = try reader.readI64();
    const pattern = try reader.take(pattern_len);
    const reason = try reader.take(reason_len);
    const set_by = try reader.take(setter_len);
    return .{ .match = match, .pattern = pattern, .scope = scope, .action = action, .reason = reason, .set_by = set_by, .created_ms = created_ms, .expires_ms = expires_ms };
}

fn insertIdentity(table: *[identity_table_len]u16, seen: *[max_wards]Identity, count: usize, identity: Identity) Error!void {
    var slot: usize = @intCast(identityHash(identity) & (identity_table_len - 1));
    while (table[slot] != 0) : (slot = (slot + 1) & (identity_table_len - 1)) {
        const prior = seen[table[slot] - 1];
        if (prior.match == identity.match and std.mem.eql(u8, prior.pattern, identity.pattern)) return error.DuplicateWard;
    }
    seen[count] = identity;
    table[slot] = @intCast(count + 1);
}

fn identityHash(identity: Identity) u64 {
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    hash = (hash ^ @as(u64, @intFromEnum(identity.match))) *% 0x100_0000_01b3;
    for (identity.pattern) |byte| hash = (hash ^ byte) *% 0x100_0000_01b3;
    return hash;
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

test "WARD checkpoint preserves physical order params and signed timers" {
    const alloc = std.testing.allocator;
    var source = warden.Registry.init(alloc, .{ .max_wards = 5, .max_pattern = 40, .max_reason = 40, .max_setter = 20 });
    defer source.deinit();
    try source.add(.{ .match = .host, .pattern = "*.example", .scope = .mesh, .action = .refuse, .reason = "wide", .set_by = "Oper", .created_ms = -42, .expires_ms = 0 });
    try source.add(.{ .match = .host, .pattern = "Bad.Example", .scope = .node, .action = .expel, .reason = "specific", .set_by = "Other", .created_ms = 10, .expires_ms = 900 });
    try source.add(.{ .match = .host, .pattern = "bad.example", .scope = .mesh, .action = .quarantine, .reason = "case-distinct", .set_by = "Peer", .created_ms = 11, .expires_ms = 901 });
    try source.add(.{ .match = .account, .pattern = "alice*", .scope = .node, .action = .require_auth, .reason = "", .set_by = "", .created_ms = 12, .expires_ms = -1 });
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    var restored = try decode(alloc, wire);
    defer restored.deinit();
    try std.testing.expectEqualDeep(source.params, restored.params);
    try std.testing.expectEqual(source.count(), restored.count());
    for (source.all(), restored.all()) |a, b| {
        try std.testing.expectEqual(a.match, b.match);
        try std.testing.expectEqual(a.scope, b.scope);
        try std.testing.expectEqual(a.action, b.action);
        try std.testing.expectEqualStrings(a.pattern, b.pattern);
        try std.testing.expectEqualStrings(a.reason, b.reason);
        try std.testing.expectEqualStrings(a.set_by, b.set_by);
        try std.testing.expectEqual(a.created_ms, b.created_ms);
        try std.testing.expectEqual(a.expires_ms, b.expires_ms);
        try std.testing.expect(@intFromPtr(a.pattern.ptr) != @intFromPtr(b.pattern.ptr));
    }
    const reencoded = try encode(alloc, &restored);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);
    try std.testing.expectEqualStrings("wide", restored.check(.{ .host = "bad.example" }, 100).?.reason);
    try std.testing.expect(restored.find(.host, "Bad.Example") != null);
    try std.testing.expect(restored.find(.host, "bad.example") != null);

    var empty = warden.Registry.init(alloc, .{ .max_wards = 0, .max_pattern = 0, .max_reason = 0, .max_setter = 0 });
    defer empty.deinit();
    const empty_wire = try encode(alloc, &empty);
    defer alloc.free(empty_wire);
    var empty_restored = try decode(alloc, empty_wire);
    defer empty_restored.deinit();
    try std.testing.expectEqualDeep(empty.params, empty_restored.params);
    try std.testing.expectEqual(@as(usize, 0), empty_restored.count());
}

test "WARD checkpoint rejects malformed rows duplicates and config" {
    const alloc = std.testing.allocator;
    var source = warden.Registry.init(alloc, .{});
    defer source.deinit();
    try source.add(.{ .match = .host, .pattern = "a.example", .reason = "r", .set_by = "s" });
    try source.add(.{ .match = .host, .pattern = "b.example", .reason = "r", .set_by = "s" });
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    var bad = try alloc.dupe(u8, wire);
    defer alloc.free(bad);

    try std.testing.expect(!isCheckpoint("wrong"));
    try std.testing.expectError(error.Truncated, validateCheckpoint(wire[0 .. wire.len - 1]));
    bad[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[header_len + 25] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));

    const row_len = 3 + 2 + 2 + 2 + 8 + 8 + "a.example".len + 1 + 1;
    @memcpy(bad, wire);
    bad[header_len + row_len + 25] = 'a';
    testRechecksum(bad);
    try std.testing.expectError(error.DuplicateWard, validateCheckpoint(bad));

    @memcpy(bad, wire);
    bad[header_len] = 255;
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u16, bad[header_len + 3 ..][0..2], 0, .little);
    testRechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u16, bad[14..16], 1, .little);
    testRechecksum(bad);
    try std.testing.expectError(error.CheckpointTooLarge, validateCheckpoint(bad));

    @memcpy(bad, wire);
    std.mem.writeInt(u16, bad[22..24], 1, .little);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    const trailing = try alloc.alloc(u8, wire.len + 1);
    defer alloc.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));
}

test "WARD checkpoint staged decode sweeps allocation failures" {
    const alloc = std.testing.allocator;
    var source = warden.Registry.init(alloc, .{});
    defer source.deinit();
    try source.add(.{ .match = .mask, .pattern = "bad!*@*", .scope = .mesh, .action = .expel, .reason = "reason", .set_by = "oper", .created_ms = 1, .expires_ms = 100 });
    try source.add(.{ .match = .country, .pattern = "RU", .scope = .node, .action = .require_auth, .reason = "", .set_by = "", .created_ms = 2, .expires_ms = 0 });
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, registry: *const warden.Registry) !void {
            const bytes = try encode(allocator, registry);
            defer allocator.free(bytes);
            try validateCheckpoint(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, EncodeSweep.run, .{&source});
    const wire = try encode(alloc, &source);
    defer alloc.free(wire);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var current = warden.Registry.init(allocator, .{});
            defer current.deinit();
            try current.add(.{ .match = .host, .pattern = "keeper.example", .reason = "keep" });
            var staged = decode(allocator, bytes) catch |err| {
                try std.testing.expectEqual(@as(usize, 1), current.count());
                try std.testing.expect(current.find(.host, "keeper.example") != null);
                return err;
            };
            std.mem.swap(warden.Registry, &current, &staged);
            staged.deinit();
            try std.testing.expectEqual(@as(usize, 2), current.count());
            try std.testing.expect(current.find(.host, "keeper.example") == null);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, DecodeSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}
