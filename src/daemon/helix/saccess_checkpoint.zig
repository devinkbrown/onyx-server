// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for IRCX server-level SACCESS policy. Physical entry
//! order is part of the decision rule: first matching DENY/GRANT/etc. wins.

const std = @import("std");
const saccess = @import("../../proto/ircx_saccess.zig");

pub const max_entries: usize = 4096;
pub const max_checkpoint_bytes: usize = 2 * 1024 * 1024;
pub const checkpoint_magic = [_]u8{ 'S', 'A', 'C', 'S' };
pub const checkpoint_version: u8 = 1;
const header_len: usize = 4 + 1 + 3 + 4 + 4 + 8;
const checksum_len: usize = 32;
const row_header_len: usize = 1 + 1 + 1 + 2 + 8;
const checksum_domain = "onyx-saccess-checkpoint-v1";
const identity_table_len = max_entries * 2;

comptime {
    if (max_entries > std.math.maxInt(u16) or max_checkpoint_bytes > std.math.maxInt(u32) or
        identity_table_len & (identity_table_len - 1) != 0)
        @compileError("SACCESS checkpoint exceeds wire or identity-index bounds");
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
    count: usize,
    max_entries_value: usize,
};

const Identity = struct {
    entry_type: saccess.EntryType,
    mask: []const u8,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Validate the full image without allocation. A fixed on-stack index rejects
/// case-insensitive duplicate identities while leaving physical order intact.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const header = try parseHeader(bytes);
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    var seen: [max_entries]Identity = undefined;
    var table: [identity_table_len]u16 = undefined;
    @memset(&table, 0);
    var seen_count: usize = 0;
    for (0..header.count) |_| {
        const entry = try readEntry(&reader);
        try insertIdentity(&table, &seen, &seen_count, .{ .entry_type = entry.entry_type, .mask = entry.mask });
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Seal the exact stored sequence, including absent versus present-empty
/// reasons, zero-valued optional durations, and the policy entry ceiling.
pub fn encode(allocator: std.mem.Allocator, store: *const saccess.ServerAccessStore) Error![]u8 {
    const count = store.entries.items.len;
    if (count > max_entries or count > store.max_entries) return error.CheckpointTooLarge;
    const max_entries_value = std.math.cast(u64, store.max_entries) orelse return error.CheckpointTooLarge;
    var total_len: usize = header_len + checksum_len;
    for (0..count) |index| {
        const entry = store.snapshotAt(index) orelse return error.InvalidField;
        saccess.validateStoredEntry(entry) catch return error.InvalidField;
        const reason_len = if (entry.reason) |reason| reason.len else 0;
        try addLen(&total_len, row_header_len + entry.mask.len + reason_len);
    }

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(checkpoint_version);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(total_len - header_len - checksum_len));
    writer.writeU32(@intCast(count));
    writer.writeU64(max_entries_value);
    for (0..count) |index| {
        const entry = store.snapshotAt(index).?;
        writer.writeByte(typeToWire(entry.entry_type));
        writer.writeByte(@as(u8, @intFromBool(entry.duration != null)) |
            (@as(u8, @intFromBool(entry.reason != null)) << 1));
        writer.writeByte(@intCast(entry.mask.len));
        writer.writeU16(@intCast(if (entry.reason) |reason| reason.len else 0));
        writer.writeU64(entry.duration orelse 0);
        writer.writeBytes(entry.mask);
        if (entry.reason) |reason| writer.writeBytes(reason);
    }
    std.debug.assert(writer.pos + checksum_len == out.len);
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(out[0..writer.pos], &digest);
    writer.writeBytes(&digest);
    try validateCheckpoint(out);
    return out;
}

/// Build a detached, fully owned store. The caller may swap it only after the
/// rest of the Helix image passes validation; OOM frees every staged row.
pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!saccess.ServerAccessStore {
    try validateCheckpoint(bytes);
    const header = try parseHeader(bytes);
    var restored = saccess.ServerAccessStore.initWith(allocator, header.max_entries_value);
    errdefer restored.deinit();
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (0..header.count) |_| {
        const entry = try readEntry(&reader);
        restored.add(entry) catch |err| switch (err) {
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
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    const max_entries_value = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .little)) orelse return error.CheckpointTooLarge;
    if (count > max_entries or body_len > max_checkpoint_bytes - header_len - checksum_len)
        return error.CheckpointTooLarge;
    if (count > max_entries_value) return error.InvalidField;
    if (count > body_len / row_header_len) return error.Truncated;
    const expected_len = header_len + body_len + checksum_len;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    const saved: [checksum_len]u8 = bytes[bytes.len - checksum_len ..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, saved)) return error.ChecksumMismatch;
    return .{ .count = count, .max_entries_value = max_entries_value };
}

fn readEntry(reader: *Reader) Error!saccess.Entry {
    const entry_type = wireToType(try reader.readByte()) orelse return error.InvalidField;
    const flags = try reader.readByte();
    if (flags & ~@as(u8, 3) != 0) return error.InvalidField;
    const mask_len: usize = try reader.readByte();
    const reason_len: usize = try reader.readU16();
    const duration_value = try reader.readU64();
    if (mask_len == 0 or mask_len > saccess.DEFAULT_MAX_MASK_BYTES or
        reason_len > saccess.DEFAULT_MAX_REASON_BYTES or
        (flags & 1 == 0 and duration_value != 0) or
        (flags & 2 == 0 and reason_len != 0)) return error.InvalidField;
    const mask = try reader.take(mask_len);
    const reason_bytes = try reader.take(reason_len);
    const entry = saccess.Entry{
        .entry_type = entry_type,
        .mask = mask,
        .duration = if (flags & 1 != 0) duration_value else null,
        .reason = if (flags & 2 != 0) reason_bytes else null,
    };
    saccess.validateStoredEntry(entry) catch return error.InvalidField;
    return entry;
}

fn typeToWire(entry_type: saccess.EntryType) u8 {
    return switch (entry_type) {
        .deny => 0,
        .gag => 1,
        .grant => 2,
        .nochannel => 3,
        .nonick => 4,
        .holdnick => 5,
    };
}

fn wireToType(value: u8) ?saccess.EntryType {
    return switch (value) {
        0 => .deny,
        1 => .gag,
        2 => .grant,
        3 => .nochannel,
        4 => .nonick,
        5 => .holdnick,
        else => null,
    };
}

fn insertIdentity(table: *[identity_table_len]u16, seen: *[max_entries]Identity, count: *usize, identity: Identity) Error!void {
    var slot = identityHash(identity) & (identity_table_len - 1);
    while (table[slot] != 0) : (slot = (slot + 1) & (identity_table_len - 1)) {
        const previous = seen[table[slot] - 1];
        if (previous.entry_type == identity.entry_type and std.ascii.eqlIgnoreCase(previous.mask, identity.mask))
            return error.DuplicateIdentity;
    }
    seen[count.*] = identity;
    table[slot] = @intCast(count.* + 1);
    count.* += 1;
}

fn identityHash(identity: Identity) usize {
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    hash = (hash ^ @as(u64, typeToWire(identity.entry_type))) *% 0x100_0000_01b3;
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
    fn take(self: *Reader, amount: usize) Error![]const u8 {
        if (amount > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..amount];
        self.pos += amount;
        return result;
    }
    fn readByte(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }
    fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
};

fn reseal(bytes: []u8) void {
    var digest: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}

test "SACCESS checkpoint preserves physical match order and nullable values" {
    var source = saccess.ServerAccessStore.initWith(std.testing.allocator, 777);
    defer source.deinit();
    try source.add(.{ .entry_type = .deny, .mask = "*!*@host", .duration = 0, .reason = "" });
    try source.add(.{ .entry_type = .deny, .mask = "bad*", .duration = null, .reason = null });
    try source.add(.{ .entry_type = .holdnick, .mask = "Nick*", .duration = 42, .reason = "held" });
    const wire = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(wire);
    try validateCheckpoint(wire);
    var restored = try decodeOwned(std.testing.allocator, wire);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 777), restored.max_entries);
    try std.testing.expectEqual(@as(usize, 3), restored.entries.items.len);
    const first = restored.snapshotAt(0).?;
    try std.testing.expectEqualStrings("*!*@host", first.mask);
    try std.testing.expectEqual(@as(?u64, 0), first.duration);
    try std.testing.expect(first.reason != null and first.reason.?.len == 0);
    const second = restored.snapshotAt(1).?;
    try std.testing.expectEqualStrings("bad*", second.mask);
    try std.testing.expect(second.duration == null and second.reason == null);
    const matched = restored.matchHostmask(.deny, "bad!x@host") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(first.mask, matched.mask);
    try std.testing.expectEqualStrings("Nick*", restored.snapshotAt(2).?.mask);
}

test "SACCESS source replacement keeps first-match position and spelling" {
    var source = saccess.ServerAccessStore.initWith(std.testing.allocator, 3);
    defer source.deinit();
    try source.add(.{ .entry_type = .deny, .mask = "Bad*", .reason = "old" });
    try source.add(.{ .entry_type = .deny, .mask = "Other*", .reason = "other" });
    try source.add(.{ .entry_type = .deny, .mask = "bAd*", .reason = "new" });
    try std.testing.expectEqual(@as(usize, 2), source.entries.items.len);
    const wire = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(wire);
    var restored = try decodeOwned(std.testing.allocator, wire);
    defer restored.deinit();
    try std.testing.expectEqualStrings("Bad*", restored.snapshotAt(0).?.mask);
    try std.testing.expectEqualStrings("new", restored.snapshotAt(0).?.reason.?);
    try std.testing.expectEqualStrings("Other*", restored.snapshotAt(1).?.mask);
}

test "SACCESS checkpoint rejects malformed rows and duplicate identities" {
    var source = saccess.ServerAccessStore.initWith(std.testing.allocator, 2);
    defer source.deinit();
    try source.add(.{ .entry_type = .deny, .mask = "A*" });
    try source.add(.{ .entry_type = .deny, .mask = "b*" });
    const wire = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(wire);
    try std.testing.expectError(error.Truncated, validateCheckpoint(wire[0 .. wire.len - 1]));
    const extra = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(extra);
    @memcpy(extra[0..wire.len], wire);
    extra[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateCheckpoint(extra));
    var bad = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad);
    bad[0] = 'X';
    try std.testing.expectError(error.BadMagic, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[24] = 9;
    reseal(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[25] = 0x80;
    reseal(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[26] = 0;
    reseal(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[52] = 'a'; // second two-byte mask becomes the first identity, ignoring case
    reseal(bad);
    try std.testing.expectError(error.DuplicateIdentity, validateCheckpoint(bad));
    @memcpy(bad, wire);
    bad[24] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));
    @memcpy(bad, wire);
    std.mem.writeInt(u64, bad[16..24], 1, .little);
    reseal(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
}

test "SACCESS checkpoint encode and detached decode survive every allocation failure" {
    var source = saccess.ServerAccessStore.initWith(std.testing.allocator, 8);
    defer source.deinit();
    try source.add(.{ .entry_type = .deny, .mask = "*!*@host", .duration = 0, .reason = "" });
    try source.add(.{ .entry_type = .grant, .mask = "trusted*", .reason = "trusted" });
    const wire = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(wire);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, store: *const saccess.ServerAccessStore) !void {
            const bytes = try encode(allocator, store);
            defer allocator.free(bytes);
            try validateCheckpoint(bytes);
        }
    };
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var restored = try decodeOwned(allocator, bytes);
            defer restored.deinit();
            try std.testing.expectEqual(@as(usize, 2), restored.entries.items.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, DecodeSweep.run, .{wire});
    try std.testing.expectEqual(@as(usize, 2), source.entries.items.len);
}
