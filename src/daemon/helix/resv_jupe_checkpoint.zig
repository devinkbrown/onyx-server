// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for live channel RESV and server JUPE policy.
//! Entries retain physical first-match order, including unswept expired rows.

const std = @import("std");
const svc_resv = @import("../svc_resv.zig");
const svc_jupe = @import("../svc_jupe.zig");

pub const max_entries: usize = 4096;
pub const max_checkpoint_bytes: usize = 8 * 1024 * 1024;
const header_len: usize = 4 + 1 + 3 + 4 + 4 + 4 * 8;
const row_header_len: usize = 3 * 4 + 2 * 8;
const checksum_len: usize = 32;
const identity_table_len = max_entries * 2;

comptime {
    if (max_entries > std.math.maxInt(u16) or max_checkpoint_bytes > std.math.maxInt(u32) or
        identity_table_len & (identity_table_len - 1) != 0)
        @compileError("RESV/JUPE checkpoint exceeds wire or identity-index bounds");
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

const Kind = enum { channel, server };
pub const channel = Codec(.channel);
pub const server = Codec(.server);

const Row = struct {
    pattern: []const u8,
    reason: []const u8,
    setter: []const u8,
    created_ms: i64,
    expires_ms: i64,
};

fn Codec(comptime kind: Kind) type {
    const Store = if (kind == .channel) svc_resv.ChannelResv else svc_jupe.JupeStore;
    const Params = if (kind == .channel) svc_resv.Params else svc_jupe.Params;
    const magic = if (kind == .channel) [_]u8{ 'C', 'R', 'E', 'S' } else [_]u8{ 'S', 'J', 'U', 'P' };
    const checksum_domain = if (kind == .channel) "onyx-channel-resv-checkpoint-v1" else "onyx-server-jupe-checkpoint-v1";

    return struct {
        pub const checkpoint_magic = magic;
        pub const checkpoint_version: u8 = 1;

        const Header = struct {
            count: usize,
            params: Params,
        };

        pub fn isCheckpoint(bytes: []const u8) bool {
            return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
        }

        /// Validate every row and duplicate identity using fixed stack storage.
        /// No allocation or mutation occurs before the caller stages adoption.
        pub fn validateCheckpoint(bytes: []const u8) Error!void {
            const header = try parseHeader(bytes);
            var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
            var seen: [max_entries][]const u8 = undefined;
            var table: [identity_table_len]u16 = undefined;
            @memset(&table, 0);
            var seen_count: usize = 0;
            for (0..header.count) |_| {
                const row = try readRow(&reader, header.params);
                try insertIdentity(&table, &seen, &seen_count, row.pattern);
            }
            if (reader.remaining() != 0) return error.TrailingBytes;
        }

        /// Seal the exact stored sequence and all four configuration ceilings.
        pub fn encode(allocator: std.mem.Allocator, store: *const Store) Error![]u8 {
            const count = rowCount(store);
            if (count > max_entries or count > maxCount(store.params)) return error.CheckpointTooLarge;
            var total_len: usize = header_len + checksum_len;
            for (0..count) |index| {
                const row = rowAt(store, index);
                try validateRow(store.params, row);
                try addLen(&total_len, row_header_len);
                try addLen(&total_len, row.pattern.len);
                try addLen(&total_len, row.reason.len);
                try addLen(&total_len, row.setter.len);
            }

            const out = try allocator.alloc(u8, total_len);
            errdefer allocator.free(out);
            var writer = Writer{ .bytes = out };
            writer.writeBytes(&checkpoint_magic);
            writer.writeByte(checkpoint_version);
            writer.writeBytes(&.{ 0, 0, 0 });
            writer.writeU32(@intCast(total_len - header_len - checksum_len));
            writer.writeU32(@intCast(count));
            try writeParams(&writer, store.params);
            for (0..count) |index| {
                const row = rowAt(store, index);
                writer.writeU32(@intCast(row.pattern.len));
                writer.writeU32(@intCast(row.reason.len));
                writer.writeU32(@intCast(row.setter.len));
                writer.writeI64(row.created_ms);
                writer.writeI64(row.expires_ms);
                writer.writeBytes(row.pattern);
                writer.writeBytes(row.reason);
                writer.writeBytes(row.setter);
            }
            std.debug.assert(writer.pos + checksum_len == out.len);
            var digest: [checksum_len]u8 = undefined;
            checkpointChecksum(out[0..writer.pos], &digest);
            writer.writeBytes(&digest);
            try validateCheckpoint(out);
            return out;
        }

        /// Decode into a detached owner. Adoption can swap this store only after
        /// all image validation and candidate configuration checks succeed.
        pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!Store {
            try validateCheckpoint(bytes);
            const header = try parseHeader(bytes);
            var restored = Store.init(allocator, header.params);
            errdefer restored.deinit();
            var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
            for (0..header.count) |_| {
                const row = try readRow(&reader, header.params);
                if (kind == .channel) {
                    restored.add(.{
                        .pattern = row.pattern,
                        .reason = row.reason,
                        .set_by = row.setter,
                        .created_ms = row.created_ms,
                        .expires_ms = row.expires_ms,
                    }) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.InvalidField,
                    };
                } else {
                    restored.add(row.pattern, row.reason, row.setter, row.created_ms, row.expires_ms) catch |err| switch (err) {
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
            const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
            if (count > max_entries or body_len > max_checkpoint_bytes - header_len - checksum_len)
                return error.CheckpointTooLarge;
            if (count > body_len / row_header_len) return error.Truncated;
            const expected_len = header_len + body_len + checksum_len;
            if (bytes.len < expected_len) return error.Truncated;
            if (bytes.len > expected_len) return error.TrailingBytes;
            var digest: [checksum_len]u8 = undefined;
            checkpointChecksum(bytes[0 .. bytes.len - checksum_len], &digest);
            const saved: [checksum_len]u8 = bytes[bytes.len - checksum_len ..][0..checksum_len].*;
            if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, saved)) return error.ChecksumMismatch;
            const params = try readParams(bytes[16..header_len]);
            if (count > maxCount(params)) return error.InvalidField;
            return .{ .count = count, .params = params };
        }

        fn readRow(reader: *Reader, params: Params) Error!Row {
            const pattern_len: usize = try reader.readU32();
            const reason_len: usize = try reader.readU32();
            const setter_len: usize = try reader.readU32();
            const created_ms = try reader.readI64();
            const expires_ms = try reader.readI64();
            const row = Row{
                .pattern = try reader.take(pattern_len),
                .reason = try reader.take(reason_len),
                .setter = try reader.take(setter_len),
                .created_ms = created_ms,
                .expires_ms = expires_ms,
            };
            try validateRow(params, row);
            return row;
        }

        fn rowCount(store: *const Store) usize {
            return if (kind == .channel) store.reservations.items.len else store.entries.items.len;
        }

        fn rowAt(store: *const Store, index: usize) Row {
            if (kind == .channel) {
                const row = store.reservations.items[index];
                return .{ .pattern = row.pattern, .reason = row.reason, .setter = row.set_by, .created_ms = row.created_ms, .expires_ms = row.expires_ms };
            } else {
                const row = store.entries.items[index];
                return .{ .pattern = row.pattern, .reason = row.reason, .setter = row.setter, .created_ms = row.created_ms, .expires_ms = row.expires_ms };
            }
        }

        fn validateRow(params: Params, row: Row) Error!void {
            if (kind == .channel) {
                svc_resv.validateStoredEntry(params, .{
                    .pattern = row.pattern,
                    .reason = row.reason,
                    .set_by = row.setter,
                    .created_ms = row.created_ms,
                    .expires_ms = row.expires_ms,
                }) catch return error.InvalidField;
            } else {
                svc_jupe.validateStoredEntry(params, .{
                    .pattern = row.pattern,
                    .reason = row.reason,
                    .setter = row.setter,
                    .created_ms = row.created_ms,
                    .expires_ms = row.expires_ms,
                }) catch return error.InvalidField;
            }
        }

        fn maxCount(params: Params) usize {
            return if (kind == .channel) params.max_resvs else params.max_entries;
        }

        fn writeParams(writer: *Writer, params: Params) Error!void {
            writer.writeU64(std.math.cast(u64, maxCount(params)) orelse return error.CheckpointTooLarge);
            writer.writeU64(std.math.cast(u64, params.max_pattern) orelse return error.CheckpointTooLarge);
            writer.writeU64(std.math.cast(u64, params.max_reason) orelse return error.CheckpointTooLarge);
            writer.writeU64(std.math.cast(u64, params.max_setter) orelse return error.CheckpointTooLarge);
        }

        fn readParams(bytes: []const u8) Error!Params {
            const max_count = std.math.cast(usize, std.mem.readInt(u64, bytes[0..8], .little)) orelse return error.InvalidField;
            const max_pattern = std.math.cast(usize, std.mem.readInt(u64, bytes[8..16], .little)) orelse return error.InvalidField;
            const max_reason = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .little)) orelse return error.InvalidField;
            const max_setter = std.math.cast(usize, std.mem.readInt(u64, bytes[24..32], .little)) orelse return error.InvalidField;
            if (kind == .channel) {
                return .{ .max_resvs = max_count, .max_pattern = max_pattern, .max_reason = max_reason, .max_setter = max_setter };
            } else {
                return .{ .max_entries = max_count, .max_pattern = max_pattern, .max_reason = max_reason, .max_setter = max_setter };
            }
        }

        fn insertIdentity(table: *[identity_table_len]u16, seen: *[max_entries][]const u8, count: *usize, pattern: []const u8) Error!void {
            var slot = identityHash(pattern) & (identity_table_len - 1);
            while (table[slot] != 0) : (slot = (slot + 1) & (identity_table_len - 1)) {
                const previous = seen[table[slot] - 1];
                const duplicate = if (kind == .channel) std.ascii.eqlIgnoreCase(previous, pattern) else std.mem.eql(u8, previous, pattern);
                if (duplicate) return error.DuplicateIdentity;
            }
            seen[count.*] = pattern;
            table[slot] = @intCast(count.* + 1);
            count.* += 1;
        }

        fn identityHash(pattern: []const u8) usize {
            var hash: u64 = 0xcbf2_9ce4_8422_2325;
            for (pattern) |byte| {
                const key = if (kind == .channel) std.ascii.toLower(byte) else byte;
                hash = (hash ^ key) *% 0x100_0000_01b3;
            }
            return @intCast(hash);
        }

        fn checkpointChecksum(bytes: []const u8, out: *[checksum_len]u8) void {
            var hasher = std.crypto.hash.Blake3.init(.{});
            hasher.update(checksum_domain);
            hasher.update(bytes);
            hasher.final(out);
        }
    };
}

fn addLen(total: *usize, amount: usize) Error!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
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
    fn writeU64(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }
    fn writeI64(self: *Writer, value: i64) void {
        self.writeU64(@bitCast(value));
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
    fn readU32(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
    fn readI64(self: *Reader) Error!i64 {
        return @bitCast(try self.readU64());
    }
};

fn reseal(comptime kind: Kind, bytes: []u8) void {
    const domain = if (kind == .channel) "onyx-channel-resv-checkpoint-v1" else "onyx-server-jupe-checkpoint-v1";
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(domain);
    hasher.update(bytes[0 .. bytes.len - checksum_len]);
    var digest: [checksum_len]u8 = undefined;
    hasher.final(&digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}

test "RESV/JUPE checkpoint preserves channel order, exact times, and params" {
    var source = svc_resv.ChannelResv.init(std.testing.allocator, .{ .max_resvs = 5, .max_pattern = 22, .max_reason = 32, .max_setter = 16 });
    defer source.deinit();
    try source.add(.{ .pattern = "#bad*", .reason = "broad", .set_by = "Oper", .created_ms = -9, .expires_ms = 0 });
    try source.add(.{ .pattern = "#bad?", .reason = "specific", .set_by = "Admin", .created_ms = 10, .expires_ms = 999 });
    try source.add(.{ .pattern = "&expired", .reason = "", .set_by = "", .created_ms = 2, .expires_ms = 3 });
    const wire = try channel.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(wire);
    try channel.validateCheckpoint(wire);
    var restored = try channel.decodeOwned(std.testing.allocator, wire);
    defer restored.deinit();
    try std.testing.expect(std.meta.eql(source.params, restored.params));
    try std.testing.expectEqual(@as(usize, 3), restored.count());
    var rows: [3]svc_resv.Reservation = undefined;
    const entries = restored.list(&rows);
    try std.testing.expectEqualStrings("#bad*", entries[0].pattern);
    try std.testing.expectEqual(@as(i64, -9), entries[0].created_ms);
    try std.testing.expectEqualStrings("#bad?", entries[1].pattern);
    try std.testing.expectEqual(@as(i64, 999), entries[1].expires_ms);
    try std.testing.expectEqualStrings("", entries[2].set_by);
    try std.testing.expectEqual(@as(i64, 3), entries[2].expires_ms);
    try std.testing.expectEqualStrings("broad", restored.match("#badx", 1).?.reason);
}

test "RESV/JUPE checkpoint retains exact-identity server case variants and first match" {
    var source = svc_jupe.JupeStore.init(std.testing.allocator, .{ .max_entries = 7, .max_pattern = 30, .max_reason = 30, .max_setter = 16 });
    defer source.deinit();
    try source.add("*.Example", "first", "Oper", -1, 0);
    try source.add("*.example", "second", "Admin", 2, 99);
    try source.add("gone.example", "expired but unswept", "", 3, 4);
    const wire = try server.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(wire);
    var restored = try server.decodeOwned(std.testing.allocator, wire);
    defer restored.deinit();
    try std.testing.expect(std.meta.eql(source.params, restored.params));
    try std.testing.expectEqual(@as(usize, 3), restored.count());
    var rows: [3]svc_jupe.Entry = undefined;
    const entries = restored.list(&rows);
    try std.testing.expectEqualStrings("*.Example", entries[0].pattern);
    try std.testing.expectEqualStrings("*.example", entries[1].pattern);
    try std.testing.expectEqual(@as(i64, 4), entries[2].expires_ms);
    try std.testing.expectEqualStrings("first", restored.isJuped("x.example", 1).?.reason);
}

test "RESV/JUPE checkpoint rejects corruption, duplicate identity, and invalid limits" {
    var channels = svc_resv.ChannelResv.init(std.testing.allocator, .{});
    defer channels.deinit();
    try channels.add(.{ .pattern = "#a", .reason = "r", .set_by = "s", .created_ms = 1 });
    try channels.add(.{ .pattern = "#b", .reason = "r", .set_by = "s", .created_ms = 2 });
    const channel_wire = try channel.encode(std.testing.allocator, &channels);
    defer std.testing.allocator.free(channel_wire);
    try std.testing.expectError(error.Truncated, channel.validateCheckpoint(channel_wire[0 .. channel_wire.len - 1]));
    var altered = try std.testing.allocator.dupe(u8, channel_wire);
    defer std.testing.allocator.free(altered);
    altered[0] = 'X';
    try std.testing.expectError(error.BadMagic, channel.validateCheckpoint(altered));
    @memcpy(altered, channel_wire);
    altered[header_len + 28 + 2 + 1 + 1 + 28 + 1] = 'A'; // second pattern becomes #A
    reseal(.channel, altered);
    try std.testing.expectError(error.DuplicateIdentity, channel.validateCheckpoint(altered));
    @memcpy(altered, channel_wire);
    std.mem.writeInt(u64, altered[16..24], 1, .little);
    reseal(.channel, altered);
    try std.testing.expectError(error.InvalidField, channel.validateCheckpoint(altered));
    @memcpy(altered, channel_wire);
    altered[header_len] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, channel.validateCheckpoint(altered));

    var jupes = svc_jupe.JupeStore.init(std.testing.allocator, .{});
    defer jupes.deinit();
    try jupes.add("a", "r", "s", 1, 0);
    try jupes.add("b", "r", "s", 2, 0);
    const jupe_wire = try server.encode(std.testing.allocator, &jupes);
    defer std.testing.allocator.free(jupe_wire);
    var changed = try std.testing.allocator.dupe(u8, jupe_wire);
    defer std.testing.allocator.free(changed);
    changed[header_len + 28 + 1 + 1 + 1 + 28] = 'a';
    reseal(.server, changed);
    try std.testing.expectError(error.DuplicateIdentity, server.validateCheckpoint(changed));
    @memcpy(changed, jupe_wire);
    changed[header_len + 28] = ' ';
    reseal(.server, changed);
    try std.testing.expectError(error.InvalidField, server.validateCheckpoint(changed));
}

test "RESV/JUPE checkpoint detached decode survives every allocation failure" {
    var channels = svc_resv.ChannelResv.init(std.testing.allocator, .{});
    defer channels.deinit();
    try channels.add(.{ .pattern = "#one", .reason = "first", .set_by = "oper", .created_ms = 1 });
    try channels.add(.{ .pattern = "#two", .reason = "second", .set_by = "admin", .created_ms = 2 });
    const ChannelEncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, store: *const svc_resv.ChannelResv) !void {
            const bytes = try channel.encode(allocator, store);
            defer allocator.free(bytes);
            try channel.validateCheckpoint(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ChannelEncodeSweep.run, .{&channels});
    const channel_wire = try channel.encode(std.testing.allocator, &channels);
    defer std.testing.allocator.free(channel_wire);
    const ChannelSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var restored = try channel.decodeOwned(allocator, bytes);
            defer restored.deinit();
            try std.testing.expectEqual(@as(usize, 2), restored.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ChannelSweep.run, .{channel_wire});
    try std.testing.expectEqual(@as(usize, 2), channels.count());

    var jupes = svc_jupe.JupeStore.init(std.testing.allocator, .{});
    defer jupes.deinit();
    try jupes.add("one.*", "first", "oper", 1, 0);
    try jupes.add("two.*", "second", "admin", 2, 3);
    const JupeEncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, store: *const svc_jupe.JupeStore) !void {
            const bytes = try server.encode(allocator, store);
            defer allocator.free(bytes);
            try server.validateCheckpoint(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, JupeEncodeSweep.run, .{&jupes});
    const jupe_wire = try server.encode(std.testing.allocator, &jupes);
    defer std.testing.allocator.free(jupe_wire);
    const JupeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var restored = try server.decodeOwned(allocator, bytes);
            defer restored.deinit();
            try std.testing.expectEqual(@as(usize, 2), restored.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, JupeSweep.run, .{jupe_wire});
    try std.testing.expectEqual(@as(usize, 2), jupes.count());
}
