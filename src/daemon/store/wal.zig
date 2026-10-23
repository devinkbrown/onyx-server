// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical WAL/snapshot record codecs. No live store or namespace ownership.

const std = @import("std");
const BatchMutation = @import("contracts.zig").BatchMutation;
const CoverageSlot = @import("contracts.zig").CoverageSlot;
const Family = @import("contracts.zig").Family;
const MutationKind = @import("contracts.zig").MutationKind;
const SnapshotCoverage = @import("contracts.zig").SnapshotCoverage;
const StoreError = @import("contracts.zig").StoreError;
const batch_format_version = @import("contracts.zig").batch_format_version;
const batch_guard_len = @import("contracts.zig").batch_guard_len;
const cold_epoch_record_len = @import("contracts.zig").cold_epoch_record_len;
const decodeFamily = @import("contracts.zig").decodeFamily;
const max_batch_mutations = @import("contracts.zig").max_batch_mutations;
const meta_kind_batch = @import("contracts.zig").meta_kind_batch;
const meta_kind_batch_format = @import("contracts.zig").meta_kind_batch_format;
const meta_kind_next_seq = @import("contracts.zig").meta_kind_next_seq;
const meta_kind_snapshot_coverage = @import("contracts.zig").meta_kind_snapshot_coverage;
const meta_kind_wal_epoch = @import("contracts.zig").meta_kind_wal_epoch;
const meta_next_seq_payload_len = @import("contracts.zig").meta_next_seq_payload_len;
const payload_header_len = @import("contracts.zig").payload_header_len;
const record_header_len = @import("contracts.zig").record_header_len;
const snapshot_coverage_payload_len = @import("contracts.zig").snapshot_coverage_payload_len;
const snapshot_coverage_slot_len = @import("contracts.zig").snapshot_coverage_slot_len;
const snapshot_coverage_v1_payload_len = @import("contracts.zig").snapshot_coverage_v1_payload_len;
const snapshot_coverage_version = @import("contracts.zig").snapshot_coverage_version;
const tombstone_len = @import("contracts.zig").tombstone_len;
const wal_epoch_len = @import("contracts.zig").wal_epoch_len;
const wal_epoch_payload_len = @import("contracts.zig").wal_epoch_payload_len;

pub fn coldDigest(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes, &digest, .{});
    return digest;
}

pub fn coldEpoch(epoch: [wal_epoch_len]u8) [cold_epoch_record_len]u8 {
    var record: [cold_epoch_record_len]u8 = undefined;
    writeU32(record[0..4], wal_epoch_payload_len);
    record[record_header_len] = meta_kind_wal_epoch;
    record[record_header_len + 1 ..].* = epoch;
    writeU32(record[4..8], checksum(record[record_header_len..]));
    return record;
}

pub fn writeRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    kind: MutationKind,
    store_family: Family,
    key: []const u8,
    value: []const u8,
    max_record_bytes: usize,
) !u64 {
    const payload_len = try checkedPayloadLen(kind, key, value, max_record_bytes);
    const record_len = std.math.add(usize, record_header_len, payload_len) catch return StoreError.RecordTooLarge;

    const record = try allocator.alloc(u8, record_len);
    defer allocator.free(record);

    writeU32(record[0..4], @intCast(payload_len));
    const payload = record[record_header_len..];
    payload[0] = @backingInt(kind);
    payload[1] = @backingInt(store_family);
    writeU32(payload[2..][0..4], @intCast(key.len));
    writeU32(payload[6..][0..4], if (kind == .delete) tombstone_len else @as(u32, @intCast(value.len)));
    @memcpy(payload[payload_header_len..][0..key.len], key);
    if (kind == .put)
        @memcpy(payload[payload_header_len + key.len ..][0..value.len], value);
    writeU32(record[4..][0..4], checksum(payload));

    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

pub fn isAllowedMetaPayloadLen(payload_len: u32) bool {
    return payload_len == meta_next_seq_payload_len or
        payload_len == wal_epoch_payload_len or
        payload_len == snapshot_coverage_payload_len or
        payload_len == snapshot_coverage_v1_payload_len;
}

pub fn parseWalEpoch(payload: []const u8) ![wal_epoch_len]u8 {
    if (payload.len != wal_epoch_payload_len or payload[0] != meta_kind_wal_epoch)
        return StoreError.BadRecord;
    var epoch: [wal_epoch_len]u8 = undefined;
    @memcpy(&epoch, payload[1..]);
    return epoch;
}

pub fn parseSnapshotCoverage(payload: []const u8) !SnapshotCoverage {
    if ((payload.len != snapshot_coverage_payload_len and payload.len != snapshot_coverage_v1_payload_len) or payload[0] != meta_kind_snapshot_coverage)
        return StoreError.BadRecord;
    var coverage = SnapshotCoverage{ .slots = undefined, .count = 0 };
    if (payload.len == snapshot_coverage_v1_payload_len) {
        if (payload[1] != 1 or payload[2] != 1) return StoreError.SnapshotCoverageMismatch;
        var slot = CoverageSlot{ .covered_len = readU64(payload[3..11]), .epoch = undefined, .digest = undefined };
        @memcpy(&slot.epoch, payload[11..27]);
        @memcpy(&slot.digest, payload[27..]);
        coverage.slots[0] = slot;
        coverage.count = 1;
        return coverage;
    }
    if (payload[1] != snapshot_coverage_version or payload[2] == 0 or payload[2] > 2) {
        return StoreError.SnapshotCoverageMismatch;
    }
    var i: usize = 0;
    while (i < payload[2]) : (i += 1) {
        const start = 3 + i * snapshot_coverage_slot_len;
        var covered_bytes: [8]u8 = undefined;
        @memcpy(&covered_bytes, payload[start .. start + 8]);
        var slot = CoverageSlot{ .covered_len = readU64(&covered_bytes), .epoch = undefined, .digest = undefined };
        @memcpy(&slot.epoch, payload[start + 8 .. start + 8 + wal_epoch_len]);
        @memcpy(&slot.digest, payload[start + 8 + wal_epoch_len .. start + snapshot_coverage_slot_len]);
        coverage.slots[i] = slot;
    }
    coverage.count = payload[2];
    return coverage;
}

pub fn batchPayloadLen(mutations: []const BatchMutation, limit: usize) !usize {
    if (mutations.len == 0 or mutations.len > max_batch_mutations) return StoreError.BadRecord;
    var size: usize = 3;
    for (mutations, 0..) |mutation, i| {
        if ((mutation.kind == .put) != (mutation.value != null)) return StoreError.BadRecord;
        for (mutations[0..i]) |prior| {
            if (mutation.family == prior.family and std.mem.eql(u8, mutation.key, prior.key)) return StoreError.BadRecord;
        }
        const part = try checkedPayloadLen(mutation.kind, mutation.key, mutation.value orelse "", limit);
        size = std.math.add(usize, size, 4) catch return StoreError.RecordTooLarge;
        size = std.math.add(usize, size, part) catch return StoreError.RecordTooLarge;
    }
    if (size > limit or size > std.math.maxInt(u32)) return StoreError.RecordTooLarge;
    return size;
}

pub fn encodeBatchGuard(record: *[batch_guard_len]u8) void {
    writeU32(record[0..4], 2);
    record[record_header_len] = meta_kind_batch_format;
    record[record_header_len + 1] = batch_format_version;
    writeU32(record[4..8], checksum(record[record_header_len..]));
}

pub fn encodeMutation(payload: []u8, mutation: BatchMutation) void {
    payload[0] = @backingInt(mutation.kind);
    payload[1] = @backingInt(mutation.family);
    writeU32(payload[2..6], @intCast(mutation.key.len));
    writeU32(payload[6..10], if (mutation.value) |value| @intCast(value.len) else tombstone_len);
    @memcpy(payload[payload_header_len..][0..mutation.key.len], mutation.key);
    if (mutation.value) |value| @memcpy(payload[payload_header_len + mutation.key.len ..], value);
}

pub fn decodeBatch(payload: []const u8, out: *[max_batch_mutations]BatchMutation) !usize {
    if (payload.len < 3 or payload[0] != meta_kind_batch or payload[1] != batch_format_version or payload[2] == 0 or payload[2] > max_batch_mutations)
        return StoreError.BadRecord;
    var offset: usize = 3;
    const count: usize = payload[2];
    for (out[0..count]) |*mutation| {
        if (payload.len - offset < 4) return StoreError.BadRecord;
        const len: usize = readU32(payload[offset..][0..4]);
        offset += 4;
        if (len < payload_header_len or len > payload.len - offset) return StoreError.BadRecord;
        const part = payload[offset..][0..len];
        const kind: MutationKind = switch (part[0]) {
            0 => .put,
            1 => .delete,
            else => return StoreError.UnknownRecordKind,
        };
        const family_value = decodeFamily(part[1]) orelse return StoreError.UnknownFamily;
        const key_len: usize = readU32(part[2..6]);
        const value_len = readU32(part[6..10]);
        if ((kind == .delete) != (value_len == tombstone_len)) return StoreError.BadRecord;
        if (key_len > len - payload_header_len) return StoreError.BadRecord;
        const remainder = len - payload_header_len - key_len;
        if (remainder != (if (kind == .delete) @as(usize, 0) else @as(usize, value_len))) return StoreError.BadRecord;
        mutation.* = .{ .family = family_value, .kind = kind, .key = part[payload_header_len..][0..key_len], .value = if (kind == .put) part[payload_header_len + key_len ..] else null };
        offset += len;
    }
    if (offset != payload.len) return StoreError.BadRecord;
    _ = try batchPayloadLen(out[0..count], std.math.maxInt(usize));
    return count;
}

pub fn checkedPayloadLen(
    kind: MutationKind,
    key: []const u8,
    value: []const u8,
    max_record_bytes: usize,
) !usize {
    if (key.len > std.math.maxInt(u32) or (kind == .put and value.len > std.math.maxInt(u32)))
        return StoreError.RecordTooLarge;
    var payload_len = std.math.add(usize, payload_header_len, key.len) catch return StoreError.RecordTooLarge;
    if (kind == .put) payload_len = std.math.add(usize, payload_len, value.len) catch return StoreError.RecordTooLarge;
    if (payload_len > max_record_bytes) return StoreError.RecordTooLarge;
    return payload_len;
}

pub fn recordSize(kind: MutationKind, key: []const u8, value: []const u8, max_record_bytes: usize) !usize {
    const payload_len = try checkedPayloadLen(kind, key, value, max_record_bytes);
    return std.math.add(usize, record_header_len, payload_len) catch StoreError.RecordTooLarge;
}

pub fn writeNextSeqRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    next_seq: u64,
) !u64 {
    const record = try allocator.alloc(u8, record_header_len + meta_next_seq_payload_len);
    defer allocator.free(record);

    writeU32(record[0..4], meta_next_seq_payload_len);
    const payload = record[record_header_len..];
    payload[0] = meta_kind_next_seq;
    writeU64(payload[1..9], next_seq);
    writeU32(record[4..][0..4], checksum(payload));

    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

pub fn writeWalEpochRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    epoch: *const [wal_epoch_len]u8,
) !u64 {
    const record_len = record_header_len + wal_epoch_payload_len;
    const record = try allocator.alloc(u8, record_len);
    defer allocator.free(record);
    writeU32(record[0..4], wal_epoch_payload_len);
    const payload = record[record_header_len..];
    payload[0] = meta_kind_wal_epoch;
    @memcpy(payload[1..], epoch);
    writeU32(record[4..8], checksum(payload));
    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

pub fn writeSnapshotCoverageRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    coverage: *const SnapshotCoverage,
) !u64 {
    const record_len = record_header_len + snapshot_coverage_payload_len;
    const record = try allocator.alloc(u8, record_len);
    defer allocator.free(record);
    writeU32(record[0..4], snapshot_coverage_payload_len);
    const payload = record[record_header_len..];
    payload[0] = meta_kind_snapshot_coverage;
    payload[1] = snapshot_coverage_version;
    payload[2] = @intCast(coverage.count);
    for (coverage.slots[0..coverage.count], 0..) |slot, i| {
        const start = 3 + i * snapshot_coverage_slot_len;
        var covered_bytes: [8]u8 = undefined;
        writeU64(&covered_bytes, slot.covered_len);
        @memcpy(payload[start .. start + 8], &covered_bytes);
        @memcpy(payload[start + 8 .. start + 8 + wal_epoch_len], &slot.epoch);
        @memcpy(payload[start + 8 + wal_epoch_len .. start + snapshot_coverage_slot_len], &slot.digest);
    }
    writeU32(record[4..8], checksum(payload));
    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

pub fn isMutationPayload(payload: []const u8) bool {
    if (payload.len == 0) return false;
    return payload[0] == @backingInt(MutationKind.put) or
        payload[0] == @backingInt(MutationKind.delete);
}

pub fn checksum(payload: []const u8) u32 {
    return std.hash.Fnv1a_32.hash(payload);
}

pub fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

pub fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .little);
}

pub fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

pub fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .little);
}
