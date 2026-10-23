// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict canonical ADS1 checkpoint codec and validation.

const std = @import("std");
const ClientId = @import("model.zig").ClientId;
const EventId = @import("model.zig").EventId;
const hard_max_records = @import("model.zig").hard_max_records;
const hard_max_checkpoint_bytes = @import("model.zig").hard_max_checkpoint_bytes;
const Config = @import("model.zig").Config;
const CheckpointError = @import("model.zig").CheckpointError;
const validateConfig = @import("policy.zig").validateConfig;
const validRenderedRecord = @import("policy.zig").validRenderedRecord;

pub const CheckpointMeta = struct {
    config: Config,
    count: usize,
    attachment_count: usize,
    body_len: usize,
    total_record_bytes: usize,
    next_sequence: u64,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and
        std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Allocation-free strict whole-image validation used by Helix relation checks.
pub fn validateCheckpoint(bytes: []const u8) CheckpointError!CheckpointMeta {
    return validateCheckpointImpl(bytes, null);
}

pub fn validateCheckpointImpl(
    bytes: []const u8,
    validation_steps: ?*usize,
) CheckpointError!CheckpointMeta {
    if (validation_steps) |steps| steps.* = 0;
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (bytes[5] != 0) return error.InvalidField;
    const config = Config{
        .max_attachments = readU32(bytes[6..10]),
        .max_records = readU32(bytes[10..14]),
        .max_total_bytes = readU64(bytes[14..22]),
        .max_record_bytes = readU32(bytes[22..26]),
    };
    try validateConfig(config);
    const count: usize = readU32(bytes[26..30]);
    const body_len: usize = std.math.cast(usize, readU64(bytes[30..38])) orelse
        return error.CheckpointTooLarge;
    const next_sequence = readU64(bytes[38..46]);
    if (count > config.max_records) return error.CapacityExceeded;
    if (next_sequence != @as(u64, @intCast(count)) + 1) return error.InvalidField;
    const prefix_len = std.math.add(usize, header_len, body_len) catch
        return error.CheckpointTooLarge;
    const expected_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (expected_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var actual_checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
    if (!std.mem.eql(u8, &actual_checksum, bytes[prefix_len..])) return error.ChecksumMismatch;

    var pos: usize = header_len;
    var total_record_bytes: usize = 0;
    var attachment_count: usize = 0;
    var previous_client: ClientId = 0;
    var previous_event_id: EventId = @splat(0);
    var have_previous = false;
    var rank_bitmap: [hard_max_records / 8]u8 = @splat(0);
    for (0..count) |_| {
        if (validation_steps) |steps| steps.* += 1;
        const current = try parseEntry(bytes, &pos, config.max_record_bytes);
        total_record_bytes = std.math.add(usize, total_record_bytes, current.bytes.len) catch
            return error.CapacityExceeded;
        if (total_record_bytes > config.max_total_bytes) return error.CapacityExceeded;
        if (current.sequence == 0 or current.sequence > count) return error.InvalidField;
        const rank_index: usize = @intCast(current.sequence - 1);
        const rank_mask: u8 = @as(u8, 1) << @intCast(rank_index & 7);
        if (rank_bitmap[rank_index / 8] & rank_mask != 0) return error.InvalidField;
        rank_bitmap[rank_index / 8] |= rank_mask;

        if (have_previous) {
            switch (compareEntryKey(
                previous_client,
                previous_event_id,
                current.client,
                current.event_id,
            )) {
                .eq => return error.DuplicateEntry,
                .gt => return error.NonCanonicalOrder,
                .lt => {},
            }
        }
        if (!have_previous or previous_client != current.client) {
            attachment_count += 1;
            if (attachment_count > config.max_attachments) return error.CapacityExceeded;
        }
        previous_client = current.client;
        previous_event_id = current.event_id;
        have_previous = true;
    }
    if (pos < prefix_len) return error.InvalidField;
    if (pos > prefix_len) return error.Truncated;
    return .{
        .config = config,
        .count = count,
        .attachment_count = attachment_count,
        .body_len = body_len,
        .total_record_bytes = total_record_bytes,
        .next_sequence = next_sequence,
    };
}

const EntryView = struct {
    client: ClientId,
    sequence: u64,
    event_id: EventId,
    bytes: []const u8,
};

pub fn parseEntry(bytes: []const u8, pos: *usize, max_record_bytes: usize) CheckpointError!EntryView {
    const payload_end = bytes.len - checksum_len;
    if (pos.* > payload_end or payload_end - pos.* < entry_prefix_len) return error.Truncated;
    const client = readU64(bytes[pos.*..][0..8]);
    pos.* += 8;
    const sequence = readU64(bytes[pos.*..][0..8]);
    pos.* += 8;
    const event_id: EventId = bytes[pos.*..][0..event_id_len].*;
    pos.* += event_id_len;
    const record_len: usize = readU32(bytes[pos.*..][0..4]);
    pos.* += 4;
    if (record_len > max_record_bytes) return error.CapacityExceeded;
    if (record_len > payload_end - pos.*) return error.Truncated;
    const record = bytes[pos.*..][0..record_len];
    pos.* += record_len;
    if (!validRenderedRecord(record)) return error.InvalidRecord;
    return .{ .client = client, .sequence = sequence, .event_id = event_id, .bytes = record };
}

pub fn compareEntryKey(
    a_client: ClientId,
    a_event_id: EventId,
    b_client: ClientId,
    b_event_id: EventId,
) std.math.Order {
    if (a_client < b_client) return .lt;
    if (a_client > b_client) return .gt;
    return std.mem.order(u8, &a_event_id, &b_event_id);
}

pub const checkpoint_magic = [_]u8{ 'A', 'D', 'S', '1' };

pub const checkpoint_version: u8 = 1;

pub const header_len: usize = 46;

pub const event_id_len: usize = @sizeOf(EventId);

pub const entry_prefix_len: usize = 8 + 8 + event_id_len + 4;

pub const checksum_len: usize = std.crypto.hash.Blake3.digest_length;

const checkpoint_checksum_domain = "onyx-attachment-delivery-spool-v1";

pub fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(checkpoint_checksum_domain);
    hash.update(prefix);
    hash.final(out);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

pub fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

pub fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .big);
}
