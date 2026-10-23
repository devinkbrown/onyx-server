// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the attachment delivery spool.

const std = @import("std");
const testing = std.testing;
const ClientId = @import("model.zig").ClientId;
const Config = @import("model.zig").Config;
const Spool = @import("engine.zig").Spool;
const eventId = @import("engine.zig").eventId;
const validateCheckpoint = @import("checkpoint.zig").validateCheckpoint;
const parseEntry = @import("checkpoint.zig").parseEntry;
const header_len = @import("checkpoint.zig").header_len;
const event_id_len = @import("checkpoint.zig").event_id_len;
const checksum_len = @import("checkpoint.zig").checksum_len;
const checkpointChecksum = @import("checkpoint.zig").checkpointChecksum;
const writeU64 = @import("checkpoint.zig").writeU64;

test "attachment delivery spool checkpoint round trip corruption and OOM are strict" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 9, .event_id = eventId(1), .bytes = "first\r\n" },
        .{ .client = 8, .event_id = eventId(2), .bytes = "second\r\n" },
    });
    const checkpoint = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const meta = try validateCheckpoint(checkpoint);
    try testing.expectEqual(@as(usize, 2), meta.count);
    try testing.expectEqual(spool.totalBytes(), meta.total_record_bytes);

    var restored = try Spool.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.attachmentCount());
    const reencoded = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, checkpoint, reencoded);

    var replaced = try Spool.init(testing.allocator, config);
    defer replaced.deinit();
    try replaced.replaceFromCheckpoint(checkpoint);
    try testing.expectEqual(@as(usize, 2), replaced.attachmentCount());
    const replaced_checkpoint = try replaced.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(replaced_checkpoint);
    try testing.expectEqualSlices(u8, checkpoint, replaced_checkpoint);

    var corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[header_len] ^= 0x80;
    try testing.expectError(error.ChecksumMismatch, validateCheckpoint(corrupt));
    try testing.expectError(error.Truncated, validateCheckpoint(checkpoint[0 .. checkpoint.len - 1]));
    var trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0;
    try testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));
    var unknown_flags = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(unknown_flags);
    unknown_flags[5] = 1;
    try testing.expectError(error.InvalidField, validateCheckpoint(unknown_flags));

    var duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    var duplicate_pos: usize = header_len;
    const first_view = try parseEntry(duplicate, &duplicate_pos, config.max_record_bytes);
    const second_start = duplicate_pos;
    writeU64(duplicate[second_start..][0..8], first_view.client);
    @memcpy(
        duplicate[second_start + 16 ..][0..event_id_len],
        &first_view.event_id,
    );
    checkpointChecksum(
        duplicate[0 .. duplicate.len - checksum_len],
        duplicate[duplicate.len - checksum_len ..][0..checksum_len],
    );
    try testing.expectError(error.DuplicateEntry, validateCheckpoint(duplicate));

    var bad_order = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_order);
    var order_pos: usize = header_len;
    const first_order = try parseEntry(bad_order, &order_pos, config.max_record_bytes);
    writeU64(bad_order[order_pos + 8 ..][0..8], first_order.sequence);
    checkpointChecksum(
        bad_order[0 .. bad_order.len - checksum_len],
        bad_order[bad_order.len - checksum_len ..][0..checksum_len],
    );
    try testing.expectError(error.InvalidField, validateCheckpoint(bad_order));

    try testing.expectError(error.ConfigMismatch, Spool.decodeCheckpoint(testing.allocator, .{
        .max_attachments = config.max_attachments,
        .max_records = 7,
        .max_total_bytes = config.max_total_bytes,
        .max_record_bytes = config.max_record_bytes,
    }, checkpoint));

    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, encoded: []const u8) !void {
            var candidate = try Spool.decodeCheckpoint(allocator, cfg, encoded);
            defer candidate.deinit();
            try testing.expectEqual(@as(usize, 2), candidate.len());
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        DecodeSweep.run,
        .{ config, checkpoint },
    );

    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.ChecksumMismatch, spool.replaceFromCheckpoint(corrupt));
    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "attachment delivery spool checkpoint normalizes sequence gaps but preserves authority" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "retired-one\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "retired-two\r\n" },
        .{ .client = 1, .event_id = eventId(3), .bytes = "live-three\r\n" },
        .{ .client = 2, .event_id = eventId(4), .bytes = "live-four\r\n" },
    });
    try testing.expect(spool.commitHeadToSendq(1, 1, eventId(1)));
    try testing.expect(spool.commitHeadToSendq(2, 2, eventId(2)));
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(5), .bytes = "live-five\r\n" },
    });
    try testing.expectEqual(@as(u64, 6), spool.next_sequence);
    try testing.expectEqual(@as(u64, 3), spool.entries.items[0].sequence);

    const checkpoint = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try Spool.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(u64, 4), restored.next_sequence);
    try testing.expectEqual(@as(usize, 3), restored.len());
    try testing.expectEqual(@as(ClientId, 1), restored.entries.items[0].client);
    try testing.expectEqual(eventId(3), restored.entries.items[0].event_id);
    try testing.expectEqualStrings("live-three\r\n", restored.entries.items[0].bytes);
    try testing.expectEqual(@as(ClientId, 2), restored.entries.items[1].client);
    try testing.expectEqual(eventId(4), restored.entries.items[1].event_id);
    try testing.expectEqualStrings("live-four\r\n", restored.entries.items[1].bytes);
    try testing.expectEqual(@as(ClientId, 1), restored.entries.items[2].client);
    try testing.expectEqual(eventId(5), restored.entries.items[2].event_id);
    try testing.expectEqualStrings("live-five\r\n", restored.entries.items[2].bytes);

    // Both a retired tuple and a tuple borrowed from the predecessor incarnation
    // fail closed. A fresh post-restore tuple remains able to retire the head.
    try testing.expect(!restored.commitHeadToSendq(1, 1, eventId(1)));
    try testing.expect(!restored.commitHeadToSendq(1, 3, eventId(3)));
    const reencoded = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, checkpoint, reencoded);
    try testing.expect(restored.commitHeadToSendq(1, 1, eventId(3)));
    try testing.expectEqual(eventId(4), restored.entries.items[0].event_id);
    try testing.expectEqual(eventId(5), restored.entries.items[1].event_id);
}
