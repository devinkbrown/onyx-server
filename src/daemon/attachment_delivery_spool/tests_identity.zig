// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the attachment delivery spool.

const std = @import("std");
const testing = std.testing;
const ClientId = @import("model.zig").ClientId;
const Config = @import("model.zig").Config;
const BatchRecord = @import("model.zig").BatchRecord;
const PendingRecord = @import("model.zig").PendingRecord;
const Spool = @import("engine.zig").Spool;
const eventId = @import("engine.zig").eventId;
const validateCheckpoint = @import("checkpoint.zig").validateCheckpoint;

test "attachment delivery spool discard is no-fail complete and preserves unrelated FIFO" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 64, .max_record_bytes = 16 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();

    const empty = spool.discardAttachment(7);
    try testing.expectEqual(@as(usize, 0), empty.discarded_records);
    try testing.expectEqual(@as(usize, 0), empty.discarded_bytes);
    try testing.expectEqual(@as(usize, 0), spool.attachmentCount());

    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "a\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "b\r\n" },
        .{ .client = 1, .event_id = eventId(3), .bytes = "c\r\n" },
        .{ .client = 3, .event_id = eventId(4), .bytes = "d\r\n" },
    });
    try testing.expectEqual(@as(usize, 3), spool.attachmentCount());
    try testing.expectEqual(@as(usize, 12), spool.totalBytes());

    var page: [1]PendingRecord = undefined;
    _ = spool.collectPending(&page);
    const discarded = spool.discardAttachment(1);
    try testing.expectEqual(@as(usize, 2), discarded.discarded_records);
    try testing.expectEqual(@as(usize, 6), discarded.discarded_bytes);
    try testing.expectEqual(@as(usize, 2), spool.len());
    try testing.expectEqual(@as(usize, 2), spool.attachmentCount());
    try testing.expectEqual(@as(usize, 6), spool.totalBytes());
    try testing.expect(!spool.contains(1, eventId(1)));
    try testing.expect(!spool.contains(1, eventId(3)));

    var pending: [2]PendingRecord = undefined;
    const remaining = spool.collectPending(&pending);
    try testing.expectEqual(@as(usize, 2), remaining.len);
    try testing.expectEqual(@as(ClientId, 2), remaining[0].client);
    try testing.expectEqual(@as(ClientId, 3), remaining[1].client);

    const checkpoint = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const meta = try validateCheckpoint(checkpoint);
    try testing.expectEqual(@as(usize, 2), meta.count);
    try testing.expectEqual(@as(usize, 2), meta.attachment_count);
    var restored = try Spool.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.attachmentCount());

    const before_missing = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before_missing);
    _ = spool.discardAttachment(99);
    const after_missing = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_missing);
    try testing.expectEqualSlices(u8, before_missing, after_missing);

    _ = spool.discardAttachment(2);
    _ = spool.discardAttachment(3);
    try testing.expectEqual(@as(usize, 0), spool.len());
    try testing.expectEqual(@as(usize, 0), spool.attachmentCount());
    try testing.expectEqual(@as(usize, 0), spool.totalBytes());
}

test "attachment delivery spool duplicate is idempotent and differing bytes equivocate" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 4,
        .max_total_bytes = 64,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    const first = BatchRecord{ .client = 7, .event_id = eventId(7), .bytes = "same\r\n" };
    _ = try spool.reserveBatch(&.{first});
    const duplicate = try spool.reserveBatch(&.{ first, first });
    try testing.expectEqual(@as(usize, 0), duplicate.inserted);
    try testing.expectEqual(@as(usize, 2), duplicate.exact_duplicates);
    try testing.expectEqual(@as(usize, 1), spool.len());
    try testing.expectError(error.Equivocation, spool.reserveBatch(&.{
        .{ .client = 7, .event_id = eventId(7), .bytes = "different\r\n" },
    }));
    try testing.expectEqual(@as(usize, 1), spool.len());
    try testing.expectError(error.InvalidRecord, spool.reserveBatch(&.{
        .{ .client = 8, .event_id = eventId(8), .bytes = "two\r\nlines\r\n" },
    }));
}
