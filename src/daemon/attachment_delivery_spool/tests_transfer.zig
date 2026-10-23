// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the attachment delivery spool.

const std = @import("std");
const testing = std.testing;
const ClientId = @import("model.zig").ClientId;
const PendingRecord = @import("model.zig").PendingRecord;
const Spool = @import("engine.zig").Spool;
const eventId = @import("engine.zig").eventId;

test "attachment delivery spool transfers detached resume atomically" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "old-one\r\n" },
        .{ .client = 1, .event_id = eventId(2), .bytes = "shared\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "shared\r\n" },
    });
    const transfer = try spool.transferAttachment(1, 2);
    try testing.expectEqual(@as(usize, 2), transfer.transferred);
    try testing.expectEqual(@as(usize, 1), transfer.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(2));
    try testing.expectEqual(@as(usize, 0), spool.pendingCountFor(1));
    try testing.expectEqual(@as(usize, 1), spool.attachmentCount());

    _ = try spool.reserveBatch(&.{
        .{ .client = 3, .event_id = eventId(9), .bytes = "source\r\n" },
        .{ .client = 4, .event_id = eventId(9), .bytes = "conflict\r\n" },
    });
    try testing.expectEqual(@as(usize, 3), spool.attachmentCount());
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.Equivocation, spool.transferAttachment(3, 4));
    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "prepared attachment transfer abort leaves spool byte-identical" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "two\r\n" },
    });
    var page: [1]PendingRecord = undefined;
    _ = spool.collectPending(&page);
    const fair_cursor_before = spool.fair_cursor;
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    var prepared = try spool.prepareAttachmentTransfer(10, 30);
    prepared.abort();
    prepared.deinit();

    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);
}

test "prepared attachment transfer conflict leaves spool byte-identical" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "source\r\n" },
        .{ .client = 20, .event_id = eventId(1), .bytes = "conflict\r\n" },
    });
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    try testing.expectError(error.Equivocation, spool.prepareAttachmentTransfer(10, 20));

    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "prepared attachment transfer OOM leaves spool byte-identical" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var spool = try Spool.init(failing.allocator(), .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer {
        failing.fail_index = std.math.maxInt(usize);
        spool.deinit();
    }
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "source\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "other\r\n" },
    });
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, spool.prepareAttachmentTransfer(10, 30));
    failing.fail_index = std.math.maxInt(usize);

    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "prepared attachment transfer commit moves old rows to new exactly" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 30, .event_id = eventId(3), .bytes = "other\r\n" },
        .{ .client = 10, .event_id = eventId(2), .bytes = "two\r\n" },
    });

    var prepared = try spool.prepareAttachmentTransfer(10, 20);
    defer prepared.deinit();
    try testing.expect(spool.contains(10, eventId(1)));
    try testing.expect(!spool.contains(20, eventId(1)));
    const result = prepared.commit();

    try testing.expectEqual(@as(usize, 2), result.transferred);
    try testing.expectEqual(@as(usize, 0), result.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 0), spool.pendingCountFor(10));
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(20));
    try testing.expectEqual(@as(usize, 1), spool.pendingCountFor(30));
    try testing.expectEqual(@as(ClientId, 20), spool.entries.items[0].client);
    try testing.expectEqual(@as(u64, 1), spool.entries.items[0].sequence);
    try testing.expectEqualStrings("one\r\n", spool.entries.items[0].bytes);
    try testing.expectEqual(@as(ClientId, 30), spool.entries.items[1].client);
    try testing.expectEqual(@as(u64, 2), spool.entries.items[1].sequence);
    try testing.expectEqual(@as(ClientId, 20), spool.entries.items[2].client);
    try testing.expectEqual(@as(u64, 3), spool.entries.items[2].sequence);
    try testing.expectEqualStrings("two\r\n", spool.entries.items[2].bytes);
}

test "prepared attachment transfer merges one duplicate event exactly once" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "shared\r\n" },
        .{ .client = 20, .event_id = eventId(1), .bytes = "shared\r\n" },
        .{ .client = 10, .event_id = eventId(2), .bytes = "unique\r\n" },
    });

    var prepared = try spool.prepareAttachmentTransfer(10, 20);
    defer prepared.deinit();
    const result = prepared.commit();

    try testing.expectEqual(@as(usize, 2), result.transferred);
    try testing.expectEqual(@as(usize, 1), result.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 2), spool.len());
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(20));
    try testing.expectEqual(@as(usize, 1), spool.attachmentCount());
    try testing.expectEqual(@as(u64, 1), spool.entries.items[0].sequence);
    try testing.expectEqual(eventId(1), spool.entries.items[0].event_id);
    try testing.expectEqualStrings("shared\r\n", spool.entries.items[0].bytes);
    try testing.expectEqual(@as(u64, 3), spool.entries.items[1].sequence);
    try testing.expectEqual(eventId(2), spool.entries.items[1].event_id);
    try testing.expectEqualStrings("unique\r\n", spool.entries.items[1].bytes);
}
