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

test "attachment delivery spool retains a slow client while healthy clients drain fairly" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "slow-one\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "healthy-one\r\n" },
        .{ .client = 10, .event_id = eventId(3), .bytes = "slow-two\r\n" },
    });

    var pending_buf: [4]PendingRecord = undefined;
    const first = spool.collectPending(&pending_buf);
    try testing.expectEqual(@as(usize, 2), first.len);
    try testing.expectEqual(@as(ClientId, 10), first[0].client);
    try testing.expectEqualStrings("slow-one\r\n", first[0].bytes);
    try testing.expectEqual(@as(ClientId, 20), first[1].client);
    // A later record for the slow client cannot overtake its retained head.
    try testing.expect(!spool.commitHeadToSendq(10, 3, eventId(3)));
    try testing.expect(spool.commitHeadToSendq(20, first[1].sequence, eventId(2)));
    try testing.expect(!spool.commitHeadToSendq(20, first[1].sequence, eventId(2)));
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(10));
    try testing.expectEqual(@as(usize, 1), spool.attachmentCount());

    _ = try spool.reserveBatch(&.{
        .{ .client = 20, .event_id = eventId(4), .bytes = "healthy-two\r\n" },
    });
    try testing.expectEqual(@as(usize, 2), spool.attachmentCount());
    const second = spool.collectPending(&pending_buf);
    try testing.expectEqual(@as(usize, 2), second.len);
    var saw_slow = false;
    var saw_healthy = false;
    for (second) |pending| {
        if (pending.client == 10) {
            saw_slow = true;
            try testing.expectEqualStrings("slow-one\r\n", pending.bytes);
        }
        if (pending.client == 20) {
            saw_healthy = true;
            try testing.expectEqualStrings("healthy-two\r\n", pending.bytes);
        }
    }
    try testing.expect(saw_slow and saw_healthy);
    for (second) |pending| if (pending.client == 20) {
        try testing.expect(spool.commitHeadToSendq(20, pending.sequence, eventId(4)));
        break;
    };
    try testing.expectEqual(@as(usize, 2), spool.len());
}

test "attachment delivery spool fair page reaches client thirty three" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 40,
        .max_records = 40,
        .max_total_bytes = 1024,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    var batch: [33]BatchRecord = undefined;
    for (&batch, 0..) |*record, index| record.* = .{
        .client = @intCast(index + 1),
        .event_id = eventId(1),
        .bytes = "pending\r\n",
    };
    _ = try spool.reserveBatch(&batch);
    var page: [32]PendingRecord = undefined;
    try testing.expectEqual(@as(usize, 32), spool.collectPending(&page).len);
    var last: [1]PendingRecord = undefined;
    const next = spool.collectPending(&last);
    try testing.expectEqual(@as(usize, 1), next.len);
    try testing.expectEqual(@as(ClientId, 33), next[0].client);
}

test "attachment delivery spool collects unique clients without advancing fairness" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 64, .max_record_bytes = 16 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 3, .event_id = eventId(1), .bytes = "a\r\n" },
        .{ .client = 1, .event_id = eventId(2), .bytes = "b\r\n" },
        .{ .client = 3, .event_id = eventId(3), .bytes = "c\r\n" },
        .{ .client = 2, .event_id = eventId(4), .bytes = "d\r\n" },
        .{ .client = 1, .event_id = eventId(5), .bytes = "e\r\n" },
    });

    var pending_page: [2]PendingRecord = undefined;
    _ = spool.collectPending(&pending_page);
    const fair_cursor_before = spool.fair_cursor;

    var all_buffer: [3]ClientId = undefined;
    const all = spool.collectAttachmentClients(&all_buffer);
    try testing.expectEqual(@as(usize, spool.attachmentCount()), all.len);
    try testing.expectEqualSlices(ClientId, &.{ 3, 1, 2 }, all);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);

    var truncated_buffer: [2]ClientId = undefined;
    const truncated = spool.collectAttachmentClients(&truncated_buffer);
    try testing.expectEqualSlices(ClientId, &.{ 3, 1 }, truncated);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);

    var empty_buffer: [0]ClientId = .{};
    try testing.expectEqual(@as(usize, 0), spool.collectAttachmentClients(&empty_buffer).len);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);
}
