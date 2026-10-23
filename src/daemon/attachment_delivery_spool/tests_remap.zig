// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the attachment delivery spool.

const std = @import("std");
const testing = std.testing;
const Config = @import("model.zig").Config;
const AttachmentRemap = @import("model.zig").AttachmentRemap;
const BatchRecord = @import("model.zig").BatchRecord;
const Spool = @import("engine.zig").Spool;
const eventId = @import("engine.zig").eventId;

test "attachment delivery spool empty remap is a no-op only for empty authority" {
    const config = Config{ .max_attachments = 2, .max_records = 4, .max_total_bytes = 64, .max_record_bytes = 16 };
    var empty = try Spool.init(testing.allocator, config);
    defer empty.deinit();

    const no_mappings = try empty.remapAttachments(&.{});
    try testing.expectEqual(@as(usize, 0), no_mappings.records_remapped);
    try testing.expectEqual(@as(usize, 0), no_mappings.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 0), no_mappings.attachment_count);

    const unused_mapping = try empty.remapAttachments(&.{
        .{ .old_client = 9, .new_client = 10 },
    });
    try testing.expectEqual(@as(usize, 0), unused_mapping.records_remapped);
    try testing.expectEqual(@as(usize, 0), unused_mapping.attachment_count);

    _ = try empty.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "a\r\n" },
    });
    try testing.expectError(error.MissingMapping, empty.remapAttachments(&.{}));
    try testing.expect(empty.contains(1, eventId(1)));
}

test "attachment delivery spool simultaneous remap supports two and three cycles" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var two_cycle = try Spool.init(testing.allocator, config);
    defer two_cycle.deinit();
    _ = try two_cycle.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "from-one\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "from-two\r\n" },
    });
    const two = try two_cycle.remapAttachments(&.{
        .{ .old_client = 1, .new_client = 2 },
        .{ .old_client = 2, .new_client = 1 },
    });
    try testing.expectEqual(@as(usize, 2), two.records_remapped);
    try testing.expectEqual(@as(usize, 0), two.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 2), two.attachment_count);
    try testing.expect(two_cycle.contains(2, eventId(1)));
    try testing.expect(two_cycle.contains(1, eventId(2)));
    try testing.expect(!two_cycle.contains(1, eventId(1)));
    try testing.expect(!two_cycle.contains(2, eventId(2)));

    var three_cycle = try Spool.init(testing.allocator, config);
    defer three_cycle.deinit();
    _ = try three_cycle.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "ten\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "twenty\r\n" },
        .{ .client = 30, .event_id = eventId(3), .bytes = "thirty\r\n" },
    });
    const three = try three_cycle.remapAttachments(&.{
        .{ .old_client = 10, .new_client = 20 },
        .{ .old_client = 20, .new_client = 30 },
        .{ .old_client = 30, .new_client = 10 },
    });
    try testing.expectEqual(@as(usize, 3), three.records_remapped);
    try testing.expectEqual(@as(usize, 3), three_cycle.attachmentCount());
    try testing.expect(three_cycle.contains(20, eventId(1)));
    try testing.expect(three_cycle.contains(30, eventId(2)));
    try testing.expect(three_cycle.contains(10, eventId(3)));
}

test "attachment delivery spool remap OOM is byte exact" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    const records = [_]BatchRecord{
        .{ .client = 1, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "two\r\n" },
    };
    const mappings = [_]AttachmentRemap{
        .{ .old_client = 1, .new_client = 2 },
        .{ .old_client = 2, .new_client = 1 },
    };

    var reached_success = false;
    for (0..6) |fail_offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var candidate = try Spool.init(failing.allocator(), config);
        defer {
            failing.fail_index = std.math.maxInt(usize);
            candidate.deinit();
        }
        _ = try candidate.reserveBatch(&records);
        const before = try candidate.encodeCheckpoint(testing.allocator);
        defer testing.allocator.free(before);
        failing.fail_index = failing.alloc_index + fail_offset;
        const attempt = candidate.remapAttachments(&mappings);
        if (attempt) |result| {
            try testing.expectEqual(@as(usize, 2), result.records_remapped);
            reached_success = true;
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            const after = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(after);
            try testing.expectEqualSlices(u8, before, after);
        }
    }
    try testing.expect(reached_success);
}
