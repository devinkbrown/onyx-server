// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the attachment delivery spool.

const std = @import("std");
const testing = std.testing;
const Config = @import("model.zig").Config;
const BatchRecord = @import("model.zig").BatchRecord;
const OwnedBatchRecord = @import("model.zig").OwnedBatchRecord;
const Spool = @import("engine.zig").Spool;
const eventId = @import("engine.zig").eventId;

test "attachment delivery spool batch reservation is atomic under OOM and capacity" {
    const config = Config{ .max_attachments = 3, .max_records = 3, .max_total_bytes = 32, .max_record_bytes = 16 };
    const batch = [_]BatchRecord{
        .{ .client = 1, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 2, .event_id = eventId(1), .bytes = "two\r\n" },
    };

    const OomSweep = struct {
        fn run(allocator: std.mem.Allocator, records: []const BatchRecord) !void {
            var spool = try Spool.init(allocator, config);
            defer spool.deinit();
            const result = try spool.reserveBatch(records);
            try testing.expectEqual(@as(usize, 2), result.inserted);
            try testing.expectEqual(@as(usize, 2), spool.len());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, OomSweep.run, .{batch[0..]});

    // Every individual preparation allocation failure leaves the live authority
    // byte-identical, not merely empty after teardown.
    var reached_success = false;
    for (0..8) |fail_offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var candidate = try Spool.init(failing.allocator(), config);
        defer {
            failing.fail_index = std.math.maxInt(usize);
            candidate.deinit();
        }
        const candidate_before = try candidate.encodeCheckpoint(testing.allocator);
        defer testing.allocator.free(candidate_before);
        failing.fail_index = failing.alloc_index + fail_offset;
        const attempt = candidate.reserveBatch(&batch);
        if (attempt) |result| {
            try testing.expectEqual(@as(usize, 2), result.inserted);
            reached_success = true;
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            const candidate_after = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(candidate_after);
            try testing.expectEqualSlices(u8, candidate_before, candidate_after);
        }
    }
    try testing.expect(reached_success);

    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(batch[0..]);
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.CapacityExceeded, spool.reserveBatch(&.{
        .{ .client = 3, .event_id = eventId(2), .bytes = "three\r\n" },
        .{ .client = 4, .event_id = eventId(3), .bytes = "four\r\n" },
    }));
    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "attachment delivery spool prepared batch abort is byte exact and commit cannot fail" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    var aborted = try spool.prepareBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "prepared\r\n" },
        .{ .client = 2, .event_id = eventId(1), .bytes = "different-caps\r\n" },
    });
    defer aborted.deinit();
    const while_prepared = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(while_prepared);
    try testing.expectEqualSlices(u8, before, while_prepared);
    aborted.abort();
    const after_abort = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_abort);
    try testing.expectEqualSlices(u8, before, after_abort);
    try testing.expectEqual(@as(usize, 0), spool.attachmentCount());

    var committed = try spool.prepareBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "prepared\r\n" },
        .{ .client = 2, .event_id = eventId(1), .bytes = "different-caps\r\n" },
    });
    defer committed.deinit();
    const result = committed.commit();
    try testing.expectEqual(@as(usize, 2), result.inserted);
    try testing.expectEqual(@as(usize, 2), spool.len());
    try testing.expectEqual(@as(usize, 2), spool.attachmentCount());
}

test "owned attachment batch adopts inserted bodies and adopts nothing on failure" {
    var spool = try Spool.init(testing.allocator, .{});
    defer spool.deinit();

    const first = try testing.allocator.dupe(u8, "one\r\n");
    const first_ptr = first.ptr;
    var adopted = [_]OwnedBatchRecord{
        .{ .client = 7, .event_id = eventId(3), .bytes = first },
    };
    const inserted = try spool.reserveOwnedBatch(&adopted);
    try testing.expectEqual(@as(usize, 1), inserted.inserted);
    try testing.expectEqual(@as(usize, 0), adopted[0].bytes.len);
    try testing.expectEqual(first_ptr, spool.entries.items[0].bytes.ptr);

    const duplicate = try testing.allocator.dupe(u8, "one\r\n");
    var again = [_]OwnedBatchRecord{
        .{ .client = 7, .event_id = eventId(3), .bytes = duplicate },
    };
    const dup = try spool.reserveOwnedBatch(&again);
    try testing.expectEqual(@as(usize, 0), dup.inserted);
    try testing.expectEqual(@as(usize, 1), dup.exact_duplicates);
    try testing.expectEqual(duplicate.ptr, again[0].bytes.ptr);
    testing.allocator.free(again[0].bytes);
    try testing.expectEqual(@as(usize, 1), spool.len());

    const conflict = try testing.allocator.dupe(u8, "two\r\n");
    var bad = [_]OwnedBatchRecord{
        .{ .client = 7, .event_id = eventId(3), .bytes = conflict },
    };
    try testing.expectError(error.Equivocation, spool.reserveOwnedBatch(&bad));
    try testing.expectEqual(conflict.ptr, bad[0].bytes.ptr);
    testing.allocator.free(bad[0].bytes);
    try testing.expectEqualStrings("one\r\n", spool.entries.items[0].bytes);

    var limited = try Spool.init(testing.allocator, .{
        .max_attachments = 1,
        .max_records = 1,
        .max_total_bytes = 64,
        .max_record_bytes = 32,
    });
    defer limited.deinit();
    const keep = try testing.allocator.dupe(u8, "keep\r\n");
    const drop = try testing.allocator.dupe(u8, "drop\r\n");
    var overflow = [_]OwnedBatchRecord{
        .{ .client = 1, .event_id = eventId(1), .bytes = keep },
        .{ .client = 2, .event_id = eventId(1), .bytes = drop },
    };
    try testing.expectError(error.CapacityExceeded, limited.reserveOwnedBatch(&overflow));
    try testing.expectEqual(keep.ptr, overflow[0].bytes.ptr);
    try testing.expectEqual(drop.ptr, overflow[1].bytes.ptr);
    testing.allocator.free(overflow[0].bytes);
    testing.allocator.free(overflow[1].bytes);
    try testing.expectEqual(@as(usize, 0), limited.len());

    const left = try testing.allocator.dupe(u8, "left\r\n");
    const right = try testing.allocator.dupe(u8, "right\r\n");
    var pending = [_]OwnedBatchRecord{
        .{ .client = 4, .event_id = eventId(8), .bytes = left },
        .{ .client = 5, .event_id = eventId(8), .bytes = right },
    };
    var prepared = try spool.prepareOwnedBatch(&pending);
    try testing.expectEqual(@as(usize, 0), pending[0].bytes.len);
    try testing.expectEqual(@as(usize, 0), pending[1].bytes.len);
    try testing.expectEqual(left.ptr, prepared.staged[0].bytes.ptr);
    prepared.deinit();
    try testing.expectEqual(@as(usize, 1), spool.len());
}
