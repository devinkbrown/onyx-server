// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! history tests.

const std = @import("std");
const types = @import("types.zig");
const retained = @import("retained_message.zig");
const history = @import("store.zig");
const support = @import("test_support.zig");

test "append evicts oldest and latest returns newest first" {
    const Store = history.Lotus(.{ .max_targets = 2, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try support.appendForTest(&store, "#lotus", "m1", 1, "one");
    try support.appendForTest(&store, "#lotus", "m2", 2, "two");
    try support.appendForTest(&store, "#lotus", "m3", 3, "three");
    const result = try store.append("#lotus", .{
        .msgid = "m4",
        .sender = "alice",
        .text = "four",
        .timestamp = 4,
    });

    try std.testing.expect(result.evicted);
    try std.testing.expectEqual(@as(usize, 3), result.target_len);

    var out: [3]types.Message = undefined;
    const got = try store.latest("#lotus", 3, &out);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try support.expectMsg(got[0], "m4", 4, "four");
    try support.expectMsg(got[1], "m3", 3, "three");
    try support.expectMsg(got[2], "m2", 2, "two");
}

test "latest before and after page visible messages correctly" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 5, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try support.appendForTest(&store, "#lotus", "m1", 1, "one");
    try support.appendForTest(&store, "#lotus", "m2", 2, "two");
    try support.appendForTest(&store, "#lotus", "m3", 3, "three");
    try support.appendForTest(&store, "#lotus", "m4", 4, "four");
    try support.appendForTest(&store, "#lotus", "m5", 5, "five");

    var latest_out: [3]types.Message = undefined;
    const latest_page = try store.latest("#lotus", 3, &latest_out);
    try support.expectIds(latest_page, &.{ "m5", "m4", "m3" });

    var before_out: [2]types.Message = undefined;
    const before_page = try store.before("#lotus", 4, 2, &before_out);
    try support.expectIds(before_page, &.{ "m3", "m2" });

    var after_out: [3]types.Message = undefined;
    const after_page = try store.after("#lotus", 2, 3, &after_out);
    try support.expectIds(after_page, &.{ "m3", "m4", "m5" });
}

test "between window composes after() with an upper-bound filter" {
    // Mirrors the CHATHISTORY BETWEEN wiring in the daemon: collect oldest-first
    // after the low bound, then keep only those strictly before the high bound.
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 8, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try support.appendForTest(&store, "#lotus", "m1", 1, "one");
    try support.appendForTest(&store, "#lotus", "m2", 2, "two");
    try support.appendForTest(&store, "#lotus", "m3", 3, "three");
    try support.appendForTest(&store, "#lotus", "m4", 4, "four");
    try support.appendForTest(&store, "#lotus", "m5", 5, "five");

    // BETWEEN (1, 5): strictly between -> m2, m3, m4.
    var buf: [8]types.Message = undefined;
    const raw = try store.after("#lotus", 1, buf.len, &buf);
    var k: usize = 0;
    for (raw) |m| {
        if (m.timestamp < 5) {
            buf[k] = m;
            k += 1;
        }
    }
    try support.expectIds(buf[0..k], &.{ "m2", "m3", "m4" });
}

test "timestampOf resolves a msgid to its timestamp" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 4, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try support.appendForTest(&store, "#lotus", "m1", 11, "one");
    try support.appendForTest(&store, "#lotus", "m2", 22, "two");

    try std.testing.expectEqual(@as(?u64, 22), store.timestampOf("#lotus", "m2"));
    try std.testing.expectEqual(@as(?u64, 11), store.timestampOf("#lotus", "m1"));
    try std.testing.expectEqual(@as(?u64, null), store.timestampOf("#lotus", "nope"));
    try std.testing.expectEqual(@as(?u64, null), store.timestampOf("#absent", "m1"));
}

test "around window composes before() reversed + after() at the pivot" {
    // Mirrors the CHATHISTORY AROUND wiring: ~half strictly before the pivot
    // (reversed to chronological), then the pivot and later, oldest-first.
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 8, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try support.appendForTest(&store, "#lotus", "m1", 1, "one");
    try support.appendForTest(&store, "#lotus", "m2", 2, "two");
    try support.appendForTest(&store, "#lotus", "m3", 3, "three");
    try support.appendForTest(&store, "#lotus", "m4", 4, "four");
    try support.appendForTest(&store, "#lotus", "m5", 5, "five");

    // AROUND pivot=3, limit=4 -> half=2 before (m1,m2) + pivot/after (m3,m4).
    const center: u64 = 3;
    const total: usize = 4;
    const half = total / 2;
    var before_buf: [8]types.Message = undefined;
    var after_buf: [8]types.Message = undefined;
    const before_part = try store.before("#lotus", center, half, before_buf[0..half]);
    const remaining = total - before_part.len;
    const after_part = try store.after("#lotus", center - 1, remaining, after_buf[0..remaining]);
    var out: [8]types.Message = undefined;
    var k: usize = 0;
    var i: usize = before_part.len;
    while (i > 0) {
        i -= 1;
        out[k] = before_part[i];
        k += 1;
    }
    for (after_part) |m| {
        out[k] = m;
        k += 1;
    }
    try support.expectIds(out[0..k], &.{ "m1", "m2", "m3", "m4" });
}

test "redact hides reads but keeps slot" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try support.appendForTest(&store, "#lotus", "m1", 1, "one");
    try support.appendForTest(&store, "#lotus", "m2", 2, "two");
    try support.appendForTest(&store, "#lotus", "m3", 3, "three");
    try store.redact("#lotus", "m2");

    try std.testing.expectEqual(@as(usize, 3), try store.storedCount("#lotus"));

    var out: [3]types.Message = undefined;
    const got = try store.latest("#lotus", 3, &out);
    try support.expectIds(got, &.{ "m3", "m1" });
}

test "aggregate counts expose targets entries and tombstones" {
    const Store = history.Lotus(.{ .max_targets = 2, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try support.appendForTest(&store, "#a", "a1", 1, "one");
    try support.appendForTest(&store, "#a", "a2", 2, "two");
    try support.appendForTest(&store, "#b", "b1", 3, "three");
    try store.redact("#a", "a1");

    try std.testing.expectEqual(@as(usize, 2), store.targetCount());
    try std.testing.expectEqual(@as(usize, 3), store.totalStoredCount());
    try std.testing.expectEqual(@as(usize, 1), store.tombstoneCount());
}

test "root is deterministic and changes on edits and tombstones" {
    const Store = history.Lotus(.{ .max_targets = 2, .max_per_target = 3, .max_text = 32 });
    var first = Store.init(std.testing.allocator);
    defer first.deinit();
    var second = Store.init(std.testing.allocator);
    defer second.deinit();

    try support.appendForTest(&first, "#b", "b1", 3, "three");
    try support.appendForTest(&first, "#a", "a1", 1, "one");
    try support.appendForTest(&first, "#a", "a2", 2, "two");

    try support.appendForTest(&second, "#a", "a1", 1, "one");
    try support.appendForTest(&second, "#a", "a2", 2, "two");
    try support.appendForTest(&second, "#b", "b1", 3, "three");

    const before = first.root();
    try std.testing.expectEqualSlices(u8, &before, &second.root());

    try first.edit("#a", "a2", "two-edited");
    const edited = first.root();
    try std.testing.expect(!std.mem.eql(u8, &before, &edited));

    try first.redact("#a", "a1");
    const redacted = first.root();
    try std.testing.expect(!std.mem.eql(u8, &edited, &redacted));
}

test "edit replaces message text" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 2, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try support.appendForTest(&store, "kain", "m1", 1, "before");
    try store.edit("kain", "m1", "after");

    var out: [1]types.Message = undefined;
    const got = try store.latest("kain", 1, &out);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try support.expectMsg(got[0], "m1", 1, "after");
    const after_hash = retained.hashText("after");
    const before_hash = retained.hashText("before");
    try std.testing.expectEqualSlices(u8, &after_hash, &got[0].hash);
    try std.testing.expect(!std.mem.eql(u8, &before_hash, &got[0].hash));
}

test "client tags are retained for TAGMSG entries" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 2, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.append("#lotus", .{
        .msgid = "m1",
        .sender = "alice",
        .text = "",
        .timestamp = 1,
        .command = "TAGMSG",
        .client_tags = "+typing=active;+draft/reply=m0;+draft/react=ok",
    });

    var out: [1]types.Message = undefined;
    const got = try store.latest("#lotus", 1, &out);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqualStrings("TAGMSG", got[0].command);
    try std.testing.expectEqualStrings("+typing=active;+draft/reply=m0;+draft/react=ok", got[0].client_tags.?);
}

test "ownership remains leak free across fills evictions edits and deinit" {
    const Store = history.Lotus(.{ .max_targets = 2, .max_per_target = 4, .max_text = 64 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    var i: usize = 0;
    while (i < 24) : (i += 1) {
        var msgid_buf: [16]u8 = undefined;
        var text_buf: [32]u8 = undefined;
        const msgid = try std.fmt.bufPrint(&msgid_buf, "m{d}", .{i});
        const text = try std.fmt.bufPrint(&text_buf, "body-{d}", .{i});
        const target: []const u8 = if (i % 2 == 0) "#a" else "#b";
        _ = try store.append(target, .{
            .msgid = msgid,
            .sender = "alice",
            .text = text,
            .timestamp = @intCast(i),
        });
    }

    try store.edit("#a", "m22", "edited-body");
    try store.redact("#b", "m23");

    var out: [4]types.Message = undefined;
    const got = try store.latest("#a", 4, &out);
    try std.testing.expect(got.len > 0);
    try support.expectMsg(got[0], "m22", 22, "edited-body");
}
