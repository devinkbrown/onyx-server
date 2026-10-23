// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: managed bridge.

const std = @import("std");
const KvTable = @import("table.zig").KvTable;
const StoreOwnerObserver = @import("tests_source_owner.zig").StoreOwnerObserver;

test "STORE managed core distinct NEW origin preserves OLD growth and shared Work" {
    var old: StoreOwnerObserver = .{};
    var candidate: StoreOwnerObserver = .{};
    var table = KvTable.init(old.allocator());
    defer table.deinit();
    try table.ensureUnusedCapacity(6);
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f" };
    for (keys) |key| {
        const entry = try table.getOrPut(key);
        entry.value_ptr.* = @constCast("OLD");
    }
    const before_ptr = table.slots.ptr;
    const before_len = table.slots.len;
    const before_revision = table.revision;
    const old_calls = old.calls;
    old.fail_at = old.calls;
    var work: KvTable.Work = .{ .limit = 100_000 };
    var first = try table.prepareWithStorage(&.{.{ .key = "g", .value = @constCast("NEW") }}, candidate.allocator(), &work);
    try std.testing.expect(first.replacement != null);
    try std.testing.expectEqual(old_calls, old.calls);
    try std.testing.expectEqual(@intFromPtr(before_ptr), @intFromPtr(table.slots.ptr));
    try std.testing.expectEqual(before_len, table.slots.len);
    try std.testing.expectEqual(before_revision, table.revision);
    try std.testing.expectEqualStrings("OLD", table.get("a").?);
    const used = work.total;
    try first.validate();
    try std.testing.expect(work.total > used);
    first.abort();
    try candidate.checkAll(false);
    var second = try table.prepareWithStorage(&.{.{ .key = "h", .value = @constCast("NEXT") }}, candidate.allocator(), &work);
    try std.testing.expect(work.total > used);
    second.abort();
    try candidate.checkAll(false);
    try std.testing.expect(table.get("g") == null and table.get("h") == null);
    // Ordinary inline plans remain movable without a pointer to a dead stack.
    var ordinary = try table.prepare(&.{.{ .key = "a", .value = @constCast("UPDATE") }}, 100_000);
    try std.testing.expect(ordinary.shared_work == null);
    try ordinary.validate();
    ordinary.abort();
}

test "STORE managed core shared work cannot reset across families and OOM retry" {
    for (0..3) |fail_at| {
        var a = KvTable.init(std.testing.allocator);
        defer a.deinit();
        var b = KvTable.init(std.testing.allocator);
        defer b.deinit();
        var candidate: StoreOwnerObserver = .{ .fail_at = fail_at };
        var work: KvTable.Work = .{ .limit = 100_000 };
        var p = a.prepareWithStorage(&.{.{ .key = "a", .value = @constCast("A") }}, candidate.allocator(), &work) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try candidate.checkAll(false);
            try std.testing.expectEqual(@as(usize, 0), a.slots.len);
            candidate.fail_at = std.math.maxInt(usize);
            var retry = try a.prepareWithStorage(&.{.{ .key = "a", .value = @constCast("A") }}, candidate.allocator(), &work);
            retry.abort();
            try candidate.checkAll(false);
            continue;
        };
        var q = b.prepareWithStorage(&.{.{ .key = "b", .value = @constCast("B") }}, candidate.allocator(), &work) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            p.abort();
            try candidate.checkAll(false);
            try std.testing.expectEqual(@as(usize, 0), b.slots.len);
            candidate.fail_at = std.math.maxInt(usize);
            var retry = try b.prepareWithStorage(&.{.{ .key = "b", .value = @constCast("B") }}, candidate.allocator(), &work);
            retry.abort();
            try candidate.checkAll(false);
            continue;
        };
        const spent = work.total;
        work.limit = spent;
        try std.testing.expectError(error.TableWorkExceeded, q.validate());
        p.abort();
        q.abort();
        try candidate.checkAll(false);
        try std.testing.expectEqual(@as(usize, 0), a.slots.len);
        try std.testing.expectEqual(@as(usize, 0), b.slots.len);
    }
}
