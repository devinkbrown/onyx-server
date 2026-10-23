// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! exact once tests.

const std = @import("std");
const types = @import("types.zig");
const retained = @import("retained_message.zig");
const history = @import("store.zig");
const support = @import("test_support.zig");

test "exact-once ingestion classifies every retained identity field without mutation" {
    const Store = history.Lotus(.{ .max_targets = 2, .max_per_target = 4, .max_text = 64 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const original = types.ExactInputMessage{
        .msgid = "mesh-1",
        .sender = "alice",
        .text = "hello",
        .timestamp = 11,
        .command = "NOTICE",
        .client_tags = "+draft/reply=mesh-0",
    };
    switch (try store.ingestExactOnce("#lotus", original)) {
        .inserted => |result| {
            try std.testing.expect(!result.evicted);
            try std.testing.expectEqual(@as(usize, 1), result.target_len);
        },
        else => return error.TestUnexpectedResult,
    }

    const before = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(before);
    switch (try store.ingestExactOnce("#lotus", original)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }

    const conflicts = [_]types.ExactInputMessage{
        .{ .msgid = "mesh-1", .sender = "mallory", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "changed", .timestamp = 11, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 12, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "PRIVMSG", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = null },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = "" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0", .tombstone = true },
    };
    for (conflicts) |conflict| {
        switch (try store.ingestExactOnce("#lotus", conflict)) {
            .equivocation => {},
            else => return error.TestUnexpectedResult,
        }
        const after_conflict = try store.encodeCheckpoint(std.testing.allocator);
        defer std.testing.allocator.free(after_conflict);
        try std.testing.expectEqualSlices(u8, before, after_conflict);
    }

    // A msgid is global within the retained Lotus window, not target-scoped.
    switch (try store.ingestExactOnce("#other", original)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), store.targetCount());
    const after = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "exact-once ingestion tracks edited and redacted retained state" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 3, .max_text = 64 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const original = types.ExactInputMessage{
        .msgid = "mesh-edit",
        .sender = "alice",
        .text = "before",
        .timestamp = 20,
    };
    switch (try store.ingestExactOnce("#lotus", original)) {
        .inserted => {},
        else => return error.TestUnexpectedResult,
    }
    try store.edit("#lotus", original.msgid, "after");

    switch (try store.ingestExactOnce("#lotus", original)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    const edited = types.ExactInputMessage{
        .msgid = original.msgid,
        .sender = original.sender,
        .text = "after",
        .timestamp = original.timestamp,
    };
    switch (try store.ingestExactOnce("#lotus", edited)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }

    try store.redact("#lotus", original.msgid);
    const before = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(before);
    switch (try store.ingestExactOnce("#lotus", edited)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    const redacted = types.ExactInputMessage{
        .msgid = original.msgid,
        .sender = original.sender,
        .text = "after",
        .timestamp = original.timestamp,
        .tombstone = true,
    };
    switch (try store.ingestExactOnce("#lotus", redacted)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    const after = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "exact-once ingestion preserves eviction boundaries and legacy append semantics" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 2, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const first = types.ExactInputMessage{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 };
    const second = types.ExactInputMessage{ .msgid = "m2", .sender = "alice", .text = "two", .timestamp = 2 };
    const third = types.ExactInputMessage{ .msgid = "m3", .sender = "alice", .text = "three", .timestamp = 3 };
    switch (try store.ingestExactOnce("#lotus", first)) {
        .inserted => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.ingestExactOnce("#lotus", second)) {
        .inserted => {},
        else => return error.TestUnexpectedResult,
    }
    const full_root = store.root();
    switch (try store.ingestExactOnce("#lotus", first)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.ingestExactOnce("#lotus", .{ .msgid = "m1", .sender = "alice", .text = "conflict", .timestamp = 1 })) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualSlices(u8, &full_root, &store.root());

    switch (try store.ingestExactOnce("#lotus", third)) {
        .inserted => |result| try std.testing.expect(result.evicted),
        else => return error.TestUnexpectedResult,
    }
    // Once m1 has left the bounded retained window it can be inserted again.
    switch (try store.ingestExactOnce("#lotus", first)) {
        .inserted => |result| try std.testing.expect(result.evicted),
        else => return error.TestUnexpectedResult,
    }
    var out: [2]types.Message = undefined;
    try support.expectIds(try store.latest("#lotus", 2, &out), &.{ "m1", "m3" });

    // The existing append API still accepts a repeated msgid by design.
    var legacy = Store.init(std.testing.allocator);
    defer legacy.deinit();
    _ = try legacy.append("#lotus", types.exactInput(first));
    _ = try legacy.append("#lotus", .{ .msgid = "m1", .sender = "alice", .text = "different", .timestamp = 2 });
    try std.testing.expectEqual(@as(usize, 2), legacy.totalStoredCount());
}

test "exact-once ingestion is atomic across allocation failures and non-inserts allocate nothing" {
    const Store = history.Lotus(.{ .max_targets = 2, .max_per_target = 2, .max_text = 32 });
    const FullRingSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.ingestExactOnce("#a", .{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 });
            _ = try store.ingestExactOnce("#a", .{ .msgid = "m2", .sender = "alice", .text = "two", .timestamp = 2 });
            const before = store.root();
            const outcome = store.ingestExactOnce("#a", .{ .msgid = "m3", .sender = "alice", .text = "three", .timestamp = 3 }) catch |err| {
                try std.testing.expectEqualSlices(u8, &before, &store.root());
                try std.testing.expectEqual(@as(usize, 2), store.totalStoredCount());
                return err;
            };
            switch (outcome) {
                .inserted => |result| try std.testing.expect(result.evicted),
                else => return error.TestUnexpectedResult,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, FullRingSweep.run, .{});

    const NewTargetSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.ingestExactOnce("#a", .{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 });
            const before = store.root();
            const outcome = store.ingestExactOnce("#b", .{
                .msgid = "m2",
                .sender = "bob",
                .text = "two",
                .timestamp = 2,
                .command = "TAGMSG",
                .client_tags = "+typing=active",
            }) catch |err| {
                try std.testing.expectEqualSlices(u8, &before, &store.root());
                try std.testing.expectEqual(@as(usize, 1), store.totalStoredCount());
                try std.testing.expectEqual(@as(usize, 1), store.targetCount());
                return err;
            };
            switch (outcome) {
                .inserted => |result| try std.testing.expect(!result.evicted),
                else => return error.TestUnexpectedResult,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, NewTargetSweep.run, .{});

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var store = Store.init(failing.allocator());
    defer store.deinit();
    const exact = types.ExactInputMessage{ .msgid = "stable", .sender = "alice", .text = "body", .timestamp = 10 };
    _ = try store.ingestExactOnce("#a", exact);
    const before = store.root();
    failing.fail_index = failing.alloc_index;
    switch (try store.ingestExactOnce("#a", exact)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.ingestExactOnce("#a", .{ .msgid = "stable", .sender = "alice", .text = "other", .timestamp = 10 })) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &before, &store.root());
}

test "exact-once ingestion classifies repeated msgids restored from legacy append checkpoints" {
    const Store = history.Lotus(.{ .max_targets = 1, .max_per_target = 4, .max_text = 32 });
    const exact = types.ExactInputMessage{
        .msgid = "legacy-id",
        .sender = "alice",
        .text = "same",
        .timestamp = 10,
        .command = "NOTICE",
        .client_tags = "+x=1",
    };

    var legacy_exact = Store.init(std.testing.allocator);
    defer legacy_exact.deinit();
    _ = try legacy_exact.append("#lotus", types.exactInput(exact));
    _ = try legacy_exact.append("#lotus", types.exactInput(exact));
    const exact_wire = try legacy_exact.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(exact_wire);
    var restored_exact = try Store.decodeCheckpoint(std.testing.allocator, exact_wire);
    defer restored_exact.deinit();
    switch (try restored_exact.ingestExactOnce("#lotus", exact)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    const exact_after = try restored_exact.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(exact_after);
    try std.testing.expectEqualSlices(u8, exact_wire, exact_after);
    try std.testing.expectEqual(@as(usize, 2), restored_exact.totalStoredCount());

    var legacy_conflict = Store.init(std.testing.allocator);
    defer legacy_conflict.deinit();
    _ = try legacy_conflict.append("#lotus", types.exactInput(exact));
    _ = try legacy_conflict.append("#lotus", .{
        .msgid = exact.msgid,
        .sender = exact.sender,
        .text = "different",
        .timestamp = exact.timestamp,
        .command = exact.command,
        .client_tags = exact.client_tags,
    });
    const conflict_wire = try legacy_conflict.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(conflict_wire);
    var restored_conflict = try Store.decodeCheckpoint(std.testing.allocator, conflict_wire);
    defer restored_conflict.deinit();
    switch (try restored_conflict.ingestExactOnce("#lotus", exact)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    const conflict_after = try restored_conflict.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(conflict_after);
    try std.testing.expectEqualSlices(u8, conflict_wire, conflict_after);
    try std.testing.expectEqual(@as(usize, 2), restored_conflict.totalStoredCount());
}
