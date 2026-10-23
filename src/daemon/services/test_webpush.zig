// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webpush regression tests.

const std = @import("std");
const store_mod = @import("../store.zig");
const OroStore = @import("records.zig").OroStore;
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const WebpushPruneResult = @import("contracts.zig").WebpushPruneResult;
const webpush_prune_dead = @import("test_support.zig").webpush_prune_dead;
const webpushPruneTestSeed = @import("test_support.zig").webpushPruneTestSeed;
const webpushPruneTestProgress = @import("test_support.zig").webpushPruneTestProgress;
const webpush_value_max = @import("contracts.zig").webpush_value_max;

test "webpush reconciliation: real all-account private rows commit synced groups and cold reopen exact subscriptions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "webpush-prune.wal");
        defer store.deinit();
        var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
        try webpushPruneTestSeed(&services);
        const result = try services.webpushPruneDead(std.testing.allocator, &webpush_prune_dead);
        try std.testing.expectEqual(@as(usize, 7), result.rows_examined);
        try std.testing.expectEqual(@as(usize, 6), result.rows_changed);
        try std.testing.expectEqual(@as(usize, 12), result.subscriptions_removed);
        try std.testing.expectEqual(@as(usize, 6), try webpushPruneTestProgress(&services));
        const sequence = store.next_seq;
        const offset = store.wal_offset;
        const repeated = try services.webpushPruneDead(std.testing.allocator, &webpush_prune_dead);
        try std.testing.expectEqual(@as(usize, 0), repeated.rows_changed);
        try std.testing.expectEqual(sequence, store.next_seq);
        try std.testing.expectEqual(offset, store.wal_offset);
    }
    var reopened = try openTestStore(tmp, "webpush-prune.wal");
    defer reopened.deinit();
    var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
    try std.testing.expectEqual(@as(usize, 6), try webpushPruneTestProgress(&cold));
    _ = try cold.identifyAccount("alpha", "test-password");
}

test "webpush reconciliation: every allocator failure retains exact old or synced-prefix rows and complete cut retries same Store with cold replay" {
    var failures: usize = 0;
    var prefix_failures: usize = 0;
    for (0..256) |index| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
        var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "webpush-oom.wal");
        defer store.deinit();
        var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
        try webpushPruneTestSeed(&services);
        const sequence = store.next_seq;
        const before = try tmp.dir.readFileAlloc(std.testing.io, "webpush-oom.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        failing.fail_index = failing.alloc_index + index;
        var induced = false;
        _ = services.webpushPruneDead(failing.allocator(), &webpush_prune_dead) catch |err| blk: {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expect(!store.preparedWritesPoisoned());
            const progress = try webpushPruneTestProgress(&services);
            try std.testing.expect(progress == 0 or progress == 4);
            try std.testing.expectEqual(sequence + progress, store.next_seq);
            if (progress == 0) {
                const after = try tmp.dir.readFileAlloc(std.testing.io, "webpush-oom.wal", std.testing.allocator, .unlimited);
                defer std.testing.allocator.free(after);
                try std.testing.expectEqualSlices(u8, before, after);
            } else prefix_failures += 1;
            // Original live row publication agrees with actual synced WAL.
            {
                var reopened = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "webpush-oom.wal", .{});
                defer reopened.deinit();
                var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
                try std.testing.expectEqual(progress, try webpushPruneTestProgress(&cold));
            }
            // Retry the SAME live original Store. An independent read-only
            // replay proves the synced result; no owner is substituted.
            _ = try services.webpushPruneDead(failing.allocator(), &webpush_prune_dead);
            try std.testing.expectEqual(@as(usize, 6), try webpushPruneTestProgress(&services));
            {
                var reopened = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "webpush-oom.wal", .{});
                defer reopened.deinit();
                var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
                try std.testing.expectEqual(@as(usize, 6), try webpushPruneTestProgress(&cold));
            }
            failures += 1;
            induced = true;
            break :blk Services.WebpushPruneResult{};
        };
        if (!induced) {
            try std.testing.expectEqual(@as(usize, 6), try webpushPruneTestProgress(&services));
            try std.testing.expect(failures > 0 and prefix_failures > 0);
            std.debug.print("webpush reconciliation: {d} allocator failures including {d} synced-prefix retries\n", .{ failures, prefix_failures });
            return;
        }
    }
    return error.FailureSweepDidNotComplete;
}

test "webpush reconciliation: failed short and uncertain sync preserve live predecessor and require actual poisoned Store cold reopen" {
    const cases = [_]struct { fault: store_mod.PreparedIoFault, durable_rows: usize }{
        .{ .fault = .{ .write = .failed }, .durable_rows = 0 },
        .{ .fault = .{ .write = .short }, .durable_rows = 0 },
        .{ .fault = .{ .sync = true }, .durable_rows = 4 },
    };
    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, "webpush-io.wal");
            defer store.deinit();
            var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
            try webpushPruneTestSeed(&services);
            const sequence = store.next_seq;
            const offset = store.wal_offset;
            store.setPreparedIoFault(case.fault);
            try std.testing.expectError(error.IoAmbiguous, services.webpushPruneDead(std.testing.allocator, &webpush_prune_dead));
            try std.testing.expect(store.preparedWritesPoisoned());
            try std.testing.expectEqual(@as(usize, 0), try webpushPruneTestProgress(&services));
            try std.testing.expectEqual(sequence, store.next_seq);
            try std.testing.expectEqual(offset, store.wal_offset);
            try std.testing.expectError(error.StorePoisoned, services.webpushPruneDead(std.testing.allocator, &webpush_prune_dead));
        }
        var reopened = try openTestStore(tmp, "webpush-io.wal");
        defer reopened.deinit();
        var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
        try std.testing.expectEqual(case.durable_rows, try webpushPruneTestProgress(&cold));
        _ = try cold.webpushPruneDead(std.testing.allocator, &webpush_prune_dead);
        try std.testing.expectEqual(@as(usize, 6), try webpushPruneTestProgress(&cold));
    }
}

test "webpush reconciliation: malformed private rows fail before any pruning and unrelated namespaces stay outside the cut" {
    const faults = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "wps\x00bad", .value = "not a subscription" },
        .{ .key = "wps\x00BAD", .value = "" },
        .{ .key = "wps\x00", .value = "" },
    };
    for (faults) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "webpush-malformed.wal");
        defer store.deinit();
        var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
        try webpushPruneTestSeed(&services);
        try store.family(.props).put(fault.key, fault.value);
        const sequence = store.next_seq;
        const before = try tmp.dir.readFileAlloc(std.testing.io, "webpush-malformed.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        if (services.webpushPruneDead(std.testing.allocator, &webpush_prune_dead)) |_| return error.ExpectedMalformedRecord else |err| try std.testing.expect(err == error.InvalidRecord or err == error.MalformedRecord);
        try std.testing.expectEqual(@as(usize, 0), try webpushPruneTestProgress(&services));
        try std.testing.expectEqual(sequence, store.next_seq);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "webpush-malformed.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
    }
}

test "webpush reconciliation: original absolute deadline rejects before allocation or durable mutation and a fresh deadline admits exact pruning" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "webpush-deadline.wal");
    defer store.deinit();
    var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
    try webpushPruneTestSeed(&services);
    const sequence = store.next_seq;
    const before = try tmp.dir.readFileAlloc(std.testing.io, "webpush-deadline.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    try std.testing.expectError(error.Timeout, services.webpushPruneDeadUntil(failing.allocator(), &webpush_prune_dead, expired));
    const wrong: std.Io.Clock.Timestamp = .{ .clock = .real, .raw = .zero };
    try std.testing.expectError(error.InvalidDeadline, services.webpushPruneDeadUntil(failing.allocator(), &webpush_prune_dead, wrong));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(sequence, store.next_seq);
    try std.testing.expectEqual(@as(usize, 0), try webpushPruneTestProgress(&services));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "webpush-deadline.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    const fresh: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = std.Io.Clock.awake.now(std.testing.io).addDuration(.fromMilliseconds(5000)) };
    const result = try services.webpushPruneDeadUntil(std.testing.allocator, &webpush_prune_dead, fresh);
    try std.testing.expectEqual(@as(usize, 6), result.rows_changed);
    try std.testing.expectEqual(@as(usize, 6), try webpushPruneTestProgress(&services));
}

test "services shared context strict webpush copy distinguishes source poison allocation failure malformed data and absence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "strict-copy.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try std.testing.expect((try services.legacyStore()) == &store);
    try std.testing.expect((try services.webpushGetAllocStrict(std.testing.allocator, "alice")) == null);
    try services.webpushPutStrict("alice", "malformed original subscription image");
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, services.webpushGetAllocStrict(failing.allocator(), "alice"));
    const exact = (try services.webpushGetAllocStrict(std.testing.allocator, "alice")).?;
    defer std.testing.allocator.free(exact);
    try std.testing.expectEqualStrings("malformed original subscription image", exact);
    try std.testing.expectError(error.InvalidName, services.webpushGetAllocStrict(std.testing.allocator, "invalid name"));
    var plan = try store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "source", .value = "uncertain" }});
    defer plan.abort();
    store.setPreparedIoFault(.{ .sync = true });
    try std.testing.expectError(error.IoAmbiguous, plan.commit());
    try std.testing.expectError(error.StorePoisoned, services.webpushGetAllocStrict(std.testing.allocator, "alice"));
}

test "services shared context strict webpush mutation refuses invalid or oversized input and retains legacy unbound access" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "strict-put.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.webpushPutStrict("alice", "original");
    const before = store.next_seq;
    try std.testing.expectError(error.InvalidName, services.webpushPutStrict("invalid name", "replacement"));
    var oversized: [Services.webpush_value_max + 1]u8 = @splat('x');
    try std.testing.expectError(error.InvalidValue, services.webpushPutStrict("alice", &oversized));
    try std.testing.expectEqual(before, store.next_seq);
    const value = (try services.webpushGetAllocStrict(std.testing.allocator, "alice")).?;
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("original", value);
    try std.testing.expect((try services.legacyStore()) == &store);
}
