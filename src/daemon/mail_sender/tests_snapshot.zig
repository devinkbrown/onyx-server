// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");
const runtime_pause = @import("../runtime_pause.zig");
const testing = std.testing;
const Config = @import("config.zig").Config;
const Sender = @import("core.zig").Sender;

fn pausedMailCaptureAllocation(allocator: std.mem.Allocator, sender: *Sender, token: runtime_pause.Token) !void {
    var snapshot = try sender.capturePaused(allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.jobs.len);
    try std.testing.expectEqualStrings("verification secret", snapshot.jobs[0].body);
    try std.testing.expectEqual(@as(u64, 1337), snapshot.failure_seq);
}

test "companion runtime mail retained FIFO sequence secret custody and every restore OOM" {
    const config: Config = .{ .relay_host = "relay.invalid", .ehlo_domain = "test.invalid", .from = "sender@test.invalid" };
    var sender = try Sender.init(std.testing.allocator, config);
    try sender.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &sender }};
    const gate = runtime_pause.start_gate.create(std.testing.allocator, std.testing.io, &specs) catch |err| {
        sender.deinit();
        return err;
    };
    defer {
        sender.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        sender.detachAfterJoined() catch unreachable;
        sender.deinit();
        gate.control.destroyJoined();
    }
    const input = try std.testing.allocator.dupe(u8, "verification secret");
    sender.enqueue("first@test.invalid", "verify", input);
    std.testing.allocator.free(input);
    sender.enqueue("second@test.invalid", "reset", "reset secret");
    sender.failure_seq = 1337;
    const token = try sender.requestPause(1);
    try sender.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.mail, 0, &sender));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expectEqual(@as(usize, 2), sender.job_count);
    gate.control.releaseAll();
    try sender.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pausedMailCaptureAllocation, .{ &sender, token });
    var snapshot = try sender.capturePaused(std.testing.allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    var n: usize = 0;
    while (true) : (n += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var restored = try Sender.init(failing.allocator(), config);
        defer restored.deinit();
        restored.enqueue("old@test.invalid", "old", "accepted OLD secret");
        try std.testing.expectEqual(@as(usize, 1), restored.job_count);
        restored.failure_seq = 19;
        const old = restored.jobs[0];
        failing.fail_index = failing.alloc_index + n;
        restored.restoreSnapshot(&snapshot, 1024 * 1024) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 1), restored.job_count);
            try std.testing.expectEqual(@as(u64, 19), restored.failure_seq);
            try std.testing.expectEqual(@intFromPtr(old.body.ptr), @intFromPtr(restored.jobs[0].body.ptr));
            try std.testing.expectEqualStrings("accepted OLD secret", restored.jobs[0].body);
            failing.fail_index = std.math.maxInt(usize);
            try restored.restoreSnapshot(&snapshot, 1024 * 1024);
            try std.testing.expectEqual(@as(usize, 2), restored.job_count);
            try std.testing.expectEqualStrings("verification secret", restored.jobs[0].body);
            continue;
        };
        try std.testing.expectEqual(@as(usize, 7), n);
        try std.testing.expectEqual(@as(u64, 1337), restored.failure_seq);
        try std.testing.expectEqualStrings("reset secret", restored.jobs[1].body);
        break;
    }
    snapshot.config_digest[0] ^= 1;
    var refused = try Sender.init(std.testing.allocator, config);
    defer refused.deinit();
    try std.testing.expectError(error.ConfigMismatch, refused.restoreSnapshot(&snapshot, 1024 * 1024));
    try std.testing.expectEqual(@as(usize, 0), refused.job_count);
    snapshot.config_digest[0] ^= 1;
    try std.testing.expectError(error.Capacity, sender.capturePaused(std.testing.allocator, token, 1));
    // A real synchronous caller is part of the same source operation census.
    sender.active_settles.store(1, .release);
    try std.testing.expectError(error.OperationActive, sender.capturePaused(std.testing.allocator, token, 1024 * 1024));
    sender.active_settles.store(0, .release);
    try std.testing.expectEqual(@as(usize, 2), sender.job_count);
}
