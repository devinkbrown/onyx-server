// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Absolute monotonic deadlines: retries and partial I/O never renew a budget.

const std = @import("std");
const platform = @import("../../substrate/platform.zig");

pub const max_query_ms: u32 = 5000;

pub const Deadline = struct {
    expires_ms: i64,

    pub fn after(budget_ms: u32) Deadline {
        return at(platform.monotonicMillis(), budget_ms);
    }

    pub fn at(now_ms: i64, budget_ms: u32) Deadline {
        return .{ .expires_ms = now_ms +| @as(i64, @min(max_query_ms, @max(1, budget_ms))) };
    }

    pub fn remaining(self: Deadline) error{Timeout}!u32 {
        return self.remainingAt(platform.monotonicMillis());
    }

    pub fn remainingAt(self: Deadline, now_ms: i64) error{Timeout}!u32 {
        if (now_ms >= self.expires_ms) return error.Timeout;
        return @intCast(@min(@as(i128, self.expires_ms) - now_ms, max_query_ms));
    }

    pub fn slice(self: Deadline, attempt_ms: u32) error{Timeout}!Deadline {
        return .{ .expires_ms = @min(self.expires_ms, after(attempt_ms).expires_ms) };
    }
};

test "DNS absolute deadlines clamp zero overflow and oversized budgets" {
    try std.testing.expectEqual(@as(i64, 101), Deadline.at(100, 0).expires_ms);
    try std.testing.expectEqual(@as(i64, 5100), Deadline.at(100, std.math.maxInt(u32)).expires_ms);
    const deadline = Deadline.at(100, 20);
    try std.testing.expectEqual(@as(u32, 20), try deadline.remainingAt(100));
    try std.testing.expectEqual(@as(u32, 1), try deadline.remainingAt(119));
    try std.testing.expectError(error.Timeout, deadline.remainingAt(120));
    try std.testing.expectError(error.Timeout, deadline.remainingAt(121));
    try std.testing.expectEqual(std.math.maxInt(i64), Deadline.at(std.math.maxInt(i64) - 1, 20).expires_ms);
}
