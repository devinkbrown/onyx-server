// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");
const testing = std.testing;
const job_capacity = @import("limits.zig").job_capacity;
const Sender = @import("core.zig").Sender;
const testConfig = @import("core.zig").testConfig;

test "the ring is bounded: overflow is dropped without crashing" {
    var s = try Sender.init(testing.allocator, testConfig());
    defer s.deinit();

    var i: usize = 0;
    while (i < job_capacity + 32) : (i += 1) {
        s.enqueue("rcpt@example.test", "subject", "body");
    }
    try testing.expectEqual(job_capacity, s.job_count);
}

test "deinit frees queued (un-sent) jobs with no leak" {
    var s = try Sender.init(testing.allocator, testConfig());
    s.enqueue("a@example.test", "s1", "b1");
    s.enqueue("b@example.test", "s2", "b2");
    s.enqueue("c@example.test", "s3", "b3");
    try testing.expectEqual(@as(usize, 3), s.job_count);
    // deinit must free the three queued jobs + the ring (testing.allocator
    // asserts no leak on teardown).
    s.deinit();
}
