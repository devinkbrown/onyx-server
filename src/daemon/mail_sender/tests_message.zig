// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");
const testing = std.testing;
const max_message_len = @import("limits.zig").max_message_len;
const max_body_len = @import("limits.zig").max_body_len;
const Job = @import("model.zig").Job;
const testConfig = @import("core.zig").testConfig;
const buildMessage = @import("message.zig").buildMessage;

test "buildMessage emits well-formed headers and truncates an over-long body" {
    var buf: [max_message_len]u8 = undefined;
    var long_body: [max_body_len + 4096]u8 = undefined;
    @memset(&long_body, 'x');
    const job = Job{
        .to = @constCast("rcpt@example.test"),
        .subject = @constCast("Reset code"),
        .body = &long_body,
    };
    const msg = buildMessage(&buf, testConfig(), job);
    try testing.expect(std.mem.indexOf(u8, msg, "From: <noreply@example.test>\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "To: <rcpt@example.test>\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "Subject: Reset code\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "\r\n\r\n") != null); // header/body separator
    // The body was truncated to at most max_body_len bytes.
    const sep = std.mem.indexOf(u8, msg, "\r\n\r\n").? + 4;
    try testing.expect(msg.len - sep <= max_body_len);
}

test "buildMessage refuses a CRLF in a header field (header-injection guard)" {
    var buf: [max_message_len]u8 = undefined;
    // A `to` carrying a CRLF would otherwise splice an attacker-controlled header.
    const job = Job{
        .to = @constCast("rcpt@example.test\r\nBcc: victim@example.test"),
        .subject = @constCast("Reset code"),
        .body = @constCast("body"),
    };
    const msg = buildMessage(&buf, testConfig(), job);
    try testing.expectEqual(@as(usize, 0), msg.len);

    // A bare LF in the subject is likewise rejected.
    const job2 = Job{
        .to = @constCast("rcpt@example.test"),
        .subject = @constCast("Reset\ncode"),
        .body = @constCast("body"),
    };
    try testing.expectEqual(@as(usize, 0), buildMessage(&buf, testConfig(), job2).len);
}
