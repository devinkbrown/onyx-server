// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded RFC 5322 message assembly and header validation.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const smtp_client = @import("../../proto/smtp_client.zig");
const platform = @import("../../substrate/platform.zig");
const Config = @import("config.zig").Config;
const max_message_len = @import("limits.zig").max_message_len;
const max_body_len = @import("limits.zig").max_body_len;
const Job = @import("model.zig").Job;

/// Assemble the RFC 5322 message into `out`; body truncated to `max_body_len`.
/// Returns an empty slice if any header field carries a CR/LF (M2: defensive
/// header-injection guard — a caller treats an empty build as "skip enqueue").
pub fn buildMessage(out: *[max_message_len]u8, config: Config, job: Job) []const u8 {
    if (hasCrlf(job.to) or hasCrlf(config.from) or hasCrlf(job.subject)) return out[0..0];
    const body = job.body[0..@min(job.body.len, max_body_len)];
    // The Date is a fixed, syntactically-valid stub; the relay stamps its own
    // Received date, so a wall-clock-to-civil-time conversion is not worth it.
    return std.fmt.bufPrint(
        out,
        "From: <{s}>\r\nTo: <{s}>\r\nSubject: {s}\r\n" ++
            "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\nMessage-ID: <{d}@{s}>\r\n" ++
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{s}",
        .{
            config.from,                                    job.to,             job.subject,
            @as(u64, @bitCast(platform.monotonicMillis())), config.ehlo_domain, body,
        },
    ) catch out[0..0];
}

pub fn wallClockSeconds() i64 {
    if (comptime @import("builtin").os.tag != .linux) return @divTrunc(platform.realtimeMillis(), 1000);
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// True if `s` carries a raw CR or LF — the bytes an attacker would use to splice
/// extra SMTP/RFC 5322 headers. Used to reject header injection in `buildMessage`.
fn hasCrlf(s: []const u8) bool {
    return std.mem.indexOfScalar(u8, s, '\r') != null or std.mem.indexOfScalar(u8, s, '\n') != null;
}
