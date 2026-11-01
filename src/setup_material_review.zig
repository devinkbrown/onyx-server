// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded headless acknowledgement channel. IDs correlate a public review to
//! this process; they are not credentials and are never persisted.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const max_ack = 1024;
const timeout_ms: i64 = 60_000;

const Nonblocking = struct {
    fd: i32,
    old: usize,
    fn open(fd: i32) !Nonblocking {
        const old = linux.fcntl(fd, linux.F.GETFL, 0);
        if (std.posix.errno(old) != .SUCCESS) return error.ReviewChannelUnavailable;
        var flags: linux.O = @bitCast(@as(u32, @truncate(old)));
        flags.NONBLOCK = true;
        if (std.posix.errno(linux.fcntl(fd, linux.F.SETFL, @as(u32, @bitCast(flags)))) != .SUCCESS) return error.ReviewChannelUnavailable;
        return .{ .fd = fd, .old = old };
    }
    fn close(self: Nonblocking) void {
        _ = linux.fcntl(self.fd, linux.F.SETFL, self.old);
    }
};
fn nowMillis() !i64 {
    var ts: linux.timespec = undefined;
    if (std.posix.errno(linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts)) != .SUCCESS) return error.ReviewClockUnavailable;
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}
fn wait(fd: i32, events: i16, deadline: i64) !void {
    while (true) {
        const remaining = deadline - try nowMillis();
        if (remaining <= 0) return error.ReviewTimedOut;
        var descriptors = [_]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        const rc = linux.poll(&descriptors, 1, @intCast(remaining));
        switch (std.posix.errno(rc)) {
            .INTR => continue,
            .SUCCESS => {},
            else => return error.ReviewChannelUnavailable,
        }
        if (rc == 0) return error.ReviewTimedOut;
        if (descriptors[0].revents & (events | linux.POLL.HUP | linux.POLL.ERR) != 0) return;
        return error.ReviewChannelUnavailable;
    }
}
fn writeBounded(fd: i32, bytes: []const u8, deadline: i64) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        try wait(fd, linux.POLL.OUT, deadline);
        const rc = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (std.posix.errno(rc)) {
            .INTR, .AGAIN => continue,
            .SUCCESS => {},
            else => return error.ReviewChannelUnavailable,
        }
        if (rc == 0) return error.ReviewChannelUnavailable;
        offset += rc;
    }
}
const Ack = struct { action: []const u8, review_id: []const u8 };
pub fn parseAck(allocator: std.mem.Allocator, line: []const u8, id: []const u8) !bool {
    var parsed = try std.json.parseFromSlice(Ack, allocator, line, .{});
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.review_id, id)) return error.ReviewIdMismatch;
    if (std.mem.eql(u8, parsed.value.action, "publish")) return true;
    if (std.mem.eql(u8, parsed.value.action, "cancel")) return false;
    return error.InvalidReviewAction;
}
pub fn review(allocator: std.mem.Allocator, details: []const u8, id: []const u8) !bool {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    // An abandoned output pipe must return EPIPE so the caller's stage
    // cleanup runs; default SIGPIPE would terminate before defers.
    var previous: std.posix.Sigaction = undefined;
    const ignore = std.posix.Sigaction{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(std.posix.SIG.PIPE, &ignore, &previous);
    defer std.posix.sigaction(std.posix.SIG.PIPE, &previous, null);
    const out = try Nonblocking.open(1);
    defer out.close();
    const input = try Nonblocking.open(0);
    defer input.close();
    const deadline = (try nowMillis()) + timeout_ms;
    try writeBounded(1, details, deadline);
    try writeBounded(1, "\n", deadline);
    var buffer: [max_ack]u8 = undefined;
    var len: usize = 0;
    while (len < buffer.len) {
        try wait(0, linux.POLL.IN, deadline);
        const rc = linux.read(0, buffer[len..].ptr, 1);
        switch (std.posix.errno(rc)) {
            .INTR, .AGAIN => continue,
            .SUCCESS => {},
            else => return error.ReviewChannelUnavailable,
        }
        if (rc == 0) return error.ReviewCancelled;
        if (buffer[len] == '\n') return parseAck(allocator, buffer[0..len], id);
        len += 1;
    }
    return error.ReviewAcknowledgementTooLong;
}

/// The artifact has already committed when this is called. Failure cannot
/// undo publication; the caller must report that fact and exit nonzero.
pub fn writeFinal(bytes: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    var previous: std.posix.Sigaction = undefined;
    const ignore = std.posix.Sigaction{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(std.posix.SIG.PIPE, &ignore, &previous);
    defer std.posix.sigaction(std.posix.SIG.PIPE, &previous, null);
    const out = try Nonblocking.open(1);
    defer out.close();
    const deadline = (try nowMillis()) + timeout_ms;
    try writeBounded(1, bytes, deadline);
    try writeBounded(1, "\n", deadline);
}

/// Best effort and bounded: stderr may itself be closed or backpressured.
pub fn reportPublishedOutputFailure() !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    var previous: std.posix.Sigaction = undefined;
    const ignore = std.posix.Sigaction{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(std.posix.SIG.PIPE, &ignore, &previous);
    defer std.posix.sigaction(std.posix.SIG.PIPE, &previous, null);
    const err = try Nonblocking.open(2);
    defer err.close();
    try writeBounded(2, "setup: bundle published; final result output failed\n", (try nowMillis()) + 1000);
}

test "review ack is bound to exact id and strict action" {
    const a = std.testing.allocator;
    try std.testing.expect(try parseAck(a, "{\"action\":\"publish\",\"review_id\":\"abc\"}", "abc"));
    try std.testing.expect(!(try parseAck(a, "{\"action\":\"cancel\",\"review_id\":\"abc\"}", "abc")));
    try std.testing.expectError(error.ReviewIdMismatch, parseAck(a, "{\"action\":\"publish\",\"review_id\":\"old\"}", "abc"));
    try std.testing.expectError(error.InvalidReviewAction, parseAck(a, "{\"action\":\"yes\",\"review_id\":\"abc\"}", "abc"));
    try std.testing.expectError(error.UnknownField, parseAck(a, "{\"action\":\"publish\",\"review_id\":\"abc\",\"extra\":1}", "abc"));
}

fn ackAllocationProbe(a: std.mem.Allocator) !void {
    try std.testing.expect(try parseAck(a, "{\"action\":\"publish\",\"review_id\":\"abc\"}", "abc"));
}
test "review acknowledgement allocation failures propagate" {
    var fallback = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
    try std.testing.checkAllAllocationFailures(fallback.allocator(), ackAllocationProbe, .{});
}
