// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deadline-bound native Helix framing. All batches share one deadline and one
//! upgrade identity; received descriptor custody is never implicit.
const std = @import("std");
const posix = std.posix;
const sys = posix.system;
const control = @import("native_control.zig");
const platform = @import("../../substrate/platform.zig");
const envelope = @import("native_arena_envelope.zig");
pub const Error = control.Error || error{Timeout};
pub const header_len = 40;
pub const Kind = enum(u16) { hello = 1, capabilities, arena, descriptors, ready, commit, abort };
pub const Identity = struct { generation: u64, upgrade_id: envelope.UpgradeId };
pub const Header = struct { kind: Kind, identity: Identity, index: u32, total: u32 };

pub fn deadlineAfter(ms: u31) i64 {
    return platform.monotonicMillis() + ms;
}
fn wait(fd: i32, writing: bool, deadline: i64) Error!void {
    var polls = [_]posix.pollfd{.{ .fd = fd, .events = if (writing) posix.POLL.OUT else posix.POLL.IN, .revents = 0 }};
    while (true) {
        const left = deadline - platform.monotonicMillis();
        if (left <= 0) return error.Timeout;
        const rc = sys.poll(&polls, 1, @intCast(@min(left, std.math.maxInt(c_int))));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.Timeout;
                if ((polls[0].revents & polls[0].events) != 0) return;
                return error.ReceiveFailed;
            },
            .INTR => continue,
            else => return error.ReceiveFailed,
        }
    }
}
fn encode(header: Header, bytes: *[header_len]u8) void {
    @memcpy(bytes[0..4], "HXOB");
    std.mem.writeInt(u16, bytes[4..6], 1, .big);
    std.mem.writeInt(u16, bytes[6..8], @intFromEnum(header.kind), .big);
    std.mem.writeInt(u64, bytes[8..16], header.identity.generation, .big);
    @memcpy(bytes[16..32], &header.identity.upgrade_id);
    std.mem.writeInt(u32, bytes[32..36], header.index, .big);
    std.mem.writeInt(u32, bytes[36..40], header.total, .big);
}
pub fn parse(bytes: []const u8) Error!Header {
    if (bytes.len < header_len or !std.mem.eql(u8, bytes[0..4], "HXOB") or std.mem.readInt(u16, bytes[4..6], .big) != 1) return error.Protocol;
    return .{ .kind = std.enums.fromInt(Kind, std.mem.readInt(u16, bytes[6..8], .big)) orelse return error.Protocol, .identity = .{ .generation = std.mem.readInt(u64, bytes[8..16], .big), .upgrade_id = bytes[16..32].* }, .index = std.mem.readInt(u32, bytes[32..36], .big), .total = std.mem.readInt(u32, bytes[36..40], .big) };
}
pub fn send(fd: i32, header: Header, body: []const u8, fds: []const i32, deadline: i64) Error!void {
    if (body.len > control.max_payload - header_len) return error.TooLarge;
    var wire: [control.max_payload]u8 = undefined;
    defer std.crypto.secureZero(u8, &wire);
    encode(header, wire[0..header_len]);
    @memcpy(wire[header_len..][0..body.len], body);
    while (true) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        control.send(fd, wire[0 .. header_len + body.len], fds) catch |err| switch (err) {
            error.WouldBlock => {
                try wait(fd, true, deadline);
                continue;
            },
            else => return err,
        };
        return;
    }
}
pub fn receive(fd: i32, expected: Header, deadline: i64) Error!control.Message {
    while (true) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        var message = control.receive(fd) catch |err| switch (err) {
            error.WouldBlock => {
                try wait(fd, false, deadline);
                continue;
            },
            else => return err,
        };
        errdefer message.deinit();
        const actual = try parse(message.bytes());
        if (actual.kind != expected.kind or actual.identity.generation != expected.identity.generation or
            !std.mem.eql(u8, &actual.identity.upgrade_id, &expected.identity.upgrade_id) or actual.index != expected.index or actual.total != expected.total) return error.Protocol;
        return message;
    }
}

pub fn receiveAny(fd: i32, deadline: i64) Error!control.Message {
    while (true) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        return control.receive(fd) catch |err| switch (err) {
            error.WouldBlock => {
                try wait(fd, false, deadline);
                continue;
            },
            else => return err,
        };
    }
}

test "OpenBSD Helix exchanges enforce one deadline and exact generation batch identity" {
    if (comptime @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const header: Header = .{ .kind = .ready, .identity = .{ .generation = 7, .upgrade_id = @splat(9) }, .index = 0, .total = 1 };
    try std.testing.expectError(error.Timeout, receive(pair.parent, header, deadlineAfter(20)));
    try send(pair.child, header, "staged", &.{}, deadlineAfter(1000));
    var ready = try receive(pair.parent, header, deadlineAfter(1000));
    defer ready.deinit();
    try std.testing.expectEqualStrings("staged", ready.bytes()[header_len..]);
    var wrong = header;
    wrong.index = 1;
    try send(pair.child, wrong, "duplicate", &.{}, deadlineAfter(1000));
    try std.testing.expectError(error.Protocol, receive(pair.parent, header, deadlineAfter(1000)));
    try std.testing.expectError(error.Timeout, send(pair.child, header, "expired", &.{}, deadlineAfter(0)));
}
