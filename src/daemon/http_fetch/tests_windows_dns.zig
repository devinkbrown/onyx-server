// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the outbound HTTP implementation.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const resolveHostA = @import("resolution.zig").resolveHostA;
const resolveHostAAAA = @import("resolution.zig").resolveHostAAAA;
const firstWinSystemAddress = @import("windows_resolver.zig").firstWinSystemAddress;
const win = @import("windows_abi.zig").win;

// ---- tests ------------------------------------------------------------------

test "http_fetch Windows system resolver handles localhost and bounded failures" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const literal4 = try resolveHostA("127.0.0.9", 6900, 0);
    const literal6 = try resolveHostAAAA("::1", 6900, 0);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 9 }, &literal4.ip4.bytes);
    try std.testing.expectEqual(@as(u8, 1), literal6.ip6.bytes[15]);
    const a = try resolveHostA("localhost", 6900, 1000);
    const aaaa = try resolveHostAAAA("localhost", 6900, 1000);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &a.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 6900), a.ip4.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &aaaa.ip6.bytes);
    try std.testing.expectEqual(@as(u16, 6900), aaaa.ip6.port);
    try std.testing.expectError(error.ResolveTimeout, resolveHostA("localhost", 6900, 0));
    try std.testing.expectError(error.HostNotFound, resolveHostA("invalid\xff", 6900, 100));

    // A reserved nonexistent name exercises either immediate negative result
    // or asynchronous cancellation, independent of hosts-file contents.
    const clock = @import("../../substrate/platform.zig");
    const started = clock.monotonicMillis();
    const missing = resolveHostA("onyx-system-resolver-test.invalid.", 6900, 10);
    if (missing) |_| return error.TestUnexpectedResult else |err| {
        try std.testing.expect(err == error.HostNotFound or err == error.ResolveTimeout);
    }
    try std.testing.expect(clock.monotonicMillis() - started < 5000);
}

test "http_fetch Windows system result parser rejects short addresses and cycles" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var sockaddr = win.SockAddr4{ .family = win.af_inet, .port = 0, .addr = .{ 127, 0, 0, 42 } };
    var valid = win.AddrInfoExW{ .family = win.af_inet, .addr_len = @sizeOf(win.SockAddr4), .addr = @ptrCast(&sockaddr) };
    var short = win.AddrInfoExW{ .family = win.af_inet, .addr_len = 4, .addr = @ptrCast(&sockaddr), .next = &valid };
    const found = firstWinSystemAddress(&short, win.af_inet, 6900) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 42 }, &found.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 6900), found.ip4.port);
    short.next = &short;
    try std.testing.expect(firstWinSystemAddress(&short, win.af_inet, 6900) == null);
}

test "http_fetch Windows system result parser preserves IPv6 scope id" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const address = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 };
    var sockaddr = win.SockAddr6{
        .family = win.af_inet6,
        .port = std.mem.nativeToBig(u16, 7),
        .addr = address,
        .scope_id = 0x01020304,
    };
    var valid = win.AddrInfoExW{
        .family = win.af_inet6,
        .addr_len = @sizeOf(win.SockAddr6),
        .addr = @ptrCast(&sockaddr),
    };
    var other_family = win.AddrInfoExW{
        .family = win.af_inet,
        .addr_len = @sizeOf(win.SockAddr6),
        .addr = @ptrCast(&sockaddr),
        .next = &valid,
    };
    const found = firstWinSystemAddress(&other_family, win.af_inet6, 6900) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &address, &found.ip6.bytes);
    try std.testing.expectEqual(@as(u16, 6900), found.ip6.port);
    try std.testing.expectEqual(@as(u32, 0x01020304), found.ip6.interface.index);
}
