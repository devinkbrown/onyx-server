// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const smtp_client = @import("../../proto/smtp_client.zig");
const testing = std.testing;
const isLoopback = @import("resolution.zig").isLoopback;
const resolveRelayAddressWith = @import("resolution.zig").resolveRelayAddressWith;

test "isLoopback detects 127.0.0.0/8 and ::1, rejects public addresses" {
    try testing.expect(isLoopback(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 587 } }));
    try testing.expect(isLoopback(.{ .ip4 = .{ .bytes = .{ 127, 5, 9, 200 }, .port = 587 } }));
    try testing.expect(!isLoopback(.{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 587 } }));

    const v6_loop = @as([15]u8, @splat(0)) ++ [_]u8{1};
    try testing.expect(isLoopback(.{ .ip6 = .{ .bytes = v6_loop, .port = 587 } }));
    const v6_pub = [_]u8{ 0x20, 0x01 } ++ @as([13]u8, @splat(0)) ++ [_]u8{1};
    try testing.expect(!isLoopback(.{ .ip6 = .{ .bytes = v6_pub, .port = 587 } }));
}

test "SMTP relay resolver keeps A preference and timeout, with Windows AAAA fallback" {
    const Fake = struct {
        fn found4(_: []const u8, port: u16, _: u31) !net.IpAddress {
            return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
        }
        fn missing4(_: []const u8, _: u16, _: u31) !net.IpAddress {
            return error.HostNotFound;
        }
        fn timedOut4(_: []const u8, _: u16, _: u31) !net.IpAddress {
            return error.ResolveTimeout;
        }
        fn found6(_: []const u8, port: u16, _: u31) !net.IpAddress {
            return .{ .ip6 = .{ .bytes = @as([15]u8, @splat(0)) ++ [_]u8{1}, .port = port } };
        }
        fn unexpected6(_: []const u8, _: u16, _: u31) !net.IpAddress {
            return error.UnexpectedAaaaLookup;
        }
    };
    const a = try resolveRelayAddressWith(Fake.found4, Fake.unexpected6, "relay.test", 587, 1000);
    try std.testing.expect(a == .ip4);
    try std.testing.expectEqual(@as(u16, 587), a.ip4.port);
    try std.testing.expectError(error.ResolveTimeout, resolveRelayAddressWith(Fake.timedOut4, Fake.unexpected6, "relay.test", 587, 0));
    if (comptime builtin.os.tag == .windows) {
        const aaaa = try resolveRelayAddressWith(Fake.missing4, Fake.found6, "relay.test", 587, 1000);
        try std.testing.expect(aaaa == .ip6);
        try std.testing.expectEqual(@as(u8, 1), aaaa.ip6.bytes[15]);
    } else {
        try std.testing.expectError(error.HostNotFound, resolveRelayAddressWith(Fake.missing4, Fake.unexpected6, "relay.test", 587, 1000));
    }
}
