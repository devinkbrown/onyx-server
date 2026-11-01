// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const std = @import("std");
const builtin = @import("builtin");
const smtp_client = @import("../../proto/smtp_client.zig");
const store_mod = @import("../store.zig");
const testing = std.testing;
const Sender = @import("core.zig").Sender;
const win = @import("windows_abi.zig").win;

test "DST GAP-D7 configured relay with a trust store records a durable delivery failure" {
    std.debug.print("GAP-D7 branch=configured relay with a non-empty trust store records a durable delivery failure; empty trust still refuses remote AUTH; live mail stays off\n", .{});
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var relay_port: u16 = 1;
    var reserved: ?usize = null;
    var winsock_started = false;
    defer {
        if (comptime builtin.os.tag == .windows) {
            if (reserved) |fd| {
                _ = win.closesocket(fd);
            }
            if (winsock_started) {
                _ = win.WSACleanup();
            }
        }
    }
    if (comptime builtin.os.tag == .windows) {
        // A held, non-listening socket gives this failure proof its own port.
        // Port 1 can be occupied or filtered, so it cannot establish refusal.
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.TestUnexpectedResult;
        winsock_started = true;
        reserved = win.WSASocketW(win.af_inet, win.sock_stream, win.ipproto_tcp, null, 0, 1);
        if (reserved.? == win.invalid_socket) return error.TestUnexpectedResult;
        const exclusive: i32 = 1;
        if (win.setsockopt(reserved.?, win.sol_socket, win.so_exclusiveaddruse, &exclusive, @sizeOf(i32)) != 0)
            return error.TestUnexpectedResult;
        var address = win.SockAddr4{ .family = win.af_inet, .port = 0, .addr = .{ 127, 0, 0, 1 } };
        if (win.bind(reserved.?, &address, @sizeOf(win.SockAddr4)) != 0) return error.TestUnexpectedResult;
        var address_len: i32 = @sizeOf(win.SockAddr4);
        if (win.getsockname(reserved.?, &address, &address_len) != 0 or address_len != @sizeOf(win.SockAddr4))
            return error.TestUnexpectedResult;
        relay_port = std.mem.bigToNative(u16, address.port);
        try std.testing.expect(relay_port != 0);
    }
    const anchors = [_][]const u8{"anchor"};
    var sender = try Sender.init(allocator, .{
        .relay_host = "127.0.0.1",
        .relay_port = relay_port,
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .trust_anchors = &anchors,
        .failure_wal = "mailfail.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
    });
    defer sender.deinit();
    try std.testing.expect(sender.config.trust_anchors.len != 0);
    try sender.settle("d7@example.test", "verify", "code");

    var opened = try store_mod.OroStore.open(allocator, io, tmp.dir, "mailfail.wal");
    defer opened.deinit();
    const row = opened.get(.props, "mailfail:1") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, row, "d7@example.test") != null);
    try std.testing.expect(std.mem.indexOf(u8, row, "ConnectFailed") != null or std.mem.indexOf(u8, row, "SocketUnavailable") != null);

    var refused = try Sender.init(allocator, .{
        .relay_host = "203.0.113.5",
        .relay_port = 587,
        .ehlo_domain = "onyx.test",
        .from = "onyx@example.test",
        .user = "submit",
        .pass = "secret",
        .failure_wal = "mailfail-auth.wal",
        .failure_io = io,
        .failure_dir = tmp.dir,
    });
    defer refused.deinit();
    try std.testing.expect(refused.config.trust_anchors.len == 0);
    try refused.settle("d7@example.test", "verify", "code");
    var auth_store = try store_mod.OroStore.open(allocator, io, tmp.dir, "mailfail-auth.wal");
    defer auth_store.deinit();
    const auth_row = auth_store.get(.props, "mailfail:1") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, auth_row, "UnverifiedAuthRelay") != null);
}
