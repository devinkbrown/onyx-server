// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native Windows TLS 1.3/0-RTT client for windows_helix_early_data_smoke.py.
//! Arguments: port, stored-session hex or -, ticket age ms, early IRC hex or -,
//! 1-RTT IRC hex or -.
//! The socket is loopback only. stdout/stderr are merged by the Python harness.
const std = @import("std");
const Client = @import("onyx_server").crypto.tls_client.Client;

const win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: u32,
        zero: [8]u8 = @splat(0),
    };
    extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, kind: i32, protocol: i32, info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn connect(socket: usize, addr: *const SockAddr4, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, length: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, length: i32, flags: i32) callconv(.winapi) i32;
};

fn decodeHex(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    if (std.mem.eql(u8, encoded, "-")) return allocator.alloc(u8, 0);
    if (encoded.len % 2 != 0) return error.InvalidHex;
    const result = try allocator.alloc(u8, encoded.len / 2);
    errdefer allocator.free(result);
    for (result, 0..) |*byte, i| {
        const hi = try std.fmt.charToDigit(encoded[i * 2], 16);
        const lo = try std.fmt.charToDigit(encoded[i * 2 + 1], 16);
        byte.* = (hi << 4) | lo;
    }
    return result;
}

fn socketWrite(fd: usize, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = win.send(fd, bytes[off..].ptr, @intCast(@min(bytes.len - off, std.math.maxInt(i32))), 0);
        if (n <= 0) return error.SocketWriteFailed;
        off += @intCast(n);
    }
}

fn socketRead(fd: usize, bytes: []u8) !usize {
    const n = win.recv(fd, bytes.ptr, @intCast(bytes.len), 0);
    if (n < 0) return error.SocketReadFailed;
    return @intCast(n);
}

fn recordLen(bytes: []const u8) ?usize {
    if (bytes.len < 5) return null;
    const len = 5 + @as(usize, std.mem.readInt(u16, bytes[3..5], .big));
    if (len > 18432) return null;
    return if (bytes.len >= len) len else null;
}

fn consumePrefix(bytes: *std.ArrayList(u8), len: usize) void {
    const left = bytes.items.len - len;
    std.mem.copyForwards(u8, bytes.items[0..left], bytes.items[len..]);
    bytes.items.len = left;
}

fn reportTicket(allocator: std.mem.Allocator, client: *Client) !void {
    if (client.takeSessionTicket()) |ticket| {
        defer allocator.free(ticket);
        const hex = try allocator.alloc(u8, ticket.len * 2);
        defer allocator.free(hex);
        const digits = "0123456789abcdef";
        for (ticket, 0..) |byte, i| {
            hex[i * 2] = digits[byte >> 4];
            hex[i * 2 + 1] = digits[byte & 0x0f];
        }
        std.debug.print("TICKET={s}\n", .{hex});
    }
}

fn run(init: std.process.Init) !void {
    const allocator = init.gpa;
    var args = try std.process.Args.iterateAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();
    const port = try std.fmt.parseInt(u16, args.next() orelse return error.InvalidArguments, 10);
    const ticket = try decodeHex(allocator, args.next() orelse return error.InvalidArguments);
    defer allocator.free(ticket);
    const ticket_age_ms = try std.fmt.parseInt(u64, args.next() orelse return error.InvalidArguments, 10);
    const early = try decodeHex(allocator, args.next() orelse return error.InvalidArguments);
    defer allocator.free(early);
    const fallback = try decodeHex(allocator, args.next() orelse return error.InvalidArguments);
    defer allocator.free(fallback);
    if (args.next() != null) return error.InvalidArguments;

    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.WinsockStartupFailed;
    defer _ = win.WSACleanup();
    const fd = win.WSASocketW(2, 1, 6, null, 0, 1);
    if (fd == win.invalid_socket) return error.SocketOpenFailed;
    defer _ = win.closesocket(fd);
    const timeout_ms: u32 = 60_000;
    if (win.setsockopt(fd, 0xffff, 0x1006, &timeout_ms, @sizeOf(u32)) != 0 or
        win.setsockopt(fd, 0xffff, 0x1005, &timeout_ms, @sizeOf(u32)) != 0)
        return error.SocketTimeoutFailed;
    const address = win.SockAddr4{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    if (win.connect(fd, &address, @sizeOf(win.SockAddr4)) != 0) return error.ConnectFailed;

    var client = try Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &.{} });
    defer client.deinit();
    // The disposable fixture uses an OS-generated self-signed leaf. The engine
    // still verifies CertificateVerify and the resumed PSK binder.
    client.skipServerCertVerifyForTest();
    if (ticket.len > 0) try client.setSessionTicket(ticket, ticket_age_ms);
    if (early.len > 0) try client.setEarlyData(early);
    const first_flight = try client.start();
    defer allocator.free(first_flight);
    try socketWrite(fd, first_flight);

    var buf: [18432]u8 = undefined;
    while (!client.handshakeDone()) {
        const n = try socketRead(fd, &buf);
        if (n == 0) return error.HandshakeEof;
        switch (try client.feed(buf[0..n])) {
            .need_more => {},
            .bytes_to_send => |reply| {
                defer allocator.free(reply);
                try socketWrite(fd, reply);
            },
        }
    }
    std.debug.print("RESUMED={s}\n", .{if (client.psk_accepted) "yes" else "no"});
    std.debug.print("EARLY={s}\n", .{if (client.earlyDataAccepted()) |accepted|
        (if (accepted) @as([]const u8, "accepted") else "rejected")
    else
        "none"});
    if (fallback.len > 0 and (early.len == 0 or client.earlyDataAccepted() == false)) {
        const encrypted = try client.encrypt(fallback);
        defer allocator.free(encrypted);
        try socketWrite(fd, encrypted);
    }

    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(allocator);
    try received.appendSlice(allocator, client.pendingBytes());
    while (true) {
        while (recordLen(received.items)) |length| {
            switch (try client.decryptApp(received.items[0..length])) {
                .control => {
                    try reportTicket(allocator, &client);
                    if (try client.takePendingSend()) |reply| {
                        defer allocator.free(reply);
                        try socketWrite(fd, reply);
                    }
                },
                .application_data => |plain| {
                    defer allocator.free(plain);
                    std.debug.print("{s}", .{plain});
                },
            }
            consumePrefix(&received, length);
        }
        const n = try socketRead(fd, &buf);
        if (n == 0) return;
        try received.appendSlice(allocator, buf[0..n]);
        if (received.items.len > 1 << 20) return error.ExcessiveTlsInput;
    }
}

pub fn main(init: std.process.Init) !void {
    try run(init);
}
