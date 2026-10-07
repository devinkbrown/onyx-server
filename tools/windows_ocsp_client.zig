// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native TLS 1.2 client for windows_ocsp_live_smoke.py. Completes a verified
//! handshake with a must-staple leaf and compares the received OCSP DER exactly.
const std = @import("std");
const Client = @import("onyx_server").crypto.tls12_client.Client;

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

fn writeAll(fd: usize, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = win.send(fd, bytes[off..].ptr, @intCast(@min(bytes.len - off, std.math.maxInt(i32))), 0);
        if (n <= 0) return error.SocketWriteFailed;
        off += @intCast(n);
    }
}

fn run(init: std.process.Init) !void {
    const allocator = init.gpa;
    var args = try std.process.Args.iterateAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();
    const port = try std.fmt.parseInt(u16, args.next() orelse return error.InvalidArguments, 10);
    const anchor = try decodeHex(allocator, args.next() orelse return error.InvalidArguments);
    defer allocator.free(anchor);
    const expected = try decodeHex(allocator, args.next() orelse return error.InvalidArguments);
    defer allocator.free(expected);
    const now = try std.fmt.parseInt(i64, args.next() orelse return error.InvalidArguments, 10);
    if (args.next() != null or anchor.len == 0 or expected.len == 0) return error.InvalidArguments;

    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.WinsockStartupFailed;
    defer _ = win.WSACleanup();
    const fd = win.WSASocketW(2, 1, 6, null, 0, 1);
    if (fd == win.invalid_socket) return error.SocketOpenFailed;
    defer _ = win.closesocket(fd);
    const timeout_ms: u32 = 5000;
    if (win.setsockopt(fd, 0xffff, 0x1006, &timeout_ms, @sizeOf(u32)) != 0 or
        win.setsockopt(fd, 0xffff, 0x1005, &timeout_ms, @sizeOf(u32)) != 0)
        return error.SocketTimeoutFailed;
    const address = win.SockAddr4{
        .family = 2,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    if (win.connect(fd, &address, @sizeOf(win.SockAddr4)) != 0) return error.ConnectFailed;

    const anchors = [_][]const u8{anchor};
    var client = try Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = now,
    });
    defer client.deinit();
    const first = try client.start();
    defer allocator.free(first);
    try writeAll(fd, first);
    var buf: [18432]u8 = undefined;
    while (!client.handshakeDone()) {
        const n = win.recv(fd, &buf, @intCast(buf.len), 0);
        if (n <= 0) return error.HandshakeEof;
        switch (try client.feed(buf[0..@intCast(n)])) {
            .need_more => {},
            .bytes_to_send => |flight| {
                defer allocator.free(flight);
                try writeAll(fd, flight);
            },
        }
    }
    const staple = client.ocsp_staple orelse return error.MissingOcspStaple;
    if (!std.mem.eql(u8, staple, expected)) return error.OcspStapleMismatch;
    std.debug.print("OCSP_STAPLE_MATCH={d}\n", .{staple.len});
}

pub fn main(init: std.process.Init) !void {
    try run(init);
}
