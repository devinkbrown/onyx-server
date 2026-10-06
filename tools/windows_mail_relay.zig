// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-shot, loopback-only pure Zig STARTTLS relay for the live Windows mail smoke.
//! Arguments: port, DER certificate output path, optional alternate anchor path.
//! No certificate key is written.
const std = @import("std");
const onyx = @import("onyx_server");
const metrics = onyx.daemon.metrics_http;
const selfsign = onyx.proto.x509_selfsign;
const tls_server = onyx.crypto.tls_server;
const max_record = 16 * 1024 + 512;

const win = struct {
    const FdSet = extern struct { count: u32, sockets: [64]usize };
    const Timeval = extern struct { seconds: i32, microseconds: i32 };
    extern "ws2_32" fn accept(socket: usize, addr: ?*anyopaque, addr_len: ?*i32) callconv(.winapi) usize;
    extern "ws2_32" fn select(nfds: i32, reads: ?*FdSet, writes: ?*FdSet, excepts: ?*FdSet, timeout: *Timeval) callconv(.winapi) i32;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
};

fn readSome(fd: usize, bytes: []u8) !usize {
    const n = win.recv(fd, bytes.ptr, @intCast(bytes.len), 0);
    if (n <= 0) return error.SocketReadFailed;
    return @intCast(n);
}
fn readExact(fd: usize, bytes: []u8) !void {
    var off: usize = 0;
    while (off < bytes.len) off += try readSome(fd, bytes[off..]);
}
fn readRecord(fd: usize, buffer: *[max_record]u8) ![]const u8 {
    try readExact(fd, buffer[0..5]);
    const size = 5 + @as(usize, std.mem.readInt(u16, buffer[3..5], .big));
    if (size > buffer.len) return error.RecordTooLarge;
    try readExact(fd, buffer[5..size]);
    return buffer[0..size];
}
fn readLine(fd: usize, buffer: []u8) ![]const u8 {
    for (buffer, 0..) |_, i| {
        _ = try readSome(fd, buffer[i .. i + 1]);
        if (i != 0 and buffer[i - 1] == '\r' and buffer[i] == '\n') return buffer[0 .. i + 1];
    }
    return error.LineTooLong;
}
fn writeAll(fd: usize, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = win.send(fd, bytes[off..].ptr, @intCast(bytes.len - off), 0);
        if (n <= 0) return error.SocketWriteFailed;
        off += @intCast(n);
    }
}
fn reply(engine: *tls_server.Server, fd: usize, bytes: []const u8) !void {
    const record = try engine.encrypt(bytes);
    defer std.heap.page_allocator.free(record);
    try writeAll(fd, record);
}
fn command(engine: *tls_server.Server, fd: usize, buffer: *[max_record]u8, prefix: []const u8) ![]u8 {
    const bytes = try engine.decrypt(try readRecord(fd, buffer));
    if (!std.mem.startsWith(u8, bytes, prefix)) {
        std.heap.page_allocator.free(bytes);
        return error.UnexpectedSmtpCommand;
    }
    return bytes;
}
fn expectCommand(engine: *tls_server.Server, fd: usize, buffer: *[max_record]u8, prefix: []const u8) !void {
    const bytes = try command(engine, fd, buffer, prefix);
    std.heap.page_allocator.free(bytes);
}
fn exchange(fd: usize, chain: []const []const u8, key_pair: std.crypto.sign.Ed25519.KeyPair) !void {
    var blocking: u32 = 0;
    if (win.ioctlsocket(fd, 0x8004667e, &blocking) != 0) return error.SocketSetupFailed;
    const timeout: u32 = 15_000;
    if (win.setsockopt(fd, 0xffff, 0x1006, &timeout, @sizeOf(u32)) != 0 or
        win.setsockopt(fd, 0xffff, 0x1005, &timeout, @sizeOf(u32)) != 0) return error.SocketSetupFailed;
    try writeAll(fd, "220 onyx test relay\r\n");
    var line: [256]u8 = undefined;
    if (!std.mem.eql(u8, try readLine(fd, &line), "EHLO onyx.test\r\n")) return error.UnexpectedEhlo;
    try writeAll(fd, "250 STARTTLS\r\n");
    if (!std.mem.eql(u8, try readLine(fd, &line), "STARTTLS\r\n")) return error.ExpectedStarttls;
    try writeAll(fd, "220 ready for TLS\r\n");
    var engine = try tls_server.Server.init(std.heap.page_allocator, .{ .cert_chain = chain, .signing_key = key_pair });
    defer engine.deinit();
    var buffer: [max_record]u8 = undefined;
    while (!engine.handshakeDone()) {
        switch (try engine.feed(try readRecord(fd, &buffer))) {
            .bytes_to_send => |bytes| {
                defer std.heap.page_allocator.free(bytes);
                try writeAll(fd, bytes);
            },
            .need_more => {},
        }
    }
    try expectCommand(&engine, fd, &buffer, "EHLO onyx.test\r\n");
    try reply(&engine, fd, "250 TLS ready\r\n");
    try expectCommand(&engine, fd, &buffer, "MAIL FROM:<noreply@example.test>\r\n");
    try reply(&engine, fd, "250 sender ok\r\n");
    try expectCommand(&engine, fd, &buffer, "RCPT TO:<recipient@example.test>\r\n");
    try reply(&engine, fd, "250 recipient ok\r\n");
    try expectCommand(&engine, fd, &buffer, "DATA\r\n");
    try reply(&engine, fd, "354 send message\r\n");
    const message = try command(&engine, fd, &buffer, "From: <noreply@example.test>\r\n");
    defer std.heap.page_allocator.free(message);
    if (std.mem.indexOf(u8, message, "To: <recipient@example.test>\r\n") == null or
        std.mem.indexOf(u8, message, "Subject: Verify your account\r\n") == null or
        std.mem.indexOf(u8, message, "Hello deliveredacct,\r\n\r\nYour verification code for onyx.test is: ") == null or
        std.mem.indexOf(u8, message, "Confirm it on IRC with:  VERIFY ") == null or
        !std.mem.endsWith(u8, message, "\r\n.\r\n")) return error.InvalidMessage;
    try reply(&engine, fd, "250 queued\r\n");
    try expectCommand(&engine, fd, &buffer, "QUIT\r\n");
    try reply(&engine, fd, "221 bye\r\n");
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const port_arg = args.next() orelse return error.InvalidArguments;
    const cert_path = args.next() orelse return error.InvalidArguments;
    const alternate_path = args.next();
    if (args.next() != null) return error.InvalidArguments;
    const port = try std.fmt.parseInt(u16, port_arg, 10);
    const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x6d));
    var cert_buffer: [2048]u8 = undefined;
    const cert = try selfsign.buildSelfSigned(&cert_buffer, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x6d, 1 },
        .key_pair = pair,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    var snapshot = metrics.MetricsSnapshot.init(init.gpa);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, port);
    defer listener.shutdown();
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = cert_path, .data = cert });
    if (alternate_path) |path| {
        const other_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x6e));
        var other_buffer: [2048]u8 = undefined;
        const other = try selfsign.buildSelfSigned(&other_buffer, .{
            .common_name = "127.0.0.1",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{ 0x6e, 1 },
            .key_pair = other_pair,
            .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
            .is_ca = true,
        });
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = other });
    }
    var reads = win.FdSet{ .count = 1, .sockets = undefined };
    reads.sockets[0] = listener.listen_fd;
    var timeout = win.Timeval{ .seconds = 30, .microseconds = 0 };
    if (win.select(0, &reads, null, null, &timeout) != 1) return error.RelayTimeout;
    const fd = win.accept(listener.listen_fd, null, null);
    if (fd == std.math.maxInt(usize)) return error.AcceptFailed;
    defer _ = win.closesocket(fd);
    const chain = [_][]const u8{cert};
    try exchange(fd, &chain, pair);
    std.debug.print("PASS: trusted STARTTLS accepted verification mail\n", .{});
}
