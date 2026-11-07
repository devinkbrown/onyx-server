// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client half of `tools/openssl_interop.sh`: drives Armor's OUTBOUND TLS
//! stack — the daemon's real `http_fetch.get` (TLS 1.3 `tls_client`, with the
//! hardened `tls12_client` fallback) — against an `openssl s_server -www`.
//!
//! Usage: openssl_interop_client <port> <ca-der-base64> [server-name]
//!
//! Connects to 127.0.0.1:<port>, verifies the server chain against the single
//! trust anchor (no `insecure_skip_verify`), sends `GET / HTTP/1.0`, and writes
//! the response to stdout. `s_server -www` answers with a status page that
//! names the protocol and cipher OpenSSL negotiated, which the script asserts.
//! Exit 0 = response received; 1 = TLS/HTTP failure (error name on stderr);
//! 2 = usage. Test-only: built by the interop script, never by `zig build`.

const std = @import("std");
const onyx_server = @import("onyx_server");

const http_fetch = onyx_server.daemon.http_fetch;

pub fn main(init: std.process.Init) void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const code = run(gpa.allocator(), init);
    _ = gpa.deinit();
    std.process.exit(code);
}

fn run(alloc: std.mem.Allocator, init: std.process.Init) u8 {
    var it = std.process.Args.iterateAllocator(init.minimal.args, alloc) catch return 1;
    defer it.deinit();
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(alloc);
    while (it.next()) |a| argv.append(alloc, a) catch return 1;
    if (argv.items.len < 3 or argv.items.len > 4) {
        writeFd(2, "usage: openssl_interop_client <port> <ca-der-base64> [server-name]\n");
        return 2;
    }
    const port = std.fmt.parseInt(u16, argv.items[1], 10) catch return 2;
    const b64 = argv.items[2];
    const name = if (argv.items.len == 4) argv.items[3] else "localhost";

    const dec = std.base64.standard.Decoder;
    const der_len = dec.calcSizeForSlice(b64) catch return 2;
    const der = alloc.alloc(u8, der_len) catch return 1;
    defer alloc.free(der);
    dec.decode(der, b64) catch return 2;

    // The request names `name` in Host so the SNI and HTTP authority agree;
    // the connection itself goes to the loopback address explicitly.
    var req_buf: [512]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{name}) catch return 2;

    const anchors = [_][]const u8{der};
    // `getAtAddress` pins the dial to loopback while `name` still drives SNI
    // and certificate name verification (RFC 6125) exactly as `get` would.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    const body = http_fetch.getAtAddress(alloc, name, port, true, request, addr, .{
        .trust_anchors = &anchors,
        .connect_timeout_ms = 5000,
        .recv_timeout_ms = 10000,
    }) catch |e| {
        writeFd(2, "openssl_interop_client: ");
        writeFd(2, @errorName(e));
        writeFd(2, "\n");
        return 1;
    };
    defer alloc.free(body);
    writeFd(1, body);
    return 0;
}

fn writeFd(fd: std.os.linux.fd_t, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + off, bytes.len - off);
        const signed: isize = @bitCast(rc);
        if (signed <= 0) return;
        off += @intCast(rc);
    }
}
