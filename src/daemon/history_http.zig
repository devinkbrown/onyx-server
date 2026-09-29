// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Loopback read of history the account can already see via CHATHISTORY.
//! A non-loopback bind is refused. This is not an admin API: the only route
//! is GET /history, and the body is whatever that account's CHATHISTORY
//! visibility check allows.

const std = @import("std");

pub const loopback_v4 = "127.0.0.1";
pub const loopback_v6 = "::1";

pub fn bindAllowed(addr: []const u8) bool {
    return std.mem.eql(u8, addr, loopback_v4) or std.mem.eql(u8, addr, loopback_v6);
}

/// Empty config means loopback. Any other address must itself be loopback.
pub fn listenAddr(configured: []const u8) error{PublicBind}![]const u8 {
    if (configured.len == 0) return loopback_v4;
    if (!bindAllowed(configured)) return error.PublicBind;
    return configured;
}

pub const Reader = struct {
    ptr: *anyopaque,
    readFn: *const fn (ptr: *anyopaque, account: []const u8, target: []const u8, out: []u8) error{Denied}!usize,
};

pub fn handleRequest(request: []const u8, reader: Reader, body_buf: []u8, out: []u8) []const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return writeResponse(400, "bad request\n", out);
    const line = request[0..line_end];
    if (!std.ascii.startsWithIgnoreCase(line, "GET ")) return writeResponse(405, "method\n", out);
    const rest = line["GET ".len..];
    const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return writeResponse(400, "bad request\n", out);
    const target_uri = rest[0..sp];
    if (!std.mem.startsWith(u8, target_uri, "/history")) return writeResponse(404, "not found\n", out);
    const qmark = std.mem.indexOfScalar(u8, target_uri, '?') orelse return writeResponse(400, "target required\n", out);
    const query = target_uri[qmark + 1 ..];
    const raw_target = queryParam(query, "target") orelse return writeResponse(400, "target required\n", out);
    var target_buf: [256]u8 = undefined;
    const target = decodeQuery(raw_target, &target_buf) orelse return writeResponse(400, "bad target\n", out);
    if (target.len == 0) return writeResponse(400, "target required\n", out);
    const auth = headerValue(request, "Authorization") orelse return writeResponse(401, "account required\n", out);
    const prefix = "Bearer ";
    if (auth.len <= prefix.len or !std.ascii.startsWithIgnoreCase(auth, prefix)) return writeResponse(401, "account required\n", out);
    const account = std.mem.trim(u8, auth[prefix.len..], " ");
    if (account.len == 0 or account.len > 64) return writeResponse(401, "account required\n", out);
    const n = reader.readFn(reader.ptr, account, target, body_buf) catch return writeResponse(403, "denied\n", out);
    return writeResponse(200, body_buf[0..n], out);
}

fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |part| {
        if (std.mem.startsWith(u8, part, name) and part.len > name.len and part[name.len] == '=') {
            return part[name.len + 1 ..];
        }
    }
    return null;
}

fn headerValue(request: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, request, '\n');
    _ = it.next();
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (line.len == 0) break;
        if (line.len <= name.len or line[name.len] != ':') continue;
        if (!std.ascii.eqlIgnoreCase(line[0..name.len], name)) continue;
        return std.mem.trim(u8, line[name.len + 1 ..], " \t");
    }
    return null;
}

fn decodeQuery(src: []const u8, dest: []u8) ?[]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (n >= dest.len) return null;
        if (src[i] == '%' and i + 2 < src.len) {
            const byte = std.fmt.parseInt(u8, src[i + 1 .. i + 3], 16) catch return null;
            dest[n] = byte;
            n += 1;
            i += 3;
            continue;
        }
        dest[n] = if (src[i] == '+') ' ' else src[i];
        n += 1;
        i += 1;
    }
    return dest[0..n];
}

fn writeResponse(status: u16, body: []const u8, out: []u8) []const u8 {
    const reason = switch (status) {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        else => "Error",
    };
    return std.fmt.bufPrint(out, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, reason, body.len, body }) catch "HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
}

test "GAP-P12 loopback is the only history bind and other paths are not an admin API" {
    try std.testing.expect(bindAllowed("127.0.0.1"));
    try std.testing.expect(bindAllowed("::1"));
    try std.testing.expectError(error.PublicBind, listenAddr("0.0.0.0"));
    const addr = try listenAddr("");
    try std.testing.expectEqualStrings("127.0.0.1", addr);

    const reader = Reader{ .ptr = undefined, .readFn = refuseAll };
    var body: [64]u8 = undefined;
    var out: [512]u8 = undefined;
    const missing = handleRequest("GET /admin HTTP/1.1\r\n\r\n", reader, &body, &out);
    try std.testing.expect(std.mem.indexOf(u8, missing, " 404 ") != null);
    const posted = handleRequest("POST /history?target=%23room HTTP/1.1\r\nAuthorization: Bearer member\r\n\r\n", reader, &body, &out);
    try std.testing.expect(std.mem.indexOf(u8, posted, " 405 ") != null);
}

fn refuseAll(_: *anyopaque, _: []const u8, _: []const u8, _: []u8) error{Denied}!usize {
    return error.Denied;
}
