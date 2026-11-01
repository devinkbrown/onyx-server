// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict URL parsing and endpoint identity normalization.

const std = @import("std");
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const net = std.Io.net;
const Error = @import("contracts.zig").Error;

/// A parsed `http(s)://host[:port]/path` URL. Slices borrow the input.
pub const Url = struct {
    tls: bool,
    host: []const u8,
    port: u16,
    path: []const u8,
};

/// Split an absolute http/https URL into its parts. Defaults the port (80/443)
/// and the path ("/").
pub fn parseUrl(url: []const u8) Error!Url {
    var tls = false;
    var rest = url;
    if (std.mem.startsWith(u8, rest, "https://")) {
        tls = true;
        rest = rest["https://".len..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest["http://".len..];
    } else return error.BadUrl;

    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const authority = if (slash) |i| rest[0..i] else rest;
    const path = if (slash) |i| rest[i..] else "/";
    if (authority.len == 0) return error.BadUrl;

    var host = authority;
    var port: u16 = if (tls) 443 else 80;
    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.BadUrl;
        if (end <= 1) return error.BadUrl;
        const literal = net.IpAddress.parse(authority[1..end], port) catch return error.BadUrl;
        if (literal != .ip6) return error.BadUrl;
        host = authority[0 .. end + 1];
        if (end + 1 < authority.len) {
            if (authority[end + 1] != ':') return error.BadUrl;
            port = std.fmt.parseInt(u16, authority[end + 2 ..], 10) catch return error.BadUrl;
        }
    } else {
        if (std.mem.indexOfAny(u8, authority, "[]@") != null) return error.BadUrl;
        if (std.mem.lastIndexOfScalar(u8, authority, ':')) |c| {
            host = authority[0..c];
            port = std.fmt.parseInt(u16, authority[c + 1 ..], 10) catch return error.BadUrl;
        }
    }
    if (host.len == 0 or port == 0) return error.BadUrl;
    for (authority) |c| {
        if (c <= 0x20 or c == 0x7f) return error.BadUrl;
    }
    return .{ .tls = tls, .host = host, .port = port, .path = path };
}

/// Brackets belong in the HTTP Host field but not DNS lookups or TLS identity.
pub fn endpointHost(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
}
