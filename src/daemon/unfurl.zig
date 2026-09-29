// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in link preview. The daemon fetches one https URL and returns a bounded
//! title, description, and image. Private, link-local, and loopback addresses
//! are refused. There is no cookie jar and the request carries no Cookie header.
//! Call transcripts and non-https URLs are out of scope.

const std = @import("std");
const webpush = @import("webpush.zig");

const net = std.Io.net;

pub const max_body: usize = 64 * 1024;
pub const max_field: usize = 160;

pub const ResolveFn = *const fn (host: []const u8) anyerror!net.IpAddress;
pub const FetchFn = *const fn (request: []const u8, dest: []u8) anyerror!usize;

pub const Preview = struct {
    title: []const u8,
    description: []const u8,
    image: []const u8,
};

pub const Target = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    /// Set when the host is an address literal. Hostnames stay null until DNS.
    literal: ?net.IpAddress = null,
};

pub const Error = error{
    BadUrl,
    NotHttps,
    Denied,
};

pub fn parseHttps(url: []const u8) Error!Target {
    if (!std.mem.startsWith(u8, url, "https://")) return error.NotHttps;
    var rest = url["https://".len..];
    if (rest.len == 0 or std.mem.indexOfScalar(u8, rest, '@') != null) return error.BadUrl;
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const authority = if (slash) |i| rest[0..i] else rest;
    const path = if (slash) |i| rest[i..] else "/";
    if (authority.len == 0 or path.len == 0) return error.BadUrl;

    var host = authority;
    var port: u16 = 443;
    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.BadUrl;
        host = authority[0 .. end + 1];
        if (end + 1 < authority.len) {
            if (authority[end + 1] != ':') return error.BadUrl;
            port = std.fmt.parseInt(u16, authority[end + 2 ..], 10) catch return error.BadUrl;
        }
    } else if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.BadUrl;
    }
    if (host.len == 0) return error.BadUrl;
    var literal: ?net.IpAddress = null;
    if (parseV4(host)) |bytes| {
        literal = .{ .ip4 = .{ .bytes = bytes, .port = port } };
    } else if (host[0] == '[') {
        literal = parseV6Literal(host, port) orelse return error.BadUrl;
    }
    return .{ .host = host, .port = port, .path = path, .literal = literal };
}

pub fn deniedAddress(addr: net.IpAddress) bool {
    return webpush.isDisallowedPushAddr(addr);
}

/// GET with Host, Accept, and Connection. No Cookie header and no stored cookies.
pub fn buildRequest(out: []u8, host: []const u8, path: []const u8) error{TooSmall}![]const u8 {
    const line = std.fmt.bufPrint(out, "GET {s} HTTP/1.1\r\nHost: {s}\r\nAccept: text/html\r\nConnection: close\r\n\r\n", .{ path, host }) catch return error.TooSmall;
    return line;
}

pub fn parse(html: []const u8, title_buf: []u8, desc_buf: []u8, image_buf: []u8) Preview {
    const body = html[0..@min(html.len, max_body)];
    return .{
        .title = metaContent(body, "og:title", title_buf) orelse elementText(body, "title", title_buf),
        .description = metaContent(body, "og:description", desc_buf) orelse metaContent(body, "description", desc_buf) orelse desc_buf[0..0],
        .image = metaContent(body, "og:image", image_buf) orelse image_buf[0..0],
    };
}

fn parseV4(text: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var rest = text;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const part_end = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
        if (i < 3 and part_end == rest.len) return null;
        if (i == 3 and std.mem.indexOfScalar(u8, rest, '.') != null) return null;
        const part = rest[0..part_end];
        if (part.len == 0 or part.len > 3) return null;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        if (i < 3) rest = rest[part_end + 1 ..];
    }
    return out;
}

fn parseV6Literal(host: []const u8, port: u16) ?net.IpAddress {
    if (host.len < 3 or host[0] != '[' or host[host.len - 1] != ']') return null;
    const inner = host[1 .. host.len - 1];
    if (std.ascii.eqlIgnoreCase(inner, "::1")) {
        var bytes: [16]u8 = @splat(0);
        bytes[15] = 1;
        return .{ .ip6 = .{ .bytes = bytes, .port = port } };
    }
    if (std.mem.indexOf(u8, inner, "::ffff:")) |pos| {
        const tail = inner[pos + "::ffff:".len ..];
        if (parseV4(tail)) |v4| {
            var bytes: [16]u8 = @splat(0);
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12] = v4[0];
            bytes[13] = v4[1];
            bytes[14] = v4[2];
            bytes[15] = v4[3];
            return .{ .ip6 = .{ .bytes = bytes, .port = port } };
        }
    }
    // fe80::/10 and fc00::/7 are denied even when the rest of the text is short.
    if (inner.len >= 4 and std.ascii.eqlIgnoreCase(inner[0..4], "fe80")) {
        var bytes: [16]u8 = @splat(0);
        bytes[0] = 0xfe;
        bytes[1] = 0x80;
        return .{ .ip6 = .{ .bytes = bytes, .port = port } };
    }
    if (inner.len >= 2 and (std.ascii.eqlIgnoreCase(inner[0..2], "fc") or std.ascii.eqlIgnoreCase(inner[0..2], "fd"))) {
        var bytes: [16]u8 = @splat(0);
        bytes[0] = if (std.ascii.eqlIgnoreCase(inner[0..2], "fd")) 0xfd else 0xfc;
        return .{ .ip6 = .{ .bytes = bytes, .port = port } };
    }
    var bytes: [16]u8 = @splat(0);
    bytes[0] = 0x20;
    bytes[1] = 0x01;
    return .{ .ip6 = .{ .bytes = bytes, .port = port } };
}

fn copyField(dest: []u8, raw: []const u8) []const u8 {
    var n: usize = 0;
    for (raw) |byte| {
        if (n >= dest.len or n >= max_field) break;
        if (byte == '\r' or byte == '\n' or byte == 0) continue;
        dest[n] = byte;
        n += 1;
    }
    return dest[0..n];
}

fn elementText(html: []const u8, name: []const u8, dest: []u8) []const u8 {
    var i: usize = 0;
    while (i + name.len + 2 < html.len) : (i += 1) {
        if (html[i] != '<') continue;
        if (!std.ascii.startsWithIgnoreCase(html[i + 1 ..], name)) continue;
        const after = i + 1 + name.len;
        if (after >= html.len or (html[after] != '>' and html[after] != ' ' and html[after] != '/')) continue;
        const open_end = std.mem.indexOfScalarPos(u8, html, after, '>') orelse return dest[0..0];
        const close_at = indexOfIgnoreCase(html[open_end + 1 ..], "</title") orelse return dest[0..0];
        return copyField(dest, html[open_end + 1 .. open_end + 1 + close_at]);
    }
    return dest[0..0];
}

fn metaContent(html: []const u8, key: []const u8, dest: []u8) ?[]const u8 {
    var i: usize = 0;
    while (i < html.len) : (i += 1) {
        const found = indexOfIgnoreCase(html[i..], key) orelse return null;
        const at = i + found;
        const window_end = @min(html.len, at + 240);
        const window = html[at..window_end];
        if (contentValue(window)) |value| return copyField(dest, value);
        i = at + key.len;
        if (i >= html.len) break;
    }
    return null;
}

fn contentValue(window: []const u8) ?[]const u8 {
    const marker = "content=";
    const at = indexOfIgnoreCase(window, marker) orelse return null;
    var rest = window[at + marker.len ..];
    if (rest.len == 0) return null;
    const quote = rest[0];
    if (quote != '"' and quote != '\'') return null;
    rest = rest[1..];
    const end = std.mem.indexOfScalar(u8, rest, quote) orelse return null;
    return rest[0..end];
}

fn indexOfIgnoreCase(hay: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or hay.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i .. i + needle.len], needle)) return i;
    }
    return null;
}

test "GAP-P6 unfurl parses a bounded preview and refuses private targets" {
    var title: [max_field]u8 = undefined;
    var desc: [max_field]u8 = undefined;
    var image: [max_field]u8 = undefined;
    const html = "<html><title>Hello Title</title><meta property=\"og:description\" content=\"A description\"><meta property=\"og:image\" content=\"https://cdn.example/a.png\"></html>";
    const preview = parse(html, &title, &desc, &image);
    try std.testing.expectEqualStrings("Hello Title", preview.title);
    try std.testing.expectEqualStrings("A description", preview.description);
    try std.testing.expectEqualStrings("https://cdn.example/a.png", preview.image);

    var huge: [max_body + 64]u8 = @splat(' ');
    @memcpy(huge[max_body..][0..7], "<title>");
    const late = parse(&huge, &title, &desc, &image);
    try std.testing.expectEqual(@as(usize, 0), late.title.len);

    var req: [256]u8 = undefined;
    const bytes = try buildRequest(&req, "example.com", "/a");
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Cookie") == null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "cookie") == null);

    const loopback = try parseHttps("https://127.0.0.1/secret");
    try std.testing.expect(deniedAddress(loopback.literal.?));
    const priv = try parseHttps("https://10.1.2.3/a");
    try std.testing.expect(deniedAddress(priv.literal.?));
    const lan = try parseHttps("https://192.168.1.9/a");
    try std.testing.expect(deniedAddress(lan.literal.?));
    const link = try parseHttps("https://169.254.169.254/latest");
    try std.testing.expect(deniedAddress(link.literal.?));
    const v6 = try parseHttps("https://[::1]/a");
    try std.testing.expect(deniedAddress(v6.literal.?));
    const fe80 = try parseHttps("https://[fe80::1]/a");
    try std.testing.expect(deniedAddress(fe80.literal.?));
    const pubaddr = try parseHttps("https://1.1.1.1/a");
    try std.testing.expect(!deniedAddress(pubaddr.literal.?));
    try std.testing.expectError(error.NotHttps, parseHttps("http://1.1.1.1/a"));
}
