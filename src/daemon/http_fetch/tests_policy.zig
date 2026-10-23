// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the outbound HTTP implementation.

const std = @import("std");
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const net = std.Io.net;
const Options = @import("contracts.zig").Options;
const parseUrl = @import("url.zig").parseUrl;
const endpointHost = @import("url.zig").endpointHost;
const getAtAddress = @import("client.zig").getAtAddress;

test "parseUrl splits scheme/host/port/path with defaults" {
    const u = try parseUrl("https://feeds.bbci.co.uk/news/rss.xml");
    try std.testing.expect(u.tls);
    try std.testing.expectEqualStrings("feeds.bbci.co.uk", u.host);
    try std.testing.expectEqual(@as(u16, 443), u.port);
    try std.testing.expectEqualStrings("/news/rss.xml", u.path);

    const p = try parseUrl("http://wttr.in");
    try std.testing.expect(!p.tls);
    try std.testing.expectEqual(@as(u16, 80), p.port);
    try std.testing.expectEqualStrings("/", p.path);

    const q = try parseUrl("http://example.com:8080/a/b?c=d");
    try std.testing.expectEqual(@as(u16, 8080), q.port);
    try std.testing.expectEqualStrings("/a/b?c=d", q.path);

    const v6 = try parseUrl("https://[2001:db8::1]:8443/health");
    try std.testing.expectEqualStrings("[2001:db8::1]", v6.host);
    try std.testing.expectEqualStrings("2001:db8::1", endpointHost(v6.host));
    try std.testing.expectEqual(@as(u16, 8443), v6.port);
    try std.testing.expectEqualStrings("/health", v6.path);
    try std.testing.expectError(error.BadUrl, parseUrl("https://[not-ipv6]:8443/"));
    try std.testing.expectError(error.BadUrl, parseUrl("https://[::1]extra/"));
    try std.testing.expectError(error.BadUrl, parseUrl("https://[::1]:0/"));

    try std.testing.expectError(error.BadUrl, parseUrl("ftp://nope"));
}

test "http_fetch Options default CT and CRL policy is fail-open" {
    const opts = Options{};
    try std.testing.expectEqual(@as(usize, 0), opts.ct_logs.len);
    try std.testing.expect(!opts.enforce_sct);
    try std.testing.expectEqual(@as(u8, 0), opts.require_sct);
    try std.testing.expect(opts.crl == null);
    try std.testing.expect(!opts.require_crl);
    try std.testing.expect(!opts.windows_chain_policy);
}

test "http_fetch required Windows chain policy rejects insecure transport options" {
    const addr = try net.IpAddress.parse("127.0.0.1", 443);
    const options: Options = .{ .windows_chain_policy = true, .insecure_skip_verify = true };
    try std.testing.expectError(error.BadCertificate, getAtAddress(
        std.testing.allocator,
        "example.com",
        443,
        true,
        "GET / HTTP/1.1\r\n\r\n",
        addr,
        options,
    ));
    try std.testing.expectError(error.BadCertificate, getAtAddress(
        std.testing.allocator,
        "example.com",
        443,
        false,
        "GET / HTTP/1.1\r\n\r\n",
        addr,
        .{ .windows_chain_policy = true },
    ));
}

test "GAP-K6 CRL and CT callers pass DER and the fetch defaults stay fail-open" {
    const opts = Options{};
    try std.testing.expect(opts.crl == null);
    try std.testing.expect(!opts.require_crl);
    try std.testing.expectEqual(@as(u8, 0), opts.require_sct);
    try std.testing.expectEqual(@as(usize, 0), opts.ct_logs.len);
    const url = try parseUrl("http://crl.example/leaf.crl");
    try std.testing.expectEqualStrings("crl.example", url.host);
    try std.testing.expectEqualStrings("/leaf.crl", url.path);
}
