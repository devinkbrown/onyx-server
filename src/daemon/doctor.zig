// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only, fixed preflight checks for an already loaded configuration.
const std = @import("std");
const config_boot = @import("config_boot.zig");
const tls_certs = @import("tls_certs.zig");
const x509 = @import("../crypto/x509.zig");
const http_fetch = @import("http_fetch.zig");
const http1 = @import("../proto/http1_client.zig");

pub const FetchFn = *const fn (std.mem.Allocator, []const u8) anyerror![]u8;
pub const Result = struct {
    lines: []u8,
    failed: bool,
    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        allocator.free(self.lines);
    }
};

fn line(out: *std.ArrayList(u8), allocator: std.mem.Allocator, failed: *bool, status: []const u8, id: []const u8, citation: []const u8, detail: []const u8) !void {
    if (std.mem.eql(u8, status, "fail")) failed.* = true;
    const formatted = try std.fmt.allocPrint(allocator, "doctor {s} {s} {s} {s}\n", .{ status, id, citation, detail });
    defer allocator.free(formatted);
    try out.appendSlice(allocator, formatted);
}

fn gauge(body: []const u8, name: []const u8) ?f64 {
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw| {
        const row = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, row, name) or row.len <= name.len or !std.ascii.isWhitespace(row[name.len])) continue;
        const value = std.mem.trim(u8, row[name.len..], " \t");
        const end = std.mem.indexOfAny(u8, value, " \t") orelse value.len;
        const parsed = std.fmt.parseFloat(f64, value[0..end]) catch continue;
        if (std.math.isFinite(parsed)) return parsed;
    }
    return null;
}

/// The optional body is for offline fixtures. With a URL, fetch is invoked
/// exactly once; no other network path exists in this module.
pub fn report(allocator: std.mem.Allocator, io: std.Io, loaded: *const config_boot.Loaded, metrics_url: ?[]const u8, metrics_body: ?[]const u8, fetch: ?FetchFn) !Result {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var failed = false;

    const io_reason = config_boot.configCheckError(loaded.io, .off);
    try line(&out, allocator, &failed, if (io_reason == null) "pass" else "fail", "sqpoll_defer_taskrun", "src/daemon/config_boot.zig", io_reason orelse "configCheckError allowed io flags");
    const ktls_reason = config_boot.configCheckError(.{}, loaded.tls.ktls);
    try line(&out, allocator, &failed, if (ktls_reason == null) "pass" else "fail", "ktls_txrx", "src/daemon/config_boot.zig", ktls_reason orelse "configCheckError allowed kTLS mode");

    if (!loaded.parsed.ocsp.enabled) {
        try line(&out, allocator, &failed, "skipped", "ocsp_leaf_uri", "ocsp.enabled", "false");
    } else if (loaded.parsed.tls.cert_path) |path| {
        if (path.len == 0) {
            try line(&out, allocator, &failed, "fail", "ocsp_leaf_uri", "tls.cert_path", "missing leaf");
        } else {
            const chain = tls_certs.loadCertChain(allocator, io, path) catch |err| blk: {
                const detail = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ path, @errorName(err) });
                defer allocator.free(detail);
                try line(&out, allocator, &failed, "skipped", "ocsp_leaf_uri", path, detail);
                break :blk null;
            };
            if (chain) |certs| {
                defer {
                    for (certs) |der| allocator.free(der);
                    allocator.free(certs);
                }
                if (certs.len == 0) {
                    try line(&out, allocator, &failed, "fail", "ocsp_leaf_uri", "tls.cert_path", "missing leaf");
                } else if (x509.parse(certs[0])) |leaf| {
                    if (leaf.aia_ocsp_url.len == 0) {
                        try line(&out, allocator, &failed, "fail", "ocsp_leaf_uri", "aia_ocsp_url", "leaf has no AIA OCSP responder URL");
                    } else {
                        try line(&out, allocator, &failed, "pass", "ocsp_leaf_uri", "aia_ocsp_url", leaf.aia_ocsp_url);
                    }
                } else |err| {
                    const detail = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ path, @errorName(err) });
                    defer allocator.free(detail);
                    try line(&out, allocator, &failed, "skipped", "ocsp_leaf_uri", path, detail);
                }
            }
        }
    } else {
        try line(&out, allocator, &failed, "fail", "ocsp_leaf_uri", "tls.cert_path", "missing leaf");
    }

    var owned_body: ?[]u8 = null;
    defer if (owned_body) |body| allocator.free(body);
    var body = metrics_body;
    var fetch_error: ?[]const u8 = null;
    if (metrics_url) |url| {
        if (fetch) |get| {
            owned_body = get(allocator, url) catch |err| blk: {
                fetch_error = @errorName(err);
                break :blk null;
            };
            body = owned_body;
        } else {
            fetch_error = "no fetch function";
            body = null;
        }
    }
    if (body) |metrics| {
        const tcp = gauge(metrics, "onyx_s2s_tcp_active");
        const links = gauge(metrics, "onyx_s2s_links_active");
        if (tcp == null) {
            try line(&out, allocator, &failed, "skipped", "s2s_handshake", "onyx_s2s_tcp_active", "missing gauge");
        } else if (links == null) {
            try line(&out, allocator, &failed, "skipped", "s2s_handshake", "onyx_s2s_links_active", "missing gauge");
        } else {
            const stuck = tcp.? > 0 and links.? == 0;
            try line(&out, allocator, &failed, if (stuck) "fail" else "pass", "s2s_handshake", "onyx_s2s_tcp_active,onyx_s2s_links_active", if (stuck) "TCP active but no established Mooring link" else "gauges do not show a stuck handshake");
        }
    } else {
        try line(&out, allocator, &failed, "skipped", "s2s_handshake", if (metrics_url == null) "no metrics URL" else metrics_url.?, fetch_error orelse "no metrics body");
    }
    return .{ .lines = try out.toOwnedSlice(allocator), .failed = failed };
}

/// One explicit GET. The caller never invokes this without a metrics URL.
pub fn fetchMetrics(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const target = try http_fetch.parseUrl(url);
    var request_buf: [2048]u8 = undefined;
    const req = try http1.buildRequest(&request_buf, "GET", target.host, target.path, &.{}, "");
    const response = try http_fetch.get(allocator, target.host, target.port, target.tls, req, .{ .max_response_bytes = 1024 * 1024 });
    defer allocator.free(response);
    var storage: [32]http1.Header = undefined;
    const parsed = try http1.parseResponse(response, &storage);
    if (parsed.status != 200) return error.MetricsHttpStatus;
    return allocator.dupe(u8, parsed.body);
}

test "GAP-O4 branch=doctor read-only fixed checks" {
    std.debug.print("GAP-O4 branch=doctor read-only fixed checks\n", .{});
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromText(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const fixture = "onyx_s2s_tcp_active 2\nonyx_s2s_links_active 0\n";
    const Counter = struct {
        var calls: usize = 0;
        var last_url: []const u8 = "";
        fn fetch(a: std.mem.Allocator, url: []const u8) ![]u8 {
            calls += 1;
            last_url = url;
            return a.dupe(u8, fixture);
        }
    };
    Counter.calls = 0;
    const offline = try report(allocator, std.testing.io, &loaded, null, fixture, Counter.fetch);
    defer offline.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), Counter.calls);
    try std.testing.expect(offline.failed);
    try std.testing.expect(std.mem.indexOf(u8, offline.lines, "doctor fail s2s_handshake") != null);
    const online = try report(allocator, std.testing.io, &loaded, "http://example.test/metrics", null, Counter.fetch);
    defer online.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), Counter.calls);
    try std.testing.expectEqualStrings("http://example.test/metrics", Counter.last_url);
    try std.testing.expect(online.failed);
    const skipped = try report(allocator, std.testing.io, &loaded, null, null, Counter.fetch);
    defer skipped.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), Counter.calls);
    try std.testing.expect(!skipped.failed);
    try std.testing.expect(std.mem.indexOf(u8, skipped.lines, "no metrics URL") != null);
}

test "GAP-O4 config failures, missing gauges, and parsed OCSP leaf" {
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromText(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[io]\nsqpoll=true\ndefer_taskrun=true\n[tls]\nktls=\"txrx\"\n[ocsp]\nenabled=true\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const missing = try report(allocator, std.testing.io, &loaded, null, "onyx_s2s_tcp_active 1\n", null);
    defer missing.deinit(allocator);
    try std.testing.expect(missing.failed);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, config_boot.sqpoll_defer_taskrun_reason) != null);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, config_boot.ktls_txrx_footgun) != null);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, "doctor fail ocsp_leaf_uri tls.cert_path missing leaf") != null);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, "doctor skipped s2s_handshake onyx_s2s_links_active missing gauge") != null);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const leaf_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT
        \\BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz
        \\MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj
        \\GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp
        \\LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O
        \\BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf
        \\lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN
        \\Lw0=
        \\-----END CERTIFICATE-----
    ;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "leaf.pem", .data = leaf_pem });
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/leaf.pem", .{tmp.sub_path});
    defer allocator.free(path);
    const config_text = try std.fmt.allocPrint(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\ncert_path=\"{s}\"\n[ocsp]\nenabled=true\n", .{path});
    defer allocator.free(config_text);
    var cert_loaded = try config_boot.loadFromText(allocator, config_text, .{ .port = 6680 }, .{});
    defer cert_loaded.deinit(allocator);
    const parsed = try report(allocator, std.testing.io, &cert_loaded, null, "onyx_s2s_tcp_active 1\nonyx_s2s_links_active 1\n", null);
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.failed);
    try std.testing.expect(std.mem.indexOf(u8, parsed.lines, "doctor fail ocsp_leaf_uri aia_ocsp_url leaf has no AIA OCSP responder URL") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.lines, "doctor pass s2s_handshake") != null);
}
