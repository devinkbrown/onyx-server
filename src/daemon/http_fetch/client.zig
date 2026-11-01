// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP request composition, address pinning, and TLS fallback policy.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const http1 = @import("../../proto/http1_client.zig");
const net = std.Io.net;
const Error = @import("contracts.zig").Error;
const Options = @import("contracts.zig").Options;
const Url = @import("url.zig").Url;
const endpointHost = @import("url.zig").endpointHost;
const getTls12 = @import("tls_exchange.zig").getTls12;
const getTls = @import("tls_exchange.zig").getTls;
const readHttp = @import("tls_exchange.zig").readHttp;
const resolveHostA = @import("resolution.zig").resolveHostA;
const resolveHostAAAA = @import("resolution.zig").resolveHostAAAA;
const resolveHostFamilies = @import("resolution.zig").resolveHostFamilies;
const connectAddr = @import("native_io.zig").connectAddr;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const closeFd = @import("native_io.zig").closeFd;
const writeAll = @import("native_io.zig").writeAll;
const win = @import("windows_abi.zig").win;

/// Perform one GET to `host` and return the full HTTP response (headers+body,
/// caller owns). `request_bytes` is a complete HTTP/1.1 request (built by
/// `geo_fetch`). On TLS, `server_name`/SNI is `host`.
pub fn get(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    tls: bool,
    request_bytes: []const u8,
    opts: Options,
) Error![]u8 {
    if (opts.connect_established) |connected| connected.* = false;
    if (opts.windows_chain_policy and (!tls or opts.insecure_skip_verify)) return error.BadCertificate;
    const lookup_host = endpointHost(host);
    const addr: net.IpAddress = if (comptime builtin.os.tag == .windows) blk: {
        // The Windows system resolver can have an AAAA answer with no A
        // answer. Keep the chosen address pinned for the entire request.
        break :blk resolveHostA(lookup_host, port, opts.recv_timeout_ms) catch |err| switch (err) {
            error.HostNotFound => try resolveHostAAAA(lookup_host, port, opts.recv_timeout_ms),
            else => return err,
        };
    } else blk: {
        // One poll covers A and AAAA. Prefer IPv4 when it exists so an
        // established HTTPS path stays on the address it already used; a
        // v6-only name still connects.
        const families = try resolveHostFamilies(lookup_host, opts.recv_timeout_ms);
        if (families.v4) |bytes| break :blk .{ .ip4 = .{ .bytes = bytes, .port = port } };
        if (families.v6) |bytes| break :blk .{ .ip6 = .{ .bytes = bytes, .port = port } };
        return error.HostNotFound;
    };
    var connected = false;
    var first_opts = opts;
    first_opts.connect_established = opts.connect_established orelse &connected;
    return getAtAddress(allocator, host, port, tls, request_bytes, addr, first_opts) catch |err| {
        if (comptime builtin.os.tag == .windows) {
            const literal = net.IpAddress.parse(lookup_host, port) catch null;
            if (addr == .ip4 and literal == null and !first_opts.connect_established.?.* and
                (err == error.ConnectFailed or err == error.ConnectTimeout))
            {
                const next = try resolveHostAAAA(lookup_host, port, opts.recv_timeout_ms);
                return getAtAddress(allocator, host, port, tls, request_bytes, next, first_opts);
            }
        }
        return err;
    };
}

/// Send one request to an already selected IP while using `host` for HTTP Host,
/// TLS SNI, and certificate verification. Security-sensitive callers can screen
/// the resolved address and connect to exactly that address without a second
/// DNS lookup or rebinding window.
pub fn getAtAddress(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    tls: bool,
    request_bytes: []const u8,
    addr: net.IpAddress,
    opts: Options,
) Error![]u8 {
    if (opts.connect_established) |connected| connected.* = false;
    if (opts.windows_chain_policy and (!tls or opts.insecure_skip_verify)) return error.BadCertificate;
    const selected_port = switch (addr) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    if (selected_port != port) return error.ConnectFailed;
    if (comptime builtin.os.tag == .windows) {
        var startup: [408]u8 align(8) = @splat(0);
        if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    }
    defer {
        if (comptime builtin.os.tag == .windows) _ = win.WSACleanup();
    }
    if (!tls) {
        const fd = try connectAddr(addr, opts.connect_timeout_ms);
        defer closeFd(fd);
        if (opts.connect_established) |connected| connected.* = true;
        try setRecvTimeout(fd, opts.recv_timeout_ms);
        try writeAll(fd, request_bytes);
        return try readHttp(allocator, fd, opts.max_response_bytes);
    }

    // Try TLS 1.3 first (the preferred client). Many RSS/CDN hosts still serve
    // TLS 1.2 only, so a failed handshake may retry on a fresh connection.
    // Once the handshake succeeds, preserve every subsequent failure. A failed
    // request write may have transmitted a prefix and must never replay a POST.
    {
        const fd = try connectAddr(addr, opts.connect_timeout_ms);
        defer closeFd(fd);
        if (opts.connect_established) |connected| connected.* = true;
        try setRecvTimeout(fd, opts.recv_timeout_ms);
        var application_phase = false;
        if (getTls(allocator, fd, endpointHost(host), request_bytes, opts, &application_phase)) |resp| {
            return resp;
        } else |err| {
            if (application_phase or err == error.ResponseTooLarge or tlsTrustFailure(err)) return err;
        }
    }
    const fd2 = try connectAddr(addr, opts.connect_timeout_ms);
    defer closeFd(fd2);
    try setRecvTimeout(fd2, opts.recv_timeout_ms);
    return try getTls12(allocator, fd2, endpointHost(host), request_bytes, opts);
}

fn tlsTrustFailure(err: anyerror) bool {
    return switch (err) {
        error.UnknownCa,
        error.CertificateNameMismatch,
        error.CertificateRevoked,
        error.BadCertificate,
        error.Expired,
        error.NotYetValid,
        error.IssuerMismatch,
        error.NotSelfSigned,
        error.MissingSignature,
        error.BadSignature,
        error.BadSct,
        error.InsufficientScts,
        => true,
        else => false,
    };
}

/// Perform one HTTP POST of `body` to `url` with `content_type`, returning the
/// full HTTP response (headers+body, caller owns). Built for the OCSP stapler,
/// which submits a DER `OCSPRequest` (`application/ocsp-request`) to a
/// responder's AIA URL; responder URLs are almost always plain `http://`
/// (responses are signed, so plain transport is correct). Emits
/// `Connection: close` so the responder ends the stream and the read loop
/// terminates deterministically. The request line is built into a
/// caller-scoped scratch buffer sized to the (small) body plus header framing.
pub fn post(
    allocator: std.mem.Allocator,
    url: Url,
    content_type: []const u8,
    body: []const u8,
    opts: Options,
) Error![]u8 {
    const headers = [_]http1.Header{
        .{ .name = "Content-Type", .value = content_type },
        .{ .name = "Accept", .value = "application/ocsp-response" },
        .{ .name = "Connection", .value = "close" },
    };
    return postWithHeaders(allocator, url, &headers, body, null, opts);
}

/// POST a JSON body with `X-Onyx-Signature`. The signature is the caller's
/// HMAC over the exact body bytes. Used by outbound event webhooks.
pub fn postSigned(
    allocator: std.mem.Allocator,
    url: Url,
    body: []const u8,
    signature: []const u8,
    opts: Options,
) Error![]u8 {
    const headers = [_]http1.Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "X-Onyx-Signature", .value = signature },
        .{ .name = "Connection", .value = "close" },
    };
    return postWithHeaders(allocator, url, &headers, body, null, opts);
}

/// Signed webhook POST to an already screened address. The HTTP Host and TLS
/// identity still use `url.host`; no second hostname resolution is performed.
pub fn postSignedAtAddress(
    allocator: std.mem.Allocator,
    url: Url,
    body: []const u8,
    signature: []const u8,
    addr: net.IpAddress,
    opts: Options,
) Error![]u8 {
    const headers = [_]http1.Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "X-Onyx-Signature", .value = signature },
        .{ .name = "Connection", .value = "close" },
    };
    return postWithHeaders(allocator, url, &headers, body, addr, opts);
}

fn postWithHeaders(
    allocator: std.mem.Allocator,
    url: Url,
    headers: []const http1.Header,
    body: []const u8,
    pinned_addr: ?net.IpAddress,
    opts: Options,
) Error![]u8 {
    // buildRequest writes method/path/Host + each header + Content-Length + body.
    const default_port: u16 = if (url.tls) 443 else 80;
    const owned_host: ?[]u8 = if (url.port == default_port) null else try std.fmt.allocPrint(allocator, "{s}:{d}", .{ url.host, url.port });
    defer if (owned_host) |value| allocator.free(value);
    const host_header: []const u8 = if (owned_host) |value| value else url.host;
    var extra: usize = host_header.len + url.path.len + 256;
    for (headers) |h| extra += h.name.len + h.value.len + 4;
    const cap = std.math.add(usize, body.len, extra) catch return error.ResponseTooLarge;
    const req_buf = try allocator.alloc(u8, cap);
    defer allocator.free(req_buf);
    const request_bytes = http1.buildRequest(req_buf, "POST", host_header, url.path, headers, body) catch
        return error.ResponseTooLarge;
    return if (pinned_addr) |addr|
        getAtAddress(allocator, url.host, url.port, url.tls, request_bytes, addr, opts)
    else
        get(allocator, url.host, url.port, url.tls, request_bytes, opts);
}
