// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blocking, thread-safe outbound HTTP/1.1 GET (plain + TLS 1.3), for the
//! geo_services background fetcher thread.
//!
//! It is deliberately self-contained and does NOT touch the reactor's io_uring
//! `Io` (which is not safe to share across threads): DNS, connect, and socket
//! I/O use raw OS sockets (Winsock on Windows, `linux`/`posix` elsewhere).
//! Unix resolver configuration comes from `/etc/resolv.conf`; Windows uses
//! the system hostname resolver. Connect and receive are bounded by
//! timeouts so a stalled upstream cannot wedge the fetcher thread.
//!
//! TLS reuses `crypto/tls_client` (the same client `acme_runner` drives), so
//! news feeds over HTTPS verify against caller-supplied trust anchors.
const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const dns = @import("../proto/dns.zig");
const resolv_conf = @import("../proto/resolv_conf.zig");
const tls_client = @import("../crypto/tls_client.zig");
const tls_client_failure = @import("tls_client_failure.zig");
const tls12_client = @import("../crypto/tls12_client.zig");
const sct = @import("../crypto/sct.zig");
const http1 = @import("../proto/http1_client.zig");
const net = std.Io.net;
const Socket = if (builtin.os.tag == .windows) usize else sys.fd_t;

const win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const af_inet: i32 = 2;
    const sock_stream: i32 = 1;
    const ipproto_tcp: i32 = 6;
    const sol_socket: i32 = 0xffff;
    const so_error: i32 = 0x1007;
    const so_rcvtimeo: i32 = 0x1006;
    const so_sndtimeo: i32 = 0x1005;
    const fionbio: u32 = 0x8004667e;
    const interrupted: i32 = 10004;
    const would_block: i32 = 10035;
    const in_progress: i32 = 10036;
    const already: i32 = 10037;
    const timed_out: i32 = 10060;
    const io_pending: i32 = 997;
    const af_inet6: i32 = 23;
    const ns_dns: u32 = 12;
    const wait_object_0: u32 = 0;
    const wait_timeout: u32 = 258;

    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: [4]u8,
        zero: [8]u8 = @splat(0),
    };
    const SockAddr6 = extern struct {
        family: u16,
        port: u16,
        flowinfo: u32 = 0,
        addr: [16]u8,
        scope_id: u32 = 0,
    };
    const FdSet = extern struct {
        count: u32,
        sockets: [64]usize,
    };
    const Timeval = extern struct {
        seconds: i32,
        microseconds: i32,
    };
    const Overlapped = extern struct {
        internal: usize = 0,
        internal_high: usize = 0,
        offset_or_pointer: usize = 0,
        event: ?*anyopaque = null,
    };
    const AddrInfoExW = extern struct {
        flags: i32 = 0,
        family: i32 = 0,
        socket_type: i32 = 0,
        protocol: i32 = 0,
        addr_len: usize = 0,
        canonical_name: ?[*:0]u16 = null,
        addr: ?*anyopaque = null,
        blob: ?*anyopaque = null,
        blob_len: usize = 0,
        provider: ?*anyopaque = null,
        next: ?*AddrInfoExW = null,
    };
    comptime {
        if (@sizeOf(SockAddr4) != 16 or @sizeOf(SockAddr6) != 28 or @sizeOf(FdSet) != 520 or @sizeOf(Timeval) != 8 or
            @sizeOf(Overlapped) != 32 or @sizeOf(AddrInfoExW) != 72)
            @compileError("Windows HTTP socket ABI shape changed");
    }

    extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
    extern "ws2_32" fn connect(socket: usize, address: *const anyopaque, address_len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn bind(socket: usize, address: *const anyopaque, address_len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(socket: usize, address: *anyopaque, address_len: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn accept(socket: usize, address: ?*anyopaque, address_len: ?*i32) callconv(.winapi) usize;
    extern "ws2_32" fn select(ignored_nfds: i32, readfds: ?*FdSet, writefds: ?*FdSet, exceptfds: ?*FdSet, timeout: *Timeval) callconv(.winapi) i32;
    extern "ws2_32" fn getsockopt(socket: usize, level: i32, option: i32, value: *anyopaque, length: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, length: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, length: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn GetAddrInfoExW(name: [*:0]const u16, service: ?[*:0]const u16, namespace: u32, provider: ?*const anyopaque, hints: *const AddrInfoExW, result: *?*AddrInfoExW, timeout: ?*Timeval, overlapped: *Overlapped, completion: *const fn (u32, u32, *Overlapped) callconv(.winapi) void, cancel_handle: *?*anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn GetAddrInfoExCancel(cancel_handle: *?*anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn FreeAddrInfoExW(result: *AddrInfoExW) callconv(.winapi) void;
    extern "kernel32" fn CreateEventW(attributes: ?*const anyopaque, manual_reset: i32, initial_state: i32, name: ?[*:0]const u16) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn WaitForSingleObject(handle: *anyopaque, milliseconds: u32) callconv(.winapi) u32;
    extern "kernel32" fn SetEvent(handle: *anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn CloseHandle(handle: *anyopaque) callconv(.winapi) i32;
};

pub const Error = error{
    BadUrl,
    NoNameservers,
    HostNotFound,
    ResolveTimeout,
    ConnectFailed,
    ConnectTimeout,
    SocketUnavailable,
    ConnectionClosed,
    RecvTimeout,
    ResponseTooLarge,
} || std.mem.Allocator.Error || tls_client.Error || tls12_client.Error;

const max_tls_record = 16 * 1024 + 512;

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
fn endpointHost(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
}

pub const Options = struct {
    /// Trust anchors (DER certs) for TLS verification; required when `url.tls`
    /// unless `insecure_skip_verify` is set.
    trust_anchors: []const []const u8 = &.{},
    /// Exact DER certificates that must never appear in the presented chain.
    /// Windows outbound HTTPS supplies its Disallowed store here.
    disallowed_certs: []const []const u8 = &.{},
    /// Require the Windows native HTTPS chain and CTL policy in addition to
    /// the Zig verifier. Production daemon HTTPS sets this with system roots.
    windows_chain_policy: bool = false,
    /// Skip server-certificate verification (TLS transport only). Intended as a
    /// documented escape hatch for public read-only feeds when a usable system
    /// CA bundle is unavailable; off by default.
    insecure_skip_verify: bool = false,
    /// Set after the first TCP connection succeeds. A caller may retry a
    /// different address only while this remains false; later failures could
    /// follow TLS or application bytes on the wire.
    connect_established: ?*bool = null,
    connect_timeout_ms: u31 = 5000,
    recv_timeout_ms: u31 = 10000,
    max_response_bytes: usize = 512 * 1024,
    /// Optional leaf CRL (DER) forwarded to both TLS clients. Empty/absent is
    /// the historical fail-open ACME/HTTPS posture.
    crl: ?[]const u8 = null,
    /// When true AND `crl` is set, an unusable CRL fails the handshake closed.
    require_crl: bool = false,
    /// Optional pinned CT logs for the TLS 1.3 client. Empty (default) skips
    /// the SCT path so ACME/HTTPS stay byte-identical. TLS 1.2 has no SCT
    /// wire; these fields are ignored on the 1.2 fallback.
    ct_logs: []const sct.CtLog = &.{},
    enforce_sct: bool = false,
    require_sct: u8 = 0,
};

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
    const addr = resolveHostA(lookup_host, port, opts.recv_timeout_ms) catch |err| blk: {
        // The Windows system resolver can have an AAAA answer with no A
        // answer. Keep the chosen address pinned for the entire request.
        if (comptime builtin.os.tag == .windows) {
            if (err == error.HostNotFound) break :blk try resolveHostAAAA(lookup_host, port, opts.recv_timeout_ms);
        }
        return err;
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

/// TLS 1.2 variant of `getTls` (hardened `tls12_client`). Used as the fallback
/// when the TLS 1.3 handshake fails — broadens outbound reach to TLS-1.2-only
/// hosts. Mirrors `getTls` but uses the 1.2 client's `decrypt` (no KeyUpdate).
fn getTls12(
    allocator: std.mem.Allocator,
    fd: Socket,
    host: []const u8,
    request_bytes: []const u8,
    opts: Options,
) Error![]u8 {
    var tc = try tls12_client.Client.init(allocator, .{
        .server_name = host,
        .trust_anchors = opts.trust_anchors,
        .disallowed_certs = opts.disallowed_certs,
        .windows_chain_policy = opts.windows_chain_policy,
        .alpn_protocols = &.{"http/1.1"},
        .now_unix_seconds = wallClockSeconds(),
        .crl = opts.crl,
        .require_crl = opts.require_crl,
    });
    defer tc.deinit();
    if (opts.insecure_skip_verify) tc.skipServerCertVerifyForTest();

    {
        const hello = try tc.start();
        defer allocator.free(hello);
        try writeAll(fd, hello);
    }
    var read_buf: [max_tls_record]u8 = undefined;
    while (!tc.handshakeDone()) {
        const n = try readSome(fd, &read_buf);
        switch (tc.feed(read_buf[0..n]) catch |err| {
            sendFatal(fd, &tc, err);
            return err;
        }) {
            .need_more => {},
            .bytes_to_send => |out| {
                defer allocator.free(out);
                try writeAll(fd, out);
            },
        }
    }
    {
        const record = try tc.encrypt(request_bytes);
        defer allocator.free(record);
        try writeAll(fd, record);
    }

    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(allocator);
    try pending.appendSlice(allocator, tc.pendingBytes());
    var plaintext: std.ArrayList(u8) = .empty;
    defer plaintext.deinit(allocator);

    read_loop: while (true) {
        while (frameRecordLen(pending.items)) |rec_len| {
            const rec = pending.items[0..rec_len];
            const pt = tc.decrypt(rec) catch |err| switch (err) {
                error.TlsAlert => break :read_loop, // close_notify ends the stream
                else => {
                    sendFatal(fd, &tc, err);
                    return err;
                },
            };
            defer allocator.free(pt);
            if (plaintext.items.len + pt.len > opts.max_response_bytes) return error.ResponseTooLarge;
            try plaintext.appendSlice(allocator, pt);
            consumePrefix(&pending, rec_len);
            if (http1.isComplete(plaintext.items)) break :read_loop;
        }
        if (http1.isComplete(plaintext.items)) break;
        const n = readSome(fd, &read_buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        try pending.appendSlice(allocator, read_buf[0..n]);
    }
    return plaintext.toOwnedSlice(allocator);
}

fn getTls(
    allocator: std.mem.Allocator,
    fd: Socket,
    host: []const u8,
    request_bytes: []const u8,
    opts: Options,
    application_phase: *bool,
) Error![]u8 {
    var tc = try tls_client.Client.init(allocator, .{
        .server_name = host,
        .trust_anchors = opts.trust_anchors,
        .disallowed_certs = opts.disallowed_certs,
        .windows_chain_policy = opts.windows_chain_policy,
        .alpn_protocols = &.{"http/1.1"},
        .now_unix_seconds = wallClockSeconds(),
        .crl = opts.crl,
        .require_crl = opts.require_crl,
        .ct_logs = opts.ct_logs,
        .enforce_sct = opts.enforce_sct,
        .require_sct = opts.require_sct,
    });
    defer tc.deinit();
    if (opts.insecure_skip_verify) tc.skipServerCertVerifyForTest();

    {
        const hello = try tc.start();
        defer allocator.free(hello);
        try writeAll(fd, hello);
    }
    var read_buf: [max_tls_record]u8 = undefined;
    while (!tc.handshakeDone()) {
        const n = try readSome(fd, &read_buf);
        switch (tc.feed(read_buf[0..n]) catch |err| {
            sendFatal(fd, &tc, err);
            return err;
        }) {
            .need_more => {},
            .bytes_to_send => |out| {
                defer allocator.free(out);
                try writeAll(fd, out);
            },
        }
    }
    application_phase.* = true;
    {
        const record = try tc.encrypt(request_bytes);
        defer allocator.free(record);
        try writeAll(fd, record);
    }

    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(allocator);
    try pending.appendSlice(allocator, tc.pendingBytes());
    var plaintext: std.ArrayList(u8) = .empty;
    defer plaintext.deinit(allocator);

    read_loop: while (true) {
        while (frameRecordLen(pending.items)) |rec_len| {
            const rec = pending.items[0..rec_len];
            const read = tc.decryptApp(rec) catch |err| switch (err) {
                error.TlsAlert => break :read_loop, // close_notify ends the stream
                else => {
                    sendFatal(fd, &tc, err);
                    return err;
                },
            };
            switch (read) {
                .application_data => |pt| {
                    defer allocator.free(pt);
                    if (plaintext.items.len + pt.len > opts.max_response_bytes) return error.ResponseTooLarge;
                    try plaintext.appendSlice(allocator, pt);
                },
                .control => {},
            }
            // A server KeyUpdate (surfaced as .control) may queue a reply we must
            // write back before continuing to read under the rotated keys.
            if (try tc.takePendingSend()) |reply| {
                defer allocator.free(reply);
                try writeAll(fd, reply);
            }
            consumePrefix(&pending, rec_len);
            if (http1.isComplete(plaintext.items)) break :read_loop;
        }
        if (http1.isComplete(plaintext.items)) break;
        const n = readSome(fd, &read_buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        try pending.appendSlice(allocator, read_buf[0..n]);
    }
    return plaintext.toOwnedSlice(allocator);
}

fn readHttp(allocator: std.mem.Allocator, fd: Socket, max_bytes: usize) Error![]u8 {
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(allocator);
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = readSome(fd, &buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        if (acc.items.len + n > max_bytes) return error.ResponseTooLarge;
        try acc.appendSlice(allocator, buf[0..n]);
        if (http1.isComplete(acc.items)) break;
    }
    return acc.toOwnedSlice(allocator);
}

fn sendFatal(fd: Socket, client: anytype, failure: anytype) void {
    tls_client_failure.sendFatal(fd, client, failure);
}

/// Wall-clock time in Unix seconds, used to reject expired server certificates.
fn wallClockSeconds() i64 {
    if (comptime builtin.os.tag == .windows) {
        const millis = @import("../substrate/platform.zig").realtimeMillisChecked() orelse return 0;
        return @divTrunc(millis, 1000);
    }
    var ts: sys.timespec = undefined;
    if (posix.errno(sys.clock_gettime(posix.CLOCK.REALTIME, &ts)) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

// ---- TLS record framing (mirrors acme_runner) -------------------------------

fn frameRecordLen(buf: []const u8) ?usize {
    if (buf.len < 5) return null;
    const len = (@as(usize, buf[3]) << 8) | @as(usize, buf[4]);
    const total = 5 + len;
    if (buf.len < total) return null;
    return total;
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const rem = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..rem], list.items[n..]);
    list.shrinkRetainingCapacity(rem);
}

// ---- DNS (A-record over UDP, blocking) --------------------------------------

/// Resolve `host` to an address: IP literals parse directly; otherwise query
/// the system resolver with a bounded wait (Windows) or each configured DNS
/// server (Unix). Public so mesh auto-connect can dial hostname peers.
pub fn resolveHostA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| return addr else |_| {}
    if (comptime builtin.os.tag == .windows) {
        return resolveHostWindows(host, port, timeout_ms, false);
    }

    var conf_buf: [4096]u8 = undefined;
    const text = readSmallFile("/etc/resolv.conf", &conf_buf) catch return error.NoNameservers;
    const conf = resolv_conf.parse(text);
    const servers = conf.nameserverSlice();
    if (servers.len == 0) return error.NoNameservers;

    var id_seed: [2]u8 = undefined;
    osEntropy(&id_seed);
    const query_id = std.mem.readInt(u16, &id_seed, .big);
    var query_buf: [dns.max_message_len]u8 = undefined;
    const query = dns.encodeQuery(&query_buf, query_id, host, .a) catch return error.HostNotFound;

    for (servers) |srv| {
        const ns_v4 = switch (srv) {
            .ipv4 => |b| b,
            .ipv6 => continue,
        };
        if (queryOneServer(ns_v4, query, timeout_ms)) |ipv4| {
            return .{ .ip4 = .{ .bytes = ipv4, .port = port } };
        } else |_| {}
    }
    return error.HostNotFound;
}

fn queryOneServer(ns_v4: [4]u8, query: []const u8, timeout_ms: u31) Error![4]u8 {
    const msg = try queryServerPort(ns_v4, 53, query, timeout_ms);
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .a => |ipv4| return ipv4,
        else => {},
    };
    return error.HostNotFound;
}

fn queryServerPort(ns_v4: [4]u8, port: u16, query: []const u8, timeout_ms: u31) Error!dns.Message(1, dns.max_cache_addrs) {
    const question = dns.parseMessage(1, 0, query) catch return error.HostNotFound;
    if (question.question_count != 1) return error.HostNotFound;
    const fd = try udpSocket();
    defer closeFd(fd);
    try setRecvTimeout(fd, timeout_ms);
    var sa = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(ns_v4) };
    if (posix.errno(sys.connect(fd, @ptrCast(&sa), @sizeOf(sys.sockaddr.in))) != .SUCCESS) return error.ConnectFailed;
    try writeAll(fd, query);
    var resp: [dns.max_message_len]u8 = undefined;
    const rc = sys.read(fd, &resp, resp.len);
    if (posix.errno(rc) != .SUCCESS) return error.HostNotFound;
    const msg = dns.parseMessage(1, dns.max_cache_addrs, resp[0..@intCast(rc)]) catch return error.HostNotFound;
    const q = question.questions[0];
    if (msg.header.id != question.header.id or msg.header.rcode() != 0 or
        msg.header.flags & 0x7a00 != 0 or
        !dns.responseMatchesQuestion(1, dns.max_cache_addrs, &msg, q.name.slice(), q.qtype)) return error.HostNotFound;
    if (!dns.responseAnswersFollowCnames(dns.max_cache_addrs, resp[0..@intCast(rc)], q.name.slice(), q.qtype)) return error.HostNotFound;
    return msg;
}

/// Like `resolveHostA` but requests IPv6 addresses. The Unix path queries AAAA
/// records over configured IPv4 nameservers; Windows uses its system resolver.
pub fn resolveHostAAAA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| switch (addr) {
        .ip6 => return addr,
        .ip4 => {}, // an IPv4 literal is not an AAAA answer — fall through to DNS
    } else |_| {}
    if (comptime builtin.os.tag == .windows) {
        return resolveHostWindows(host, port, timeout_ms, true);
    }

    var conf_buf: [4096]u8 = undefined;
    const text = readSmallFile("/etc/resolv.conf", &conf_buf) catch return error.NoNameservers;
    const conf = resolv_conf.parse(text);
    const servers = conf.nameserverSlice();
    if (servers.len == 0) return error.NoNameservers;

    var id_seed: [2]u8 = undefined;
    osEntropy(&id_seed);
    const query_id = std.mem.readInt(u16, &id_seed, .big);
    var query_buf: [dns.max_message_len]u8 = undefined;
    const query = dns.encodeQuery(&query_buf, query_id, host, .aaaa) catch return error.HostNotFound;

    for (servers) |srv| {
        const ns_v4 = switch (srv) {
            .ipv4 => |b| b,
            .ipv6 => continue,
        };
        if (queryOneServer6(ns_v4, query, timeout_ms)) |ipv6| {
            return .{ .ip6 = .{ .bytes = ipv6, .port = port } };
        } else |_| {}
    }
    return error.HostNotFound;
}

fn resolveHostWindows(host: []const u8, port: u16, timeout_ms: u31, want_v6: bool) Error!net.IpAddress {
    if (comptime builtin.os.tag != .windows) return error.NoNameservers;
    if (timeout_ms == 0) return error.ResolveTimeout;
    if (host.len == 0 or host.len > 1024 or std.mem.indexOfScalar(u8, host, 0) != null)
        return error.HostNotFound;
    const wide = std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, host) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.HostNotFound,
    };
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) {
        std.heap.page_allocator.free(wide);
        return error.SocketUnavailable;
    }
    const event = win.CreateEventW(null, 1, 0, null) orelse {
        _ = win.WSACleanup();
        std.heap.page_allocator.free(wide);
        return error.SocketUnavailable;
    };
    const state = std.heap.page_allocator.create(WinResolveState) catch {
        _ = win.CloseHandle(event);
        _ = win.WSACleanup();
        std.heap.page_allocator.free(wide);
        return error.OutOfMemory;
    };
    state.* = .{
        .event = event,
        .name = wide,
        .family = if (want_v6) win.af_inet6 else win.af_inet,
        .port = port,
    };
    state.hints.family = state.family;
    state.hints.socket_type = win.sock_stream;
    state.hints.protocol = win.ipproto_tcp;
    defer state.release();

    // Callback owns one reference from the time the query is issued. On a
    // timeout, cancellation signals completion while some namespace providers
    // may continue internally; the caller can return without freeing storage
    // still reachable by Winsock. The callback frees the result and last ref.
    var cancel_handle: ?*anyopaque = null;
    const rc = win.GetAddrInfoExW(state.name.ptr, null, win.ns_dns, null, &state.hints, &state.result, null, &state.overlapped, winResolveCompleted, &cancel_handle);
    if (rc != win.io_pending) winResolveCompleted(@bitCast(rc), 0, &state.overlapped);

    const wait_ms: u32 = @min(timeout_ms, 2500);
    const waited = win.WaitForSingleObject(state.event, wait_ms);
    if (waited != win.wait_object_0) {
        if (cancel_handle != null) _ = win.GetAddrInfoExCancel(&cancel_handle);
        return if (waited == win.wait_timeout) error.ResolveTimeout else error.HostNotFound;
    }
    const status = state.status.load(.acquire);
    if (status == win.timed_out) return error.ResolveTimeout;
    if (status != 0) return error.HostNotFound;
    return state.answer orelse error.HostNotFound;
}

const WinResolveState = struct {
    // OVERLAPPED and all input/output storage must outlive GetAddrInfoExW.
    overlapped: win.Overlapped = .{},
    hints: win.AddrInfoExW = .{},
    result: ?*win.AddrInfoExW = null,
    event: *anyopaque,
    name: [:0]u16,
    family: i32,
    port: u16,
    answer: ?net.IpAddress = null,
    status: std.atomic.Value(i32) = .init(win.io_pending),
    refs: std.atomic.Value(u32) = .init(2),

    fn release(self: *WinResolveState) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        _ = win.CloseHandle(self.event);
        std.heap.page_allocator.free(self.name);
        _ = win.WSACleanup();
        std.heap.page_allocator.destroy(self);
    }
};

fn winResolveCompleted(status: u32, _: u32, overlapped: *win.Overlapped) callconv(.winapi) void {
    const state: *WinResolveState = @fieldParentPtr("overlapped", overlapped);
    if (state.result) |result| {
        if (status == 0) state.answer = firstWinSystemAddress(result, state.family, state.port);
        win.FreeAddrInfoExW(result);
        state.result = null;
    }
    state.status.store(@bitCast(status), .release);
    _ = win.SetEvent(state.event);
    state.release();
}

fn firstWinSystemAddress(head: ?*win.AddrInfoExW, family: i32, port: u16) ?net.IpAddress {
    var cursor = head;
    for (0..64) |_| {
        const entry = cursor orelse return null;
        cursor = entry.next;
        if (entry.family != family or entry.addr_len > 128) continue;
        const addr = entry.addr orelse continue;
        const raw: [*]const u8 = @ptrCast(addr);
        if (family == win.af_inet) {
            if (entry.addr_len < 16 or std.mem.readInt(u16, raw[0..2], .little) != win.af_inet) continue;
            var bytes: [4]u8 = undefined;
            @memcpy(&bytes, raw[4..8]);
            return .{ .ip4 = .{ .bytes = bytes, .port = port } };
        }
        if (family == win.af_inet6) {
            if (entry.addr_len < 28 or std.mem.readInt(u16, raw[0..2], .little) != win.af_inet6) continue;
            var bytes: [16]u8 = undefined;
            @memcpy(&bytes, raw[8..24]);
            const scope = std.mem.readInt(u32, raw[24..28], .little);
            return .{ .ip6 = .{ .bytes = bytes, .port = port, .interface = .{ .index = scope } } };
        }
    }
    return null;
}

fn queryOneServer6(ns_v4: [4]u8, query: []const u8, timeout_ms: u31) Error![16]u8 {
    const msg = try queryServerPort(ns_v4, 53, query, timeout_ms);
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .aaaa => |ipv6| return ipv6,
        else => {},
    };
    return error.HostNotFound;
}

// ---- raw socket helpers (mirror acme_runner / server idiom) ------------------

fn connectAddr(addr: net.IpAddress, timeout_ms: u31) Error!Socket {
    if (comptime builtin.os.tag == .windows) return connectAddrWindows(addr, timeout_ms);
    const fd = try socketTcpNonblock(if (addr == .ip4) posix.AF.INET else posix.AF.INET6);
    errdefer closeFd(fd);
    const rc = switch (addr) {
        .ip4 => |a4| blk: {
            var sa = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, a4.port), .addr = @bitCast(a4.bytes) };
            break :blk sys.connect(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
        },
        .ip6 => |a6| blk: {
            var sa = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, a6.port), .addr = a6.bytes, .flowinfo = 0, .scope_id = a6.interface.index };
            break :blk sys.connect(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
        },
    };
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => try waitWritable(fd, timeout_ms),
        else => return error.ConnectFailed,
    }
    // Confirm the connect succeeded (SO_ERROR == 0).
    var err_val: i32 = 0;
    var err_len: sys.socklen_t = @sizeOf(i32);
    if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err_val), &err_len)) != .SUCCESS)
        return error.ConnectFailed;
    if (err_val != 0) return error.ConnectFailed;
    try setBlocking(fd);
    return fd;
}

fn connectAddrWindows(addr: net.IpAddress, timeout_ms: u31) Error!Socket {
    if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
    const family: i32 = switch (addr) {
        .ip4 => win.af_inet,
        .ip6 => win.af_inet6,
    };
    const fd = win.WSASocketW(family, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (fd == win.invalid_socket) return error.SocketUnavailable;
    errdefer _ = win.closesocket(fd);
    var nonblocking: u32 = 1;
    if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
    const connected = switch (addr) {
        .ip4 => |a4| blk: {
            const sa = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, a4.port), .addr = a4.bytes };
            break :blk win.connect(fd, &sa, @sizeOf(win.SockAddr4));
        },
        .ip6 => |a6| blk: {
            const sa = win.SockAddr6{ .family = win.af_inet6, .port = std.mem.nativeToBig(u16, a6.port), .addr = a6.bytes, .scope_id = a6.interface.index };
            break :blk win.connect(fd, &sa, @sizeOf(win.SockAddr6));
        },
    };
    if (connected != 0) {
        const err = win.WSAGetLastError();
        if (err != win.would_block and err != win.in_progress and err != win.already) return error.ConnectFailed;
        if (!try windowsWaitWritable(fd, @max(1, @min(timeout_ms, 60_000)))) return error.ConnectTimeout;
    }
    var socket_error: i32 = 0;
    var error_len: i32 = @sizeOf(i32);
    if (win.getsockopt(fd, win.sol_socket, win.so_error, &socket_error, &error_len) != 0 or
        socket_error != 0 or error_len != @sizeOf(i32)) return error.ConnectFailed;
    nonblocking = 0;
    if (win.ioctlsocket(fd, win.fionbio, &nonblocking) != 0) return error.SocketUnavailable;
    return fd;
}

fn windowsWaitWritable(fd: usize, timeout_ms: u31) Error!bool {
    if (comptime builtin.os.tag != .windows) return error.ConnectFailed;
    var writes = win.FdSet{ .count = 1, .sockets = undefined };
    writes.sockets[0] = fd;
    var failures = win.FdSet{ .count = 1, .sockets = undefined };
    failures.sockets[0] = fd;
    var timeout = win.Timeval{ .seconds = @intCast(timeout_ms / 1000), .microseconds = @intCast((timeout_ms % 1000) * 1000) };
    // Winsock reports a failed nonblocking connect in exceptfds, not writefds.
    const ready = win.select(0, null, &writes, &failures, &timeout);
    if (ready < 0) return error.ConnectFailed;
    if (ready == 0) return false;
    if (failures.count != 0) return error.ConnectFailed;
    if (writes.count == 0) return error.ConnectFailed;
    return true;
}

fn waitWritable(fd: sys.fd_t, timeout_ms: u31) Error!void {
    // sys.pollfd/POLL/SOCK.* (not posix.*): these pair with the raw linux
    // syscalls; posix.* resolves to libc/ws2_32 on non-Linux (build-time only).
    var pfd = [_]sys.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    const rc = sys.poll(&pfd, 1, timeout_ms);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.ConnectFailed,
    }
    if (rc == 0) return error.ConnectTimeout;
    if (pfd[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) return error.ConnectFailed;
}

fn socketTcpNonblock(family: u32) Error!sys.fd_t {
    const rc = sys.socket(family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn udpSocket() Error!sys.fd_t {
    const rc = sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn setBlocking(fd: sys.fd_t) Error!void {
    if (comptime builtin.os.tag != .linux) {
        const old = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
        if (posix.errno(old) != .SUCCESS) return error.ConnectFailed;
        var flags: posix.O = @bitCast(@as(u32, @intCast(old)));
        flags.NONBLOCK = false;
        if (posix.errno(sys.fcntl(fd, posix.F.SETFL, @as(usize, @as(u32, @bitCast(flags))))) != .SUCCESS) return error.ConnectFailed;
        return;
    }
    const flags = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    _ = sys.fcntl(fd, posix.F.SETFL, flags & ~@as(usize, posix.SOCK.NONBLOCK));
}

fn setRecvTimeout(fd: Socket, timeout_ms: u31) Error!void {
    if (comptime builtin.os.tag == .windows) {
        const finite_ms: u32 = @max(1, @min(timeout_ms, 60_000));
        if (win.setsockopt(fd, win.sol_socket, win.so_rcvtimeo, &finite_ms, @sizeOf(u32)) != 0 or
            win.setsockopt(fd, win.sol_socket, win.so_sndtimeo, &finite_ms, @sizeOf(u32)) != 0)
            return error.RecvTimeout;
        return;
    }
    const finite_ms = if (builtin.os.tag == .linux) timeout_ms else @max(timeout_ms, 1);
    const tv = sys.timeval{ .sec = @intCast(finite_ms / 1000), .usec = @intCast((finite_ms % 1000) * 1000) };
    const recv_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(sys.timeval));
    const send_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, @ptrCast(&tv), @sizeOf(sys.timeval));
    if (comptime builtin.os.tag != .linux) {
        if (posix.errno(recv_rc) != .SUCCESS or posix.errno(send_rc) != .SUCCESS) return error.RecvTimeout;
    }
}

fn closeFd(fd: Socket) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(fd);
        return;
    }
    _ = sys.close(fd);
}

fn writeAll(fd: Socket, bytes: []const u8) Error!void {
    if (comptime builtin.os.tag == .windows) {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const amount: i32 = @intCast(@min(bytes.len - offset, std.math.maxInt(i32)));
            const sent = win.send(fd, bytes[offset..].ptr, amount, 0);
            if (sent > 0) {
                offset += @intCast(sent);
                continue;
            }
            if (sent == 0) return error.ConnectionClosed;
            switch (win.WSAGetLastError()) {
                win.interrupted => continue,
                win.timed_out, win.would_block => return error.RecvTimeout,
                else => return error.ConnectionClosed,
            }
        }
        return;
    }
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = if (comptime builtin.os.tag == .linux) sys.write(fd, bytes[off..].ptr, bytes.len - off) else sys.send(fd, bytes[off..].ptr, bytes.len - off, posix.MSG.NOSIGNAL);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.ConnectionClosed;
                off += n;
            },
            .INTR => {},
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}

fn readSome(fd: Socket, buf: []u8) Error!usize {
    if (comptime builtin.os.tag == .windows) {
        while (true) {
            const received = win.recv(fd, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(i32))), 0);
            if (received > 0) return @intCast(received);
            if (received == 0) return error.ConnectionClosed;
            switch (win.WSAGetLastError()) {
                win.interrupted => continue,
                win.timed_out, win.would_block => return error.RecvTimeout,
                else => return error.ConnectionClosed,
            }
        }
    }
    while (true) {
        const rc = sys.read(fd, buf.ptr, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                // read()==0 is EOF (peer FIN). Surface it as ConnectionClosed so
                // every caller terminates — notably the TLS handshake loop, which
                // otherwise feeds empty -> need_more -> reads EOF again forever,
                // pegging a core and leaking the socket in CLOSE-WAIT.
                if (n == 0) return error.ConnectionClosed;
                return n;
            },
            .INTR => continue,
            .AGAIN => return error.RecvTimeout,
            else => return error.ConnectionClosed,
        }
    }
}

fn readSmallFile(path: [*:0]const u8, buf: []u8) ![]u8 {
    const rc = sys.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = builtin.os.tag != .linux }, @as(posix.mode_t, 0));
    if (posix.errno(rc) != .SUCCESS) return error.NoNameservers;
    const fd: sys.fd_t = @intCast(rc);
    defer closeFd(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const r = sys.read(fd, buf[total..].ptr, buf.len - total);
        switch (posix.errno(r)) {
            .SUCCESS => {
                const n: usize = @intCast(r);
                if (n == 0) break;
                total += n;
            },
            .INTR => continue,
            else => return error.NoNameservers,
        }
    }
    return buf[0..total];
}

fn osEntropy(buf: []u8) void {
    if (comptime builtin.os.tag != .linux) {
        sys.arc4random_buf(buf.ptr, buf.len);
        return;
    }
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = sys.getrandom(buf.ptr + filled, buf.len - filled, 0);
        if (posix.errno(rc) != .SUCCESS) {
            for (buf[filled..]) |*b| b.* = 0x55; // query IDs are not security-critical
            return;
        }
        filled += @intCast(rc);
    }
}

// ---- tests ------------------------------------------------------------------

test "http_fetch Windows system resolver handles localhost and bounded failures" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const literal4 = try resolveHostA("127.0.0.9", 6900, 0);
    const literal6 = try resolveHostAAAA("::1", 6900, 0);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 9 }, &literal4.ip4.bytes);
    try std.testing.expectEqual(@as(u8, 1), literal6.ip6.bytes[15]);
    const a = try resolveHostA("localhost", 6900, 1000);
    const aaaa = try resolveHostAAAA("localhost", 6900, 1000);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &a.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 6900), a.ip4.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &aaaa.ip6.bytes);
    try std.testing.expectEqual(@as(u16, 6900), aaaa.ip6.port);
    try std.testing.expectError(error.ResolveTimeout, resolveHostA("localhost", 6900, 0));
    try std.testing.expectError(error.HostNotFound, resolveHostA("invalid\xff", 6900, 100));

    // A reserved nonexistent name exercises either immediate negative result
    // or asynchronous cancellation, independent of hosts-file contents.
    const clock = @import("../substrate/platform.zig");
    const started = clock.monotonicMillis();
    const missing = resolveHostA("onyx-system-resolver-test.invalid.", 6900, 10);
    if (missing) |_| return error.TestUnexpectedResult else |err| {
        try std.testing.expect(err == error.HostNotFound or err == error.ResolveTimeout);
    }
    try std.testing.expect(clock.monotonicMillis() - started < 5000);
}

test "http_fetch Windows system result parser rejects short addresses and cycles" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var sockaddr = win.SockAddr4{ .family = win.af_inet, .port = 0, .addr = .{ 127, 0, 0, 42 } };
    var valid = win.AddrInfoExW{ .family = win.af_inet, .addr_len = @sizeOf(win.SockAddr4), .addr = @ptrCast(&sockaddr) };
    var short = win.AddrInfoExW{ .family = win.af_inet, .addr_len = 4, .addr = @ptrCast(&sockaddr), .next = &valid };
    const found = firstWinSystemAddress(&short, win.af_inet, 6900) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 42 }, &found.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 6900), found.ip4.port);
    short.next = &short;
    try std.testing.expect(firstWinSystemAddress(&short, win.af_inet, 6900) == null);
}

test "http_fetch Windows plaintext loopback timeout and response limit" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("metrics_http.zig");
    const a = std.testing.allocator;
    var snapshot = metrics.MetricsSnapshot.init(a);
    defer snapshot.deinit();
    try snapshot.set("windows_fetch_probe 1\n");
    var server = try metrics.MetricsServer.init(&snapshot, 0);
    defer server.shutdown();
    const request = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    // A connected listener without an HTTP worker must honor the receive bound.
    try std.testing.expectError(error.RecvTimeout, get(a, "127.0.0.1", server.port, false, request, .{ .recv_timeout_ms = 80 }));
    var established = false;
    try std.testing.expectError(error.RecvTimeout, get(a, "localhost", server.port, false, request, .{
        .recv_timeout_ms = 80,
        .connect_established = &established,
    }));
    try std.testing.expect(established); // A connected request must not replay on AAAA.
    try server.spawn();
    try std.testing.expectError(error.ResponseTooLarge, get(a, "127.0.0.1", server.port, false, request, .{ .max_response_bytes = 32 }));
    const response = try get(a, "127.0.0.1", server.port, false, request, .{});
    defer a.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, response, "windows_fetch_probe 1\n"));
    const pinned = try net.IpAddress.parse("127.0.0.1", server.port);
    const bypasses_dns = try getAtAddress(a, "onyx-address-pin.invalid.", server.port, false, request, pinned, .{});
    defer a.free(bypasses_dns);
    try std.testing.expect(std.mem.startsWith(u8, bypasses_dns, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expectError(error.ConnectFailed, getAtAddress(a, "onyx-address-pin.invalid.", server.port - 1, false, request, pinned, .{}));
}

test "http_fetch Windows IPv6 pinned and literal loopback HTTP" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.TestUnexpectedResult;
    defer _ = win.WSACleanup();
    const listener = win.WSASocketW(win.af_inet6, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (listener == win.invalid_socket) return error.TestUnexpectedResult;
    defer _ = win.closesocket(listener);
    var address = win.SockAddr6{ .family = win.af_inet6, .port = 0, .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    if (win.bind(listener, &address, @sizeOf(win.SockAddr6)) != 0 or win.listen(listener, 2) != 0)
        return error.TestUnexpectedResult;
    var address_len: i32 = @sizeOf(win.SockAddr6);
    if (win.getsockname(listener, &address, &address_len) != 0 or address_len != @sizeOf(win.SockAddr6))
        return error.TestUnexpectedResult;
    const port = std.mem.bigToNative(u16, address.port);
    const Worker = struct {
        listener: usize,
        port: u16,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.failure = err;
            };
        }

        fn serve(self: *@This()) !void {
            for (0..4) |index| {
                var reads = win.FdSet{ .count = 1, .sockets = undefined };
                reads.sockets[0] = self.listener;
                var timeout = win.Timeval{ .seconds = 3, .microseconds = 0 };
                if (win.select(0, &reads, null, null, &timeout) != 1) return error.TestUnexpectedResult;
                const client = win.accept(self.listener, null, null);
                if (client == win.invalid_socket) return error.TestUnexpectedResult;
                {
                    defer _ = win.closesocket(client);
                    try setRecvTimeout(client, 2000);
                    var request: [512]u8 = undefined;
                    var size: usize = 0;
                    while (std.mem.indexOf(u8, request[0..size], "\r\n\r\n") == null) {
                        if (size == request.len) return error.TestUnexpectedResult;
                        size += try readSome(client, request[size..]);
                    }
                    if (index == 3) {
                        var host_header_buf: [80]u8 = undefined;
                        const host_header = try std.fmt.bufPrint(&host_header_buf, "Host: onyx-address-pin.invalid.:{d}\r\n", .{self.port});
                        if (!std.mem.startsWith(u8, request[0..size], "POST /signed HTTP/1.1\r\n") or
                            std.mem.indexOf(u8, request[0..size], "X-Onyx-Signature: sha256=test") == null or
                            std.mem.indexOf(u8, request[0..size], host_header) == null)
                            return error.TestUnexpectedResult;
                    } else if (!std.mem.startsWith(u8, request[0..size], "GET /ipv6 HTTP/1.1\r\n")) {
                        return error.TestUnexpectedResult;
                    }
                    try writeAll(client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                }
            }
        }
    };
    var worker = Worker{ .listener = listener, .port = port };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const request = "GET /ipv6 HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n";
    const pinned = try net.IpAddress.parse("::1", port);
    const first = try getAtAddress(std.testing.allocator, "localhost", port, false, request, pinned, .{});
    defer std.testing.allocator.free(first);
    try std.testing.expect(std.mem.endsWith(u8, first, "\r\n\r\nOK"));
    const second = try get(std.testing.allocator, "::1", port, false, request, .{});
    defer std.testing.allocator.free(second);
    try std.testing.expect(std.mem.endsWith(u8, second, "\r\n\r\nOK"));
    // localhost has an A answer, but only the IPv6 listener is open. The
    // failed IPv4 dial must fall through to the AAAA address before any send.
    var established = false;
    const third = try get(std.testing.allocator, "localhost", port, false, request, .{
        .connect_established = &established,
        .connect_timeout_ms = 250,
    });
    defer std.testing.allocator.free(third);
    try std.testing.expect(established);
    try std.testing.expect(std.mem.endsWith(u8, third, "\r\n\r\nOK"));
    const signed = try postSignedAtAddress(std.testing.allocator, .{
        .tls = false,
        .host = "onyx-address-pin.invalid.",
        .port = port,
        .path = "/signed",
    }, "{}", "sha256=test", pinned, .{});
    defer std.testing.allocator.free(signed);
    try std.testing.expect(std.mem.endsWith(u8, signed, "\r\n\r\nOK"));
    thread.join();
    joined = true;
    if (worker.failure) |err| return err;
}

test "http_fetch Windows HTTPS loopback verifies trusted anchor and rejects untrusted anchor" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("metrics_http.zig");
    const selfsign = @import("../proto/x509_selfsign.zig");
    const tls_server = @import("../crypto/tls_server.zig");
    const a = std.testing.allocator;
    var snapshot = metrics.MetricsSnapshot.init(a);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();

    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x67));
    var cert_buffer: [2048]u8 = undefined;
    const cert = try selfsign.buildSelfSigned(&cert_buffer, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x67, 1 },
        .key_pair = kp,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    const Worker = struct {
        listener: usize,
        chain: []const []const u8,
        key_pair: std.crypto.sign.Ed25519.KeyPair,
        expect_http: bool,
        request_seen: bool = false,
        alert_seen: bool = false,
        fallback_seen: bool = false,
        failure: ?anyerror = null,

        fn readable(fd: usize, timeout_ms: u32) !bool {
            var reads = win.FdSet{ .count = 1, .sockets = undefined };
            reads.sockets[0] = fd;
            var timeout = win.Timeval{ .seconds = @intCast(timeout_ms / 1000), .microseconds = @intCast((timeout_ms % 1000) * 1000) };
            const rc = win.select(0, &reads, null, null, &timeout);
            if (rc < 0) return error.TestUnexpectedResult;
            return rc > 0;
        }

        fn readExact(fd: usize, bytes: []u8) !void {
            var offset: usize = 0;
            while (offset < bytes.len) {
                offset += try readSome(fd, bytes[offset..]);
            }
        }

        fn record(fd: usize, buffer: []u8) ![]u8 {
            try readExact(fd, buffer[0..5]);
            const len = 5 + @as(usize, std.mem.readInt(u16, buffer[3..5], .big));
            if (len > buffer.len) return error.TestUnexpectedResult;
            try readExact(fd, buffer[5..len]);
            return buffer[0..len];
        }

        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.failure = err;
            };
        }

        fn exchange(self: *@This()) !void {
            if (!try readable(self.listener, 2000)) return error.TestUnexpectedResult;
            const fd = win.accept(self.listener, null, null);
            if (fd == win.invalid_socket) return error.TestUnexpectedResult;
            defer closeFd(fd);
            var blocking: u32 = 0;
            if (win.ioctlsocket(fd, win.fionbio, &blocking) != 0) return error.TestUnexpectedResult;
            try setRecvTimeout(fd, 2000);

            var engine = try tls_server.Server.init(std.heap.page_allocator, .{
                .cert_chain = self.chain,
                .signing_key = self.key_pair,
            });
            defer engine.deinit();
            var buffer: [max_tls_record]u8 = undefined;
            while (!engine.handshakeDone()) {
                switch (try engine.feed(try record(fd, &buffer))) {
                    .bytes_to_send => |bytes| {
                        defer std.heap.page_allocator.free(bytes);
                        try writeAll(fd, bytes);
                    },
                    .need_more => {},
                }
                if (!self.expect_http) {
                    // The client must reject the unknown anchor before an HTTP
                    // request. Drain its fatal alert, then check for a fallback.
                    try std.testing.expectError(error.TlsAlert, engine.feed(try record(fd, &buffer)));
                    self.alert_seen = true;
                    self.fallback_seen = try readable(self.listener, 250);
                    return;
                }
            }
            const request = try engine.decrypt(try record(fd, &buffer));
            defer std.heap.page_allocator.free(request);
            self.request_seen = std.mem.startsWith(u8, request, "GET /trusted HTTP/1.1\r\n");
            const response = try engine.encrypt("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            defer std.heap.page_allocator.free(response);
            try writeAll(fd, response);
        }
    };

    const request = "GET /trusted HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    var trusted_worker = Worker{ .listener = listener.listen_fd, .chain = &chain, .key_pair = kp, .expect_http = true };
    const trusted_thread = try std.Thread.spawn(.{}, Worker.run, .{&trusted_worker});
    var trusted_joined = false;
    defer if (!trusted_joined) trusted_thread.join();
    const trusted = get(a, "127.0.0.1", listener.port, true, request, .{ .trust_anchors = &chain, .recv_timeout_ms = 2000 });
    defer if (trusted) |response| a.free(response) else |_| {};
    trusted_thread.join();
    trusted_joined = true;
    if (trusted_worker.failure) |err| return err;
    try std.testing.expect(trusted_worker.request_seen);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", try trusted);

    var untrusted_worker = Worker{ .listener = listener.listen_fd, .chain = &chain, .key_pair = kp, .expect_http = false };
    const untrusted_thread = try std.Thread.spawn(.{}, Worker.run, .{&untrusted_worker});
    var untrusted_joined = false;
    defer if (!untrusted_joined) untrusted_thread.join();
    const untrusted = get(a, "127.0.0.1", listener.port, true, request, .{ .recv_timeout_ms = 2000 });
    defer if (untrusted) |response| a.free(response) else |_| {};
    untrusted_thread.join();
    untrusted_joined = true;
    if (untrusted_worker.failure) |err| return err;
    try std.testing.expectError(error.UnknownCa, untrusted);
    try std.testing.expect(untrusted_worker.alert_seen and !untrusted_worker.request_seen and !untrusted_worker.fallback_seen);

    // A pinned IPv6 connection must keep the hostname for SNI and certificate
    // verification, exactly as the IPv4 path does.
    const listener6 = win.WSASocketW(win.af_inet6, win.sock_stream, win.ipproto_tcp, null, 0, 1);
    if (listener6 == win.invalid_socket) return error.TestUnexpectedResult;
    defer _ = win.closesocket(listener6);
    var address6 = win.SockAddr6{ .family = win.af_inet6, .port = 0, .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    if (win.bind(listener6, &address6, @sizeOf(win.SockAddr6)) != 0 or win.listen(listener6, 1) != 0)
        return error.TestUnexpectedResult;
    var address6_len: i32 = @sizeOf(win.SockAddr6);
    if (win.getsockname(listener6, &address6, &address6_len) != 0 or address6_len != @sizeOf(win.SockAddr6))
        return error.TestUnexpectedResult;
    const port6 = std.mem.bigToNative(u16, address6.port);
    var cert_buffer6: [2048]u8 = undefined;
    const cert6 = try selfsign.buildSelfSigned(&cert_buffer6, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x67, 6 },
        .key_pair = kp,
        .dns_names = &.{"localhost"},
        .is_ca = true,
    });
    const chain6 = [_][]const u8{cert6};
    var ipv6_worker = Worker{ .listener = listener6, .chain = &chain6, .key_pair = kp, .expect_http = true };
    const ipv6_thread = try std.Thread.spawn(.{}, Worker.run, .{&ipv6_worker});
    var ipv6_joined = false;
    defer if (!ipv6_joined) ipv6_thread.join();
    const pinned6 = try net.IpAddress.parse("::1", port6);
    const request6 = "GET /trusted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const ipv6_response = getAtAddress(a, "localhost", port6, true, request6, pinned6, .{ .trust_anchors = &chain6, .recv_timeout_ms = 2000 });
    defer if (ipv6_response) |response| a.free(response) else |_| {};
    ipv6_thread.join();
    ipv6_joined = true;
    if (ipv6_worker.failure) |err| return err;
    try std.testing.expect(ipv6_worker.request_seen);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", try ipv6_response);
}

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

test "http_fetch native loopback request timeout entropy and descriptor failure" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const metrics = @import("metrics_http.zig");
    var snapshot = metrics.MetricsSnapshot.init(std.testing.allocator);
    defer snapshot.deinit();
    try snapshot.set("native_worker_probe 1\n");
    var server = try metrics.MetricsServer.init(&snapshot, 0);
    defer server.shutdown();
    const request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    // An open TCP backlog with no HTTP worker must fail within receive timeout.
    try std.testing.expectError(error.RecvTimeout, get(std.testing.allocator, "127.0.0.1", server.port, false, request, .{ .recv_timeout_ms = 40 }));
    try server.spawn();
    const response = try get(std.testing.allocator, "127.0.0.1", server.port, false, request, .{});
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, response, "native_worker_probe 1\n"));
    var random: [32]u8 = @splat(0);
    osEntropy(&random);
    try std.testing.expect(!std.mem.allEqual(u8, &random, 0));
    try std.testing.expect(wallClockSeconds() > 1_700_000_000);
    var empty: [1]u8 = undefined;
    try std.testing.expectError(error.NoNameservers, readSmallFile("/definitely-missing-onyx-resolver", &empty));
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expectError(error.RecvTimeout, setRecvTimeout(-1, 1));
        try std.testing.expectError(error.ConnectFailed, setBlocking(-1));
    }
}

test "http_fetch Linux IPv6 pinned loopback HTTP" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const listener_rc = sys.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    if (posix.errno(listener_rc) != .SUCCESS) return error.SkipZigTest;
    const listener: sys.fd_t = @intCast(listener_rc);
    defer closeFd(listener);
    var loopback: [16]u8 = @splat(0);
    loopback[15] = 1;
    var address = posix.sockaddr.in6{ .port = 0, .addr = loopback, .flowinfo = 0, .scope_id = 0 };
    if (posix.errno(sys.bind(listener, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS or
        posix.errno(sys.listen(listener, 1)) != .SUCCESS) return error.SkipZigTest;
    var address_len: posix.socklen_t = @sizeOf(@TypeOf(address));
    if (posix.errno(sys.getsockname(listener, @ptrCast(&address), &address_len)) != .SUCCESS) return error.TestUnexpectedResult;
    const port = std.mem.bigToNative(u16, address.port);
    const Worker = struct {
        listener: sys.fd_t,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.failure = err;
            };
        }

        fn serve(self: *@This()) !void {
            var polls = [_]posix.pollfd{.{ .fd = self.listener, .events = posix.POLL.IN, .revents = 0 }};
            if (posix.errno(sys.poll(&polls, 1, 3000)) != .SUCCESS or polls[0].revents & posix.POLL.IN == 0)
                return error.TestUnexpectedResult;
            const client_rc = sys.accept(self.listener, null, null);
            if (posix.errno(client_rc) != .SUCCESS) return error.TestUnexpectedResult;
            const client: sys.fd_t = @intCast(client_rc);
            defer closeFd(client);
            var request: [256]u8 = undefined;
            var size: usize = 0;
            while (std.mem.indexOf(u8, request[0..size], "\r\n\r\n") == null) {
                if (size == request.len) return error.TestUnexpectedResult;
                const n = sys.read(client, request[size..].ptr, request.len - size);
                if (posix.errno(n) != .SUCCESS or n == 0) return error.TestUnexpectedResult;
                size += @intCast(n);
            }
            if (!std.mem.startsWith(u8, request[0..size], "GET /ipv6 HTTP/1.1\r\n"))
                return error.TestUnexpectedResult;
            const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
            try writeAll(client, response);
        }
    };
    var worker = Worker{ .listener = listener };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const pinned = try net.IpAddress.parse("::1", port);
    const request = "GET /ipv6 HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n";
    const response = try getAtAddress(std.testing.allocator, "[::1]", port, false, request, pinned, .{});
    defer std.testing.allocator.free(response);
    thread.join();
    joined = true;
    if (worker.failure) |err| return err;
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nOK"));
}

test "http_fetch native DNS UDP transport binds replies to query identity" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const Worker = struct {
        fd: posix.fd_t,
        response: []const u8,
        ok: bool = false,
        fn run(self: *@This()) void {
            var bytes: [512]u8 = undefined;
            var addr: posix.sockaddr.storage = undefined;
            var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
            const got = sys.recvfrom(self.fd, &bytes, bytes.len, 0, @ptrCast(&addr), &len);
            if (posix.errno(got) != .SUCCESS) return;
            const sent = sys.sendto(self.fd, self.response.ptr, self.response.len, 0, @ptrCast(&addr), len);
            self.ok = posix.errno(sent) == .SUCCESS and sent == self.response.len;
        }
    };
    const q = dns.Query{ .name = "native-worker.test", .qtype = .a };
    const answer = dns.Answer{ .name = "canonical-worker.test", .rr_type = .a, .ttl = 5, .data = .{ .a = .{ 127, 0, 0, 7 } } };
    var query_buf: [512]u8 = undefined;
    const query = try dns.encodeQuery(&query_buf, 0x8712, q.name, .a);
    for (0..4) |mode| {
        const wrong_id = mode == 1;
        const canonical = mode >= 2;
        const fd = try udpSocket();
        defer closeFd(fd);
        try setRecvTimeout(fd, 1000);
        var addr = sys.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))));
        var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&addr), &len)));
        var response_buf: [512]u8 = undefined;
        var selected = answer;
        if (!canonical) selected.name = q.name;
        const encoded = try dns.encodeMessage(&response_buf, .{ .id = if (wrong_id) 0x8713 else 0x8712, .response = true, .questions = &.{q}, .answers = &.{selected} });
        var response_len = encoded.len;
        if (mode == 2) {
            var target_buf: [128]u8 = undefined;
            const target = try dns.encodeQuery(&target_buf, 0, answer.name, .a);
            const owner_wire = query[12 .. query.len - 4];
            const target_wire = target[12 .. target.len - 4];
            @memcpy(response_buf[response_len..][0..owner_wire.len], owner_wire);
            response_len += owner_wire.len;
            const header = response_buf[response_len..][0..10];
            std.mem.writeInt(u16, header[0..2], 5, .big);
            std.mem.writeInt(u16, header[2..4], dns.class_in, .big);
            std.mem.writeInt(u32, header[4..8], 5, .big);
            std.mem.writeInt(u16, header[8..10], @intCast(target_wire.len), .big);
            response_len += 10;
            @memcpy(response_buf[response_len..][0..target_wire.len], target_wire);
            response_len += target_wire.len;
            std.mem.writeInt(u16, response_buf[6..8], 2, .big);
        }
        var worker = Worker{ .fd = fd, .response = response_buf[0..response_len] };
        const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
        var joined = false;
        defer if (!joined) thread.join();
        if (wrong_id or mode == 3) {
            try std.testing.expectError(error.HostNotFound, queryServerPort(.{ 127, 0, 0, 1 }, std.mem.bigToNative(u16, addr.port), query, 100));
        } else {
            const msg = try queryServerPort(.{ 127, 0, 0, 1 }, std.mem.bigToNative(u16, addr.port), query, 100);
            try std.testing.expectEqual([4]u8{ 127, 0, 0, 7 }, msg.answers[0].data.a);
        }
        thread.join();
        joined = true;
        try std.testing.expect(worker.ok);
    }
}

test "TLS client fatal transport: http_fetch socket writer preserves control custody" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try tls_client_failure.testFatalTransportProof(true, writeAll);
}

test "TLS client fatal transport: http_fetch Windows socket writer preserves control custody" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const Callback = struct {
        fn send(fd: usize, client: *tls_client.Client, failure: tls_client.Error) void {
            sendFatal(fd, client, failure);
        }
    };
    try tls_client_failure.testWindowsFatalTransportProof(true, Callback.send);
}

test "TLS client fatal transport: HTTP POST response failure never opens a fallback connection" {
    // Live listener plus raw-fd writes; Windows HANDLEs cannot compile it.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    const runtime = @import("os_runtime.zig");
    const metrics = @import("metrics_http.zig");
    const tls_server = @import("../crypto/tls_server.zig");
    var snapshot = metrics.MetricsSnapshot.init(a);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();
    const peer = try tls_client_failure.TestPeer.init(a);
    defer peer.deinit();
    peer.server.deinit();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x7c));
    peer.server = try tls_server.Server.init(a, .{ .cert_chain = &peer.chain, .signing_key = kp });
    const Worker = struct {
        listener: i32,
        peer: *tls_client_failure.TestPeer,
        request_seen: bool = false,
        alert_seen: bool = false,
        fallback_seen: bool = false,
        failure: ?anyerror = null,

        fn readable(fd: i32, ms: i32) !bool {
            var polls = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
            const rc = sys.poll(&polls, 1, ms);
            if (posix.errno(rc) != .SUCCESS) return error.TestUnexpectedResult;
            return rc > 0;
        }

        fn record(fd: i32, buffer: []u8) ![]u8 {
            try tls_client_failure.testReadExact(fd, buffer[0..5]);
            const n = 5 + @as(usize, std.mem.readInt(u16, buffer[3..5], .big));
            if (n > buffer.len) return error.TestUnexpectedResult;
            try tls_client_failure.testReadExact(fd, buffer[5..n]);
            return buffer[0..n];
        }

        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.failure = err;
            };
        }

        fn exchange(self: *@This()) !void {
            if (!try readable(self.listener, 2000)) return error.TestUnexpectedResult;
            const rc = sys.accept(self.listener, null, null);
            if (posix.errno(rc) != .SUCCESS) return error.TestUnexpectedResult;
            const fd: i32 = @intCast(rc);
            defer runtime.close(fd);
            try setBlocking(fd);
            try setRecvTimeout(fd, 1000);
            var buffer: [max_tls_record]u8 = undefined;
            const engine = &self.peer.server;
            while (!engine.handshakeDone()) {
                switch (try engine.feed(try record(fd, &buffer))) {
                    .bytes_to_send => |bytes| {
                        defer std.testing.allocator.free(bytes);
                        try writeAll(fd, bytes);
                    },
                    .need_more => {},
                }
            }
            const request = try engine.decrypt(try record(fd, &buffer));
            defer std.testing.allocator.free(request);
            self.request_seen = std.mem.startsWith(u8, request, "POST /once HTTP/1.1\r\n") and std.mem.endsWith(u8, request, "once");
            const malformed = try engine.encrypt("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            defer std.testing.allocator.free(malformed);
            malformed[malformed.len - 1] ^= 1; // authenticated response must fail
            try writeAll(fd, malformed);
            const alert = try record(fd, &buffer);
            try tls_client_failure.testExpectAlert(engine, alert, 20);
            self.alert_seen = true;
            self.fallback_seen = try readable(self.listener, 250);
        }
    };
    var worker = Worker{ .listener = listener.listen_fd, .peer = peer };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const request = "POST /once HTTP/1.1\r\nHost: irc.test\r\nContent-Length: 4\r\n\r\nonce";
    const result = get(a, "127.0.0.1", listener.port, true, request, .{ .insecure_skip_verify = true, .recv_timeout_ms = 1000 });
    defer if (result) |bytes| a.free(bytes) else |_| {};
    thread.join();
    joined = true;
    if (worker.failure) |err| return err;
    try std.testing.expectError(error.RecordAuthenticationFailed, result);
    try std.testing.expect(worker.request_seen and worker.alert_seen);
    try std.testing.expect(!worker.fallback_seen);
}
