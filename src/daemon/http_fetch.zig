// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blocking, thread-safe outbound HTTP/1.1 GET (plain + TLS 1.3), for the
//! geo_services background fetcher thread.
//!
//! It is deliberately self-contained and does NOT touch the reactor's io_uring
//! `Io` (which is not safe to share across threads): DNS, connect, and socket
//! I/O are raw `linux`/`posix` syscalls, and `/etc/resolv.conf` is read with a
//! blocking `open`/`read`. Connect and receive are bounded by timeouts so a
//! stalled upstream can never wedge the fetcher thread.
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

pub const Error = error{
    BadUrl,
    NoNameservers,
    HostNotFound,
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
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |c| {
        // Guard against an IPv6 literal (not supported upstream anyway).
        if (std.mem.indexOfScalar(u8, authority, ']') == null) {
            host = authority[0..c];
            port = std.fmt.parseInt(u16, authority[c + 1 ..], 10) catch return error.BadUrl;
        }
    }
    return .{ .tls = tls, .host = host, .port = port, .path = path };
}

pub const Options = struct {
    /// Trust anchors (DER certs) for TLS verification; required when `url.tls`
    /// unless `insecure_skip_verify` is set.
    trust_anchors: []const []const u8 = &.{},
    /// Skip server-certificate verification (TLS transport only). Intended as a
    /// documented escape hatch for public read-only feeds when a usable system
    /// CA bundle is unavailable; off by default.
    insecure_skip_verify: bool = false,
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
    if (comptime builtin.os.tag == .windows) return error.SocketUnavailable;
    const addr = try resolveHostA(host, port, opts.recv_timeout_ms);

    if (!tls) {
        const fd = try connectAddr(addr, opts.connect_timeout_ms);
        defer closeFd(fd);
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
        try setRecvTimeout(fd, opts.recv_timeout_ms);
        var application_phase = false;
        if (getTls(allocator, fd, host, request_bytes, opts, &application_phase)) |resp| {
            return resp;
        } else |err| {
            if (application_phase or err == error.ResponseTooLarge) return err;
        }
    }
    const fd2 = try connectAddr(addr, opts.connect_timeout_ms);
    defer closeFd(fd2);
    try setRecvTimeout(fd2, opts.recv_timeout_ms);
    return try getTls12(allocator, fd2, host, request_bytes, opts);
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
    return postWithHeaders(allocator, url, &headers, body, opts);
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
    return postWithHeaders(allocator, url, &headers, body, opts);
}

fn postWithHeaders(
    allocator: std.mem.Allocator,
    url: Url,
    headers: []const http1.Header,
    body: []const u8,
    opts: Options,
) Error![]u8 {
    // buildRequest writes method/path/Host + each header + Content-Length + body.
    var extra: usize = url.host.len + url.path.len + 256;
    for (headers) |h| extra += h.name.len + h.value.len + 4;
    const cap = std.math.add(usize, body.len, extra) catch return error.ResponseTooLarge;
    const req_buf = try allocator.alloc(u8, cap);
    defer allocator.free(req_buf);
    const request_bytes = http1.buildRequest(req_buf, "POST", url.host, url.path, headers, body) catch
        return error.ResponseTooLarge;
    return get(allocator, url.host, url.port, url.tls, request_bytes, opts);
}

/// TLS 1.2 variant of `getTls` (hardened `tls12_client`). Used as the fallback
/// when the TLS 1.3 handshake fails — broadens outbound reach to TLS-1.2-only
/// hosts. Mirrors `getTls` but uses the 1.2 client's `decrypt` (no KeyUpdate).
fn getTls12(
    allocator: std.mem.Allocator,
    fd: sys.fd_t,
    host: []const u8,
    request_bytes: []const u8,
    opts: Options,
) Error![]u8 {
    var tc = try tls12_client.Client.init(allocator, .{
        .server_name = host,
        .trust_anchors = opts.trust_anchors,
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
            tls_client_failure.sendFatal(fd, &tc, err);
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
                    tls_client_failure.sendFatal(fd, &tc, err);
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
    fd: sys.fd_t,
    host: []const u8,
    request_bytes: []const u8,
    opts: Options,
    application_phase: *bool,
) Error![]u8 {
    var tc = try tls_client.Client.init(allocator, .{
        .server_name = host,
        .trust_anchors = opts.trust_anchors,
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
            tls_client_failure.sendFatal(fd, &tc, err);
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
                    tls_client_failure.sendFatal(fd, &tc, err);
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

fn readHttp(allocator: std.mem.Allocator, fd: sys.fd_t, max_bytes: usize) Error![]u8 {
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

/// Wall-clock time in Unix seconds, used to reject expired server certificates.
fn wallClockSeconds() i64 {
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

/// Resolve `host` to an address: IP literals parse directly; otherwise a
/// blocking A-record query against the system resolvers, bounded by
/// `timeout_ms` per nameserver. Public so the daemon's mesh auto-connect can
/// dial configured "host:port" peers by name (same blocking-DNS contract).
pub fn resolveHostA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| return addr else |_| {}
    if (comptime builtin.os.tag == .windows) return error.NoNameservers;

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

/// Like `resolveHostA` but queries AAAA records, returning an IPv6 address.
/// Used by the mesh dial path so a v6-only peer resolves; the query travels over
/// the (IPv4) system resolvers exactly like the A path.
pub fn resolveHostAAAA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| switch (addr) {
        .ip6 => return addr,
        .ip4 => {}, // an IPv4 literal is not an AAAA answer — fall through to DNS
    } else |_| {}
    if (comptime builtin.os.tag == .windows) return error.NoNameservers;

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

fn queryOneServer6(ns_v4: [4]u8, query: []const u8, timeout_ms: u31) Error![16]u8 {
    const msg = try queryServerPort(ns_v4, 53, query, timeout_ms);
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .aaaa => |ipv6| return ipv6,
        else => {},
    };
    return error.HostNotFound;
}

// ---- raw socket helpers (mirror acme_runner / server idiom) ------------------

fn connectAddr(addr: net.IpAddress, timeout_ms: u31) Error!sys.fd_t {
    const a4 = switch (addr) {
        .ip4 => |x| x,
        .ip6 => return error.ConnectFailed,
    };
    const fd = try socketTcpNonblock();
    errdefer closeFd(fd);
    var sa = sys.sockaddr.in{ .port = std.mem.nativeToBig(u16, a4.port), .addr = @bitCast(a4.bytes) };
    const rc = sys.connect(fd, @ptrCast(&sa), @sizeOf(sys.sockaddr.in));
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

fn socketTcpNonblock() Error!sys.fd_t {
    const rc = sys.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
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

fn setRecvTimeout(fd: sys.fd_t, timeout_ms: u31) Error!void {
    const finite_ms = if (builtin.os.tag == .linux) timeout_ms else @max(timeout_ms, 1);
    const tv = sys.timeval{ .sec = @intCast(finite_ms / 1000), .usec = @intCast((finite_ms % 1000) * 1000) };
    const recv_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(sys.timeval));
    const send_rc = sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, @ptrCast(&tv), @sizeOf(sys.timeval));
    if (comptime builtin.os.tag != .linux) {
        if (posix.errno(recv_rc) != .SUCCESS or posix.errno(send_rc) != .SUCCESS) return error.RecvTimeout;
    }
}

fn closeFd(fd: sys.fd_t) void {
    _ = sys.close(fd);
}

fn writeAll(fd: sys.fd_t, bytes: []const u8) Error!void {
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

fn readSome(fd: sys.fd_t, buf: []u8) Error!usize {
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

    try std.testing.expectError(error.BadUrl, parseUrl("ftp://nope"));
}

test "http_fetch Options default CT and CRL policy is fail-open" {
    const opts = Options{};
    try std.testing.expectEqual(@as(usize, 0), opts.ct_logs.len);
    try std.testing.expect(!opts.enforce_sct);
    try std.testing.expectEqual(@as(u8, 0), opts.require_sct);
    try std.testing.expect(opts.crl == null);
    try std.testing.expect(!opts.require_crl);
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
