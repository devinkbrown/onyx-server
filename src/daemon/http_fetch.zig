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
const linux = std.os.linux;
const posix = std.posix;
const dns = @import("../proto/dns.zig");
const resolv_conf = @import("../proto/resolv_conf.zig");
const tls_client = @import("../crypto/tls_client.zig");
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
    const addr = try resolveHostA(host, port, opts.recv_timeout_ms);

    if (!tls) {
        const fd = try connectAddr(addr, opts.connect_timeout_ms);
        defer closeFd(fd);
        setRecvTimeout(fd, opts.recv_timeout_ms);
        try writeAll(fd, request_bytes);
        return try readHttp(allocator, fd, opts.max_response_bytes);
    }

    // Try TLS 1.3 first (the preferred client). Many RSS/CDN hosts still serve
    // TLS 1.2 only (or trip the 1.3 client), so on any handshake/transport
    // failure fall back to the hardened TLS 1.2 client on a *fresh* connection
    // (the failed handshake consumed the first socket). `ResponseTooLarge` means
    // 1.3 actually worked — don't retry that.
    {
        const fd = try connectAddr(addr, opts.connect_timeout_ms);
        defer closeFd(fd);
        setRecvTimeout(fd, opts.recv_timeout_ms);
        if (getTls(allocator, fd, host, request_bytes, opts)) |resp| {
            return resp;
        } else |err| switch (err) {
            error.ResponseTooLarge => return err,
            else => {},
        }
    }
    const fd2 = try connectAddr(addr, opts.connect_timeout_ms);
    defer closeFd(fd2);
    setRecvTimeout(fd2, opts.recv_timeout_ms);
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
    // buildRequest writes method/path/Host + each header + Content-Length + body.
    // 256 bytes covers the fixed framing and the three short headers above.
    const cap = body.len + url.host.len + url.path.len + content_type.len + 256;
    const req_buf = try allocator.alloc(u8, cap);
    defer allocator.free(req_buf);
    const request_bytes = http1.buildRequest(req_buf, "POST", url.host, url.path, &headers, body) catch
        return error.ResponseTooLarge;
    return get(allocator, url.host, url.port, url.tls, request_bytes, opts);
}

/// TLS 1.2 variant of `getTls` (hardened `tls12_client`). Used as the fallback
/// when the TLS 1.3 handshake fails — broadens outbound reach to TLS-1.2-only
/// hosts. Mirrors `getTls` but uses the 1.2 client's `decrypt` (no KeyUpdate).
fn getTls12(
    allocator: std.mem.Allocator,
    fd: linux.fd_t,
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
        switch (try tc.feed(read_buf[0..n])) {
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
                else => return err,
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
    fd: linux.fd_t,
    host: []const u8,
    request_bytes: []const u8,
    opts: Options,
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
        switch (try tc.feed(read_buf[0..n])) {
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
            const read = tc.decryptApp(rec) catch |err| switch (err) {
                error.TlsAlert => break :read_loop, // close_notify ends the stream
                else => return err,
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

fn readHttp(allocator: std.mem.Allocator, fd: linux.fd_t, max_bytes: usize) Error![]u8 {
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
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
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
    const fd = try udpSocket();
    defer closeFd(fd);
    setRecvTimeout(fd, timeout_ms);
    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, 53), .addr = @bitCast(ns_v4) };
    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.ConnectFailed;
    if (posix.errno(linux.write(fd, query.ptr, query.len)) != .SUCCESS) return error.ConnectFailed;

    var resp: [dns.max_message_len]u8 = undefined;
    const rc = linux.read(fd, &resp, resp.len);
    if (posix.errno(rc) != .SUCCESS) return error.HostNotFound;
    const n: usize = @intCast(rc);
    const msg = dns.parseMessage(1, dns.max_cache_addrs, resp[0..n]) catch return error.HostNotFound;
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .a => |ipv4| return ipv4,
        else => {},
    };
    return error.HostNotFound;
}

/// Like `resolveHostA` but queries AAAA records, returning an IPv6 address.
/// Used by the mesh dial path so a v6-only peer resolves; the query travels over
/// the (IPv4) system resolvers exactly like the A path.
pub fn resolveHostAAAA(host: []const u8, port: u16, timeout_ms: u31) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |addr| switch (addr) {
        .ip6 => return addr,
        .ip4 => {}, // an IPv4 literal is not an AAAA answer — fall through to DNS
    } else |_| {}

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
    const fd = try udpSocket();
    defer closeFd(fd);
    setRecvTimeout(fd, timeout_ms);
    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, 53), .addr = @bitCast(ns_v4) };
    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.ConnectFailed;
    if (posix.errno(linux.write(fd, query.ptr, query.len)) != .SUCCESS) return error.ConnectFailed;

    var resp: [dns.max_message_len]u8 = undefined;
    const rc = linux.read(fd, &resp, resp.len);
    if (posix.errno(rc) != .SUCCESS) return error.HostNotFound;
    const n: usize = @intCast(rc);
    const msg = dns.parseMessage(1, dns.max_cache_addrs, resp[0..n]) catch return error.HostNotFound;
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .aaaa => |ipv6| return ipv6,
        else => {},
    };
    return error.HostNotFound;
}

// ---- raw socket helpers (mirror acme_runner / server idiom) ------------------

fn connectAddr(addr: net.IpAddress, timeout_ms: u31) Error!linux.fd_t {
    const a4 = switch (addr) {
        .ip4 => |x| x,
        .ip6 => return error.ConnectFailed,
    };
    const fd = try socketTcpNonblock();
    errdefer closeFd(fd);
    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, a4.port), .addr = @bitCast(a4.bytes) };
    const rc = linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => try waitWritable(fd, timeout_ms),
        else => return error.ConnectFailed,
    }
    // Confirm the connect succeeded (SO_ERROR == 0).
    var err_val: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    if (posix.errno(linux.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err_val), &err_len)) != .SUCCESS)
        return error.ConnectFailed;
    if (err_val != 0) return error.ConnectFailed;
    setBlocking(fd);
    return fd;
}

fn waitWritable(fd: linux.fd_t, timeout_ms: u31) Error!void {
    // linux.pollfd/POLL/SOCK.* (not posix.*): these pair with the raw linux
    // syscalls; posix.* resolves to libc/ws2_32 on non-Linux (build-time only).
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    const rc = linux.poll(&pfd, 1, timeout_ms);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.ConnectFailed,
    }
    if (rc == 0) return error.ConnectTimeout;
    if (pfd[0].revents & (linux.POLL.ERR | linux.POLL.HUP) != 0) return error.ConnectFailed;
}

fn socketTcpNonblock() Error!linux.fd_t {
    const rc = linux.socket(posix.AF.INET, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn udpSocket() Error!linux.fd_t {
    const rc = linux.socket(posix.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, linux.IPPROTO.UDP);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.SocketUnavailable,
    };
}

fn setBlocking(fd: linux.fd_t) void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    _ = linux.fcntl(fd, linux.F.SETFL, flags & ~@as(usize, linux.SOCK.NONBLOCK));
}

fn setRecvTimeout(fd: linux.fd_t, timeout_ms: u31) void {
    const tv = linux.timeval{ .sec = @divTrunc(timeout_ms, 1000), .usec = @as(i64, @intCast(timeout_ms % 1000)) * 1000 };
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
}

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
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

fn readSome(fd: linux.fd_t, buf: []u8) Error!usize {
    while (true) {
        const rc = linux.read(fd, buf.ptr, buf.len);
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
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    if (posix.errno(rc) != .SUCCESS) return error.NoNameservers;
    const fd: linux.fd_t = @intCast(rc);
    defer closeFd(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const r = linux.read(fd, buf[total..].ptr, buf.len - total);
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
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
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
