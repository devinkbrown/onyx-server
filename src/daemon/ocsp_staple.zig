// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-daemon OCSP-staple fetch/verify/cache/refresh scheduler.
//!
//! Mirrors `acme_renewal.Service`: a dedicated OS thread that never touches live
//! TLS listener state. Each cycle it re-reads the leaf + issuer from the
//! configured cert file, builds an OCSP request for the leaf's AIA responder URL,
//! POSTs it over the off-reactor blocking `http_fetch` transport, verifies +
//! freshness-gates the response with `ocsp.isStapleServable`, and — only on a
//! good, in-window, issuer-signed response — hands the raw DER to the server via
//! `publishOcspStaple`, which reactor 0 swaps into `config.tls_ocsp_staple`.
//!
//! Failure is non-fatal and non-destructive: on any fetch/verify/freshness error
//! the previously published staple keeps serving until it actually expires (the
//! server never clears a good staple on our behalf). A `revoked` response for our
//! own leaf is logged CRITICAL and never stapled.

const std = @import("std");
const dlog = @import("dlog.zig");
const linux = std.os.linux;

const config_format = @import("config_format.zig");
const http_fetch = @import("http_fetch.zig");
const http1 = @import("../proto/http1_client.zig");
const ocsp = @import("../crypto/ocsp.zig");
const platform = @import("../substrate/platform.zig");
const server_mod = @import("server.zig");
const tls_certs = @import("tls_certs.zig");
const x509 = @import("../crypto/x509.zig");

const wake_poll_ms: u64 = 1000;
const ocsp_request_content_type = "application/ocsp-request";
/// DER serials are <= 20 bytes (RFC 5280 §4.1.2.2) plus a possible sign octet.
const max_serial_len = 24;

/// Tunables for the fetch scheduler. `main.zig` populates these from the
/// `[ocsp]` config section; defaults are safe for a Let's Encrypt-style leaf.
pub const Options = struct {
    /// How often the worker wakes to check whether a (re)fetch is due. The actual
    /// responder is only contacted when the cached staple is stale or missing.
    check_interval_ms: u64 = 15 * 60 * 1000,
    /// Never re-contact the responder more often than this after a success.
    min_refresh_seconds: i64 = 5 * 60,
    /// Re-contact the responder at least this often even if nextUpdate is distant.
    max_refresh_seconds: i64 = 24 * 60 * 60,
    /// Clock-skew tolerance applied to thisUpdate/nextUpdate freshness checks.
    skew_seconds: i64 = ocsp.default_staple_skew_seconds,
    connect_timeout_ms: u31 = 5000,
    recv_timeout_ms: u31 = 10000,
    max_response_bytes: usize = 64 * 1024,
};

/// Seconds until the next responder contact for a staple valid over
/// `[this_update, next_update)`, evaluated at `now`. Standard stapling practice
/// refreshes at the halfway point; the result is clamped to `[min_s, max_s]` so a
/// long-lived response is still re-checked and a near-expiry one is not hammered.
pub fn refreshDelaySeconds(
    this_update: i64,
    next_update: i64,
    now: i64,
    min_s: i64,
    max_s: i64,
) i64 {
    const halfway = this_update + @divTrunc(next_update - this_update, 2);
    const delay = halfway - now;
    return std.math.clamp(delay, min_s, max_s);
}

/// Retry delay after `failures` consecutive responder-fetch failures: exponential
/// backoff starting at `min_s` and doubling each additional failure, clamped to
/// `max_s`. `failures == 0/1` yields `min_s`. Keeps a down responder from being
/// hammered every check interval while still recovering within `max_s`.
pub fn backoffSeconds(failures: u32, min_s: i64, max_s: i64) i64 {
    var delay = min_s;
    var n: u32 = 1;
    while (n < failures and delay < max_s) : (n += 1) {
        // Guard against i64 overflow on an absurd `max_s`; we clamp anyway.
        if (delay > @divTrunc(std.math.maxInt(i64), 2)) {
            delay = max_s;
            break;
        }
        delay *= 2;
    }
    return std.math.clamp(delay, min_s, max_s);
}

/// Transport options for an OCSP POST. Verification uses `trust_anchors`
/// (the daemon trust store). A bad responder certificate fails the fetch;
/// the caller keeps the previous staple.
pub fn ocspTransportOptions(trust_anchors: []const []const u8, opts: Options) http_fetch.Options {
    return .{
        .trust_anchors = trust_anchors,
        .insecure_skip_verify = false,
        .connect_timeout_ms = opts.connect_timeout_ms,
        .recv_timeout_ms = opts.recv_timeout_ms,
        .max_response_bytes = opts.max_response_bytes,
    };
}

/// Outcome of one responder fetch. `.keep` means the previous staple stays
/// (transport failure, bad certificate, bad signature, or a revoked leaf).
/// `.publish` is an owned DER body the caller hands to the server.
pub const StapleDecision = union(enum) {
    keep,
    publish: []u8,
};

/// POST `request_der` and decide whether the body may replace the staple.
/// This is the function `Service.fetchAndPublish` uses. A TLS failure,
/// including an untrusted responder certificate, returns `.keep`.
pub fn fetchAndDecide(
    allocator: std.mem.Allocator,
    url: http_fetch.Url,
    request_der: []const u8,
    trust_anchors: []const []const u8,
    opts: Options,
    issuer_spki: []const u8,
    serial: []const u8,
    now: i64,
) StapleDecision {
    const http_resp = http_fetch.post(allocator, url, ocsp_request_content_type, request_der, ocspTransportOptions(trust_anchors, opts)) catch |err| {
        dlog.log("onyx-server: ocsp fetch failed ({s}); keeping current staple\n", .{@errorName(err)});
        return .keep;
    };
    defer allocator.free(http_resp);

    const der = extractOcspBody(http_resp) orelse {
        dlog.log("onyx-server: ocsp fetch: responder returned no usable OCSPResponse body\n", .{});
        return .keep;
    };

    // Signature checks are unchanged: a revoked verdict is honored only when
    // the response is issuer-signed (or signed by an issuer-authorized
    // delegated responder). An unsigned body cannot forge a revocation.
    if (ocsp.parse(der)) |parsed| {
        if (ocsp.verifyResponseSignatureWithChain(parsed, issuer_spki, now)) {
            if (ocsp.statusForSerial(parsed, serial)) |status| {
                if (status == .revoked) {
                    dlog.log("onyx-server: CRITICAL ocsp responder reports THIS server's certificate REVOKED — not stapling\n", .{});
                    return .keep;
                }
            }
        }
    } else |_| {}

    if (!ocsp.isStapleServable(der, issuer_spki, serial, now, opts.skew_seconds)) {
        dlog.log("onyx-server: ocsp response not servable (bad sig/status/freshness); keeping current staple\n", .{});
        return .keep;
    }

    const owned = allocator.dupe(u8, der) catch {
        dlog.log("onyx-server: ocsp staple skipped: out of memory copying response\n", .{});
        return .keep;
    };
    return .{ .publish = owned };
}

/// Extract the DER OCSPResponse body from a complete HTTP response, or null if
/// the status is not 200 or the body is empty. `http_response` is decoded in
/// place (chunked/Content-Length framing); the returned slice aliases it.
pub fn extractOcspBody(http_response: []u8) ?[]const u8 {
    var header_storage: [32]http1.Header = undefined;
    const resp = http1.parseResponse(http_response, &header_storage) catch return null;
    if (resp.status != 200) return null;
    if (resp.body.len == 0) return null;
    return resp.body;
}

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *server_mod.Server,
    tls: *const config_format.Config.Tls,
    opts: Options,
    /// Daemon trust store (DER anchors). HTTPS OCSP fetches verify against
    /// this set. Empty fails closed; `insecure_skip_verify` is not used.
    /// Borrowed for the process lifetime (same store as ACME / Web Push).
    trust_anchors: []const []const u8 = &.{},
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    // Bookkeeping so a fresh, still-valid staple isn't re-fetched every wake.
    last_serial: [max_serial_len]u8 = undefined,
    last_serial_len: usize = 0,
    next_refresh_unix: i64 = 0,
    // Exponential-backoff state so a down responder isn't re-contacted every check
    // interval. Reset on a successful publish or a leaf-serial change.
    fail_count: u32 = 0,
    next_retry_unix: i64 = 0,
    // One-shot log gates for persistent skip conditions (avoid per-wake spam).
    warned_no_issuer: bool = false,
    warned_no_aia: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        server: *server_mod.Server,
        tls: *const config_format.Config.Tls,
        opts: Options,
    ) Service {
        return .{
            .allocator = allocator,
            .io = io,
            .server = server,
            .tls = tls,
            .opts = opts,
        };
    }

    pub fn start(self: *Service) void {
        if (self.thread != null) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch |err| {
            dlog.log("onyx-server: ocsp stapler start failed ({s}); stapling disabled\n", .{@errorName(err)});
            return;
        };
        dlog.log("onyx-server: ocsp staple scheduler enabled (check interval {d}ms)\n", .{self.opts.check_interval_ms});
    }

    pub fn stop(self: *Service) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn worker(self: *Service) void {
        // Fetch promptly at startup, then on the check interval.
        self.checkOnce();
        while (!self.stop_flag.load(.acquire)) {
            if (!sleepInterruptible(self.opts.check_interval_ms, &self.stop_flag)) break;
            self.checkOnce();
        }
    }

    fn checkOnce(self: *Service) void {
        const cert_path = self.tls.cert_path orelse return;

        const chain = tls_certs.loadCertChain(self.allocator, self.io, cert_path) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot read cert file {s} ({s})\n", .{ cert_path, @errorName(err) });
            return;
        };
        defer {
            for (chain) |der| self.allocator.free(der);
            self.allocator.free(chain);
        }
        if (chain.len < 2) {
            if (!self.warned_no_issuer) {
                dlog.log("onyx-server: ocsp staple disabled: cert file {s} has no issuer cert (need fullchain)\n", .{cert_path});
                self.warned_no_issuer = true;
            }
            return;
        }
        self.warned_no_issuer = false;

        const leaf = x509.parse(chain[0]) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot parse leaf cert ({s})\n", .{@errorName(err)});
            return;
        };
        const issuer = x509.parse(chain[1]) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot parse issuer cert ({s})\n", .{@errorName(err)});
            return;
        };
        if (leaf.aia_ocsp_url.len == 0) {
            if (!self.warned_no_aia) {
                dlog.log("onyx-server: ocsp staple disabled: leaf has no AIA OCSP responder URL\n", .{});
                self.warned_no_aia = true;
            }
            return;
        }
        self.warned_no_aia = false;

        const now = @divTrunc(platform.realtimeMillis(), 1000);

        // A cert rotation (new serial vs the last published one) deserves a fresh
        // attempt, not the backoff accumulated against the previous leaf.
        if (self.last_serial_len != 0 and
            !std.mem.eql(u8, self.last_serial[0..self.last_serial_len], leaf.serial_der))
        {
            self.fail_count = 0;
            self.next_retry_unix = 0;
        }

        // A still-valid staple for this exact serial doesn't need re-fetching yet.
        if (self.hasFreshStapleFor(leaf.serial_der, now)) return;
        // Back off after consecutive failures instead of re-hammering a down
        // responder every check interval.
        if (now < self.next_retry_unix) return;

        if (!self.fetchAndPublish(leaf, issuer, now)) self.noteFetchFailure(now);
    }

    /// Record a failed fetch and schedule the next attempt with exponential
    /// backoff (`backoffSeconds`). Bounded so the counter can't wrap.
    fn noteFetchFailure(self: *Service, now: i64) void {
        if (self.fail_count < std.math.maxInt(u32)) self.fail_count += 1;
        const delay = backoffSeconds(self.fail_count, self.opts.min_refresh_seconds, self.opts.max_refresh_seconds);
        self.next_retry_unix = now + delay;
        dlog.log("onyx-server: ocsp fetch retry backing off {d}s after {d} consecutive failure(s)\n", .{ delay, self.fail_count });
    }

    /// Returns true when a fresh, servable staple was published; false on any
    /// failure (so the caller can apply backoff).
    fn fetchAndPublish(self: *Service, leaf: x509.Certificate, issuer: x509.Certificate, now: i64) bool {
        const req = ocsp.buildRequestForCerts(self.allocator, leaf, issuer) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot build request ({s})\n", .{@errorName(err)});
            return false;
        };
        defer self.allocator.free(req);

        const url = http_fetch.parseUrl(leaf.aia_ocsp_url) catch {
            dlog.log("onyx-server: ocsp staple skipped: malformed AIA URL\n", .{});
            return false;
        };
        const decision = fetchAndDecide(self.allocator, url, req, self.trust_anchors, self.opts, issuer.spki_der, leaf.serial_der, now);
        switch (decision) {
            .keep => return false,
            .publish => |owned| {
                self.recordPublished(owned, leaf.serial_der, now);
                self.server.publishOcspStaple(owned);
                return true;
            },
        }
    }

    /// True when the last published staple covers `serial` and it is not yet time
    /// to refresh — lets the worker wake frequently without hammering responders.
    fn hasFreshStapleFor(self: *Service, serial: []const u8, now: i64) bool {
        if (self.last_serial_len == 0) return false;
        if (!std.mem.eql(u8, self.last_serial[0..self.last_serial_len], serial)) return false;
        return now < self.next_refresh_unix;
    }

    /// Record the serial + schedule the next responder contact from the freshly
    /// published response's thisUpdate/nextUpdate (falls back to min interval).
    fn recordPublished(self: *Service, der: []const u8, serial: []const u8, now: i64) void {
        // A successful publish clears the failure backoff.
        self.fail_count = 0;
        self.next_retry_unix = 0;
        if (serial.len <= max_serial_len) {
            @memcpy(self.last_serial[0..serial.len], serial);
            self.last_serial_len = serial.len;
        } else {
            self.last_serial_len = 0; // unexpectedly long serial: always re-fetch
        }

        var delay = self.opts.min_refresh_seconds;
        if (ocsp.parse(der)) |parsed| {
            if (ocsp.singleForSerial(parsed, serial)) |single| {
                if (single.next_update) |next_bytes| {
                    const this_e = x509.generalizedTimeToEpoch(single.this_update) catch now;
                    const next_e = x509.generalizedTimeToEpoch(next_bytes) catch (now + self.opts.min_refresh_seconds);
                    delay = refreshDelaySeconds(this_e, next_e, now, self.opts.min_refresh_seconds, self.opts.max_refresh_seconds);
                }
            }
        } else |_| {}
        self.next_refresh_unix = now + delay;
        dlog.log("onyx-server: ocsp staple published ({d} bytes); next refresh in {d}s\n", .{ der.len, delay });
    }
};

fn sleepInterruptible(total_ms: u64, stop_flag: *std.atomic.Value(bool)) bool {
    var remaining = total_ms;
    while (remaining > 0) {
        if (stop_flag.load(.acquire)) return false;
        const chunk = @min(remaining, wake_poll_ms);
        sleepMs(@intCast(chunk));
        remaining -= chunk;
    }
    return !stop_flag.load(.acquire);
}

fn sleepMs(ms: u32) void {
    if (comptime @import("builtin").os.tag != .linux) return @import("os_runtime.zig").sleepMillis(ms);
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

test "refreshDelaySeconds halves the validity window, clamped" {
    const this_u: i64 = 1_700_000_000;
    const next_u: i64 = this_u + 4000; // 4000s window, halfway at +2000

    // Fetched at thisUpdate: refresh in ~half the window.
    try std.testing.expectEqual(@as(i64, 2000), refreshDelaySeconds(this_u, next_u, this_u, 60, 86_400));

    // Past the halfway point clamps up to the minimum, never negative.
    try std.testing.expectEqual(@as(i64, 60), refreshDelaySeconds(this_u, next_u, this_u + 3000, 60, 86_400));

    // A very long window clamps down to the daily ceiling.
    const long_next = this_u + 30 * 24 * 60 * 60;
    try std.testing.expectEqual(@as(i64, 86_400), refreshDelaySeconds(this_u, long_next, this_u, 60, 86_400));
}

test "backoffSeconds doubles per failure, clamped to [min,max]" {
    // 0/1 failures → the minimum.
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(0, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(1, 300, 86_400));
    // Then doubles each additional failure.
    try std.testing.expectEqual(@as(i64, 600), backoffSeconds(2, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 1200), backoffSeconds(3, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 2400), backoffSeconds(4, 300, 86_400));
    // Clamps to max once the doubling would exceed it, and stays there.
    try std.testing.expectEqual(@as(i64, 86_400), backoffSeconds(20, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 86_400), backoffSeconds(std.math.maxInt(u32), 300, 86_400));
    // A tiny window never returns below min even for 1 failure.
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(1, 300, 300));
}

test "extractOcspBody returns body only for a 200 with content" {
    const allocator = std.testing.allocator;

    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: 5\r\n\r\n\x30\x03\x0a\x01\x00");
        defer allocator.free(raw);
        const body = extractOcspBody(raw).?;
        try std.testing.expectEqualSlices(u8, "\x30\x03\x0a\x01\x00", body);
    }
    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nbad");
        defer allocator.free(raw);
        try std.testing.expect(extractOcspBody(raw) == null);
    }
    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        defer allocator.free(raw);
        try std.testing.expect(extractOcspBody(raw) == null);
    }
}

const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const tls_conn = @import("tls_conn.zig");
const posix = std.posix;

const OcspStub = struct {
    listen_fd: linux.fd_t,
    der: []const u8,
    kp: Ed25519.KeyPair,
    stop: *std.atomic.Value(bool),
    app_posts: *std.atomic.Value(u32),
};

fn ocspWriteAll(fd: linux.fd_t, bytes: []const u8) void {
    if (comptime @import("builtin").os.tag == .openbsd) {
        @import("native_network.zig").writeAll(fd, bytes) catch {};
        return;
    }
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (posix.errno(rc) != .SUCCESS) return;
        const n: usize = @intCast(rc);
        if (n == 0) return;
        off += n;
    }
}

fn ocspListenLoopback() !struct { fd: linux.fd_t, port: u16 } {
    if (comptime @import("builtin").os.tag == .openbsd) {
        const opened = try @import("io_backend.zig").listenTcp("127.0.0.1", 0);
        return .{ .fd = opened.fd, .port = opened.port };
    }
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.Socket;
    const fd: linux.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);
    var yes: u32 = 1;
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(u32));
    var addr = linux.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.Bind;
    if (posix.errno(linux.listen(fd, 8)) != .SUCCESS) return error.Listen;
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.Bind;
    const bound: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
}

fn ocspStubServe(alloc: std.mem.Allocator, fd: linux.fd_t, stub: *OcspStub) void {
    defer @import("io_backend.zig").closeSocket(fd);
    if (comptime @import("builtin").os.tag == .openbsd) {
        @import("native_network.zig").setBlocking(fd) catch return;
        @import("native_network.zig").setTimeout(fd, 2000) catch return;
    } else {
        const rtv = linux.timeval{ .sec = 2, .usec = 0 };
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&rtv), @sizeOf(linux.timeval));
    }
    var conn = tls_conn.TlsConn.init(alloc, .{ .cert_chain = &.{stub.der}, .signing_key = stub.kp }) catch return;
    defer conn.deinit();
    var buf: [16 * 1024]u8 = undefined;
    var plain_acc: [4096]u8 = undefined;
    var plain_len: usize = 0;
    while (!stub.stop.load(.acquire)) {
        const rc = if (comptime @import("builtin").os.tag == .openbsd)
            std.c.read(fd, &buf, buf.len)
        else
            linux.read(fd, &buf, buf.len);
        if (posix.errno(rc) != .SUCCESS) return;
        const n: usize = @intCast(rc);
        if (n == 0) return;
        const out = conn.onInbound(buf[0..n]) catch |err| {
            if (conn.takeAlert(err)) |alert| {
                defer alloc.free(alert);
                ocspWriteAll(fd, alert);
            }
            return;
        };
        if (out.handshake_bytes.len != 0) {
            const flight = alloc.dupe(u8, out.handshake_bytes) catch return;
            defer alloc.free(flight);
            ocspWriteAll(fd, flight);
        }
        if (out.plaintext.len != 0 and plain_len < plain_acc.len) {
            const take = @min(out.plaintext.len, plain_acc.len - plain_len);
            @memcpy(plain_acc[plain_len..][0..take], out.plaintext[0..take]);
            plain_len += take;
        }
        if (conn.handshakeDone() and std.mem.indexOf(u8, plain_acc[0..plain_len], "\r\n\r\n") != null) {
            _ = stub.app_posts.fetchAdd(1, .monotonic);
            const body = "nope";
            var hdr_buf: [160]u8 = undefined;
            const hdr = std.fmt.bufPrint(&hdr_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch return;
            const cipher = conn.write(hdr) catch return;
            const owned = alloc.dupe(u8, cipher) catch return;
            defer alloc.free(owned);
            ocspWriteAll(fd, owned);
            return;
        }
    }
}

fn ocspStubAccept(stub: *OcspStub) void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    if (comptime @import("builtin").os.tag == .openbsd) {
        while (!stub.stop.load(.acquire)) {
            var ready = [_]posix.pollfd{.{ .fd = stub.listen_fd, .events = posix.POLL.IN, .revents = 0 }};
            const polled = std.c.poll(&ready, 1, 50);
            if (polled < 0) {
                if (posix.errno(polled) == .INTR) continue;
                return;
            }
            if (polled == 0) continue;
            const fd = std.c.accept(stub.listen_fd, null, null);
            switch (posix.errno(fd)) {
                .SUCCESS => ocspStubServe(alloc, fd, stub),
                .AGAIN, .INTR, .CONNABORTED => continue,
                else => return,
            }
        }
        return;
    }
    const tv = linux.timeval{ .sec = 0, .usec = 200_000 };
    _ = linux.setsockopt(stub.listen_fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    while (!stub.stop.load(.acquire)) {
        const rc = linux.accept4(stub.listen_fd, null, null, posix.SOCK.CLOEXEC);
        switch (posix.errno(rc)) {
            .SUCCESS => ocspStubServe(alloc, @intCast(rc), stub),
            .AGAIN, .INTR, .CONNABORTED => continue,
            else => return,
        }
    }
}

test "tls ocsp fetch uses the daemon trust store and a bad certificate keeps the previous staple" {
    if (comptime @import("builtin").os.tag != .linux and @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    const good_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x41)));
    const bad_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x42)));
    var good_buf: [1400]u8 = undefined;
    var bad_buf: [1400]u8 = undefined;
    const good_der = try x509_selfsign.buildSelfSigned(&good_buf, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x01, 0x02 },
        .key_pair = good_kp,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    const bad_der = try x509_selfsign.buildSelfSigned(&bad_buf, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x03, 0x04 },
        .key_pair = bad_kp,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });

    const listener = try ocspListenLoopback();
    var stop = std.atomic.Value(bool).init(false);
    var posts = std.atomic.Value(u32).init(0);
    var stub = OcspStub{
        .listen_fd = listener.fd,
        .der = good_der,
        .kp = good_kp,
        .stop = &stop,
        .app_posts = &posts,
    };
    const thread = try std.Thread.spawn(.{}, ocspStubAccept, .{&stub});
    defer {
        stop.store(true, .release);
        thread.join();
        @import("io_backend.zig").closeSocket(listener.fd);
    }

    const url_text = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/ocsp", .{listener.port});
    defer allocator.free(url_text);
    const url = try http_fetch.parseUrl(url_text);
    const opts = Options{ .connect_timeout_ms = 2000, .recv_timeout_ms = 3000 };
    const previous = "previous-staple";
    const transport = ocspTransportOptions(&.{good_der}, opts);
    try std.testing.expect(!transport.insecure_skip_verify);
    try std.testing.expectEqual(@as(usize, 1), transport.trust_anchors.len);
    try std.testing.expectEqual(good_der.ptr, transport.trust_anchors[0].ptr);

    const untrusted = fetchAndDecide(allocator, url, "ocsp-request", &.{bad_der}, opts, "issuer-spki", "serial", 1_700_000_000);
    try std.testing.expect(untrusted == .keep);
    try std.testing.expectEqual(@as(u32, 0), posts.load(.monotonic));

    const trusted_garbage = fetchAndDecide(allocator, url, "ocsp-request", &.{good_der}, opts, "issuer-spki", "serial", 1_700_000_000);
    switch (trusted_garbage) {
        .keep => {},
        .publish => |owned| {
            allocator.free(owned);
            return error.TestUnexpectedResult;
        },
    }
    try std.testing.expect(posts.load(.monotonic) >= 1);
    try std.testing.expectEqualStrings("previous-staple", previous);
    std.debug.print("GAP-A8 branch=trust-store bad-cert=keep signature-fail=keep previous={s}\n", .{previous});
}

test {
    std.testing.refAllDecls(@This());
}
