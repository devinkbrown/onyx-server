// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live ACME issuance orchestration: drives the `acme_client` state machine over
//! real TLS 1.3 + HTTP/1.1 to a CA (e.g. Let's Encrypt), serving HTTP-01
//! challenges from a `TokenStore` and writing the issued chain to disk.
//!
//! This runs OUT OF BAND (blocking sockets, a dedicated call — not the io_uring
//! hot loop). Certificate issuance/renewal happens roughly every ~60 days, so a
//! simple synchronous driver is the right tool; it never blocks the event loop.
//!
//! It is clean-room and self-contained: TLS via `crypto/tls_client`, HTTP via
//! `proto/http1_client`, ACME via `daemon/acme_client`, signatures via ES256
//! (`crypto/sign`). No OpenSSL, no certbot, no external processes.
//!
//! Trust anchors (the CA root DER(s) that validate the ACME API endpoint's own
//! certificate) are supplied by the caller — this module pins nothing implicitly.

const std = @import("std");
const builtin = @import("builtin");
const dlog = @import("dlog.zig");

const tls_client = @import("../crypto/tls_client.zig");
const tls_client_failure = @import("tls_client_failure.zig");
const http1 = @import("../proto/http1_client.zig");
const acme = @import("acme_client.zig");
const http01 = @import("acme_http01_server.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const pem = @import("../proto/pem.zig");
const dns = @import("../proto/dns.zig");
const resolv_conf = @import("../proto/resolv_conf.zig");
const toml = @import("../proto/toml.zig");
const http_fetch = @import("http_fetch.zig");
const os_runtime = @import("os_runtime.zig");

const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const posix = std.posix;
const net = std.Io.net;

pub const Error = error{
    InvalidUrl,
    NotHttps,
    ConnectionClosed,
    ConnectFailed,
    SocketUnavailable,
    UnsupportedAddressFamily,
    ResponseTooLarge,
} || Allocator.Error || tls_client.Error || http1.Error || http_fetch.Error;

/// Resolves an ACME endpoint hostname to an IP address. Injected because this
/// std build has no DNS resolver and the daemon's S2S path uses configured IPs;
/// a future DNS module (or a static config map) provides the implementation.
pub const Resolver = struct {
    ctx: *anyopaque,
    resolveFn: *const fn (ctx: *anyopaque, host: []const u8, port: u16) anyerror!net.IpAddress,

    fn resolve(self: Resolver, host: []const u8, port: u16) anyerror!net.IpAddress {
        return self.resolveFn(self.ctx, host, port);
    }
};

/// Default maximum bytes accepted for a single HTTP response (ACME payloads are
/// small). Operationally tunable via `[acme].max_response_bytes`.
pub const default_max_response_bytes: usize = 256 * 1024;
/// Default max ACME state-machine steps before aborting.
pub const default_max_steps: usize = 64;
/// Default max bytes of an RFC 7807 problem body logged on error/debug.
pub const default_error_body_preview_bytes: usize = 512;
/// Default max bytes read from /etc/resolv.conf by the built-in resolver.
pub const default_resolv_conf_max_bytes: usize = 64 * 1024;
/// Default UDP port used for the built-in resolver's DNS A-record lookups.
pub const default_dns_port: u16 = 53;
const max_tls_record: usize = 5 + (1 << 14) + 256;

// ---------------------------------------------------------------------------
// URL parsing (absolute https URLs only)
// ---------------------------------------------------------------------------

pub const Url = struct {
    host: []const u8,
    port: u16,
    path: []const u8,

    /// Parse `https://host[:port]/path`. Slices borrow `url`.
    pub fn parse(url: []const u8) Error!Url {
        const scheme = "https://";
        if (!std.mem.startsWith(u8, url, scheme)) return error.NotHttps;
        const rest = url[scheme.len..];
        const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const authority = rest[0..path_start];
        const path = if (path_start == rest.len) "/" else rest[path_start..];
        if (authority.len == 0) return error.InvalidUrl;

        var host = authority;
        var port: u16 = 443;
        if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
            // Guard against IPv6 literals (not needed for ACME hostnames).
            if (std.mem.indexOfScalar(u8, authority, ']') == null) {
                host = authority[0..colon];
                port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch
                    return error.InvalidUrl;
            }
        }
        if (host.len == 0) return error.InvalidUrl;
        return .{ .host = host, .port = port, .path = path };
    }
};

// ---------------------------------------------------------------------------
// Blocking one-shot HTTPS request over the clean-room TLS 1.3 client
// ---------------------------------------------------------------------------

/// Perform a single request/response over a fresh TLS 1.3 connection and return
/// the decrypted HTTP response bytes (caller owns). `Connection: close` is sent;
/// one connection serves exactly one exchange (simple and correct for ACME).
pub fn httpsRequest(
    allocator: Allocator,
    resolver: Resolver,
    trust_anchors: []const []const u8,
    method: []const u8,
    url: Url,
    extra_headers: []const http1.Header,
    body: []const u8,
    max_response_bytes: usize,
) Error![]u8 {
    const addr = resolver.resolve(url.host, url.port) catch return error.ConnectFailed;
    if (comptime builtin.os.tag == .windows) {
        // Reuse the native Winsock transport: it pins this resolved address,
        // verifies the CA certificate and bounds connect/read/write waits.
        // The request bytes are constructed here so ACME's nonce and JWS
        // headers reach the CA unchanged.
        var req_buf: [16 * 1024]u8 = undefined;
        const request = try http1.buildRequest(&req_buf, method, url.host, url.path, extra_headers, body);
        return http_fetch.getAtAddress(allocator, url.host, url.port, true, request, addr, .{
            .trust_anchors = trust_anchors,
            .connect_timeout_ms = 5000,
            .recv_timeout_ms = 10000,
            .max_response_bytes = max_response_bytes,
        });
    }
    const fd = try connectAddr(addr);
    defer closeFd(fd);

    var tc = try tls_client.Client.init(allocator, .{
        .server_name = url.host,
        .trust_anchors = trust_anchors,
        .alpn_protocols = &.{"http/1.1"},
        .now_unix_seconds = wallClockSeconds(),
        // ACME directory TLS stays fail-open on CRL/CT (no CDP or pinned-log
        // cache here). http_fetch.Options is the opt-in wire for fetchers that
        // already hold a caller-supplied CRL or CT log set.
        .require_crl = false,
        .enforce_sct = false,
        .require_sct = 0,
    });
    defer tc.deinit();

    // --- TLS handshake ---
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

    // --- Build + send the (encrypted) request ---
    {
        var req_buf: [16 * 1024]u8 = undefined;
        const req = try http1.buildRequest(&req_buf, method, url.host, url.path, extra_headers, body);
        const record = try tc.encrypt(req);
        defer allocator.free(record);
        try writeAll(fd, record);
    }

    // --- Read + decrypt the response until it is a complete HTTP message ---
    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(allocator);
    try pending.appendSlice(allocator, tc.pendingBytes()); // drain post-Finished flush

    var plaintext: std.ArrayList(u8) = .empty;
    defer plaintext.deinit(allocator);

    read_loop: while (true) {
        // Frame and decrypt every complete TLS record we currently hold.
        while (frameRecordLen(pending.items)) |rec_len| {
            const rec = pending.items[0..rec_len];
            const read = tc.decryptApp(rec) catch |err| switch (err) {
                // A trailing alert (close_notify, sent with Connection: close)
                // ends the stream; the HTTP response we already have is final.
                error.TlsAlert => break :read_loop,
                else => {
                    tls_client_failure.sendFatal(fd, &tc, err);
                    return err;
                },
            };
            switch (read) {
                .application_data => |pt| {
                    defer allocator.free(pt);
                    if (plaintext.items.len + pt.len > max_response_bytes) return error.ResponseTooLarge;
                    try plaintext.appendSlice(allocator, pt);
                },
                .control => {}, // post-handshake record (e.g. NewSessionTicket): ignore
            }
            // A server KeyUpdate may queue a reply we must write back before
            // reading further under the rotated keys.
            if (try tc.takePendingSend()) |reply| {
                defer allocator.free(reply);
                try writeAll(fd, reply);
            }
            consumePrefix(&pending, rec_len);
            // Stop as soon as the HTTP message is complete, so we never decrypt a
            // trailing close_notify/record bundled in the same segment.
            if (http1.isComplete(plaintext.items)) break :read_loop;
        }
        if (http1.isComplete(plaintext.items)) break;

        const n = readSome(fd, &read_buf) catch |err| switch (err) {
            error.ConnectionClosed => break, // server closed; use what we have
            else => return err,
        };
        if (n == 0) break;
        try pending.appendSlice(allocator, read_buf[0..n]);
    }

    return plaintext.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// acme_client.Transport adapter
// ---------------------------------------------------------------------------

/// Bridges `acme_client.Transport` to live HTTPS. Owns the most recent response
/// buffer + header scratch; each call frees the prior one, so returned slices
/// stay valid until the next `get`/`postJws` (which is exactly the contract the
/// state machine relies on).
pub const HttpsTransport = struct {
    allocator: Allocator,
    resolver: Resolver,
    trust_anchors: []const []const u8,
    last_response: ?[]u8 = null,
    header_scratch: [64]http1.Header = undefined,
    /// When true, log every exchange; errors (status >= 300) are always logged.
    debug: bool = false,
    /// Max bytes accepted for a single HTTP response.
    max_response_bytes: usize = default_max_response_bytes,
    /// Max bytes of an RFC 7807 problem body logged on error/debug.
    error_body_preview_bytes: usize = default_error_body_preview_bytes,

    pub fn init(allocator: Allocator, resolver: Resolver, trust_anchors: []const []const u8) HttpsTransport {
        return .{ .allocator = allocator, .resolver = resolver, .trust_anchors = trust_anchors };
    }

    pub fn deinit(self: *HttpsTransport) void {
        if (self.last_response) |r| self.allocator.free(r);
        self.last_response = null;
    }

    pub fn transport(self: *HttpsTransport) acme.Transport {
        return .{ .ctx = self, .getFn = getThunk, .postJwsFn = postThunk };
    }

    fn exchange(
        self: *HttpsTransport,
        method: []const u8,
        url_str: []const u8,
        extra: []const http1.Header,
        body: []const u8,
    ) anyerror!acme.HttpResponse {
        const url = try Url.parse(url_str);
        const raw = httpsRequest(self.allocator, self.resolver, self.trust_anchors, method, url, extra, body, self.max_response_bytes) catch |err| {
            if (self.debug) dlog.log("acme!! {s} {s} transport error: {s}\n", .{ method, url_str, @errorName(err) });
            return err;
        };
        if (self.last_response) |r| self.allocator.free(r);
        self.last_response = raw;
        const resp = try http1.parseResponse(raw, &self.header_scratch);
        // Trace every exchange under --debug; always surface error bodies (the
        // RFC 7807 problem document) so failures are diagnosable without --debug.
        if (self.debug or resp.status >= 300) {
            const preview = resp.body[0..@min(resp.body.len, self.error_body_preview_bytes)];
            dlog.log("acme<- {s} {s} -> {d} (body {d}B)\n  {s}\n", .{ method, url_str, resp.status, resp.body.len, preview });
        }
        return .{
            .status = resp.status,
            .body = resp.body,
            .nonce = http1.header(resp, "replay-nonce"),
            .location = http1.header(resp, "location"),
        };
    }

    fn getThunk(ctx: *anyopaque, url: []const u8) anyerror!acme.HttpResponse {
        const self: *HttpsTransport = @ptrCast(@alignCast(ctx));
        return self.exchange("GET", url, &.{}, "");
    }

    fn postThunk(ctx: *anyopaque, url: []const u8, jws_body: []const u8) anyerror!acme.HttpResponse {
        const self: *HttpsTransport = @ptrCast(@alignCast(ctx));
        const headers = [_]http1.Header{
            .{ .name = "Content-Type", .value = "application/jose+json" },
            .{ .name = "Connection", .value = "close" },
        };
        return self.exchange("POST", url, &headers, jws_body);
    }
};

// ---------------------------------------------------------------------------
// ES256 signer adapter (ECDSA P-256; account key == issued-cert key, per
// acme_client). Let's Encrypt accepts ES256/ES384/ES512/RS256, not EdDSA.
// ---------------------------------------------------------------------------

pub const Es256Signer = struct {
    key_pair: ecdsa_p256.KeyPair,

    pub fn init(key_pair: ecdsa_p256.KeyPair) Es256Signer {
        return .{ .key_pair = key_pair };
    }

    pub fn signer(self: *Es256Signer) acme.Signer {
        const sec1 = self.key_pair.public_key.toUncompressedSec1(); // 0x04 ‖ x ‖ y
        var x: [32]u8 = undefined;
        var y: [32]u8 = undefined;
        @memcpy(&x, sec1[1..33]);
        @memcpy(&y, sec1[33..65]);
        return .{ .ctx = self, .public_key_x = x, .public_key_y = y, .signFn = signThunk };
    }

    fn signThunk(ctx: *anyopaque, signing_input: []const u8, out: []u8) anyerror![]const u8 {
        const self: *Es256Signer = @ptrCast(@alignCast(ctx));
        if (out.len < 64) return error.NoSpaceLeft;
        const sig = try ecdsa_p256.sign(signing_input, self.key_pair);
        const raw = sig.toBytes(); // fixed-width r‖s (64 bytes), the ES256 form
        @memcpy(out[0..64], &raw);
        return out[0..64];
    }
};

// ---------------------------------------------------------------------------
// Top-level issuance driver
// ---------------------------------------------------------------------------

pub const IssueConfig = struct {
    directory_url: []const u8,
    domains: []const []const u8,
    contacts: []const []const u8 = &.{},
    /// CA-API trust anchors (root CA DER) validating the ACME endpoint cert.
    trust_anchors: []const []const u8,
    /// Absolute path the issued PEM chain is written to (kain-owned dir).
    cert_out_path: []const u8,
    /// Absolute path the cert PRIVATE KEY (SEC1 EC PEM) is written to, for the
    /// TLS server (nginx) to consume. Null skips writing the key.
    key_out_path: ?[]const u8 = null,
    /// Max state-machine steps before giving up (defends against loops/hangs).
    max_steps: usize = default_max_steps,
    /// Log every HTTP exchange (errors are always logged regardless).
    debug: bool = false,
    /// Max bytes accepted for a single ACME HTTP response.
    max_response_bytes: usize = default_max_response_bytes,
    /// Max bytes of an RFC 7807 problem body logged on error/debug.
    error_body_preview_bytes: usize = default_error_body_preview_bytes,
    /// Max bytes read from /etc/resolv.conf by the built-in resolver.
    resolv_conf_max_bytes: usize = default_resolv_conf_max_bytes,
    /// UDP port the built-in resolver uses for DNS A-record lookups.
    dns_port: u16 = default_dns_port,
};

/// Overlay `[acme]` config onto `cfg`, leaving any absent key at its current
/// (default) value. Behavior is unchanged when the document carries none of
/// these keys. Only operational tunables are read here; cryptographic/protocol
/// domain constants stay in code.
pub fn applyToml(cfg: *IssueConfig, doc: *const toml.Document) void {
    if (doc.getUint("acme.max_steps")) |v| {
        if (v != 0) cfg.max_steps = @intCast(v);
    }
    if (doc.getBool("acme.debug")) |v| cfg.debug = v;
    if (doc.getUint("acme.max_response_bytes")) |v| {
        if (v != 0) cfg.max_response_bytes = @intCast(v);
    }
    if (doc.getUint("acme.error_body_preview_bytes")) |v| {
        cfg.error_body_preview_bytes = @intCast(v);
    }
    if (doc.getUint("acme.resolv_conf_max_bytes")) |v| {
        if (v != 0) cfg.resolv_conf_max_bytes = @intCast(v);
    }
    if (doc.getUint("acme.dns_port")) |v| {
        if (v >= 1 and v <= std.math.maxInt(u16)) cfg.dns_port = @intCast(v);
    }
}

pub const IssueResult = struct {
    state: acme.State,
    cert_written: bool,
};

/// Run a full issuance. `token_store` MUST already be wired to a live HTTP-01
/// responder reachable at `http://<domain>/.well-known/acme-challenge/<token>`
/// (see [acme_http01_server]); this driver only populates/clears it.
///
/// `resolver` turns ACME endpoint hostnames into IPs. Pass `null` to use the
/// built-in blocking resolver (reads /etc/resolv.conf, queries via our own
/// `dns.zig` over UDP). `io` is used for the resolver's resolv.conf read and the
/// atomic cert write.
pub fn issue(
    allocator: Allocator,
    io: std.Io,
    cfg: IssueConfig,
    account_key: ecdsa_p256.KeyPair,
    cert_key: ecdsa_p256.KeyPair,
    token_store: *http01.TokenStore,
    resolver: ?Resolver,
) !IssueResult {
    var sys = SystemResolver{
        .allocator = allocator,
        .io = io,
        .resolv_conf_max_bytes = cfg.resolv_conf_max_bytes,
        .dns_port = cfg.dns_port,
    };
    const active_resolver = resolver orelse sys.resolver();

    var account_es = Es256Signer.init(account_key);
    var cert_es = Es256Signer.init(cert_key);
    var http_transport = HttpsTransport.init(allocator, active_resolver, cfg.trust_anchors);
    http_transport.debug = cfg.debug;
    http_transport.max_response_bytes = cfg.max_response_bytes;
    http_transport.error_body_preview_bytes = cfg.error_body_preview_bytes;
    tls_client.debug_log = cfg.debug;
    defer http_transport.deinit();

    var client = acme.Acme.init(allocator, .{
        .directory_url = cfg.directory_url,
        .domains = cfg.domains,
        .contacts = cfg.contacts,
        .signer = account_es.signer(),
        .cert_signer = cert_es.signer(),
    });
    defer client.deinit();

    var cert_written = false;
    var steps: usize = 0;
    while (steps < cfg.max_steps) : (steps += 1) {
        const progress = try client.step(http_transport.transport());
        for (progress.effects) |effect| switch (effect) {
            .serve_http01 => |c| try token_store.put(c.token, c.key_authorization),
            .write_cert => |c| {
                try writeCertAtomic(io, std.Io.Dir.cwd(), cfg.cert_out_path, c.pem);
                if (cfg.key_out_path) |kp| {
                    var pem_buf: [512]u8 = undefined;
                    const key_pem = try ecPrivateKeyPem(cert_key, &pem_buf);
                    try writeKeyAtomic(io, std.Io.Dir.cwd(), kp, key_pem);
                }
                cert_written = true;
            },
        };
        if (progress.done) {
            return .{ .state = progress.state, .cert_written = cert_written };
        }
    }
    return error.TooManySteps;
}

// ---------------------------------------------------------------------------
// Built-in blocking DNS resolver (reuses our own dns.zig + resolv_conf)
// ---------------------------------------------------------------------------

/// Default `Resolver`: on Unix, parses /etc/resolv.conf and performs a blocking
/// A-record lookup over UDP using the clean-room `dns.zig` codec. On Windows,
/// delegates to the DNS Client through GetAddrInfoExW. Out-of-band only.
///
/// Handles IP literals and direct A records. The Unix codec does not decode
/// CNAME chains or EDNS additional records, so CDN-fronted endpoints may need
/// a custom `Resolver` (or a static host→IP) there.
pub const SystemResolver = struct {
    allocator: Allocator,
    io: std.Io,
    /// Max bytes read from /etc/resolv.conf.
    resolv_conf_max_bytes: usize = default_resolv_conf_max_bytes,
    /// UDP port used for DNS A-record lookups.
    dns_port: u16 = default_dns_port,

    pub fn resolver(self: *SystemResolver) Resolver {
        return .{ .ctx = self, .resolveFn = resolveThunk };
    }

    fn resolveThunk(ctx: *anyopaque, host: []const u8, port: u16) anyerror!net.IpAddress {
        const self: *SystemResolver = @ptrCast(@alignCast(ctx));
        // IP-literal fast path (no query needed).
        if (net.IpAddress.parse(host, port)) |addr| return addr else |_| {}
        // Windows DNS Client resolution applies the host's configured name
        // service policy. Web Push validates this one result and then connects
        // to that exact IP, so no second lookup can bypass its SSRF guard.
        if (comptime builtin.os.tag == .windows) {
            const fetch = @import("http_fetch.zig");
            return fetch.resolveHostA(host, port, 3000) catch |err| switch (err) {
                error.HostNotFound => try fetch.resolveHostAAAA(host, port, 3000),
                else => return err,
            };
        }
        return systemResolveA(self.allocator, self.io, host, port, self.resolv_conf_max_bytes, self.dns_port);
    }
};

test "acme_runner Windows SystemResolver delegates localhost to DNS Client" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var system = SystemResolver{ .allocator = std.testing.allocator, .io = std.testing.io };
    const resolver = system.resolver();
    const address = try resolver.resolveFn(resolver.ctx, "localhost", 443);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &address.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 443), address.ip4.port);
}

fn systemResolveA(
    allocator: Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    resolv_conf_max_bytes: usize,
    dns_port: u16,
) !net.IpAddress {
    const text = std.Io.Dir.cwd().readFileAlloc(io, "/etc/resolv.conf", allocator, .limited(resolv_conf_max_bytes)) catch
        return error.NoNameservers;
    defer allocator.free(text);
    const conf = resolv_conf.parse(text);
    const servers = conf.nameserverSlice();
    if (servers.len == 0) return error.NoNameservers;

    var id_seed: [2]u8 = undefined;
    osEntropy(&id_seed);
    const query_id = std.mem.readInt(u16, &id_seed, .big);

    var query_buf: [dns.max_message_len]u8 = undefined;
    const query = try dns.encodeQuery(&query_buf, query_id, host, .a);

    // Try every configured nameserver in order, over whichever transport its
    // address family requires (UDP/IPv4 or UDP/IPv6). In an IPv6-only resolver
    // environment (e.g. nameserver ::1) only the v6 path is reachable, so it
    // must be wired — not skipped — or resolution fails with NoNameservers.
    for (servers) |srv| {
        const answer = switch (srv) {
            .ipv4 => |b| queryOneServer(b, query, dns_port) catch continue,
            .ipv6 => |b| queryOneServer6(b, query, dns_port) catch continue,
        };
        if (answer) |ipv4| return .{ .ip4 = .{ .bytes = ipv4, .port = port } };
    }
    return error.HostNotFound;
}

/// Send `query` to a v4 nameserver:<dns_port> and return the first A record, or null.
fn queryOneServer(ns_v4: [4]u8, query: []const u8, dns_port: u16) !?[4]u8 {
    if (comptime builtin.os.tag == .openbsd) return queryNativeServer(.{ .ip4 = .{ .bytes = ns_v4, .port = dns_port } }, query);
    const fd = try udpSocket(posix.AF.INET);
    defer closeFd(fd);
    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, dns_port), .addr = @bitCast(ns_v4) };
    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return error.ConnectFailed;
    return exchangeQuery(fd, query);
}

/// Send `query` to a v6 nameserver:<dns_port> over UDP/IPv6 and return the first
/// A record, or null. Mirrors `queryOneServer` exactly, differing only in the
/// socket family and `sockaddr_in6` (flowinfo/scope_id left zero — link-local
/// scopes are not expressible in resolv.conf's textual form we parse).
fn queryOneServer6(ns_v6: [16]u8, query: []const u8, dns_port: u16) !?[4]u8 {
    if (comptime builtin.os.tag == .openbsd) return queryNativeServer(.{ .ip6 = .{ .bytes = ns_v6, .port = dns_port } }, query);
    const fd = try udpSocket(posix.AF.INET6);
    defer closeFd(fd);
    var sa = linux.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, dns_port),
        .flowinfo = 0,
        .addr = ns_v6,
        .scope_id = 0,
    };
    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
        return error.ConnectFailed;
    return exchangeQuery(fd, query);
}

/// Write `query` to the (already-connected) UDP socket `fd`, read the reply, and
/// return the first A record found, or null. Shared by the v4 and v6 paths so
/// the send/recv/parse semantics stay identical across address families.
fn exchangeQuery(fd: linux.fd_t, query: []const u8) !?[4]u8 {
    if (posix.errno(linux.write(fd, query.ptr, query.len)) != .SUCCESS) return error.ConnectFailed;

    var resp_buf: [dns.max_message_len]u8 = undefined;
    const rc = linux.read(fd, &resp_buf, resp_buf.len);
    if (posix.errno(rc) != .SUCCESS) return error.ConnectFailed;
    const n: usize = @intCast(rc);

    const msg = dns.parseMessage(1, dns.max_cache_addrs, resp_buf[0..n]) catch return null;
    for (msg.answerSlice()) |rr| switch (rr.data) {
        .a => |ipv4| return ipv4,
        else => {},
    };
    return null;
}

fn queryNativeServer(address: net.IpAddress, query: []const u8) !?[4]u8 {
    const native = @import("native_network.zig");
    const fd = try native.socket(if (address == .ip4) posix.AF.INET else posix.AF.INET6, true, false);
    defer @import("os_runtime.zig").close(fd);
    try native.setTimeout(fd, 3000);
    try native.connectSocket(fd, address);
    try native.writeAll(fd, query);
    var response: [dns.max_message_len]u8 = undefined;
    const count = try native.readSome(fd, &response);
    const question = dns.parseMessage(1, 0, query) catch return null;
    if (question.question_count != 1) return null;
    const name = question.questionSlice()[0].name.slice();
    const message = dns.parseMessage(1, dns.max_cache_addrs, response[0..count]) catch return null;
    if (message.header.id != question.header.id or message.header.rcode() != 0 or (message.header.flags & 0x7a00) != 0 or !dns.responseMatchesQuestion(1, dns.max_cache_addrs, &message, name, .a) or
        !dns.responseAnswersFollowCnames(dns.max_cache_addrs, response[0..count], name, .a)) return null;
    for (message.answerSlice()) |rr| switch (rr.data) {
        .a => |bytes| return bytes,
        else => {},
    };
    return null;
}

// ---------------------------------------------------------------------------
// Low-level socket helpers (raw linux syscalls, matching server.zig idiom)
// ---------------------------------------------------------------------------

fn connectAddr(addr: net.IpAddress) Error!linux.fd_t {
    if (comptime builtin.os.tag == .openbsd) return @import("native_network.zig").connect(addr, 5000) catch return error.ConnectFailed;
    const a4 = switch (addr) {
        .ip4 => |x| x,
        .ip6 => return error.UnsupportedAddressFamily,
    };
    const fd = try socketTcp();
    errdefer closeFd(fd);
    var sa = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, a4.port),
        .addr = @bitCast(a4.bytes),
    };
    switch (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)))) {
        .SUCCESS => return fd,
        else => return error.ConnectFailed,
    }
}

// Linux-only socket helpers (SOCK_CLOEXEC). `refAllDecls` in the test build
// force-references these module-level decls, so gate the bodies at comptime for
// foreign-target compiles. On Linux they are analyzed and run exactly as before;
// the live ACME runner is Linux-only.
fn socketTcp() Error!linux.fd_t {
    if (comptime builtin.os.tag == .linux) {
        const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
        return switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => error.SocketUnavailable,
        };
    } else return error.SocketUnavailable;
}

fn udpSocket(family: u32) Error!linux.fd_t {
    if (comptime builtin.os.tag == .linux) {
        const rc = linux.socket(family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
        return switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => error.SocketUnavailable,
        };
    } else return error.SocketUnavailable;
}

fn closeFd(fd: linux.fd_t) void {
    if (comptime builtin.os.tag == .openbsd) return @import("os_runtime.zig").close(fd);
    _ = linux.close(fd);
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) Error!void {
    if (comptime builtin.os.tag == .openbsd) return @import("native_network.zig").writeAll(fd, bytes) catch return error.ConnectionClosed;
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        switch (posix.errno(rc)) {
            .SUCCESS => off += @intCast(rc),
            else => return error.ConnectionClosed,
        }
    }
}

fn readSome(fd: linux.fd_t, buf: []u8) Error!usize {
    if (comptime builtin.os.tag == .openbsd) return @import("native_network.zig").readSome(fd, buf) catch return error.ConnectionClosed;
    const rc = linux.read(fd, buf.ptr, buf.len);
    switch (posix.errno(rc)) {
        .SUCCESS => {
            const n: usize = @intCast(rc);
            if (n == 0) return error.ConnectionClosed;
            return n;
        },
        else => return error.ConnectionClosed,
    }
}

fn osEntropy(buf: []u8) void {
    if (comptime builtin.os.tag != .linux) {
        @import("../substrate/platform.zig").fillOsEntropy(buf) catch @panic("ACME DNS entropy unavailable");
        return;
    }
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
        if (posix.errno(rc) != .SUCCESS) {
            // Fallback: monotonic-ish fill; query IDs are not security-critical.
            for (buf[filled..]) |*b| b.* = 0x55;
            return;
        }
        filled += @intCast(rc);
    }
}

/// Return the total wire length of the leading TLS record in `buf`, or null if a
/// full record is not yet present.
fn frameRecordLen(buf: []const u8) ?usize {
    if (buf.len < 5) return null;
    const len = std.mem.readInt(u16, buf[3..5], .big);
    const total = 5 + @as(usize, len);
    if (buf.len < total) return null;
    return total;
}

/// Wall-clock time in Unix seconds, used to reject expired ACME server certs.
fn wallClockSeconds() i64 {
    if (comptime builtin.os.tag != .linux) return @divTrunc(@import("../substrate/platform.zig").realtimeMillis(), 1000);
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const remain = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..remain], list.items[n..]);
    list.shrinkRetainingCapacity(remain);
}

/// Encode a P-256 key pair as a SEC1 `EC PRIVATE KEY` PEM (RFC 5915), the form
/// nginx's ssl_certificate_key accepts. Returns a slice of `out`.
fn ecPrivateKeyPem(kp: ecdsa_p256.KeyPair, out: []u8) ![]const u8 {
    const priv = kp.secret_key.toBytes(); // 32-byte scalar
    const sec1 = kp.public_key.toUncompressedSec1(); // 0x04 ‖ x ‖ y (65 bytes)
    // ECPrivateKey ::= SEQUENCE { INTEGER 1, OCTET STRING priv,
    //   [0] namedCurve(prime256v1), [1] BIT STRING uncompressed-point }
    var der: [121]u8 = .{
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
    } ++ @as([32]u8, @splat(0)) // private scalar
    ++ [_]u8{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 } // [0] prime256v1
    ++ [_]u8{ 0xa1, 0x44, 0x03, 0x42, 0x00 } // [1] BIT STRING header (0 unused bits)
    ++ @as([65]u8, @splat(0)); // uncompressed point
    @memcpy(der[7..39], &priv);
    @memcpy(der[56..121], &sec1);
    return pem.encode(out, "EC PRIVATE KEY", &der) catch return error.NoSpaceLeft;
}

/// Owner-only (0o600) file mode for the POSIX TLS private key. This is umask-monotonic:
/// a umask can only *clear* bits, never add group/other permission, so the key is
/// never written group/world-readable regardless of the process umask. On targets
/// without a POSIX permission model use the native Windows private-DACL path
/// below. The discriminant is a `u0` `mode_t` (Windows and any `mode_t`-less
/// target, e.g. wasm freestanding), so `.fromMode` is only referenced where it exists.
const key_file_perms: std.Io.File.Permissions = if (std.posix.mode_t == u0 or builtin.os.tag == .windows)
    .default_file
else
    .fromMode(0o600);

/// Write the issued PEM chain to `path` atomically (temp file + rename via the
/// Io layer), so an nginx reload never reads a partial cert. The chain is public;
/// default permissions are fine. The containing dir should be kain-owned.
fn writeCertAtomic(io: std.Io, dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    try writeAtomic(io, dir, path, data, .default_file);
}

/// Write the TLS PRIVATE KEY to `path` atomically with owner-only (0o600) perms.
/// The atomic temp file is created with the key mode and renamed over the target,
/// which carries the mode with it — so on a shared host no other local user can
/// read the daemon's private key (impersonation/MITM), and a renewal never leaves
/// a world-readable key behind. Same durability as the chain writer (fsync+rename).
fn writeKeyAtomic(io: std.Io, dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return writeKeyAtomicWindows(io, dir, path, data);
    try writeAtomic(io, dir, path, data, key_file_perms);
}

fn writeKeyAtomicWindows(io: std.Io, dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const name = std.fs.path.basename(path);
    const parent = try os_runtime.openPrivateDirectoryWindows(io, dir, parent_path);
    defer parent.close(io);

    // If this is a renewal, harden the previous key before publication. An
    // exclusive open refuses a retained reader of a permissive old file.
    const old_key: ?std.Io.File = os_runtime.openExistingPrivateWindows(parent, name, .remediate) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (old_key) |file| file.close(io);

    var atomic = try parent.createFileAtomic(io, name, .{ .replace = true, .permissions = .default_file });
    defer atomic.deinit(io);
    // The temporary file inherits the private directory ACL before any key
    // data exists. Reopen it exclusively and install a protected file DACL,
    // matching the account-store snapshot custody path.
    try os_runtime.requireInheritedPrivateFileWindows(atomic.file);
    atomic.file.close(io);
    atomic.file_open = false;
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    atomic.file = try os_runtime.openExistingPrivateWindows(atomic.dir, &temp_name, .remediate_read_write);
    atomic.file_open = true;
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Atomic write with an explicit file mode: create an unnamed/temp file with
/// `perms`, stream + fsync the data, then atomically rename it over `path`. A
/// reader never sees a partial file, and the final file has exactly `perms`
/// (subject to umask). `.replace = true` intentionally makes a fresh inode, so
/// callers MUST pass the intended perms every time — the previous file's mode is
/// NOT inherited (this is why the key path must pass `key_file_perms`, not rely
/// on a pre-existing 0o600 that a rename would otherwise destroy).
fn writeAtomic(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    data: []const u8,
    perms: std.Io.File.Permissions,
) !void {
    var atomic = try dir.createFileAtomic(io, path, .{ .replace = true, .permissions = perms });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

// ---------------------------------------------------------------------------
// Tests (network paths are exercised live, not here; these cover pure logic)
// ---------------------------------------------------------------------------

test "Url.parse extracts host, default port, and path" {
    const u = try Url.parse("https://acme-v02.api.letsencrypt.org/directory");
    try std.testing.expectEqualStrings("acme-v02.api.letsencrypt.org", u.host);
    try std.testing.expectEqual(@as(u16, 443), u.port);
    try std.testing.expectEqualStrings("/directory", u.path);
}

test "Url.parse honors explicit port and bare authority" {
    const a = try Url.parse("https://example.com:8443/acme/new-order");
    try std.testing.expectEqual(@as(u16, 8443), a.port);
    try std.testing.expectEqualStrings("/acme/new-order", a.path);

    const b = try Url.parse("https://example.com");
    try std.testing.expectEqualStrings("example.com", b.host);
    try std.testing.expectEqualStrings("/", b.path);
}

test "Url.parse rejects non-https and empty authority" {
    try std.testing.expectError(error.NotHttps, Url.parse("http://example.com/"));
    try std.testing.expectError(error.InvalidUrl, Url.parse("https:///path"));
}

test "frameRecordLen needs a full record" {
    try std.testing.expectEqual(@as(?usize, null), frameRecordLen(&[_]u8{ 0x17, 0x03, 0x03 }));
    // header says 4 bytes of payload; only 2 present -> incomplete
    try std.testing.expectEqual(@as(?usize, null), frameRecordLen(&[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb }));
    // full 4-byte payload present -> total 9
    try std.testing.expectEqual(@as(?usize, 9), frameRecordLen(&[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd }));
}

test "consumePrefix shifts remaining bytes down" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try list.appendSlice(allocator, "ABCDEFG");
    consumePrefix(&list, 3);
    try std.testing.expectEqualStrings("DEFG", list.items);
}

test "acme writeKeyAtomic writes the TLS private key owner-only (0o600)" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const io = std.testing.io;

    // Pin umask so the resulting mode is deterministic, then restore it. Zig's
    // test runner executes test blocks sequentially on one thread, so mutating
    // the process-global umask here is race-free.
    const old_umask = if (comptime builtin.os.tag == .openbsd) std.c.umask(0o022) else std.os.linux.syscall1(.umask, 0o022);
    defer if (comptime builtin.os.tag == .openbsd) {
        _ = std.c.umask(old_umask);
    } else {
        _ = std.os.linux.syscall1(.umask, old_umask);
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeKeyAtomic(io, tmp.dir, "tls.key", "-----BEGIN EC PRIVATE KEY-----\ns\n-----END EC PRIVATE KEY-----\n");

    const st = try tmp.dir.statFile(io, "tls.key", .{});
    const mode = st.permissions.toMode() & 0o777;
    // The fix: owner rw only. A world/group-readable key on a shared host lets
    // any local user impersonate the daemon (MITM), which is the bug this guards.
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), mode);
    // Umask-independent security invariant: never any group/other permission.
    try std.testing.expectEqual(@as(std.posix.mode_t, 0), mode & 0o077);
}

test "Windows ACME private key publication requires a private parent and preserves owner-only ACL" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "broad", .default_dir);
    try std.testing.expectError(error.InsecurePermissions, writeKeyAtomic(io, tmp.dir, "broad/tls.key", "secret"));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "broad/tls.key", .{}));

    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(io);
    try writeKeyAtomic(io, tmp.dir, "private/tls.key", "first secret");
    {
        const secured = try os_runtime.openExistingPrivateWindows(tmp.dir, "private/tls.key", .verify_only);
        secured.close(io);
    }
    const first = try tmp.dir.readFileAlloc(io, "private/tls.key", std.testing.allocator, .limited(128));
    defer std.testing.allocator.free(first);
    try std.testing.expectEqualStrings("first secret", first);

    const held_reader = try tmp.dir.openFile(io, "private/tls.key", .{ .mode = .read_only });
    try std.testing.expectError(error.FileBusy, writeKeyAtomic(io, tmp.dir, "private/tls.key", "second secret"));
    held_reader.close(io);
    try writeKeyAtomic(io, tmp.dir, "private/tls.key", "second secret");
    const final = try tmp.dir.readFileAlloc(io, "private/tls.key", std.testing.allocator, .limited(128));
    defer std.testing.allocator.free(final);
    try std.testing.expectEqualStrings("second secret", final);
    const secured = try os_runtime.openExistingPrivateWindows(tmp.dir, "private/tls.key", .verify_only);
    secured.close(io);
}

test "Windows ACME HTTPS sends JWS request to pinned loopback and verifies CA" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("metrics_http.zig");
    const selfsign = @import("../proto/x509_selfsign.zig");
    const tls_server = @import("../crypto/tls_server.zig");
    const Win = struct {
        const invalid_socket = std.math.maxInt(usize);
        const FdSet = extern struct { count: u32, sockets: [64]usize };
        const Timeval = extern struct { seconds: i32, microseconds: i32 };
        extern "ws2_32" fn select(i32, ?*FdSet, ?*FdSet, ?*FdSet, *Timeval) callconv(.winapi) i32;
        extern "ws2_32" fn accept(usize, ?*anyopaque, ?*i32) callconv(.winapi) usize;
        extern "ws2_32" fn closesocket(usize) callconv(.winapi) i32;
        extern "ws2_32" fn ioctlsocket(usize, u32, *u32) callconv(.winapi) i32;
        extern "ws2_32" fn setsockopt(usize, i32, i32, *const anyopaque, i32) callconv(.winapi) i32;
        extern "ws2_32" fn recv(usize, [*]u8, i32, i32) callconv(.winapi) i32;
        extern "ws2_32" fn send(usize, [*]const u8, i32, i32) callconv(.winapi) i32;
    };
    const Worker = struct {
        listener: usize,
        chain: []const []const u8,
        key_pair: std.crypto.sign.Ed25519.KeyPair,
        expect_http: bool,
        request_seen: bool = false,
        fallback_seen: bool = false,
        failure: ?anyerror = null,

        fn readable(fd: usize, timeout_ms: u32) !bool {
            var reads = Win.FdSet{ .count = 1, .sockets = undefined };
            reads.sockets[0] = fd;
            var timeout = Win.Timeval{ .seconds = @intCast(timeout_ms / 1000), .microseconds = @intCast((timeout_ms % 1000) * 1000) };
            const ready = Win.select(0, &reads, null, null, &timeout);
            if (ready < 0) return error.TestUnexpectedResult;
            return ready != 0;
        }

        fn record(fd: usize, buffer: []u8) ![]u8 {
            var used: usize = 0;
            while (used < 5) {
                const got = Win.recv(fd, buffer[used..].ptr, @intCast(5 - used), 0);
                if (got <= 0) return error.TestUnexpectedResult;
                used += @intCast(got);
            }
            const record_len = 5 + @as(usize, std.mem.readInt(u16, buffer[3..5], .big));
            if (record_len > buffer.len) return error.TestUnexpectedResult;
            while (used < record_len) {
                const got = Win.recv(fd, buffer[used..].ptr, @intCast(record_len - used), 0);
                if (got <= 0) return error.TestUnexpectedResult;
                used += @intCast(got);
            }
            return buffer[0..record_len];
        }

        fn sendAll(fd: usize, bytes: []const u8) !void {
            var sent: usize = 0;
            while (sent < bytes.len) {
                const n = Win.send(fd, bytes[sent..].ptr, @intCast(bytes.len - sent), 0);
                if (n <= 0) return error.TestUnexpectedResult;
                sent += @intCast(n);
            }
        }

        fn run(self: *@This()) void {
            self.exchange() catch |err| {
                self.failure = err;
            };
        }

        fn exchange(self: *@This()) !void {
            if (!try readable(self.listener, 2000)) return error.TestUnexpectedResult;
            const fd = Win.accept(self.listener, null, null);
            if (fd == Win.invalid_socket) return error.TestUnexpectedResult;
            defer _ = Win.closesocket(fd);
            var blocking: u32 = 0;
            if (Win.ioctlsocket(fd, 0x8004667e, &blocking) != 0) return error.TestUnexpectedResult;
            const timeout_ms: u32 = 2000;
            if (Win.setsockopt(fd, 0xffff, 0x1006, &timeout_ms, @sizeOf(u32)) != 0 or
                Win.setsockopt(fd, 0xffff, 0x1005, &timeout_ms, @sizeOf(u32)) != 0) return error.TestUnexpectedResult;

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
                        try sendAll(fd, bytes);
                    },
                    .need_more => {},
                }
                if (!self.expect_http) {
                    // A rejected CA may only produce a fatal alert. No JWS
                    // request or fallback connection may follow it.
                    _ = record(fd, &buffer) catch null;
                    self.fallback_seen = try readable(self.listener, 250);
                    return;
                }
            }
            const request = try engine.decrypt(try record(fd, &buffer));
            defer std.heap.page_allocator.free(request);
            self.request_seen = std.mem.startsWith(u8, request, "POST /new-order HTTP/1.1\r\nHost: 127.0.0.1\r\n") and
                std.mem.indexOf(u8, request, "Content-Type: application/jose+json\r\n") != null and
                std.mem.endsWith(u8, request, "\r\n\r\n{\"protected\":\"nonce\"}");
            const response = try engine.encrypt("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nOK");
            defer std.heap.page_allocator.free(response);
            try sendAll(fd, response);
        }
    };
    const Static = struct {
        fn resolve(_: *anyopaque, _: []const u8, port: u16) anyerror!net.IpAddress {
            return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
        }
    };

    const allocator = std.testing.allocator;
    var snapshot = metrics.MetricsSnapshot.init(allocator);
    defer snapshot.deinit();
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();
    const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x68));
    var cert_buffer: [2048]u8 = undefined;
    const cert = try selfsign.buildSelfSigned(&cert_buffer, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x68, 1 },
        .key_pair = key_pair,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    var ctx: u8 = 0;
    const resolver = Resolver{ .ctx = &ctx, .resolveFn = Static.resolve };
    const url = Url{ .host = "127.0.0.1", .port = listener.port, .path = "/new-order" };
    const headers = [_]http1.Header{.{ .name = "Content-Type", .value = "application/jose+json" }};
    const body = "{\"protected\":\"nonce\"}";

    var trusted_worker = Worker{ .listener = listener.listen_fd, .chain = &chain, .key_pair = key_pair, .expect_http = true };
    const trusted_thread = try std.Thread.spawn(.{}, Worker.run, .{&trusted_worker});
    var trusted_joined = false;
    defer if (!trusted_joined) trusted_thread.join();
    const trusted = httpsRequest(allocator, resolver, &chain, "POST", url, &headers, body, 1024);
    defer if (trusted) |response| allocator.free(response) else |_| {};
    trusted_thread.join();
    trusted_joined = true;
    if (trusted_worker.failure) |err| return err;
    try std.testing.expect(trusted_worker.request_seen);
    try std.testing.expectEqualStrings("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nOK", try trusted);

    var untrusted_worker = Worker{ .listener = listener.listen_fd, .chain = &chain, .key_pair = key_pair, .expect_http = false };
    const untrusted_thread = try std.Thread.spawn(.{}, Worker.run, .{&untrusted_worker});
    var untrusted_joined = false;
    defer if (!untrusted_joined) untrusted_thread.join();
    const untrusted = httpsRequest(allocator, resolver, &.{}, "POST", url, &headers, body, 1024);
    defer if (untrusted) |response| allocator.free(response) else |_| {};
    untrusted_thread.join();
    untrusted_joined = true;
    if (untrusted_worker.failure) |err| return err;
    try std.testing.expectError(error.UnknownCa, untrusted);
    try std.testing.expect(!untrusted_worker.request_seen and !untrusted_worker.fallback_seen);
}

test "Windows TLS ACME loopback issuance serves HTTP-01 and publishes a private matching key" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const metrics = @import("metrics_http.zig");
    const listener = @import("acme_http01_listener.zig");
    const selfsign = @import("../proto/x509_selfsign.zig");
    const tls_server = @import("../crypto/tls_server.zig");
    const tls_certs = @import("tls_certs.zig");
    const jwk = @import("../proto/acme_jwk.zig");
    const challenge = @import("../proto/acme_challenge.zig");
    const base64url = @import("../proto/base64url.zig");
    const csr = @import("../proto/csr.zig");
    const order = @import("../proto/acme_order.zig");
    const x509 = @import("../crypto/x509.zig");

    const Win = struct {
        const invalid_socket = std.math.maxInt(usize);
        const SockAddr4 = extern struct {
            family: u16 = 2,
            port: u16,
            addr: [4]u8 = .{ 127, 0, 0, 1 },
            zero: [8]u8 = @splat(0),
        };
        const FdSet = extern struct { count: u32, sockets: [64]usize };
        const Timeval = extern struct { seconds: i32, microseconds: i32 };
        extern "ws2_32" fn select(i32, ?*FdSet, ?*FdSet, ?*FdSet, *Timeval) callconv(.winapi) i32;
        extern "ws2_32" fn accept(usize, ?*anyopaque, ?*i32) callconv(.winapi) usize;
        extern "ws2_32" fn closesocket(usize) callconv(.winapi) i32;
        extern "ws2_32" fn WSASocketW(i32, i32, i32, ?*anyopaque, u32, u32) callconv(.winapi) usize;
        extern "ws2_32" fn connect(usize, *const SockAddr4, i32) callconv(.winapi) i32;
        extern "ws2_32" fn ioctlsocket(usize, u32, *u32) callconv(.winapi) i32;
        extern "ws2_32" fn setsockopt(usize, i32, i32, *const anyopaque, i32) callconv(.winapi) i32;
        extern "ws2_32" fn recv(usize, [*]u8, i32, i32) callconv(.winapi) i32;
        extern "ws2_32" fn send(usize, [*]const u8, i32, i32) callconv(.winapi) i32;
    };
    const Ca = struct {
        socket: usize,
        port: u16,
        challenge_port: u16,
        api_cert: []const u8,
        api_key: std.crypto.sign.Ed25519.KeyPair,
        account_public_key: ecdsa_p256.PublicKey,
        expected_contact: []const u8,
        expected_finalize_payload: []const u8,
        issued_chain_pem: []const u8,
        expected_authorization: []const u8,
        steps_done: usize = 0,
        challenge_checked: bool = false,
        failure: ?anyerror = null,

        fn sendAll(fd: usize, bytes: []const u8) !void {
            var sent: usize = 0;
            while (sent < bytes.len) {
                const n = Win.send(fd, bytes[sent..].ptr, @intCast(bytes.len - sent), 0);
                if (n <= 0) return error.TestUnexpectedResult;
                sent += @intCast(n);
            }
        }

        fn readable(fd: usize) !bool {
            var reads = Win.FdSet{ .count = 1, .sockets = undefined };
            reads.sockets[0] = fd;
            var timeout = Win.Timeval{ .seconds = 5, .microseconds = 0 };
            const ready = Win.select(0, &reads, null, null, &timeout);
            if (ready < 0) return error.TestUnexpectedResult;
            return ready != 0;
        }

        fn record(fd: usize, buffer: []u8) ![]u8 {
            var used: usize = 0;
            while (used < 5) {
                const got = Win.recv(fd, buffer[used..].ptr, @intCast(5 - used), 0);
                if (got <= 0) return error.TestUnexpectedResult;
                used += @intCast(got);
            }
            const len = 5 + @as(usize, std.mem.readInt(u16, buffer[3..5], .big));
            if (len > buffer.len) return error.TestUnexpectedResult;
            while (used < len) {
                const got = Win.recv(fd, buffer[used..].ptr, @intCast(len - used), 0);
                if (got <= 0) return error.TestUnexpectedResult;
                used += @intCast(got);
            }
            return buffer[0..len];
        }

        fn stringMember(value: std.json.Value, name: []const u8) ![]const u8 {
            if (value != .object) return error.TestUnexpectedResult;
            const member = value.object.get(name) orelse return error.TestUnexpectedResult;
            if (member != .string) return error.TestUnexpectedResult;
            return member.string;
        }

        fn checkJws(self: *@This(), step: usize, request: []const u8) !void {
            const head_end = std.mem.indexOf(u8, request, "\r\n\r\n") orelse return error.TestUnexpectedResult;
            const body = request[head_end + 4 ..];
            var flattened = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, body, .{});
            defer flattened.deinit();
            const protected_b64 = try stringMember(flattened.value, "protected");
            const payload_b64 = try stringMember(flattened.value, "payload");
            const signature_b64 = try stringMember(flattened.value, "signature");

            var protected_buf: [1024]u8 = undefined;
            const protected_json = try base64url.decode(&protected_buf, protected_b64);
            var protected = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, protected_json, .{});
            defer protected.deinit();
            if (!std.mem.eql(u8, try stringMember(protected.value, "alg"), "ES256")) return error.TestUnexpectedResult;
            var nonce_buf: [24]u8 = undefined;
            const nonce = try std.fmt.bufPrint(&nonce_buf, "n{d}", .{step - 1});
            if (!std.mem.eql(u8, try stringMember(protected.value, "nonce"), nonce)) return error.TestUnexpectedResult;
            const first_space = std.mem.indexOfScalar(u8, request, ' ') orelse return error.TestUnexpectedResult;
            const rest = request[first_space + 1 ..];
            const path_end = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.TestUnexpectedResult;
            var url_buf: [160]u8 = undefined;
            const expected_url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}{s}", .{ self.port, rest[0..path_end] });
            if (!std.mem.eql(u8, try stringMember(protected.value, "url"), expected_url)) return error.TestUnexpectedResult;
            if (step == 1) {
                const key = protected.value.object.get("jwk") orelse return error.TestUnexpectedResult;
                if (!std.mem.eql(u8, try stringMember(key, "kty"), "EC") or
                    !std.mem.eql(u8, try stringMember(key, "crv"), "P-256")) return error.TestUnexpectedResult;
                const point = self.account_public_key.toUncompressedSec1();
                var x_buf: [jwk.thumbprint_b64_len]u8 = undefined;
                var y_buf: [jwk.thumbprint_b64_len]u8 = undefined;
                const x = std.base64.url_safe_no_pad.Encoder.encode(&x_buf, point[1..33]);
                const y = std.base64.url_safe_no_pad.Encoder.encode(&y_buf, point[33..65]);
                if (!std.mem.eql(u8, try stringMember(key, "x"), x) or
                    !std.mem.eql(u8, try stringMember(key, "y"), y)) return error.TestUnexpectedResult;
            } else {
                var kid_buf: [160]u8 = undefined;
                const kid = try std.fmt.bufPrint(&kid_buf, "https://127.0.0.1:{d}/acct/9", .{self.port});
                if (!std.mem.eql(u8, try stringMember(protected.value, "kid"), kid)) return error.TestUnexpectedResult;
            }

            var sig_buf: [ecdsa_p256.raw_signature_length]u8 = undefined;
            const sig_bytes = try base64url.decode(&sig_buf, signature_b64);
            if (sig_bytes.len != sig_buf.len) return error.TestUnexpectedResult;
            var signing_buf: [8192]u8 = undefined;
            const signing_input = try std.fmt.bufPrint(&signing_buf, "{s}.{s}", .{ protected_b64, payload_b64 });
            if (!ecdsa_p256.verify(ecdsa_p256.Signature.fromBytes(sig_buf), signing_input, self.account_public_key))
                return error.TestUnexpectedResult;

            var payload_buf: [8192]u8 = undefined;
            const payload = try base64url.decode(&payload_buf, payload_b64);
            if (step == 1 or step == 2) {
                var parsed_payload = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, payload, .{});
                defer parsed_payload.deinit();
                if (parsed_payload.value != .object) return error.TestUnexpectedResult;
                if (step == 1) {
                    const agreed = parsed_payload.value.object.get("termsOfServiceAgreed") orelse return error.TestUnexpectedResult;
                    const contacts = parsed_payload.value.object.get("contact") orelse return error.TestUnexpectedResult;
                    if (agreed != .bool or !agreed.bool or contacts != .array or contacts.array.items.len != 1 or
                        contacts.array.items[0] != .string or
                        !std.mem.eql(u8, contacts.array.items[0].string, self.expected_contact))
                        return error.TestUnexpectedResult;
                } else {
                    const identifiers = parsed_payload.value.object.get("identifiers") orelse return error.TestUnexpectedResult;
                    if (identifiers != .array or identifiers.array.items.len != 1) return error.TestUnexpectedResult;
                    const identifier = identifiers.array.items[0];
                    if (!std.mem.eql(u8, try stringMember(identifier, "type"), "dns") or
                        !std.mem.eql(u8, try stringMember(identifier, "value"), "localhost"))
                        return error.TestUnexpectedResult;
                }
            }
            if (step == 6 and !std.mem.eql(u8, payload, self.expected_finalize_payload)) return error.TestUnexpectedResult;
            if (step == 4 and !std.mem.eql(u8, payload, "{}")) return error.TestUnexpectedResult;
            if ((step == 3 or step == 5 or step >= 7) and payload.len != 0) return error.TestUnexpectedResult;
        }

        fn checkChallenge(self: *@This()) !void {
            const fd = Win.WSASocketW(2, 1, 6, null, 0, 1);
            if (fd == Win.invalid_socket) return error.TestUnexpectedResult;
            defer _ = Win.closesocket(fd);
            const address = Win.SockAddr4{ .port = std.mem.nativeToBig(u16, self.challenge_port) };
            if (Win.connect(fd, &address, @sizeOf(Win.SockAddr4)) != 0) return error.TestUnexpectedResult;
            const timeout_ms: u32 = 2000;
            if (Win.setsockopt(fd, 0xffff, 0x1006, &timeout_ms, @sizeOf(u32)) != 0) return error.TestUnexpectedResult;
            try sendAll(fd, "GET /.well-known/acme-challenge/tok123 HTTP/1.1\r\nHost: localhost\r\n\r\n");
            var response: [4096]u8 = undefined;
            var used: usize = 0;
            while (used < response.len) {
                const got = Win.recv(fd, response[used..].ptr, @intCast(response.len - used), 0);
                if (got <= 0) return error.TestUnexpectedResult;
                used += @intCast(got);
                if (std.mem.indexOf(u8, response[0..used], self.expected_authorization) != null) break;
            }
            if (!std.mem.startsWith(u8, response[0..used], "HTTP/1.1 200 OK\r\n") or
                std.mem.indexOf(u8, response[0..used], self.expected_authorization) == null)
                return error.TestUnexpectedResult;
            self.challenge_checked = true;
        }

        fn responseBody(self: *@This(), step: usize, out: []u8) ![]const u8 {
            const base = try std.fmt.bufPrint(out, "https://127.0.0.1:{d}", .{self.port});
            var body: [4096]u8 = undefined;
            const result = switch (step) {
                0 => try std.fmt.bufPrint(&body, "{{\"newNonce\":\"{s}/nonce\",\"newAccount\":\"{s}/acct\",\"newOrder\":\"{s}/order\",\"revokeCert\":\"{s}/revoke\",\"keyChange\":\"{s}/keychange\"}}", .{ base, base, base, base, base }),
                1 => "{\"status\":\"valid\"}",
                2 => try std.fmt.bufPrint(&body, "{{\"status\":\"pending\",\"identifiers\":[{{\"type\":\"dns\",\"value\":\"localhost\"}}],\"authorizations\":[\"{s}/authz/1\"],\"finalize\":\"{s}/finalize/1\"}}", .{ base, base }),
                3, 4 => try std.fmt.bufPrint(&body, "{{\"status\":\"pending\",\"identifier\":{{\"type\":\"dns\",\"value\":\"localhost\"}},\"challenges\":[{{\"type\":\"http-01\",\"url\":\"{s}/chal/1\",\"token\":\"tok123\",\"status\":\"pending\"}}]}}", .{base}),
                5 => try std.fmt.bufPrint(&body, "{{\"status\":\"valid\",\"identifier\":{{\"type\":\"dns\",\"value\":\"localhost\"}},\"challenges\":[{{\"type\":\"http-01\",\"url\":\"{s}/chal/1\",\"token\":\"tok123\",\"status\":\"valid\"}}]}}", .{base}),
                6, 7 => try std.fmt.bufPrint(&body, "{{\"status\":\"processing\",\"identifiers\":[{{\"type\":\"dns\",\"value\":\"localhost\"}}],\"authorizations\":[\"{s}/authz/1\"],\"finalize\":\"{s}/finalize/1\"}}", .{ base, base }),
                8 => try std.fmt.bufPrint(&body, "{{\"status\":\"valid\",\"identifiers\":[{{\"type\":\"dns\",\"value\":\"localhost\"}}],\"authorizations\":[\"{s}/authz/1\"],\"finalize\":\"{s}/finalize/1\",\"certificate\":\"{s}/cert/1\"}}", .{ base, base, base }),
                9 => self.issued_chain_pem,
                else => return error.TestUnexpectedResult,
            };
            if (result.len > out.len) return error.TestUnexpectedResult;
            @memcpy(out[0..result.len], result);
            return out[0..result.len];
        }

        fn exchange(self: *@This(), step: usize) !void {
            if (!try readable(self.socket)) return error.TestUnexpectedResult;
            const fd = Win.accept(self.socket, null, null);
            if (fd == Win.invalid_socket) return error.TestUnexpectedResult;
            defer _ = Win.closesocket(fd);
            var blocking: u32 = 0;
            if (Win.ioctlsocket(fd, 0x8004667e, &blocking) != 0) return error.TestUnexpectedResult;
            const timeout_ms: u32 = 3000;
            if (Win.setsockopt(fd, 0xffff, 0x1006, &timeout_ms, @sizeOf(u32)) != 0 or
                Win.setsockopt(fd, 0xffff, 0x1005, &timeout_ms, @sizeOf(u32)) != 0) return error.TestUnexpectedResult;
            var engine = try tls_server.Server.init(std.heap.page_allocator, .{
                .cert_chain = &.{self.api_cert},
                .signing_key = self.api_key,
            });
            defer engine.deinit();
            var record_buf: [max_tls_record]u8 = undefined;
            while (!engine.handshakeDone()) {
                switch (try engine.feed(try record(fd, &record_buf))) {
                    .bytes_to_send => |bytes| {
                        defer std.heap.page_allocator.free(bytes);
                        try sendAll(fd, bytes);
                    },
                    .need_more => {},
                }
            }
            const request = try engine.decrypt(try record(fd, &record_buf));
            defer std.heap.page_allocator.free(request);
            const paths = [_][]const u8{
                "GET /directory HTTP/1.1\r\n",   "POST /acct HTTP/1.1\r\n",
                "POST /order HTTP/1.1\r\n",      "POST /authz/1 HTTP/1.1\r\n",
                "POST /chal/1 HTTP/1.1\r\n",     "POST /authz/1 HTTP/1.1\r\n",
                "POST /finalize/1 HTTP/1.1\r\n", "POST /order/1 HTTP/1.1\r\n",
                "POST /order/1 HTTP/1.1\r\n",    "POST /cert/1 HTTP/1.1\r\n",
            };
            if (!std.mem.startsWith(u8, request, paths[step])) return error.TestUnexpectedResult;
            if (step != 0) {
                if (std.mem.indexOf(u8, request, "Content-Type: application/jose+json\r\n") == null)
                    return error.TestUnexpectedResult;
                try self.checkJws(step, request);
            }
            // The state machine publishes the token after the challenge POST
            // returns. A real CA validates asynchronously; do so on the next
            // authorization poll, after the runner has handled that effect.
            if (step == 5) try self.checkChallenge();

            var body_buf: [4096]u8 = undefined;
            const body = try self.responseBody(step, &body_buf);
            var location_buf: [160]u8 = undefined;
            const location: []const u8 = switch (step) {
                1 => try std.fmt.bufPrint(&location_buf, "Location: https://127.0.0.1:{d}/acct/9\r\n", .{self.port}),
                2 => try std.fmt.bufPrint(&location_buf, "Location: https://127.0.0.1:{d}/order/1\r\n", .{self.port}),
                else => "",
            };
            var http_buf: [8192]u8 = undefined;
            const http_response = try std.fmt.bufPrint(&http_buf, "HTTP/1.1 {s}\r\nReplay-Nonce: n{d}\r\n{s}Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
                if (step == 1 or step == 2) @as([]const u8, "201 Created") else "200 OK",
                step,
                location,
                body.len,
                body,
            });
            const encrypted = try engine.encrypt(http_response);
            defer std.heap.page_allocator.free(encrypted);
            try sendAll(fd, encrypted);
            self.steps_done += 1;
        }

        fn run(self: *@This()) void {
            for (0..10) |step| self.exchange(step) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    const Static = struct {
        fn resolve(_: *anyopaque, host: []const u8, port: u16) anyerror!net.IpAddress {
            if (!std.mem.eql(u8, host, "127.0.0.1")) return error.TestUnexpectedResult;
            return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var snapshot = metrics.MetricsSnapshot.init(allocator);
    defer snapshot.deinit();
    var ca_listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer ca_listener.shutdown();
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();
    var challenge_listener = try listener.ChallengeServer.init(&store, 0);
    defer challenge_listener.shutdown();
    try challenge_listener.spawn();

    const api_key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x69));
    var api_der_buf: [2048]u8 = undefined;
    const api_cert = try selfsign.buildSelfSigned(&api_der_buf, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x69, 1 },
        .key_pair = api_key,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    const account_key = ecdsa_p256.KeyPair.generate(io);
    const cert_key = ecdsa_p256.KeyPair.generate(io);
    const issuer_key = ecdsa_p256.KeyPair.generate(io);
    var issuer_der_buf: [2048]u8 = undefined;
    const issuer_der = try selfsign.buildSelfSignedEcdsaP256(&issuer_der_buf, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x70, 1 },
        .key_pair = issuer_key,
        .is_ca = true,
    });
    var leaf_der_buf: [2048]u8 = undefined;
    const leaf_der = try selfsign.buildEcdsaP256IssuedBy(&leaf_der_buf, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x70, 2 },
        .key_pair = cert_key,
        .dns_names = &.{"localhost"},
    }, issuer_key);
    const leaf_view = try x509.parse(leaf_der);
    var cri_buf: [4096]u8 = undefined;
    const cri = try csr.certificationRequestInfo(&cri_buf, .{
        .common_name = "localhost",
        .dns_names = &.{"localhost"},
        .spki_der = leaf_view.spki_der,
    });
    const csr_signature = try ecdsa_p256.sign(cri, cert_key);
    var csr_sig_buf: [80]u8 = undefined;
    const csr_sig_der = try ecdsa_p256.signatureToDer(csr_signature, &csr_sig_buf);
    const ecdsa_sha256_sig_alg = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
    var csr_buf: [4096]u8 = undefined;
    const expected_csr = try csr.assemble(&csr_buf, cri, &ecdsa_sha256_sig_alg, csr_sig_der);
    var finalize_buf: [8192]u8 = undefined;
    const expected_finalize_payload = try order.buildFinalize(&finalize_buf, expected_csr);
    var leaf_pem_buf: [4096]u8 = undefined;
    var issuer_pem_buf: [4096]u8 = undefined;
    const leaf_pem = try pem.encode(&leaf_pem_buf, "CERTIFICATE", leaf_der);
    const issuer_pem = try pem.encode(&issuer_pem_buf, "CERTIFICATE", issuer_der);
    var fullchain_buf: [8192]u8 = undefined;
    const fullchain = try std.fmt.bufPrint(&fullchain_buf, "{s}{s}", .{ leaf_pem, issuer_pem });

    var account_es = Es256Signer.init(account_key);
    const account_public = account_es.signer();
    var thumb_digest: [32]u8 = undefined;
    jwk.thumbprintEc(account_public.public_key_x, account_public.public_key_y, &thumb_digest);
    var thumb_buf: [jwk.thumbprint_b64_len]u8 = undefined;
    const thumb = std.base64.url_safe_no_pad.Encoder.encode(&thumb_buf, &thumb_digest);
    var authorization_buf: [512]u8 = undefined;
    const expected_authorization = try challenge.keyAuthorization("tok123", thumb, &authorization_buf);

    var ca = Ca{
        .socket = ca_listener.listen_fd,
        .port = ca_listener.port,
        .challenge_port = challenge_listener.port,
        .api_cert = api_cert,
        .api_key = api_key,
        .account_public_key = account_key.public_key,
        .expected_contact = "mailto:admin@localhost",
        .expected_finalize_payload = expected_finalize_payload,
        .issued_chain_pem = fullchain,
        .expected_authorization = expected_authorization,
    };
    const ca_thread = try std.Thread.spawn(.{}, Ca.run, .{&ca});
    var ca_joined = false;
    defer if (!ca_joined) ca_thread.join();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(io);
    const tmp_path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(tmp_path);
    const cert_path = try std.fs.path.join(allocator, &.{ tmp_path, "fullchain.pem" });
    defer allocator.free(cert_path);
    const key_path = try std.fs.path.join(allocator, &.{ tmp_path, "private", "server.key" });
    defer allocator.free(key_path);
    const directory_url = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/directory", .{ca_listener.port});
    defer allocator.free(directory_url);
    var resolver_ctx: u8 = 0;
    const result = issue(allocator, io, .{
        .directory_url = directory_url,
        .domains = &.{"localhost"},
        .contacts = &.{"mailto:admin@localhost"},
        .trust_anchors = &.{api_cert},
        .cert_out_path = cert_path,
        .key_out_path = key_path,
    }, account_key, cert_key, &store, .{ .ctx = &resolver_ctx, .resolveFn = Static.resolve });
    ca_thread.join();
    ca_joined = true;
    if (ca.failure) |err| return err;
    try std.testing.expectEqual(@as(usize, 10), ca.steps_done);
    try std.testing.expect(ca.challenge_checked);
    const issued = try result;
    try std.testing.expectEqual(acme.State.done, issued.state);
    try std.testing.expect(issued.cert_written);
    var loaded = try tls_certs.loadOrBootstrap(allocator, io, .{ .cert_path = cert_path, .key_path = key_path });
    defer loaded.deinit(allocator);
    try std.testing.expectEqual(tls_certs.KeyKind.ecdsa_p256, loaded.key_kind);
    try std.testing.expectEqual(@as(usize, 2), loaded.cert_chain.len);
    try std.testing.expectEqualSlices(u8, leaf_der, loaded.cert_chain[0]);
    try std.testing.expectEqualSlices(u8, issuer_der, loaded.cert_chain[1]);
    try std.testing.expectEqualSlices(u8, &cert_key.public_key.toUncompressedSec1(), &loaded.ecdsa_p256_signing_key.?.public_key.toUncompressedSec1());
    const secured = try os_runtime.openExistingPrivateWindows(std.Io.Dir.cwd(), key_path, .verify_only);
    secured.close(io);
}

test "acme writeCertAtomic leaves the public cert chain default-readable" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const io = std.testing.io;

    const old_umask = if (comptime builtin.os.tag == .openbsd) std.c.umask(0o022) else std.os.linux.syscall1(.umask, 0o022);
    defer if (comptime builtin.os.tag == .openbsd) {
        _ = std.c.umask(old_umask);
    } else {
        _ = std.os.linux.syscall1(.umask, old_umask);
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeCertAtomic(io, tmp.dir, "fullchain.pem", "-----BEGIN CERTIFICATE-----\np\n-----END CERTIFICATE-----\n");

    const st = try tmp.dir.statFile(io, "fullchain.pem", .{});
    const mode = st.permissions.toMode() & 0o777;
    // The public chain keeps default_file (0o666) & ~umask(0o022) = 0o644 — the
    // private-key hardening must NOT lock down the chain nginx/peers must read.
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o644), mode);
}

test "applyToml overlays runner acme tunables" {
    const allocator = std.testing.allocator;
    const src =
        \\[acme]
        \\max_steps = 128
        \\debug = true
        \\max_response_bytes = 1048576
        \\error_body_preview_bytes = 1024
        \\resolv_conf_max_bytes = 131072
        \\dns_port = 5353
    ;
    var doc = try toml.parse(allocator, src);
    defer doc.deinit(allocator);

    var cfg: IssueConfig = .{
        .directory_url = "https://x/dir",
        .domains = &.{"x.test"},
        .trust_anchors = &.{},
        .cert_out_path = "/p/c.pem",
    };
    applyToml(&cfg, &doc);

    try std.testing.expectEqual(@as(usize, 128), cfg.max_steps);
    try std.testing.expectEqual(true, cfg.debug);
    try std.testing.expectEqual(@as(usize, 1048576), cfg.max_response_bytes);
    try std.testing.expectEqual(@as(usize, 1024), cfg.error_body_preview_bytes);
    try std.testing.expectEqual(@as(usize, 131072), cfg.resolv_conf_max_bytes);
    try std.testing.expectEqual(@as(u16, 5353), cfg.dns_port);
}

test "applyToml leaves runner defaults when acme table absent" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[tls]\ndebug_log = true\n");
    defer doc.deinit(allocator);

    var cfg: IssueConfig = .{
        .directory_url = "https://x/dir",
        .domains = &.{"x.test"},
        .trust_anchors = &.{},
        .cert_out_path = "/p/c.pem",
    };
    applyToml(&cfg, &doc);

    try std.testing.expectEqual(@as(usize, 64), cfg.max_steps);
    try std.testing.expectEqual(false, cfg.debug);
    try std.testing.expectEqual(default_max_response_bytes, cfg.max_response_bytes);
    try std.testing.expectEqual(default_error_body_preview_bytes, cfg.error_body_preview_bytes);
    try std.testing.expectEqual(default_resolv_conf_max_bytes, cfg.resolv_conf_max_bytes);
    try std.testing.expectEqual(default_dns_port, cfg.dns_port);
}

test "v6 nameserver sockaddr is built with INET6 family, big-endian port, and raw bytes" {
    // Mirrors the construction inside queryOneServer6: this proves the v6 path's
    // sockaddr is shaped correctly (family/port/addr/scope) and is reachable —
    // it is no longer skipped with `continue` as the old loop did.
    const ns_v6: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }; // ::1
    const sa = posix.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 53),
        .flowinfo = 0,
        .addr = ns_v6,
        .scope_id = 0,
    };
    try std.testing.expectEqual(@as(@TypeOf(sa.family), posix.AF.INET6), sa.family);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 53), sa.port);
    try std.testing.expectEqual(@as(u32, 0), sa.flowinfo);
    try std.testing.expectEqual(@as(u32, 0), sa.scope_id);
    try std.testing.expectEqualSlices(u8, &ns_v6, &sa.addr);
}

test "udpSocket opens an AF_INET6 datagram socket" {
    // The v6 transport must actually open an IPv6 UDP socket (the gap was that
    // this path didn't exist). Skip only if the kernel/sandbox lacks IPv6.
    const fd = if (comptime builtin.os.tag == .openbsd)
        try @import("native_network.zig").socket(posix.AF.INET6, true, false)
    else
        udpSocket(posix.AF.INET6) catch return error.SkipZigTest;
    closeFd(fd);
}

fn nativeDnsFixture() !void {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    const sys = posix.system;
    const Responder = struct {
        fd: i32,
        served: usize = 0,
        fn run(self: *@This()) void {
            for (0..3) |index| {
                var bytes: [dns.max_message_len]u8 = undefined;
                var peer: posix.sockaddr.in6 = undefined;
                var len: posix.socklen_t = @sizeOf(@TypeOf(peer));
                const got = sys.recvfrom(self.fd, &bytes, bytes.len, 0, @ptrCast(&peer), &len);
                if (posix.errno(got) != .SUCCESS) return;
                const question = dns.parseMessage(1, 0, bytes[0..@intCast(got)]) catch return;
                if (question.question_count != 1) return;
                const q = question.questions[0];
                var wire: [dns.max_message_len]u8 = undefined;
                const reply = dns.encodeMessage(&wire, .{
                    .id = question.header.id,
                    .response = true,
                    .questions = &.{.{ .name = q.name.slice(), .qtype = q.qtype }},
                    .answers = &.{.{ .name = q.name.slice(), .rr_type = .a, .ttl = 30, .data = .{ .a = .{ 203, 0, 113, 7 } } }},
                }) catch return;
                // Valid framing/ID/question cannot make a truncated or error
                // response authoritative, even when it contains an address.
                if (index == 1) wire[2] |= 0x02;
                if (index == 2) wire[3] |= 0x03;
                const sent = sys.sendto(self.fd, reply.ptr, reply.len, 0, @ptrCast(&peer), len);
                if (posix.errno(sent) != .SUCCESS or sent != reply.len) return;
                self.served += 1;
            }
        }
    };
    const fd = try @import("native_network.zig").socket(posix.AF.INET6, true, false);
    defer closeFd(fd);
    try @import("native_network.zig").setTimeout(fd, 1000);
    var loopback: [16]u8 = @splat(0);
    loopback[15] = 1;
    var address = posix.sockaddr.in6{ .addr = loopback, .port = 0, .scope_id = 0, .flowinfo = 0 };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))));
    var len: posix.socklen_t = @sizeOf(@TypeOf(address));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&address), &len)));
    var responder = Responder{ .fd = fd };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    var joined = false;
    defer if (!joined) thread.join();
    var query_buf: [dns.max_message_len]u8 = undefined;
    const query = try dns.encodeQuery(&query_buf, 0x4242, "host.test", .a);
    const port = std.mem.bigToNative(u16, address.port);
    try std.testing.expectEqual(@as(?[4]u8, .{ 203, 0, 113, 7 }), try queryOneServer6(loopback, query, port));
    try std.testing.expectEqual(@as(?[4]u8, null), try queryOneServer6(loopback, query, port));
    try std.testing.expectEqual(@as(?[4]u8, null), try queryOneServer6(loopback, query, port));
    thread.join();
    joined = true;
    try std.testing.expectEqual(@as(usize, 3), responder.served);
}

test "queryOneServer6 round-trips an A record against a ::1 DNS responder" {
    if (comptime builtin.os.tag == .openbsd) {
        try nativeDnsFixture();
    } else if (comptime builtin.os.tag == .linux) {
        // End-to-end proof the v6 path opens a socket, connects, sends the query,
        // and parses the reply — exercising exactly queryOneServer6 -> exchangeQuery.
        // A real UDP/IPv6 loopback responder answers with one A record. If the
        // sandbox has no usable IPv6 loopback, skip rather than fail.
        const srv = udpSocket(posix.AF.INET6) catch return error.SkipZigTest;
        defer closeFd(srv);

        var bind_sa = linux.sockaddr.in6{
            .port = 0, // ephemeral
            .flowinfo = 0,
            .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, // ::1
            .scope_id = 0,
        };
        if (posix.errno(linux.bind(srv, @ptrCast(&bind_sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
            return error.SkipZigTest; // no IPv6 loopback in this environment

        // Recover the kernel-assigned ephemeral port.
        var name_sa: linux.sockaddr.in6 = undefined;
        var name_len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        if (posix.errno(linux.getsockname(srv, @ptrCast(&name_sa), &name_len)) != .SUCCESS)
            return error.SkipZigTest;
        const bound_port = std.mem.bigToNative(u16, name_sa.port);

        // Build the client query the same way systemResolveA does.
        var query_buf: [dns.max_message_len]u8 = undefined;
        const query = try dns.encodeQuery(&query_buf, 0x4242, "host.test", .a);

        // Pre-stage the canned A-record response so we can reply the moment the
        // query lands (single-threaded: receive, then send, then parse).
        var resp_buf: [dns.max_message_len]u8 = undefined;
        const answers = [_]dns.Answer{.{
            .name = "host.test",
            .rr_type = .a,
            .ttl = 60,
            .data = .{ .a = .{ 203, 0, 113, 7 } },
        }};
        const questions = [_]dns.Query{.{ .name = "host.test", .qtype = .a }};
        const response = try dns.encodeMessage(&resp_buf, .{
            .id = 0x4242,
            .response = true,
            .recursion_available = true,
            .questions = &questions,
            .answers = &answers,
        });

        // Client side: connected UDP/IPv6 socket to our responder, send query.
        const cli = try udpSocket(posix.AF.INET6);
        defer closeFd(cli);
        var dst_sa = linux.sockaddr.in6{
            .port = std.mem.nativeToBig(u16, bound_port),
            .flowinfo = 0,
            .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .scope_id = 0,
        };
        if (posix.errno(linux.connect(cli, @ptrCast(&dst_sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
            return error.SkipZigTest;
        if (posix.errno(linux.write(cli, query.ptr, query.len)) != .SUCCESS) return error.SkipZigTest;

        // Server side: receive the query, reply to the sender with the A record.
        var in_buf: [dns.max_message_len]u8 = undefined;
        var from_sa: linux.sockaddr.in6 = undefined;
        var from_len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        const rc = linux.recvfrom(srv, &in_buf, in_buf.len, 0, @ptrCast(&from_sa), &from_len);
        if (posix.errno(rc) != .SUCCESS) return error.SkipZigTest;
        if (posix.errno(linux.sendto(srv, response.ptr, response.len, 0, @ptrCast(&from_sa), from_len)) != .SUCCESS)
            return error.SkipZigTest;

        // Client reads + parses the reply exactly like exchangeQuery does.
        var reply_buf: [dns.max_message_len]u8 = undefined;
        const n_rc = linux.read(cli, &reply_buf, reply_buf.len);
        try std.testing.expectEqual(linux.E.SUCCESS, posix.errno(n_rc));
        const n: usize = @intCast(n_rc);
        const msg = try dns.parseMessage(1, dns.max_cache_addrs, reply_buf[0..n]);
        var found: ?[4]u8 = null;
        for (msg.answerSlice()) |rr| switch (rr.data) {
            .a => |ipv4| found = ipv4,
            else => {},
        };
        try std.testing.expectEqual(@as(?[4]u8, .{ 203, 0, 113, 7 }), found);
    } else return error.SkipZigTest;
}

test {
    std.testing.refAllDecls(@This());
}

test "TLS client fatal transport: acme_runner socket writer preserves control custody" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try tls_client_failure.testFatalTransportProof(true, writeAll);
}
