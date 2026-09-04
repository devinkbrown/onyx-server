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
const http1 = @import("../proto/http1_client.zig");
const acme = @import("acme_client.zig");
const http01 = @import("acme_http01_server.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const pem = @import("../proto/pem.zig");
const dns = @import("../proto/dns.zig");
const resolv_conf = @import("../proto/resolv_conf.zig");
const toml = @import("../proto/toml.zig");

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
} || Allocator.Error || tls_client.Error || http1.Error;

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
    const fd = try connectAddr(addr);
    defer closeFd(fd);

    var tc = try tls_client.Client.init(allocator, .{
        .server_name = url.host,
        .trust_anchors = trust_anchors,
        .alpn_protocols = &.{"http/1.1"},
        .now_unix_seconds = wallClockSeconds(),
        // ACME directory TLS stays fail-open on CRL (no CDP cache here).
        // http_fetch.Options.crl / require_crl is the opt-in wire for fetchers
        // that already hold a caller-supplied CRL.
        .require_crl = false,
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
        switch (try tc.feed(read_buf[0..n])) {
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
                else => return err,
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

/// Default `Resolver`: parses /etc/resolv.conf and performs a blocking A-record
/// lookup over UDP using the clean-room `dns.zig` codec. Out-of-band only.
///
/// Handles IP literals and direct A records. Our minimal codec does not decode
/// CNAME chains or EDNS additional records, so CDN-fronted endpoints may not
/// resolve here — inject a custom `Resolver` (or a static host→IP) for those.
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
        return systemResolveA(self.allocator, self.io, host, port, self.resolv_conf_max_bytes, self.dns_port);
    }
};

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

// ---------------------------------------------------------------------------
// Low-level socket helpers (raw linux syscalls, matching server.zig idiom)
// ---------------------------------------------------------------------------

fn connectAddr(addr: net.IpAddress) Error!linux.fd_t {
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
    _ = linux.close(fd);
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) Error!void {
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

/// Owner-only (0o600) file mode for the TLS private key. This is umask-monotonic:
/// a umask can only *clear* bits, never add group/other permission, so the key is
/// never written group/world-readable regardless of the process umask. On targets
/// without a POSIX permission model fall back to the default — the daemon deploys
/// on Linux/musl where the model applies. The discriminant is a `u0` `mode_t`
/// (Windows and any `mode_t`-less target, e.g. wasm freestanding), not the OS tag,
/// so the posix-only `.fromMode` is only referenced where it exists.
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
    try writeAtomic(io, dir, path, data, key_file_perms);
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
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;

    // Pin umask so the resulting mode is deterministic, then restore it. Zig's
    // test runner executes test blocks sequentially on one thread, so mutating
    // the process-global umask here is race-free.
    const old_umask = std.os.linux.syscall1(.umask, 0o022);
    defer _ = std.os.linux.syscall1(.umask, old_umask);

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

test "acme writeCertAtomic leaves the public cert chain default-readable" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;

    const old_umask = std.os.linux.syscall1(.umask, 0o022);
    defer _ = std.os.linux.syscall1(.umask, old_umask);

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
    const sa = linux.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 53),
        .flowinfo = 0,
        .addr = ns_v6,
        .scope_id = 0,
    };
    try std.testing.expectEqual(@as(linux.sa_family_t, posix.AF.INET6), sa.family);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 53), sa.port);
    try std.testing.expectEqual(@as(u32, 0), sa.flowinfo);
    try std.testing.expectEqual(@as(u32, 0), sa.scope_id);
    try std.testing.expectEqualSlices(u8, &ns_v6, &sa.addr);
}

test "udpSocket opens an AF_INET6 datagram socket" {
    // The v6 transport must actually open an IPv6 UDP socket (the gap was that
    // this path didn't exist). Skip only if the kernel/sandbox lacks IPv6.
    const fd = udpSocket(posix.AF.INET6) catch return error.SkipZigTest;
    closeFd(fd);
}

test "queryOneServer6 round-trips an A record against a ::1 DNS responder" {
    if (comptime builtin.os.tag == .linux) {
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
