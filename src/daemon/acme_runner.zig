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
const dns_address_lookup = @import("dns_address_lookup.zig");
const toml = @import("../proto/toml.zig");
const http_fetch = @import("http_fetch.zig");
const os_runtime = @import("os_runtime.zig");
const ec_pkcs = @import("../proto/ec_pkcs.zig");
const acme_challenge = @import("../proto/acme_challenge.zig");
const platform = @import("../substrate/platform.zig");

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

/// RFC 8701 GREASE stays on for this outbound TLS 1.3 client so peers that
/// mishandle unknown values are found early; GREASE ECH stays off because the
/// daemon holds no ECHConfig for these hosts (draft-ietf-tls-esni §6.2).
pub const outbound_grease = true;
pub const outbound_ech_grease = false;

/// Default maximum bytes accepted for a single HTTP response (ACME payloads are
/// small). Operationally tunable via `[acme].max_response_bytes`.
pub const default_max_response_bytes: usize = 256 * 1024;
/// Default max ACME state-machine steps before aborting.
pub const default_max_steps: usize = 64;
/// Default max bytes of an RFC 7807 problem body logged on error/debug.
pub const default_error_body_preview_bytes: usize = 512;
/// Hard ceiling on logged body-preview source bytes, regardless of config.
/// The CA body is remote-controlled text: the preview is additionally
/// escaped (see `escapedBodyPreview`) so it can never forge log lines.
pub const max_error_body_preview_bytes: usize = 1024;
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
        .grease = outbound_grease,
        .ech_grease = outbound_ech_grease,
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

/// Escaped, bounded preview of a remote-controlled response body for logs.
pub const BodyPreview = struct {
    text: []const u8,
    truncated: bool,
};

/// Render at most `limit` source bytes (hard-capped at
/// `max_error_body_preview_bytes`) of `body` into `buf` as a single log-safe
/// line: newline/CR/tab/backslash get C-style escapes, every other control,
/// DEL, or non-ASCII byte becomes `\xNN`. An escape is never split at the
/// buffer boundary; `truncated` reports any omitted source bytes.
pub fn escapedBodyPreview(body: []const u8, limit: usize, buf: []u8) BodyPreview {
    const effective = @min(limit, max_error_body_preview_bytes);
    const source = body[0..@min(body.len, effective)];
    var truncated = body.len > source.len;
    var out: usize = 0;
    for (source) |c| {
        var esc: [4]u8 = undefined;
        const unit: []const u8 = switch (c) {
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            '\\' => "\\\\",
            '"' => "\\\"",
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => blk: {
                esc[0] = c;
                break :blk esc[0..1];
            },
            else => blk: {
                const hex = "0123456789abcdef";
                esc = .{ '\\', 'x', hex[c >> 4], hex[c & 0xf] };
                break :blk esc[0..4];
            },
        };
        if (out + unit.len > buf.len) {
            truncated = true;
            break;
        }
        @memcpy(buf[out..][0..unit.len], unit);
        out += unit.len;
    }
    return .{ .text = buf[0..out], .truncated = truncated };
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
            var preview_buf: [4 * max_error_body_preview_bytes]u8 = undefined;
            const preview = escapedBodyPreview(resp.body, self.error_body_preview_bytes, &preview_buf);
            dlog.log("acme<- {s} {s} -> {d} (body {d}B) preview=\"{s}\"{s}\n", .{
                method,
                url_str,
                resp.status,
                resp.body.len,
                preview.text,
                if (preview.truncated) "...[truncated]" else "",
            });
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
// ES256 signer adapter (ECDSA P-256). Used for both the persistent account key
// and the per-issuance certificate key, which are always distinct key pairs.
// Let's Encrypt accepts ES256/ES384/ES512/RS256, not EdDSA.
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

/// Challenge types the runner can answer (re-exported for config parsing).
pub const ChallengeType = acme.ChallengeType;

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
    /// Challenge type answered for every authorization.
    challenge: ChallengeType = .http_01,
    /// dns-01: the operator hook (required when `challenge == .dns_01`).
    dns_hook: ?DnsHook = null,
    /// dns-01: wait after `hook add` before the CA is told to validate.
    dns_propagation_delay_ms: u32 = default_dns_propagation_delay_ms,
    /// dns-01: optional propagation probe polled within the delay.
    txt_probe: ?TxtProbe = null,
    /// tls-alpn-01: the store the TLS listener serves `acme-tls/1` from
    /// (required when `challenge == .tls_alpn_01`).
    tls_alpn01_store: ?*TlsAlpn01Store = null,
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
        cfg.error_body_preview_bytes = @intCast(@min(v, max_error_body_preview_bytes));
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

/// Run a full issuance. For http-01, `token_store` MUST already be wired to a
/// live HTTP-01 responder reachable at
/// `http://<domain>/.well-known/acme-challenge/<token>` (see
/// [acme_http01_server]); this driver only populates/clears it. For dns-01,
/// `cfg.dns_hook` publishes the TXT record; for tls-alpn-01,
/// `cfg.tls_alpn01_store` must be the store the TLS listener consults. The
/// account key must be the persisted one (`loadOrCreateAccountKey`) and the
/// certificate key a different, fresh key.
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
    token_store: ?*http01.TokenStore,
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
        .challenge = cfg.challenge,
    });
    defer client.deinit();

    var hook_provisioner: HookProvisioner = undefined;
    var sink = EffectSink{
        .allocator = allocator,
        .io = io,
        .dir = std.Io.Dir.cwd(),
        .cert_out_path = cfg.cert_out_path,
        .key_out_path = cfg.key_out_path,
        .cert_key = cert_key,
        .token_store = token_store,
        .dns_propagation_delay_ms = cfg.dns_propagation_delay_ms,
        .txt_probe = cfg.txt_probe,
        .tls_alpn01 = cfg.tls_alpn01_store,
    };
    switch (cfg.challenge) {
        .http_01 => if (token_store == null) return error.Http01Unavailable,
        .dns_01 => {
            const hook = cfg.dns_hook orelse return error.Dns01Unavailable;
            hook_provisioner = .{ .allocator = allocator, .io = io, .hook = hook };
            sink.dns = hook_provisioner.provisioner();
        },
        .tls_alpn_01 => if (cfg.tls_alpn01_store == null) return error.TlsAlpn01Unavailable,
    }
    return runSteps(&client, http_transport.transport(), &sink, cfg.max_steps);
}

// ---------------------------------------------------------------------------
// Persistent ACME account key (RFC 8555 §7.3)
// ---------------------------------------------------------------------------

/// File name of the default account key, placed in the directory of the TLS
/// certificate key (`[tls].key_path`), which already holds private material
/// (and on Windows must be a private directory).
pub const default_account_key_name = "acme-account.key.pem";

/// Maximum bytes read from an account key file (a SEC1 P-256 PEM is ~230).
const max_account_key_file_bytes: usize = 4096;

pub const AccountKeyError = error{
    /// The key file is readable by group or other (POSIX mode & 0o077 != 0).
    InsecureAccountKeyPermissions,
    /// The file is not a SEC1 / PKCS#8 P-256 private key PEM.
    InvalidAccountKey,
    /// The account key path aliases the certificate chain or certificate key.
    AccountKeyPathConflict,
};

pub const AccountKey = struct {
    key_pair: ecdsa_p256.KeyPair,
    /// True when this call generated and persisted a fresh key (first run or a
    /// migrated deployment): the next newAccount registers a new account.
    created: bool,

    pub fn wipe(self: *AccountKey) void {
        ecdsa_p256.wipeKeyPair(&self.key_pair);
    }
};

/// Default account key path: `<dirname(cert_key_path)>/acme-account.key.pem`.
/// Caller owns the result.
pub fn defaultAccountKeyPath(allocator: Allocator, cert_key_path: []const u8) Allocator.Error![]u8 {
    const dir = std.fs.path.dirname(cert_key_path) orelse return allocator.dupe(u8, default_account_key_name);
    return std.fs.path.join(allocator, &.{ dir, default_account_key_name });
}

/// Refuse an account key path that would overwrite (or be overwritten by) the
/// issued chain or certificate key: the two keys MUST stay separate files.
pub fn checkAccountKeyPath(account_key_path: []const u8, cert_path: []const u8, cert_key_path: ?[]const u8) AccountKeyError!void {
    if (account_key_path.len == 0) return error.AccountKeyPathConflict;
    if (std.mem.eql(u8, account_key_path, cert_path)) return error.AccountKeyPathConflict;
    if (cert_key_path) |k| if (std.mem.eql(u8, account_key_path, k)) return error.AccountKeyPathConflict;
}

/// Load the persisted ACME account key at `path`, or generate one, persist it
/// owner-only (0600) and return it with `created = true`.
///
/// Migration (deployments from before this file existed): earlier releases
/// generated a throwaway account key on every issuance and never stored it, so
/// no previous account key survives to sign an RFC 8555 §7.3.5 keyChange
/// (whose outer JWS must be signed by the OLD key). A missing file therefore
/// means "register": the key is generated and written BEFORE contacting the
/// CA, and the following newAccount creates the account (RFC 8555 §7.3). Every
/// later run re-sends newAccount with the same key, which the CA answers with
/// the existing account URL (RFC 8555 §7.3.1: "200 (OK) and ... the URL of
/// that account in the Location header field"), so issuance is idempotent and
/// no orphan accounts accumulate.
///
/// Fail closed: an existing but unreadable, malformed, or group/world-readable
/// file is an error — never silently replaced, since replacing it would orphan
/// the registered account.
pub fn loadOrCreateAccountKey(io: std.Io, dir: std.Io.Dir, path: []const u8) !AccountKey {
    if (loadAccountKey(io, dir, path)) |kp| {
        return .{ .key_pair = kp, .created = false };
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    var kp = ecdsa_p256.generate(io);
    errdefer ecdsa_p256.wipeKeyPair(&kp);
    var pem_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &pem_buf);
    const text = try ecPrivateKeyPem(kp, &pem_buf);
    writeKeyExclusive(io, dir, path, text) catch |err| switch (err) {
        // Another writer created it first: use theirs so both agree.
        error.PathAlreadyExists => {
            ecdsa_p256.wipeKeyPair(&kp);
            return .{ .key_pair = try loadAccountKey(io, dir, path), .created = false };
        },
        else => return err,
    };
    return .{ .key_pair = kp, .created = true };
}

/// Read and parse a persisted account key (SEC1 `EC PRIVATE KEY` or PKCS#8
/// `PRIVATE KEY`, P-256 only), refusing group/other-accessible files on POSIX.
pub fn loadAccountKey(io: std.Io, dir: std.Io.Dir, path: []const u8) !ecdsa_p256.KeyPair {
    var file = try dir.openFile(io, path, .{});
    defer file.close(io);
    if (comptime std.posix.mode_t != u0 and builtin.os.tag != .windows) {
        // Checked on the opened descriptor: no stat/open race.
        const st = try file.stat(io);
        if (st.permissions.toMode() & 0o077 != 0) return error.InsecureAccountKeyPermissions;
    }
    var file_buf: [max_account_key_file_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &file_buf);
    var reader = file.reader(io, &.{});
    const n = reader.interface.readSliceShort(&file_buf) catch return error.InvalidAccountKey;
    if (n == file_buf.len) return error.InvalidAccountKey; // oversize: not a P-256 key
    const text = file_buf[0..n];
    var der_buf: [max_account_key_file_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);
    const der = pem.decode(text, "EC PRIVATE KEY", &der_buf) catch
        pem.decode(text, "PRIVATE KEY", &der_buf) catch return error.InvalidAccountKey;
    var scalar = ec_pkcs.parseScalar(der) catch return error.InvalidAccountKey;
    defer std.crypto.secureZero(u8, &scalar);
    const sk = ecdsa_p256.SecretKey.fromBytes(scalar) catch return error.InvalidAccountKey;
    return ecdsa_p256.keyPairFromSecretKey(sk) catch return error.InvalidAccountKey;
}

/// Create `path` exclusively with owner-only permissions (fsync + link), so a
/// concurrent creator can never be overwritten.
fn writeKeyExclusive(io: std.Io, dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        // The Windows private-DACL publisher replaces; account key creation is
        // single-writer there (the renewal thread or the CLI).
        dir.access(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return writeKeyAtomicWindows(io, dir, path, data),
            else => return err,
        };
        return error.PathAlreadyExists;
    }
    var atomic = try dir.createFileAtomic(io, path, .{ .replace = false, .permissions = key_file_perms });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.link(io);
}

// ---------------------------------------------------------------------------
// dns-01 operator hook (RFC 8555 §8.4)
// ---------------------------------------------------------------------------

/// Default wall-clock bound on one hook invocation.
pub const default_dns_hook_timeout_ms: u32 = 60_000;
/// Default wait after a successful `add` before telling the CA to validate.
pub const default_dns_propagation_delay_ms: u32 = 30_000;
/// The only environment a hook sees (no daemon secrets leak into it).
const hook_path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub const HookAction = enum { add, del };

pub const HookError = error{
    /// The hook path is not absolute, or an argument failed validation.
    InvalidHookArgument,
    /// The hook could not be started (missing, not executable, ...).
    HookSpawnFailed,
    /// The hook did not exit within `timeout_ms`; it was SIGKILLed.
    HookTimeout,
    /// The hook exited non-zero or was killed by a signal.
    HookFailed,
    /// dns-01 hooks are supported on Linux only.
    Unsupported,
} || Allocator.Error;

/// An operator executable invoked as `<path> add <fqdn> <txt>` to publish and
/// `<path> del <fqdn> <txt>` to remove a dns-01 TXT record. The argv is passed
/// to execve directly — no shell, no interpolation — and both values are
/// validated before spawn: the name is LDH (never starts with `-`), the TXT
/// value is exactly 43 base64url characters (it MAY start with `-`, so hooks
/// must read their arguments positionally, never as options). stdin/stdout are /dev/null, stderr is inherited
/// (hook diagnostics land in the daemon log), and the environment is only
/// `PATH`; hooks read credentials from their own files.
pub const DnsHook = struct {
    path: []const u8,
    timeout_ms: u32 = default_dns_hook_timeout_ms,

    pub fn run(self: DnsHook, allocator: Allocator, io: std.Io, action: HookAction, fqdn: []const u8, txt: []const u8) HookError!void {
        if (!std.fs.path.isAbsolute(self.path)) return error.InvalidHookArgument;
        if (!acme_challenge.isValidDnsName(fqdn)) return error.InvalidHookArgument;
        // RFC 8555 §8.4: the value is base64url(SHA-256(keyAuth)) — exactly
        // 43 unpadded base64url characters, nothing else is ever passed.
        if (txt.len != acme_challenge.dns01TxtValueLen() or !acme_challenge.validateToken(txt)) return error.InvalidHookArgument;
        if (comptime builtin.os.tag != .linux) return error.Unsupported;

        const argv = [_][]const u8{ self.path, @tagName(action), fqdn, txt };
        var env = std.process.Environ.Map.init(allocator);
        defer env.deinit();
        try env.put("PATH", hook_path_env);

        var child = std.process.spawn(io, .{
            .argv = &argv,
            .environ_map = &env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .inherit,
        }) catch return error.HookSpawnFailed;
        // Idempotent after `wait`; on any early return it SIGKILLs and reaps.
        defer child.kill(io);

        const pid = child.id orelse return error.HookSpawnFailed;
        const deadline = platform.monotonicMillis() +| @as(i64, self.timeout_ms);
        while (true) {
            var status: linux.siginfo_t = std.mem.zeroes(linux.siginfo_t);
            switch (posix.errno(linux.waitid(.PID, pid, &status, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT, null))) {
                .SUCCESS => if (status.fields.common.first.piduid.pid != 0) break,
                .INTR => continue,
                else => return error.HookFailed,
            }
            const now = platform.monotonicMillis();
            if (now >= deadline) {
                _ = linux.kill(pid, .KILL);
                return error.HookTimeout;
            }
            std.Io.sleep(io, .fromMilliseconds(@min(deadline - now, 10)), .awake) catch return error.HookFailed;
        }
        const term = child.wait(io) catch return error.HookFailed;
        if (!term.success()) return error.HookFailed;
    }
};

/// Publish/remove a dns-01 TXT record. Production uses `DnsHook`; tests inject.
pub const Dns01Provisioner = struct {
    ctx: *anyopaque,
    runFn: *const fn (ctx: *anyopaque, action: HookAction, fqdn: []const u8, txt: []const u8) anyerror!void,

    fn run(self: Dns01Provisioner, action: HookAction, fqdn: []const u8, txt: []const u8) anyerror!void {
        return self.runFn(self.ctx, action, fqdn, txt);
    }
};

/// Optional propagation check: returns true once `fqdn` serves `txt`.
pub const TxtProbe = struct {
    ctx: *anyopaque,
    probeFn: *const fn (ctx: *anyopaque, fqdn: []const u8, txt: []const u8) bool,
};

/// Bridges `DnsHook` to `Dns01Provisioner`.
pub const HookProvisioner = struct {
    allocator: Allocator,
    io: std.Io,
    hook: DnsHook,

    pub fn provisioner(self: *HookProvisioner) Dns01Provisioner {
        return .{ .ctx = self, .runFn = runThunk };
    }

    fn runThunk(ctx: *anyopaque, action: HookAction, fqdn: []const u8, txt: []const u8) anyerror!void {
        const self: *HookProvisioner = @ptrCast(@alignCast(ctx));
        return self.hook.run(self.allocator, self.io, action, fqdn, txt);
    }
};

/// Wait for a freshly published TXT record to be visible before the CA is
/// told to validate. Without a probe this is a fixed `delay_ms` sleep; with a
/// probe it polls every `poll_ms` until the probe sees the value, failing with
/// `error.DnsPropagationTimeout` after `delay_ms` (fail closed: never trigger
/// validation against a record known not to be there).
pub fn waitForPropagation(io: std.Io, fqdn: []const u8, txt: []const u8, delay_ms: u32, poll_ms: u32, probe: ?TxtProbe) !void {
    const p = probe orelse {
        std.Io.sleep(io, .fromMilliseconds(delay_ms), .awake) catch {};
        return;
    };
    const deadline = platform.monotonicMillis() +| @as(i64, delay_ms);
    while (true) {
        if (p.probeFn(p.ctx, fqdn, txt)) return;
        const now = platform.monotonicMillis();
        if (now >= deadline) return error.DnsPropagationTimeout;
        std.Io.sleep(io, .fromMilliseconds(@min(deadline - now, @max(poll_ms, 1))), .awake) catch {};
    }
}

// ---------------------------------------------------------------------------
// tls-alpn-01 certificate store (RFC 8737)
// ---------------------------------------------------------------------------

/// Thread-safe, allocation-free registry of live TLS-ALPN-01 challenge
/// certificates, keyed by identifier (case-insensitive). The renewal thread
/// `put`s an entry before telling the CA to validate and `remove`s it when the
/// authorization settles; the TLS listener calls `selectForClientHello` on a
/// new connection's first record and, on a hit, completes that handshake with
/// the leased certificate/key and ALPN `acme-tls/1` only, then closes (RFC 8737
/// §4: no application data is exchanged).
pub const TlsAlpn01Store = struct {
    pub const max_entries = 8;

    mutex: std.atomic.Mutex = .unlocked,
    entries: [max_entries]Entry = @splat(.{}),

    const Entry = struct {
        used: bool = false,
        name_len: u16 = 0,
        name: [acme_challenge.max_dns_name_len]u8 = undefined,
        cert_len: u16 = 0,
        cert: [acme_challenge.max_tls_alpn01_cert_len]u8 = undefined,
        key_pair: ecdsa_p256.KeyPair = undefined,
    };

    /// A by-value copy the listener owns for the life of one handshake, so a
    /// concurrent `remove` can never free bytes a handshake is still using.
    pub const Lease = struct {
        cert_len: u16,
        cert: [acme_challenge.max_tls_alpn01_cert_len]u8,
        key_pair: ecdsa_p256.KeyPair,

        pub fn certDer(self: *const Lease) []const u8 {
            return self.cert[0..self.cert_len];
        }

        pub fn wipe(self: *Lease) void {
            ecdsa_p256.wipeKeyPair(&self.key_pair);
        }
    };

    pub const PutError = error{ InvalidDomain, CertificateTooLarge, StoreFull };

    fn lock(self: *TlsAlpn01Store) void {
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
    }

    /// Install (or replace) the challenge certificate for `domain`.
    pub fn put(self: *TlsAlpn01Store, domain: []const u8, cert_der: []const u8, key_pair: ecdsa_p256.KeyPair) PutError!void {
        if (!acme_challenge.isValidDnsName(domain)) return error.InvalidDomain;
        if (cert_der.len > acme_challenge.max_tls_alpn01_cert_len) return error.CertificateTooLarge;
        self.lock();
        defer self.mutex.unlock();
        const slot = self.find(domain) orelse for (&self.entries) |*e| {
            if (!e.used) break e;
        } else return error.StoreFull;
        slot.used = true;
        slot.name_len = @intCast(domain.len);
        @memcpy(slot.name[0..domain.len], domain);
        slot.cert_len = @intCast(cert_der.len);
        @memcpy(slot.cert[0..cert_der.len], cert_der);
        slot.key_pair = key_pair;
    }

    /// Remove the entry for `domain` (wiping its key). No-op when absent.
    pub fn remove(self: *TlsAlpn01Store, domain: []const u8) void {
        self.lock();
        defer self.mutex.unlock();
        if (self.find(domain)) |e| {
            ecdsa_p256.wipeKeyPair(&e.key_pair);
            e.* = .{};
        }
    }

    /// Copy out the entry matching SNI `server_name`, if any.
    pub fn lookup(self: *TlsAlpn01Store, server_name: []const u8) ?Lease {
        self.lock();
        defer self.mutex.unlock();
        const e = self.find(server_name) orelse return null;
        var lease: Lease = .{ .cert_len = e.cert_len, .cert = undefined, .key_pair = e.key_pair };
        @memcpy(lease.cert[0..e.cert_len], e.cert[0..e.cert_len]);
        return lease;
    }

    /// The listener hook: if `first_record` is a TLS-ALPN-01 validation
    /// ClientHello (SNI + ALPN exactly `acme-tls/1`, see
    /// `acme_challenge.peekAcmeTlsHello`) for a name with a live challenge,
    /// return its lease. Null means "handle the connection normally".
    pub fn selectForClientHello(self: *TlsAlpn01Store, first_record: []const u8) ?Lease {
        if (self.isEmpty()) return null;
        const hello = acme_challenge.peekAcmeTlsHello(first_record) orelse return null;
        return self.lookup(hello.server_name);
    }

    pub fn isEmpty(self: *TlsAlpn01Store) bool {
        self.lock();
        defer self.mutex.unlock();
        for (self.entries) |e| if (e.used) return false;
        return true;
    }

    fn find(self: *TlsAlpn01Store, name: []const u8) ?*Entry {
        for (&self.entries) |*e| {
            if (e.used and std.ascii.eqlIgnoreCase(e.name[0..e.name_len], name)) return e;
        }
        return null;
    }
};

/// Validity of a TLS-ALPN-01 certificate around `now`: the CA validates
/// within minutes, a small backdate absorbs validator clock skew.
const tls_alpn01_backdate_s: i64 = 24 * 60 * 60;
const tls_alpn01_lifetime_s: i64 = 7 * 24 * 60 * 60;

/// Mint the RFC 8737 challenge certificate for `domain` with a fresh
/// ephemeral key. The serial is derived from the public key (unique per key;
/// no RNG needed beyond key generation).
pub fn mintTlsAlpn01(io: std.Io, out: []u8, domain: []const u8, key_authorization: []const u8, now_unix: i64) !struct { der: []const u8, key_pair: ecdsa_p256.KeyPair } {
    var kp = ecdsa_p256.generate(io);
    errdefer ecdsa_p256.wipeKeyPair(&kp);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&kp.public_key.toUncompressedSec1(), &digest, .{});
    const der = try acme_challenge.buildTlsAlpn01Certificate(out, .{
        .domain = domain,
        .key_authorization = key_authorization,
        .key_pair = kp,
        .serial = digest[0..16].*,
        .not_before = @max(now_unix - tls_alpn01_backdate_s, 0),
        .not_after = now_unix + tls_alpn01_lifetime_s,
    });
    return .{ .der = der, .key_pair = kp };
}

// ---------------------------------------------------------------------------
// Effect handling + step loop
// ---------------------------------------------------------------------------

/// Acts on `acme_client` effects for one issuance and remembers every
/// provisioned challenge response so `cleanup` can withdraw it whatever the
/// outcome (http-01 tokens, dns-01 TXT records via `del`, tls-alpn-01 certs).
pub const EffectSink = struct {
    allocator: Allocator,
    io: std.Io,
    /// Directory the cert/key paths resolve against (`cwd` in production).
    dir: std.Io.Dir,
    cert_out_path: []const u8,
    key_out_path: ?[]const u8,
    cert_key: ecdsa_p256.KeyPair,
    token_store: ?*http01.TokenStore = null,
    dns: ?Dns01Provisioner = null,
    dns_propagation_delay_ms: u32 = default_dns_propagation_delay_ms,
    dns_poll_ms: u32 = 2_000,
    txt_probe: ?TxtProbe = null,
    tls_alpn01: ?*TlsAlpn01Store = null,
    cert_written: bool = false,

    tokens: Pending(256) = .{},
    dns_records: Pending(acme_challenge.dns01_label.len + acme_challenge.max_dns_name_len + 1 + 64) = .{},
    alpn_names: Pending(acme_challenge.max_dns_name_len) = .{},

    pub fn handle(self: *EffectSink, effect: acme.Effect) !void {
        switch (effect) {
            .serve_http01 => |c| {
                const store = self.token_store orelse return error.Http01Unavailable;
                try self.tokens.add(c.token);
                try store.put(c.token, c.key_authorization);
            },
            .provision_dns01 => |c| {
                const dns = self.dns orelse return error.Dns01Unavailable;
                var rec_buf: [acme_challenge.dns01_label.len + acme_challenge.max_dns_name_len + 1 + 64]u8 = undefined;
                const rec = std.fmt.bufPrint(&rec_buf, "{s} {s}", .{ c.fqdn, c.txt_value }) catch return error.InvalidHookArgument;
                // Remember before running so a hook that half-applied and then
                // failed is still sent `del`.
                try self.dns_records.add(rec);
                try dns.run(.add, c.fqdn, c.txt_value);
                try waitForPropagation(self.io, c.fqdn, c.txt_value, self.dns_propagation_delay_ms, self.dns_poll_ms, self.txt_probe);
            },
            .provision_tls_alpn01 => |c| {
                const store = self.tls_alpn01 orelse return error.TlsAlpn01Unavailable;
                var cert_buf: [acme_challenge.max_tls_alpn01_cert_len]u8 = undefined;
                var minted = try mintTlsAlpn01(self.io, &cert_buf, c.domain, c.key_authorization, wallClockSeconds());
                defer ecdsa_p256.wipeKeyPair(&minted.key_pair);
                try self.alpn_names.add(c.domain);
                try store.put(c.domain, minted.der, minted.key_pair);
            },
            .write_cert => |c| {
                try writeCertAtomic(self.io, self.dir, self.cert_out_path, c.pem);
                if (self.key_out_path) |kp| {
                    var pem_buf: [512]u8 = undefined;
                    defer std.crypto.secureZero(u8, &pem_buf);
                    const key_pem = try ecPrivateKeyPem(self.cert_key, &pem_buf);
                    try writeKeyAtomic(self.io, self.dir, kp, key_pem);
                }
                self.cert_written = true;
            },
        }
    }

    /// Withdraw every provisioned response. Best effort: a failing `del` hook
    /// is logged, never masks the issuance result.
    pub fn cleanup(self: *EffectSink) void {
        if (self.token_store) |store| {
            for (self.tokens.slice()) |t| _ = store.remove(t.text());
        }
        if (self.dns) |dns| {
            for (self.dns_records.slice()) |r| {
                const rec = r.text();
                const sp = std.mem.indexOfScalar(u8, rec, ' ') orelse continue;
                dns.run(.del, rec[0..sp], rec[sp + 1 ..]) catch |err| {
                    dlog.log("acme: dns-01 hook del {s} failed ({s}); remove the TXT record manually\n", .{ rec[0..sp], @errorName(err) });
                };
            }
        }
        if (self.tls_alpn01) |store| {
            for (self.alpn_names.slice()) |n| store.remove(n.text());
        }
        self.tokens = .{};
        self.dns_records = .{};
        self.alpn_names = .{};
    }
};

/// Fixed-capacity list of short strings (one entry per authorization).
fn Pending(comptime cap: usize) type {
    return struct {
        const Self = @This();
        const max = 16;
        items: [max]Item = undefined,
        len: usize = 0,

        const Item = struct {
            buf: [cap]u8 = undefined,
            n: usize = 0,
            fn text(self: *const Item) []const u8 {
                return self.buf[0..self.n];
            }
        };

        fn add(self: *Self, s: []const u8) error{TooManyAuthorizations}!void {
            if (self.len == max or s.len > cap) return error.TooManyAuthorizations;
            self.items[self.len] = .{};
            @memcpy(self.items[self.len].buf[0..s.len], s);
            self.items[self.len].n = s.len;
            self.len += 1;
        }

        fn slice(self: *const Self) []const Item {
            return self.items[0..self.len];
        }
    };
}

/// Step `client` to completion, routing every effect through `sink`. The
/// sink's provisioned responses are withdrawn on every exit path.
pub fn runSteps(client: *acme.Acme, transport: acme.Transport, sink: *EffectSink, max_steps: usize) !IssueResult {
    defer sink.cleanup();
    var steps: usize = 0;
    while (steps < max_steps) : (steps += 1) {
        const progress = try client.step(transport);
        for (progress.effects) |effect| try sink.handle(effect);
        if (progress.done) return .{ .state = progress.state, .cert_written = sink.cert_written };
    }
    return error.TooManySteps;
}

// ---------------------------------------------------------------------------
// Built-in bounded DNS resolver
// ---------------------------------------------------------------------------

/// Default `Resolver`: on Unix, reads /etc/resolv.conf and resolves one A
/// address through validated UDP, TCP fallback, and CNAME traversal under one
/// three-second budget. On Windows, delegates to the DNS Client through
/// GetAddrInfoExW. Handles IP literals without I/O. Out-of-band only.
pub const SystemResolver = struct {
    allocator: Allocator,
    io: std.Io,
    /// Max bytes read from /etc/resolv.conf.
    resolv_conf_max_bytes: usize = default_resolv_conf_max_bytes,
    /// UDP/TCP port used for DNS A-record lookups.
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
    return dns_address_lookup.resolve(text, host, port, dns_port, .a, 3000);
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
    const account_key = ecdsa_p256.generate(io);
    const cert_key = ecdsa_p256.generate(io);
    const issuer_key = ecdsa_p256.generate(io);
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

test "escapedBodyPreview escapes log-forging bytes and passes printable text" {
    var buf: [256]u8 = undefined;
    const body = "{\"detail\":\"bad\x0aforged\x0d\x09line\"}\x1b[31m\x00\x7f\xff\x5c";
    const preview = escapedBodyPreview(body, default_error_body_preview_bytes, &buf);
    try std.testing.expectEqualStrings(
        "{\\\"detail\\\":\\\"bad\\nforged\\r\\tline\\\"}\\x1b[31m\\x00\\x7f\\xff\\\\",
        preview.text,
    );
    try std.testing.expect(!preview.truncated);
    for (preview.text) |c| try std.testing.expect(c >= 0x20 and c < 0x7f);
}

test "escapedBodyPreview bounds source bytes, hard-caps the limit, and never splits an escape" {
    var buf: [8]u8 = undefined;
    // Limit is clamped to the hard cap; a 4-byte escape that would cross the
    // buffer boundary is omitted whole and reported as truncation.
    var split_buf: [7]u8 = undefined;
    const split = escapedBodyPreview("abcd\x01efgh", std.math.maxInt(usize), &split_buf);
    try std.testing.expectEqualStrings("abcd", split.text);
    try std.testing.expect(split.truncated);

    var big_buf: [4 * max_error_body_preview_bytes]u8 = undefined;
    const long_body: [max_error_body_preview_bytes + 64]u8 = @splat('x');
    const capped = escapedBodyPreview(&long_body, std.math.maxInt(usize), &big_buf);
    try std.testing.expectEqual(@as(usize, max_error_body_preview_bytes), capped.text.len);
    try std.testing.expect(capped.truncated);

    const limited = escapedBodyPreview("hello world", 5, &buf);
    try std.testing.expectEqualStrings("hello", limited.text);
    try std.testing.expect(limited.truncated);

    const empty = escapedBodyPreview("", 512, &buf);
    try std.testing.expectEqualStrings("", empty.text);
    try std.testing.expect(!empty.truncated);
}

test "applyToml clamps error_body_preview_bytes to the hard cap" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[acme]\nerror_body_preview_bytes = 999999\n");
    defer doc.deinit(allocator);

    var cfg: IssueConfig = .{
        .directory_url = "https://x/dir",
        .domains = &.{"x.test"},
        .trust_anchors = &.{},
        .cert_out_path = "/p/c.pem",
    };
    applyToml(&cfg, &doc);
    try std.testing.expectEqual(max_error_body_preview_bytes, cfg.error_body_preview_bytes);
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

test {
    _ = @import("acme_dns_tests.zig");
}

test {
    std.testing.refAllDecls(@This());
}

test "TLS client fatal transport: acme_runner socket writer preserves control custody" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try tls_client_failure.testFatalTransportProof(true, writeAll);
}

// ---------------------------------------------------------------------------
// Account key, dns-01 hook, tls-alpn-01 store, effect sink
// ---------------------------------------------------------------------------

test "account key is generated once, persisted 0600, reloaded, and distinct from the cert key" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var first = try loadOrCreateAccountKey(io, tmp.dir, "acct.pem");
    defer first.wipe();
    try std.testing.expect(first.created);
    const st = try tmp.dir.statFile(io, "acct.pem", .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);

    var second = try loadOrCreateAccountKey(io, tmp.dir, "acct.pem");
    defer second.wipe();
    try std.testing.expect(!second.created);
    try std.testing.expectEqualSlices(u8, &first.key_pair.public_key.toUncompressedSec1(), &second.key_pair.public_key.toUncompressedSec1());
    try std.testing.expectEqualSlices(u8, &first.key_pair.secret_key.toBytes(), &second.key_pair.secret_key.toBytes());

    // A per-issuance certificate key is a different key pair.
    const cert_key = ecdsa_p256.generate(io);
    try std.testing.expect(!std.mem.eql(u8, &cert_key.public_key.toUncompressedSec1(), &first.key_pair.public_key.toUncompressedSec1()));

    // The persisted form is the SEC1 PEM the TLS loader also reads.
    var buf: [1024]u8 = undefined;
    const text = try tmp.dir.readFile(io, "acct.pem", &buf);
    try std.testing.expect(std.mem.startsWith(u8, text, "-----BEGIN EC PRIVATE KEY-----"));
}

test "account key load fails closed on group-readable or malformed files and never replaces them" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var made = try loadOrCreateAccountKey(io, tmp.dir, "acct.pem");
    made.wipe();
    {
        const f = try tmp.dir.openFile(io, "acct.pem", .{});
        defer f.close(io);
        try f.setPermissions(io, .fromMode(0o640));
    }
    try std.testing.expectError(error.InsecureAccountKeyPermissions, loadOrCreateAccountKey(io, tmp.dir, "acct.pem"));

    try tmp.dir.writeFile(io, .{ .sub_path = "junk.pem", .data = "not a key\n", .flags = .{ .permissions = .fromMode(0o600) } });
    try std.testing.expectError(error.InvalidAccountKey, loadOrCreateAccountKey(io, tmp.dir, "junk.pem"));
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("not a key\n", try tmp.dir.readFile(io, "junk.pem", &buf));
}

test "account key path defaults next to the TLS key and may not alias cert or key" {
    const a = std.testing.allocator;
    const p = try defaultAccountKeyPath(a, "/etc/onyx/tls/server.key");
    defer a.free(p);
    try std.testing.expectEqualStrings("/etc/onyx/tls/acme-account.key.pem", p);
    const bare = try defaultAccountKeyPath(a, "server.key");
    defer a.free(bare);
    try std.testing.expectEqualStrings("acme-account.key.pem", bare);

    try checkAccountKeyPath("/k/acct.pem", "/k/cert.pem", "/k/key.pem");
    try std.testing.expectError(error.AccountKeyPathConflict, checkAccountKeyPath("/k/key.pem", "/k/cert.pem", "/k/key.pem"));
    try std.testing.expectError(error.AccountKeyPathConflict, checkAccountKeyPath("/k/cert.pem", "/k/cert.pem", null));
    try std.testing.expectError(error.AccountKeyPathConflict, checkAccountKeyPath("", "/k/cert.pem", null));
}

const TestHookDir = struct {
    tmp: std.testing.TmpDir,
    root: [:0]u8,

    fn init(script: []const u8) !TestHookDir {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
        errdefer std.testing.allocator.free(root);
        var body_buf: [1024]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "#!/bin/sh\n{s}\n", .{script});
        const f = try tmp.dir.createFile(io, "hook", .{ .permissions = .fromMode(0o700) });
        defer f.close(io);
        try f.writeStreamingAll(io, body);
        return .{ .tmp = tmp, .root = root };
    }

    fn hookPath(self: *const TestHookDir, buf: []u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/hook", .{self.root});
    }

    fn deinit(self: *TestHookDir) void {
        std.testing.allocator.free(self.root);
        self.tmp.cleanup();
    }
};

test "dns hook is exec'd with argv [path, add|del, fqdn, txt] and a PATH-only environment" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    // The script records "$0"-relative argv and whether HOME leaked through.
    var hd = try TestHookDir.init("d=$(dirname \"$0\"); printf '%s\\n' \"$#\" \"$1\" \"$2\" \"$3\" \"${HOME-unset}\" \"$PATH\" >> \"$d/calls\"");
    defer hd.deinit();
    var path_buf: [512]u8 = undefined;
    const hook = DnsHook{ .path = try hd.hookPath(&path_buf), .timeout_ms = 10_000 };

    const txt = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    try hook.run(std.testing.allocator, io, .add, "_acme-challenge.irc.example.test", txt);
    try hook.run(std.testing.allocator, io, .del, "_acme-challenge.irc.example.test", txt);

    var buf: [1024]u8 = undefined;
    const calls = try hd.tmp.dir.readFile(io, "calls", &buf);
    try std.testing.expectEqualStrings(
        "3\nadd\n_acme-challenge.irc.example.test\n" ++ txt ++ "\nunset\n" ++ hook_path_env ++ "\n" ++
            "3\ndel\n_acme-challenge.irc.example.test\n" ++ txt ++ "\nunset\n" ++ hook_path_env ++ "\n",
        calls,
    );
}

test "dns hook rejects relative paths and unsafe arguments without spawning" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var hd = try TestHookDir.init("touch \"$(dirname \"$0\")/ran\"");
    defer hd.deinit();
    var path_buf: [512]u8 = undefined;
    const hook = DnsHook{ .path = try hd.hookPath(&path_buf) };
    const a = std.testing.allocator;
    const txt = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    try std.testing.expectError(error.InvalidHookArgument, (DnsHook{ .path = "hook" }).run(a, io, .add, "a.test", txt));
    try std.testing.expectError(error.InvalidHookArgument, hook.run(a, io, .add, "-rf", txt));
    try std.testing.expectError(error.InvalidHookArgument, hook.run(a, io, .add, "a.test", "$(id)LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxA"));
    try std.testing.expectError(error.InvalidHookArgument, hook.run(a, io, .add, "a.test;id", txt));
    try std.testing.expectError(error.InvalidHookArgument, hook.run(a, io, .add, "a.test", "abc")); // not 43 chars
    try std.testing.expectError(error.FileNotFound, hd.tmp.dir.access(io, "ran", .{}));
}

test "dns hook non-zero exit, missing executable, and timeout fail closed" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const a = std.testing.allocator;
    const txt = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";

    var failing = try TestHookDir.init("exit 3");
    defer failing.deinit();
    var p1: [512]u8 = undefined;
    try std.testing.expectError(error.HookFailed, (DnsHook{ .path = try failing.hookPath(&p1) }).run(a, io, .add, "a.test", txt));

    try std.testing.expectError(error.HookSpawnFailed, (DnsHook{ .path = "/nonexistent/onyx-acme-hook" }).run(a, io, .add, "a.test", txt));

    var slow = try TestHookDir.init("exec sleep 30");
    defer slow.deinit();
    var p2: [512]u8 = undefined;
    const start = platform.monotonicMillis();
    try std.testing.expectError(error.HookTimeout, (DnsHook{ .path = try slow.hookPath(&p2), .timeout_ms = 200 }).run(a, io, .add, "a.test", txt));
    const elapsed = platform.monotonicMillis() - start;
    try std.testing.expect(elapsed >= 200);
    try std.testing.expect(elapsed < 5_000); // killed, not waited out
}

test "waitForPropagation polls the probe and times out closed" {
    const Probe = struct {
        hits_needed: usize,
        calls: usize = 0,
        fn probe(ctx: *anyopaque, fqdn: []const u8, txt: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            std.debug.assert(std.mem.eql(u8, fqdn, "_acme-challenge.a.test") and std.mem.eql(u8, txt, "v"));
            self.calls += 1;
            return self.calls >= self.hits_needed;
        }
    };
    var ok = Probe{ .hits_needed = 3 };
    try waitForPropagation(std.testing.io, "_acme-challenge.a.test", "v", 5_000, 1, .{ .ctx = &ok, .probeFn = Probe.probe });
    try std.testing.expectEqual(@as(usize, 3), ok.calls);

    var never = Probe{ .hits_needed = std.math.maxInt(usize) };
    try std.testing.expectError(error.DnsPropagationTimeout, waitForPropagation(std.testing.io, "_acme-challenge.a.test", "v", 50, 5, .{ .ctx = &never, .probeFn = Probe.probe }));
    try std.testing.expect(never.calls >= 2);
}

test "TlsAlpn01Store put/lookup/remove is case-insensitive, bounded, and serves only acme-tls/1 hellos" {
    var store: TlsAlpn01Store = .{};
    const kp = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x21)));
    try std.testing.expect(store.isEmpty());
    try store.put("irc.example.test", "CERT-A", kp);
    try store.put("IRC.example.test", "CERT-B", kp); // replaces
    var lease = store.lookup("irc.EXAMPLE.test") orelse return error.TestUnexpectedResult;
    defer lease.wipe();
    try std.testing.expectEqualStrings("CERT-B", lease.certDer());
    try std.testing.expect(store.lookup("other.test") == null);
    try std.testing.expectError(error.InvalidDomain, store.put("*.example.test", "C", kp));
    var big: [acme_challenge.max_tls_alpn01_cert_len + 1]u8 = undefined;
    try std.testing.expectError(error.CertificateTooLarge, store.put("x.test", &big, kp));

    var name_buf: [16]u8 = undefined;
    for (1..TlsAlpn01Store.max_entries) |i| try store.put(try std.fmt.bufPrint(&name_buf, "n{d}.test", .{i}), "C", kp);
    try std.testing.expectError(error.StoreFull, store.put("overflow.test", "C", kp));

    store.remove("IRC.EXAMPLE.TEST");
    try std.testing.expect(store.lookup("irc.example.test") == null);
    for (1..TlsAlpn01Store.max_entries) |i| store.remove(try std.fmt.bufPrint(&name_buf, "n{d}.test", .{i}));
    try std.testing.expect(store.isEmpty());
    // An empty store never inspects the record.
    try std.testing.expect(store.selectForClientHello(&.{ 22, 3, 1, 0, 0 }) == null);
}

/// Minimal canned CA for EffectSink/runSteps tests. `on_post` observes every
/// POST so a test can assert provisioning happened before validation.
const SinkMock = struct {
    const Entry = struct { url: []const u8, status: u16 = 200, body: []const u8, location: ?[]const u8 = null, used: bool = false };
    entries: []Entry,
    observer: ?*anyopaque = null,
    on_post: ?*const fn (observer: *anyopaque, url: []const u8) void = null,

    fn next(self: *SinkMock, url: []const u8) acme.HttpResponse {
        var last: ?*Entry = null;
        for (self.entries) |*e| {
            if (!std.mem.eql(u8, e.url, url)) continue;
            last = e;
            if (!e.used) {
                e.used = true;
                return .{ .status = e.status, .body = e.body, .nonce = "n", .location = e.location };
            }
        }
        if (last) |e| return .{ .status = e.status, .body = e.body, .nonce = "n", .location = e.location };
        return .{ .status = 404, .body = "{}", .nonce = "n" };
    }
    fn getThunk(ctx: *anyopaque, url: []const u8) anyerror!acme.HttpResponse {
        const self: *SinkMock = @ptrCast(@alignCast(ctx));
        return self.next(url);
    }
    fn postThunk(ctx: *anyopaque, url: []const u8, _: []const u8) anyerror!acme.HttpResponse {
        const self: *SinkMock = @ptrCast(@alignCast(ctx));
        if (self.on_post) |f| f(self.observer.?, url);
        return self.next(url);
    }
    fn transport(self: *SinkMock) acme.Transport {
        return .{ .ctx = self, .getFn = getThunk, .postJwsFn = postThunk };
    }
};

fn sinkFlow(comptime chal_type: []const u8, comptime chal_url: []const u8) [11]SinkMock.Entry {
    const authz = "{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"irc.example.test\"}," ++
        "\"challenges\":[{\"type\":\"" ++ chal_type ++ "\",\"url\":\"" ++ chal_url ++ "\",\"token\":\"tok1\",\"status\":\"pending\"}]}";
    const authz_valid = "{\"status\":\"valid\",\"identifier\":{\"type\":\"dns\",\"value\":\"irc.example.test\"},\"challenges\":[]}";
    const order = "{\"status\":\"pending\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"irc.example.test\"}]," ++
        "\"authorizations\":[\"https://ca/authz/1\"],\"finalize\":\"https://ca/fin\"}";
    const order_valid = "{\"status\":\"valid\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"irc.example.test\"}]," ++
        "\"authorizations\":[\"https://ca/authz/1\"],\"finalize\":\"https://ca/fin\",\"certificate\":\"https://ca/cert\"}";
    return .{
        .{ .url = "https://ca/dir", .body = "{\"newNonce\":\"https://ca/nonce\",\"newAccount\":\"https://ca/acct\",\"newOrder\":\"https://ca/order\",\"revokeCert\":\"https://ca/r\",\"keyChange\":\"https://ca/k\"}" },
        .{ .url = "https://ca/nonce", .body = "" },
        .{ .url = "https://ca/acct", .status = 201, .body = "{}", .location = "https://ca/acct/1" },
        .{ .url = "https://ca/order", .status = 201, .body = order, .location = "https://ca/order/1" },
        .{ .url = "https://ca/authz/1", .body = authz },
        .{ .url = chal_url, .body = "{}" },
        .{ .url = "https://ca/authz/1", .body = authz_valid },
        .{ .url = "https://ca/fin", .body = order },
        .{ .url = "https://ca/order/1", .body = order_valid },
        .{ .url = "https://ca/cert", .body = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" },
        .{ .url = "unused", .body = "" },
    };
}

test "runSteps dns-01: hook add + propagation before validation, del after, cert written" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const Recorder = struct {
        log: [4][96]u8 = undefined,
        lens: [4]usize = @splat(0),
        n: usize = 0,
        add_before_post: bool = false,
        fn run(ctx: *anyopaque, action: HookAction, fqdn: []const u8, txt: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const line = try std.fmt.bufPrint(&self.log[self.n], "{s} {s} {s}", .{ @tagName(action), fqdn, txt });
            self.lens[self.n] = line.len;
            self.n += 1;
        }
        fn onPost(ctx: *anyopaque, url: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (std.mem.eql(u8, url, "https://ca/chal/d")) self.add_before_post = self.n == 1;
        }
    };
    var rec = Recorder{};
    var entries = sinkFlow("dns-01", "https://ca/chal/d");
    var mock = SinkMock{ .entries = &entries, .observer = &rec, .on_post = Recorder.onPost };

    const account = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x31)));
    const cert_key = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x32)));
    var account_es = Es256Signer.init(account);
    var cert_es = Es256Signer.init(cert_key);
    var client = acme.Acme.init(std.testing.allocator, .{
        .directory_url = "https://ca/dir",
        .domains = &.{"irc.example.test"},
        .signer = account_es.signer(),
        .cert_signer = cert_es.signer(),
        .challenge = .dns_01,
    });
    defer client.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var sink = EffectSink{
        .allocator = std.testing.allocator,
        .io = io,
        .dir = tmp.dir,
        .cert_out_path = "chain.pem",
        .key_out_path = "key.pem",
        .cert_key = cert_key,
        .dns = .{ .ctx = &rec, .runFn = Recorder.run },
        .dns_propagation_delay_ms = 1,
    };
    const result = try runSteps(&client, mock.transport(), &sink, 64);
    try std.testing.expectEqual(acme.State.done, result.state);
    try std.testing.expect(result.cert_written);
    try std.testing.expect(rec.add_before_post);
    try std.testing.expectEqual(@as(usize, 2), rec.n);

    // TXT value = base64url(SHA-256("tok1." ++ JWK thumbprint of the ACCOUNT key)).
    const sec1 = account.public_key.toUncompressedSec1();
    var thumb_digest: [32]u8 = undefined;
    @import("../proto/acme_jwk.zig").thumbprintEc(sec1[1..33].*, sec1[33..65].*, &thumb_digest);
    var thumb_buf: [64]u8 = undefined;
    const thumb = std.base64.url_safe_no_pad.Encoder.encode(&thumb_buf, &thumb_digest);
    var ka_buf: [128]u8 = undefined;
    const ka = try acme_challenge.keyAuthorization("tok1", thumb, &ka_buf);
    var txt_buf: [64]u8 = undefined;
    const txt = try acme_challenge.dns01TxtValue(ka, &txt_buf);
    var want: [128]u8 = undefined;
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&want, "add _acme-challenge.irc.example.test {s}", .{txt}), rec.log[0][0..rec.lens[0]]);
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&want, "del _acme-challenge.irc.example.test {s}", .{txt}), rec.log[1][0..rec.lens[1]]);

    var buf: [256]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, try tmp.dir.readFile(io, "chain.pem", &buf), "-----BEGIN CERTIFICATE-----"));
    const st = try tmp.dir.statFile(io, "key.pem", .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);
}

test "runSteps dns-01: a failing hook add still gets del and aborts before validation" {
    const Failing = struct {
        adds: usize = 0,
        dels: usize = 0,
        fn run(ctx: *anyopaque, action: HookAction, _: []const u8, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            switch (action) {
                .add => {
                    self.adds += 1;
                    return error.HookFailed;
                },
                .del => self.dels += 1,
            }
        }
    };
    var hook = Failing{};
    var entries = sinkFlow("dns-01", "https://ca/chal/d");
    var mock = SinkMock{ .entries = &entries };
    const account = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x41)));
    const cert_key = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x42)));
    var account_es = Es256Signer.init(account);
    var cert_es = Es256Signer.init(cert_key);
    var client = acme.Acme.init(std.testing.allocator, .{
        .directory_url = "https://ca/dir",
        .domains = &.{"irc.example.test"},
        .signer = account_es.signer(),
        .cert_signer = cert_es.signer(),
        .challenge = .dns_01,
    });
    defer client.deinit();
    var sink = EffectSink{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .dir = std.Io.Dir.cwd(),
        .cert_out_path = "/nonexistent/never-written.pem",
        .key_out_path = null,
        .cert_key = cert_key,
        .dns = .{ .ctx = &hook, .runFn = Failing.run },
    };
    try std.testing.expectError(error.HookFailed, runSteps(&client, mock.transport(), &sink, 64));
    try std.testing.expectEqual(@as(usize, 1), hook.adds);
    try std.testing.expectEqual(@as(usize, 1), hook.dels);
    try std.testing.expect(!entries[5].used); // challenge never POSTed
}

test "runSteps tls-alpn-01: challenge cert is live in the store during validation and gone after" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var store: TlsAlpn01Store = .{};
    const Observer = struct {
        store: *TlsAlpn01Store,
        live_at_post: bool = false,
        cert_ok: bool = false,
        fn onPost(ctx: *anyopaque, url: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!std.mem.eql(u8, url, "https://ca/chal/t")) return;
            var lease = self.store.lookup("irc.example.test") orelse return;
            defer lease.wipe();
            self.live_at_post = true;
            // The leased certificate's SPKI is the leased key (what the TLS
            // engine checks in leafKeyKindMatches / CertificateVerify).
            const sec1 = lease.key_pair.public_key.toUncompressedSec1();
            self.cert_ok = std.mem.indexOf(u8, lease.certDer(), &sec1) != null and
                std.mem.indexOf(u8, lease.certDer(), &acme_challenge.id_pe_acme_identifier_oid) != null;
        }
    };
    var obs = Observer{ .store = &store };
    var entries = sinkFlow("tls-alpn-01", "https://ca/chal/t");
    var mock = SinkMock{ .entries = &entries, .observer = &obs, .on_post = Observer.onPost };
    const account = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x51)));
    const cert_key = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x52)));
    var account_es = Es256Signer.init(account);
    var cert_es = Es256Signer.init(cert_key);
    var client = acme.Acme.init(std.testing.allocator, .{
        .directory_url = "https://ca/dir",
        .domains = &.{"irc.example.test"},
        .signer = account_es.signer(),
        .cert_signer = cert_es.signer(),
        .challenge = .tls_alpn_01,
    });
    defer client.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var sink = EffectSink{
        .allocator = std.testing.allocator,
        .io = io,
        .dir = tmp.dir,
        .cert_out_path = "chain.pem",
        .key_out_path = null,
        .cert_key = cert_key,
        .tls_alpn01 = &store,
    };
    const result = try runSteps(&client, mock.transport(), &sink, 64);
    try std.testing.expect(result.cert_written);
    try std.testing.expect(obs.live_at_post);
    try std.testing.expect(obs.cert_ok);
    try std.testing.expect(store.isEmpty());
}

test "runSteps fails closed when the configured challenge has no provisioner" {
    var entries = sinkFlow("dns-01", "https://ca/chal/d");
    var mock = SinkMock{ .entries = &entries };
    const account = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x61)));
    const cert_key = try ecdsa_p256.generateDeterministic(@as([32]u8, @splat(0x62)));
    var account_es = Es256Signer.init(account);
    var cert_es = Es256Signer.init(cert_key);
    var client = acme.Acme.init(std.testing.allocator, .{
        .directory_url = "https://ca/dir",
        .domains = &.{"irc.example.test"},
        .signer = account_es.signer(),
        .cert_signer = cert_es.signer(),
        .challenge = .dns_01,
    });
    defer client.deinit();
    var sink = EffectSink{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .dir = std.Io.Dir.cwd(),
        .cert_out_path = "/nonexistent/x.pem",
        .key_out_path = null,
        .cert_key = cert_key,
    };
    try std.testing.expectError(error.Dns01Unavailable, runSteps(&client, mock.transport(), &sink, 64));
    try std.testing.expect(!entries[5].used);
}

test "outbound TLS client keeps RFC 8701 GREASE on and GREASE ECH off" {
    try std.testing.expect(outbound_grease);
    try std.testing.expect(!outbound_ech_grease);
    var tc = try tls_client.Client.init(std.testing.allocator, .{ .server_name = "example.test", .trust_anchors = &.{}, .grease = outbound_grease, .ech_grease = outbound_ech_grease });
    defer tc.deinit();
    try std.testing.expect(tc.grease != null);
    try std.testing.expect(!tc.ech_grease);
}
