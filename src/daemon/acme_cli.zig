// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `onyx-server acme-issue` entry: assemble the clean-room ACME stack into a single
//! out-of-band issuance run. Loads (or creates once, 0600) the persistent ES256
//! (ECDSA P-256) ACME account key, generates a fresh, distinct certificate key,
//! loads trust anchors from a CA bundle, answers http-01 through the loopback
//! listener (which nginx proxies `/.well-known/acme-challenge/` to) or dns-01
//! through an operator hook, and drives `acme_runner.issue`. tls-alpn-01 needs
//! the daemon's TLS listener and is only available to in-daemon renewal.
//!
//! Defaults target Let's Encrypt STAGING (the chosen dry-run posture). It never
//! touches certbot or /etc/letsencrypt; the chain is written to a kain-owned path.

const std = @import("std");
const dlog = @import("dlog.zig");

const acme_runner = @import("acme_runner.zig");
const http01 = @import("acme_http01_server.zig");
const listener = @import("acme_http01_listener.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const ca_bundle_mod = @import("ca_bundle.zig");
const toml = @import("../proto/toml.zig");

const Allocator = std.mem.Allocator;

pub const staging_directory = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const prod_directory = "https://acme-v02.api.letsencrypt.org/directory";
pub const default_ca_bundle = ca_bundle_mod.default_path;
/// Fixed loopback port nginx proxies the ACME challenge path to.
pub const default_challenge_port: u16 = 14402;
/// Max bytes read from the CA-bundle file (defense against a runaway/huge file).
pub const default_ca_bundle_max_bytes: usize = ca_bundle_mod.default_max_bytes;

pub const Options = struct {
    domain: []const u8,
    directory_url: []const u8 = staging_directory,
    cert_out_path: []const u8,
    ca_bundle_path: []const u8 = default_ca_bundle,
    contact: ?[]const u8 = null,
    challenge_port: u16 = default_challenge_port,
    /// Cert private-key output path. Null => derive from `cert_out_path`.
    key_out_path: ?[]const u8 = null,
    debug: bool = false,
    /// Max bytes read from the CA-bundle file.
    ca_bundle_max_bytes: usize = default_ca_bundle_max_bytes,
    /// Persistent account key path. Null => `acme-account.key.pem` beside the
    /// certificate key.
    account_key_path: ?[]const u8 = null,
    /// http-01 (default) or dns-01.
    challenge: acme_runner.ChallengeType = .http_01,
    /// dns-01 operator hook (absolute path); required for dns-01.
    dns_hook: ?[]const u8 = null,
    dns_hook_timeout_ms: u32 = acme_runner.default_dns_hook_timeout_ms,
    dns_propagation_delay_ms: u32 = acme_runner.default_dns_propagation_delay_ms,
};

/// Overlay `[acme]` config onto `opts`, leaving any key absent from the document
/// at its current (default / CLI-supplied) value. Behavior is unchanged when the
/// document carries none of these keys. String values borrow `doc` — the caller
/// must keep the parsed document alive for the lifetime of `opts`.
///
/// Note: `prod_directory_url` is overlaid only when the active directory is still
/// the staging default, so an explicit `--prod` (already pointing at production)
/// or a `staging_directory_url` override is never clobbered by it.
pub fn applyToml(opts: *Options, doc: *const toml.Document) void {
    // Honor a configured staging endpoint whenever the run is still on staging.
    if (std.mem.eql(u8, opts.directory_url, staging_directory)) {
        if (doc.getString("acme.staging_directory_url")) |v| opts.directory_url = v;
    }
    // Honor a configured production endpoint only for prod runs (the default
    // directory_url at this point is staging unless --prod was passed).
    if (std.mem.eql(u8, opts.directory_url, prod_directory)) {
        if (doc.getString("acme.prod_directory_url")) |v| opts.directory_url = v;
    }
    if (doc.getString("acme.ca_bundle_path")) |v| opts.ca_bundle_path = v;
    if (doc.getUint("acme.challenge_port")) |v| {
        if (v >= 1 and v <= std.math.maxInt(u16)) opts.challenge_port = @intCast(v);
    }
    if (doc.getUint("acme.ca_bundle_max_bytes")) |v| {
        if (v != 0) opts.ca_bundle_max_bytes = @intCast(v);
    }
    if (opts.account_key_path == null) {
        if (doc.getString("acme.account_key_path")) |v| opts.account_key_path = v;
    }
    if (opts.dns_hook == null) {
        if (doc.getString("acme.dns_hook")) |v| opts.dns_hook = v;
    }
}

/// Print a one-line usage summary for the acme-issue subcommand.
pub fn usage() void {
    dlog.log(
        \\usage: onyx-server acme-issue --domain <fqdn> --out <path> [options]
        \\  --domain <fqdn>        domain to issue for (required)
        \\  --out <path>           cert chain output path (required; kain-owned dir)
        \\  --key-out <path>       cert key output path (default: <out>.key.pem)
        \\  --prod                 use Let's Encrypt PRODUCTION (default: staging)
        \\  --ca-bundle <path>     trust anchors PEM (default: {s})
        \\  --contact <mailto:..>  ACME account contact (optional)
        \\  --port <n>             loopback HTTP-01 port nginx proxies to (default: {d})
        \\  --account-key <path>   persistent ACME account key (default: acme-account.key.pem
        \\                         beside the cert key; created once, mode 0600)
        \\  --challenge <type>     http-01 (default) or dns-01
        \\  --dns-hook <path>      dns-01: absolute path of an executable run as
        \\                         `<hook> add|del <fqdn> <txt>` (required for dns-01)
        \\
    , .{ default_ca_bundle, default_challenge_port });
}

/// Parse the args following `acme-issue`. Returns null (after printing usage) on
/// a malformed invocation. Slices borrow `args`.
pub fn parseArgs(args: []const []const u8) ?Options {
    var domain: ?[]const u8 = null;
    var out: ?[]const u8 = null;
    var directory: []const u8 = staging_directory;
    var ca_bundle: []const u8 = default_ca_bundle;
    var contact: ?[]const u8 = null;
    var key_out: ?[]const u8 = null;
    var port: u16 = default_challenge_port;
    var debug = false;
    var account_key: ?[]const u8 = null;
    var challenge: acme_runner.ChallengeType = .http_01;
    var dns_hook: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--prod")) {
            directory = prod_directory;
        } else if (std.mem.eql(u8, a, "--debug")) {
            debug = true;
        } else if (std.mem.eql(u8, a, "--domain") and i + 1 < args.len) {
            i += 1;
            domain = args[i];
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out = args[i];
        } else if (std.mem.eql(u8, a, "--key-out") and i + 1 < args.len) {
            i += 1;
            key_out = args[i];
        } else if (std.mem.eql(u8, a, "--ca-bundle") and i + 1 < args.len) {
            i += 1;
            ca_bundle = args[i];
        } else if (std.mem.eql(u8, a, "--contact") and i + 1 < args.len) {
            i += 1;
            contact = args[i];
        } else if (std.mem.eql(u8, a, "--port") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch return null;
        } else if (std.mem.eql(u8, a, "--account-key") and i + 1 < args.len) {
            i += 1;
            account_key = args[i];
        } else if (std.mem.eql(u8, a, "--challenge") and i + 1 < args.len) {
            i += 1;
            challenge = acme_runner.ChallengeType.fromString(args[i]) orelse return null;
        } else if (std.mem.eql(u8, a, "--dns-hook") and i + 1 < args.len) {
            i += 1;
            dns_hook = args[i];
        } else {
            return null;
        }
    }

    if (domain == null or out == null) return null;
    switch (challenge) {
        .http_01 => {},
        .dns_01 => {
            const hook = dns_hook orelse return null;
            if (!std.fs.path.isAbsolute(hook)) return null;
        },
        // Needs the daemon's TLS listener to serve acme-tls/1.
        .tls_alpn_01 => return null,
    }
    return .{
        .domain = domain.?,
        .directory_url = directory,
        .cert_out_path = out.?,
        .ca_bundle_path = ca_bundle,
        .contact = contact,
        .challenge_port = port,
        .key_out_path = key_out,
        .debug = debug,
        .account_key_path = account_key,
        .challenge = challenge,
        .dns_hook = dns_hook,
    };
}

/// Run a full issuance. Returns true iff a certificate was written.
pub fn runIssue(allocator: Allocator, io: std.Io, opts: Options) !bool {
    // --- Trust anchors from the CA bundle ---
    const bundle_text = try std.Io.Dir.cwd().readFileAlloc(io, opts.ca_bundle_path, allocator, .limited(opts.ca_bundle_max_bytes));
    defer allocator.free(bundle_text);

    var anchors = try loadTrustAnchors(allocator, bundle_text);
    defer freeTrustAnchors(allocator, &anchors);
    if (anchors.items.len == 0) return error.NoTrustAnchors;
    dlog.log("acme: loaded {d} trust anchors from {s}\n", .{ anchors.items.len, opts.ca_bundle_path });

    // Key path: explicit --key-out, else derive (<cert without .pem>.key.pem).
    const derived_key = try deriveKeyPath(allocator, opts.cert_out_path);
    defer allocator.free(derived_key);
    const key_out = opts.key_out_path orelse derived_key;

    // --- Keys: ES256 / ECDSA P-256 (the alg Let's Encrypt accepts). The
    // account key is persisted and reused (RFC 8555 §7.3.1: newAccount with a
    // known key returns the existing account); the certificate key is fresh
    // per run and MUST differ (LE rejects a CSR keyed to the account). ---
    const derived_account = try acme_runner.defaultAccountKeyPath(allocator, key_out);
    defer allocator.free(derived_account);
    const account_path = opts.account_key_path orelse derived_account;
    try acme_runner.checkAccountKeyPath(account_path, opts.cert_out_path, key_out);
    var account = try acme_runner.loadOrCreateAccountKey(io, std.Io.Dir.cwd(), account_path);
    defer account.wipe();
    dlog.log("acme: account key {s} ({s})\n", .{ account_path, if (account.created) "created; registering new account" else "loaded" });
    var cert_key = ecdsa_p256.generate(io);
    defer ecdsa_p256.wipeKeyPair(&cert_key);

    // --- Loopback HTTP-01 listener (nginx proxies the challenge path here) ---
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();
    var server: ?listener.ChallengeServer = null;
    defer if (server) |*s| s.shutdown();
    if (opts.challenge == .http_01) {
        server = try listener.ChallengeServer.init(&store, opts.challenge_port);
        // spawn() shuts the listener down itself on failure.
        server.?.spawn() catch |err| {
            server = null;
            return err;
        };
        dlog.log("acme: HTTP-01 listener on 127.0.0.1:{d}\n", .{server.?.port});
    }

    // --- Drive issuance ---
    const domains = [_][]const u8{opts.domain};
    var contacts_storage: [1][]const u8 = undefined;
    const contacts: []const []const u8 = if (opts.contact) |c| blk: {
        contacts_storage[0] = c;
        break :blk contacts_storage[0..1];
    } else &.{};

    const result = try acme_runner.issue(allocator, io, .{
        .directory_url = opts.directory_url,
        .domains = &domains,
        .contacts = contacts,
        .trust_anchors = anchors.items,
        .cert_out_path = opts.cert_out_path,
        .key_out_path = key_out,
        .debug = opts.debug,
        .challenge = opts.challenge,
        .dns_hook = if (opts.dns_hook) |h| .{ .path = h, .timeout_ms = opts.dns_hook_timeout_ms } else null,
        .dns_propagation_delay_ms = opts.dns_propagation_delay_ms,
    }, account.key_pair, cert_key, if (opts.challenge == .http_01) &store else null, null);

    if (result.cert_written) {
        dlog.log("acme: SUCCESS — wrote chain {s}\n              and key {s}\n", .{ opts.cert_out_path, key_out });
    } else {
        dlog.log("acme: finished in state {s} without a cert\n", .{@tagName(result.state)});
    }
    return result.cert_written;
}

/// Derive the key output path from the cert path: strip a trailing ".pem" and
/// append ".key.pem", else append ".key". Caller owns the result.
fn deriveKeyPath(allocator: Allocator, cert_path: []const u8) ![]u8 {
    if (std.mem.endsWith(u8, cert_path, ".pem")) {
        const stem = cert_path[0 .. cert_path.len - ".pem".len];
        return std.fmt.allocPrint(allocator, "{s}.key.pem", .{stem});
    }
    return std.fmt.allocPrint(allocator, "{s}.key", .{cert_path});
}

/// Decode every `CERTIFICATE` PEM block in `text` into owned DER, in order.
/// Shared with the geo news fetcher; see `ca_bundle.zig`.
pub const loadTrustAnchors = ca_bundle_mod.loadTrustAnchors;
const freeTrustAnchors = ca_bundle_mod.freeTrustAnchors;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseArgs requires domain and out, toggles prod" {
    try std.testing.expect(parseArgs(&.{"--domain"}) == null);
    try std.testing.expect(parseArgs(&.{ "--domain", "x.test" }) == null); // no --out

    const ok = parseArgs(&.{ "--domain", "eshmaki.me", "--out", "/p/cert.pem" }).?;
    try std.testing.expectEqualStrings("eshmaki.me", ok.domain);
    try std.testing.expectEqualStrings("/p/cert.pem", ok.cert_out_path);
    try std.testing.expectEqualStrings(staging_directory, ok.directory_url);

    const prod = parseArgs(&.{ "--domain", "eshmaki.me", "--out", "/p/c.pem", "--prod" }).?;
    try std.testing.expectEqualStrings(prod_directory, prod.directory_url);
}

test "parseArgs: account key, dns-01 hook, and refused tls-alpn-01" {
    const base = [_][]const u8{ "--domain", "irc.example.test", "--out", "/p/c.pem" };
    const plain = parseArgs(&base).?;
    try std.testing.expectEqual(acme_runner.ChallengeType.http_01, plain.challenge);
    try std.testing.expect(plain.account_key_path == null);

    const dns = parseArgs(&(base ++ [_][]const u8{ "--challenge", "dns-01", "--dns-hook", "/usr/local/bin/hook", "--account-key", "/p/acct.pem" })).?;
    try std.testing.expectEqual(acme_runner.ChallengeType.dns_01, dns.challenge);
    try std.testing.expectEqualStrings("/usr/local/bin/hook", dns.dns_hook.?);
    try std.testing.expectEqualStrings("/p/acct.pem", dns.account_key_path.?);

    try std.testing.expect(parseArgs(&(base ++ [_][]const u8{ "--challenge", "dns-01" })) == null); // no hook
    try std.testing.expect(parseArgs(&(base ++ [_][]const u8{ "--challenge", "dns-01", "--dns-hook", "hook" })) == null); // relative
    try std.testing.expect(parseArgs(&(base ++ [_][]const u8{ "--challenge", "tls-alpn-01" })) == null);
    try std.testing.expect(parseArgs(&(base ++ [_][]const u8{ "--challenge", "bogus" })) == null);
}

test "deriveKeyPath swaps .pem for .key.pem, else appends .key" {
    const allocator = std.testing.allocator;
    const a = try deriveKeyPath(allocator, "/p/eshmaki.me.fullchain.pem");
    defer allocator.free(a);
    try std.testing.expectEqualStrings("/p/eshmaki.me.fullchain.key.pem", a);
    const b = try deriveKeyPath(allocator, "/p/cert");
    defer allocator.free(b);
    try std.testing.expectEqualStrings("/p/cert.key", b);
}

test "loadTrustAnchors decodes multiple CERTIFICATE blocks" {
    const allocator = std.testing.allocator;
    // Two minimal PEM blocks wrapping the DER bytes {0x30,0x03,0x02,0x01,0x00}
    // (base64 "MAMCAQA="). Content need not be a valid cert for this decode test.
    const text =
        "# comment\n" ++
        "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n" ++
        "junk between\n" ++
        "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n";

    var anchors = try loadTrustAnchors(allocator, text);
    defer freeTrustAnchors(allocator, &anchors);

    try std.testing.expectEqual(@as(usize, 2), anchors.items.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }, anchors.items[0]);
}

test "applyToml overlays acme keys and leaves absent keys at defaults" {
    const allocator = std.testing.allocator;
    const src =
        \\[acme]
        \\staging_directory_url = "https://staging.example/dir"
        \\ca_bundle_path = "/custom/ca.pem"
        \\challenge_port = 8888
        \\ca_bundle_max_bytes = 1048576
    ;
    var doc = try toml.parse(allocator, src);
    defer doc.deinit(allocator);

    var opts: Options = .{ .domain = "x.test", .cert_out_path = "/p/c.pem" };
    applyToml(&opts, &doc);

    try std.testing.expectEqualStrings("https://staging.example/dir", opts.directory_url);
    try std.testing.expectEqualStrings("/custom/ca.pem", opts.ca_bundle_path);
    try std.testing.expectEqual(@as(u16, 8888), opts.challenge_port);
    try std.testing.expectEqual(@as(usize, 1048576), opts.ca_bundle_max_bytes);
}

test "applyToml is a no-op when the acme table is absent" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[server]\nname = \"mz\"\n");
    defer doc.deinit(allocator);

    var opts: Options = .{ .domain = "x.test", .cert_out_path = "/p/c.pem" };
    applyToml(&opts, &doc);

    try std.testing.expectEqualStrings(staging_directory, opts.directory_url);
    try std.testing.expectEqualStrings(default_ca_bundle, opts.ca_bundle_path);
    try std.testing.expectEqual(default_challenge_port, opts.challenge_port);
    try std.testing.expectEqual(default_ca_bundle_max_bytes, opts.ca_bundle_max_bytes);
}

test "applyToml overlays prod_directory_url only on prod runs" {
    const allocator = std.testing.allocator;
    const src =
        \\[acme]
        \\prod_directory_url = "https://prod.example/dir"
    ;
    var doc = try toml.parse(allocator, src);
    defer doc.deinit(allocator);

    // Staging run: prod override must NOT apply.
    var staging_opts: Options = .{ .domain = "x.test", .cert_out_path = "/p/c.pem" };
    applyToml(&staging_opts, &doc);
    try std.testing.expectEqualStrings(staging_directory, staging_opts.directory_url);

    // Prod run (e.g. --prod): the override applies.
    var prod_opts: Options = .{ .domain = "x.test", .cert_out_path = "/p/c.pem", .directory_url = prod_directory };
    applyToml(&prod_opts, &doc);
    try std.testing.expectEqualStrings("https://prod.example/dir", prod_opts.directory_url);
}

test "applyToml rejects out-of-range challenge_port and zero max bytes" {
    const allocator = std.testing.allocator;
    const src =
        \\[acme]
        \\challenge_port = 70000
        \\ca_bundle_max_bytes = 0
    ;
    var doc = try toml.parse(allocator, src);
    defer doc.deinit(allocator);

    var opts: Options = .{ .domain = "x.test", .cert_out_path = "/p/c.pem" };
    applyToml(&opts, &doc);
    try std.testing.expectEqual(default_challenge_port, opts.challenge_port);
    try std.testing.expectEqual(default_ca_bundle_max_bytes, opts.ca_bundle_max_bytes);
}

test {
    std.testing.refAllDecls(@This());
}
