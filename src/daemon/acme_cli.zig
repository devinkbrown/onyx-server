// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `onyx-server acme-issue` entry: assemble the clean-room ACME stack into a single
//! out-of-band issuance run. Generates distinct ES256 (ECDSA P-256) account and
//! certificate keys, loads trust anchors from a CA bundle, starts the loopback
//! HTTP-01 listener (which nginx proxies `/.well-known/acme-challenge/` to), and
//! drives `acme_runner.issue`.
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
        } else {
            return null;
        }
    }

    if (domain == null or out == null) return null;
    return .{
        .domain = domain.?,
        .directory_url = directory,
        .cert_out_path = out.?,
        .ca_bundle_path = ca_bundle,
        .contact = contact,
        .challenge_port = port,
        .key_out_path = key_out,
        .debug = debug,
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

    // --- Keys: ES256 / ECDSA P-256 (the alg Let's Encrypt accepts). The account
    // and certificate keys MUST differ (LE rejects a CSR keyed to the account).
    // Fresh per run; staging accounts are disposable. ---
    const account_key = ecdsa_p256.KeyPair.generate(io);
    const cert_key = ecdsa_p256.KeyPair.generate(io);

    // --- Loopback HTTP-01 listener (nginx proxies the challenge path here) ---
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();
    var server = try listener.ChallengeServer.init(&store, opts.challenge_port);
    try server.spawn();
    defer server.shutdown();
    dlog.log("acme: HTTP-01 listener on 127.0.0.1:{d}\n", .{server.port});

    // --- Drive issuance ---
    const domains = [_][]const u8{opts.domain};
    var contacts_storage: [1][]const u8 = undefined;
    const contacts: []const []const u8 = if (opts.contact) |c| blk: {
        contacts_storage[0] = c;
        break :blk contacts_storage[0..1];
    } else &.{};

    // Key path: explicit --key-out, else derive (<cert without .pem>.key.pem).
    const derived_key = try deriveKeyPath(allocator, opts.cert_out_path);
    defer allocator.free(derived_key);
    const key_out = opts.key_out_path orelse derived_key;

    const result = try acme_runner.issue(allocator, io, .{
        .directory_url = opts.directory_url,
        .domains = &domains,
        .contacts = contacts,
        .trust_anchors = anchors.items,
        .cert_out_path = opts.cert_out_path,
        .key_out_path = key_out,
        .debug = opts.debug,
    }, account_key, cert_key, &store, null);

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
