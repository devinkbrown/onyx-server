// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor verify` — certificate-chain verification against a CA bundle.
//!
//! All trust decisions are substrate calls: chain signature + validity +
//! CA/pathlen/name-constraint enforcement via src/crypto/x509_verify.zig
//! (`verifySimpleChainAt`), anchors loaded with the daemon's own bundle
//! loader (src/daemon/acme_cli.zig `loadTrustAnchors`). The optional `-name`
//! check mirrors the single-label wildcard semantics of the (file-private)
//! matcher in src/crypto/tls_client.zig `dnsPatternMatches` — exporting that
//! is a noted substrate gap; the mirror here is string comparison only.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const x509 = onyx_server.crypto.x509;
const x509_verify = onyx_server.crypto.x509_verify;
const pem = onyx_server.proto.pem;
const acme_cli = onyx_server.daemon.acme_cli;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

/// Cap on certificates accepted from the input chain file.
pub const max_chain = 8;

pub const Options = struct {
    ca_file: []const u8 = "",
    in_path: []const u8 = "-",
    /// Expected DNS name to match against the leaf SAN (openssl -verify_hostname).
    name: ?[]const u8 = null,
    /// Verification instant; null = wall clock. Exposed for deterministic tests.
    at_epoch: ?i64 = null,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor verify -CAfile <bundle> [-name <dns>] [cert]
        \\  -CAfile <path>  PEM bundle of trust anchors (required)
        \\  -name <dns>     require the leaf SAN to match this DNS name
        \\  -at <epoch>     verify at this Unix time (default: now)
        \\  [cert]          leaf or leaf+intermediates PEM; default stdin
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-CAfile")) {
            opts.ca_file = try cur.value();
        } else if (std.mem.eql(u8, a, "-name")) {
            opts.name = try cur.value();
        } else if (std.mem.eql(u8, a, "-at")) {
            opts.at_epoch = std.fmt.parseInt(i64, try cur.value(), 10) catch return error.Usage;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            return error.Usage;
        } else {
            opts.in_path = a;
        }
    }
    if (opts.ca_file.len == 0) return error.Usage;
    return opts;
}

/// Decode every CERTIFICATE block in `text` (up to `max_chain`), oldest-first
/// order preserved: leaf first, then intermediates, like a server cert file.
pub fn decodeChain(gpa: Allocator, text: []const u8, chain: *[max_chain][]u8, count: *usize) !void {
    count.* = 0;
    errdefer for (chain[0..count.*]) |c| gpa.free(c);

    var rest = text;
    while (count.* < max_chain) {
        const begin = std.mem.indexOf(u8, rest, "-----BEGIN CERTIFICATE-----") orelse break;
        const block = rest[begin..];
        const buf = try gpa.alloc(u8, block.len);
        errdefer gpa.free(buf);
        const der = try pem.decode(block, "CERTIFICATE", buf);
        const owned = try gpa.dupe(u8, der);
        gpa.free(buf);
        chain[count.*] = owned;
        count.* += 1;
        const end_marker = "-----END CERTIFICATE-----";
        const end = std.mem.indexOf(u8, block, end_marker) orelse break;
        rest = block[end + end_marker.len ..];
    }
    if (count.* == 0) return error.BeginNotFound;
}

/// RFC 9525, same rule as the TLS clients: an IP literal matches an
/// iPAddress SAN only. A DNS name matches dNSName only.
fn presentedNameMatches(name: []const u8, cert: x509.Certificate) bool {
    if (x509.IpAddress.parseLiteral(name)) |ip| {
        for (cert.san_ips[0..cert.san_ip_count]) |*san| {
            if (std.mem.eql(u8, san.slice(), ip.slice())) return true;
        }
        return false;
    }
    if (std.mem.indexOfScalar(u8, name, ':') != null) return false;
    for (cert.san_dns[0..cert.san_dns_count]) |san| {
        if (dnsPatternMatches(san, name)) return true;
    }
    return false;
}

/// Single-label DNS wildcard match (`*.example.com` matches `a.example.com`,
/// never `a.b.example.com`) — mirrors tls_client.zig's private matcher.
pub fn dnsPatternMatches(pattern: []const u8, name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(pattern, name)) return true;
    // len >= 3 matches the substrate guard exactly: a degenerate "*." is not
    // a wildcard (tls_client.zig:3449 rejects it the same way).
    if (pattern.len < 3 or !std.mem.startsWith(u8, pattern, "*.")) return false;
    const suffix = pattern[1..]; // ".example.com"
    if (name.len <= suffix.len) return false;
    const label = name[0 .. name.len - suffix.len];
    if (label.len == 0 or std.mem.indexOfScalar(u8, label, '.') != null) return false;
    return std.ascii.eqlIgnoreCase(suffix, name[name.len - suffix.len ..]);
}

pub const VerifyError = error{
    NoMatchingAnchor,
    NameMismatch,
};

/// Verify `chain` (leaf first) against `anchors` at `now`. Success requires
/// one anchor that completes a substrate-verified chain (signatures, validity
/// window, CA bits, path length, name constraints — x509_verify does all of
/// it). Fail-closed: no anchor works => error.
pub fn verifyChain(
    gpa: Allocator,
    chain: []const []const u8,
    anchors: []const []const u8,
    now: i64,
    expected_name: ?[]const u8,
) !void {
    if (expected_name) |name| {
        const leaf = try x509.parse(chain[0]);
        if (!presentedNameMatches(name, leaf)) return error.NameMismatch;
    }

    var full = try gpa.alloc([]const u8, chain.len + 1);
    defer gpa.free(full);
    @memcpy(full[0..chain.len], chain);

    var last_err: anyerror = error.NoMatchingAnchor;
    for (anchors) |anchor| {
        full[chain.len] = anchor;
        if (x509_verify.verifySimpleChainAt(full, now)) |_| {
            return;
        } else |err| {
            last_err = err;
        }
        // The chain may already end in a self-signed root present in the
        // bundle: accept `chain` alone when its last cert IS the anchor.
        if (std.mem.eql(u8, chain[chain.len - 1], anchor)) {
            if (x509_verify.verifySimpleChainAt(chain, now)) |_| return else |err| {
                last_err = err;
            }
        }
    }
    return last_err;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const chain_text = try common.readInput(gpa, io, opts.in_path);
    defer gpa.free(chain_text);
    var chain: [max_chain][]u8 = undefined;
    var chain_count: usize = 0;
    try decodeChain(gpa, chain_text, &chain, &chain_count);
    defer for (chain[0..chain_count]) |c| gpa.free(c);

    const bundle_text = try common.readInput(gpa, io, opts.ca_file);
    defer gpa.free(bundle_text);
    var anchors = try acme_cli.loadTrustAnchors(gpa, bundle_text);
    defer {
        for (anchors.items) |a| gpa.free(a);
        anchors.deinit(gpa);
    }
    if (anchors.items.len == 0) return error.NoMatchingAnchor;

    const now = opts.at_epoch orelse common.wallClockSeconds();
    var view: [max_chain][]const u8 = undefined;
    for (chain[0..chain_count], 0..) |c, i| view[i] = c;
    try verifyChain(gpa, view[0..chain_count], anchors.items, now, opts.name);
    try out.print("{s}: OK\n", .{opts.in_path});
}

// ===========================================================================
// Tests — anchors + leaves minted with the substrate self-sign builder.
// ===========================================================================

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const ecdsa_p256 = onyx_server.crypto.ecdsa_p256;

test "armorcli verify accepts a root-issued leaf and rejects a stranger" {
    const gpa = testing.allocator;
    const io = std.testing.io;
    const now: i64 = 1_800_000_000;

    // Arrange: CA root + a leaf it issued; a second, unrelated root.
    const ca_kp = ecdsa_p256.KeyPair.generate(io);
    var ca_buf: [2048]u8 = undefined;
    const ca_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ca_buf, .{
        .common_name = "armorcli root",
        .not_before = now - 1000,
        .not_after = now + 100_000,
        .serial = &.{0x01},
        .key_pair = ca_kp,
        .dns_names = &.{"root.test"},
        .is_ca = true,
    });
    const leaf_kp = ecdsa_p256.KeyPair.generate(io);
    var leaf_buf: [2048]u8 = undefined;
    // buildEcdsaP256IssuedBy writes subject == issuer == common_name (a test
    // builder limitation, x509_selfsign.zig:271), so the leaf CN must equal
    // the CA subject for DN linkage. Naming lives in the SAN anyway (RFC 6125).
    const leaf_der = try x509_selfsign.buildEcdsaP256IssuedBy(&leaf_buf, .{
        .common_name = "armorcli root",
        .not_before = now - 1000,
        .not_after = now + 100_000,
        .serial = &.{0x02},
        .key_pair = leaf_kp,
        .dns_names = &.{ "leaf.test", "*.wild.test" },
    }, ca_kp);
    const other_kp = ecdsa_p256.KeyPair.generate(io);
    var other_buf: [2048]u8 = undefined;
    const other_der = try x509_selfsign.buildSelfSignedEcdsaP256(&other_buf, .{
        .common_name = "unrelated root",
        .not_before = now - 1000,
        .not_after = now + 100_000,
        .serial = &.{0x03},
        .key_pair = other_kp,
        .dns_names = &.{"other.test"},
        .is_ca = true,
    });

    // Act / Assert: right anchor verifies; wrong anchor fails closed.
    try verifyChain(gpa, &.{leaf_der}, &.{ca_der}, now, "leaf.test");
    try verifyChain(gpa, &.{leaf_der}, &.{ other_der, ca_der }, now, null);
    try testing.expect(std.meta.isError(verifyChain(gpa, &.{leaf_der}, &.{other_der}, now, null)));

    // Expired instant fails.
    try testing.expect(std.meta.isError(verifyChain(gpa, &.{leaf_der}, &.{ca_der}, now + 200_000, null)));

    // Name matching: exact + single-label wildcard, never multi-label.
    try verifyChain(gpa, &.{leaf_der}, &.{ca_der}, now, "a.wild.test");
    try testing.expectError(error.NameMismatch, verifyChain(gpa, &.{leaf_der}, &.{ca_der}, now, "a.b.wild.test"));
    try testing.expectError(error.NameMismatch, verifyChain(gpa, &.{leaf_der}, &.{ca_der}, now, "evil.test"));
}

test "GAP-K15 armorcli verify matches an IP literal against iPAddress only" {
    const gpa = testing.allocator;
    const io = std.testing.io;
    const now: i64 = 1_800_000_000;
    const ca_kp = ecdsa_p256.KeyPair.generate(io);
    var ca_buf: [2048]u8 = undefined;
    const ca_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ca_buf, .{
        .common_name = "k15 root",
        .not_before = now - 1000,
        .not_after = now + 100_000,
        .serial = &.{0x15},
        .key_pair = ca_kp,
        .dns_names = &.{"k15.test"},
        .is_ca = true,
    });
    const leaf_kp = ecdsa_p256.KeyPair.generate(io);
    var leaf_buf: [2048]u8 = undefined;
    const v4 = [_]u8{ 1, 2, 3, 4 };
    const dns_only = try x509_selfsign.buildEcdsaP256IssuedBy(&leaf_buf, .{
        .common_name = "k15 root",
        .not_before = now - 1000,
        .not_after = now + 100_000,
        .serial = &.{0x16},
        .key_pair = leaf_kp,
        .dns_names = &.{ "1.2.3.4", "*.2.3.4", "www.example.com", "*.example.com" },
    }, ca_kp);
    try testing.expectError(error.NameMismatch, verifyChain(gpa, &.{dns_only}, &.{ca_der}, now, "1.2.3.4"));
    try verifyChain(gpa, &.{dns_only}, &.{ca_der}, now, "www.example.com");
    try verifyChain(gpa, &.{dns_only}, &.{ca_der}, now, "a.example.com");

    const ip_leaf = try x509_selfsign.buildEcdsaP256IssuedBy(&leaf_buf, .{
        .common_name = "k15 root",
        .not_before = now - 1000,
        .not_after = now + 100_000,
        .serial = &.{0x17},
        .key_pair = leaf_kp,
        .ip_addresses = &.{&v4},
    }, ca_kp);
    try verifyChain(gpa, &.{ip_leaf}, &.{ca_der}, now, "1.2.3.4");
    try testing.expectError(error.NameMismatch, verifyChain(gpa, &.{ip_leaf}, &.{ca_der}, now, "www.example.com"));
}

test "armorcli verify dnsPatternMatches is single-label only" {
    try testing.expect(dnsPatternMatches("leaf.test", "LEAF.test"));
    try testing.expect(dnsPatternMatches("*.example.com", "www.example.com"));
    try testing.expect(!dnsPatternMatches("*.example.com", "a.b.example.com"));
    try testing.expect(!dnsPatternMatches("*.example.com", "example.com"));
    try testing.expect(!dnsPatternMatches("*.example.com", ".example.com"));
    try testing.expect(!dnsPatternMatches("*example.com", "aexample.com"));
    try testing.expect(!dnsPatternMatches("*.", "a."));
}

test "armorcli verify decodeChain handles multi-block PEM and garbage" {
    const gpa = testing.allocator;
    const io = std.testing.io;
    const kp = ecdsa_p256.KeyPair.generate(io);
    var der_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(&der_buf, .{
        .common_name = "chain.test",
        .not_before = 0,
        .not_after = 1,
        .serial = &.{0x01},
        .key_pair = kp,
        .dns_names = &.{"chain.test"},
    });
    var pem_buf: [4096]u8 = undefined;
    const one = try pem.encode(&pem_buf, "CERTIFICATE", der);

    var two_blocks = Writer.Allocating.init(gpa);
    defer two_blocks.deinit();
    try two_blocks.writer.print("{s}\n{s}\n", .{ one, one });

    var chain: [max_chain][]u8 = undefined;
    var count: usize = 0;
    try decodeChain(gpa, two_blocks.written(), &chain, &count);
    defer for (chain[0..count]) |c| gpa.free(c);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualSlices(u8, der, chain[0]);

    var g_chain: [max_chain][]u8 = undefined;
    var g_count: usize = 0;
    try testing.expectError(error.BeginNotFound, decodeChain(gpa, "no pem here", &g_chain, &g_count));
}

test "armorcli verify arg parsing requires -CAfile" {
    try testing.expectError(error.Usage, parseArgs(&.{"cert.pem"}));
    const opts = try parseArgs(&.{ "-CAfile", "ca.pem", "-name", "x.test", "cert.pem" });
    try testing.expectEqualStrings("ca.pem", opts.ca_file);
    try testing.expectEqualStrings("x.test", opts.name.?);
    try testing.expectEqualStrings("cert.pem", opts.in_path);
}
