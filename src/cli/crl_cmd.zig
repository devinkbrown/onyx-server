// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor crl` — display and verify an X.509 Certificate Revocation List.
//!
//! Parse / signature / freshness / serial lookup are substrate calls
//! (`src/crypto/crl.zig`). An unauthenticated CRL never yields a revocation
//! verdict. No HTTP fetch.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const crl = onyx_server.crypto.crl;
const x509 = onyx_server.crypto.x509;
const pem = onyx_server.proto.pem;
const acme_cli = onyx_server.daemon.acme_cli;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const pem_label = "X509 CRL";

pub const Options = struct {
    in_path: []const u8 = "-",
    inform: common.Form = .auto,
    text: bool = false,
    noout: bool = false,
    verify: bool = false,
    ca_file: []const u8 = "",
    serial: ?[]const u8 = null,
    at_epoch: ?i64 = null,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor crl [-in <path>] [options]
        \\  -in <path>        CRL PEM/DER (default stdin)
        \\  -inform pem|der   force the input encoding (default: auto-detect)
        \\  -text             dump issuer, this/nextUpdate, revoked serial count
        \\  -noout            suppress the CRL PEM reprint
        \\  -verify           authenticate the CRL (requires -CAfile)
        \\  -CAfile <bundle>  PEM issuing-CA bundle
        \\  -serial <hex>     after verify+current, report whether the serial is revoked
        \\  -at <epoch>       evaluate freshness at this Unix time (default: now)
        \\
        \\Unauthenticated CRLs never produce a revocation verdict.
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-in")) {
            opts.in_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-inform")) {
            opts.inform = try common.Form.parse(try cur.value());
        } else if (std.mem.eql(u8, a, "-text")) {
            opts.text = true;
        } else if (std.mem.eql(u8, a, "-noout")) {
            opts.noout = true;
        } else if (std.mem.eql(u8, a, "-verify")) {
            opts.verify = true;
        } else if (std.mem.eql(u8, a, "-CAfile")) {
            opts.ca_file = try cur.value();
        } else if (std.mem.eql(u8, a, "-serial")) {
            opts.serial = try cur.value();
        } else if (std.mem.eql(u8, a, "-at")) {
            opts.at_epoch = std.fmt.parseInt(i64, try cur.value(), 10) catch return error.Usage;
        } else if (a.len > 0 and a[0] == '-' and a.len > 1) {
            return error.Usage;
        } else {
            opts.in_path = a;
        }
    }
    if (opts.verify and opts.ca_file.len == 0) return error.Usage;
    if (opts.serial != null and !opts.verify) return error.Usage;
    return opts;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const text = try common.readInput(gpa, io, opts.in_path);
    defer gpa.free(text);
    const der = try common.loadDer(gpa, text, pem_label, opts.inform);
    defer gpa.free(der);
    try runOnDer(gpa, io, opts, der, out);
}

pub fn runOnDer(gpa: Allocator, io: std.Io, opts: Options, der: []const u8, out: *Writer) !void {
    const parsed = try crl.parse(der);

    if (opts.text) try dumpText(&parsed, out);

    if (opts.verify) {
        const bundle_text = try common.readInput(gpa, io, opts.ca_file);
        defer gpa.free(bundle_text);
        var anchors = try acme_cli.loadTrustAnchors(gpa, bundle_text);
        defer {
            for (anchors.items) |a| gpa.free(a);
            anchors.deinit(gpa);
        }
        try authenticate(gpa, opts, parsed, der, anchors.items, out);
    }

    if (!opts.noout) {
        const buf = try gpa.alloc(u8, pem.encodedLen(pem_label, der.len));
        defer gpa.free(buf);
        try out.writeAll(try pem.encode(buf, pem_label, der));
    }
}

/// Authenticate `parsed` against already-decoded CA DERs. Tests drive this
/// directly so they do not need a temp file.
pub fn authenticate(
    gpa: Allocator,
    opts: Options,
    parsed: crl.CertificateRevocationList,
    der: []const u8,
    anchors: []const []const u8,
    out: *Writer,
) !void {
    if (anchors.len == 0) return error.NoMatchingIssuer;
    if (!verifyAgainstAnchors(der, anchors)) return error.BadSignature;

    const now = opts.at_epoch orelse common.wallClockSeconds();
    if (!crl.crlIsCurrent(parsed, now)) return error.NotCurrent;

    if (opts.serial) |hex| {
        const serial = try common.parseHexSerial(gpa, hex);
        defer gpa.free(serial);
        try out.writeAll("serial ");
        try common.writeHex(out, serial);
        if (crl.isSerialRevoked(parsed, serial)) {
            try out.writeAll(": revoked\n");
        } else {
            try out.writeAll(": not listed\n");
        }
        return;
    }
    try out.writeAll("CRL verifies: OK\n");
}

fn verifyAgainstAnchors(der: []const u8, anchors: []const []const u8) bool {
    for (anchors) |anchor| {
        const cert = x509.parse(anchor) catch continue;
        crl.verifyCrlSignature(der, cert.spki_der) catch continue;
        return true;
    }
    return false;
}

fn dumpText(parsed: *const crl.CertificateRevocationList, out: *Writer) !void {
    try out.writeAll("Certificate Revocation List:\n");
    try out.writeAll("  Issuer: ");
    try writeNameTlv(parsed.issuer_der, out);
    try out.writeByte('\n');
    try out.print("  This Update: {s} (epoch {d})\n", .{ parsed.this_update.bytes, parsed.this_update.epoch_seconds });
    if (parsed.next_update) |next| {
        try out.print("  Next Update: {s} (epoch {d})\n", .{ next.bytes, next.epoch_seconds });
    } else {
        try out.writeAll("  Next Update: <absent>\n");
    }
    try out.print("  Signature Algorithm: {s}\n", .{common.oidName(parsed.signature_algorithm_oid)});

    var count: usize = 0;
    var it = parsed.revokedSerials();
    while (true) {
        const serial = it.next() catch break;
        if (serial == null) break;
        count += 1;
    }
    try out.print("  Revoked Certificates: {d}\n", .{count});
}

fn writeNameTlv(name_der: []const u8, out: *Writer) !void {
    var top = x509.DerReader.init(name_der);
    const name = top.readExpected(x509.Tag.sequence) catch {
        try out.writeAll("<unparsed>");
        return;
    };
    var rdns = top.child(name) catch {
        try out.writeAll("<unparsed>");
        return;
    };
    var first = true;
    while (rdns.hasRemaining()) {
        const rdn = rdns.readTlv() catch {
            try out.writeAll("<unparsed>");
            return;
        };
        var set = rdns.child(rdn) catch {
            try out.writeAll("<unparsed>");
            return;
        };
        while (set.hasRemaining()) {
            const atv = set.readTlv() catch {
                try out.writeAll("<unparsed>");
                return;
            };
            var pair = set.child(atv) catch {
                try out.writeAll("<unparsed>");
                return;
            };
            const oid = pair.readExpected(x509.Tag.oid) catch {
                try out.writeAll("<unparsed>");
                return;
            };
            const value = pair.readTlv() catch {
                try out.writeAll("<unparsed>");
                return;
            };
            if (!first) try out.writeAll(", ");
            first = false;
            try out.print("{s}=", .{rdnAttrName(oid.value)});
            for (value.value) |b| {
                if (b >= 0x20 and b < 0x7f) {
                    try out.writeByte(b);
                } else {
                    try out.print("\\x{x:0>2}", .{b});
                }
            }
        }
    }
    if (first) try out.writeAll("<empty>");
}

fn rdnAttrName(oid: []const u8) []const u8 {
    if (std.mem.eql(u8, oid, &.{ 0x55, 0x04, 0x03 })) return "CN";
    if (std.mem.eql(u8, oid, &.{ 0x55, 0x04, 0x06 })) return "C";
    if (std.mem.eql(u8, oid, &.{ 0x55, 0x04, 0x0a })) return "O";
    return "?";
}

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const Ed25519 = std.crypto.sign.Ed25519;

/// Unsigned parse fixture copied from crl.zig `MinimalCrlWithRevoked` (thisUpdate
/// 2026-01-01, nextUpdate 2026-02-01, serials 0x05 and 0x0080).
const minimal_crl = [_]u8{
    0x30, 0x62, 0x30, 0x55, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2B,
    0x65, 0x70, 0x30, 0x00, 0x17, 0x0D, '2',  '6',  '0',  '1',  '0',  '1',
    '0',  '0',  '0',  '0',  '0',  '0',  'Z',  0x17, 0x0D, '2',  '6',  '0',
    '2',  '0',  '1',  '0',  '0',  '0',  '0',  '0',  '0',  'Z',  0x30, 0x29,
    0x30, 0x12, 0x02, 0x01, 0x05, 0x17, 0x0D, '2',  '6',  '0',  '1',  '0',
    '2',  '0',  '0',  '0',  '0',  '0',  '0',  'Z',  0x30, 0x13, 0x02, 0x02,
    0x00, 0x80, 0x17, 0x0D, '2',  '6',  '0',  '1',  '0',  '3',  '0',  '0',
    '0',  '0',  '0',  '0',  'Z',  0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
    0x03, 0x02, 0x00, 0x00,
};

test "armorcli crl -text dumps issuer window and revoked count without verifying" {
    const gpa = testing.allocator;
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try runOnDer(gpa, std.testing.io, .{ .text = true, .noout = true }, &minimal_crl, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Certificate Revocation List:") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "This Update:") != null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "Revoked Certificates: 2") != null);
}

test "armorcli crl -serial without -verify is usage, never a verdict" {
    try testing.expectError(error.Usage, parseArgs(&.{ "-serial", "05", "-text" }));
}

test "armorcli crl -verify accepts the issuing CA, rejects a stranger, and gates -serial" {
    const gpa = testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7C)));
    const der = try crl.testSignedCrl(gpa, kp);
    defer gpa.free(der);
    const parsed = try crl.parse(der);

    var ca_buf: [2048]u8 = undefined;
    const ca_der = try x509_selfsign.buildSelfSigned(&ca_buf, .{
        .common_name = "armorcli crl ca",
        .not_before = 1_700_000_000,
        .not_after = 2_000_000_000,
        .serial = &.{0x01},
        .key_pair = kp,
        .dns_names = &.{"crl-ca.test"},
        .is_ca = true,
    });
    const other_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x22)));
    var other_buf: [2048]u8 = undefined;
    const other_der = try x509_selfsign.buildSelfSigned(&other_buf, .{
        .common_name = "stranger",
        .not_before = 1_700_000_000,
        .not_after = 2_000_000_000,
        .serial = &.{0x02},
        .key_pair = other_kp,
        .dns_names = &.{"other.test"},
        .is_ca = true,
    });

    const now_current: i64 = 1_767_300_000;
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try authenticate(gpa, .{ .at_epoch = now_current }, parsed, der, &.{ca_der}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "CRL verifies: OK") != null);

    aw.clearRetainingCapacity();
    try testing.expectError(error.BadSignature, authenticate(
        gpa,
        .{ .at_epoch = now_current },
        parsed,
        der,
        &.{other_der},
        &aw.writer,
    ));

    aw.clearRetainingCapacity();
    try authenticate(gpa, .{ .serial = "05", .at_epoch = now_current }, parsed, der, &.{ca_der}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "serial 05: revoked") != null);

    aw.clearRetainingCapacity();
    try authenticate(gpa, .{ .serial = "99", .at_epoch = now_current }, parsed, der, &.{ca_der}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "serial 99: not listed") != null);

    try testing.expectError(error.NotCurrent, authenticate(
        gpa,
        .{ .serial = "05", .at_epoch = 1_800_000_000 },
        parsed,
        der,
        &.{ca_der},
        &aw.writer,
    ));
}

test "armorcli crl parseArgs requires -CAfile for -verify" {
    try testing.expectError(error.Usage, parseArgs(&.{"-verify"}));
    const opts = try parseArgs(&.{ "-verify", "-CAfile", "ca.pem", "-text", "-noout" });
    try testing.expect(opts.verify);
    try testing.expectEqualStrings("ca.pem", opts.ca_file);
}

test "armorcli crl rejects empty DER" {
    const gpa = testing.allocator;
    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try testing.expectError(error.EmptyInput, runOnDer(gpa, std.testing.io, .{ .noout = true }, &.{}, &aw.writer));
}
