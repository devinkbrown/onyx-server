// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor x509` — certificate display and conversion, openssl-x509 parity
//! backed entirely by the Armor substrate: parsing via src/crypto/x509.zig
//! (`x509.parse`, `DerReader`), fingerprints via the parsed cert's SHA-256
//! helpers. The only logic added here is display formatting (RDN walk of the
//! issuer/subject Name TLVs); no crypto is reimplemented.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const x509 = onyx_server.crypto.x509;
const pem = onyx_server.proto.pem;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const Options = struct {
    in_path: []const u8 = "-",
    inform: common.Form = .auto,
    outform: common.Form = .pem,
    out_path: ?[]const u8 = null,
    text: bool = false,
    fingerprint: bool = false,
    noout: bool = false,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor x509 [-in <path>] [options]
        \\  -in <path>        input certificate (PEM or DER; default stdin)
        \\  -inform pem|der   force the input encoding (default: auto-detect)
        \\  -text             print a human-readable dump of the certificate
        \\  -fingerprint      print the SHA-256 fingerprint (and the SPKI pin)
        \\  -noout            suppress the certificate output block
        \\  -outform pem|der  output encoding (default: pem)
        \\  -out <path>       write the certificate there instead of stdout
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
        } else if (std.mem.eql(u8, a, "-outform")) {
            opts.outform = try common.Form.parse(try cur.value());
            if (opts.outform == .auto) return error.Usage;
        } else if (std.mem.eql(u8, a, "-out")) {
            opts.out_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-text")) {
            opts.text = true;
        } else if (std.mem.eql(u8, a, "-fingerprint")) {
            opts.fingerprint = true;
        } else if (std.mem.eql(u8, a, "-noout")) {
            opts.noout = true;
        } else {
            return error.Usage;
        }
    }
    return opts;
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const text = try common.readInput(gpa, io, opts.in_path);
    defer gpa.free(text);
    const der = try common.loadDer(gpa, text, "CERTIFICATE", opts.inform);
    defer gpa.free(der);
    try runOnDer(gpa, io, opts, der, out);
}

/// Core, input-agnostic body — the piece the tests drive directly.
pub fn runOnDer(gpa: Allocator, io: std.Io, opts: Options, der: []const u8, out: *Writer) !void {
    const cert = try x509.parse(der);

    if (opts.text) try dumpText(&cert, out);

    if (opts.fingerprint) {
        const cert_fp = cert.certSha256();
        try out.writeAll("sha256 Fingerprint=");
        try common.writeColonHex(out, &cert_fp);
        const spki_fp = cert.spkiSha256();
        try out.writeAll("\nsha256 SPKI Pin=");
        try common.writeColonHex(out, &spki_fp);
        try out.writeByte('\n');
    }

    if (!opts.noout) {
        if (opts.out_path) |path| {
            var body = Writer.Allocating.init(gpa);
            defer body.deinit();
            try writeCertOut(gpa, opts.outform, der, &body.writer);
            try common.writePublicFile(io, std.Io.Dir.cwd(), path, body.written());
        } else {
            try writeCertOut(gpa, opts.outform, der, out);
        }
    }
}

fn writeCertOut(gpa: Allocator, form: common.Form, der: []const u8, w: *Writer) !void {
    switch (form) {
        .der => try w.writeAll(der),
        .pem, .auto => {
            const buf = try gpa.alloc(u8, pem.encodedLen("CERTIFICATE", der.len));
            defer gpa.free(buf);
            try w.writeAll(try pem.encode(buf, "CERTIFICATE", der));
        },
    }
}

/// Human-readable dump: serial, signature algorithm, issuer/subject, validity,
/// SAN, key type, key usage / EKU, basic constraints, fingerprints.
fn dumpText(cert: *const x509.Certificate, out: *Writer) !void {
    try out.writeAll("Certificate:\n");

    try out.writeAll("  Serial Number: ");
    try common.writeColonHex(out, cert.serial_der);
    try out.writeByte('\n');

    try out.print("  Signature Algorithm: {s} (", .{common.oidName(cert.signature_algorithm_oid)});
    try common.writeOidDotted(out, cert.signature_algorithm_oid);
    try out.writeAll(")\n");

    try out.writeAll("  Issuer: ");
    try writeIssuerName(cert.tbs_der, out);
    try out.writeByte('\n');

    try out.writeAll("  Subject: ");
    try writeNameTlv(cert.subject_der, out);
    try out.writeByte('\n');

    try out.writeAll("  Validity:\n");
    try out.print("    Not Before: {s} (epoch {d})\n", .{ cert.not_before.bytes, cert.not_before.epoch_seconds });
    try out.print("    Not After : {s} (epoch {d})\n", .{ cert.not_after.bytes, cert.not_after.epoch_seconds });

    try out.writeAll("  Subject Public Key: ");
    if (x509.extractPublicKey(cert.spki_der)) |spk| switch (spk) {
        .rsa => |rsa| try out.print("RSA ({d}-bit modulus)\n", .{rsaModulusBits(rsa.modulus)}),
        .ecdsa_p256 => try out.writeAll("ECDSA P-256 (256-bit)\n"),
        .ed25519 => try out.writeAll("Ed25519 (255-bit)\n"),
    } else |_| {
        // PQ / unrecognized SPKI algorithms are outside extractPublicKey's set.
        try out.writeAll("unsupported/unknown algorithm\n");
    }

    if (cert.san_dns_count > 0 or cert.san_ip_count > 0) {
        try out.writeAll("  Subject Alternative Name:\n");
        for (cert.san_dns[0..cert.san_dns_count]) |name| {
            try out.print("    DNS:{s}\n", .{name});
        }
        for (cert.san_ips[0..cert.san_ip_count]) |*ip| {
            try out.writeAll("    IP:");
            try common.writeHex(out, ip.slice());
            try out.writeByte('\n');
        }
    }

    if (cert.key_usage_present) {
        try out.writeAll("  Key Usage:");
        if (cert.key_usage_digital_signature) try out.writeAll(" digitalSignature");
        if (cert.key_usage_cert_sign) try out.writeAll(" keyCertSign");
        try out.writeByte('\n');
    }
    if (cert.eku_present) {
        try out.writeAll("  Extended Key Usage:");
        if (cert.eku_server_auth) try out.writeAll(" serverAuth");
        if (cert.eku_ocsp_signing) try out.writeAll(" OCSPSigning");
        try out.writeByte('\n');
    }
    try out.print("  Basic Constraints: CA={}", .{cert.basic_constraints_ca});
    if (cert.basic_constraints_path_len) |plen| try out.print(", pathlen={d}", .{plen});
    try out.writeByte('\n');
    if (cert.must_staple) try out.writeAll("  TLS Feature: status_request (OCSP must-staple)\n");
    if (cert.aia_ocsp_url.len > 0) try out.print("  OCSP Responder: {s}\n", .{cert.aia_ocsp_url});
}

/// The issuer Name is not retained by ParsedCertificate, so walk the TBS
/// (SEQUENCE { [0] version?, serial, sigAlg, issuer, ... }) with the substrate
/// DerReader — display-only, fail-closed.
fn writeIssuerName(tbs_der: []const u8, out: *Writer) !void {
    var top = x509.DerReader.init(tbs_der);
    const tbs = top.readExpected(x509.Tag.sequence) catch return out.writeAll("<unparsed>");
    var body = top.child(tbs) catch return out.writeAll("<unparsed>");
    // Optional [0] EXPLICIT version.
    if ((body.peekTag() catch 0) == x509.Tag.context_0_constructed) _ = body.readTlv() catch return out.writeAll("<unparsed>");
    _ = body.readTlv() catch return out.writeAll("<unparsed>"); // serialNumber
    _ = body.readTlv() catch return out.writeAll("<unparsed>"); // signature AlgorithmIdentifier
    const issuer = body.readExpected(x509.Tag.sequence) catch return out.writeAll("<unparsed>");
    try writeNameTlv(issuer.raw, out);
}

/// Render an X.501 Name TLV as `attr=value, ...`. Only the value formatting is
/// local; structure walking uses the substrate DerReader (bounds-checked).
pub fn writeNameTlv(name_der: []const u8, out: *Writer) !void {
    var top = x509.DerReader.init(name_der);
    const name = top.readExpected(x509.Tag.sequence) catch return out.writeAll("<unparsed>");
    var rdns = top.child(name) catch return out.writeAll("<unparsed>");
    var first = true;
    while (rdns.hasRemaining()) {
        const rdn = rdns.readTlv() catch return out.writeAll("<unparsed>");
        var set = rdns.child(rdn) catch return out.writeAll("<unparsed>");
        while (set.hasRemaining()) {
            const atv = set.readTlv() catch return out.writeAll("<unparsed>");
            var pair = set.child(atv) catch return out.writeAll("<unparsed>");
            const oid = pair.readExpected(x509.Tag.oid) catch return out.writeAll("<unparsed>");
            const value = pair.readTlv() catch return out.writeAll("<unparsed>");
            if (!first) try out.writeAll(", ");
            first = false;
            try out.print("{s}=", .{rdnAttrName(oid.value)});
            try writePrintable(out, value.value);
        }
    }
    if (first) try out.writeAll("<empty>");
}

fn rdnAttrName(oid: []const u8) []const u8 {
    const Named = struct { oid: []const u8, name: []const u8 };
    const table = [_]Named{
        .{ .oid = &.{ 0x55, 0x04, 0x03 }, .name = "CN" },
        .{ .oid = &.{ 0x55, 0x04, 0x06 }, .name = "C" },
        .{ .oid = &.{ 0x55, 0x04, 0x07 }, .name = "L" },
        .{ .oid = &.{ 0x55, 0x04, 0x08 }, .name = "ST" },
        .{ .oid = &.{ 0x55, 0x04, 0x0a }, .name = "O" },
        .{ .oid = &.{ 0x55, 0x04, 0x0b }, .name = "OU" },
        .{ .oid = &.{ 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19 }, .name = "DC" },
    };
    for (table) |entry| {
        if (std.mem.eql(u8, entry.oid, oid)) return entry.name;
    }
    return "?";
}

/// Print a directory-string value, escaping non-printable bytes as `\xNN` so
/// attacker-controlled subject bytes can never smuggle control sequences into
/// a terminal.
fn writePrintable(out: *Writer, bytes: []const u8) !void {
    for (bytes) |b| {
        if (b >= 0x20 and b < 0x7f) {
            try out.writeByte(b);
        } else {
            try out.print("\\x{x:0>2}", .{b});
        }
    }
}

fn rsaModulusBits(modulus: []const u8) usize {
    var i: usize = 0;
    while (i < modulus.len and modulus[i] == 0) i += 1;
    if (i == modulus.len) return 0;
    return (modulus.len - i) * 8 - @clz(modulus[i]);
}

// ===========================================================================
// Tests — fixture certs minted with the substrate self-sign builder.
// ===========================================================================

const testing = std.testing;
const x509_selfsign = onyx_server.proto.x509_selfsign;
const ecdsa_p256 = onyx_server.crypto.ecdsa_p256;

fn fixtureCert(out: []u8) ![]const u8 {
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    return x509_selfsign.buildSelfSignedEcdsaP256(out, .{
        .common_name = "armorcli.test",
        .not_before = 1_700_000_000,
        .not_after = 1_900_000_000,
        .serial = &.{ 0x01, 0x02, 0x03 },
        .key_pair = kp,
        .dns_names = &.{ "armorcli.test", "alt.armorcli.test" },
        .is_ca = true,
    });
}

test "armorcli x509 -text dumps subject, SAN, validity, and key type" {
    const gpa = testing.allocator;
    var der_buf: [2048]u8 = undefined;
    const der = try fixtureCert(&der_buf);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try runOnDer(gpa, std.testing.io, .{ .text = true, .noout = true }, der, &aw.writer);
    const got = aw.written();

    try testing.expect(std.mem.indexOf(u8, got, "Subject: CN=armorcli.test") != null);
    try testing.expect(std.mem.indexOf(u8, got, "Issuer: CN=armorcli.test") != null);
    try testing.expect(std.mem.indexOf(u8, got, "DNS:alt.armorcli.test") != null);
    try testing.expect(std.mem.indexOf(u8, got, "ECDSA P-256") != null);
    try testing.expect(std.mem.indexOf(u8, got, "Serial Number: 01:02:03") != null);
    try testing.expect(std.mem.indexOf(u8, got, "Basic Constraints: CA=true") != null);
    try testing.expect(std.mem.indexOf(u8, got, "ecdsa-with-SHA256") != null);
    // -noout: no PEM block in the output.
    try testing.expect(std.mem.indexOf(u8, got, "-----BEGIN CERTIFICATE-----") == null);
}

test "armorcli x509 -fingerprint matches the substrate certfp" {
    const gpa = testing.allocator;
    var der_buf: [2048]u8 = undefined;
    const der = try fixtureCert(&der_buf);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try runOnDer(gpa, std.testing.io, .{ .fingerprint = true, .noout = true }, der, &aw.writer);

    const fp = try onyx_server.crypto.x509_verify.certfp(der);
    var expect_hex = Writer.Allocating.init(gpa);
    defer expect_hex.deinit();
    try common.writeColonHex(&expect_hex.writer, &fp);
    try testing.expect(std.mem.indexOf(u8, aw.written(), expect_hex.written()) != null);
}

test "armorcli x509 PEM<->DER round-trips byte-identically" {
    const gpa = testing.allocator;
    var der_buf: [2048]u8 = undefined;
    const der = try fixtureCert(&der_buf);

    // DER -> PEM (default output form).
    var pem_out = Writer.Allocating.init(gpa);
    defer pem_out.deinit();
    try runOnDer(gpa, std.testing.io, .{}, der, &pem_out.writer);
    try testing.expect(std.mem.startsWith(u8, pem_out.written(), "-----BEGIN CERTIFICATE-----"));

    // PEM back -> DER via the loader, byte-identical to the original.
    const round = try common.loadDer(gpa, pem_out.written(), "CERTIFICATE", .auto);
    defer gpa.free(round);
    try testing.expectEqualSlices(u8, der, round);

    // -outform der emits the raw DER bytes.
    var der_out = Writer.Allocating.init(gpa);
    defer der_out.deinit();
    try runOnDer(gpa, std.testing.io, .{ .outform = .der }, der, &der_out.writer);
    try testing.expectEqualSlices(u8, der, der_out.written());
}

test "armorcli x509 rejects truncated DER with a typed error, no crash" {
    const gpa = testing.allocator;
    var der_buf: [2048]u8 = undefined;
    const der = try fixtureCert(&der_buf);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    // Every truncation point must yield a typed x509 error, never UB/panic.
    var cut: usize = 0;
    while (cut < der.len) : (cut += 37) {
        const err = runOnDer(gpa, std.testing.io, .{ .text = true, .noout = true }, der[0..cut], &aw.writer);
        try testing.expect(std.meta.isError(err));
    }
}

test "armorcli x509 parseArgs rejects unknown flags and missing values" {
    try testing.expectError(error.Usage, parseArgs(&.{"-bogus"}));
    try testing.expectError(error.Usage, parseArgs(&.{"-in"}));
    try testing.expectError(error.Usage, parseArgs(&.{ "-inform", "txt" }));
    const opts = try parseArgs(&.{ "-in", "a.pem", "-text", "-noout", "-fingerprint" });
    try testing.expectEqualStrings("a.pem", opts.in_path);
    try testing.expect(opts.text and opts.noout and opts.fingerprint);
}
