// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor req` — PKCS#10 CSR generation from an existing private key.
//!
//! The CSR structure comes from src/proto/csr.zig (`certificationRequestInfo`
//! + `assemble`); signing is substrate-only (crypto/ecdsa_p256.zig `sign` +
//! `signatureToDer`, or crypto/sign.zig Ed25519). This module adds only the
//! SubjectPublicKeyInfo templates (fixed DER prefixes, mirroring the
//! file-private `ecP256Spki` in src/daemon/acme_client.zig:543 — exporting it
//! is a noted substrate gap) and argument plumbing.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");
const pkey_cmd = @import("pkey_cmd.zig");

const csr = onyx_server.proto.csr;
const pem = onyx_server.proto.pem;
const ec_pkcs = onyx_server.proto.ec_pkcs;
const ecdsa_p256 = onyx_server.crypto.ecdsa_p256;
const ed25519 = onyx_server.crypto.sign;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

/// DER AlgorithmIdentifier for ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
const ecdsa_sha256_sig_alg = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
/// DER AlgorithmIdentifier for Ed25519 (1.3.101.112).
const ed25519_sig_alg = [_]u8{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };

pub const Options = struct {
    key_path: []const u8 = "",
    common_name: []const u8 = "",
    /// SubjectAltName dNSName entries (`-dns`, repeatable). When empty the CN
    /// is used as the sole SAN — RFC 6125 clients ignore the CN.
    dns_names: [max_dns]([]const u8) = undefined,
    dns_count: usize = 0,
    out_path: ?[]const u8 = null,

    pub const max_dns = 16;

    pub fn dns(self: *const Options) []const []const u8 {
        return self.dns_names[0..self.dns_count];
    }
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor req -key <path> -cn <name> [-dns <name>]... [-out <path>]
        \\  -key <path>   signing key PEM (EC PRIVATE KEY or PKCS#8 Ed25519)
        \\  -cn <name>    subject common name (required)
        \\  -dns <name>   SAN dNSName (repeatable; default: the CN)
        \\  -out <path>   write the CSR PEM there; default stdout
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-key")) {
            opts.key_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-cn")) {
            opts.common_name = try cur.value();
        } else if (std.mem.eql(u8, a, "-dns")) {
            if (opts.dns_count == Options.max_dns) return error.Usage;
            opts.dns_names[opts.dns_count] = try cur.value();
            opts.dns_count += 1;
        } else if (std.mem.eql(u8, a, "-out")) {
            opts.out_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-passin")) {
            return error.NotImplemented; // no encrypted-key support; never argv
        } else {
            return error.Usage;
        }
    }
    if (opts.key_path.len == 0 or opts.common_name.len == 0) return error.Usage;
    return opts;
}

/// DER SubjectPublicKeyInfo for an uncompressed P-256 point (91 bytes).
/// Mirrors src/daemon/acme_client.zig `ecP256Spki` (file-private there).
fn ecP256Spki(sec1: [65]u8) [91]u8 {
    var out: [91]u8 = .{
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    } ++ @as([65]u8, @splat(0));
    @memcpy(out[26..91], &sec1);
    return out;
}

/// DER SubjectPublicKeyInfo for a raw Ed25519 public key (44 bytes, RFC 8410).
fn ed25519Spki(public: [32]u8) [44]u8 {
    var out: [44]u8 = [_]u8{
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    } ++ @as([32]u8, @splat(0));
    @memcpy(out[12..44], &public);
    return out;
}

/// Build and sign the CSR from key PEM text; returns the CSR PEM in `out_buf`.
/// Split from `run` so tests drive it without touching the filesystem.
pub fn buildCsrPem(key_text: []const u8, cn: []const u8, dns_names: []const []const u8, out_buf: []u8) ![]const u8 {
    const default_san = [_][]const u8{cn};
    const sans: []const []const u8 = if (dns_names.len == 0) &default_san else dns_names;

    var der_buf: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);
    var cri_buf: [2048]u8 = undefined;
    var csr_buf: [2560]u8 = undefined;

    if (pem.decode(key_text, "EC PRIVATE KEY", &der_buf)) |key_der| {
        var scalar = try ec_pkcs.parseScalar(key_der);
        defer std.crypto.secureZero(u8, &scalar);
        const sk = try ecdsa_p256.SecretKey.fromBytes(scalar);
        const kp = try ecdsa_p256.keyPairFromSecretKey(sk);

        const spki = ecP256Spki(kp.public_key.toUncompressedSec1());
        const cri = try csr.certificationRequestInfo(&cri_buf, .{
            .common_name = cn,
            .dns_names = sans,
            .spki_der = &spki,
        });
        const sig = try ecdsa_p256.sign(cri, kp);
        var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
        const sig_der = try ecdsa_p256.signatureToDer(sig, &sig_der_buf);
        const csr_der = try csr.assemble(&csr_buf, cri, &ecdsa_sha256_sig_alg, sig_der);
        return pem.encode(out_buf, "CERTIFICATE REQUEST", csr_der);
    } else |_| {}

    if (pem.decode(key_text, "PRIVATE KEY", &der_buf)) |key_der| {
        var seed = try parseSeed(key_der);
        defer std.crypto.secureZero(u8, &seed);
        var kp = try ed25519.KeyPair.fromSeed(seed);
        defer kp.deinit();

        const spki = ed25519Spki(kp.public_key);
        const cri = try csr.certificationRequestInfo(&cri_buf, .{
            .common_name = cn,
            .dns_names = sans,
            .spki_der = &spki,
        });
        const sig = try kp.sign(cri);
        const csr_der = try csr.assemble(&csr_buf, cri, &ed25519_sig_alg, &sig);
        return pem.encode(out_buf, "CERTIFICATE REQUEST", csr_der);
    } else |_| {}

    return error.UnsupportedKey;
}

fn parseSeed(der: []const u8) ![32]u8 {
    // pkey_cmd's fail-closed walk is the CLI's single PKCS#8 Ed25519 parser.
    return pkey_cmd.parseEd25519Pkcs8(der);
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const key_text = try common.readInput(gpa, io, opts.key_path);
    defer {
        std.crypto.secureZero(u8, key_text);
        gpa.free(key_text);
    }
    var out_buf: [4096]u8 = undefined;
    const csr_pem = try buildCsrPem(key_text, opts.common_name, opts.dns(), &out_buf);
    if (opts.out_path) |path| {
        try common.writePublicFile(io, std.Io.Dir.cwd(), path, csr_pem);
    } else {
        try out.writeAll(csr_pem);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const x509 = onyx_server.crypto.x509;

test "armorcli req builds a verifiable ECDSA P-256 CSR" {
    // Arrange: a fresh EC key from genpkey.
    var key_buf: [512]u8 = undefined;
    const key_pem = try pkey_cmd.generatePem(std.testing.io, .ec, &key_buf);

    // Act
    var csr_pem_buf: [4096]u8 = undefined;
    const csr_pem = try buildCsrPem(key_pem, "req.armorcli.test", &.{ "req.armorcli.test", "alt.test" }, &csr_pem_buf);

    // Assert: PEM label + the signature verifies against the embedded SPKI.
    try testing.expect(std.mem.startsWith(u8, csr_pem, "-----BEGIN CERTIFICATE REQUEST-----"));
    var der_buf: [4096]u8 = undefined;
    const csr_der = try pem.decode(csr_pem, "CERTIFICATE REQUEST", &der_buf);

    var top = x509.DerReader.init(csr_der);
    const outer = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var body = try top.child(outer);
    const cri = try body.readExpected(x509.Tag.sequence);
    _ = try body.readExpected(x509.Tag.sequence); // signatureAlgorithm
    const sig_bits = try body.readExpected(x509.Tag.bit_string);
    try body.expectEmpty();

    // Extract the SPKI from the CRI (4th field: version, subject, spki, attrs).
    var cri_body = try body.child(cri);
    _ = try cri_body.readExpected(x509.Tag.integer);
    _ = try cri_body.readExpected(x509.Tag.sequence);
    const spki = try cri_body.readExpected(x509.Tag.sequence);
    const spk = try x509.extractPublicKey(spki.raw);
    const point = try ecdsa_p256.parsePublicKeySec1(spk.ecdsa_p256);

    const sig = try ecdsa_p256.signatureFromDer(sig_bits.value[1..]);
    try testing.expect(ecdsa_p256.verify(sig, cri.raw, point));
}

test "armorcli req builds a verifiable Ed25519 CSR" {
    var key_buf: [512]u8 = undefined;
    const key_pem = try pkey_cmd.generatePem(std.testing.io, .ed25519, &key_buf);

    var csr_pem_buf: [4096]u8 = undefined;
    const csr_pem = try buildCsrPem(key_pem, "ed.armorcli.test", &.{}, &csr_pem_buf);

    var der_buf: [4096]u8 = undefined;
    const csr_der = try pem.decode(csr_pem, "CERTIFICATE REQUEST", &der_buf);
    var top = x509.DerReader.init(csr_der);
    const outer = try top.readExpected(x509.Tag.sequence);
    var body = try top.child(outer);
    const cri = try body.readExpected(x509.Tag.sequence);
    _ = try body.readExpected(x509.Tag.sequence);
    const sig_bits = try body.readExpected(x509.Tag.bit_string);

    var cri_body = try body.child(cri);
    _ = try cri_body.readExpected(x509.Tag.integer);
    _ = try cri_body.readExpected(x509.Tag.sequence);
    const spki = try cri_body.readExpected(x509.Tag.sequence);
    const spk = try x509.extractPublicKey(spki.raw);

    var public: [32]u8 = undefined;
    @memcpy(&public, spk.ed25519);
    var sig: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 65), sig_bits.value.len); // unused-bits byte + 64
    @memcpy(&sig, sig_bits.value[1..]);
    try testing.expect(try ed25519.verify(cri.raw, sig, public));
}

test "armorcli req fails closed on a non-key input and bad args" {
    var out_buf: [4096]u8 = undefined;
    try testing.expectError(error.UnsupportedKey, buildCsrPem("not a key", "cn.test", &.{}, &out_buf));

    try testing.expectError(error.Usage, parseArgs(&.{ "-cn", "x" })); // missing -key
    try testing.expectError(error.Usage, parseArgs(&.{ "-key", "k.pem" })); // missing -cn
    try testing.expectError(error.NotImplemented, parseArgs(&.{ "-key", "k", "-cn", "c", "-passin", "stdin" }));
}
