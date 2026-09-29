// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor genpkey` / `armor pkey` — key generation and inspection.
//!
//! Generation is 100% substrate: ECDSA P-256 via crypto/ecdsa_p256.zig
//! (`KeyPair.generate`), Ed25519 via crypto/sign.zig (`KeyPair.generate`,
//! secret material held on a sealed page and wiped). This module only adds the
//! standard *serialization* wrappers around the substrate key material:
//! SEC1 `EC PRIVATE KEY` (RFC 5915, mirroring the file-private encoder in
//! src/daemon/acme_runner.zig:668 — exporting that is a noted substrate gap)
//! and PKCS#8 for Ed25519 (RFC 8410 fixed prefix). No cryptographic math is
//! implemented here.
//!
//! Private-key files are ALWAYS written 0o600 (common.writeKeyFile). Secrets
//! never appear on argv: `-passin` is parsed for CLI compatibility but the
//! substrate has no encrypted-PEM (PKCS#8 EncryptedPrivateKeyInfo) support, so
//! it is rejected fail-closed with `error.NotImplemented`.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const ecdsa_p256 = onyx_server.crypto.ecdsa_p256;
const ed25519 = onyx_server.crypto.sign;
const pem = onyx_server.proto.pem;
const ec_pkcs = onyx_server.proto.ec_pkcs;
const x509 = onyx_server.crypto.x509;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const Algorithm = enum {
    ec, // ECDSA P-256
    ed25519,

    pub fn parse(text: []const u8) common.Error!Algorithm {
        if (std.mem.eql(u8, text, "ec") or std.mem.eql(u8, text, "EC") or
            std.mem.eql(u8, text, "p256") or std.mem.eql(u8, text, "P-256")) return .ec;
        if (std.mem.eql(u8, text, "ed25519") or std.mem.eql(u8, text, "ED25519")) return .ed25519;
        // RSA and P-384 generation are substrate gaps (rsa_sign.zig has no
        // keygen; only P-256 has a signing wrapper) — reject loudly rather
        // than silently produce a different key type.
        if (std.mem.eql(u8, text, "rsa") or std.mem.eql(u8, text, "RSA") or
            std.mem.eql(u8, text, "p384") or std.mem.eql(u8, text, "P-384")) return error.NotImplemented;
        return error.Usage;
    }
};

pub const GenOptions = struct {
    algorithm: Algorithm = .ec,
    out_path: ?[]const u8 = null,
};

pub const InspectOptions = struct {
    in_path: []const u8 = "-",
    noout: bool = false,
};

pub fn genUsage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor genpkey -algorithm ec|ed25519 [-out <path>]
        \\  -algorithm <alg>  key type: ec (ECDSA P-256) or ed25519
        \\  -out <path>       write the key there (file mode 0600); default stdout
        \\  (rsa / p384 generation and -passin encryption are not supported by
        \\   the Armor substrate yet; both are rejected explicitly)
        \\
    );
}

pub fn inspectUsage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor pkey -in <path> [-noout]
        \\  -in <path>   private key PEM (EC PRIVATE KEY or PKCS#8 Ed25519)
        \\  -noout       print only the summary, not the key block
        \\  -passin ...  NOT SUPPORTED (no encrypted-PEM support; never put a
        \\               passphrase on argv)
        \\
    );
}

pub fn parseGenArgs(args: []const []const u8) common.Error!GenOptions {
    var opts = GenOptions{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-algorithm")) {
            opts.algorithm = try Algorithm.parse(try cur.value());
        } else if (std.mem.eql(u8, a, "-out")) {
            opts.out_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-passin") or std.mem.eql(u8, a, "-passout") or std.mem.eql(u8, a, "-pass")) {
            // Fail closed: no encrypted-key support, and a passphrase must
            // never ride argv anyway.
            return error.NotImplemented;
        } else {
            return error.Usage;
        }
    }
    return opts;
}

pub fn parseInspectArgs(args: []const []const u8) common.Error!InspectOptions {
    var opts = InspectOptions{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-in")) {
            opts.in_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-noout")) {
            opts.noout = true;
        } else if (std.mem.eql(u8, a, "-passin")) {
            return error.NotImplemented;
        } else {
            return error.Usage;
        }
    }
    return opts;
}

// -- Serialization (encoding only; key material comes from the substrate) ----

/// SEC1 ECPrivateKey DER for a P-256 key pair (RFC 5915), the layout nginx and
/// openssl both accept. Fixed 121-byte template; mirrors the file-private
/// encoder in src/daemon/acme_runner.zig.
pub fn ecPrivateKeyDer(kp: ecdsa_p256.KeyPair) [121]u8 {
    const priv = kp.secret_key.toBytes();
    const sec1 = kp.public_key.toUncompressedSec1();
    var der: [121]u8 = .{
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
    } ++ @as([32]u8, @splat(0)) // private scalar
    ++ [_]u8{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 } // [0] prime256v1
    ++ [_]u8{ 0xa1, 0x44, 0x03, 0x42, 0x00 } // [1] BIT STRING (0 unused bits)
    ++ @as([65]u8, @splat(0)); // uncompressed point
    @memcpy(der[7..39], &priv);
    @memcpy(der[56..121], &sec1);
    return der;
}

/// PKCS#8 PrivateKeyInfo DER for an Ed25519 seed (RFC 8410 §7): the fixed
/// 16-byte prefix `30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20` + seed.
pub fn ed25519Pkcs8Der(seed: [32]u8) [48]u8 {
    var der: [48]u8 = [_]u8{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    } ++ @as([32]u8, @splat(0));
    @memcpy(der[16..48], &seed);
    return der;
}

/// Generate a key of `alg` and render its PEM into `buf`. The DER scratch is
/// secure-zeroed before returning; only the PEM (which the caller is asking
/// for) leaves the function.
pub fn generatePem(io: std.Io, alg: Algorithm, buf: []u8) ![]const u8 {
    switch (alg) {
        .ec => {
            const kp = ecdsa_p256.KeyPair.generate(io);
            var der = ecPrivateKeyDer(kp);
            defer std.crypto.secureZero(u8, &der);
            return pem.encode(buf, "EC PRIVATE KEY", &der);
        },
        .ed25519 => {
            var kp = try ed25519.KeyPair.generate(io);
            defer kp.deinit(); // wipes the Secret-wrapped secret key
            var seed: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            // sign.zig stores seed || public key (RFC 8032 layout).
            @memcpy(&seed, kp.secret_key.expose()[0..32]);
            var der = ed25519Pkcs8Der(seed);
            defer std.crypto.secureZero(u8, &der);
            return pem.encode(buf, "PRIVATE KEY", &der);
        },
    }
}

pub fn runGen(gpa: Allocator, io: std.Io, opts: GenOptions, out: *Writer) !void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const key_pem = try generatePem(io, opts.algorithm, &buf);
    if (opts.out_path) |path| {
        try common.writeKeyFile(io, std.Io.Dir.cwd(), path, key_pem);
    } else {
        try out.writeAll(key_pem);
    }
}

/// Parsed summary of a private-key input, derived without printing any secret.
pub const KeyInfo = struct {
    kind: Algorithm,
    /// Public key bytes: SEC1 uncompressed point (EC) or raw 32-byte Ed25519.
    public: [65]u8,
    public_len: usize,

    pub fn publicSlice(self: *const KeyInfo) []const u8 {
        return self.public[0..self.public_len];
    }
};

/// Identify a private-key PEM and recover its PUBLIC half via the substrate
/// (ec_pkcs scalar parse + std key derivation; sign.KeyPair.fromSeed). The
/// private scalar/seed is wiped before returning — inspection output never
/// contains secret bytes.
pub fn inspectPem(text: []const u8) !KeyInfo {
    var der_buf: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);

    if (pem.decode(text, "EC PRIVATE KEY", &der_buf)) |der| {
        var scalar = try ec_pkcs.parseScalar(der);
        defer std.crypto.secureZero(u8, &scalar);
        const sk = try ecdsa_p256.SecretKey.fromBytes(scalar);
        const kp = try ecdsa_p256.KeyPair.fromSecretKey(sk);
        var info = KeyInfo{ .kind = .ec, .public = undefined, .public_len = ecdsa_p256.sec1_uncompressed_length };
        const sec1 = kp.public_key.toUncompressedSec1();
        @memcpy(info.public[0..sec1.len], &sec1);
        return info;
    } else |_| {}

    if (pem.decode(text, "PRIVATE KEY", &der_buf)) |der| {
        var seed = try parseEd25519Pkcs8(der);
        defer std.crypto.secureZero(u8, &seed);
        var kp = try ed25519.KeyPair.fromSeed(seed);
        defer kp.deinit();
        var info = KeyInfo{ .kind = .ed25519, .public = undefined, .public_len = ed25519.public_key_len };
        @memcpy(info.public[0..32], &kp.public_key);
        return info;
    } else |_| {}

    return error.UnsupportedKey;
}

/// Fail-closed PKCS#8 walk (substrate DerReader) accepting only v0 Ed25519.
/// Shared with `armor req` (the CLI's single PKCS#8 Ed25519 parser).
pub fn parseEd25519Pkcs8(der: []const u8) ![32]u8 {
    var top = x509.DerReader.init(der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var body = try top.child(seq);

    const version = try body.readExpected(x509.Tag.integer);
    if (version.value.len != 1 or version.value[0] != 0) return error.UnsupportedKey;

    const alg = try body.readExpected(x509.Tag.sequence);
    var alg_body = try body.child(alg);
    const oid = try alg_body.readExpected(x509.Tag.oid);
    if (!std.mem.eql(u8, oid.value, &.{ 0x2b, 0x65, 0x70 })) return error.UnsupportedKey;

    const wrapped = try body.readExpected(x509.Tag.octet_string);
    var inner = try body.child(wrapped);
    const key = try inner.readExpected(x509.Tag.octet_string);
    try inner.expectEmpty();
    if (key.value.len != 32) return error.UnsupportedKey;

    var seed: [32]u8 = undefined;
    @memcpy(&seed, key.value);
    return seed;
}

pub fn runInspect(gpa: Allocator, io: std.Io, opts: InspectOptions, out: *Writer) !void {
    const text = try common.readInput(gpa, io, opts.in_path);
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    const info = try inspectPem(text);
    switch (info.kind) {
        .ec => try out.writeAll("Private-Key: ECDSA P-256 (256 bit)\n"),
        .ed25519 => try out.writeAll("Private-Key: Ed25519 (255 bit)\n"),
    }
    try out.writeAll("pub: ");
    try common.writeHex(out, info.publicSlice());
    try out.writeByte('\n');
    if (!opts.noout) {
        // Re-emit the key text exactly as read (already validated above).
        try out.writeAll(std.mem.trimEnd(u8, text, "\n"));
        try out.writeByte('\n');
    }
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const builtin = @import("builtin");

test "armorcli genpkey ec emits a SEC1 PEM the substrate parses back" {
    var buf: [512]u8 = undefined;
    const key_pem = try generatePem(std.testing.io, .ec, &buf);
    try testing.expect(std.mem.startsWith(u8, key_pem, "-----BEGIN EC PRIVATE KEY-----"));

    // Round-trip: the substrate EC key parser accepts the generated DER and
    // key inspection recovers a valid SEC1 public point.
    const info = try inspectPem(key_pem);
    try testing.expectEqual(Algorithm.ec, info.kind);
    try testing.expectEqual(@as(usize, 65), info.publicSlice().len);
    try testing.expectEqual(@as(u8, 0x04), info.publicSlice()[0]);
}

test "armorcli genpkey ed25519 emits PKCS#8 that fromSeed accepts" {
    var buf: [512]u8 = undefined;
    const key_pem = try generatePem(std.testing.io, .ed25519, &buf);
    try testing.expect(std.mem.startsWith(u8, key_pem, "-----BEGIN PRIVATE KEY-----"));

    const info = try inspectPem(key_pem);
    try testing.expectEqual(Algorithm.ed25519, info.kind);
    try testing.expectEqual(@as(usize, 32), info.publicSlice().len);
}

test "armorcli pkey inspection fails closed on malformed and truncated keys" {
    // Wrong OID inside PKCS#8.
    var der = ed25519Pkcs8Der(@splat(7));
    der[10] = 0x66; // corrupt the Ed25519 OID
    var pem_buf: [256]u8 = undefined;
    const bad_pem = try pem.encode(&pem_buf, "PRIVATE KEY", &der);
    try testing.expectError(error.UnsupportedKey, inspectPem(bad_pem));

    // Truncated DER body must be a typed error, never a crash.
    var pem_buf2: [256]u8 = undefined;
    const good = ed25519Pkcs8Der(@splat(7));
    const trunc_pem = try pem.encode(&pem_buf2, "PRIVATE KEY", good[0..20]);
    try testing.expect(std.meta.isError(inspectPem(trunc_pem)));

    // Not a key at all.
    try testing.expectError(error.UnsupportedKey, inspectPem("hello world"));
}

test "armorcli genpkey writes the key file 0o600" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;

    const old_umask = std.os.linux.syscall1(.umask, 0o022);
    defer _ = std.os.linux.syscall1(.umask, old_umask);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf: [512]u8 = undefined;
    const key_pem = try generatePem(io, .ec, &buf);
    try common.writeKeyFile(io, tmp.dir, "gen.key", key_pem);

    const st = try tmp.dir.statFile(io, "gen.key", .{});
    const mode = st.permissions.toMode() & 0o777;
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), mode);
}

test "armorcli genpkey arg parsing: rsa/p384/passin are rejected explicitly" {
    try testing.expectError(error.NotImplemented, parseGenArgs(&.{ "-algorithm", "rsa" }));
    try testing.expectError(error.NotImplemented, parseGenArgs(&.{ "-algorithm", "p384" }));
    try testing.expectError(error.NotImplemented, parseGenArgs(&.{ "-passin", "stdin" }));
    try testing.expectError(error.Usage, parseGenArgs(&.{ "-algorithm", "dsa" }));
    const opts = try parseGenArgs(&.{ "-algorithm", "ed25519", "-out", "k.pem" });
    try testing.expectEqual(Algorithm.ed25519, opts.algorithm);
}
