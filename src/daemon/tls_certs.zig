// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS certificate material loader for the daemon's TLS listener.
//!
//! Resolves the leaf certificate chain + private signing key that the TLS server
//! handshake needs, from one of two sources:
//!   * **On-disk material** — when both `cert_path` and `key_path` are supplied,
//!     the files are read and decoded. Each accepts either PEM (a
//!     `-----BEGIN CERTIFICATE-----`, `-----BEGIN PRIVATE KEY-----`, or
//!     `-----BEGIN RSA PRIVATE KEY-----` block) or raw DER, detected by sniffing
//!     for the PEM armor. Private keys may be Ed25519 PKCS#8 or RSA PKCS#1/PKCS#8.
//!   * **Self-signed bootstrap** — when no paths are given and TLS is enabled,
//!     a fresh Ed25519 keypair is generated (seeded from the OS CSPRNG) and a
//!     short-lived self-signed leaf is minted with `dns_name` as its subject.
//!
//! The returned `Loaded` shape mirrors `crypto/tls_server.Config`
//! (`cert_chain` + an Ed25519 `signing_key`); the live listener is wired by
//! `main.zig`, which owns the handshake. The cert chain bytes are caller-owned —
//! call `Loaded.deinit` to release them.
const std = @import("std");
const builtin = @import("builtin");
const kernel_linux = @import("kernel_linux.zig");

const pem = @import("../proto/pem.zig");
const ed25519_pkcs8 = @import("../proto/ed25519_pkcs8.zig");
const rsa_pkcs = @import("../proto/rsa_pkcs.zig");
const ec_pkcs = @import("../proto/ec_pkcs.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const rsa_sign = @import("../crypto/rsa_sign.zig");
const x509 = @import("../crypto/x509.zig");
const random = @import("../crypto/random.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_certs requires a 64-bit target");
}

const Ed25519 = std.crypto.sign.Ed25519;

/// PEM armor markers used to distinguish PEM input from raw DER.
const cert_pem_label = "CERTIFICATE";
const key_pem_label = "PRIVATE KEY";
const rsa_key_pem_label = "RSA PRIVATE KEY";
const ec_key_pem_label = "EC PRIVATE KEY";
const pem_begin_marker = "-----BEGIN";

/// Upper bound on a single on-disk cert or key file. Generous for a leaf chain;
/// guards against runaway reads of an attacker-controlled path.
const max_file_bytes: usize = 256 * 1024;

/// Validity window for the bootstrap leaf: backdated one hour to absorb clock
/// skew, valid for roughly one year.
const bootstrap_backdate_s: i64 = 3600;
const bootstrap_lifetime_s: i64 = 365 * 24 * 3600;
const webtransport_bootstrap_lifetime_s: i64 = 7 * 24 * 3600;

pub const Error = error{
    /// `cert_path` set without `key_path` (or vice versa).
    IncompletePathPair,
    /// Neither on-disk paths nor `enabled` bootstrap were requested.
    NothingToLoad,
    /// A PEM cert file contained no CERTIFICATE block.
    NoCertificate,
} || kernel_linux.ReadError ||
    std.Io.Dir.ReadFileAllocError ||
    pem.Error ||
    ed25519_pkcs8.ParseError ||
    rsa_pkcs.ParseError ||
    ec_pkcs.ParseError ||
    x509_selfsign.Error ||
    ecdsa_p256.DerError ||
    std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.WeakPublicKeyError ||
    random.Error;

/// Inputs for `loadOrBootstrap`. Strings are borrowed for the duration of the
/// call only (paths are read immediately; `dns_name` is copied into the cert).
pub const Options = struct {
    enabled: bool = false,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    /// Subject name minted into the self-signed bootstrap leaf.
    dns_name: []const u8 = "localhost",
};

/// On-disk/bootstrap key kind carried by `Loaded`.
pub const KeyKind = enum {
    ed25519,
    ecdsa_p256,
    rsa,
};

/// Resolved TLS material. `cert_chain` is a leaf-first list of DER
/// certificates. Exactly one signing-key field is set according to `key_kind`;
/// RSA key slices alias `rsa_key_storage`, which this value owns. The chain bytes
/// are owned by this struct; call `deinit` after the server stops borrowing it.
pub const Loaded = struct {
    cert_chain: [][]const u8,
    key_kind: KeyKind,
    signing_key: ?Ed25519.KeyPair = null,
    ecdsa_p256_signing_key: ?ecdsa_p256.KeyPair = null,
    rsa_signing_key: ?rsa_sign.PrivateKey = null,
    rsa_key_storage: ?[]u8 = null,

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        for (self.cert_chain) |der| allocator.free(der);
        allocator.free(self.cert_chain);
        if (self.signing_key) |*kp| {
            std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
        }
        if (self.ecdsa_p256_signing_key) |*kp| {
            std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
        }
        if (self.rsa_key_storage) |storage| {
            std.crypto.secureZero(u8, storage);
            allocator.free(storage);
        }
        self.* = undefined;
    }
};

/// Load TLS material from disk, or bootstrap a self-signed leaf.
///
/// Precedence: if both `cert_path` and `key_path` are set, the on-disk material
/// wins. Supplying exactly one of the pair is an error. Otherwise, when
/// `enabled`, a self-signed leaf is bootstrapped; with neither paths nor
/// `enabled`, `error.NothingToLoad` is returned.
pub fn loadOrBootstrap(allocator: std.mem.Allocator, io: std.Io, opts: Options) Error!Loaded {
    const has_cert = opts.cert_path != null;
    const has_key = opts.key_path != null;
    if (has_cert != has_key) return error.IncompletePathPair;

    if (has_cert and has_key) {
        return loadFromDisk(allocator, io, opts.cert_path.?, opts.key_path.?);
    }
    if (!opts.enabled) return error.NothingToLoad;
    return bootstrap(allocator, io, opts.dns_name);
}

/// Keep explicit disk material on the ordinary loader path. A pathless
/// WebTransport listener instead needs a short-lived P-256 leaf for browser
/// certificate-hash pinning, including the loopback IP used by local clients.
pub fn loadOrBootstrapWebTransport(allocator: std.mem.Allocator, io: std.Io, opts: Options) Error!Loaded {
    if (opts.cert_path != null or opts.key_path != null or !opts.enabled)
        return loadOrBootstrap(allocator, io, opts);
    return bootstrapWebTransport(allocator, io, opts.dns_name);
}

/// Read and decode an on-disk certificate + private key pair.
fn loadFromDisk(allocator: std.mem.Allocator, io: std.Io, cert_path: []const u8, key_path: []const u8) Error!Loaded {
    const chain = try loadCertChain(allocator, io, cert_path);
    errdefer {
        for (chain) |der| allocator.free(der);
        allocator.free(chain);
    }

    var key = try loadPrivateKey(allocator, io, key_path);
    errdefer key.deinit(allocator);

    return .{
        .cert_chain = chain,
        .key_kind = key.key_kind,
        .signing_key = key.signing_key,
        .ecdsa_p256_signing_key = key.ecdsa_p256_signing_key,
        .rsa_signing_key = key.rsa_signing_key,
        .rsa_key_storage = key.takeRsaStorage(),
    };
}

/// Read a certificate file and return the full leaf-first chain as owned DER
/// blocks. A PEM file with several `CERTIFICATE` blocks (e.g. a Let's Encrypt
/// `fullchain.pem`: leaf + issuing intermediate) yields one DER per block, in
/// file order; a single raw-DER file yields a one-element chain. Presenting the
/// intermediate lets clients build a path to the trust anchor without having it
/// cached. The caller owns the returned slice and every element.
pub fn loadCertChain(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error![][]const u8 {
    const raw = try readFileOwned(allocator, io, path);
    defer allocator.free(raw);

    if (!isPem(raw)) {
        const der = try allocator.dupe(u8, raw);
        errdefer allocator.free(der);
        const chain = try allocator.alloc([]const u8, 1);
        chain[0] = der;
        return chain;
    }

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |der| allocator.free(der);
        list.deinit(allocator);
    }

    const begin = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    var off: usize = 0;
    while (std.mem.indexOfPos(u8, raw, off, begin)) |b| {
        const e = (std.mem.indexOfPos(u8, raw, b, end_marker) orelse break) + end_marker.len;
        const block = raw[b..e];
        const der_buf = try allocator.alloc(u8, block.len);
        defer allocator.free(der_buf);
        const der = try pem.decode(block, cert_pem_label, der_buf);
        // Reserve first so the owned dupe can never be orphaned by an
        // ArrayList-growth OOM landing *between* the dupe and the append
        // (six-invariants: each owned allocation freed exactly once). With
        // capacity guaranteed, appendAssumeCapacity is infallible, so if the
        // dupe itself OOMs nothing was allocated to leak.
        try list.ensureUnusedCapacity(allocator, 1);
        list.appendAssumeCapacity(try allocator.dupe(u8, der));
        off = e;
    }

    if (list.items.len == 0) {
        // No CERTIFICATE block despite PEM armor — surface a clear decode error.
        var tiny: [1]u8 = undefined;
        _ = pem.decode(raw, cert_pem_label, &tiny) catch |err| return err;
        return error.NoCertificate;
    }
    return list.toOwnedSlice(allocator);
}

const LoadedKey = struct {
    key_kind: KeyKind,
    signing_key: ?Ed25519.KeyPair = null,
    ecdsa_p256_signing_key: ?ecdsa_p256.KeyPair = null,
    rsa_signing_key: ?rsa_sign.PrivateKey = null,
    rsa_key_storage: ?[]u8 = null,

    fn deinit(self: *LoadedKey, allocator: std.mem.Allocator) void {
        if (self.signing_key) |*kp| {
            std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
        }
        if (self.ecdsa_p256_signing_key) |*kp| {
            std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
        }
        if (self.rsa_key_storage) |storage| {
            std.crypto.secureZero(u8, storage);
            allocator.free(storage);
            self.rsa_key_storage = null;
        }
    }

    fn takeRsaStorage(self: *LoadedKey) ?[]u8 {
        const storage = self.rsa_key_storage;
        self.rsa_key_storage = null;
        return storage;
    }
};

/// Read a private key file (PEM or DER) and return Ed25519 or RSA signing material.
fn loadPrivateKey(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error!LoadedKey {
    const raw = try readFileOwned(allocator, io, path);
    // `raw` holds the private key in its serialized on-disk form (PEM armor or
    // raw DER, and for the non-PEM path it IS `der` below) — wipe before free
    // so the key material doesn't linger in freed heap memory, matching the
    // parsed-form zeroing this module already does elsewhere.
    defer {
        std.crypto.secureZero(u8, raw);
        allocator.free(raw);
    }

    var der_buf: ?[]u8 = null;
    // Same rationale as `raw`: this is the PEM-decoded DER copy of the key,
    // still serialized secret material.
    defer if (der_buf) |buf| {
        std.crypto.secureZero(u8, buf);
        allocator.free(buf);
    };
    // A SEC1 EC key carries its own PEM label; the PKCS#8 and PKCS#1 labels
    // cover Ed25519/RSA and PKCS#8-wrapped EC. `is_sec1_ec` forces the EC path.
    var is_sec1_ec = false;
    const der = if (!isPem(raw)) raw else blk: {
        const buf = try allocator.alloc(u8, raw.len);
        der_buf = buf;
        const first = try pem.decodeFirst(raw, buf);
        if (std.mem.eql(u8, first.label, ec_key_pem_label)) {
            is_sec1_ec = true;
        } else if (!std.mem.eql(u8, first.label, key_pem_label) and !std.mem.eql(u8, first.label, rsa_key_pem_label)) {
            return error.UnsupportedAlgorithm;
        }
        break :blk first.der;
    };

    if (is_sec1_ec) return loadEc(der);

    // PKCS#8 / DER: probe Ed25519, then EC P-256, then RSA.
    if (ed25519_pkcs8.parse(der)) |seed| {
        var seed_copy = seed;
        defer std.crypto.secureZero(u8, &seed_copy);
        return .{
            .key_kind = .ed25519,
            .signing_key = try Ed25519.KeyPair.generateDeterministic(seed_copy),
        };
    } else |_| {}

    if (ec_pkcs.parseScalar(der)) |_| {
        return loadEc(der);
    } else |_| {}

    const rsa = try rsa_pkcs.parse(allocator, der);
    return .{
        .key_kind = .rsa,
        .rsa_signing_key = rsa.key,
        .rsa_key_storage = rsa.storage,
    };
}

/// Decode an EC P-256 private key (SEC1 or PKCS#8 DER) into a signing keypair.
fn loadEc(der: []const u8) Error!LoadedKey {
    var scalar = try ec_pkcs.parseScalar(der);
    defer std.crypto.secureZero(u8, &scalar);
    const secret = ecdsa_p256.SecretKey.fromBytes(scalar) catch return error.UnsupportedAlgorithm;
    const kp = ecdsa_p256.KeyPair.fromSecretKey(secret) catch return error.UnsupportedAlgorithm;
    return .{ .key_kind = .ecdsa_p256, .ecdsa_p256_signing_key = kp };
}

/// Generate a fresh Ed25519 keypair and mint a self-signed leaf for `dns_name`.
fn bootstrap(allocator: std.mem.Allocator, io: std.Io, dns_name: []const u8) Error!Loaded {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try random.fillOsEntropy(&seed);
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    const now = std.Io.Clock.real.now(io).toSeconds();
    var der_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = dns_name,
        .not_before = now - bootstrap_backdate_s,
        .not_after = now + bootstrap_lifetime_s,
        .serial = &bootstrap_serial,
        .key_pair = key_pair,
        // Standards TLS clients match the SAN, not the CN, so the bootstrap leaf
        // carries dns_name as a SAN and is marked a CA so it can self-anchor.
        .dns_names = &.{dns_name},
        .is_ca = true,
    });

    const owned = try allocator.dupe(u8, der);
    errdefer allocator.free(owned);
    const chain = try allocator.alloc([]const u8, 1);
    chain[0] = owned;
    return .{ .cert_chain = chain, .key_kind = .ed25519, .signing_key = key_pair };
}

fn bootstrapWebTransport(allocator: std.mem.Allocator, io: std.Io, dns_name: []const u8) Error!Loaded {
    const key_pair = ecdsa_p256.KeyPair.generate(io);
    const now = std.Io.Clock.real.now(io).toSeconds();
    var der_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(&der_buf, .{
        .common_name = dns_name,
        .not_before = now - bootstrap_backdate_s,
        .not_after = now - bootstrap_backdate_s + webtransport_bootstrap_lifetime_s,
        .serial = &bootstrap_serial,
        .key_pair = key_pair,
        .dns_names = &.{dns_name},
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = false,
        .key_usage_digital_signature = true,
    });
    const owned = try allocator.dupe(u8, der);
    errdefer allocator.free(owned);
    const chain = try allocator.alloc([]const u8, 1);
    chain[0] = owned;
    return .{ .cert_chain = chain, .key_kind = .ecdsa_p256, .ecdsa_p256_signing_key = key_pair };
}

/// Resolved hardened-TLS-1.2 material: an ECDSA-P256 leaf chain + key. The 1.2
/// engine signs ServerKeyExchange with ecdsa_secp256r1_sha256, so its leg always
/// uses an ECDSA-P256 cert regardless of the (possibly Ed25519) 1.3 cert.
pub const Tls12 = struct {
    cert_chain: [][]const u8,
    key: ecdsa_p256.KeyPair,

    pub fn deinit(self: *Tls12, allocator: std.mem.Allocator) void {
        for (self.cert_chain) |der| allocator.free(der);
        allocator.free(self.cert_chain);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key));
    }
};

/// Mint a fresh ECDSA-P256 keypair + self-signed leaf for the hardened TLS 1.2
/// leg of the listener (`dns_name` as CN/SAN; self-anchoring CA).
pub fn bootstrapTls12(allocator: std.mem.Allocator, io: std.Io, dns_name: []const u8) !Tls12 {
    const key = ecdsa_p256.KeyPair.generate(io);
    const now = std.Io.Clock.real.now(io).toSeconds();
    var der_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(&der_buf, .{
        .common_name = dns_name,
        .not_before = now - bootstrap_backdate_s,
        .not_after = now + bootstrap_lifetime_s,
        .serial = &bootstrap_serial,
        .key_pair = key,
        .dns_names = &.{dns_name},
        .is_ca = true,
    });
    const owned = try allocator.dupe(u8, der);
    errdefer allocator.free(owned);
    const chain = try allocator.alloc([]const u8, 1);
    chain[0] = owned;
    return .{ .cert_chain = chain, .key = key };
}

/// Fixed nonzero serial for bootstrap leaves; uniqueness across boots is not
/// required since these are ephemeral, single-host certificates.
const bootstrap_serial = [_]u8{ 0x53, 0x55, 0x5a, 0x55 }; // "SUZU"

/// True when `bytes` looks like PEM (carries the BEGIN armor).
fn isPem(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, pem_begin_marker) != null;
}

/// Read a whole file into an owned buffer, bounded by `max_file_bytes`. Uses the
/// Zig 0.16 `std.Io` layer so the caller controls the IO implementation.
fn readFileOwned(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error![]u8 {
    if (comptime builtin.os.tag == .linux) {
        return kernel_linux.readFileResolved(allocator, path, max_file_bytes);
    }
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_file_bytes));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "loadOrBootstrap: no paths mints a verifiable self-signed leaf for dns_name" {
    // Arrange
    const allocator = testing.allocator;
    const dns_name = "irc.example.test";

    // Act
    var loaded = try loadOrBootstrap(allocator, testing.io, .{ .enabled = true, .dns_name = dns_name });
    defer loaded.deinit(allocator);

    // Assert
    try testing.expectEqual(@as(usize, 1), loaded.cert_chain.len);
    try testing.expectEqual(KeyKind.ed25519, loaded.key_kind);
    const cert = try x509.parse(loaded.cert_chain[0]);
    // The bootstrap leaf is self-signed: its embedded public key must match the
    // returned signing key, and its TBS signature must verify under that key.
    try expectSelfSignedBy(loaded.cert_chain[0], loaded.signing_key.?);
    // When the certificate carries SAN entries, dns_name must be present; the
    // current minter encodes dns_name as the subject CN, so SAN may be empty.
    if (cert.san_dns_count != 0) {
        var found = false;
        for (cert.san_dns[0..cert.san_dns_count]) |name| {
            if (std.mem.eql(u8, name, dns_name)) found = true;
        }
        try testing.expect(found);
    }
}

test "loadOrBootstrapWebTransport: pathless leaf is short-lived P-256 with DNS and loopback SANs" {
    const x509_verify = @import("../crypto/x509_verify.zig");
    const allocator = testing.allocator;
    var loaded = try loadOrBootstrapWebTransport(allocator, testing.io, .{
        .enabled = true,
        .dns_name = "localhost",
    });
    defer loaded.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), loaded.cert_chain.len);
    try testing.expectEqual(KeyKind.ecdsa_p256, loaded.key_kind);
    try testing.expect(loaded.ecdsa_p256_signing_key != null);
    try testing.expect(loaded.signing_key == null);

    const cert = try x509.parse(loaded.cert_chain[0]);
    try testing.expectEqual(webtransport_bootstrap_lifetime_s, cert.not_after.epoch_seconds - cert.not_before.epoch_seconds);
    try testing.expectEqual(@as(usize, 1), cert.san_dns_count);
    try testing.expectEqualStrings("localhost", cert.san_dns[0]);
    try testing.expectEqual(@as(usize, 1), cert.san_ip_count);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, cert.san_ips[0].slice());
    try testing.expect(!cert.basic_constraints_ca);
    try testing.expect(cert.key_usage_present);
    try testing.expect(cert.key_usage_digital_signature);
    try testing.expect(!cert.key_usage_cert_sign);

    const sec1 = loaded.ecdsa_p256_signing_key.?.public_key.toUncompressedSec1();
    switch (try x509.extractPublicKey(cert.spki_der)) {
        .ecdsa_p256 => |embedded| try testing.expectEqualSlices(u8, &sec1, embedded),
        else => return error.TestUnexpectedResult,
    }
    const link = try x509_verify.linkInfo(loaded.cert_chain[0]);
    try x509_verify.verifyCertSignature(link.tbs_der, link.signature_der, link.sig_alg_oid, link.sig_alg_params, link.spki_der);
}

test "loadOrBootstrap: bootstrap keypairs differ across calls" {
    // Arrange
    const allocator = testing.allocator;

    // Act
    var a = try loadOrBootstrap(allocator, testing.io, .{ .enabled = true, .dns_name = "a.test" });
    defer a.deinit(allocator);
    var b = try loadOrBootstrap(allocator, testing.io, .{ .enabled = true, .dns_name = "a.test" });
    defer b.deinit(allocator);

    // Assert: fresh OS entropy per call yields distinct public keys.
    try testing.expectEqual(KeyKind.ed25519, a.key_kind);
    try testing.expectEqual(KeyKind.ed25519, b.key_kind);
    try testing.expect(!std.mem.eql(
        u8,
        &a.signing_key.?.public_key.toBytes(),
        &b.signing_key.?.public_key.toBytes(),
    ));
}

test "loadOrBootstrap: disabled with no paths reports NothingToLoad" {
    // Arrange / Act / Assert
    try testing.expectError(
        error.NothingToLoad,
        loadOrBootstrap(testing.allocator, testing.io, .{ .enabled = false }),
    );
}

test "loadOrBootstrap: a lone cert_path is rejected" {
    // Arrange / Act / Assert
    try testing.expectError(
        error.IncompletePathPair,
        loadOrBootstrap(testing.allocator, testing.io, .{ .enabled = true, .cert_path = "leaf.pem" }),
    );
}

test "loadOrBootstrap: PEM round-trip from disk decodes cert + key" {
    // Arrange: mint a DER cert + key, wrap both as PEM, write to a temp dir.
    const allocator = testing.allocator;
    const seed = @as([Ed25519.KeyPair.seed_length]u8, @splat(0x21));
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    var cert_der_buf: [768]u8 = undefined;
    const cert_der = try x509_selfsign.buildSelfSigned(&cert_der_buf, .{
        .common_name = "disk.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x01, 0x02 },
        .key_pair = key_pair,
    });

    var key_der_buf: [ed25519_pkcs8.der_len]u8 = undefined;
    const key_der = try ed25519_pkcs8.encode(&key_der_buf, seed);

    var cert_pem_buf: [4096]u8 = undefined;
    const cert_pem = try pem.encode(&cert_pem_buf, cert_pem_label, cert_der);
    var key_pem_buf: [4096]u8 = undefined;
    const key_pem = try pem.encode(&key_pem_buf, key_pem_label, key_der);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.pem", .data = cert_pem });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.key", .data = key_pem });
    const cert_path = try tmpPath(allocator, tmp, "leaf.pem");
    defer allocator.free(cert_path);
    const key_path = try tmpPath(allocator, tmp, "leaf.key");
    defer allocator.free(key_path);

    // Act
    var loaded = try loadOrBootstrap(allocator, testing.io, .{
        .enabled = true,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer loaded.deinit(allocator);

    // Assert: decoded chain equals the source DER and the key recovers the seed.
    try testing.expectEqual(@as(usize, 1), loaded.cert_chain.len);
    try testing.expectEqual(KeyKind.ed25519, loaded.key_kind);
    try testing.expectEqualSlices(u8, cert_der, loaded.cert_chain[0]);
    try testing.expectEqualSlices(
        u8,
        &key_pair.public_key.toBytes(),
        &loaded.signing_key.?.public_key.toBytes(),
    );
}

test "loadOrBootstrap: raw DER files (no PEM armor) load directly" {
    // Arrange
    const allocator = testing.allocator;
    const seed = @as([Ed25519.KeyPair.seed_length]u8, @splat(0x37));
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    var cert_der_buf: [768]u8 = undefined;
    const cert_der = try x509_selfsign.buildSelfSigned(&cert_der_buf, .{
        .common_name = "der.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{0x09},
        .key_pair = key_pair,
    });
    var key_der_buf: [ed25519_pkcs8.der_len]u8 = undefined;
    const key_der = try ed25519_pkcs8.encode(&key_der_buf, seed);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.der", .data = cert_der });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.key.der", .data = key_der });
    const cert_path = try tmpPath(allocator, tmp, "leaf.der");
    defer allocator.free(cert_path);
    const key_path = try tmpPath(allocator, tmp, "leaf.key.der");
    defer allocator.free(key_path);

    // Act
    var loaded = try loadOrBootstrap(allocator, testing.io, .{
        .enabled = true,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer loaded.deinit(allocator);

    // Assert
    try testing.expectEqual(KeyKind.ed25519, loaded.key_kind);
    try testing.expectEqualSlices(u8, cert_der, loaded.cert_chain[0]);
    try testing.expectEqualSlices(
        u8,
        &key_pair.public_key.toBytes(),
        &loaded.signing_key.?.public_key.toBytes(),
    );
}

test "loadCertChain: allocation failure at any point is leak-clean (dupe/append boundary)" {
    // Regression for the dupe-then-append OOM leak: an OutOfMemory landing between
    // the per-cert `allocator.dupe` and its insertion into `list` must free the
    // dupe, never orphan it. The 2-block PEM makes a *later* iteration OOM while
    // `list` already holds an earlier dupe, so the sweep proves the function-level
    // errdefer frees the accumulated items (not just the current one) with no leak.
    // `checkAllAllocationFailures` fails allocation 0,1,2,... in turn and asserts
    // every run either fully succeeds or returns OutOfMemory with NO leak.
    const allocator = testing.allocator;

    const kp0 = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x41)));
    const kp1 = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x42)));
    var der0_buf: [768]u8 = undefined;
    var der1_buf: [768]u8 = undefined;
    const der0 = try x509_selfsign.buildSelfSigned(&der0_buf, .{
        .common_name = "chain0.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x0A, 0x01 },
        .key_pair = kp0,
    });
    const der1 = try x509_selfsign.buildSelfSigned(&der1_buf, .{
        .common_name = "chain1.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x0A, 0x02 },
        .key_pair = kp1,
    });

    var pem0_buf: [4096]u8 = undefined;
    var pem1_buf: [4096]u8 = undefined;
    const pem0 = try pem.encode(&pem0_buf, cert_pem_label, der0);
    const pem1 = try pem.encode(&pem1_buf, cert_pem_label, der1);

    // Concatenate the two PEM blocks into one chain file.
    var file_buf: [8192]u8 = undefined;
    @memcpy(file_buf[0..pem0.len], pem0);
    @memcpy(file_buf[pem0.len..][0..pem1.len], pem1);
    const file_data = file_buf[0 .. pem0.len + pem1.len];

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "chain.pem", .data = file_data });
    const chain_path = try tmpPath(allocator, tmp, "chain.pem");
    defer allocator.free(chain_path);

    const Sweep = struct {
        fn run(alloc: std.mem.Allocator, io: std.Io, path: []const u8) !void {
            const chain = try loadCertChain(alloc, io, path);
            defer {
                for (chain) |der| alloc.free(der);
                alloc.free(chain);
            }
            try testing.expectEqual(@as(usize, 2), chain.len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ testing.io, @as([]const u8, chain_path) });
}

/// Build a cwd-relative path into a testing tmp dir, matching `testing.tmpDir`'s
/// `.zig-cache/tmp/<sub_path>` layout so `std.Io.Dir.cwd()` reads resolve.
fn tmpPath(allocator: std.mem.Allocator, tmp: testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

/// Verify that `cert_der` is a self-signed Ed25519 certificate whose embedded
/// SPKI public key equals `key_pair`'s and whose TBS signature verifies.
fn expectSelfSignedBy(cert_der: []const u8, key_pair: Ed25519.KeyPair) !void {
    var cert_cursor: usize = 0;
    const cert = try readTlv(cert_der, &cert_cursor);
    var body_cursor: usize = 0;
    const tbs = try readTlv(cert.value, &body_cursor);
    _ = try readTlv(cert.value, &body_cursor); // signatureAlgorithm
    const sig_bits = try readTlv(cert.value, &body_cursor);

    const sig = Ed25519.Signature.fromBytes(
        sig_bits.value[1..][0..Ed25519.Signature.encoded_length].*,
    );
    try sig.verify(tbs.full, key_pair.public_key);
}

const Tlv = struct {
    tag: u8,
    value: []const u8,
    full: []const u8,
};

/// Minimal DER TLV reader for the self-signed verification assertion.
fn readTlv(input: []const u8, cursor: *usize) !Tlv {
    const start = cursor.*;
    if (input.len - cursor.* < 2) return error.Truncated;
    const tag = input[cursor.*];
    cursor.* += 1;
    const len_byte = input[cursor.*];
    cursor.* += 1;
    var len: usize = 0;
    if ((len_byte & 0x80) == 0) {
        len = len_byte;
    } else {
        const count = len_byte & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) return error.BadLength;
        if (input.len - cursor.* < count) return error.Truncated;
        for (0..count) |_| {
            len = (len << 8) | input[cursor.*];
            cursor.* += 1;
        }
    }
    if (input.len - cursor.* < len) return error.Truncated;
    const value = input[cursor.* .. cursor.* + len];
    cursor.* += len;
    return .{ .tag = tag, .value = value, .full = input[start..cursor.*] };
}

test {
    testing.refAllDecls(@This());
}
