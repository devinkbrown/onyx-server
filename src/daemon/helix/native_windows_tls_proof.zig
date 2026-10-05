// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free commitment to the default TLS certificate and signing key
//! actually serving on a Windows node. The same digest can be derived from a
//! disk-loaded candidate and the source's live Server.Config after ACME reload.
//! It is a proof component, not a substitute for the full config-source proof.

const std = @import("std");
const tls_certs = @import("../tls_certs.zig");
const ecdsa_p256 = @import("../../crypto/ecdsa_p256.zig");
const rsa_sign = @import("../../crypto/rsa_sign.zig");
const x509 = @import("../../crypto/x509.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;
const domain = "onyx/helix/windows-live-default-tls/v1\x00";
const effective_domain = "onyx/helix/windows-effective-config-dynamic-tls/v1\x00";
const tls12_domain = "onyx/helix/windows-live-generated-tls12/v1\x00";
const serving_domain = "onyx/helix/windows-live-serving-tls/v1\x00";
const max_material_bytes: usize = 64 * 1024 * 1024;

pub const Digest = [Sha256.digest_length]u8;
pub const Error = error{ InvalidMaterial, TooLarge };

/// Borrowed view of either a `tls_certs.Loaded` or the live Server.Config.
/// Exactly one signing key must be present. RSA slices refer to their retained
/// server-owned DER storage, but the digest hashes semantic private components
/// rather than depending on a particular PKCS encoding or memory address.
pub const Material = struct {
    cert_chain: []const []const u8,
    signing_key: ?*const Ed25519.KeyPair = null,
    ecdsa_p256_signing_key: ?*const ecdsa_p256.KeyPair = null,
    rsa_signing_key: ?*const rsa_sign.PrivateKey = null,
};

pub const GeneratedTls12 = struct {
    cert_chain: []const []const u8,
    signing_key: *const ecdsa_p256.KeyPair,
};

pub const Tls12Mode = enum(u8) { disabled, shared_default, generated };

pub fn fromLoaded(loaded: *const tls_certs.Loaded) Material {
    return .{
        .cert_chain = loaded.cert_chain,
        .signing_key = if (loaded.signing_key) |*key| key else null,
        .ecdsa_p256_signing_key = if (loaded.ecdsa_p256_signing_key) |*key| key else null,
        .rsa_signing_key = if (loaded.rsa_signing_key) |*key| key else null,
    };
}

pub fn digestLoaded(loaded: *const tls_certs.Loaded) Error!Digest {
    switch (loaded.key_kind) {
        .ed25519 => if (loaded.signing_key == null) return error.InvalidMaterial,
        .ecdsa_p256 => if (loaded.ecdsa_p256_signing_key == null) return error.InvalidMaterial,
        .rsa => if (loaded.rsa_signing_key == null) return error.InvalidMaterial,
    }
    return digest(fromLoaded(loaded));
}

/// Hash the current default TLS leaf, full chain, and private signing material.
/// The caller must hold the server's World lock while reading a live config; a
/// cert reload may otherwise replace the borrowed chain/key generations.
pub fn digest(material: Material) Error!Digest {
    if (material.cert_chain.len == 0) return error.InvalidMaterial;
    const key_count: u8 = @as(u8, @intFromBool(material.signing_key != null)) +
        @as(u8, @intFromBool(material.ecdsa_p256_signing_key != null)) +
        @as(u8, @intFromBool(material.rsa_signing_key != null));
    if (key_count != 1) return error.InvalidMaterial;

    var hash = Sha256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    hash.update(domain);
    var charged: usize = 0;
    try recordCount(&hash, material.cert_chain.len);
    for (material.cert_chain) |der| {
        if (der.len == 0) return error.InvalidMaterial;
        try recordBytes(&hash, &charged, der);
    }
    if (material.signing_key) |key| {
        hash.update(&.{1});
        var secret = key.secret_key.toBytes();
        defer std.crypto.secureZero(u8, &secret);
        const public = key.public_key.toBytes();
        try recordBytes(&hash, &charged, &secret);
        try recordBytes(&hash, &charged, &public);
    } else if (material.ecdsa_p256_signing_key) |key| {
        hash.update(&.{2});
        var secret = key.secret_key.toBytes();
        defer std.crypto.secureZero(u8, &secret);
        const public = key.public_key.toUncompressedSec1();
        try recordBytes(&hash, &charged, &secret);
        try recordBytes(&hash, &charged, &public);
    } else if (material.rsa_signing_key) |key| {
        hash.update(&.{3});
        if (key.n.len == 0 or key.e.len == 0 or key.d.len == 0) return error.InvalidMaterial;
        try recordBytes(&hash, &charged, key.n);
        try recordBytes(&hash, &charged, key.e);
        try recordBytes(&hash, &charged, key.d);
        const crt_count: u8 = @as(u8, @intFromBool(key.p != null)) + @as(u8, @intFromBool(key.q != null)) +
            @as(u8, @intFromBool(key.dp != null)) + @as(u8, @intFromBool(key.dq != null)) +
            @as(u8, @intFromBool(key.qinv != null));
        if (crt_count != 0 and crt_count != 5) return error.InvalidMaterial;
        hash.update(&.{@intFromBool(crt_count == 5)});
        if (crt_count == 5) {
            try recordBytes(&hash, &charged, key.p.?);
            try recordBytes(&hash, &charged, key.q.?);
            try recordBytes(&hash, &charged, key.dp.?);
            try recordBytes(&hash, &charged, key.dq.?);
            try recordBytes(&hash, &charged, key.qinv.?);
        }
    }
    return hash.finalResult();
}

/// A handoff must prove that the certificate and private key agree. This is
/// allocation-free and can run on both the source's live material and the
/// candidate's detached, fully decoded replacement before READY.
pub fn validateIdentity(material: Material) !void {
    _ = try digest(material);
    const leaf = try x509.parse(material.cert_chain[0]);
    const key = try x509.extractPublicKey(leaf.spki_der);
    switch (key) {
        .ed25519 => |public| {
            const private = material.signing_key orelse return error.TlsKeyMismatch;
            if (material.ecdsa_p256_signing_key != null or material.rsa_signing_key != null or
                !std.mem.eql(u8, public, &private.public_key.toBytes())) return error.TlsKeyMismatch;
        },
        .ecdsa_p256 => |public| {
            const private = material.ecdsa_p256_signing_key orelse return error.TlsKeyMismatch;
            if (material.signing_key != null or material.rsa_signing_key != null or
                !std.mem.eql(u8, public, &private.public_key.toUncompressedSec1())) return error.TlsKeyMismatch;
        },
        .rsa => |public| {
            const private = material.rsa_signing_key orelse return error.TlsKeyMismatch;
            if (material.signing_key != null or material.ecdsa_p256_signing_key != null or
                !std.mem.eql(u8, public.modulus, private.n) or
                !std.mem.eql(u8, public.exponent, private.e)) return error.TlsKeyMismatch;
        },
    }
}

pub fn digestGeneratedTls12(material: GeneratedTls12) Error!Digest {
    if (material.cert_chain.len == 0) return error.InvalidMaterial;
    var hash = Sha256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    hash.update(tls12_domain);
    var charged: usize = 0;
    try recordCount(&hash, material.cert_chain.len);
    for (material.cert_chain) |der| try recordBytes(&hash, &charged, der);
    var secret = material.signing_key.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &secret);
    const public = material.signing_key.public_key.toUncompressedSec1();
    try recordBytes(&hash, &charged, &secret);
    try recordBytes(&hash, &charged, &public);
    return hash.finalResult();
}

pub fn validateGeneratedTls12(material: GeneratedTls12) !void {
    _ = try digestGeneratedTls12(material);
    const leaf = try x509.parse(material.cert_chain[0]);
    const key = try x509.extractPublicKey(leaf.spki_der);
    switch (key) {
        .ecdsa_p256 => |public| {
            if (!std.mem.eql(u8, public, &material.signing_key.public_key.toUncompressedSec1())) return error.TlsKeyMismatch;
        },
        else => return error.TlsKeyMismatch,
    }
}

/// Bind the currently serving TLS 1.3 generation and the exact TLS 1.2 leg.
/// A generated 1.2 leaf is not reproducible by a new process, so it must be
/// carried from the source and verified before the candidate serves clients.
pub fn digestServing(default: Material, mode: Tls12Mode, generated: ?GeneratedTls12) Error!Digest {
    if ((mode == .generated) != (generated != null)) return error.InvalidMaterial;
    if (mode == .shared_default and default.ecdsa_p256_signing_key == null and default.rsa_signing_key == null)
        return error.InvalidMaterial;
    if (mode == .generated and default.signing_key == null) return error.InvalidMaterial;
    const default_digest = try digest(default);
    const generated_digest: ?Digest = if (generated) |leg| try digestGeneratedTls12(leg) else null;
    var hash = Sha256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    hash.update(serving_domain);
    hash.update(&default_digest);
    hash.update(&.{@intFromEnum(mode)});
    if (generated_digest) |d| hash.update(&d);
    return hash.finalResult();
}

pub fn equal(a: Digest, b: Digest) bool {
    return std.crypto.timing_safe.eql(Digest, a, b);
}

/// Join a main-computed static effective proof (config source, SNI, ECH,
/// VAPID, node/cloak, OAuth, and GeoIP) with `digestServing` for the current
/// default cert/key and TLS 1.2 leg. Main and Server must use the same static
/// proof across renewal; any other effective-policy mutation invalidates it.
pub fn composeEffective(static_effective: Digest, live_serving_tls: Digest) Digest {
    var hash = Sha256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    hash.update(effective_domain);
    hash.update(&static_effective);
    hash.update(&live_serving_tls);
    return hash.finalResult();
}

fn recordCount(hash: *Sha256, count: usize) Error!void {
    const bounded = std.math.cast(u64, count) orelse return error.TooLarge;
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, bounded, .big);
    hash.update(&length);
}

fn recordBytes(hash: *Sha256, charged: *usize, bytes: []const u8) Error!void {
    if (bytes.len == 0) return error.InvalidMaterial;
    if (bytes.len > max_material_bytes - charged.*) return error.TooLarge;
    charged.* += bytes.len;
    try recordCount(hash, bytes.len);
    hash.update(bytes);
}

test "Windows live TLS proof matches a loaded Ed25519 leaf and detects cert or key drift" {
    const key = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    const chain = [_][]const u8{ "leaf", "issuer" };
    const loaded = tls_certs.Loaded{ .cert_chain = @constCast(&chain), .key_kind = .ed25519, .signing_key = key };
    const source = try digestLoaded(&loaded);
    try std.testing.expect(equal(source, try digest(.{ .cert_chain = &chain, .signing_key = &key })));
    const changed_chain = [_][]const u8{ "other", "issuer" };
    try std.testing.expect(!equal(source, try digest(.{ .cert_chain = &changed_chain, .signing_key = &key })));
    const changed_key = try Ed25519.KeyPair.generateDeterministic(@splat(8));
    try std.testing.expect(!equal(source, try digest(.{ .cert_chain = &chain, .signing_key = &changed_key })));
}

test "Windows live TLS proof matches P256 and hashes RSA private components" {
    const secret = try ecdsa_p256.SecretKey.fromBytes(@splat(3));
    const ec = try ecdsa_p256.KeyPair.fromSecretKey(secret);
    const chain = [_][]const u8{"leaf"};
    const ec_loaded = tls_certs.Loaded{ .cert_chain = @constCast(&chain), .key_kind = .ecdsa_p256, .ecdsa_p256_signing_key = ec };
    try std.testing.expect(equal(try digestLoaded(&ec_loaded), try digest(.{ .cert_chain = &chain, .ecdsa_p256_signing_key = &ec })));

    const rsa = rsa_sign.PrivateKey{ .n = "n", .e = "e", .d = "d", .p = "p", .q = "q", .dp = "dp", .dq = "dq", .qinv = "qi" };
    const rsa_loaded = tls_certs.Loaded{ .cert_chain = @constCast(&chain), .key_kind = .rsa, .rsa_signing_key = rsa };
    const expected = try digestLoaded(&rsa_loaded);
    try std.testing.expect(equal(expected, try digest(.{ .cert_chain = &chain, .rsa_signing_key = &rsa })));
    var changed = rsa;
    changed.d = "d2";
    try std.testing.expect(!equal(expected, try digest(.{ .cert_chain = &chain, .rsa_signing_key = &changed })));
}

test "Windows live TLS proof rejects malformed key shape and missing chain" {
    const key = try Ed25519.KeyPair.generateDeterministic(@splat(9));
    const chain = [_][]const u8{"leaf"};
    try std.testing.expectError(error.InvalidMaterial, digest(.{ .cert_chain = &.{}, .signing_key = &key }));
    try std.testing.expectError(error.InvalidMaterial, digest(.{ .cert_chain = &chain }));
    const rsa = rsa_sign.PrivateKey{ .n = "n", .e = "e", .d = "d" };
    try std.testing.expectError(error.InvalidMaterial, digest(.{ .cert_chain = &chain, .signing_key = &key, .rsa_signing_key = &rsa }));
    const partial = rsa_sign.PrivateKey{ .n = "n", .e = "e", .d = "d", .p = "p" };
    try std.testing.expectError(error.InvalidMaterial, digest(.{ .cert_chain = &chain, .rsa_signing_key = &partial }));
}

test "Windows dynamic TLS proof binds both static policy and live certificate" {
    const static_a: Digest = @splat(1);
    const static_b: Digest = @splat(2);
    const tls_a: Digest = @splat(3);
    const tls_b: Digest = @splat(4);
    const a = composeEffective(static_a, tls_a);
    try std.testing.expect(equal(a, composeEffective(static_a, tls_a)));
    try std.testing.expect(!equal(a, composeEffective(static_b, tls_a)));
    try std.testing.expect(!equal(a, composeEffective(static_a, tls_b)));
}

test "Windows serving TLS proof distinguishes generated TLS 1.2 generations" {
    const ed = try Ed25519.KeyPair.generateDeterministic(@splat(0x51));
    const ec_a = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(@splat(0x21)));
    const ec_b = try ecdsa_p256.KeyPair.fromSecretKey(try ecdsa_p256.SecretKey.fromBytes(@splat(0x22)));
    const default_chain = [_][]const u8{"default"};
    const side_chain_a = [_][]const u8{"side-a"};
    const side_chain_b = [_][]const u8{"side-b"};
    const default: Material = .{ .cert_chain = &default_chain, .signing_key = &ed };
    const a = try digestServing(default, .generated, .{ .cert_chain = &side_chain_a, .signing_key = &ec_a });
    try std.testing.expect(equal(a, try digestServing(default, .generated, .{ .cert_chain = &side_chain_a, .signing_key = &ec_a })));
    try std.testing.expect(!equal(a, try digestServing(default, .generated, .{ .cert_chain = &side_chain_b, .signing_key = &ec_a })));
    try std.testing.expect(!equal(a, try digestServing(default, .generated, .{ .cert_chain = &side_chain_a, .signing_key = &ec_b })));
    try std.testing.expectError(error.InvalidMaterial, digestServing(default, .shared_default, null));
    try std.testing.expectError(error.InvalidMaterial, digestServing(default, .generated, null));
}
