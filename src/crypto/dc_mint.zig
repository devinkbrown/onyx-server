// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Delegated credential minting and short-lived rotation (RFC 9345).
//!
//! A delegated credential (DC) lets a TLS 1.3 server sign CertificateVerify with
//! a short-lived key it holds online, while the long-lived certificate key only
//! signs the DC. This module mints that DC: it generates the delegated key pair,
//! builds the `Credential`, and signs it with the end-entity (delegation)
//! certificate's key over the exact RFC 9345 §4.1.3 message reconstructed by
//! `proto/delegated_credential.zig`. The output plugs straight into
//! `tls_server.Config.delegated_credential` through `Minted.serverCredential`.
//!
//! Policy enforced here, fail closed, so a minted DC always passes the client
//! checks of RFC 9345 §4.1.3:
//!   * the delegation certificate carries the DelegationUsage extension and the
//!     digitalSignature KeyUsage (RFC 9345 §4.2);
//!   * the supplied leaf key matches the certificate's SubjectPublicKeyInfo;
//!   * the DC expires no more than seven days after `now` (§4.1.3 check 2) and
//!     strictly before the certificate's notAfter (§4.1.3 check 1, which a
//!     client also enforces through ordinary chain validation);
//!   * `valid_time` is counted from the certificate's notBefore (§4.1.1).
//!
//! Signature schemes (RFC 8446 §4.2.3): the leaf key signs with `ed25519`,
//! `ecdsa_secp256r1_sha256` (DER `ECDSA-Sig-Value`) or `rsa_pss_rsae_sha256`
//! (32-byte salt, RFC 8017 §9.1). PKCS#1 v1.5 is never used — TLS 1.3 forbids it
//! for handshake signatures (RFC 8446 §4.2.3), and RFC 9345 §4 requires the DC
//! signature to use a TLS 1.3 scheme. The delegated key is ECDSA P-256 by
//! default (the scheme every DC-capable browser accepts) or Ed25519.
//!
//! Rotation: `RotationPolicy` describes a short DC lifetime and when to renew
//! before expiry; `RotationPolicy.due` answers "mint now?" for a daemon timer
//! and `RotationPolicy.mintNext` mints a fresh DC, clamped to the certificate's
//! remaining validity.
const std = @import("std");

const delegated_credential = @import("../proto/delegated_credential.zig");
const tls_signature_scheme = @import("../proto/tls_signature_scheme.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_sign = @import("rsa_sign.zig");
const rsa_verify = @import("rsa_verify.zig");
const random = @import("random.zig");
const x509 = @import("x509.zig");
const tls_server = @import("tls_server.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Scheme = tls_signature_scheme.SignatureScheme;

/// The longest lifetime a DC may have, measured from the moment it is minted
/// (RFC 9345 §4.1.3 check 2).
pub const max_lifetime_seconds: u32 = delegated_credential.max_valid_time_seconds;

pub const Error = error{
    /// The delegation certificate lacks the DelegationUsage extension
    /// (OID 1.3.6.1.4.1.44363.44, RFC 9345 §4.2).
    DelegationUsageMissing,
    /// The delegation certificate lacks the digitalSignature KeyUsage bit.
    DigitalSignatureKeyUsageMissing,
    /// The supplied leaf private key does not match the certificate's SPKI.
    LeafKeyMismatch,
    /// Lifetime is zero or longer than seven days.
    InvalidLifetime,
    /// `now` precedes the certificate's notBefore, so no valid `valid_time`.
    CertificateNotYetValid,
    /// The requested expiry is at or after the certificate's notAfter.
    OutlivesCertificate,
    /// The expiry offset from notBefore does not fit `uint32 valid_time`.
    ValidTimeOverflow,
    /// The certificate key type cannot sign a TLS 1.3 DC.
    UnsupportedLeafKey,
    /// The supplied delegated private key does not match the DC's SPKI.
    DcKeyMismatch,
} || std.mem.Allocator.Error ||
    delegated_credential.Error ||
    x509.Error ||
    ecdsa_p256.DerError ||
    rsa_sign.Error ||
    random.Error ||
    std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.WeakPublicKeyError ||
    std.crypto.errors.EncodingError;

/// The delegation certificate's private key (the key that signs the DC).
pub const LeafKey = union(enum) {
    ed25519: Ed25519.KeyPair,
    ecdsa_p256: ecdsa_p256.KeyPair,
    rsa: rsa_sign.PrivateKey,
};

/// The delegated key's algorithm, i.e. the DC's `dc_cert_verify_algorithm`.
pub const DcAlgorithm = enum {
    ecdsa_p256,
    ed25519,

    pub fn scheme(self: DcAlgorithm) Scheme {
        return switch (self) {
            .ecdsa_p256 => .ecdsa_secp256r1_sha256,
            .ed25519 => .ed25519,
        };
    }
};

/// The delegated private key. Owned by `Minted`; wiped by `Minted.deinit`.
pub const DcPrivateKey = union(DcAlgorithm) {
    ecdsa_p256: ecdsa_p256.KeyPair,
    ed25519: Ed25519.KeyPair,
};

pub const MintOptions = struct {
    /// DER of the end-entity delegation certificate (`cert_chain[0]`).
    leaf_der: []const u8,
    /// The private key matching `leaf_der`'s SPKI.
    leaf_key: LeafKey,
    dc_algorithm: DcAlgorithm = .ecdsa_p256,
    /// Current wall-clock Unix seconds (this module takes no clock).
    now_unix: i64,
    /// Seconds from `now_unix` until the DC expires; 1 ..= seven days.
    lifetime_seconds: u32,
    /// When true, a lifetime that would reach the certificate's notAfter is
    /// shortened to end one second before it instead of failing. Rotation uses
    /// this so the last DCs of a certificate's life still mint.
    clamp_to_certificate: bool = false,
};

/// A freshly minted DC. `wire` is the RFC 9345 §4 `DelegatedCredential`
/// structure (the leaf CertificateEntry extension body).
pub const Minted = struct {
    wire: []u8,
    private_key: DcPrivateKey,
    /// Absolute expiry: certificate notBefore + `valid_time`.
    expiry_unix: i64,
    valid_time: u32,

    /// The `tls_server.Config.delegated_credential` value. Borrows `self`; keep
    /// `self` alive (and un-wiped) for as long as the server uses it.
    pub fn serverCredential(self: *const Minted) tls_server.DelegatedCredential {
        return .{
            .wire = self.wire,
            .private_key = switch (self.private_key) {
                .ecdsa_p256 => |kp| .{ .ecdsa_p256 = kp },
                .ed25519 => |kp| .{ .ed25519 = kp },
            },
        };
    }

    /// Secure-zero the delegated private key and free the wire bytes.
    pub fn deinit(self: *Minted, allocator: std.mem.Allocator) void {
        switch (self.private_key) {
            .ecdsa_p256 => |*kp| ecdsa_p256.wipeKeyPair(kp),
            .ed25519 => |*kp| std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key)),
        }
        allocator.free(self.wire);
        self.* = undefined;
    }
};

/// Mint one delegated credential. See the module header for every check.
pub fn mint(allocator: std.mem.Allocator, io: std.Io, opts: MintOptions) Error!Minted {
    var dc_key: DcPrivateKey = switch (opts.dc_algorithm) {
        .ecdsa_p256 => .{ .ecdsa_p256 = ecdsa_p256.KeyPair.generate(io) },
        .ed25519 => blk: {
            var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            try random.fillOsEntropy(&seed);
            break :blk .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(seed) };
        },
    };
    // On success `mintWithKey` returns its own copy inside `Minted`, so this
    // stack copy is wiped on every path, not only on failure.
    defer wipeDcKey(&dc_key);
    return mintWithKey(allocator, opts, dc_key);
}

fn wipeDcKey(key: *DcPrivateKey) void {
    switch (key.*) {
        .ecdsa_p256 => |*kp| ecdsa_p256.wipeKeyPair(kp),
        .ed25519 => |*kp| std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key)),
    }
}

/// Fail with `error.LeafKeyMismatch` unless `key` is the private half of the
/// SubjectPublicKeyInfo in `leaf_der` (full public-key comparison, not only
/// the key type). Servers call this at startup so a wrong `-key` fails there
/// instead of in every handshake's CertificateVerify (RFC 8446 §4.4.3).
pub fn checkLeafKey(leaf_der: []const u8, key: LeafKey) Error!void {
    const leaf = try x509.parse(leaf_der);
    _ = try leafScheme(key, try x509.extractPublicKey(leaf.spki_der));
}

/// Fail with `error.DcKeyMismatch` unless `key` is the private half of the
/// delegated SubjectPublicKeyInfo carried in the DC `wire` (RFC 9345 §4:
/// the server signs CertificateVerify with the DC's private key, and the
/// client verifies it against `Credential.ASN1_subjectPublicKeyInfo`).
pub fn checkDcKey(wire: []const u8, key: DcPrivateKey) Error!void {
    const parsed = try delegated_credential.parse(wire);
    const dc_pub = try x509.extractPublicKey(parsed.spki);
    switch (key) {
        .ed25519 => |kp| {
            const raw = switch (dc_pub) {
                .ed25519 => |pk| pk,
                else => return error.DcKeyMismatch,
            };
            if (!std.mem.eql(u8, raw, &kp.public_key.toBytes())) return error.DcKeyMismatch;
        },
        .ecdsa_p256 => |kp| {
            const sec1 = switch (dc_pub) {
                .ecdsa_p256 => |pk| pk,
                else => return error.DcKeyMismatch,
            };
            if (!std.mem.eql(u8, sec1, &kp.public_key.toUncompressedSec1())) return error.DcKeyMismatch;
        },
    }
}

/// Mint with a caller-chosen delegated key (deterministic tests, HSM-held
/// keys). On success the returned `Minted` owns a copy of `dc_key`.
pub fn mintWithKey(allocator: std.mem.Allocator, opts: MintOptions, dc_key: DcPrivateKey) Error!Minted {
    const leaf = try x509.parse(opts.leaf_der);
    if (!leaf.delegation_usage) return error.DelegationUsageMissing;
    if (!leaf.key_usage_digital_signature) return error.DigitalSignatureKeyUsageMissing;
    const algorithm = try leafScheme(opts.leaf_key, try x509.extractPublicKey(leaf.spki_der));

    if (opts.lifetime_seconds == 0 or opts.lifetime_seconds > max_lifetime_seconds) return error.InvalidLifetime;
    const not_before = leaf.not_before.epoch_seconds;
    const not_after = leaf.not_after.epoch_seconds;
    if (opts.now_unix < not_before) return error.CertificateNotYetValid;
    var expiry = opts.now_unix + @as(i64, opts.lifetime_seconds);
    if (expiry >= not_after) {
        if (!opts.clamp_to_certificate) return error.OutlivesCertificate;
        expiry = not_after - 1;
        if (expiry <= opts.now_unix) return error.OutlivesCertificate;
    }
    const offset = expiry - not_before;
    if (offset <= 0 or offset > std.math.maxInt(u32)) return error.ValidTimeOverflow;
    const valid_time: u32 = @intCast(offset);

    var spki_buf: [max_spki_len]u8 = undefined;
    const spki = dcSpki(&spki_buf, dc_key);
    // The delegated key itself decides `dc_cert_verify_algorithm`; for
    // `mintWithKey` that overrides `opts.dc_algorithm`.
    const cred_fixed: delegated_credential.Credential = .{
        .valid_time = valid_time,
        .dc_cert_verify_algorithm = @as(DcAlgorithm, dc_key).scheme().toInt(),
        .spki = spki,
    };

    var portion_buf: [max_spki_len + 16]u8 = undefined;
    const portion = try delegated_credential.writeSignedPortion(&portion_buf, cred_fixed, algorithm.toInt());
    const msg = try allocator.alloc(u8, delegated_credential.signedMessageLen(opts.leaf_der.len, portion.len));
    defer allocator.free(msg);
    const signed = try delegated_credential.writeSignedMessage(msg, opts.leaf_der, portion);

    var sig_buf: [rsa_verify.max_bytes]u8 = undefined;
    const sig = try signWithLeaf(opts.leaf_key, signed, &sig_buf);

    const wire = try allocator.alloc(u8, portion.len + 2 + sig.len);
    errdefer allocator.free(wire);
    const written = try delegated_credential.serialize(wire, cred_fixed, algorithm.toInt(), sig);
    std.debug.assert(written.len == wire.len);
    return .{ .wire = wire, .private_key = dc_key, .expiry_unix = expiry, .valid_time = valid_time };
}

/// Short-lived rotation policy for a daemon timer. Defaults: a 24-hour DC,
/// renewed once half its life has elapsed, so a client clock up to 12 hours
/// behind still accepts the current DC and a missed renewal has 12 hours of
/// slack before the server must fall back to the certificate key.
pub const RotationPolicy = struct {
    lifetime_seconds: u32 = 24 * 60 * 60,
    /// Renew when the active DC has this many seconds or fewer left.
    renew_before_seconds: u32 = 12 * 60 * 60,
    dc_algorithm: DcAlgorithm = .ecdsa_p256,

    /// Fails closed on a policy that could never keep a valid DC installed.
    pub fn validate(self: RotationPolicy) Error!void {
        if (self.lifetime_seconds == 0 or self.lifetime_seconds > max_lifetime_seconds) return error.InvalidLifetime;
        if (self.renew_before_seconds >= self.lifetime_seconds) return error.InvalidLifetime;
    }

    /// True when no DC is installed or the installed one is within the renewal
    /// window (or already expired).
    pub fn due(self: RotationPolicy, active_expiry_unix: ?i64, now_unix: i64) bool {
        const expiry = active_expiry_unix orelse return true;
        return expiry - now_unix <= @as(i64, self.renew_before_seconds);
    }

    /// Unix second at which the DC expiring at `expiry_unix` should be renewed.
    pub fn renewAt(self: RotationPolicy, expiry_unix: i64) i64 {
        return expiry_unix - @as(i64, self.renew_before_seconds);
    }

    /// Mint the next DC for `leaf_der`, clamped to the certificate's remaining
    /// validity. The caller swaps it into the TLS config and `deinit`s the old
    /// one only after no handshake can still reference it.
    pub fn mintNext(
        self: RotationPolicy,
        allocator: std.mem.Allocator,
        io: std.Io,
        leaf_der: []const u8,
        leaf_key: LeafKey,
        now_unix: i64,
    ) Error!Minted {
        try self.validate();
        return mint(allocator, io, .{
            .leaf_der = leaf_der,
            .leaf_key = leaf_key,
            .dc_algorithm = self.dc_algorithm,
            .now_unix = now_unix,
            .lifetime_seconds = self.lifetime_seconds,
            .clamp_to_certificate = true,
        });
    }
};

/// Map the leaf key to its TLS 1.3 DC signature scheme after proving the key
/// matches the certificate's public key.
fn leafScheme(key: LeafKey, cert_key: x509.SubjectPublicKey) Error!Scheme {
    switch (key) {
        .ed25519 => |kp| {
            const raw = switch (cert_key) {
                .ed25519 => |pk| pk,
                else => return error.LeafKeyMismatch,
            };
            if (!std.mem.eql(u8, raw, &kp.public_key.toBytes())) return error.LeafKeyMismatch;
            return .ed25519;
        },
        .ecdsa_p256 => |kp| {
            const sec1 = switch (cert_key) {
                .ecdsa_p256 => |pk| pk,
                else => return error.LeafKeyMismatch,
            };
            if (!std.mem.eql(u8, sec1, &kp.public_key.toUncompressedSec1())) return error.LeafKeyMismatch;
            return .ecdsa_secp256r1_sha256;
        },
        .rsa => |priv| {
            const pub_key = switch (cert_key) {
                .rsa => |pk| pk,
                else => return error.LeafKeyMismatch,
            };
            if (!std.mem.eql(u8, stripZeros(pub_key.modulus), stripZeros(priv.n)) or
                !std.mem.eql(u8, stripZeros(pub_key.exponent), stripZeros(priv.e)))
            {
                return error.LeafKeyMismatch;
            }
            return .rsa_pss_rsae_sha256;
        },
    }
}

fn stripZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) i += 1;
    return bytes[i..];
}

fn signWithLeaf(key: LeafKey, msg: []const u8, out: *[rsa_verify.max_bytes]u8) Error![]const u8 {
    switch (key) {
        .ed25519 => |kp| {
            const sig = (try kp.sign(msg, null)).toBytes();
            @memcpy(out[0..sig.len], &sig);
            return out[0..sig.len];
        },
        .ecdsa_p256 => |kp| {
            const sig = try ecdsa_p256.sign(msg, kp);
            return ecdsa_p256.signatureToDer(sig, out);
        },
        .rsa => |priv| {
            // rsa_pss_rsae_sha256: MGF1-SHA-256, salt length = hash length
            // (RFC 8446 §4.2.3).
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            var salt: [32]u8 = undefined;
            try random.fillOsEntropy(&salt);
            return rsa_sign.signPss(priv, .sha256, &digest, &salt, out);
        },
    }
}

// SubjectPublicKeyInfo prefixes (RFC 5480 §2 for id-ecPublicKey/prime256v1,
// RFC 8410 §4 for id-Ed25519).
const p256_spki_prefix = [_]u8{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};
const ed25519_spki_prefix = [_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
const max_spki_len = p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length;

/// DER SubjectPublicKeyInfo of the delegated public key.
pub fn dcSpki(out: *[max_spki_len]u8, key: DcPrivateKey) []const u8 {
    switch (key) {
        .ecdsa_p256 => |kp| {
            @memcpy(out[0..p256_spki_prefix.len], &p256_spki_prefix);
            const sec1 = kp.public_key.toUncompressedSec1();
            @memcpy(out[p256_spki_prefix.len..][0..sec1.len], &sec1);
            return out[0 .. p256_spki_prefix.len + sec1.len];
        },
        .ed25519 => |kp| {
            @memcpy(out[0..ed25519_spki_prefix.len], &ed25519_spki_prefix);
            const pk = kp.public_key.toBytes();
            @memcpy(out[ed25519_spki_prefix.len..][0..pk.len], &pk);
            return out[0 .. ed25519_spki_prefix.len + pk.len];
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const x509_selfsign = @import("../proto/x509_selfsign.zig");

const t_not_before: i64 = 1_704_067_200;
const t_not_after: i64 = t_not_before + 30 * 24 * 3600;

fn delegationLeaf(buf: []u8, kp: Ed25519.KeyPair, delegation: bool, digital_signature: bool) ![]const u8 {
    return x509_selfsign.buildSelfSigned(buf, .{
        .common_name = "dc.example.test",
        .not_before = t_not_before,
        .not_after = t_not_after,
        .serial = &.{ 0x44, 0x43 },
        .key_pair = kp,
        .dns_names = &.{"dc.example.test"},
        .delegation_usage = delegation,
        .key_usage_digital_signature = digital_signature,
    });
}

/// Independent verifier mirroring the TLS client's RFC 9345 §4.1.3 checks.
fn verifyMinted(leaf_der: []const u8, wire: []const u8, now: i64) !delegated_credential.Parsed {
    const dc = try delegated_credential.parse(wire);
    const leaf = try x509.parse(leaf_der);
    const expiry = leaf.not_before.epoch_seconds + @as(i64, dc.valid_time);
    if (now > expiry) return error.Expired;
    if (expiry > now + @as(i64, max_lifetime_seconds)) return error.TooLong;
    if (expiry >= leaf.not_after.epoch_seconds) return error.Outlives;
    var msg_buf: [4096]u8 = undefined;
    const msg = try delegated_credential.writeSignedMessage(&msg_buf, leaf_der, dc.signed_portion);
    const pk_raw = (try x509.extractPublicKey(leaf.spki_der)).ed25519;
    const pk = try Ed25519.PublicKey.fromBytes(pk_raw[0..32].*);
    try Ed25519.Signature.fromBytes(dc.signature[0..64].*).verify(msg, pk);
    return dc;
}

test "dc_mint mints an ed25519-signed P-256 DC that verifies per RFC 9345 4.1.3" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x51)));
    var buf: [1024]u8 = undefined;
    const leaf = try delegationLeaf(&buf, kp, true, true);
    const now = t_not_before + 3600;

    var minted = try mint(testing.allocator, testing.io, .{
        .leaf_der = leaf,
        .leaf_key = .{ .ed25519 = kp },
        .now_unix = now,
        .lifetime_seconds = 24 * 3600,
    });
    defer minted.deinit(testing.allocator);

    try testing.expectEqual(now + 24 * 3600, minted.expiry_unix);
    const dc = try verifyMinted(leaf, minted.wire, now);
    try testing.expectEqual(Scheme.ecdsa_secp256r1_sha256.toInt(), dc.dc_cert_verify_algorithm);
    try testing.expectEqual(Scheme.ed25519.toInt(), dc.algorithm);
    // The embedded SPKI is the delegated key's public key.
    var spki_buf: [max_spki_len]u8 = undefined;
    try testing.expectEqualSlices(u8, dcSpki(&spki_buf, minted.private_key), dc.spki);

    // A flipped signature bit must fail the independent verifier.
    minted.wire[minted.wire.len - 1] ^= 1;
    try testing.expectError(error.SignatureVerificationFailed, verifyMinted(leaf, minted.wire, now));
}

test "dc_mint fails closed without DelegationUsage, digitalSignature, or a matching key" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x52)));
    const other = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x53)));
    var buf: [1024]u8 = undefined;
    const now = t_not_before + 60;

    const no_du = try delegationLeaf(&buf, kp, false, true);
    try testing.expectError(error.DelegationUsageMissing, mint(testing.allocator, testing.io, .{
        .leaf_der = no_du,
        .leaf_key = .{ .ed25519 = kp },
        .now_unix = now,
        .lifetime_seconds = 3600,
    }));

    var buf2: [1024]u8 = undefined;
    const no_ds = try delegationLeaf(&buf2, kp, true, false);
    try testing.expectError(error.DigitalSignatureKeyUsageMissing, mint(testing.allocator, testing.io, .{
        .leaf_der = no_ds,
        .leaf_key = .{ .ed25519 = kp },
        .now_unix = now,
        .lifetime_seconds = 3600,
    }));

    var buf3: [1024]u8 = undefined;
    const good = try delegationLeaf(&buf3, kp, true, true);
    try testing.expectError(error.LeafKeyMismatch, mint(testing.allocator, testing.io, .{
        .leaf_der = good,
        .leaf_key = .{ .ed25519 = other },
        .now_unix = now,
        .lifetime_seconds = 3600,
    }));
    const ec = ecdsa_p256.KeyPair.generate(testing.io);
    try testing.expectError(error.LeafKeyMismatch, mint(testing.allocator, testing.io, .{
        .leaf_der = good,
        .leaf_key = .{ .ecdsa_p256 = ec },
        .now_unix = now,
        .lifetime_seconds = 3600,
    }));
}

test "dc_mint checkLeafKey and checkDcKey compare whole public keys, not only key types" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x58)));
    const other = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x59)));
    var buf: [1024]u8 = undefined;
    const leaf = try delegationLeaf(&buf, kp, true, true);

    try checkLeafKey(leaf, .{ .ed25519 = kp });
    // Same type (Ed25519), different key.
    try testing.expectError(error.LeafKeyMismatch, checkLeafKey(leaf, .{ .ed25519 = other }));
    try testing.expectError(error.LeafKeyMismatch, checkLeafKey(leaf, .{ .ecdsa_p256 = ecdsa_p256.KeyPair.generate(testing.io) }));

    var minted = try mint(testing.allocator, testing.io, .{
        .leaf_der = leaf,
        .leaf_key = .{ .ed25519 = kp },
        .now_unix = t_not_before + 60,
        .lifetime_seconds = 3600,
    });
    defer minted.deinit(testing.allocator);
    try checkDcKey(minted.wire, minted.private_key);
    // Same type (P-256), different key.
    try testing.expectError(error.DcKeyMismatch, checkDcKey(minted.wire, .{ .ecdsa_p256 = ecdsa_p256.KeyPair.generate(testing.io) }));
    try testing.expectError(error.DcKeyMismatch, checkDcKey(minted.wire, .{ .ed25519 = other }));
}

test "dc_mint enforces the seven-day cap and the certificate window" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x54)));
    var buf: [1024]u8 = undefined;
    const leaf = try delegationLeaf(&buf, kp, true, true);
    const base: MintOptions = .{ .leaf_der = leaf, .leaf_key = .{ .ed25519 = kp }, .now_unix = t_not_before + 60, .lifetime_seconds = 3600 };

    var o = base;
    o.lifetime_seconds = 0;
    try testing.expectError(error.InvalidLifetime, mint(testing.allocator, testing.io, o));
    o.lifetime_seconds = max_lifetime_seconds + 1;
    try testing.expectError(error.InvalidLifetime, mint(testing.allocator, testing.io, o));

    o = base;
    o.now_unix = t_not_before - 1;
    try testing.expectError(error.CertificateNotYetValid, mint(testing.allocator, testing.io, o));

    o = base;
    o.now_unix = t_not_after - 3600;
    o.lifetime_seconds = 7200;
    try testing.expectError(error.OutlivesCertificate, mint(testing.allocator, testing.io, o));
    o.clamp_to_certificate = true;
    var clamped = try mint(testing.allocator, testing.io, o);
    defer clamped.deinit(testing.allocator);
    try testing.expectEqual(t_not_after - 1, clamped.expiry_unix);

    // Exactly seven days is allowed.
    var week = base;
    week.lifetime_seconds = max_lifetime_seconds;
    var ok = try mint(testing.allocator, testing.io, week);
    defer ok.deinit(testing.allocator);
    _ = try verifyMinted(leaf, ok.wire, week.now_unix);
}

test "dc_mint ECDSA leaf signs with ecdsa_secp256r1_sha256 and Ed25519 DC keys work" {
    const leaf_kp = ecdsa_p256.KeyPair.generate(testing.io);
    var buf: [2048]u8 = undefined;
    const leaf = try x509_selfsign.buildSelfSignedEcdsaP256(&buf, .{
        .common_name = "dc.example.test",
        .not_before = t_not_before,
        .not_after = t_not_after,
        .serial = &.{0x45},
        .key_pair = leaf_kp,
        .dns_names = &.{"dc.example.test"},
        .delegation_usage = true,
        .key_usage_digital_signature = true,
    });
    var minted = try mint(testing.allocator, testing.io, .{
        .leaf_der = leaf,
        .leaf_key = .{ .ecdsa_p256 = leaf_kp },
        .dc_algorithm = .ed25519,
        .now_unix = t_not_before + 10,
        .lifetime_seconds = 600,
    });
    defer minted.deinit(testing.allocator);
    const dc = try delegated_credential.parse(minted.wire);
    try testing.expectEqual(Scheme.ecdsa_secp256r1_sha256.toInt(), dc.algorithm);
    try testing.expectEqual(Scheme.ed25519.toInt(), dc.dc_cert_verify_algorithm);
    var msg_buf: [4096]u8 = undefined;
    const msg = try delegated_credential.writeSignedMessage(&msg_buf, leaf, dc.signed_portion);
    try testing.expect(ecdsa_p256.verify(try ecdsa_p256.signatureFromDer(dc.signature), msg, leaf_kp.public_key));
    try testing.expect(minted.serverCredential().private_key == .ed25519);
}

test "dc_mint RotationPolicy renews inside the window and clamps at certificate end" {
    const policy: RotationPolicy = .{};
    try policy.validate();
    try testing.expect(policy.due(null, 0));
    try testing.expect(!policy.due(100_000, 100_000 - 13 * 3600));
    try testing.expect(policy.due(100_000, 100_000 - 12 * 3600));
    try testing.expect(policy.due(100_000, 200_000));
    try testing.expectEqual(@as(i64, 100_000 - 12 * 3600), policy.renewAt(100_000));
    try testing.expectError(error.InvalidLifetime, (RotationPolicy{ .lifetime_seconds = 3600, .renew_before_seconds = 3600 }).validate());
    try testing.expectError(error.InvalidLifetime, (RotationPolicy{ .lifetime_seconds = max_lifetime_seconds + 1 }).validate());

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x55)));
    var buf: [1024]u8 = undefined;
    const leaf = try delegationLeaf(&buf, kp, true, true);
    var next = try policy.mintNext(testing.allocator, testing.io, leaf, .{ .ed25519 = kp }, t_not_after - 3600);
    defer next.deinit(testing.allocator);
    try testing.expectEqual(t_not_after - 1, next.expiry_unix);
    _ = try verifyMinted(leaf, next.wire, t_not_after - 3600);
}
