// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const rsa_sign = @import("../crypto/rsa_sign.zig");
const rsa_verify = @import("../crypto/rsa_verify.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

pub const Error = error{
    NoSpaceLeft,
    UnsupportedArchitecture,
    InvalidCommonName,
    CommonNameTooLong,
    InvalidSerial,
    SerialTooLarge,
    InvalidValidity,
    InvalidTime,
    InvalidDnsName,
    InvalidIpAddress,
};

pub const Params = struct {
    common_name: []const u8,
    not_before: i64,
    not_after: i64,
    serial: []const u8,
    key_pair: Ed25519.KeyPair,
    /// SubjectAltName dNSName entries. Standards TLS clients (RFC 6125) ignore
    /// the CN and match the hostname against the SAN, so a server cert MUST
    /// carry at least one. Empty keeps the legacy (extension-less) output.
    dns_names: []const []const u8 = &.{},
    /// SubjectAltName iPAddress entries, encoded as raw IPv4 (4-byte) or IPv6
    /// (16-byte) address octets.
    ip_addresses: []const []const u8 = &.{},
    /// Emit a critical BasicConstraints `cA:TRUE` so the cert can serve as its
    /// own trust anchor (self-signed root). Off by default.
    is_ca: bool = false,
    /// basicConstraints pathLenConstraint (0..=127 supported by this test
    /// builder). Only emitted when `is_ca` and set. Null omits it.
    path_len: ?u8 = null,
    /// Emit an authorityInfoAccess extension with this id-ad-ocsp responder URI.
    /// Empty omits it.
    ocsp_url: []const u8 = &.{},
    /// Emit the id-pe-tlsfeature extension listing status_request(5) — must-staple.
    must_staple: bool = false,
    /// Emit the id-ce-delegationUsage extension (RFC 9345 §4.2) — authorizes this
    /// certificate to sign delegated credentials. Off by default.
    delegation_usage: bool = false,
    /// Emit a critical KeyUsage extension asserting digitalSignature (RFC 5280
    /// §4.2.1.3), required alongside delegationUsage for a delegated-credential leaf.
    /// Off by default.
    key_usage_digital_signature: bool = false,
};

pub const EcdsaP256Params = struct {
    common_name: []const u8,
    not_before: i64,
    not_after: i64,
    serial: []const u8,
    key_pair: ecdsa_p256.KeyPair,
    /// SubjectAltName dNSName entries. Standards TLS clients (RFC 6125) ignore
    /// the CN and match the hostname against the SAN, so a server cert MUST
    /// carry at least one. Empty keeps the legacy (extension-less) output.
    dns_names: []const []const u8 = &.{},
    /// SubjectAltName iPAddress entries, encoded as raw IPv4 (4-byte) or IPv6
    /// (16-byte) address octets.
    ip_addresses: []const []const u8 = &.{},
    /// Emit a critical BasicConstraints `cA:TRUE` so the cert can serve as its
    /// own trust anchor (self-signed root). Off by default.
    is_ca: bool = false,
    /// Emit an ExtendedKeyUsage extension listing id-kp-OCSPSigning — marks the
    /// cert as a delegated OCSP responder (RFC 6960 §4.2.2.2). Off by default.
    eku_ocsp_signing: bool = false,
    /// Emit the id-ce-delegationUsage extension (RFC 9345 §4.2) — authorizes this
    /// cert to sign delegated credentials. Off by default.
    delegation_usage: bool = false,
    /// Emit a critical KeyUsage extension asserting the digitalSignature bit
    /// (RFC 5280 §4.2.1.3) — required alongside delegationUsage for a DC leaf.
    /// Off by default.
    key_usage_digital_signature: bool = false,
};

pub const EcdsaP384Params = struct {
    common_name: []const u8,
    not_before: i64,
    not_after: i64,
    serial: []const u8,
    key_pair: EcdsaP384.KeyPair,
    /// SubjectAltName dNSName entries. Standards TLS clients (RFC 6125) ignore
    /// the CN and match the hostname against the SAN, so a server cert MUST
    /// carry at least one. Empty keeps the legacy (extension-less) output.
    dns_names: []const []const u8 = &.{},
    /// SubjectAltName iPAddress entries, encoded as raw IPv4 (4-byte) or IPv6
    /// (16-byte) address octets.
    ip_addresses: []const []const u8 = &.{},
    /// Emit a critical BasicConstraints `cA:TRUE` so the cert can serve as its
    /// own trust anchor (self-signed root). Off by default.
    is_ca: bool = false,
};

pub const RsaParams = struct {
    common_name: []const u8,
    not_before: i64,
    not_after: i64,
    serial: []const u8,
    /// Big-endian RSA modulus encoded into SubjectPublicKeyInfo.
    public_modulus: []const u8,
    /// Big-endian RSA public exponent encoded into SubjectPublicKeyInfo.
    public_exponent: []const u8,
    /// RSA private key used to self-sign the TBS certificate with
    /// sha256WithRSAEncryption.
    private_key: rsa_sign.PrivateKey,
    /// SubjectAltName dNSName entries. Standards TLS clients (RFC 6125) ignore
    /// the CN and match the hostname against the SAN, so a server cert MUST
    /// carry at least one. Empty keeps the legacy (extension-less) output.
    dns_names: []const []const u8 = &.{},
    /// SubjectAltName iPAddress entries, encoded as raw IPv4 (4-byte) or IPv6
    /// (16-byte) address octets.
    ip_addresses: []const []const u8 = &.{},
    /// Emit a critical BasicConstraints `cA:TRUE` so the cert can serve as its
    /// own trust anchor (self-signed root). Off by default.
    is_ca: bool = false,
    /// Sign with sha384WithRSAEncryption instead of sha256 (for exercising the
    /// SHA-384 RSA cert-verification path). Off by default.
    sig_sha384: bool = false,
    /// Sign with id-RSASSA-PSS (SHA-256 / MGF1-SHA-256 / saltLength 32) instead of
    /// the PKCS#1 v1.5 default, emitting an RSASSA-PSS-params signatureAlgorithm
    /// (for exercising the PSS cert-verification path). Takes precedence over
    /// `sig_sha384`. Off by default.
    sig_pss: bool = false,
};

const tag_integer: u8 = 0x02;
const tag_bit_string: u8 = 0x03;
const tag_null: u8 = 0x05;
const tag_oid: u8 = 0x06;
const tag_utf8_string: u8 = 0x0c;
const tag_sequence: u8 = 0x30;
const tag_set: u8 = 0x31;
const tag_utc_time: u8 = 0x17;
const tag_generalized_time: u8 = 0x18;
const tag_context_0_constructed: u8 = 0xa0;
const tag_context_1_constructed: u8 = 0xa1;
const tag_context_2_constructed: u8 = 0xa2;

const max_common_name_len = 64;
const max_serial_len = 20;
const max_dns_name_len = 253;
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 }; // 1.3.132.0.34
const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ecdsa_sha384 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_sha256_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const oid_sha384_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
const oid_rsassa_pss = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a }; // 1.2.840.113549.1.1.10
const oid_mgf1 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08 }; // 1.2.840.113549.1.1.8
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }; // 2.16.840.1.101.3.4.2.1
/// RSASSA-PSS saltLength minted here: equal to the SHA-256 digest length.
const rsa_pss_salt_len: u8 = 32;
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 }; // 2.5.29.17
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 }; // 2.5.29.19
const oid_extended_key_usage = [_]u8{ 0x55, 0x1d, 0x25 }; // 2.5.29.37
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f }; // 2.5.29.15
const oid_eku_ocsp_signing = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 }; // 1.3.6.1.5.5.7.3.9
const oid_delegation_usage = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2c }; // 1.3.6.1.4.1.44363.44
const oid_authority_info_access = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
const oid_id_ad_ocsp = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 };
const oid_tls_feature = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18 };
const tag_boolean: u8 = 0x01;
const tag_octet_string: u8 = 0x04;
const tag_context_3_constructed: u8 = 0xa3;
const tag_san_dns_name: u8 = 0x82; // GeneralName [2] dNSName (context, primitive)
const tag_san_ip_address: u8 = 0x87; // GeneralName [7] iPAddress (context, primitive)

const SignatureAlgorithm = enum {
    ed25519,
    ecdsa_p256_sha256,
    /// ecdsa-with-SHA384 (P-384 issuer key). Exercises the SHA-384 ECDSA
    /// cert-verification path.
    ecdsa_p384_sha384,
    rsa_sha256,
    rsa_sha384,
    /// id-RSASSA-PSS with SHA-256 / MGF1-SHA-256 / saltLength 32.
    rsa_pss_sha256,
};

const RsaPublicKey = struct {
    modulus: []const u8,
    exponent: []const u8,
};

const SubjectPublicKey = union(enum) {
    ed25519: [Ed25519.PublicKey.encoded_length]u8,
    ecdsa_p256_sec1: [ecdsa_p256.sec1_uncompressed_length]u8,
    ecdsa_p384_sec1: [EcdsaP384.PublicKey.uncompressed_sec1_encoded_length]u8,
    rsa: RsaPublicKey,
};

pub fn buildSelfSigned(out: []u8, params: Params) ![]const u8 {
    if (@bitSizeOf(usize) != 64) return error.UnsupportedArchitecture;
    try validateParams(params);

    var tbs_buf: [1400]u8 = undefined;
    const tbs = try buildTbs(&tbs_buf, params, .ed25519, .{ .ed25519 = params.key_pair.public_key.toBytes() });
    const sig = try Ed25519.KeyPair.sign(params.key_pair, tbs, null);
    const sig_bytes = sig.toBytes();

    var cert_body_buf: [1600]u8 = undefined;
    var cert_body = DerWriter.init(&cert_body_buf);
    try cert_body.write(tbs);
    try writeSignatureAlgorithmIdentifier(&cert_body, .ed25519);
    try writeSignatureBitString(&cert_body, &sig_bytes);

    var cert = DerWriter.init(out);
    try cert.tlv(tag_sequence, cert_body.bytes());
    return cert.bytes();
}

pub fn buildSelfSignedEcdsaP256(out: []u8, params: EcdsaP256Params) ![]const u8 {
    if (@bitSizeOf(usize) != 64) return error.UnsupportedArchitecture;
    try validateParams(params);

    var tbs_buf: [1400]u8 = undefined;
    const public_sec1 = params.key_pair.public_key.toUncompressedSec1();
    const tbs = try buildTbs(&tbs_buf, params, .ecdsa_p256_sha256, .{ .ecdsa_p256_sec1 = public_sec1 });
    const sig = try ecdsa_p256.sign(tbs, params.key_pair);
    var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = try ecdsa_p256.signatureToDer(sig, &sig_der_buf);

    var cert_body_buf: [1600]u8 = undefined;
    var cert_body = DerWriter.init(&cert_body_buf);
    try cert_body.write(tbs);
    try writeSignatureAlgorithmIdentifier(&cert_body, .ecdsa_p256_sha256);
    try writeSignatureBitString(&cert_body, sig_der);

    var cert = DerWriter.init(out);
    try cert.tlv(tag_sequence, cert_body.bytes());
    return cert.bytes();
}

/// Mint a self-signed ECDSA P-384 certificate (ecdsa-with-SHA384). Mirrors
/// `buildSelfSignedEcdsaP256` for the P-384 curve, exercising the SHA-384 ECDSA
/// cert-verification path. `out` receives the DER; the returned slice aliases it.
pub fn buildSelfSignedEcdsaP384(out: []u8, params: EcdsaP384Params) ![]const u8 {
    if (@bitSizeOf(usize) != 64) return error.UnsupportedArchitecture;
    try validateParams(params);

    var tbs_buf: [1400]u8 = undefined;
    const public_sec1 = params.key_pair.public_key.toUncompressedSec1();
    const tbs = try buildTbs(&tbs_buf, params, .ecdsa_p384_sha384, .{ .ecdsa_p384_sec1 = public_sec1 });
    const sig = try params.key_pair.sign(tbs, null);
    var sig_der_buf: [EcdsaP384.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&sig_der_buf);

    var cert_body_buf: [1600]u8 = undefined;
    var cert_body = DerWriter.init(&cert_body_buf);
    try cert_body.write(tbs);
    try writeSignatureAlgorithmIdentifier(&cert_body, .ecdsa_p384_sha384);
    try writeSignatureBitString(&cert_body, sig_der);

    var cert = DerWriter.init(out);
    try cert.tlv(tag_sequence, cert_body.bytes());
    return cert.bytes();
}

/// Like `buildSelfSignedEcdsaP256`, but the TBS is signed by `issuer_key` rather
/// than the subject's own key — an ISSUER-signed leaf. The subject SPKI is still
/// `params.key_pair`'s public key. Used to mint a delegated OCSP responder cert
/// (issuer-signed, `eku_ocsp_signing`) for tests. The subject/issuer Names both
/// read `params.common_name`; delegation authorization checks the issuer's
/// SIGNATURE over this cert (not a Name chain), so that is sufficient here.
pub fn buildEcdsaP256IssuedBy(out: []u8, params: EcdsaP256Params, issuer_key: ecdsa_p256.KeyPair) ![]const u8 {
    if (@bitSizeOf(usize) != 64) return error.UnsupportedArchitecture;
    try validateParams(params);

    var tbs_buf: [1400]u8 = undefined;
    const public_sec1 = params.key_pair.public_key.toUncompressedSec1();
    const tbs = try buildTbs(&tbs_buf, params, .ecdsa_p256_sha256, .{ .ecdsa_p256_sec1 = public_sec1 });
    const sig = try ecdsa_p256.sign(tbs, issuer_key);
    var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = try ecdsa_p256.signatureToDer(sig, &sig_der_buf);

    var cert_body_buf: [1600]u8 = undefined;
    var cert_body = DerWriter.init(&cert_body_buf);
    try cert_body.write(tbs);
    try writeSignatureAlgorithmIdentifier(&cert_body, .ecdsa_p256_sha256);
    try writeSignatureBitString(&cert_body, sig_der);

    var cert = DerWriter.init(out);
    try cert.tlv(tag_sequence, cert_body.bytes());
    return cert.bytes();
}

pub fn buildSelfSignedRsa(out: []u8, params: RsaParams) ![]const u8 {
    if (@bitSizeOf(usize) != 64) return error.UnsupportedArchitecture;
    try validateParams(params);

    const alg: SignatureAlgorithm = if (params.sig_pss)
        .rsa_pss_sha256
    else if (params.sig_sha384)
        .rsa_sha384
    else
        .rsa_sha256;
    var tbs_buf: [2048]u8 = undefined;
    const tbs = try buildTbs(&tbs_buf, params, alg, .{
        .rsa = .{ .modulus = params.public_modulus, .exponent = params.public_exponent },
    });
    var sig_buf: [512]u8 = undefined;
    const sig = switch (alg) {
        .rsa_pss_sha256 => blk: {
            var digest: [32]u8 = undefined;
            Sha256.hash(tbs, &digest, .{});
            // A fixed 32-byte salt keeps the minted cert deterministic; PSS verify
            // recovers the salt from the signature, so the value is immaterial.
            const salt: [rsa_pss_salt_len]u8 = @splat(0xAB);
            break :blk try rsa_sign.signPss(params.private_key, .sha256, &digest, &salt, &sig_buf);
        },
        .rsa_sha384 => blk: {
            var digest: [48]u8 = undefined;
            Sha384.hash(tbs, &digest, .{});
            break :blk try rsa_sign.signPkcs1v15(params.private_key, .sha384, &digest, &sig_buf);
        },
        else => blk: {
            var digest: [32]u8 = undefined;
            Sha256.hash(tbs, &digest, .{});
            break :blk try rsa_sign.signPkcs1v15(params.private_key, .sha256, &digest, &sig_buf);
        },
    };

    var cert_body_buf: [3072]u8 = undefined;
    var cert_body = DerWriter.init(&cert_body_buf);
    try cert_body.write(tbs);
    try writeSignatureAlgorithmIdentifier(&cert_body, alg);
    try writeSignatureBitString(&cert_body, sig);

    var cert = DerWriter.init(out);
    try cert.tlv(tag_sequence, cert_body.bytes());
    return cert.bytes();
}

fn validateParams(params: anytype) Error!void {
    if (params.common_name.len == 0) return error.InvalidCommonName;
    if (params.common_name.len > max_common_name_len) return error.CommonNameTooLong;
    for (params.common_name) |b| {
        if (b < 0x20 or b == 0x7f) return error.InvalidCommonName;
    }
    if (params.serial.len == 0) return error.InvalidSerial;
    if (params.not_after < params.not_before) return error.InvalidValidity;
    for (params.dns_names) |name| {
        if (name.len == 0 or name.len > max_dns_name_len) return error.InvalidDnsName;
        for (name) |b| if (b <= 0x20 or b >= 0x7f) return error.InvalidDnsName;
    }
    for (params.ip_addresses) |ip| {
        if (ip.len != 4 and ip.len != 16) return error.InvalidIpAddress;
    }
}

fn buildTbs(out: []u8, params: anytype, signature_algorithm: SignatureAlgorithm, public_key: SubjectPublicKey) ![]const u8 {
    var body_buf: [2048]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try writeVersion(&body);
    try writeSerial(&body, params.serial);
    try writeSignatureAlgorithmIdentifier(&body, signature_algorithm);
    try writeName(&body, params.common_name);
    try writeValidity(&body, params.not_before, params.not_after);
    try writeName(&body, params.common_name);
    try writeSubjectPublicKeyInfo(&body, public_key);
    var want_ext = params.dns_names.len != 0 or params.ip_addresses.len != 0 or params.is_ca;
    if (comptime @hasField(@TypeOf(params), "eku_ocsp_signing")) {
        if (params.eku_ocsp_signing) want_ext = true;
    }
    if (comptime @hasField(@TypeOf(params), "delegation_usage")) {
        if (params.delegation_usage) want_ext = true;
    }
    if (comptime @hasField(@TypeOf(params), "key_usage_digital_signature")) {
        if (params.key_usage_digital_signature) want_ext = true;
    }
    if (want_ext) try writeExtensions(&body, params);

    var tbs = DerWriter.init(out);
    try tbs.tlv(tag_sequence, body.bytes());
    return tbs.bytes();
}

/// `[3] EXPLICIT SEQUENCE OF Extension` carrying SubjectAltName (dNSNames) and,
/// optionally, a critical BasicConstraints cA:TRUE.
fn writeExtensions(w: *DerWriter, params: anytype) !void {
    var seq_buf: [768]u8 = undefined;
    var seq = DerWriter.init(&seq_buf);

    if (params.is_ca) {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN } -> octet-string -> ext.
        var bc_buf: [8]u8 = undefined;
        var bc = DerWriter.init(&bc_buf);
        try bc.tlv(tag_boolean, &.{0xff});
        // pathLenConstraint INTEGER (small values only; positive so no sign byte).
        if (comptime @hasField(@TypeOf(params), "path_len")) {
            if (params.path_len) |pl| try bc.tlv(tag_integer, &[_]u8{pl & 0x7f});
        }
        var bc_seq_buf: [12]u8 = undefined;
        var bc_seq = DerWriter.init(&bc_seq_buf);
        try bc_seq.tlv(tag_sequence, bc.bytes());
        try writeExtension(&seq, &oid_basic_constraints, true, bc_seq.bytes());
    }

    if (params.dns_names.len != 0 or params.ip_addresses.len != 0) {
        var names_buf: [600]u8 = undefined;
        var names = DerWriter.init(&names_buf);
        for (params.dns_names) |name| try names.tlv(tag_san_dns_name, name);
        for (params.ip_addresses) |ip| try names.tlv(tag_san_ip_address, ip);
        var san_buf: [620]u8 = undefined;
        var san = DerWriter.init(&san_buf);
        try san.tlv(tag_sequence, names.bytes());
        try writeExtension(&seq, &oid_subject_alt_name, false, san.bytes());
    }

    if (comptime @hasField(@TypeOf(params), "ocsp_url")) {
        if (params.ocsp_url.len != 0) {
            // AIA ::= SEQUENCE OF AccessDescription{ OID id-ad-ocsp, [6] URI }.
            var ad_buf: [320]u8 = undefined;
            var ad = DerWriter.init(&ad_buf);
            try ad.tlv(tag_oid, &oid_id_ad_ocsp);
            try ad.tlv(0x86, params.ocsp_url); // [6] uniformResourceIdentifier
            var ad_seq_buf: [340]u8 = undefined;
            var ad_seq = DerWriter.init(&ad_seq_buf);
            try ad_seq.tlv(tag_sequence, ad.bytes());
            var aia_buf: [360]u8 = undefined;
            var aia = DerWriter.init(&aia_buf);
            try aia.tlv(tag_sequence, ad_seq.bytes());
            try writeExtension(&seq, &oid_authority_info_access, false, aia.bytes());
        }
    }

    if (comptime @hasField(@TypeOf(params), "eku_ocsp_signing")) {
        if (params.eku_ocsp_signing) {
            // ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId { id-kp-OCSPSigning }.
            var eku_buf: [16]u8 = undefined;
            var eku = DerWriter.init(&eku_buf);
            try eku.tlv(tag_oid, &oid_eku_ocsp_signing);
            var eku_seq_buf: [20]u8 = undefined;
            var eku_seq = DerWriter.init(&eku_seq_buf);
            try eku_seq.tlv(tag_sequence, eku.bytes());
            try writeExtension(&seq, &oid_extended_key_usage, false, eku_seq.bytes());
        }
    }

    if (comptime @hasField(@TypeOf(params), "key_usage_digital_signature")) {
        if (params.key_usage_digital_signature) {
            // KeyUsage ::= BIT STRING; digitalSignature is bit 0 (0x80 in the
            // first content byte, 7 unused bits). Marked critical per RFC 5280.
            var ku_buf: [8]u8 = undefined;
            var ku = DerWriter.init(&ku_buf);
            try ku.tlv(tag_bit_string, &[_]u8{ 0x07, 0x80 });
            try writeExtension(&seq, &oid_key_usage, true, ku.bytes());
        }
    }

    if (comptime @hasField(@TypeOf(params), "delegation_usage")) {
        if (params.delegation_usage) {
            // DelegationUsage ::= NULL (RFC 9345 §4.2); non-critical.
            var du_buf: [4]u8 = undefined;
            var du = DerWriter.init(&du_buf);
            try du.tlv(tag_null, &.{});
            try writeExtension(&seq, &oid_delegation_usage, false, du.bytes());
        }
    }

    if (comptime @hasField(@TypeOf(params), "must_staple")) {
        if (params.must_staple) {
            // TLS Feature ::= SEQUENCE { INTEGER 5 (status_request) }.
            var feat_buf: [8]u8 = undefined;
            var feat = DerWriter.init(&feat_buf);
            try feat.tlv(tag_integer, &.{0x05});
            var tf_buf: [12]u8 = undefined;
            var tf = DerWriter.init(&tf_buf);
            try tf.tlv(tag_sequence, feat.bytes());
            try writeExtension(&seq, &oid_tls_feature, false, tf.bytes());
        }
    }

    var explicit_buf: [768]u8 = undefined;
    var explicit = DerWriter.init(&explicit_buf);
    try explicit.tlv(tag_sequence, seq.bytes());
    try w.tlv(tag_context_3_constructed, explicit.bytes());
}

/// One `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL,
/// extnValue OCTET STRING }`. `der` is the already-encoded extension value.
fn writeExtension(w: *DerWriter, oid: []const u8, critical: bool, der: []const u8) !void {
    var ext_buf: [700]u8 = undefined;
    var ext = DerWriter.init(&ext_buf);
    try ext.tlv(tag_oid, oid);
    if (critical) try ext.tlv(tag_boolean, &.{0xff});
    try ext.tlv(tag_octet_string, der);
    try w.tlv(tag_sequence, ext.bytes());
}

fn writeVersion(w: *DerWriter) !void {
    var inner_buf: [3]u8 = undefined;
    var inner = DerWriter.init(&inner_buf);
    try inner.tlv(tag_integer, &.{0x02});
    try w.tlv(tag_context_0_constructed, inner.bytes());
}

fn writeSerial(w: *DerWriter, serial: []const u8) !void {
    var start: usize = 0;
    while (start < serial.len and serial[start] == 0) : (start += 1) {}
    if (start == serial.len) return error.InvalidSerial;
    const trimmed = serial[start..];
    if (trimmed.len > max_serial_len) return error.SerialTooLarge;

    var buf: [max_serial_len + 1]u8 = undefined;
    var len = trimmed.len;
    if ((trimmed[0] & 0x80) != 0) {
        buf[0] = 0;
        @memcpy(buf[1 .. 1 + trimmed.len], trimmed);
        len += 1;
    } else {
        @memcpy(buf[0..trimmed.len], trimmed);
    }
    try w.tlv(tag_integer, buf[0..len]);
}

fn writeSignatureAlgorithmIdentifier(w: *DerWriter, algorithm: SignatureAlgorithm) !void {
    // Large enough for the widest case: id-RSASSA-PSS OID + RSASSA-PSS-params.
    var body_buf: [96]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    switch (algorithm) {
        .ed25519 => try body.tlv(tag_oid, &oid_ed25519),
        .ecdsa_p256_sha256 => try body.tlv(tag_oid, &oid_ecdsa_sha256),
        .ecdsa_p384_sha384 => try body.tlv(tag_oid, &oid_ecdsa_sha384),
        .rsa_sha256 => {
            try body.tlv(tag_oid, &oid_sha256_rsa);
            try body.tlv(tag_null, "");
        },
        .rsa_sha384 => {
            try body.tlv(tag_oid, &oid_sha384_rsa);
            try body.tlv(tag_null, "");
        },
        .rsa_pss_sha256 => {
            try body.tlv(tag_oid, &oid_rsassa_pss);
            try writeRsaPssSha256Params(&body);
        },
    }
    try w.tlv(tag_sequence, body.bytes());
}

/// Append the RSASSA-PSS-params SEQUENCE (SHA-256 / MGF1-SHA-256 / saltLength 32,
/// trailerField defaulted) that follows id-RSASSA-PSS in the signatureAlgorithm
/// (RFC 4055 §3.1). The hash AlgorithmIdentifiers omit the optional NULL, which
/// the verifier accepts.
fn writeRsaPssSha256Params(w: *DerWriter) !void {
    // SHA-256 AlgorithmIdentifier: SEQUENCE { OID id-sha256 }.
    var sha_alg_buf: [16]u8 = undefined;
    var sha_alg = DerWriter.init(&sha_alg_buf);
    {
        var oid_buf: [12]u8 = undefined;
        var oid_w = DerWriter.init(&oid_buf);
        try oid_w.tlv(tag_oid, &oid_sha256);
        try sha_alg.tlv(tag_sequence, oid_w.bytes());
    }

    var params_buf: [96]u8 = undefined;
    var params = DerWriter.init(&params_buf);
    // hashAlgorithm [0] EXPLICIT AlgorithmIdentifier.
    try params.tlv(tag_context_0_constructed, sha_alg.bytes());
    // maskGenAlgorithm [1] EXPLICIT { OID id-mgf1, <SHA-256 AlgorithmIdentifier> }.
    var mgf_buf: [48]u8 = undefined;
    var mgf = DerWriter.init(&mgf_buf);
    try mgf.tlv(tag_oid, &oid_mgf1);
    try mgf.write(sha_alg.bytes());
    var mgf_alg_buf: [48]u8 = undefined;
    var mgf_alg = DerWriter.init(&mgf_alg_buf);
    try mgf_alg.tlv(tag_sequence, mgf.bytes());
    try params.tlv(tag_context_1_constructed, mgf_alg.bytes());
    // saltLength [2] EXPLICIT INTEGER 32.
    var salt_buf: [8]u8 = undefined;
    var salt_w = DerWriter.init(&salt_buf);
    try salt_w.tlv(tag_integer, &[_]u8{rsa_pss_salt_len});
    try params.tlv(tag_context_2_constructed, salt_w.bytes());

    try w.tlv(tag_sequence, params.bytes());
}

fn writeRsaPublicKeyAlgorithmIdentifier(w: *DerWriter) !void {
    var body_buf: [16]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try body.tlv(tag_oid, &oid_rsa_encryption);
    try body.tlv(tag_null, "");
    try w.tlv(tag_sequence, body.bytes());
}

fn writeEcPublicKeyAlgorithmIdentifier(w: *DerWriter) !void {
    var body_buf: [24]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try body.tlv(tag_oid, &oid_ec_public_key);
    try body.tlv(tag_oid, &oid_prime256v1);
    try w.tlv(tag_sequence, body.bytes());
}

fn writeEcP384PublicKeyAlgorithmIdentifier(w: *DerWriter) !void {
    var body_buf: [24]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try body.tlv(tag_oid, &oid_ec_public_key);
    try body.tlv(tag_oid, &oid_secp384r1);
    try w.tlv(tag_sequence, body.bytes());
}

fn writeName(w: *DerWriter, common_name: []const u8) !void {
    var attr_body_buf: [80]u8 = undefined;
    var attr_body = DerWriter.init(&attr_body_buf);
    try attr_body.tlv(tag_oid, &oid_common_name);
    try attr_body.tlv(tag_utf8_string, common_name);

    var attr_buf: [96]u8 = undefined;
    var attr = DerWriter.init(&attr_buf);
    try attr.tlv(tag_sequence, attr_body.bytes());

    var rdn_buf: [112]u8 = undefined;
    var rdn = DerWriter.init(&rdn_buf);
    try rdn.tlv(tag_set, attr.bytes());

    try w.tlv(tag_sequence, rdn.bytes());
}

fn writeValidity(w: *DerWriter, not_before: i64, not_after: i64) !void {
    var before_buf: [15]u8 = undefined;
    var after_buf: [15]u8 = undefined;
    const before = try formatAsn1Time(&before_buf, not_before);
    const after = try formatAsn1Time(&after_buf, not_after);

    var body_buf: [36]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try body.tlv(before.tag, before_buf[0..before.len]);
    try body.tlv(after.tag, after_buf[0..after.len]);
    try w.tlv(tag_sequence, body.bytes());
}

fn writeSubjectPublicKeyInfo(w: *DerWriter, public_key: SubjectPublicKey) !void {
    var body_buf: [768]u8 = undefined;
    var body = DerWriter.init(&body_buf);

    switch (public_key) {
        .ed25519 => |key| {
            try writeSignatureAlgorithmIdentifier(&body, .ed25519);
            var bit_string: [1 + Ed25519.PublicKey.encoded_length]u8 = undefined;
            bit_string[0] = 0;
            @memcpy(bit_string[1..], &key);
            try body.tlv(tag_bit_string, &bit_string);
        },
        .ecdsa_p256_sec1 => |sec1| {
            try writeEcPublicKeyAlgorithmIdentifier(&body);
            var bit_string: [1 + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
            bit_string[0] = 0;
            @memcpy(bit_string[1..], &sec1);
            try body.tlv(tag_bit_string, &bit_string);
        },
        .ecdsa_p384_sec1 => |sec1| {
            try writeEcP384PublicKeyAlgorithmIdentifier(&body);
            var bit_string: [1 + EcdsaP384.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined;
            bit_string[0] = 0;
            @memcpy(bit_string[1..], &sec1);
            try body.tlv(tag_bit_string, &bit_string);
        },
        .rsa => |key| {
            try writeRsaPublicKeyAlgorithmIdentifier(&body);
            var rsa_body_buf: [640]u8 = undefined;
            var rsa_body = DerWriter.init(&rsa_body_buf);
            try writePositiveInteger(&rsa_body, key.modulus);
            try writePositiveInteger(&rsa_body, key.exponent);
            var rsa_seq_buf: [672]u8 = undefined;
            var rsa_seq = DerWriter.init(&rsa_seq_buf);
            try rsa_seq.tlv(tag_sequence, rsa_body.bytes());
            var bit_string: [1 + 672]u8 = undefined;
            if (rsa_seq.bytes().len > bit_string.len - 1) return error.NoSpaceLeft;
            bit_string[0] = 0;
            @memcpy(bit_string[1..][0..rsa_seq.bytes().len], rsa_seq.bytes());
            try body.tlv(tag_bit_string, bit_string[0 .. 1 + rsa_seq.bytes().len]);
        },
    }
    try w.tlv(tag_sequence, body.bytes());
}

fn writeSignatureBitString(w: *DerWriter, signature: []const u8) !void {
    var bit_string: [1 + 512]u8 = undefined;
    if (signature.len > bit_string.len - 1) return error.NoSpaceLeft;
    bit_string[0] = 0;
    @memcpy(bit_string[1..][0..signature.len], signature);
    try w.tlv(tag_bit_string, bit_string[0 .. 1 + signature.len]);
}

fn writePositiveInteger(w: *DerWriter, bytes: []const u8) !void {
    var start: usize = 0;
    while (start < bytes.len and bytes[start] == 0) : (start += 1) {}
    if (start == bytes.len) return error.InvalidSerial;
    const trimmed = bytes[start..];
    var buf: [513]u8 = undefined;
    if (trimmed.len > buf.len - 1) return error.NoSpaceLeft;
    if ((trimmed[0] & 0x80) != 0) {
        buf[0] = 0;
        @memcpy(buf[1..][0..trimmed.len], trimmed);
        try w.tlv(tag_integer, buf[0 .. 1 + trimmed.len]);
    } else {
        @memcpy(buf[0..trimmed.len], trimmed);
        try w.tlv(tag_integer, buf[0..trimmed.len]);
    }
}

const Asn1Time = struct {
    tag: u8,
    len: usize,
};

fn formatAsn1Time(out: *[15]u8, unix_seconds: i64) Error!Asn1Time {
    const seconds_per_day: i64 = 86_400;
    const days = @divFloor(unix_seconds, seconds_per_day);
    const sod_i64 = @mod(unix_seconds, seconds_per_day);
    const date = civilFromDays(days);
    if (date.year < 1 or date.year > 9999) return error.InvalidTime;

    const hour = @divTrunc(sod_i64, 3600);
    const minute = @divTrunc(sod_i64 - hour * 3600, 60);
    const second = sod_i64 - hour * 3600 - minute * 60;

    if (date.year >= 1950 and date.year <= 2049) {
        write2(out[0..2], @intCast(@mod(date.year, 100)));
        write2(out[2..4], @intCast(date.month));
        write2(out[4..6], @intCast(date.day));
        write2(out[6..8], @intCast(hour));
        write2(out[8..10], @intCast(minute));
        write2(out[10..12], @intCast(second));
        out[12] = 'Z';
        return .{ .tag = tag_utc_time, .len = 13 };
    }

    write4(out[0..4], @intCast(date.year));
    write2(out[4..6], @intCast(date.month));
    write2(out[6..8], @intCast(date.day));
    write2(out[8..10], @intCast(hour));
    write2(out[10..12], @intCast(minute));
    write2(out[12..14], @intCast(second));
    out[14] = 'Z';
    return .{ .tag = tag_generalized_time, .len = 15 };
}

const Date = struct {
    year: i64,
    month: i64,
    day: i64,
};

fn civilFromDays(days_since_epoch: i64) Date {
    const z = days_since_epoch + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097;
    const yoe = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36_524) - @divTrunc(doe, 146_096), 365);
    var year = yoe + era * 400;
    const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp = @divTrunc(5 * doy + 2, 153);
    const day = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const month = mp + if (mp < 10) @as(i64, 3) else -9;
    if (month <= 2) year += 1;
    return .{ .year = year, .month = month, .day = day };
}

fn write2(out: []u8, value: u8) void {
    out[0] = '0' + value / 10;
    out[1] = '0' + value % 10;
}

fn write4(out: []u8, value: u16) void {
    out[0] = '0' + @as(u8, @intCast(value / 1000));
    out[1] = '0' + @as(u8, @intCast(value / 100 % 10));
    out[2] = '0' + @as(u8, @intCast(value / 10 % 10));
    out[3] = '0' + @as(u8, @intCast(value % 10));
}

const DerWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn init(buf: []u8) DerWriter {
        return .{ .buf = buf };
    }

    fn bytes(self: *const DerWriter) []const u8 {
        return self.buf[0..self.pos];
    }

    fn write(self: *DerWriter, bytes_in: []const u8) !void {
        if (self.buf.len - self.pos < bytes_in.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos .. self.pos + bytes_in.len], bytes_in);
        self.pos += bytes_in.len;
    }

    fn tlv(self: *DerWriter, tag: u8, value: []const u8) !void {
        if (self.buf.len - self.pos < 1) return error.NoSpaceLeft;
        self.buf[self.pos] = tag;
        self.pos += 1;
        try self.length(value.len);
        try self.write(value);
    }

    fn length(self: *DerWriter, len: usize) !void {
        if (len < 128) {
            if (self.buf.len - self.pos < 1) return error.NoSpaceLeft;
            self.buf[self.pos] = @intCast(len);
            self.pos += 1;
            return;
        }
        var tmp: [@sizeOf(usize)]u8 = undefined;
        var n = len;
        var count: usize = 0;
        while (n != 0) : (n >>= 8) {
            tmp[tmp.len - 1 - count] = @intCast(n & 0xff);
            count += 1;
        }
        if (self.buf.len - self.pos < 1 + count) return error.NoSpaceLeft;
        self.buf[self.pos] = 0x80 | @as(u8, @intCast(count));
        self.pos += 1;
        try self.write(tmp[tmp.len - count ..]);
    }
};

const testing = std.testing;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const Tlv = struct {
    tag: u8,
    value: []const u8,
    full: []const u8,
};

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

fn testParams() !Params {
    return .{
        .common_name = "example.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x7f, 0x01 },
        .key_pair = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x42))),
    };
}

test "buildSelfSigned returns a self-signed DER certificate with matching issuer subject and signature" {
    // Arrange
    const params = try testParams();
    var out: [512]u8 = undefined;

    // Act
    const der = try buildSelfSigned(&out, params);

    // Assert
    var cert_cursor: usize = 0;
    const cert = try readTlv(der, &cert_cursor);
    try testing.expectEqual(tag_sequence, cert.tag);
    try testing.expectEqual(der.len, cert_cursor);

    var body_cursor: usize = 0;
    const tbs = try readTlv(cert.value, &body_cursor);
    const sig_alg = try readTlv(cert.value, &body_cursor);
    const sig_bits = try readTlv(cert.value, &body_cursor);
    try testing.expectEqual(cert.value.len, body_cursor);
    try testing.expectEqual(tag_sequence, tbs.tag);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x03, 0x2b, 0x65, 0x70 }, sig_alg.value);
    try testing.expectEqual(tag_bit_string, sig_bits.tag);
    try testing.expectEqual(@as(u8, 0), sig_bits.value[0]);

    var tbs_cursor: usize = 0;
    _ = try readTlv(tbs.value, &tbs_cursor);
    _ = try readTlv(tbs.value, &tbs_cursor);
    _ = try readTlv(tbs.value, &tbs_cursor);
    const issuer = try readTlv(tbs.value, &tbs_cursor);
    _ = try readTlv(tbs.value, &tbs_cursor);
    const subject = try readTlv(tbs.value, &tbs_cursor);
    try testing.expectEqualSlices(u8, issuer.full, subject.full);

    const signature = Ed25519.Signature.fromBytes(sig_bits.value[1..][0..Ed25519.Signature.encoded_length].*);
    try signature.verify(tbs.full, params.key_pair.public_key);
}

test "buildSelfSigned encodes UTCTime and GeneralizedTime boundaries" {
    // Arrange
    var params = try testParams();
    params.not_before = -631_152_000;
    params.not_after = 2_524_608_000;
    var out: [512]u8 = undefined;

    // Act
    const der = try buildSelfSigned(&out, params);

    // Assert
    var cursor: usize = 0;
    const cert = try readTlv(der, &cursor);
    cursor = 0;
    const tbs = try readTlv(cert.value, &cursor);
    cursor = 0;
    _ = try readTlv(tbs.value, &cursor);
    _ = try readTlv(tbs.value, &cursor);
    _ = try readTlv(tbs.value, &cursor);
    _ = try readTlv(tbs.value, &cursor);
    const validity = try readTlv(tbs.value, &cursor);
    cursor = 0;
    const before = try readTlv(validity.value, &cursor);
    const after = try readTlv(validity.value, &cursor);
    try testing.expectEqual(tag_utc_time, before.tag);
    try testing.expectEqualSlices(u8, "500101000000Z", before.value);
    try testing.expectEqual(tag_generalized_time, after.tag);
    try testing.expectEqualSlices(u8, "20500101000000Z", after.value);
}

test "buildSelfSigned reports truncation and oversized inputs with typed errors" {
    // Arrange
    var params = try testParams();
    var out: [512]u8 = undefined;
    const full = try buildSelfSigned(&out, params);
    var small: [1]u8 = undefined;

    // Act and assert
    try testing.expectError(error.NoSpaceLeft, buildSelfSigned(&small, params));
    var cursor: usize = 0;
    try testing.expectError(error.Truncated, readTlv(full[0 .. full.len - 1], &cursor));

    params.serial = &(@as([21]u8, @splat(0x01)));
    try testing.expectError(error.SerialTooLarge, buildSelfSigned(&out, params));

    params.serial = &.{0};
    try testing.expectError(error.InvalidSerial, buildSelfSigned(&out, params));

    params.serial = &.{1};
    params.common_name = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm";
    try testing.expectError(error.CommonNameTooLong, buildSelfSigned(&out, params));
}

test "buildSelfSigned emits SAN dnsNames + CA basic-constraints parseable by x509" {
    const x509 = @import("../crypto/x509.zig");
    var params = try testParams();
    params.dns_names = &.{ "irc.example.test", "example.test" };
    params.is_ca = true;
    var out: [1024]u8 = undefined;
    const der = try buildSelfSigned(&out, params);

    const cert = try x509.parse(der);
    try testing.expect(cert.basic_constraints_ca);
    try testing.expectEqual(@as(usize, 2), cert.san_dns_count);
    try testing.expectEqualStrings("irc.example.test", cert.san_dns[0]);
    try testing.expectEqualStrings("example.test", cert.san_dns[1]);

    // The TBS signature must still verify after adding the v3 extensions block.
    var cursor: usize = 0;
    const outer = try readTlv(der, &cursor);
    var body_cursor: usize = 0;
    const tbs = try readTlv(outer.value, &body_cursor);
    _ = try readTlv(outer.value, &body_cursor);
    const sig_bits = try readTlv(outer.value, &body_cursor);
    const signature = Ed25519.Signature.fromBytes(sig_bits.value[1..][0..Ed25519.Signature.encoded_length].*);
    try signature.verify(tbs.full, params.key_pair.public_key);
}

test "basicConstraints pathLenConstraint round-trips through x509 parse" {
    const x509 = @import("../crypto/x509.zig");
    var out: [1024]u8 = undefined;

    // CA with pathLen:2 -> parsed field is 2.
    var p2 = try testParams();
    p2.is_ca = true;
    p2.path_len = 2;
    const cert2 = try x509.parse(try buildSelfSigned(&out, p2));
    try testing.expect(cert2.basic_constraints_ca);
    try testing.expectEqual(@as(?u32, 2), cert2.basic_constraints_path_len);

    // CA with pathLen:0 -> parsed field is 0 (distinct from absent/null).
    var p0 = try testParams();
    p0.is_ca = true;
    p0.path_len = 0;
    const cert0 = try x509.parse(try buildSelfSigned(&out, p0));
    try testing.expectEqual(@as(?u32, 0), cert0.basic_constraints_path_len);

    // CA without an explicit pathLen -> null (no constraint).
    var pnone = try testParams();
    pnone.is_ca = true;
    const certn = try x509.parse(try buildSelfSigned(&out, pnone));
    try testing.expect(certn.basic_constraints_ca);
    try testing.expectEqual(@as(?u32, null), certn.basic_constraints_path_len);
}

test "x509 exposes subject_der + raw subject_public_key (OCSP CertID inputs)" {
    const x509 = @import("../crypto/x509.zig");
    var params = try testParams();
    params.dns_names = &.{"ocsp.test"};
    var out: [1024]u8 = undefined;
    const cert = try x509.parse(try buildSelfSigned(&out, params));

    // subject_der is the subject Name TLV — a DER SEQUENCE.
    try testing.expect(cert.subject_der.len > 2);
    try testing.expectEqual(@as(u8, 0x30), cert.subject_der[0]);

    // For an Ed25519 cert the raw subjectPublicKey (BIT STRING value minus the
    // unused-bits octet) is exactly the 32-byte public key.
    try testing.expectEqualSlices(u8, &params.key_pair.public_key.toBytes(), cert.subject_public_key);
}

test "x509 extracts AIA OCSP responder URL + must-staple flag" {
    const x509 = @import("../crypto/x509.zig");
    var out: [1024]u8 = undefined;

    var params = try testParams();
    params.dns_names = &.{"aia.test"};
    params.ocsp_url = "http://ocsp.example.test/";
    params.must_staple = true;
    const cert = try x509.parse(try buildSelfSigned(&out, params));
    try testing.expectEqualStrings("http://ocsp.example.test/", cert.aia_ocsp_url);
    try testing.expect(cert.must_staple);

    // Absent by default (no AIA / no TLS-feature extension).
    var plain = try testParams();
    plain.dns_names = &.{"plain.test"};
    const c2 = try x509.parse(try buildSelfSigned(&out, plain));
    try testing.expectEqual(@as(usize, 0), c2.aia_ocsp_url.len);
    try testing.expect(!c2.must_staple);
}

test "buildSelfSignedEcdsaP256 emits P-256 SPKI and ECDSA-SHA256 signature" {
    const x509 = @import("../crypto/x509.zig");
    const kp = ecdsa_p256.KeyPair.generate(testing.io);
    var out: [1024]u8 = undefined;
    const der = try buildSelfSignedEcdsaP256(&out, .{
        .common_name = "ecdsa.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x55, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"ecdsa.test"},
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });

    const parsed = try x509.parse(der);
    try testing.expect(parsed.basic_constraints_ca);
    try testing.expectEqual(@as(usize, 1), parsed.san_dns_count);
    try testing.expectEqualStrings("ecdsa.test", parsed.san_dns[0]);
    try testing.expectEqual(@as(usize, 1), parsed.san_ip_count);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, parsed.san_ips[0].slice());
    try testing.expectEqualSlices(u8, &oid_ecdsa_sha256, parsed.signature_algorithm_oid);

    var cursor: usize = 0;
    const outer = try readTlv(der, &cursor);
    var body_cursor: usize = 0;
    const tbs = try readTlv(outer.value, &body_cursor);
    const sig_alg = try readTlv(outer.value, &body_cursor);
    const sig_bits = try readTlv(outer.value, &body_cursor);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }, sig_alg.value);
    try testing.expectEqual(@as(u8, 0), sig_bits.value[0]);
    const signature = try ecdsa_p256.signatureFromDer(sig_bits.value[1..]);
    try testing.expect(ecdsa_p256.verify(signature, tbs.full, kp.public_key));

    cursor = 0;
    _ = try readTlv(tbs.value, &cursor); // version
    _ = try readTlv(tbs.value, &cursor); // serial
    _ = try readTlv(tbs.value, &cursor); // signature
    _ = try readTlv(tbs.value, &cursor); // issuer
    _ = try readTlv(tbs.value, &cursor); // validity
    _ = try readTlv(tbs.value, &cursor); // subject
    const spki = try readTlv(tbs.value, &cursor);
    cursor = 0;
    const spki_alg = try readTlv(spki.value, &cursor);
    const spki_bits = try readTlv(spki.value, &cursor);
    cursor = 0;
    const ec_oid = try readTlv(spki_alg.value, &cursor);
    const curve_oid = try readTlv(spki_alg.value, &cursor);
    try testing.expectEqualSlices(u8, &oid_ec_public_key, ec_oid.value);
    try testing.expectEqualSlices(u8, &oid_prime256v1, curve_oid.value);
    const sec1 = kp.public_key.toUncompressedSec1();
    try testing.expectEqualSlices(u8, &sec1, spki_bits.value[1..]);
}

test "buildSelfSignedRsa emits rsaEncryption SPKI and sha256WithRSAEncryption signature" {
    const rsa_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
    const rsa_e = hexToBytes("010001");
    const rsa_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
    const rsa_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
    const rsa_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
    const rsa_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
    const rsa_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
    const rsa_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");
    const priv = rsa_sign.PrivateKey{ .n = &rsa_n, .e = &rsa_e, .d = &rsa_d, .p = &rsa_p, .q = &rsa_q, .dp = &rsa_dp, .dq = &rsa_dq, .qinv = &rsa_qinv };
    var out: [2048]u8 = undefined;
    const der = try buildSelfSignedRsa(&out, .{
        .common_name = "rsa.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x52, 0x01 },
        .public_modulus = &rsa_n,
        .public_exponent = &rsa_e,
        .private_key = priv,
        .dns_names = &.{"rsa.test"},
        .is_ca = true,
    });

    var cursor: usize = 0;
    const outer = try readTlv(der, &cursor);
    var body_cursor: usize = 0;
    const tbs = try readTlv(outer.value, &body_cursor);
    const sig_alg = try readTlv(outer.value, &body_cursor);
    const sig_bits = try readTlv(outer.value, &body_cursor);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 }, sig_alg.value);
    try testing.expectEqual(@as(u8, 0), sig_bits.value[0]);

    cursor = 0;
    _ = try readTlv(tbs.value, &cursor); // version
    _ = try readTlv(tbs.value, &cursor); // serial
    _ = try readTlv(tbs.value, &cursor); // signature
    _ = try readTlv(tbs.value, &cursor); // issuer
    _ = try readTlv(tbs.value, &cursor); // validity
    _ = try readTlv(tbs.value, &cursor); // subject
    const spki = try readTlv(tbs.value, &cursor);
    cursor = 0;
    const spki_alg = try readTlv(spki.value, &cursor);
    const spki_bits = try readTlv(spki.value, &cursor);
    cursor = 0;
    const rsa_oid = try readTlv(spki_alg.value, &cursor);
    const null_params = try readTlv(spki_alg.value, &cursor);
    try testing.expectEqualSlices(u8, &oid_rsa_encryption, rsa_oid.value);
    try testing.expectEqual(tag_null, null_params.tag);

    cursor = 0;
    const rsa_seq = try readTlv(spki_bits.value[1..], &cursor);
    cursor = 0;
    const n = try readTlv(rsa_seq.value, &cursor);
    const e = try readTlv(rsa_seq.value, &cursor);
    try testing.expectEqualSlices(u8, &rsa_n, n.value[1..]);
    try testing.expectEqualSlices(u8, &rsa_e, e.value);

    var digest: [32]u8 = undefined;
    Sha256.hash(tbs.full, &digest, .{});
    try testing.expect(rsa_verify.verifyPkcs1v15(.{ .n = &rsa_n, .e = &rsa_e }, .sha256, &digest, sig_bits.value[1..]));
}

test "buildSelfSignedRsa with sig_sha384 emits sha384WithRSA + verifies under SHA-384" {
    const x509 = @import("../crypto/x509.zig");
    const rsa_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
    const rsa_e = hexToBytes("010001");
    const rsa_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
    const rsa_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
    const rsa_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
    const rsa_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
    const rsa_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
    const rsa_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");
    const priv = rsa_sign.PrivateKey{ .n = &rsa_n, .e = &rsa_e, .d = &rsa_d, .p = &rsa_p, .q = &rsa_q, .dp = &rsa_dp, .dq = &rsa_dq, .qinv = &rsa_qinv };
    var out: [2048]u8 = undefined;
    const der = try buildSelfSignedRsa(&out, .{
        .common_name = "rsa384.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x52, 0x02 },
        .public_modulus = &rsa_n,
        .public_exponent = &rsa_e,
        .private_key = priv,
        .dns_names = &.{"rsa384.test"},
        .sig_sha384 = true,
    });

    // The parsed cert advertises sha384WithRSAEncryption.
    const cert = try x509.parse(der);
    try testing.expectEqualSlices(u8, &oid_sha384_rsa, cert.signature_algorithm_oid);

    // The self-signature verifies under SHA-384 — the exact path the tls_client
    // cert validator's sha384WithRSA branch drives.
    var cursor: usize = 0;
    const outer = try readTlv(der, &cursor);
    var body_cursor: usize = 0;
    const tbs = try readTlv(outer.value, &body_cursor);
    _ = try readTlv(outer.value, &body_cursor); // sig alg
    const sig_bits = try readTlv(outer.value, &body_cursor);
    var digest: [48]u8 = undefined;
    Sha384.hash(tbs.full, &digest, .{});
    try testing.expect(rsa_verify.verifyPkcs1v15(.{ .n = &rsa_n, .e = &rsa_e }, .sha384, &digest, sig_bits.value[1..]));
}

test "buildSelfSignedRsa with sig_pss emits id-RSASSA-PSS and verifies through x509_verify" {
    const x509 = @import("../crypto/x509.zig");
    const x509_verify = @import("../crypto/x509_verify.zig");
    const rsa_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
    const rsa_e = hexToBytes("010001");
    const rsa_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
    const rsa_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
    const rsa_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
    const rsa_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
    const rsa_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
    const rsa_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");
    const priv = rsa_sign.PrivateKey{ .n = &rsa_n, .e = &rsa_e, .d = &rsa_d, .p = &rsa_p, .q = &rsa_q, .dp = &rsa_dp, .dq = &rsa_dq, .qinv = &rsa_qinv };
    var out: [2048]u8 = undefined;
    const der = try buildSelfSignedRsa(&out, .{
        .common_name = "rsapss.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x52, 0x03 },
        .public_modulus = &rsa_n,
        .public_exponent = &rsa_e,
        .private_key = priv,
        .dns_names = &.{"rsapss.test"},
        .sig_pss = true,
    });

    // The parsed cert advertises id-RSASSA-PSS.
    const cert = try x509.parse(der);
    try testing.expectEqualSlices(u8, &oid_rsassa_pss, cert.signature_algorithm_oid);

    // The self-signature verifies through the shared verifier's PSS branch, which
    // parses the RSASSA-PSS-params carried in sig_alg_params — proving the minted
    // params SEQUENCE is well-formed and the salt/hash/MGF match the signature.
    const info = try x509_verify.linkInfo(der);
    try x509_verify.verifyCertSignature(info.tbs_der, info.signature_der, info.sig_alg_oid, info.sig_alg_params, info.spki_der);

    // A flipped signature byte is rejected by the same PSS path.
    var tampered: [2048]u8 = undefined;
    @memcpy(tampered[0..der.len], der);
    tampered[der.len - 1] ^= 0x01;
    const bad = try x509_verify.linkInfo(tampered[0..der.len]);
    try testing.expectError(error.BadSignature, x509_verify.verifyCertSignature(bad.tbs_der, bad.signature_der, bad.sig_alg_oid, bad.sig_alg_params, bad.spki_der));
}

test "buildSelfSignedEcdsaP384 emits ecdsa-with-SHA384 over a P-384 key and verifies through x509_verify" {
    const x509 = @import("../crypto/x509.zig");
    const x509_verify = @import("../crypto/x509_verify.zig");
    const kp = try EcdsaP384.KeyPair.generateDeterministic(@as([EcdsaP384.KeyPair.seed_length]u8, @splat(0x3d)));
    var out: [1024]u8 = undefined;
    const der = try buildSelfSignedEcdsaP384(&out, .{
        .common_name = "p384.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x52, 0x06 },
        .key_pair = kp,
        .dns_names = &.{"p384.test"},
    });

    // The parsed cert advertises ecdsa-with-SHA384.
    const cert = try x509.parse(der);
    try testing.expectEqualSlices(u8, &oid_ecdsa_sha384, cert.signature_algorithm_oid);

    // The self-signature verifies through the shared verifier's P-384 branch,
    // which parses the P-384 issuer point straight from the SPKI (x509's
    // SubjectPublicKey union does not model P-384).
    const info = try x509_verify.linkInfo(der);
    try x509_verify.verifyCertSignature(info.tbs_der, info.signature_der, info.sig_alg_oid, info.sig_alg_params, info.spki_der);

    // A flipped signature byte is rejected by the same P-384 path.
    var tampered: [1024]u8 = undefined;
    @memcpy(tampered[0..der.len], der);
    tampered[der.len - 1] ^= 0x01;
    const bad = try x509_verify.linkInfo(tampered[0..der.len]);
    try testing.expectError(error.BadSignature, x509_verify.verifyCertSignature(bad.tbs_der, bad.signature_der, bad.sig_alg_oid, bad.sig_alg_params, bad.spki_der));
}

test "x509_verify rejects ecdsa-with-SHA384 over a non-P-384 (P-256) issuer key, fail-closed" {
    const x509_verify = @import("../crypto/x509_verify.zig");
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(@as([ecdsa_p256.KeyPair.seed_length]u8, @splat(0x2c)));
    var out: [1024]u8 = undefined;
    const der = try buildSelfSignedEcdsaP256(&out, .{
        .common_name = "p256.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x52, 0x07 },
        .key_pair = kp,
        .dns_names = &.{"p256.test"},
    });
    const info = try x509_verify.linkInfo(der);
    // The issuer SPKI is a P-256 key; claiming ecdsa-with-SHA384 must NOT verify —
    // the P-384 branch rejects the non-secp384r1 curve fail-closed as BadSignature.
    try testing.expectError(
        error.BadSignature,
        x509_verify.verifyCertSignature(info.tbs_der, info.signature_der, &oid_ecdsa_sha384, null, info.spki_der),
    );
}

test "buildSelfSigned rejects malformed SAN dnsNames" {
    var params = try testParams();
    params.dns_names = &.{"bad host"}; // space is not a legal dNSName byte
    var out: [1024]u8 = undefined;
    try testing.expectError(error.InvalidDnsName, buildSelfSigned(&out, params));
}

test "buildSelfSigned has stable DER known-answer prefix for deterministic inputs" {
    // Arrange
    const params = try testParams();
    var out: [512]u8 = undefined;

    // Act
    const der = try buildSelfSigned(&out, params);

    // Assert
    const expected_prefix = [_]u8{
        0x30, 0x81, 0xdb, 0x30, 0x81, 0x8e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        0x02, 0x7f, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x17,
    };
    try testing.expect(der.len > expected_prefix.len);
    try testing.expectEqualSlices(u8, &expected_prefix, der[0..expected_prefix.len]);
}
