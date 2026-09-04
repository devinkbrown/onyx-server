// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal fail-closed X.509/DER reader for TLS and certfp.
//!
//! This is not a chain validator. It extracts only the certificate fields the
//! TLS and certfp layers need, keeps parsed data as slices into caller-owned
//! DER bytes, and refuses non-canonical or truncated DER.
const std = @import("std");
const hash = @import("hash.zig");

pub const MaxDerLen = 1024 * 1024;
pub const MaxDepth = 16;
// CDN/shared certs routinely carry many SAN dNSName entries (wildcards for
// dozens of subdomains), so the default bound is generous enough to parse
// real-world leaf certificates from public hosts.
pub const DefaultMaxDnsNames = 192;
pub const DefaultMaxIpAddresses = 16;

pub const Error = error{
    EmptyInput,
    Oversize,
    OverDepth,
    Truncated,
    TrailingData,
    UnsupportedTag,
    InvalidTag,
    InvalidLength,
    NonCanonicalLength,
    IndefiniteLength,
    InvalidInteger,
    InvalidBitString,
    InvalidOid,
    InvalidBoolean,
    InvalidTime,
    InvalidCertificate,
    MissingField,
    TooManySan,
    InvalidName,
    InvalidIpAddress,
    PemBeginMissing,
    PemEndMissing,
    PemInvalidBase64,
    OutputTooSmall,
    /// SubjectPublicKeyInfo uses an algorithm Onyx Server's verifier does not support.
    UnsupportedKey,
    /// SubjectPublicKeyInfo is structurally malformed for its key family.
    InvalidKey,
    /// A critical X.509 extension OID this parser does not implement (RFC 5280 §4.2).
    UnsupportedCriticalExtension,
};

pub const Sha256Digest = hash.Sha256.Digest;

pub const Tag = struct {
    pub const boolean = 0x01;
    pub const integer = 0x02;
    pub const bit_string = 0x03;
    pub const octet_string = 0x04;
    pub const null_value = 0x05;
    pub const oid = 0x06;
    pub const sequence = 0x30;
    pub const utc_time = 0x17;
    pub const generalized_time = 0x18;
    pub const context_0_constructed = 0xA0;
    pub const context_1_constructed = 0xA1;
    pub const context_3_constructed = 0xA3;
    pub const san_dns_name = 0x82;
    pub const san_ip_address = 0x87;
};

/// Maximum dNSName subtrees per direction (permitted/excluded) retained from a
/// NameConstraints extension. Real CAs use a handful; excess subtrees are
/// rejected rather than silently dropped.
pub const MaxNameConstraints = 24;

const Oid = struct {
    const subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 };
    const basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 };
    const name_constraints = [_]u8{ 0x55, 0x1D, 0x1E };
    const key_usage = [_]u8{ 0x55, 0x1D, 0x0F };
    const extended_key_usage = [_]u8{ 0x55, 0x1D, 0x25 };
    // id-kp-serverAuth (1.3.6.1.5.5.7.3.1) and anyExtendedKeyUsage (2.5.29.37.0).
    const eku_server_auth = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
    const eku_any = [_]u8{ 0x55, 0x1D, 0x25, 0x00 };
    // id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9) — a delegated OCSP responder's cert
    // MUST carry this (RFC 6960 §4.2.2.2). anyExtendedKeyUsage does NOT satisfy it.
    const eku_ocsp_signing = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };
    // authorityInfoAccess (1.3.6.1.5.5.7.1.1); id-ad-ocsp (1.3.6.1.5.5.7.48.1).
    const authority_info_access = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
    const id_ad_ocsp = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 };
    // id-pe-tlsfeature (1.3.6.1.5.5.7.1.24) — OCSP must-staple carrier.
    const tls_feature = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18 };
    // cRLDistributionPoints (2.5.29.31) — where to fetch the issuer's CRL.
    const crl_distribution_points = [_]u8{ 0x55, 0x1D, 0x1F };
    // id-ce-delegationUsage (1.3.6.1.4.1.44363.44) — RFC 9345 §4.2: an end-entity
    // certificate MUST carry this extension to authorize delegated credentials.
    const delegation_usage = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDA, 0x4B, 0x2C };
};

pub const TimeKind = enum { utc, generalized };

pub const Time = struct {
    kind: TimeKind,
    bytes: []const u8,
    epoch_seconds: i64,
};

pub const IpAddress = struct {
    bytes: [16]u8,
    len: u8,

    pub fn slice(self: *const IpAddress) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Tlv = struct {
    tag: u8,
    header_len: usize,
    value: []const u8,
    raw: []const u8,
};

/// Cursor over DER TLV elements with strict length and bounds checks.
pub const DerReader = struct {
    input: []const u8,
    offset: usize = 0,
    depth: usize = 0,

    pub fn init(input: []const u8) DerReader {
        return .{ .input = input };
    }

    pub fn hasRemaining(self: DerReader) bool {
        return self.offset < self.input.len;
    }

    pub fn remaining(self: DerReader) []const u8 {
        return self.input[self.offset..];
    }

    pub fn peekTag(self: DerReader) Error!u8 {
        if (!self.hasRemaining()) return error.Truncated;
        return self.input[self.offset];
    }

    pub fn readTlv(self: *DerReader) Error!Tlv {
        if (self.input.len > MaxDerLen) return error.Oversize;
        if (self.offset >= self.input.len) return error.Truncated;
        const start = self.offset;
        if (self.input.len - start < 2) return error.Truncated;

        const tag = self.input[start];
        if ((tag & 0x1F) == 0x1F) return error.UnsupportedTag;

        var pos = start + 2;
        var len: usize = 0;
        const first_len = self.input[start + 1];
        if ((first_len & 0x80) == 0) {
            len = first_len;
        } else {
            const len_octets = first_len & 0x7F;
            if (len_octets == 0) return error.IndefiniteLength;
            if (len_octets > @sizeOf(usize)) return error.InvalidLength;
            if (self.input.len - pos < len_octets) return error.Truncated;
            if (len_octets > 1 and self.input[pos] == 0) return error.NonCanonicalLength;

            var i: usize = 0;
            while (i < len_octets) : (i += 1) {
                if (len > (std.math.maxInt(usize) >> 8)) return error.InvalidLength;
                len = (len << 8) | self.input[pos + i];
            }
            if (len < 128) return error.NonCanonicalLength;
            pos += len_octets;
        }

        if (len > MaxDerLen) return error.Oversize;
        if (self.input.len - pos < len) return error.Truncated;
        const end = pos + len;
        self.offset = end;
        return .{
            .tag = tag,
            .header_len = pos - start,
            .value = self.input[pos..end],
            .raw = self.input[start..end],
        };
    }

    pub fn readExpected(self: *DerReader, expected_tag: u8) Error!Tlv {
        const tlv = try self.readTlv();
        if (tlv.tag != expected_tag) return error.InvalidTag;
        return tlv;
    }

    pub fn child(self: DerReader, tlv: Tlv) Error!DerReader {
        if (self.depth >= MaxDepth) return error.OverDepth;
        return .{ .input = tlv.value, .depth = self.depth + 1 };
    }

    pub fn expectEmpty(self: DerReader) Error!void {
        if (self.hasRemaining()) return error.TrailingData;
    }
};

/// Parsed certificate with comptime-bounded SAN storage.
pub fn ParsedCertificate(comptime max_dns_names: usize, comptime max_ip_addresses: usize) type {
    return struct {
        const Self = @This();

        der: []const u8,
        tbs_der: []const u8,
        /// DER INTEGER contents for TBSCertificate.serialNumber, including any
        /// leading sign-padding byte required by DER for a positive serial.
        serial_der: []const u8,
        spki_der: []const u8,
        spki_value: []const u8,
        /// The subject `Name` TLV (full tag+len+value). When this cert is a CA,
        /// this is the `issuer_name_der` an OCSP CertID hashes (RFC 6960).
        subject_der: []const u8,
        /// The issuer `Name` TLV (full tag+len+value). Equal to `subject_der`
        /// exactly when the certificate is self-issued (self-signed / a trust
        /// anchor) — the signature_algorithms_cert exemption in RFC 8446 §4.2.3.
        issuer_der: []const u8,
        /// The raw subjectPublicKey BIT STRING value WITHOUT the leading
        /// unused-bits octet — the `issuer_key_bytes` an OCSP CertID hashes.
        subject_public_key: []const u8,
        /// The id-ad-ocsp responder URI from authorityInfoAccess (empty if absent):
        /// where to fetch an OCSP response to staple.
        aia_ocsp_url: []const u8,
        /// True when the cert carries the TLS Feature (id-pe-tlsfeature) extension
        /// listing status_request(5) — OCSP must-staple.
        must_staple: bool,
        /// True when the cert carries the id-ce-delegationUsage extension
        /// (1.3.6.1.4.1.44363.44). RFC 9345 §4.2: a delegated credential MUST be
        /// rejected unless the delegation (end-entity) certificate has it.
        delegation_usage: bool,
        not_before: Time,
        not_after: Time,
        signature_algorithm_oid: []const u8,
        san_dns: [max_dns_names][]const u8,
        san_dns_count: usize,
        san_ips: [max_ip_addresses]IpAddress,
        san_ip_count: usize,
        basic_constraints_ca: bool,
        /// basicConstraints pathLenConstraint (RFC 5280 §4.2.1.10): the maximum
        /// number of non-self-issued intermediate CAs that may follow this cert
        /// toward the leaf. `null` when absent (CA with no path limit, or a
        /// non-CA cert). Only meaningful when `basic_constraints_ca` is true.
        basic_constraints_path_len: ?u32,
        /// KeyUsage extension (2.5.29.15). `key_usage_present` is false when the
        /// extension is absent; the bit fields are only meaningful when present.
        key_usage_present: bool,
        key_usage_digital_signature: bool,
        key_usage_cert_sign: bool,
        /// ExtendedKeyUsage extension (2.5.29.37). `eku_present` is false when
        /// absent. `eku_server_auth` is true when id-kp-serverAuth or
        /// anyExtendedKeyUsage is listed. `eku_ocsp_signing` is true ONLY when
        /// id-kp-OCSPSigning is listed (anyExtendedKeyUsage does not count — RFC
        /// 6960 requires the specific OID on a delegated OCSP responder cert).
        eku_present: bool,
        eku_server_auth: bool,
        eku_ocsp_signing: bool,
        /// NameConstraints extension (2.5.29.30) dNSName subtrees. Only meaningful
        /// when `name_constraints_present`. When `nc_permitted_dns_count > 0`, a
        /// constrained dNSName must match one permitted subtree; it must match no
        /// excluded subtree. `nc_unsupported_name_form` is set when a GeneralName
        /// is not a dNSName, or a GeneralSubtree carries minimum/maximum — RFC
        /// 5280 §4.2.1.10 requires those forms to be enforced or the chain
        /// rejected, and this parser does not match iPAddress/rfc822Name/URI.
        name_constraints_present: bool,
        nc_permitted_dns: [MaxNameConstraints][]const u8,
        nc_permitted_dns_count: usize,
        nc_excluded_dns: [MaxNameConstraints][]const u8,
        nc_excluded_dns_count: usize,
        nc_unsupported_name_form: bool,

        pub fn parse(der: []const u8) Error!Self {
            var cert = Self{
                .der = der,
                .tbs_der = &.{},
                .serial_der = &.{},
                .spki_der = &.{},
                .spki_value = &.{},
                .subject_der = &.{},
                .issuer_der = &.{},
                .subject_public_key = &.{},
                .aia_ocsp_url = &.{},
                .must_staple = false,
                .delegation_usage = false,
                .not_before = emptyTime(),
                .not_after = emptyTime(),
                .signature_algorithm_oid = &.{},
                .san_dns = undefined,
                .san_dns_count = 0,
                .san_ips = undefined,
                .san_ip_count = 0,
                .basic_constraints_ca = false,
                .basic_constraints_path_len = null,
                .key_usage_present = false,
                .key_usage_digital_signature = false,
                .key_usage_cert_sign = false,
                .eku_present = false,
                .eku_server_auth = false,
                .eku_ocsp_signing = false,
                .name_constraints_present = false,
                .nc_permitted_dns = undefined,
                .nc_permitted_dns_count = 0,
                .nc_excluded_dns = undefined,
                .nc_excluded_dns_count = 0,
                .nc_unsupported_name_form = false,
            };
            try parseInto(Self, &cert, der);
            return cert;
        }

        pub fn certSha256(self: Self) Sha256Digest {
            return hash.Sha256.hash(self.der);
        }

        pub fn spkiSha256(self: Self) Sha256Digest {
            return hash.Sha256.hash(self.spki_der);
        }

        pub fn certSha256Hex(self: Self, out: []u8) Error![]const u8 {
            return writeHex(&self.certSha256(), out);
        }

        pub fn spkiSha256Hex(self: Self, out: []u8) Error![]const u8 {
            return writeHex(&self.spkiSha256(), out);
        }
    };
}

pub const Certificate = ParsedCertificate(DefaultMaxDnsNames, DefaultMaxIpAddresses);

pub fn parse(der: []const u8) Error!Certificate {
    return Certificate.parse(der);
}

// ---------------------------------------------------------------------------
// SubjectPublicKeyInfo extraction.
//
// Recovers the raw public-key material an issuer needs to verify a child
// certificate's signature. Slices alias the caller-owned SPKI bytes; no
// allocation, no copying. Only the key families Onyx Server's X.509 verifier
// dispatches on are recognized — anything else is `UnsupportedKey`, so callers
// fail closed rather than treating an unknown key as trusted.
// ---------------------------------------------------------------------------

/// Algorithm OIDs found in a SubjectPublicKeyInfo AlgorithmIdentifier.
const SpkiOid = struct {
    /// rsaEncryption (1.2.840.113549.1.1.1).
    const rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    /// id-ecPublicKey (1.2.840.10045.2.1).
    const ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    /// prime256v1 / secp256r1 (1.2.840.10045.3.1.7).
    const prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    /// id-Ed25519 (1.3.101.112).
    const ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };
    /// id-ML-DSA-44 (2.16.840.1.101.3.4.3.17) — SPKI AlgorithmIdentifier OID for
    /// a raw ML-DSA-44 public key (NIST CSOR sigAlgs .17). One OID names both the
    /// key and the signature algorithm.
    const ml_dsa_44 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
    /// id-ML-DSA-65 (2.16.840.1.101.3.4.3.18) — the SPKI AlgorithmIdentifier OID
    /// for a raw ML-DSA-65 public key (draft-ietf-lamps-dilithium-certificates).
    /// Same OID identifies both the key and the signature algorithm.
    const ml_dsa_65 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
    /// id-ML-DSA-87 (2.16.840.1.101.3.4.3.19) — SPKI AlgorithmIdentifier OID for
    /// a raw ML-DSA-87 public key (NIST CSOR sigAlgs .19).
    const ml_dsa_87 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };
};

/// The 8-byte OID prefix shared by every SLH-DSA parameter set,
/// 2.16.840.1.101.3.4.3.{20..31} (id-slh-dsa-*, draft-ietf-lamps-x509-slhdsa).
/// The caller supplies the full 9-byte OID including the trailing set byte.
pub const slh_dsa_oid_prefix = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 };

/// Length of an Ed25519 raw public key.
pub const ed25519_public_key_len = 32;
/// Length of a raw ML-DSA-44 public key (ρ ‖ t1), per FIPS 204.
pub const ml_dsa_44_public_key_len = 1312;
/// Length of a raw ML-DSA-65 public key (ρ ‖ t1), per FIPS 204.
pub const ml_dsa_65_public_key_len = 1952;
/// Length of a raw ML-DSA-87 public key (ρ ‖ t1), per FIPS 204.
pub const ml_dsa_87_public_key_len = 2592;
/// Length of an uncompressed SEC1 P-256 point (0x04 || X32 || Y32).
pub const ec_p256_sec1_len = 65;

/// RSA public key recovered from an SPKI: big-endian modulus and exponent with
/// any DER sign-padding (leading 0x00) byte stripped to the unsigned magnitude.
pub const RsaPublicKey = struct {
    modulus: []const u8,
    exponent: []const u8,
};

/// A parsed SubjectPublicKeyInfo, tagged by key family.
pub const SubjectPublicKey = union(enum) {
    rsa: RsaPublicKey,
    /// Uncompressed SEC1 P-256 point (`0x04 || X32 || Y32`), 65 bytes.
    ecdsa_p256: []const u8,
    /// Raw 32-byte Ed25519 public key.
    ed25519: []const u8,
};

/// Parse a SubjectPublicKeyInfo (`spki_der`, the full `SEQUENCE`) into the raw
/// public-key material. Recognizes RSA, ECDSA P-256, and Ed25519; any other
/// algorithm is `error.UnsupportedKey`.
pub fn extractPublicKey(spki_der: []const u8) Error!SubjectPublicKey {
    var top = DerReader.init(spki_der);
    const seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(Tag.sequence);
    const key_bits = try spki.readExpected(Tag.bit_string);
    try spki.expectEmpty();

    const alg = try parseSpkiAlgorithm(spki, alg_seq);
    const key_bytes = try parseBitString(key_bits);

    if (std.mem.eql(u8, alg.oid, &SpkiOid.rsa_encryption)) {
        var r = DerReader.init(key_bytes);
        const rsa_seq = try r.readExpected(Tag.sequence);
        try r.expectEmpty();
        var body = try r.child(rsa_seq);
        const modulus = try unsignedInteger(try body.readExpected(Tag.integer));
        const exponent = try unsignedInteger(try body.readExpected(Tag.integer));
        try body.expectEmpty();
        return .{ .rsa = .{ .modulus = modulus, .exponent = exponent } };
    }
    if (std.mem.eql(u8, alg.oid, &SpkiOid.ec_public_key)) {
        const params = alg.params orelse return error.UnsupportedKey;
        if (!std.mem.eql(u8, params, &SpkiOid.prime256v1)) return error.UnsupportedKey;
        if (key_bytes.len != ec_p256_sec1_len or key_bytes[0] != 0x04) return error.InvalidKey;
        return .{ .ecdsa_p256 = key_bytes };
    }
    if (std.mem.eql(u8, alg.oid, &SpkiOid.ed25519)) {
        if (key_bytes.len != ed25519_public_key_len) return error.InvalidKey;
        return .{ .ed25519 = key_bytes };
    }
    return error.UnsupportedKey;
}

/// Extract a raw ML-DSA public key from a SubjectPublicKeyInfo, requiring the
/// AlgorithmIdentifier OID to match `expected_oid` exactly (one of id-ML-DSA-44/
/// 65/87) with an ABSENT parameters field (draft-ietf-lamps-dilithium-
/// certificates), the key BIT STRING to hold exactly the raw key bytes with zero
/// unused bits, and the decoded key to be exactly `expected_len` bytes. Fails
/// closed on any deviation. This is a separate entry point from
/// `extractPublicKey` so the post-quantum path never widens the classical
/// `SubjectPublicKey` union that many unrelated verifiers switch over.
fn extractMlDsaPublicKey(spki_der: []const u8, expected_oid: []const u8, expected_len: usize) Error![]const u8 {
    var top = DerReader.init(spki_der);
    const seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(Tag.sequence);
    const key_bits = try spki.readExpected(Tag.bit_string);
    try spki.expectEmpty();

    // AlgorithmIdentifier: exact-OID match, parameters MUST be absent.
    var alg = try spki.child(alg_seq);
    const oid = try alg.readExpected(Tag.oid);
    try validateOid(oid.value);
    if (!std.mem.eql(u8, oid.value, expected_oid)) return error.UnsupportedKey;
    try alg.expectEmpty();

    // A raw key BIT STRING is byte-aligned: zero unused bits (parseBitString only
    // rejects >7, so enforce the exact-0 requirement here for the PQ path).
    if (key_bits.value.len == 0 or key_bits.value[0] != 0) return error.InvalidKey;
    const key_bytes = try parseBitString(key_bits);
    if (key_bytes.len != expected_len) return error.InvalidKey;
    return key_bytes;
}

/// Extract the raw ML-DSA-44 public key (1312 bytes, ρ ‖ t1) from an SPKI whose
/// AlgorithmIdentifier OID is exactly id-ML-DSA-44 (2.16.840.1.101.3.4.3.17).
pub fn extractMlDsa44PublicKey(spki_der: []const u8) Error![]const u8 {
    return extractMlDsaPublicKey(spki_der, &SpkiOid.ml_dsa_44, ml_dsa_44_public_key_len);
}

/// Extract the raw ML-DSA-65 public key (1952 bytes, ρ ‖ t1) from an SPKI whose
/// AlgorithmIdentifier OID is exactly id-ML-DSA-65 (2.16.840.1.101.3.4.3.18).
pub fn extractMlDsa65PublicKey(spki_der: []const u8) Error![]const u8 {
    return extractMlDsaPublicKey(spki_der, &SpkiOid.ml_dsa_65, ml_dsa_65_public_key_len);
}

/// Extract the raw ML-DSA-87 public key (2592 bytes, ρ ‖ t1) from an SPKI whose
/// AlgorithmIdentifier OID is exactly id-ML-DSA-87 (2.16.840.1.101.3.4.3.19).
pub fn extractMlDsa87PublicKey(spki_der: []const u8) Error![]const u8 {
    return extractMlDsaPublicKey(spki_der, &SpkiOid.ml_dsa_87, ml_dsa_87_public_key_len);
}

/// Extract a raw SLH-DSA public key (PK.seed ‖ PK.root, `expected_len` bytes) from
/// a SubjectPublicKeyInfo. The AlgorithmIdentifier OID must equal `expected_oid`
/// exactly (an id-slh-dsa-* OID, `2.16.840.1.101.3.4.3.{20..31}`) with an ABSENT
/// parameters field (draft-ietf-lamps-x509-slhdsa), and the key BIT STRING must
/// hold exactly the raw key bytes with zero unused bits. Fails closed on any
/// deviation. Like `extractMlDsa65PublicKey`, this is a separate entry point from
/// `extractPublicKey` so the post-quantum path never widens the classical
/// `SubjectPublicKey` union that many unrelated verifiers switch over.
pub fn extractSlhDsaPublicKey(
    spki_der: []const u8,
    expected_oid: []const u8,
    expected_len: usize,
) Error![]const u8 {
    var top = DerReader.init(spki_der);
    const seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(Tag.sequence);
    const key_bits = try spki.readExpected(Tag.bit_string);
    try spki.expectEmpty();

    // AlgorithmIdentifier: exact-OID match, parameters MUST be absent.
    var alg = try spki.child(alg_seq);
    const oid = try alg.readExpected(Tag.oid);
    try validateOid(oid.value);
    if (!std.mem.eql(u8, oid.value, expected_oid)) return error.UnsupportedKey;
    try alg.expectEmpty();

    // A raw key BIT STRING is byte-aligned: zero unused bits (parseBitString only
    // rejects >7, so enforce the exact-0 requirement here for the PQ path).
    if (key_bits.value.len == 0 or key_bits.value[0] != 0) return error.InvalidKey;
    const key_bytes = try parseBitString(key_bits);
    if (key_bytes.len != expected_len) return error.InvalidKey;
    return key_bytes;
}

const SpkiAlgorithm = struct {
    oid: []const u8,
    params: ?[]const u8,
};

fn parseSpkiAlgorithm(parent: DerReader, seq_tlv: Tlv) Error!SpkiAlgorithm {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(Tag.oid);
    try validateOid(oid.value);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) {
        const p = try r.readTlv();
        if (p.tag == Tag.oid) params = p.value;
    }
    try r.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

/// DER INTEGER content as an unsigned big-endian magnitude: rejects negatives
/// and strips the single leading 0x00 sign byte DER requires when the magnitude
/// MSB is set.
fn unsignedInteger(tlv: Tlv) Error![]const u8 {
    if (tlv.tag != Tag.integer or tlv.value.len == 0) return error.InvalidInteger;
    try validateDerInteger(tlv.value);
    if ((tlv.value[0] & 0x80) != 0) return error.InvalidInteger; // negative
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..];
    if (v.len == 0) return error.InvalidInteger;
    return v;
}

/// Decode a single CERTIFICATE PEM block into caller-provided DER storage.
pub fn pemToDer(pem: []const u8, out: []u8) Error![]const u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const begin_pos = std.mem.indexOf(u8, pem, begin) orelse return error.PemBeginMissing;
    const data_start = begin_pos + begin.len;
    const rel_end = std.mem.indexOf(u8, pem[data_start..], end) orelse return error.PemEndMissing;
    const b64 = pem[data_start .. data_start + rel_end];
    if (b64.len > MaxDerLen * 2) return error.Oversize;

    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    if (decoder.calcSizeUpperBound(b64.len) > out.len) return error.OutputTooSmall;
    const written = decoder.decode(out, b64) catch |err| switch (err) {
        error.NoSpaceLeft => return error.OutputTooSmall,
        error.InvalidCharacter, error.InvalidPadding => return error.PemInvalidBase64,
    };
    if (written == 0) return error.EmptyInput;
    if (written > MaxDerLen) return error.Oversize;
    return out[0..written];
}

/// Write lowercase hexadecimal bytes into `out`.
pub fn writeHex(bytes: []const u8, out: []u8) Error![]const u8 {
    if (out.len < bytes.len * 2) return error.OutputTooSmall;
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0F];
    }
    return out[0 .. bytes.len * 2];
}

// ---------------------------------------------------------------------------
// Embedded SCT (Certificate Transparency) extension.
//
// These are deliberately standalone from the `parseExtensions` state machine
// above: they neither read nor mutate the `ParsedCertificate` extension fields,
// so adding SCT support cannot perturb chain/certfp parsing. They only unwrap
// the extension's DER envelope into the raw TLS SignedCertificateTimestampList
// bytes; decoding the individual SCTs is `crypto/sct.zig`'s job.
// ---------------------------------------------------------------------------

/// OID 1.3.6.1.4.1.11129.2.4.2 — the X.509 `SignedCertificateTimestampList`
/// extension (RFC 6962 §3.3) carrying SCTs embedded in a certificate.
pub const sct_list_extension_oid = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02 };

/// Unwrap an SCT extension's value into the raw TLS `SignedCertificateTimestampList`.
///
/// `extn_value` is the CONTENT of the extension's `extnValue` OCTET STRING — the
/// bytes a DER extension reader yields after stripping the outer OCTET STRING
/// wrapper every X.509 extension carries (exactly the `value.value` the other
/// per-extension parsers here receive). For the SCT extension that content is
/// itself a DER OCTET STRING (`SignedCertificateTimestampList ::= OCTET STRING`)
/// wrapping the TLS-encoded list; this peels that inner OCTET STRING and returns
/// the raw TLS bytes, ready for `sct.parseList`. Between this and the generic
/// extension reader, both OCTET STRING wrappers are peeled. Fails closed on any
/// malformed or non-canonical DER, or trailing bytes.
pub fn parseSctList(extn_value: []const u8) Error![]const u8 {
    var r = DerReader.init(extn_value);
    const inner = try r.readExpected(Tag.octet_string);
    try r.expectEmpty();
    return inner.value;
}

/// Locate the embedded SCT extension in a certificate and return the raw TLS
/// `SignedCertificateTimestampList` bytes (ready for `sct.parseList`), or `null`
/// when the certificate carries no SCT extension.
///
/// Walks the certificate structurally to its extensions; it does NOT otherwise
/// validate the certificate (use `parse` for that). Standalone from
/// `parseExtensions`. Fails closed on malformed DER.
pub fn findSctListExtension(cert_der: []const u8) Error!?[]const u8 {
    if (cert_der.len == 0) return error.EmptyInput;
    if (cert_der.len > MaxDerLen) return error.Oversize;

    var top = DerReader.init(cert_der);
    const cert_seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(Tag.sequence);
    // signatureAlgorithm and signatureValue are not needed to find extensions.

    var tbs_reader = try body.child(tbs);
    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == Tag.context_0_constructed) {
        _ = try tbs_reader.readTlv(); // [0] EXPLICIT version
    }
    _ = try tbs_reader.readExpected(Tag.integer); // serialNumber
    _ = try tbs_reader.readExpected(Tag.sequence); // signature
    _ = try tbs_reader.readExpected(Tag.sequence); // issuer
    _ = try tbs_reader.readExpected(Tag.sequence); // validity
    _ = try tbs_reader.readExpected(Tag.sequence); // subject
    _ = try tbs_reader.readExpected(Tag.sequence); // subjectPublicKeyInfo

    while (tbs_reader.hasRemaining()) {
        const tag = try tbs_reader.peekTag();
        switch (tag) {
            0x81, 0x82 => _ = try tbs_reader.readTlv(), // issuer/subject UniqueID
            Tag.context_3_constructed => return scanExtensionsForSct(tbs_reader, try tbs_reader.readTlv()),
            else => return null,
        }
    }
    return null;
}

fn scanExtensionsForSct(parent: DerReader, ext_tlv: Tlv) Error!?[]const u8 {
    var explicit = try parent.child(ext_tlv);
    const seq_tlv = try explicit.readExpected(Tag.sequence);
    try explicit.expectEmpty();

    var extensions = try explicit.child(seq_tlv);
    while (extensions.hasRemaining()) {
        const one_tlv = try extensions.readExpected(Tag.sequence);
        var one = try extensions.child(one_tlv);
        const oid_tlv = try one.readExpected(Tag.oid);
        try validateOid(oid_tlv.value);
        const critical = try readExtensionCriticalField(&one);
        const value = try one.readExpected(Tag.octet_string);
        try one.expectEmpty();
        try rejectUnsupportedCriticalExtension(critical, oid_tlv.value);
        if (std.mem.eql(u8, oid_tlv.value, &sct_list_extension_oid)) {
            return try parseSctList(value.value);
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Precertificate TBSCertificate reconstruction (RFC 6962 §3.2).
//
// An SCT EMBEDDED in a certificate signs over the *precertificate*: the leaf's
// TBSCertificate with the embedded SCT-list extension (OID
// 1.3.6.1.4.1.11129.2.4.2) removed. To verify a deployed leaf's embedded SCTs,
// the exact precert TBS bytes must be reconstructed — the leaf TBS with only
// that one extension stripped and every affected enclosing length (the
// Extensions SEQUENCE, the [3] EXPLICIT wrapper, and the outer TBSCertificate
// SEQUENCE) re-encoded to canonical minimal DER. Every other byte — all the
// other extensions, in wire order — is preserved verbatim.
//
// Scope: the common case where the CA signs the precertificate directly, so the
// issuer_key_hash is SHA-256 of the issuing CA's SubjectPublicKeyInfo and the
// TBS issuer field is unchanged. A Precertificate Signing Certificate (RFC 6962
// §3.1), which additionally rewrites the issuer, is out of scope — an SCT that
// needs that rewrite simply fails to verify, which the caller's fail-open policy
// tolerates. Standalone from `parseInto`; fails closed on malformed DER.
// ---------------------------------------------------------------------------

/// Bytes the DER length octets for `content_len` occupy (excluding the tag).
/// Canonical minimal encoding: short form (<128) is a single octet; long form is
/// `0x80|n` followed by `n` big-endian minimal magnitude octets.
fn derLenOctets(content_len: usize) usize {
    if (content_len < 0x80) return 1;
    var n = content_len;
    var octets: usize = 0;
    while (n != 0) : (n >>= 8) octets += 1;
    return 1 + octets;
}

/// Size of a full DER TLV header (tag + length octets) for `content_len`.
fn derHeaderLen(content_len: usize) usize {
    return 1 + derLenOctets(content_len);
}

/// Write a canonical minimal DER TLV header (`tag` + length octets for
/// `content_len`) at the start of `out`, returning the number of bytes written.
/// Caller guarantees `out.len >= derHeaderLen(content_len)`.
fn writeDerHeader(out: []u8, tag: u8, content_len: usize) usize {
    out[0] = tag;
    if (content_len < 0x80) {
        out[1] = @intCast(content_len);
        return 2;
    }
    var n = content_len;
    var octets: usize = 0;
    while (n != 0) : (n >>= 8) octets += 1;
    out[1] = 0x80 | @as(u8, @intCast(octets));
    var i: usize = 0;
    while (i < octets) : (i += 1) {
        const shift: u6 = @intCast(8 * (octets - 1 - i));
        out[2 + i] = @intCast((content_len >> shift) & 0xff);
    }
    return 2 + octets;
}

/// Reconstruct the precertificate TBSCertificate that a leaf's EMBEDDED SCTs
/// sign over: its TBSCertificate with the SCT-list extension (OID
/// 1.3.6.1.4.1.11129.2.4.2) removed and the enclosing lengths re-encoded to
/// canonical minimal DER (RFC 6962 §3.2). Writes into `out` and returns the
/// written prefix — the exact bytes to frame as the `PreCert` TBSCertificate for
/// `sct.buildPrecertEntry` / `verifySctAgainstLogs`.
///
/// Requires the leaf to actually carry the SCT-list extension (call after
/// `findSctListExtension` returns non-null); a leaf without it yields
/// `error.MissingField`. Fails with `error.OutputTooSmall` when `out` cannot
/// hold the (always strictly smaller than the input) result, and fails closed on
/// any malformed DER.
pub fn buildPrecertTbs(out: []u8, leaf_der: []const u8) Error![]const u8 {
    if (leaf_der.len == 0) return error.EmptyInput;
    if (leaf_der.len > MaxDerLen) return error.Oversize;

    var top = DerReader.init(leaf_der);
    const cert_seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();
    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(Tag.sequence);
    // signatureAlgorithm / signatureValue are irrelevant to the TBS.

    var tbs_reader = try body.child(tbs);
    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == Tag.context_0_constructed) {
        _ = try tbs_reader.readTlv(); // [0] EXPLICIT version
    }
    _ = try tbs_reader.readExpected(Tag.integer); // serialNumber
    _ = try tbs_reader.readExpected(Tag.sequence); // signature
    _ = try tbs_reader.readExpected(Tag.sequence); // issuer
    _ = try tbs_reader.readExpected(Tag.sequence); // validity
    _ = try tbs_reader.readExpected(Tag.sequence); // subject
    _ = try tbs_reader.readExpected(Tag.sequence); // subjectPublicKeyInfo

    // issuerUniqueID [1] / subjectUniqueID [2] (primitive, IMPLICIT) belong to
    // the preserved prefix; skip them and stop at the extensions [3].
    while (tbs_reader.hasRemaining()) {
        const tag = try tbs_reader.peekTag();
        if (tag == Tag.context_3_constructed) break;
        if (tag == 0x81 or tag == 0x82) {
            _ = try tbs_reader.readTlv();
            continue;
        }
        return error.MissingField; // an unexpected field, or no extensions at all
    }
    if (!tbs_reader.hasRemaining()) return error.MissingField; // no extensions

    // Every TBS byte before [3] is copied verbatim.
    const prefix_len = tbs_reader.offset;
    const ext3 = try tbs_reader.readExpected(Tag.context_3_constructed);
    try tbs_reader.expectEmpty();

    var explicit = try tbs_reader.child(ext3);
    const exts_seq = try explicit.readExpected(Tag.sequence);
    try explicit.expectEmpty();

    // Pass 1: size the SCT-stripped Extensions SEQUENCE content, and confirm the
    // SCT-list extension is present (removing something absent is a caller error).
    var new_exts_content_len: usize = 0;
    var found_sct = false;
    var pass1 = try explicit.child(exts_seq);
    while (pass1.hasRemaining()) {
        const one_tlv = try pass1.readExpected(Tag.sequence);
        var one = try pass1.child(one_tlv);
        const oid_tlv = try one.readExpected(Tag.oid);
        try validateOid(oid_tlv.value);
        if (std.mem.eql(u8, oid_tlv.value, &sct_list_extension_oid)) {
            found_sct = true;
            continue;
        }
        new_exts_content_len += one_tlv.raw.len;
    }
    if (!found_sct) return error.MissingField;

    // Enclosing sizes, computed bottom-up in canonical minimal DER.
    const exts_seq_total = derHeaderLen(new_exts_content_len) + new_exts_content_len;
    const ext3_total = derHeaderLen(exts_seq_total) + exts_seq_total;
    const tbs_content_len = prefix_len + ext3_total;
    const tbs_total = derHeaderLen(tbs_content_len) + tbs_content_len;
    if (out.len < tbs_total) return error.OutputTooSmall;

    // Pass 2: emit the TBS header, the verbatim prefix, the [3] header, the
    // Extensions SEQUENCE header, then every non-SCT extension's raw bytes in order.
    var w: usize = 0;
    w += writeDerHeader(out[w..], Tag.sequence, tbs_content_len);
    @memcpy(out[w..][0..prefix_len], tbs.value[0..prefix_len]);
    w += prefix_len;
    w += writeDerHeader(out[w..], Tag.context_3_constructed, exts_seq_total);
    w += writeDerHeader(out[w..], Tag.sequence, new_exts_content_len);

    var pass2 = try explicit.child(exts_seq);
    while (pass2.hasRemaining()) {
        const one_tlv = try pass2.readExpected(Tag.sequence);
        var one = try pass2.child(one_tlv);
        const oid_tlv = try one.readExpected(Tag.oid);
        if (std.mem.eql(u8, oid_tlv.value, &sct_list_extension_oid)) continue;
        @memcpy(out[w..][0..one_tlv.raw.len], one_tlv.raw);
        w += one_tlv.raw.len;
    }
    return out[0..w];
}

fn parseInto(comptime CertType: type, cert: *CertType, der: []const u8) Error!void {
    if (der.len == 0) return error.EmptyInput;
    if (der.len > MaxDerLen) return error.Oversize;

    var top = DerReader.init(der);
    const cert_seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(Tag.sequence);
    cert.tbs_der = tbs.raw;

    const sig_alg = try body.readExpected(Tag.sequence);
    cert.signature_algorithm_oid = try parseAlgorithmOid(body, sig_alg);

    const signature = try body.readExpected(Tag.bit_string);
    _ = try parseBitString(signature);
    try body.expectEmpty();

    try parseTbs(CertType, cert, body, tbs);
    if (cert.tbs_der.len == 0 or cert.spki_der.len == 0 or
        cert.signature_algorithm_oid.len == 0)
    {
        return error.MissingField;
    }
}

fn parseTbs(comptime CertType: type, cert: *CertType, parent: DerReader, tbs: Tlv) Error!void {
    var tbs_reader = try parent.child(tbs);

    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == Tag.context_0_constructed) {
        try parseVersion(tbs_reader, try tbs_reader.readTlv());
    }

    const serial = try tbs_reader.readExpected(Tag.integer);
    try validatePositiveInteger(serial.value);
    cert.serial_der = serial.value;

    _ = try tbs_reader.readExpected(Tag.sequence); // TBSCertificate.signature
    const issuer = try tbs_reader.readExpected(Tag.sequence); // issuer
    cert.issuer_der = issuer.raw;

    const validity = try tbs_reader.readExpected(Tag.sequence);
    var validity_reader = try tbs_reader.child(validity);
    cert.not_before = try parseTime(try validity_reader.readTlv());
    cert.not_after = try parseTime(try validity_reader.readTlv());
    try validity_reader.expectEmpty();

    const subject = try tbs_reader.readExpected(Tag.sequence); // subject
    cert.subject_der = subject.raw;

    const spki = try tbs_reader.readExpected(Tag.sequence);
    cert.spki_der = spki.raw;
    cert.spki_value = spki.value;
    // Capture the raw subjectPublicKey bit-string value (minus the unused-bits
    // octet) for the OCSP CertID issuerKeyHash.
    {
        var spki_reader = try tbs_reader.child(spki);
        _ = try spki_reader.readExpected(Tag.sequence); // AlgorithmIdentifier
        const bits = try spki_reader.readExpected(Tag.bit_string);
        if (bits.value.len >= 1) cert.subject_public_key = bits.value[1..];
    }
    try validateSpki(tbs_reader, spki);

    var saw_extensions = false;
    while (tbs_reader.hasRemaining()) {
        const tag = try tbs_reader.peekTag();
        switch (tag) {
            0x81, 0x82 => {
                _ = try tbs_reader.readTlv(); // issuerUniqueID / subjectUniqueID
            },
            Tag.context_3_constructed => {
                if (saw_extensions) return error.InvalidCertificate;
                saw_extensions = true;
                try parseExtensions(CertType, cert, tbs_reader, try tbs_reader.readTlv());
            },
            else => return error.InvalidTag,
        }
    }
}

fn parseVersion(parent: DerReader, version_tlv: Tlv) Error!void {
    var explicit = try parent.child(version_tlv);
    const version = try explicit.readExpected(Tag.integer);
    try explicit.expectEmpty();
    try validateDerInteger(version.value);
    if (version.value.len != 1 or version.value[0] > 2) return error.InvalidCertificate;
}

fn validateSpki(parent: DerReader, spki_tlv: Tlv) Error!void {
    var spki = try parent.child(spki_tlv);
    const alg = try spki.readExpected(Tag.sequence);
    _ = try parseAlgorithmOid(spki, alg);
    const key = try spki.readExpected(Tag.bit_string);
    _ = try parseBitString(key);
    try spki.expectEmpty();
}

fn parseAlgorithmOid(parent: DerReader, seq_tlv: Tlv) Error![]const u8 {
    var alg = try parent.child(seq_tlv);
    const oid = try alg.readExpected(Tag.oid);
    try validateOid(oid.value);
    if (alg.hasRemaining()) {
        _ = try alg.readTlv(); // optional parameters
    }
    try alg.expectEmpty();
    return oid.value;
}

fn parseExtensions(comptime CertType: type, cert: *CertType, parent: DerReader, ext_tlv: Tlv) Error!void {
    var explicit = try parent.child(ext_tlv);
    const seq_tlv = try explicit.readExpected(Tag.sequence);
    try explicit.expectEmpty();

    var extensions = try explicit.child(seq_tlv);
    while (extensions.hasRemaining()) {
        const one_tlv = try extensions.readExpected(Tag.sequence);
        var one = try extensions.child(one_tlv);
        const oid_tlv = try one.readExpected(Tag.oid);
        try validateOid(oid_tlv.value);

        const critical = try readExtensionCriticalField(&one);

        const value = try one.readExpected(Tag.octet_string);
        try one.expectEmpty();

        var handled = false;
        if (std.mem.eql(u8, oid_tlv.value, &Oid.subject_alt_name)) {
            try parseSubjectAltName(CertType, cert, one, value.value);
            handled = true;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.basic_constraints)) {
            const bc = try parseBasicConstraints(one, value.value);
            cert.basic_constraints_ca = bc.ca;
            cert.basic_constraints_path_len = bc.path_len;
            handled = true;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.key_usage)) {
            try parseKeyUsage(CertType, cert, one, value.value);
            handled = true;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.extended_key_usage)) {
            try parseExtendedKeyUsage(CertType, cert, one, value.value);
            handled = true;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.name_constraints)) {
            try parseNameConstraints(CertType, cert, one, value.value);
            handled = true;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.authority_info_access)) {
            try parseAuthorityInfoAccess(CertType, cert, one, value.value);
            handled = true;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.tls_feature)) {
            try parseTlsFeature(CertType, cert, one, value.value);
            handled = true;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.delegation_usage)) {
            // RFC 9345 §4.2: presence authorizes delegated credentials. The
            // extension value is an empty/NULL body carrying no data we act on.
            cert.delegation_usage = true;
            handled = true;
        }
        if (!handled) try rejectUnsupportedCriticalExtension(critical, oid_tlv.value);
    }
}

/// True when `parseExtensions` recognizes an extension OID (handled or
/// intentionally ignored). Used to enforce RFC 5280 §4.2 critical semantics.
fn extensionOidIsSupported(oid_value: []const u8) bool {
    if (std.mem.eql(u8, oid_value, &Oid.subject_alt_name)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.basic_constraints)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.key_usage)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.extended_key_usage)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.name_constraints)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.authority_info_access)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.tls_feature)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.delegation_usage)) return true;
    if (std.mem.eql(u8, oid_value, &Oid.crl_distribution_points)) return true;
    if (std.mem.eql(u8, oid_value, &sct_list_extension_oid)) return true;
    return false;
}

fn readExtensionCriticalField(one: *DerReader) Error!bool {
    if (one.hasRemaining() and try one.peekTag() == Tag.boolean) {
        return try parseBoolean(try one.readTlv());
    }
    return false;
}

fn rejectUnsupportedCriticalExtension(critical: bool, oid_value: []const u8) Error!void {
    if (critical and !extensionOidIsSupported(oid_value)) return error.UnsupportedCriticalExtension;
}

/// authorityInfoAccess (RFC 5280 §4.2.2.1): capture the id-ad-ocsp responder URI
/// (GeneralName uniformResourceIdentifier, context-primitive tag [6] = 0x86).
fn parseAuthorityInfoAccess(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence); // SEQUENCE OF AccessDescription
    try inner.expectEmpty();
    var seq = try inner.child(seq_tlv);
    while (seq.hasRemaining()) {
        const ad_tlv = try seq.readExpected(Tag.sequence); // AccessDescription
        var ad = try seq.child(ad_tlv);
        const method = try ad.readExpected(Tag.oid);
        if (std.mem.eql(u8, method.value, &Oid.id_ad_ocsp) and ad.hasRemaining()) {
            const loc = try ad.readTlv();
            if (loc.tag == 0x86 and cert.aia_ocsp_url.len == 0) cert.aia_ocsp_url = loc.value;
        }
    }
}

/// id-pe-tlsfeature (RFC 7633): `Features ::= SEQUENCE OF INTEGER`. Set
/// `must_staple` when status_request(5) is present.
fn parseTlsFeature(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();
    var seq = try inner.child(seq_tlv);
    while (seq.hasRemaining()) {
        const feat = try seq.readExpected(Tag.integer);
        if (feat.value.len == 1 and feat.value[0] == 5) cert.must_staple = true;
    }
}

/// NameConstraints (RFC 5280 §4.2.1.10): SEQUENCE { permittedSubtrees [0],
/// excludedSubtrees [1] }, each GeneralSubtrees = SEQUENCE OF GeneralSubtree.
/// dNSName bases with default minimum=0 / absent maximum are retained.
/// Any other GeneralName form, or a present minimum/maximum, sets
/// `nc_unsupported_name_form` so `enforceNameConstraints` fails closed.
fn parseNameConstraints(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();
    cert.name_constraints_present = true;

    var nc = try inner.child(seq_tlv);
    while (nc.hasRemaining()) {
        const tag = try nc.peekTag();
        const tlv = try nc.readTlv();
        if (tag == Tag.context_0_constructed) {
            try collectDnsSubtrees(CertType, cert, nc, tlv, &cert.nc_permitted_dns, &cert.nc_permitted_dns_count);
        } else if (tag == Tag.context_1_constructed) {
            try collectDnsSubtrees(CertType, cert, nc, tlv, &cert.nc_excluded_dns, &cert.nc_excluded_dns_count);
        }
    }
}

fn collectDnsSubtrees(
    comptime CertType: type,
    cert: *CertType,
    parent: DerReader,
    subtrees_tlv: Tlv,
    out: *[MaxNameConstraints][]const u8,
    count: *usize,
) Error!void {
    var subs = try parent.child(subtrees_tlv);
    while (subs.hasRemaining()) {
        const gs_tlv = try subs.readExpected(Tag.sequence);
        var gs = try subs.child(gs_tlv);
        const base = try gs.readTlv();
        if (base.tag == Tag.san_dns_name) {
            if (count.* >= out.len) return error.TooManySan;
            out[count.*] = base.value;
            count.* += 1;
        } else {
            cert.nc_unsupported_name_form = true;
        }
        // RFC 5280 §4.2.1.10: within this profile minimum MUST be zero and
        // maximum MUST be absent. Any leftover GeneralSubtree field is a
        // distance we do not enforce — fail closed at verify time.
        if (gs.hasRemaining()) cert.nc_unsupported_name_form = true;
    }
}

/// KeyUsage is a DER BIT STRING; bit 0 (MSB of the first content byte) is
/// digitalSignature and bit 5 is keyCertSign (RFC 5280 §4.2.1.3).
fn parseKeyUsage(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const bits = try inner.readExpected(Tag.bit_string);
    try inner.expectEmpty();
    if (bits.value.len < 1) return error.InvalidBitString;
    const unused = bits.value[0];
    if (unused > 7) return error.InvalidBitString;
    cert.key_usage_present = true;
    if (bits.value.len >= 2) {
        cert.key_usage_digital_signature = (bits.value[1] & 0x80) != 0;
        cert.key_usage_cert_sign = (bits.value[1] & 0x04) != 0;
    }
}

/// ExtendedKeyUsage is a SEQUENCE OF KeyPurposeId (OID). serverAuth or
/// anyExtendedKeyUsage marks the cert usable for TLS server authentication.
fn parseExtendedKeyUsage(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();
    cert.eku_present = true;
    var seq = try inner.child(seq_tlv);
    while (seq.hasRemaining()) {
        const oid_tlv = try seq.readExpected(Tag.oid);
        try validateOid(oid_tlv.value);
        if (std.mem.eql(u8, oid_tlv.value, &Oid.eku_server_auth) or
            std.mem.eql(u8, oid_tlv.value, &Oid.eku_any))
        {
            cert.eku_server_auth = true;
        }
        // id-kp-OCSPSigning only — anyExtendedKeyUsage deliberately does NOT
        // authorize OCSP delegation (RFC 6960 §4.2.2.2 wants the exact OID).
        if (std.mem.eql(u8, oid_tlv.value, &Oid.eku_ocsp_signing)) {
            cert.eku_ocsp_signing = true;
        }
    }
}

fn parseSubjectAltName(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const names_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();

    var names = try inner.child(names_tlv);
    while (names.hasRemaining()) {
        const name = try names.readTlv();
        switch (name.tag) {
            Tag.san_dns_name => {
                try validateDnsName(name.value);
                if (cert.san_dns_count >= cert.san_dns.len) return error.TooManySan;
                cert.san_dns[cert.san_dns_count] = name.value;
                cert.san_dns_count += 1;
            },
            Tag.san_ip_address => {
                if (name.value.len != 4 and name.value.len != 16) return error.InvalidIpAddress;
                if (cert.san_ip_count >= cert.san_ips.len) return error.TooManySan;
                var ip = IpAddress{ .bytes = @as([16]u8, @splat(0)), .len = @intCast(name.value.len) };
                @memcpy(ip.bytes[0..name.value.len], name.value);
                cert.san_ips[cert.san_ip_count] = ip;
                cert.san_ip_count += 1;
            },
            else => {},
        }
    }
}

const BasicConstraints = struct { ca: bool, path_len: ?u32 };

fn parseBasicConstraints(parent: DerReader, value: []const u8) Error!BasicConstraints {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();

    var seq = try inner.child(seq_tlv);
    var ca = false;
    if (seq.hasRemaining() and try seq.peekTag() == Tag.boolean) {
        ca = try parseBoolean(try seq.readTlv());
    }
    var path_len: ?u32 = null;
    if (seq.hasRemaining() and try seq.peekTag() == Tag.integer) {
        const pl = try seq.readTlv();
        try validatePositiveInteger(pl.value);
        path_len = derIntegerToU32(pl.value);
    }
    try seq.expectEmpty();
    return .{ .ca = ca, .path_len = path_len };
}

/// Decode a validated non-negative DER INTEGER body (big-endian, optional
/// leading sign byte) into a u32. An absurdly large value (>4 bytes) is clamped
/// to maxInt — a path length that big is effectively no constraint.
fn derIntegerToU32(bytes: []const u8) u32 {
    var v = bytes;
    while (v.len > 0 and v[0] == 0x00) v = v[1..];
    if (v.len == 0) return 0;
    if (v.len > 4) return std.math.maxInt(u32);
    var acc: u32 = 0;
    for (v) |b| acc = (acc << 8) | b;
    return acc;
}

test "derIntegerToU32 decodes small path-length integers" {
    try std.testing.expectEqual(@as(u32, 0), derIntegerToU32(&.{0x00}));
    try std.testing.expectEqual(@as(u32, 0), derIntegerToU32(&.{}));
    try std.testing.expectEqual(@as(u32, 5), derIntegerToU32(&.{0x05}));
    try std.testing.expectEqual(@as(u32, 200), derIntegerToU32(&.{ 0x00, 0xC8 })); // sign byte stripped
    try std.testing.expectEqual(@as(u32, 0x0102), derIntegerToU32(&.{ 0x01, 0x02 }));
    try std.testing.expectEqual(std.math.maxInt(u32), derIntegerToU32(&.{ 0x01, 0x02, 0x03, 0x04, 0x05 }));
}

fn nestedBytes(parent: DerReader, value: []const u8) Error!DerReader {
    if (parent.depth >= MaxDepth) return error.OverDepth;
    return .{ .input = value, .depth = parent.depth + 1 };
}

fn parseBoolean(tlv: Tlv) Error!bool {
    if (tlv.tag != Tag.boolean or tlv.value.len != 1) return error.InvalidBoolean;
    return switch (tlv.value[0]) {
        0x00 => false,
        0xFF => true,
        else => error.InvalidBoolean,
    };
}

fn validatePositiveInteger(value: []const u8) Error!void {
    try validateDerInteger(value);
    if ((value[0] & 0x80) != 0) return error.InvalidInteger;
}

fn validateDerInteger(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidInteger;
    if (value.len > 1) {
        if (value[0] == 0x00 and (value[1] & 0x80) == 0) return error.InvalidInteger;
        if (value[0] == 0xFF and (value[1] & 0x80) != 0) return error.InvalidInteger;
    }
}

fn parseBitString(tlv: Tlv) Error![]const u8 {
    if (tlv.tag != Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

fn validateOid(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidOid;
    var at_arc_start = true;
    var ended_arc = false;
    for (value) |byte| {
        if (at_arc_start and byte == 0x80) return error.InvalidOid;
        ended_arc = (byte & 0x80) == 0;
        at_arc_start = ended_arc;
    }
    if (!ended_arc) return error.InvalidOid;
}

fn validateDnsName(name: []const u8) Error!void {
    if (name.len == 0 or name.len > 253) return error.InvalidName;
    var label_len: usize = 0;
    for (name) |c| {
        if (c == 0 or c > 0x7F or c <= ' ' or c == 0x7F) return error.InvalidName;
        if (c == '.') {
            if (label_len == 0) return error.InvalidName;
            label_len = 0;
        } else {
            label_len += 1;
            if (label_len > 63) return error.InvalidName;
        }
    }
    if (label_len == 0) return error.InvalidName;
}

fn parseTime(tlv: Tlv) Error!Time {
    return switch (tlv.tag) {
        Tag.utc_time => parseUtcTime(tlv.value),
        Tag.generalized_time => parseGeneralizedTime(tlv.value),
        else => error.InvalidTime,
    };
}

fn parseUtcTime(bytes: []const u8) Error!Time {
    if (bytes.len != 13 or bytes[12] != 'Z') return error.InvalidTime;
    const yy = try twoDigits(bytes[0..2], 0, 99);
    const year: i32 = if (yy >= 50) 1900 + @as(i32, yy) else 2000 + @as(i32, yy);
    const month = try twoDigits(bytes[2..4], 1, 12);
    const day = try twoDigits(bytes[4..6], 1, 31);
    const hour = try twoDigits(bytes[6..8], 0, 23);
    const minute = try twoDigits(bytes[8..10], 0, 59);
    const second = try twoDigits(bytes[10..12], 0, 59);
    return .{
        .kind = .utc,
        .bytes = bytes,
        .epoch_seconds = try epochSeconds(year, month, day, hour, minute, second),
    };
}

fn parseGeneralizedTime(bytes: []const u8) Error!Time {
    if (bytes.len != 15 or bytes[14] != 'Z') return error.InvalidTime;
    const year_u16 = try fourDigits(bytes[0..4]);
    const month = try twoDigits(bytes[4..6], 1, 12);
    const day = try twoDigits(bytes[6..8], 1, 31);
    const hour = try twoDigits(bytes[8..10], 0, 23);
    const minute = try twoDigits(bytes[10..12], 0, 59);
    const second = try twoDigits(bytes[12..14], 0, 59);
    return .{
        .kind = .generalized,
        .bytes = bytes,
        .epoch_seconds = try epochSeconds(@intCast(year_u16), month, day, hour, minute, second),
    };
}

/// Convert validated `YYYYMMDDHHMMSSZ` GeneralizedTime bytes to a Unix epoch
/// second count. Callers that already hold validated GeneralizedTime slices
/// (e.g. OCSP `thisUpdate`/`nextUpdate`) use this to do freshness arithmetic
/// against a wall-clock second count without re-plumbing the private `Time`
/// struct. Rejects any input `parseGeneralizedTime` would reject.
pub fn generalizedTimeToEpoch(bytes: []const u8) Error!i64 {
    return (try parseGeneralizedTime(bytes)).epoch_seconds;
}

fn twoDigits(bytes: []const u8, min: u8, max: u8) Error!u8 {
    if (bytes.len != 2) return error.InvalidTime;
    if (!std.ascii.isDigit(bytes[0]) or !std.ascii.isDigit(bytes[1])) return error.InvalidTime;
    const value = (bytes[0] - '0') * 10 + (bytes[1] - '0');
    if (value < min or value > max) return error.InvalidTime;
    return value;
}

fn fourDigits(bytes: []const u8) Error!u16 {
    if (bytes.len != 4) return error.InvalidTime;
    var value: u16 = 0;
    for (bytes) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidTime;
        value = value * 10 + @as(u16, byte - '0');
    }
    return value;
}

fn epochSeconds(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) Error!i64 {
    const max_day = daysInMonth(year, month);
    if (day > max_day) return error.InvalidTime;

    var days: i64 = 0;
    if (year >= 1970) {
        var y: i32 = 1970;
        while (y < year) : (y += 1) {
            days += daysInYear(y);
        }
    } else {
        var y: i32 = year;
        while (y < 1970) : (y += 1) {
            days -= daysInYear(y);
        }
    }

    var m: u8 = 1;
    while (m < month) : (m += 1) {
        days += daysInMonth(year, m);
    }
    days += @as(i64, day) - 1;
    return days * 86_400 + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + second;
}

fn daysInYear(year: i32) i64 {
    return if (isLeapYear(year)) 366 else 365;
}

fn daysInMonth(year: i32, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: i32) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

fn emptyTime() Time {
    return .{ .kind = .utc, .bytes = &.{}, .epoch_seconds = 0 };
}

const TestPem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT
    \\BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz
    \\MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj
    \\GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp
    \\LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O
    \\BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf
    \\lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN
    \\Lw0=
    \\-----END CERTIFICATE-----
;

const TestDerBase64Compact =
    "MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT" ++
    "BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz" ++
    "MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj" ++
    "GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp" ++
    "LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O" ++
    "BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf" ++
    "lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN" ++
    "Lw0=";

test "parse embedded certificate and compute certfp" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    const cert = try parse(der);

    try std.testing.expect(cert.tbs_der.len > 0);
    try std.testing.expect(cert.spki_der.len > 0);
    try std.testing.expect(cert.spki_value.len > 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x2B, 0x65, 0x70 }, cert.signature_algorithm_oid);
    try std.testing.expectEqual(@as(usize, 1), cert.san_dns_count);
    // Structural SAN check (the embedded fixture's dNSName ends in ".test").
    try std.testing.expect(cert.san_dns[0].len > 0);
    try std.testing.expect(std.mem.endsWith(u8, cert.san_dns[0], ".test"));
    try std.testing.expectEqual(@as(usize, 1), cert.san_ip_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, cert.san_ips[0].slice());
    try std.testing.expect(!cert.basic_constraints_ca);
    // The fixture carries a KeyUsage extension (digitalSignature only) and no
    // ExtendedKeyUsage extension.
    try std.testing.expect(cert.key_usage_present);
    try std.testing.expect(cert.key_usage_digital_signature);
    try std.testing.expect(!cert.key_usage_cert_sign);
    try std.testing.expect(!cert.eku_present);
    try std.testing.expect(!cert.eku_server_auth);
    try std.testing.expect(!cert.eku_ocsp_signing);

    var cert_hex: [64]u8 = undefined;
    var spki_hex: [64]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        "231a5709f3e42db6130a35b75d56b45dedee32690a9e6f71bf6ad87e6707ba7a",
        try cert.certSha256Hex(&cert_hex),
    );
    try std.testing.expectEqualSlices(
        u8,
        "4d9627b687eb99707c4e16eb91705ab468c12055662837088931f27bd38b721e",
        try cert.spkiSha256Hex(&spki_hex),
    );

    var encoded: [512]u8 = undefined;
    const out = std.base64.standard.Encoder.encode(&encoded, der);
    try std.testing.expectEqualSlices(u8, TestDerBase64Compact, out);
}

test "DER reader rejects malformed TLVs" {
    var truncated = DerReader.init(&[_]u8{0x30});
    var indefinite = DerReader.init(&[_]u8{ 0x30, 0x80 });
    var non_canonical = DerReader.init(&[_]u8{ 0x04, 0x81, 0x7F });
    var unsupported = DerReader.init(&[_]u8{ 0x1F, 0x01, 0x00 });

    try std.testing.expectError(error.Truncated, truncated.readTlv());
    try std.testing.expectError(error.IndefiniteLength, indefinite.readTlv());
    try std.testing.expectError(error.NonCanonicalLength, non_canonical.readTlv());
    try std.testing.expectError(error.UnsupportedTag, unsupported.readTlv());
}

test "malformed certificates and PEM are rejected" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    try std.testing.expectError(error.Truncated, parse(der[0 .. der.len - 1]));
    try std.testing.expectError(error.PemBeginMissing, pemToDer("not a cert", &der_buf));
    try std.testing.expectError(
        error.PemInvalidBase64,
        pemToDer("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n", &der_buf),
    );
}

test "extractPublicKey recovers the Ed25519 key from the embedded SPKI" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    const cert = try parse(der);

    const key = try extractPublicKey(cert.spki_der);
    switch (key) {
        .ed25519 => |raw| {
            try std.testing.expectEqual(@as(usize, ed25519_public_key_len), raw.len);
            // The embedded fixture's SPKI key bits are the 32 bytes after the
            // BIT STRING's leading unused-bits octet.
            try std.testing.expectEqualSlices(u8, cert.spki_value[cert.spki_value.len - 32 ..], raw);
        },
        else => return error.InvalidCertificate,
    }
}

test "extractPublicKey rejects a truncated SPKI" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    const cert = try parse(der);
    try std.testing.expectError(error.Truncated, extractPublicKey(cert.spki_der[0 .. cert.spki_der.len - 1]));
}

// -- SCT extension unwrap tests ---------------------------------------------

/// Append a DER TLV (short-form length only; `value.len` must be < 128) as an
/// arena-owned slice. Sufficient for the small synthetic certificates below.
fn derTlv(a: std.mem.Allocator, tag: u8, value: []const u8) []u8 {
    std.debug.assert(value.len < 128);
    const out = a.alloc(u8, 2 + value.len) catch unreachable;
    out[0] = tag;
    out[1] = @intCast(value.len);
    @memcpy(out[2..], value);
    return out;
}

test "parseSctList peels the inner OCTET STRING to the raw TLS list bytes" {
    // Arrange: extnValue content = OCTET STRING wrapping the TLS list bytes.
    const tls_list = [_]u8{ 0x00, 0x04, 0x00, 0x02, 0xAB, 0xCD };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const extn_value = derTlv(a, Tag.octet_string, &tls_list);

    // Act
    const raw = try parseSctList(extn_value);

    // Assert
    try std.testing.expectEqualSlices(u8, &tls_list, raw);
}

test "parseSctList rejects a non-OCTET-STRING wrapper and trailing bytes" {
    // A SEQUENCE where an OCTET STRING is required.
    try std.testing.expectError(error.InvalidTag, parseSctList(&[_]u8{ 0x30, 0x02, 0xAB, 0xCD }));
    // A valid inner OCTET STRING followed by a surplus byte.
    try std.testing.expectError(error.TrailingData, parseSctList(&[_]u8{ 0x04, 0x01, 0xAA, 0x00 }));
    // Truncated length.
    try std.testing.expectError(error.Truncated, parseSctList(&[_]u8{0x04}));
}

/// Build a minimal, structurally-walkable certificate carrying exactly the
/// extensions in `ext_der` ([3] EXPLICIT SEQUENCE OF Extension). Not a valid
/// certificate for `parse` (issuer/validity/spki are empty), but enough for
/// `findSctListExtension`, which only navigates structure to the extensions.
fn buildCertWithExtensions(a: std.mem.Allocator, ext_der: []const u8) []u8 {
    const empty_seq = derTlv(a, Tag.sequence, "");
    const serial = derTlv(a, Tag.integer, &[_]u8{0x01});
    const extensions_wrapper = derTlv(a, Tag.context_3_constructed, ext_der);

    var tbs_body: std.ArrayList(u8) = .empty;
    tbs_body.appendSlice(a, serial) catch unreachable; // serialNumber
    tbs_body.appendSlice(a, empty_seq) catch unreachable; // signature
    tbs_body.appendSlice(a, empty_seq) catch unreachable; // issuer
    tbs_body.appendSlice(a, empty_seq) catch unreachable; // validity
    tbs_body.appendSlice(a, empty_seq) catch unreachable; // subject
    tbs_body.appendSlice(a, empty_seq) catch unreachable; // subjectPublicKeyInfo
    tbs_body.appendSlice(a, extensions_wrapper) catch unreachable; // [3] extensions
    const tbs = derTlv(a, Tag.sequence, tbs_body.items);

    var cert_body: std.ArrayList(u8) = .empty;
    cert_body.appendSlice(a, tbs) catch unreachable;
    cert_body.appendSlice(a, empty_seq) catch unreachable; // signatureAlgorithm
    cert_body.appendSlice(a, derTlv(a, Tag.bit_string, &[_]u8{0x00})) catch unreachable; // signatureValue
    return derTlv(a, Tag.sequence, cert_body.items);
}

test "findSctListExtension returns the TLS list bytes for an embedded SCT extension" {
    // Arrange: extension { OID sct, extnValue = OCTET STRING { OCTET STRING { tls } } }.
    const tls_list = [_]u8{ 0x00, 0x08, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const inner_octet = derTlv(a, Tag.octet_string, &tls_list);
    const extn_value = derTlv(a, Tag.octet_string, inner_octet);
    var one_ext: std.ArrayList(u8) = .empty;
    one_ext.appendSlice(a, derTlv(a, Tag.oid, &sct_list_extension_oid)) catch unreachable;
    one_ext.appendSlice(a, extn_value) catch unreachable;
    const extension = derTlv(a, Tag.sequence, one_ext.items);
    const ext_seq = derTlv(a, Tag.sequence, extension); // SEQUENCE OF Extension
    const cert = buildCertWithExtensions(a, ext_seq);

    // Act
    const found = try findSctListExtension(cert);

    // Assert
    try std.testing.expect(found != null);
    try std.testing.expectEqualSlices(u8, &tls_list, found.?);
}

test "findSctListExtension returns null when the SCT extension is absent" {
    // The embedded fixture carries SAN/basicConstraints/keyUsage/SKI, no SCT.
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    try std.testing.expectEqual(@as(?[]const u8, null), try findSctListExtension(der));

    // A different extension OID (basicConstraints) also yields null.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var one_ext: std.ArrayList(u8) = .empty;
    one_ext.appendSlice(a, derTlv(a, Tag.oid, &[_]u8{ 0x55, 0x1D, 0x13 })) catch unreachable; // basicConstraints
    one_ext.appendSlice(a, derTlv(a, Tag.octet_string, derTlv(a, Tag.sequence, ""))) catch unreachable;
    const extension = derTlv(a, Tag.sequence, one_ext.items);
    const ext_seq = derTlv(a, Tag.sequence, extension);
    const cert = buildCertWithExtensions(a, ext_seq);
    try std.testing.expectEqual(@as(?[]const u8, null), try findSctListExtension(cert));
}

test "findSctListExtension fails closed on malformed certificate DER" {
    try std.testing.expectError(error.EmptyInput, findSctListExtension(""));
    // A truncated SEQUENCE header.
    try std.testing.expectError(error.Truncated, findSctListExtension(&[_]u8{0x30}));
    // Well-formed outer SEQUENCE but the TBS is cut off before extensions.
    try std.testing.expectError(error.Truncated, findSctListExtension(&[_]u8{ 0x30, 0x02, 0x30, 0x00 }));
}

/// Build one Extension TLV with an optional critical BOOLEAN (RFC 5280 §4.2).
fn buildExtensionTlv(a: std.mem.Allocator, oid: []const u8, critical: bool, extn_value: []const u8) []u8 {
    var body: std.ArrayList(u8) = .empty;
    body.appendSlice(a, derTlv(a, Tag.oid, oid)) catch unreachable;
    if (critical) body.appendSlice(a, derTlv(a, Tag.boolean, &[_]u8{0xff})) catch unreachable;
    body.appendSlice(a, derTlv(a, Tag.octet_string, extn_value)) catch unreachable;
    return derTlv(a, Tag.sequence, body.items);
}

test "unknown critical extension fails closed during extension scan" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const unknown_oid = [_]u8{ 0x55, 0x1D, 0x63 };
    const extension = buildExtensionTlv(a, &unknown_oid, true, "");
    const ext_seq = derTlv(a, Tag.sequence, extension);
    const cert = buildCertWithExtensions(a, ext_seq);
    try std.testing.expectError(error.UnsupportedCriticalExtension, findExtensionValue(cert, &[_]u8{ 0x55, 0x1D, 0x13 }));
}

test "non-critical unknown extension is ignored during extension scan" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const unknown_oid = [_]u8{ 0x55, 0x1D, 0x64 };
    const extension = buildExtensionTlv(a, &unknown_oid, false, "");
    const ext_seq = derTlv(a, Tag.sequence, extension);
    const cert = buildCertWithExtensions(a, ext_seq);
    try std.testing.expectEqual(@as(?[]const u8, null), try findExtensionValue(cert, &[_]u8{ 0x55, 0x1D, 0x13 }));
}

// -- Precert TBS reconstruction tests ---------------------------------------

/// Append canonical minimal DER length octets for `len` (short form <128; else
/// `0x80|n` + n big-endian magnitude octets) — the same encoding `writeDerHeader`
/// emits, so an independently-built "expected" TBS is byte-comparable to the
/// reconstruction across the 127/128 long-form boundary.
fn appendDerLenTest(a: std.mem.Allocator, out: *std.ArrayList(u8), len: usize) void {
    if (len < 0x80) {
        out.append(a, @intCast(len)) catch unreachable;
        return;
    }
    var octets: usize = 0;
    var n = len;
    while (n != 0) : (n >>= 8) octets += 1;
    out.append(a, 0x80 | @as(u8, @intCast(octets))) catch unreachable;
    var i: usize = 0;
    while (i < octets) : (i += 1) {
        const shift: u6 = @intCast(8 * (octets - 1 - i));
        out.append(a, @intCast((len >> shift) & 0xff)) catch unreachable;
    }
}

/// Build one DER TLV (`tag` + canonical length + `value`) of any length.
fn derTlvAny(a: std.mem.Allocator, tag: u8, value: []const u8) []u8 {
    var out: std.ArrayList(u8) = .empty;
    out.append(a, tag) catch unreachable;
    appendDerLenTest(a, &out, value.len);
    out.appendSlice(a, value) catch unreachable;
    return out.toOwnedSlice(a) catch unreachable;
}

/// An `Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING }`.
fn buildExt(a: std.mem.Allocator, oid: []const u8, extn_value_content: []const u8) []u8 {
    var body: std.ArrayList(u8) = .empty;
    body.appendSlice(a, derTlvAny(a, Tag.oid, oid)) catch unreachable;
    body.appendSlice(a, derTlvAny(a, Tag.octet_string, extn_value_content)) catch unreachable;
    return derTlvAny(a, Tag.sequence, body.items);
}

/// The SCT-list extension carrying `tls_list` (extnValue = OCTET STRING wrapping
/// an inner OCTET STRING wrapping the TLS list bytes).
fn buildSctExt(a: std.mem.Allocator, tls_list: []const u8) []u8 {
    const inner = derTlvAny(a, Tag.octet_string, tls_list);
    return buildExt(a, &sct_list_extension_oid, inner);
}

/// A structurally valid TBSCertificate prefix (version[0], serial, signature,
/// issuer, validity, subject, spki) — the fields `buildPrecertTbs` walks past
/// and copies verbatim. Reused for both the leaf and the "expected" precert TBS.
fn buildTbsPrefix(a: std.mem.Allocator) []u8 {
    var out: std.ArrayList(u8) = .empty;
    // version [0] EXPLICIT { INTEGER v3(2) }
    out.appendSlice(a, derTlvAny(a, Tag.context_0_constructed, derTlvAny(a, Tag.integer, &[_]u8{0x02}))) catch unreachable;
    out.appendSlice(a, derTlvAny(a, Tag.integer, &[_]u8{ 0x12, 0x34 })) catch unreachable; // serialNumber
    out.appendSlice(a, derTlvAny(a, Tag.sequence, "")) catch unreachable; // signature
    out.appendSlice(a, derTlvAny(a, Tag.sequence, "")) catch unreachable; // issuer
    out.appendSlice(a, derTlvAny(a, Tag.sequence, "")) catch unreachable; // validity
    out.appendSlice(a, derTlvAny(a, Tag.sequence, "")) catch unreachable; // subject
    out.appendSlice(a, derTlvAny(a, Tag.sequence, "")) catch unreachable; // subjectPublicKeyInfo
    return out.toOwnedSlice(a) catch unreachable;
}

/// Assemble a TBSCertificate from `prefix` and an ordered list of extension TLVs
/// ([3] EXPLICIT { SEQUENCE OF Extension }).
fn buildTbs(a: std.mem.Allocator, prefix: []const u8, exts: []const []const u8) []u8 {
    var ext_content: std.ArrayList(u8) = .empty;
    for (exts) |e| ext_content.appendSlice(a, e) catch unreachable;
    const ext_seq = derTlvAny(a, Tag.sequence, ext_content.items);
    const ext3 = derTlvAny(a, Tag.context_3_constructed, ext_seq);
    var tbs_body: std.ArrayList(u8) = .empty;
    tbs_body.appendSlice(a, prefix) catch unreachable;
    tbs_body.appendSlice(a, ext3) catch unreachable;
    return derTlvAny(a, Tag.sequence, tbs_body.items);
}

/// Wrap a TBSCertificate into a full `Certificate ::= SEQUENCE { tbs, sigAlg,
/// sigValue }`. sigAlg/sigValue are placeholders; `buildPrecertTbs` ignores them.
fn wrapCert(a: std.mem.Allocator, tbs: []const u8) []u8 {
    var body: std.ArrayList(u8) = .empty;
    body.appendSlice(a, tbs) catch unreachable;
    body.appendSlice(a, derTlvAny(a, Tag.sequence, "")) catch unreachable; // signatureAlgorithm
    body.appendSlice(a, derTlvAny(a, Tag.bit_string, &[_]u8{0x00})) catch unreachable; // signatureValue
    return derTlvAny(a, Tag.sequence, body.items);
}

// basicConstraints (2.5.29.13 — a real extension OID validateOid accepts) and
// keyUsage (2.5.29.15), used as the "other" extensions preserved verbatim.
const oid_basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 };
const oid_key_usage = [_]u8{ 0x55, 0x1D, 0x0F };

test "buildPrecertTbs reproduces the exact TBS with only the SCT extension removed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const prefix = buildTbsPrefix(a);
    const ext_bc = buildExt(a, &oid_basic_constraints, derTlvAny(a, Tag.sequence, ""));
    const ext_ku = buildExt(a, &oid_key_usage, derTlvAny(a, Tag.bit_string, &[_]u8{ 0x01, 0x86 }));
    const tls_list = [_]u8{ 0x00, 0x04, 0x00, 0x02, 0xAB, 0xCD };
    const ext_sct = buildSctExt(a, &tls_list);

    // SCT in the MIDDLE — proves surrounding extensions keep their order/bytes.
    const leaf_tbs = buildTbs(a, prefix, &.{ ext_bc, ext_sct, ext_ku });
    const expected_tbs = buildTbs(a, prefix, &.{ ext_bc, ext_ku });
    const leaf_cert = wrapCert(a, leaf_tbs);

    var out: [4096]u8 = undefined;
    const got = try buildPrecertTbs(&out, leaf_cert);
    try std.testing.expectEqualSlices(u8, expected_tbs, got);
    // The reconstruction is always strictly smaller than the source TBS.
    try std.testing.expect(got.len < leaf_tbs.len);
}

test "buildPrecertTbs strips the SCT whether first or last, preserving order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const prefix = buildTbsPrefix(a);
    const ext_bc = buildExt(a, &oid_basic_constraints, derTlvAny(a, Tag.sequence, ""));
    const ext_ku = buildExt(a, &oid_key_usage, derTlvAny(a, Tag.bit_string, &[_]u8{0x03}));
    const ext_sct = buildSctExt(a, &[_]u8{ 0x00, 0x02, 0x00, 0x00 });
    const expected_tbs = buildTbs(a, prefix, &.{ ext_bc, ext_ku });

    var out: [4096]u8 = undefined;
    // SCT first.
    const first = wrapCert(a, buildTbs(a, prefix, &.{ ext_sct, ext_bc, ext_ku }));
    try std.testing.expectEqualSlices(u8, expected_tbs, try buildPrecertTbs(&out, first));
    // SCT last.
    var out2: [4096]u8 = undefined;
    const last = wrapCert(a, buildTbs(a, prefix, &.{ ext_bc, ext_ku, ext_sct }));
    try std.testing.expectEqualSlices(u8, expected_tbs, try buildPrecertTbs(&out2, last));
}

test "buildPrecertTbs re-encodes lengths across the long-form DER boundary" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const prefix = buildTbsPrefix(a);
    // A large "other" extension so the Extensions SEQUENCE (and TBS) length use
    // long-form (>127) both before and after removal — the length re-encoding is
    // exercised, and the exact-byte match validates it.
    const big_payload = try a.alloc(u8, 300);
    @memset(big_payload, 0x5A);
    const ext_big = buildExt(a, &oid_basic_constraints, big_payload);
    const ext_sct = buildSctExt(a, &[_]u8{ 0x00, 0x08, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });

    const leaf_tbs = buildTbs(a, prefix, &.{ ext_big, ext_sct });
    const expected_tbs = buildTbs(a, prefix, &.{ext_big});
    const leaf_cert = wrapCert(a, leaf_tbs);

    var out: [1024]u8 = undefined;
    const got = try buildPrecertTbs(&out, leaf_cert);
    try std.testing.expectEqualSlices(u8, expected_tbs, got);
}

test "buildPrecertTbs errors when the certificate carries no SCT extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const prefix = buildTbsPrefix(a);
    const ext_bc = buildExt(a, &oid_basic_constraints, derTlvAny(a, Tag.sequence, ""));
    const cert = wrapCert(a, buildTbs(a, prefix, &.{ext_bc}));

    var out: [1024]u8 = undefined;
    try std.testing.expectError(error.MissingField, buildPrecertTbs(&out, cert));
}

test "buildPrecertTbs reports OutputTooSmall and fails closed on malformed DER" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const prefix = buildTbsPrefix(a);
    const ext_sct = buildSctExt(a, &[_]u8{ 0x00, 0x02, 0x00, 0x00 });
    const cert = wrapCert(a, buildTbs(a, prefix, &.{ext_sct}));

    // A 4-byte output cannot hold even the TBS header.
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildPrecertTbs(&tiny, cert));

    // Malformed inputs fail closed rather than reading past the slice.
    var out: [256]u8 = undefined;
    try std.testing.expectError(error.EmptyInput, buildPrecertTbs(&out, ""));
    try std.testing.expectError(error.Truncated, buildPrecertTbs(&out, &[_]u8{0x30}));
    try std.testing.expectError(error.Truncated, buildPrecertTbs(&out, &[_]u8{ 0x30, 0x02, 0x30, 0x00 }));
}

pub const MaxCrlDistributionPointUrls = 8;

/// URLs extracted from a certificate's cRLDistributionPoints extension. The
/// slices point into the caller-owned certificate DER; the struct owns no
/// memory of its own.
pub const CrlDistributionPoints = struct {
    buf: [MaxCrlDistributionPointUrls][]const u8 = undefined,
    len: usize = 0,

    /// The extracted distribution-point URLs, in certificate order (possibly
    /// empty). Each slice is a `uniformResourceIdentifier` GeneralName value.
    pub fn urls(self: *const CrlDistributionPoints) []const []const u8 {
        return self.buf[0..self.len];
    }
};

/// Extract the cRLDistributionPoints URI(s) from `cert_der` (RFC 5280
/// §4.2.1.13, OID 2.5.29.31).
///
/// Collects every `GeneralName` of type uniformResourceIdentifier (`[6]`) found
/// in each DistributionPoint's `fullName`. `nameRelativeToCRLIssuer`, `reasons`,
/// and `cRLIssuer` are ignored — URI retrieval is the only supported fetch.
///
/// Allocation-free: returned URL slices point into `cert_der`. Returns an empty
/// set when the extension is absent; errors only on malformed DER.
pub fn parseCrlDistributionPoint(cert_der: []const u8) Error!CrlDistributionPoints {
    var result = CrlDistributionPoints{};
    const ext_value = (try findExtensionValue(cert_der, &Oid.crl_distribution_points)) orelse return result;
    try collectCrlUrls(ext_value, &result);
    return result;
}

/// Walk `cert_der` → tbsCertificate → extensions and return the raw extnValue
/// OCTET STRING content for `oid`, or null when the extension (or the entire
/// extensions block) is absent.
fn findExtensionValue(cert_der: []const u8, oid: []const u8) Error!?[]const u8 {
    if (cert_der.len == 0) return error.EmptyInput;
    if (cert_der.len > MaxDerLen) return error.Oversize;

    var top = DerReader.init(cert_der);
    const cert_seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(Tag.sequence);
    var tbs_reader = try body.child(tbs);

    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == Tag.context_0_constructed) {
        _ = try tbs_reader.readTlv(); // version [0] EXPLICIT
    }
    _ = try tbs_reader.readExpected(Tag.integer); // serialNumber
    _ = try tbs_reader.readExpected(Tag.sequence); // signature
    _ = try tbs_reader.readExpected(Tag.sequence); // issuer
    _ = try tbs_reader.readExpected(Tag.sequence); // validity
    _ = try tbs_reader.readExpected(Tag.sequence); // subject
    _ = try tbs_reader.readExpected(Tag.sequence); // subjectPublicKeyInfo

    while (tbs_reader.hasRemaining()) {
        const tag = try tbs_reader.peekTag();
        switch (tag) {
            0x81, 0x82 => _ = try tbs_reader.readTlv(), // issuer/subject UniqueID
            Tag.context_3_constructed => return try scanExtensionsFor(tbs_reader, try tbs_reader.readTlv(), oid),
            else => return error.InvalidTag,
        }
    }
    return null;
}

fn scanExtensionsFor(parent: DerReader, ext_tlv: Tlv, oid: []const u8) Error!?[]const u8 {
    var explicit = try parent.child(ext_tlv);
    const seq_tlv = try explicit.readExpected(Tag.sequence);
    try explicit.expectEmpty();

    var extensions = try explicit.child(seq_tlv);
    while (extensions.hasRemaining()) {
        const one_tlv = try extensions.readExpected(Tag.sequence);
        var one = try extensions.child(one_tlv);
        const oid_tlv = try one.readExpected(Tag.oid);
        try validateOid(oid_tlv.value);
        const critical = try readExtensionCriticalField(&one);
        const value = try one.readExpected(Tag.octet_string);
        try one.expectEmpty();
        try rejectUnsupportedCriticalExtension(critical, oid_tlv.value);
        if (std.mem.eql(u8, oid_tlv.value, oid)) return value.value;
    }
    return null;
}

/// Parse a cRLDistributionPoints extnValue: `SEQUENCE OF DistributionPoint`.
fn collectCrlUrls(ext_value: []const u8, out: *CrlDistributionPoints) Error!void {
    var reader = DerReader.init(ext_value);
    const dps_tlv = try reader.readExpected(Tag.sequence);
    try reader.expectEmpty();

    var dps = try reader.child(dps_tlv);
    while (dps.hasRemaining()) {
        const dp_tlv = try dps.readExpected(Tag.sequence); // DistributionPoint
        var dp = try dps.child(dp_tlv);
        // distributionPoint [0] EXPLICIT DistributionPointName (a CHOICE, so the
        // [0] tag is explicit). reasons [1] / cRLIssuer [2] are ignored.
        if (dp.hasRemaining() and try dp.peekTag() == Tag.context_0_constructed) {
            try collectDistributionPointName(dp, try dp.readTlv(), out);
        }
    }
}

fn collectDistributionPointName(parent: DerReader, dpn_tlv: Tlv, out: *CrlDistributionPoints) Error!void {
    var dpn = try parent.child(dpn_tlv);
    while (dpn.hasRemaining()) {
        const tag = try dpn.peekTag();
        const tlv = try dpn.readTlv();
        // fullName [0] IMPLICIT GeneralNames (the SEQUENCE tag becomes 0xA0).
        // nameRelativeToCRLIssuer [1] and anything else is skipped.
        if (tag == Tag.context_0_constructed) {
            try collectUriGeneralNames(dpn, tlv, out);
        }
    }
}

fn collectUriGeneralNames(parent: DerReader, names_tlv: Tlv, out: *CrlDistributionPoints) Error!void {
    var names = try parent.child(names_tlv);
    while (names.hasRemaining()) {
        const gn = try names.readTlv();
        // uniformResourceIdentifier [6] IMPLICIT IA5String → context-primitive 0x86.
        if (gn.tag == 0x86 and out.len < out.buf.len) {
            out.buf[out.len] = gn.value;
            out.len += 1;
        }
    }
}

test "parseCrlDistributionPoint extracts fullName URI GeneralNames" {
    const a = std.testing.allocator;
    const url1 = "http://crl.example.com/root.crl";
    const url2 = "http://backup.example.com/root.crl";
    const url3 = "http://crl2.example.com/root.crl";

    // DistributionPoint #1: fullName holds two URIs.
    var gnames1: std.ArrayList(u8) = .empty;
    defer gnames1.deinit(a);
    try cdpTestTlv(a, &gnames1, 0x86, url1);
    try cdpTestTlv(a, &gnames1, 0x86, url2);
    var full1: std.ArrayList(u8) = .empty;
    defer full1.deinit(a);
    try cdpTestTlv(a, &full1, Tag.context_0_constructed, gnames1.items); // fullName [0]
    var dist1: std.ArrayList(u8) = .empty;
    defer dist1.deinit(a);
    try cdpTestTlv(a, &dist1, Tag.context_0_constructed, full1.items); // distributionPoint [0] EXPLICIT
    var dp1: std.ArrayList(u8) = .empty;
    defer dp1.deinit(a);
    try cdpTestTlv(a, &dp1, Tag.sequence, dist1.items);

    // DistributionPoint #2: fullName holds one URI.
    var gnames2: std.ArrayList(u8) = .empty;
    defer gnames2.deinit(a);
    try cdpTestTlv(a, &gnames2, 0x86, url3);
    var full2: std.ArrayList(u8) = .empty;
    defer full2.deinit(a);
    try cdpTestTlv(a, &full2, Tag.context_0_constructed, gnames2.items);
    var dist2: std.ArrayList(u8) = .empty;
    defer dist2.deinit(a);
    try cdpTestTlv(a, &dist2, Tag.context_0_constructed, full2.items);
    var dp2: std.ArrayList(u8) = .empty;
    defer dp2.deinit(a);
    try cdpTestTlv(a, &dp2, Tag.sequence, dist2.items);

    var dps: std.ArrayList(u8) = .empty; // CRLDistributionPoints
    defer dps.deinit(a);
    try dps.appendSlice(a, dp1.items);
    try dps.appendSlice(a, dp2.items);
    var crl_dps: std.ArrayList(u8) = .empty;
    defer crl_dps.deinit(a);
    try cdpTestTlv(a, &crl_dps, Tag.sequence, dps.items);

    var extn_value: std.ArrayList(u8) = .empty;
    defer extn_value.deinit(a);
    try cdpTestTlv(a, &extn_value, Tag.octet_string, crl_dps.items);

    var ext_body: std.ArrayList(u8) = .empty;
    defer ext_body.deinit(a);
    try cdpTestTlv(a, &ext_body, Tag.oid, &Oid.crl_distribution_points);
    try ext_body.appendSlice(a, extn_value.items);
    var ext: std.ArrayList(u8) = .empty;
    defer ext.deinit(a);
    try cdpTestTlv(a, &ext, Tag.sequence, ext_body.items);
    var exts: std.ArrayList(u8) = .empty;
    defer exts.deinit(a);
    try cdpTestTlv(a, &exts, Tag.sequence, ext.items);
    var ext3: std.ArrayList(u8) = .empty;
    defer ext3.deinit(a);
    try cdpTestTlv(a, &ext3, Tag.context_3_constructed, exts.items); // extensions [3]

    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(a);
    try cdpTestSkeletonFields(a, &tbs_body);
    try tbs_body.appendSlice(a, ext3.items);

    var cert: std.ArrayList(u8) = .empty;
    defer cert.deinit(a);
    try cdpTestCert(a, &cert, tbs_body.items);

    const cdp = try parseCrlDistributionPoint(cert.items);
    const got = cdp.urls();
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try std.testing.expectEqualStrings(url1, got[0]);
    try std.testing.expectEqualStrings(url2, got[1]);
    try std.testing.expectEqualStrings(url3, got[2]);
}

test "parseCrlDistributionPoint returns empty when the extension is absent" {
    const a = std.testing.allocator;
    // A TBS with no extensions block at all.
    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(a);
    try cdpTestSkeletonFields(a, &tbs_body);

    var cert: std.ArrayList(u8) = .empty;
    defer cert.deinit(a);
    try cdpTestCert(a, &cert, tbs_body.items);

    const cdp = try parseCrlDistributionPoint(cert.items);
    try std.testing.expectEqual(@as(usize, 0), cdp.urls().len);
}

test "parseCrlDistributionPoint ignores unrelated extensions" {
    const a = std.testing.allocator;
    // An extensions block that carries only basicConstraints (2.5.29.19).
    var ext_body: std.ArrayList(u8) = .empty;
    defer ext_body.deinit(a);
    try cdpTestTlv(a, &ext_body, Tag.oid, &Oid.basic_constraints);
    try cdpTestTlv(a, &ext_body, Tag.octet_string, &[_]u8{ 0x30, 0x00 }); // empty BasicConstraints SEQ
    var ext: std.ArrayList(u8) = .empty;
    defer ext.deinit(a);
    try cdpTestTlv(a, &ext, Tag.sequence, ext_body.items);
    var exts: std.ArrayList(u8) = .empty;
    defer exts.deinit(a);
    try cdpTestTlv(a, &exts, Tag.sequence, ext.items);
    var ext3: std.ArrayList(u8) = .empty;
    defer ext3.deinit(a);
    try cdpTestTlv(a, &ext3, Tag.context_3_constructed, exts.items);

    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(a);
    try cdpTestSkeletonFields(a, &tbs_body);
    try tbs_body.appendSlice(a, ext3.items);

    var cert: std.ArrayList(u8) = .empty;
    defer cert.deinit(a);
    try cdpTestCert(a, &cert, tbs_body.items);

    const cdp = try parseCrlDistributionPoint(cert.items);
    try std.testing.expectEqual(@as(usize, 0), cdp.urls().len);
}
fn cdpTestLen(a: std.mem.Allocator, out: *std.ArrayList(u8), len: usize) !void {
    if (len < 128) {
        try out.append(a, @intCast(len));
        return;
    }
    var tmp: [@sizeOf(usize)]u8 = undefined;
    var n = len;
    var count: usize = 0;
    while (n != 0) : (n >>= 8) {
        tmp[tmp.len - 1 - count] = @intCast(n & 0xff);
        count += 1;
    }
    try out.append(a, 0x80 | @as(u8, @intCast(count)));
    try out.appendSlice(a, tmp[tmp.len - count ..]);
}

fn cdpTestTlv(a: std.mem.Allocator, out: *std.ArrayList(u8), tag: u8, value: []const u8) !void {
    try out.append(a, tag);
    try cdpTestLen(a, out, value.len);
    try out.appendSlice(a, value);
}

/// Wrap `tbs_body` (the bytes inside tbsCertificate) into a minimal
/// `SEQUENCE { tbsCertificate, sigAlg, signature }` shell. Only the
/// tbsCertificate is meaningful to `parseCrlDistributionPoint`.
fn cdpTestCert(a: std.mem.Allocator, out: *std.ArrayList(u8), tbs_body: []const u8) !void {
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(a);
    try cdpTestTlv(a, &tbs, Tag.sequence, tbs_body);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try body.appendSlice(a, tbs.items);
    // Trivial (unread) sigAlg + signature to keep a cert-shaped structure.
    try cdpTestTlv(a, &body, Tag.sequence, &Oid.crl_distribution_points);
    try cdpTestTlv(a, &body, Tag.bit_string, &[_]u8{0x00});

    try cdpTestTlv(a, out, Tag.sequence, body.items);
}

/// Five empty placeholder SEQUENCEs: signature, issuer, validity, subject, spki.
fn cdpTestSkeletonFields(a: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try cdpTestTlv(a, out, Tag.integer, &[_]u8{0x01}); // serialNumber
    var i: usize = 0;
    while (i < 5) : (i += 1) try cdpTestTlv(a, out, Tag.sequence, "");
}

test "exploit: NameConstraints iPAddress and non-zero minimum set unsupported form" {
    // SEQUENCE { permittedSubtrees [0] IMPLICIT GeneralSubtrees }
    // [0] content is GeneralSubtree items directly (not a nested SEQUENCE OF).
    const ip_nc = [_]u8{
        0x30, 0x0a, 0xa0, 0x08, 0x30, 0x06, 0x87, 0x04, 0xc0, 0x00, 0x02, 0x01,
    };
    var ip_cert = std.mem.zeroes(Certificate);
    try parseNameConstraints(Certificate, &ip_cert, DerReader.init(&ip_nc), &ip_nc);
    try std.testing.expect(ip_cert.name_constraints_present);
    try std.testing.expect(ip_cert.nc_unsupported_name_form);
    try std.testing.expectEqual(@as(usize, 0), ip_cert.nc_permitted_dns_count);

    // dNSName plus minimum [0] INTEGER 1 — RFC 5280 forbids a non-zero minimum.
    const min_nc = [_]u8{
        0x30, 0x0c, 0xa0, 0x0a, 0x30, 0x08, 0x82, 0x03, 'a', '.', 'b', 0x80, 0x01, 0x01,
    };
    var min_cert = std.mem.zeroes(Certificate);
    try parseNameConstraints(Certificate, &min_cert, DerReader.init(&min_nc), &min_nc);
    try std.testing.expect(min_cert.name_constraints_present);
    try std.testing.expect(min_cert.nc_unsupported_name_form);
    try std.testing.expectEqual(@as(usize, 1), min_cert.nc_permitted_dns_count);
}
