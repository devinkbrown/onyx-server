// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! X.509 verification helpers for TLS and CERTFP plumbing.
//!
//! This module consumes the local strict DER parser in x509.zig, computes
//! CERTFP values, checks parsed validity windows, and verifies certificate
//! chains. Chain verification is cryptographic, not merely structural: each
//! certificate's signature is checked against its issuer's public key using the
//! project's own signature primitives (RSA PKCS#1 v1.5, ECDSA P-256, Ed25519).
//!
//! ## Trust-anchor stance
//!
//! `verifySimpleChain` guarantees **cryptographic chain integrity to a
//! self-signed root**: every certificate `chain[i]` is signed by `chain[i+1]`,
//! the issuer/subject distinguished names link, and the final certificate is
//! self-issued with a signature that verifies under its own embedded key. It
//! does NOT by itself establish trust — a self-signed root verifying its own
//! signature proves only that the chain is internally consistent, not that the
//! root is one the caller chose to trust.
//!
//! The CALLER must still enforce:
//!   * **Anchoring** — that the self-signed root (or a pinned leaf) is actually
//!     trusted, e.g. by matching it against a configured CA set, or by
//!     CertFP/SPKI pinning. `tls_client.zig`'s `verifyChainToTrustAnchors`
//!     performs the configured-anchor form for the outbound/admin TLS client.
//!   * **Naming** — that a leaf's SAN matches the expected hostname.
//!
//! This module is used for OUTBOUND/admin CA-chain verification. It is
//! deliberately independent of CertFP-based SASL EXTERNAL, which authenticates a
//! client by its certificate fingerprint and does not consult chain validity.
const std = @import("std");
const hash = @import("hash.zig");
const x509 = @import("x509.zig");
const rsa_verify = @import("rsa_verify.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const ed25519 = @import("sign.zig");
const ml_dsa = @import("ml_dsa.zig");
const slh_dsa = @import("slh_dsa.zig");

/// std ECDSA over P-384 with SHA-384. Used only for the ecdsa-with-SHA384 chain
/// branch, whose P-384 issuer key is parsed straight from the SPKI (see
/// `verifyEcdsaP384`) — `x509.extractPublicKey`/`SubjectPublicKey` deliberately
/// do not model P-384 (adding a union member has broad blast radius).
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

/// id-ecPublicKey (1.2.840.10045.2.1) — the SPKI algorithm OID for EC keys.
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
/// secp384r1 / ansip384r1 (1.3.132.0.34) — the EC named-curve parameter OID.
const oid_secp384r1 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };

pub const Digest = hash.Sha256.Digest;
pub const digest_len = hash.Sha256.digest_len;

pub const Error = x509.Error || error{
    NotYetValid,
    Expired,
    EmptyChain,
    IssuerMismatch,
    NotSelfSigned,
    MissingSignature,
    /// The signature algorithm OID is not one this verifier supports.
    UnsupportedSigAlg,
    /// A certificate's signature did not verify under its issuer's public key,
    /// or the signature/key encoding was malformed.
    BadSignature,
    /// A structural chain-policy violation: a non-CA or non-signing issuer, a
    /// NameConstraints exclusion/omission, or a pathLenConstraint breach. Shared
    /// by `enforceNameConstraints`/`enforcePathLen` below, and by the TLS 1.3
    /// and hardened TLS 1.2 clients' own leaf/issuer policy checks.
    BadCertificate,
};

/// Signature-algorithm OIDs found in a certificate's outer AlgorithmIdentifier.
const SigOid = struct {
    /// sha256WithRSAEncryption (1.2.840.113549.1.1.11).
    const rsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
    /// sha384WithRSAEncryption (1.2.840.113549.1.1.12).
    const rsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
    /// sha512WithRSAEncryption (1.2.840.113549.1.1.13).
    const rsa_sha512 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
    /// id-RSASSA-PSS (1.2.840.113549.1.1.10). Unlike the sha*WithRSAEncryption
    /// OIDs, this one does NOT name the hash/salt — those live in the
    /// AlgorithmIdentifier `parameters` (RSASSA-PSS-params) and must be parsed.
    const rsassa_pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
    /// ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    const ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    /// ecdsa-with-SHA384 (1.2.840.10045.4.3.3) — signed by a P-384 issuer key.
    const ecdsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
    /// id-Ed25519 (1.3.101.112).
    const ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };
    /// id-ML-DSA-44 (2.16.840.1.101.3.4.3.17). See id-ML-DSA-65 below.
    const ml_dsa_44 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
    /// id-ML-DSA-65 (2.16.840.1.101.3.4.3.18). Like Ed25519, this OID names no
    /// hash/params — ML-DSA signs the message directly and the certificate's
    /// signatureAlgorithm carries an absent parameters field
    /// (draft-ietf-lamps-dilithium-certificates).
    const ml_dsa_65 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
    /// id-ML-DSA-87 (2.16.840.1.101.3.4.3.19). See id-ML-DSA-65 above.
    const ml_dsa_87 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };
};

/// One SLH-DSA parameter set for the certificate-signature dispatch table. Like
/// ML-DSA, the id-slh-dsa-* OID names no hash/params — SLH-DSA signs the message
/// directly and the certificate's signatureAlgorithm carries an absent parameters
/// field (draft-ietf-lamps-x509-slhdsa). The verify context is empty for X.509.
const SlhDsaSet = struct {
    /// Full 9-byte OID, 2.16.840.1.101.3.4.3.{20..31}.
    oid: [9]u8,
    /// Raw public-key length (PK.seed ‖ PK.root = 2n).
    pk_len: usize,
    verify: *const fn (pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool,
};

fn slhOid(suffix: u8) [9]u8 {
    return x509.slh_dsa_oid_prefix ++ [_]u8{suffix};
}

/// All 12 standardized SLH-DSA parameter sets (FIPS 205), verify-only,
/// KAT-verified against independent NIST ACVP FIPS 205 sigVer vectors.
const slh_dsa_sets = [_]SlhDsaSet{
    .{ .oid = slhOid(0x14), .pk_len = 32, .verify = &slh_dsa.Sha2_128s.verify },
    .{ .oid = slhOid(0x15), .pk_len = 32, .verify = &slh_dsa.Sha2_128f.verify },
    .{ .oid = slhOid(0x16), .pk_len = 48, .verify = &slh_dsa.Sha2_192s.verify },
    .{ .oid = slhOid(0x17), .pk_len = 48, .verify = &slh_dsa.Sha2_192f.verify },
    .{ .oid = slhOid(0x18), .pk_len = 64, .verify = &slh_dsa.Sha2_256s.verify },
    .{ .oid = slhOid(0x19), .pk_len = 64, .verify = &slh_dsa.Sha2_256f.verify },
    .{ .oid = slhOid(0x1A), .pk_len = 32, .verify = &slh_dsa.Shake_128s.verify },
    .{ .oid = slhOid(0x1B), .pk_len = 32, .verify = &slh_dsa.Shake_128f.verify },
    .{ .oid = slhOid(0x1C), .pk_len = 48, .verify = &slh_dsa.Shake_192s.verify },
    .{ .oid = slhOid(0x1D), .pk_len = 48, .verify = &slh_dsa.Shake_192f.verify },
    .{ .oid = slhOid(0x1E), .pk_len = 64, .verify = &slh_dsa.Shake_256s.verify },
    .{ .oid = slhOid(0x1F), .pk_len = 64, .verify = &slh_dsa.Shake_256f.verify },
};

pub const LinkInfo = struct {
    subject_der: []const u8,
    issuer_der: []const u8,
    signature_der: []const u8,
    /// The signed TBSCertificate bytes (the message the signature covers).
    tbs_der: []const u8,
    /// The outer signatureAlgorithm OID identifying the signature scheme.
    sig_alg_oid: []const u8,
    /// The raw AlgorithmIdentifier `parameters` TLV that follows the OID in the
    /// outer signatureAlgorithm, or `null` when absent. Required for RSASSA-PSS,
    /// whose hash/MGF/salt are carried here rather than in the OID.
    sig_alg_params: ?[]const u8,
    /// This certificate's own SubjectPublicKeyInfo (the full SEQUENCE).
    spki_der: []const u8,

    pub fn isSelfIssued(self: LinkInfo) bool {
        return std.mem.eql(u8, self.subject_der, self.issuer_der);
    }

    pub fn hasSignature(self: LinkInfo) bool {
        return self.signature_der.len != 0;
    }
};

pub fn certfp(der: []const u8) Error!Digest {
    const cert = try x509.parse(der);
    return cert.certSha256();
}

pub fn certfpHex(der: []const u8, out: []u8) Error![]const u8 {
    if (out.len < digest_len * 2) return error.OutputTooSmall;
    const digest = try certfp(der);
    return x509.writeHex(&digest, out);
}

pub fn certfpEqual(a: *const Digest, b: *const Digest) bool {
    var diff: u8 = 0;
    for (a.*, b.*) |left, right| {
        diff |= left ^ right;
    }
    return diff == 0;
}

pub fn certfpMatchesDer(der: []const u8, expected: *const Digest) Error!bool {
    const actual = try certfp(der);
    return certfpEqual(&actual, expected);
}

pub fn validateParsedAt(cert: x509.Certificate, now_epoch_seconds: i64) Error!void {
    if (now_epoch_seconds < cert.not_before.epoch_seconds) return error.NotYetValid;
    if (now_epoch_seconds > cert.not_after.epoch_seconds) return error.Expired;
}

pub fn validateDerAt(der: []const u8, now_epoch_seconds: i64) Error!void {
    const cert = try x509.parse(der);
    return validateParsedAt(cert, now_epoch_seconds);
}

pub fn linkInfo(der: []const u8) Error!LinkInfo {
    _ = try x509.parse(der);
    return extractLinkInfo(der);
}

pub fn verifySelfSigned(der: []const u8) Error!void {
    const info = try linkInfo(der);
    try requireSignature(info);
    if (!info.isSelfIssued()) return error.NotSelfSigned;
    // A self-signed certificate must verify under its own embedded key.
    try verifySignedBy(info, info);
}

/// Verify a leaf-first certificate chain.
///
/// In addition to the structural issuer/subject DN linkage, this verifies each
/// certificate's signature against the public key of its issuer:
///   * `chain[i]` is signed by `chain[i+1]` (the next certificate toward the
///     root), and
///   * the final certificate is self-issued and its signature verifies under
///     its OWN embedded key (a self-signed root).
///
/// A broken signature, a DN that does not link, or a missing/self-non-issued
/// tail rejects the whole chain. See the module header for what callers must
/// still enforce (anchoring and naming).
pub fn verifySimpleChain(chain_der: []const []const u8) Error!void {
    if (chain_der.len == 0) return error.EmptyChain;

    var previous = try linkInfo(chain_der[0]);
    try requireSignature(previous);

    if (chain_der.len == 1) {
        if (!previous.isSelfIssued()) return error.NotSelfSigned;
        // The lone certificate is a self-signed root; verify its self-signature.
        try verifySignedBy(previous, previous);
        return;
    }

    for (chain_der[1..]) |issuer_der| {
        const issuer = try linkInfo(issuer_der);
        try requireSignature(issuer);
        if (!std.mem.eql(u8, previous.issuer_der, issuer.subject_der)) {
            return error.IssuerMismatch;
        }
        // The child's signature must verify under the issuer's public key.
        try verifySignedBy(previous, issuer);
        previous = issuer;
    }

    // The chain tip must be a self-signed root with a verifying self-signature.
    if (!previous.isSelfIssued()) return error.NotSelfSigned;
    try verifySignedBy(previous, previous);
}

/// Verify that `child`'s TBS bytes were signed by the holder of `issuer`'s key.
///
/// Public so external chain verifiers (e.g. the TLS 1.2/1.3 clients' trust-anchor
/// checks) can delegate the signature primitive here and inherit the full sig-alg
/// set — RSA PKCS#1 SHA-256/384/512, RSASSA-PSS, ECDSA P-256/P-384, Ed25519 —
/// instead of re-implementing a narrower dispatch. Both `LinkInfo`s come from
/// `linkInfo`.
pub fn verifySignedBy(child: LinkInfo, issuer: LinkInfo) Error!void {
    try verifyCertSignature(child.tbs_der, child.signature_der, child.sig_alg_oid, child.sig_alg_params, issuer.spki_der);
}

pub fn verifySimpleChainAt(chain_der: []const []const u8, now_epoch_seconds: i64) Error!void {
    for (chain_der) |der| {
        try validateDerAt(der, now_epoch_seconds);
    }
    return verifySimpleChain(chain_der);
}

/// Validate the daemon's OWN leaf-first server certificate chain at load.
///
/// A server presents `chain[0]` (its leaf) plus any issuing intermediates as
/// opaque DER for the *client* to anchor at a trusted root. It therefore must
/// NOT be held to `verifySimpleChain`'s client-anchoring rules: a real CA-issued
/// server chain never ships a self-signed root (`NotSelfSigned`), and its
/// issuing intermediate may use a key type/curve the server does not itself sign
/// with — e.g. a P-384 Let's Encrypt intermediate — which `verifySimpleChain`
/// would reject as `UnsupportedKey` while verifying the leaf→issuer signature.
///
/// So validate only what the server actually owns: the LEAF must parse and be
/// within its validity window. Intermediates are relayed verbatim and never
/// key-parsed here; the matching signing key is verified separately at load.
pub fn validateServerChainAt(chain_der: []const []const u8, now_epoch_seconds: i64) Error!void {
    if (chain_der.len == 0) return error.EmptyChain;
    try validateDerAt(chain_der[0], now_epoch_seconds);
}

/// One certificate's inputs to path-length checking. `path_len` is its
/// basicConstraints pathLenConstraint (null = absent); `self_issued` is
/// subject DN == issuer DN. Shared by the TLS 1.3 and hardened TLS 1.2
/// clients' `verifyChainToTrustAnchors` (see `enforcePathLen` below) so the
/// two engines cannot silently diverge on path-length enforcement.
pub const CaPathFact = struct { path_len: ?u32, self_issued: bool };

/// RFC 5280 §4.2.1.10 / §6.1.4(m): pathLenConstraint enforcement. `facts[0]`
/// is the leaf; `facts[1..]` are the CAs from the leaf toward the trust
/// anchor. A CA's pathLenConstraint bounds the number of NON-self-issued
/// intermediate CAs strictly between it and the leaf. This per-CA check is
/// equivalent to the RFC's running-budget algorithm.
pub fn enforcePathLen(facts: []const CaPathFact) Error!void {
    var ci: usize = 1;
    while (ci < facts.len) : (ci += 1) {
        const limit = facts[ci].path_len orelse continue;
        var below: u32 = 0;
        var bi: usize = 1;
        while (bi < ci) : (bi += 1) {
            if (!facts[bi].self_issued) below += 1;
        }
        if (below > limit) return error.BadCertificate;
    }
}

/// Reduce a leaf-first DER chain into `enforcePathLen`'s per-certificate
/// facts, writing at most `out.len` entries and returning the count written.
/// A certificate that fails to parse degrades to `{null, false}` for this
/// check only (the chain's signature/DN linkage is verified elsewhere; this
/// reduction only feeds pathLenConstraint enforcement).
pub fn buildPathFacts(chain: []const []const u8, out: []CaPathFact) usize {
    const n = @min(chain.len, out.len);
    for (chain[0..n], 0..) |der, idx| {
        const path_len = if (x509.parse(der)) |p| p.basic_constraints_path_len else |_| null;
        const self_issued = if (linkInfo(der)) |info| info.isSelfIssued() else |_| false;
        out[idx] = .{ .path_len = path_len, .self_issued = self_issued };
    }
    return n;
}

/// Enforce an issuing CA's NameConstraints (dNSName) against the leaf's SAN
/// dNSNames (RFC 5280 §4.2.1.10). Each leaf name must match no excluded
/// subtree and, when permitted dNSName subtrees exist, at least one permitted
/// subtree. Shared by the TLS 1.3 and hardened TLS 1.2 clients so a
/// name-constrained CA in the anchor set is enforced identically by both —
/// previously the TLS 1.2 client omitted this check entirely, letting a
/// name-constrained sub-CA mint an out-of-scope leaf that TLS 1.3 correctly
/// rejected but TLS 1.2 silently accepted.
pub fn enforceNameConstraints(issuer: x509.Certificate, leaf: x509.Certificate) Error!void {
    if (!issuer.name_constraints_present) return;
    // RFC 5280 §4.2.1.10: a constraint we cannot match (iPAddress, rfc822Name,
    // directoryName, URI, or a non-zero minimum / present maximum) must not be
    // ignored — otherwise a name-constrained CA can mint an out-of-scope IP
    // or mailbox that this DNS-only matcher would silently accept.
    if (issuer.nc_unsupported_name_form) return error.BadCertificate;
    var li: usize = 0;
    while (li < leaf.san_dns_count) : (li += 1) {
        const name = leaf.san_dns[li];
        var ei: usize = 0;
        while (ei < issuer.nc_excluded_dns_count) : (ei += 1) {
            if (dnsConstraintMatches(issuer.nc_excluded_dns[ei], name)) return error.BadCertificate;
        }
        if (issuer.nc_permitted_dns_count > 0) {
            var ok = false;
            var pi: usize = 0;
            while (pi < issuer.nc_permitted_dns_count) : (pi += 1) {
                if (dnsConstraintMatches(issuer.nc_permitted_dns[pi], name)) {
                    ok = true;
                    break;
                }
            }
            if (!ok) return error.BadCertificate;
        }
    }
}

/// dNSName name-constraint match (RFC 5280): the constraint matches the name
/// and any name with additional left-hand labels. An empty constraint matches
/// all; a leading-dot constraint matches strict subdomains only.
fn dnsConstraintMatches(constraint: []const u8, name: []const u8) bool {
    if (constraint.len == 0) return true;
    if (constraint[0] == '.') return asciiEndsWithIgnoreCase(name, constraint);
    if (asciiEqlIgnoreCase(name, constraint)) return true;
    // name == "<labels>." ++ constraint
    if (name.len > constraint.len + 1 and
        name[name.len - constraint.len - 1] == '.' and
        asciiEqlIgnoreCase(name[name.len - constraint.len ..], constraint))
    {
        return true;
    }
    return false;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn asciiEndsWithIgnoreCase(name: []const u8, suffix: []const u8) bool {
    if (name.len < suffix.len) return false;
    return asciiEqlIgnoreCase(name[name.len - suffix.len ..], suffix);
}

test "enforcePathLen: pathLenConstraint bounds intermediates below a CA" {
    const F = CaPathFact;
    // Normal chain [leaf, R3(pathLen:0), root]: 0 intermediates below R3 — OK.
    try enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 0, .self_issued = false },
    });
    // [leaf, subCA, root(pathLen:0)]: subCA is a non-self-issued intermediate
    // below the pathLen:0 root — REJECT.
    try std.testing.expectError(error.BadCertificate, enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 0, .self_issued = false },
    }));
    // pathLen:1 permits exactly one intermediate below.
    try enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 1, .self_issued = false },
    });
    // Two intermediates below a pathLen:1 CA — REJECT.
    try std.testing.expectError(error.BadCertificate, enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 1, .self_issued = false },
    }));
    // A self-issued (cross-signed) intermediate is exempt from the count.
    try enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = true },
        .{ .path_len = 0, .self_issued = false },
    });
}

test "dnsConstraintMatches follows RFC 5280 subtree rules" {
    try std.testing.expect(dnsConstraintMatches("example.com", "example.com"));
    try std.testing.expect(dnsConstraintMatches("example.com", "host.example.com"));
    try std.testing.expect(dnsConstraintMatches("example.com", "a.b.example.com"));
    try std.testing.expect(!dnsConstraintMatches("example.com", "notexample.com"));
    try std.testing.expect(!dnsConstraintMatches("example.com", "example.com.evil.com"));
    try std.testing.expect(!dnsConstraintMatches("example.com", "other.com"));
    // Empty constraint matches everything; leading-dot matches subdomains only.
    try std.testing.expect(dnsConstraintMatches("", "anything.test"));
    try std.testing.expect(dnsConstraintMatches(".example.com", "host.example.com"));
    try std.testing.expect(!dnsConstraintMatches(".example.com", "example.com"));
}

test "enforceNameConstraints applies permitted + excluded dNSName subtrees" {
    var issuer = std.mem.zeroes(x509.Certificate);
    issuer.name_constraints_present = true;
    issuer.nc_permitted_dns[0] = "example.com";
    issuer.nc_permitted_dns_count = 1;
    issuer.nc_excluded_dns[0] = "bad.example.com";
    issuer.nc_excluded_dns_count = 1;

    var leaf = std.mem.zeroes(x509.Certificate);
    leaf.san_dns_count = 1;

    leaf.san_dns[0] = "host.example.com"; // permitted, not excluded
    try enforceNameConstraints(issuer, leaf);

    leaf.san_dns[0] = "host.other.com"; // outside the permitted subtree
    try std.testing.expectError(error.BadCertificate, enforceNameConstraints(issuer, leaf));

    leaf.san_dns[0] = "bad.example.com"; // excluded wins over permitted
    try std.testing.expectError(error.BadCertificate, enforceNameConstraints(issuer, leaf));

    // A CA without NameConstraints imposes nothing.
    const plain = std.mem.zeroes(x509.Certificate);
    leaf.san_dns[0] = "anything.test";
    try enforceNameConstraints(plain, leaf);
}

test "exploit: NameConstraints with an unenforced name form fail closed" {
    var issuer = std.mem.zeroes(x509.Certificate);
    issuer.name_constraints_present = true;
    issuer.nc_unsupported_name_form = true;
    issuer.nc_permitted_dns[0] = "example.com";
    issuer.nc_permitted_dns_count = 1;

    var leaf = std.mem.zeroes(x509.Certificate);
    leaf.san_dns[0] = "host.example.com";
    leaf.san_dns_count = 1;
    try std.testing.expectError(error.BadCertificate, enforceNameConstraints(issuer, leaf));
}

fn requireSignature(info: LinkInfo) Error!void {
    if (!info.hasSignature()) return error.MissingSignature;
}

fn extractLinkInfo(der: []const u8) x509.Error!LinkInfo {
    var top = x509.DerReader.init(der);
    const cert_seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(x509.Tag.sequence);
    const sig_alg_seq = try body.readExpected(x509.Tag.sequence);
    const signature = try body.readExpected(x509.Tag.bit_string);
    try body.expectEmpty();

    const sig_alg = try algorithmOidAndParams(body, sig_alg_seq);
    const signature_der = try signatureBytes(signature);
    var tbs_reader = try body.child(tbs);

    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == x509.Tag.context_0_constructed) {
        _ = try tbs_reader.readTlv();
    }

    _ = try tbs_reader.readExpected(x509.Tag.integer);
    _ = try tbs_reader.readExpected(x509.Tag.sequence);
    const issuer = try tbs_reader.readExpected(x509.Tag.sequence);
    _ = try tbs_reader.readExpected(x509.Tag.sequence);
    const subject = try tbs_reader.readExpected(x509.Tag.sequence);
    const spki = try tbs_reader.readExpected(x509.Tag.sequence);

    return .{
        .subject_der = subject.raw,
        .issuer_der = issuer.raw,
        .signature_der = signature_der,
        .tbs_der = tbs.raw,
        .sig_alg_oid = sig_alg.oid,
        .sig_alg_params = sig_alg.params,
        .spki_der = spki.raw,
    };
}

/// Read the OID and the raw `parameters` TLV (if any) from an
/// AlgorithmIdentifier SEQUENCE. `params` is the full parameters TLV
/// (`tag||len||value`), or `null` when the SEQUENCE holds only the OID.
fn algorithmOidAndParams(parent: x509.DerReader, seq_tlv: x509.Tlv) x509.Error!struct {
    oid: []const u8,
    params: ?[]const u8,
} {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) params = (try r.readTlv()).raw;
    // AlgorithmIdentifier carries at most one `parameters`; tolerate none beyond.
    while (r.hasRemaining()) _ = try r.readTlv();
    return .{ .oid = oid.value, .params = params };
}

fn signatureBytes(tlv: x509.Tlv) x509.Error![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

/// Cryptographically verify that `signed.tbs_der` carries a valid signature made
/// by the holder of the key in `issuer_spki`, using the scheme named by
/// `signed.sig_alg_oid`.
///
/// Dispatches on the signature-algorithm OID:
///   * sha256/384/512WithRSAEncryption → RSASSA-PKCS1-v1_5 over the matching SHA
///   * id-RSASSA-PSS                    → RSASSA-PSS; hash/MGF/salt come from the
///                                        `sig_alg_params` (RSASSA-PSS-params)
///   * ecdsa-with-SHA256 (P-256)       → ECDSA/P-256/SHA-256
///   * ecdsa-with-SHA384 (P-384)       → ECDSA/P-384/SHA-384
///   * id-Ed25519                       → Ed25519 (signs the TBS directly)
///
/// `sig_alg_params` is the raw AlgorithmIdentifier `parameters` TLV from the
/// outer signatureAlgorithm (see `LinkInfo.sig_alg_params`); it is only consumed
/// by the PSS branch, which fails closed (`BadSignature`) when it is absent or
/// does not parse to a supported {hash, MGF1-same-hash, capped salt}.
///
/// The issuer's key family must be compatible with the signature scheme (an
/// RSA OID requires an RSA issuer key, etc.); a mismatch is `BadSignature`. Any
/// other algorithm is `UnsupportedSigAlg`.
pub fn verifyCertSignature(
    cert_tbs: []const u8,
    sig_value: []const u8,
    sig_alg_oid: []const u8,
    sig_alg_params: ?[]const u8,
    issuer_spki: []const u8,
) Error!void {
    // ML-DSA is a post-quantum scheme with a raw (non-union) public key, so each
    // parameter set is dispatched before the classical `extractPublicKey` — the
    // PQ path never touches the `SubjectPublicKey` union that unrelated verifiers
    // switch over. The context string is empty for X.509 certificate signatures
    // (draft-ietf-lamps-dilithium-certificates). Each arm extracts a key whose
    // length is pinned to its parameter set, so a signatureAlgorithm/SPKI-OID
    // mismatch fails closed as UnsupportedKey rather than mis-verifying.
    if (std.mem.eql(u8, sig_alg_oid, &SigOid.ml_dsa_44)) {
        const pk = try x509.extractMlDsa44PublicKey(issuer_spki);
        if (!ml_dsa.verify44(pk, cert_tbs, &.{}, sig_value)) return error.BadSignature;
        return;
    }
    if (std.mem.eql(u8, sig_alg_oid, &SigOid.ml_dsa_65)) {
        const pk = try x509.extractMlDsa65PublicKey(issuer_spki);
        if (!ml_dsa.verify65(pk, cert_tbs, &.{}, sig_value)) return error.BadSignature;
        return;
    }
    if (std.mem.eql(u8, sig_alg_oid, &SigOid.ml_dsa_87)) {
        const pk = try x509.extractMlDsa87PublicKey(issuer_spki);
        if (!ml_dsa.verify87(pk, cert_tbs, &.{}, sig_value)) return error.BadSignature;
        return;
    }
    // SLH-DSA (all 12 FIPS 205 sets): same PQ raw-key shape as ML-DSA, each
    // KAT-verified against independent NIST ACVP FIPS 205 sigVer vectors. Empty
    // context for X.509 certificate signatures (draft-ietf-lamps-x509-slhdsa).
    inline for (slh_dsa_sets) |set| {
        if (std.mem.eql(u8, sig_alg_oid, &set.oid)) {
            const pk = try x509.extractSlhDsaPublicKey(issuer_spki, &set.oid, set.pk_len);
            if (!set.verify(pk, cert_tbs, &.{}, sig_value)) return error.BadSignature;
            return;
        }
    }
    // ecdsa-with-SHA384 verifies under a P-384 issuer key, which the shared
    // x509.SubjectPublicKey union deliberately does not model (adding a member
    // there has broad blast radius — e.g. the JWT verifier's exhaustive switch).
    // Parse the P-384 point from the issuer SPKI locally, fail-closed — and do it
    // BEFORE `extractPublicKey`, which would reject a P-384 SPKI as UnsupportedKey.
    if (std.mem.eql(u8, sig_alg_oid, &SigOid.ecdsa_sha384)) {
        return verifyEcdsaP384(issuer_spki, cert_tbs, sig_value);
    }

    const key = try x509.extractPublicKey(issuer_spki);

    if (std.mem.eql(u8, sig_alg_oid, &SigOid.rsa_sha256)) {
        return verifyRsaPkcs1(key, .sha256, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.rsa_sha384)) {
        return verifyRsaPkcs1(key, .sha384, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.rsa_sha512)) {
        return verifyRsaPkcs1(key, .sha512, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.rsassa_pss)) {
        return verifyRsaPss(key, sig_alg_params, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.ecdsa_sha256)) {
        return verifyEcdsaP256(key, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.ed25519)) {
        return verifyEd25519(key, cert_tbs, sig_value);
    }
    return error.UnsupportedSigAlg;
}

fn verifyRsaPkcs1(
    key: x509.SubjectPublicKey,
    alg: rsa_verify.HashAlg,
    tbs: []const u8,
    sig: []const u8,
) Error!void {
    const rsa = switch (key) {
        .rsa => |k| k,
        else => return error.BadSignature,
    };
    var digest: [64]u8 = undefined;
    const digest_slice = digest[0..alg.digestLen()];
    switch (alg) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(tbs, digest[0..32], .{}),
        .sha384 => std.crypto.hash.sha2.Sha384.hash(tbs, digest[0..48], .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(tbs, digest[0..64], .{}),
    }
    const pub_key = rsa_verify.PublicKey{ .n = rsa.modulus, .e = rsa.exponent };
    if (!rsa_verify.verifyPkcs1v15(pub_key, alg, digest_slice, sig)) return error.BadSignature;
}

// ---------------------------------------------------------------------------
// RSASSA-PSS.
//
// The id-RSASSA-PSS OID names neither the hash nor the salt length; both live
// in the AlgorithmIdentifier `parameters` (RSASSA-PSS-params, RFC 4055 §3.1).
// `parsePssParams` decodes and *validates* those parameters fail-closed before
// any signature math runs, so a certificate can never steer the verifier into an
// implicit-SHA1 configuration or an unbounded salt.
// ---------------------------------------------------------------------------

/// Hard cap on an accepted PSS `saltLength` (bytes). A conformant PSS salt is the
/// hash length (≤ 64). This bound is a SECURITY boundary, not a compat knob: the
/// value is attacker-controlled (it comes from the certificate) and feeds an
/// addition in `rsa_verify.verifyPss` that would overflow a `usize` in a
/// ReleaseFast build on a huge value. Capping here fails closed at the edge.
pub const max_pss_salt_len: usize = 512;

/// Validated RSASSA-PSS parameters.
pub const PssParams = struct {
    hash: rsa_verify.HashAlg,
    salt_len: usize,
};

/// [2] context-specific constructed (saltLength) — not in `x509.Tag`.
const context_2_constructed: u8 = 0xA2;

/// Hash OIDs that may appear inside RSASSA-PSS-params (SHA-1 is deliberately
/// absent — see `pssHashFromOid`).
const PssHashOid = struct {
    /// id-sha256 (2.16.840.1.101.3.4.2.1).
    const sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
    /// id-sha384 (2.16.840.1.101.3.4.2.2).
    const sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
    /// id-sha512 (2.16.840.1.101.3.4.2.3).
    const sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
};
/// id-mgf1 (1.2.840.113549.1.1.8).
const oid_mgf1 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08 };

fn verifyRsaPss(
    key: x509.SubjectPublicKey,
    params_der: ?[]const u8,
    tbs: []const u8,
    sig: []const u8,
) Error!void {
    const rsa = switch (key) {
        .rsa => |k| k,
        else => return error.BadSignature,
    };
    // A PSS OID with no parameters is malformed — fail closed, never default.
    const params = try parsePssParams(params_der orelse return error.BadSignature);
    var digest: [64]u8 = undefined;
    const digest_slice = digest[0..params.hash.digestLen()];
    switch (params.hash) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(tbs, digest[0..32], .{}),
        .sha384 => std.crypto.hash.sha2.Sha384.hash(tbs, digest[0..48], .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(tbs, digest[0..64], .{}),
    }
    const pub_key = rsa_verify.PublicKey{ .n = rsa.modulus, .e = rsa.exponent };
    if (!rsa_verify.verifyPss(pub_key, params.hash, digest_slice, sig, params.salt_len)) {
        return error.BadSignature;
    }
}

/// Parse and validate RSASSA-PSS-params (RFC 4055 §3.1). Fail-closed:
///   * `hashAlgorithm` [0] MUST be present and one of SHA-256/384/512 — the
///     `sha1` DEFAULT is rejected (an omitted field means SHA-1, which we never
///     accept),
///   * `maskGenAlgorithm` [1] MUST be present, MGF1, over the SAME hash,
///   * `saltLength` [2] MUST be present, non-negative, and ≤ `max_pss_salt_len`,
///   * `trailerField` [3], if present, MUST be 1 (the sole defined value).
///
/// `params_der` is the raw parameters TLV (the `RSASSA-PSS-params` SEQUENCE).
pub fn parsePssParams(params_der: []const u8) Error!PssParams {
    var top = x509.DerReader.init(params_der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var r = try top.child(seq);

    // hashAlgorithm [0] EXPLICIT AlgorithmIdentifier — REQUIRED.
    if (!r.hasRemaining() or try r.peekTag() != x509.Tag.context_0_constructed) {
        return error.UnsupportedSigAlg;
    }
    const hash_alg_id = try readExplicitAlgId(r, try r.readTlv());
    const hash_alg = try pssHashFromOid(hash_alg_id.oid, hash_alg_id.params);

    // maskGenAlgorithm [1] EXPLICIT AlgorithmIdentifier — REQUIRED = MGF1(hash).
    if (!r.hasRemaining() or try r.peekTag() != x509.Tag.context_1_constructed) {
        return error.UnsupportedSigAlg;
    }
    const mgf_alg_id = try readExplicitAlgId(r, try r.readTlv());
    if (!std.mem.eql(u8, mgf_alg_id.oid, &oid_mgf1)) return error.UnsupportedSigAlg;
    // MGF1's own parameters are the AlgorithmIdentifier of its inner hash.
    const mgf_hash_tlv = mgf_alg_id.params orelse return error.BadSignature;
    const mgf_inner = try parseAlgId(mgf_hash_tlv);
    const mgf_hash = try pssHashFromOid(mgf_inner.oid, mgf_inner.params);
    if (mgf_hash != hash_alg) return error.BadSignature;

    // saltLength [2] EXPLICIT INTEGER — REQUIRED (never accept the 20 DEFAULT).
    if (!r.hasRemaining() or try r.peekTag() != context_2_constructed) {
        return error.UnsupportedSigAlg;
    }
    const salt_len = try readExplicitSaltLen(r, try r.readTlv());

    // trailerField [3] EXPLICIT INTEGER DEFAULT 1 — if present it MUST be 1.
    if (r.hasRemaining()) {
        if (try r.peekTag() != x509.Tag.context_3_constructed) return error.BadSignature;
        try requireTrailerFieldOne(r, try r.readTlv());
    }
    try r.expectEmpty();

    return .{ .hash = hash_alg, .salt_len = salt_len };
}

const AlgIdView = struct {
    oid: []const u8,
    /// Raw parameters TLV, or `null` when absent.
    params: ?[]const u8,
};

/// Decode an `[n] EXPLICIT AlgorithmIdentifier` wrapper (the explicit tag holds a
/// single AlgorithmIdentifier SEQUENCE) into its OID and raw parameters TLV.
fn readExplicitAlgId(parent: x509.DerReader, explicit: x509.Tlv) Error!AlgIdView {
    var e = try parent.child(explicit);
    const alg_seq = try e.readExpected(x509.Tag.sequence);
    try e.expectEmpty();
    return parseAlgIdReader(e, alg_seq);
}

/// Decode a bare AlgorithmIdentifier SEQUENCE (`alg_der` is the raw SEQUENCE).
fn parseAlgId(alg_der: []const u8) Error!AlgIdView {
    var top = x509.DerReader.init(alg_der);
    const alg_seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    return parseAlgIdReader(top, alg_seq);
}

fn parseAlgIdReader(parent: x509.DerReader, alg_seq: x509.Tlv) Error!AlgIdView {
    var a = try parent.child(alg_seq);
    const oid = try a.readExpected(x509.Tag.oid);
    var params: ?[]const u8 = null;
    if (a.hasRemaining()) params = (try a.readTlv()).raw;
    try a.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

/// Map a hash OID (with its optional AlgorithmIdentifier parameters) to a
/// supported `HashAlg`. SHA-1 and everything else are `UnsupportedSigAlg`. When
/// parameters are present they MUST be an explicit NULL (RFC 4055).
fn pssHashFromOid(oid: []const u8, params: ?[]const u8) Error!rsa_verify.HashAlg {
    if (params) |p| {
        // The only conformant parameters for a SHA-2 AlgorithmIdentifier are an
        // explicit NULL (0x05 0x00); anything else is malformed.
        if (p.len != 2 or p[0] != x509.Tag.null_value or p[1] != 0x00) return error.BadSignature;
    }
    if (std.mem.eql(u8, oid, &PssHashOid.sha256)) return .sha256;
    if (std.mem.eql(u8, oid, &PssHashOid.sha384)) return .sha384;
    if (std.mem.eql(u8, oid, &PssHashOid.sha512)) return .sha512;
    return error.UnsupportedSigAlg;
}

/// Decode `[2] EXPLICIT INTEGER` saltLength, capping it at `max_pss_salt_len`.
fn readExplicitSaltLen(parent: x509.DerReader, explicit: x509.Tlv) Error!usize {
    var e = try parent.child(explicit);
    const int = try e.readExpected(x509.Tag.integer);
    try e.expectEmpty();
    return saltLenFromInteger(int.value);
}

/// A DER INTEGER's content as a saltLength, rejecting negatives, non-canonical
/// encodings, and anything above the security cap. Bounded arithmetic: a value
/// wider than two content bytes already exceeds the cap, so overflow is
/// impossible before the range check fires.
fn saltLenFromInteger(bytes: []const u8) Error!usize {
    if (bytes.len == 0) return error.BadSignature;
    if (bytes[0] & 0x80 != 0) return error.BadSignature; // negative
    var v = bytes;
    if (v.len > 1 and v[0] == 0x00) {
        if (v[1] & 0x80 == 0) return error.BadSignature; // non-canonical padding
        v = v[1..];
    }
    if (v.len > 2) return error.BadSignature; // > 0xFFFF, far past the cap
    var val: usize = 0;
    for (v) |byte| val = (val << 8) | byte;
    if (val > max_pss_salt_len) return error.BadSignature;
    return val;
}

/// Decode `[3] EXPLICIT INTEGER` trailerField, requiring the sole defined value 1
/// (the `0xBC` trailer byte itself is checked by `rsa_verify.verifyPss`).
fn requireTrailerFieldOne(parent: x509.DerReader, explicit: x509.Tlv) Error!void {
    var e = try parent.child(explicit);
    const int = try e.readExpected(x509.Tag.integer);
    try e.expectEmpty();
    if (int.value.len != 1 or int.value[0] != 0x01) return error.BadSignature;
}

fn verifyEcdsaP256(key: x509.SubjectPublicKey, tbs: []const u8, sig: []const u8) Error!void {
    const sec1 = switch (key) {
        .ecdsa_p256 => |k| k,
        else => return error.BadSignature,
    };
    const pub_key = ecdsa_p256.parsePublicKeySec1(sec1) catch return error.BadSignature;
    const signature = ecdsa_p256.signatureFromDer(sig) catch return error.BadSignature;
    if (!ecdsa_p256.verify(signature, tbs, pub_key)) return error.BadSignature;
}

/// Verify an ecdsa-with-SHA384 signature under the P-384 issuer key carried in
/// `issuer_spki`. `EcdsaP384.PublicKey.fromSec1` validates the point (length and
/// on-curve); `.verify` hashes `tbs` with SHA-384 internally. Any structural or
/// key-family mismatch fails closed as `BadSignature` — a P-384 signature can
/// only have been produced by a P-384 key.
fn verifyEcdsaP384(issuer_spki: []const u8, tbs: []const u8, sig: []const u8) Error!void {
    const sec1 = try ecP384PointFromSpki(issuer_spki);
    const pub_key = EcdsaP384.PublicKey.fromSec1(sec1) catch return error.BadSignature;
    const signature = EcdsaP384.Signature.fromDer(sig) catch return error.BadSignature;
    signature.verify(tbs, pub_key) catch return error.BadSignature;
}

/// Extract the SEC1 public-key point from a P-384 SubjectPublicKeyInfo
/// (id-ecPublicKey + secp384r1). `x509.extractPublicKey` does not model P-384, so
/// this narrow, fail-closed walk stands in only for the ecdsa-with-SHA384 branch.
/// A non-P-384 issuer key is reported as `BadSignature` (a P-384 signature can
/// only be verified by a P-384 key); malformed DER propagates as an `x509.Error`.
fn ecP384PointFromSpki(spki_der: []const u8) Error![]const u8 {
    var top = x509.DerReader.init(spki_der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(x509.Tag.sequence);
    const key_bits = try spki.readExpected(x509.Tag.bit_string);
    try spki.expectEmpty();

    var alg = try spki.child(alg_seq);
    const alg_oid = try alg.readExpected(x509.Tag.oid);
    const curve_oid = try alg.readExpected(x509.Tag.oid);
    try alg.expectEmpty();
    if (!std.mem.eql(u8, alg_oid.value, &oid_ec_public_key)) return error.BadSignature;
    if (!std.mem.eql(u8, curve_oid.value, &oid_secp384r1)) return error.BadSignature;

    return signatureBytes(key_bits);
}

fn verifyEd25519(key: x509.SubjectPublicKey, tbs: []const u8, sig: []const u8) Error!void {
    const raw = switch (key) {
        .ed25519 => |k| k,
        else => return error.BadSignature,
    };
    if (raw.len != ed25519.public_key_len) return error.BadSignature;
    if (sig.len != ed25519.signature_len) return error.BadSignature;
    var pk: ed25519.PublicKey = undefined;
    @memcpy(&pk, raw);
    var fixed_sig: ed25519.Signature = undefined;
    @memcpy(&fixed_sig, sig);
    const ok = ed25519.verify(tbs, fixed_sig, pk) catch return error.BadSignature;
    if (!ok) return error.BadSignature;
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

const TestFixture = struct {
    storage: []u8,
    der: []const u8,

    fn deinit(self: TestFixture) void {
        std.testing.allocator.free(self.storage);
    }
};

fn testDer() !TestFixture {
    const allocator = std.testing.allocator;
    const storage = try allocator.alloc(u8, 512);
    errdefer allocator.free(storage);
    const decoded = try x509.pemToDer(TestPem, storage);
    return .{ .storage = storage, .der = storage[0..decoded.len] };
}

test "certfp of known DER and constant-time compare" {
    const fixture = try testDer();
    defer fixture.deinit();
    const der = fixture.der;

    const fp = try certfp(der);
    var hex: [digest_len * 2]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        "231a5709f3e42db6130a35b75d56b45dedee32690a9e6f71bf6ad87e6707ba7a",
        try certfpHex(der, &hex),
    );

    var direct: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &direct, .{});
    try std.testing.expect(certfpEqual(&fp, &direct));
    try std.testing.expect(try certfpMatchesDer(der, &fp));

    var different = fp;
    different[digest_len - 1] ^= 1;
    try std.testing.expect(!certfpEqual(&fp, &different));
}

test "validity window pass and fail" {
    const fixture = try testDer();
    defer fixture.deinit();
    const der = fixture.der;
    const cert = try x509.parse(der);

    try validateParsedAt(cert, cert.not_before.epoch_seconds);
    try validateParsedAt(cert, cert.not_after.epoch_seconds);
    try validateDerAt(der, cert.not_before.epoch_seconds + 1);
    try std.testing.expectError(error.NotYetValid, validateParsedAt(cert, cert.not_before.epoch_seconds - 1));
    try std.testing.expectError(error.Expired, validateDerAt(der, cert.not_after.epoch_seconds + 1));
}

test "self-signed certificate is accepted structurally" {
    const fixture = try testDer();
    defer fixture.deinit();
    const der = fixture.der;

    const info = try linkInfo(der);
    try std.testing.expect(info.isSelfIssued());
    try std.testing.expect(info.hasSignature());
    try verifySelfSigned(der);

    const chain = [_][]const u8{der};
    try verifySimpleChain(&chain);
    const cert = try x509.parse(der);
    try verifySimpleChainAt(&chain, cert.not_before.epoch_seconds);
}

// ===========================================================================
// Real signature-verification tests.
//
// These mint live certificate chains with the project's own signing
// primitives, so the positive cases prove the verifier accepts a genuinely
// signed chain and the negative cases prove it rejects forgeries (a flipped
// signature byte, a leaf signed by the wrong key, an unsupported algorithm, and
// an expired cert). x509_selfsign mints self-signed roots; the helpers below
// mint a CA-signed leaf whose issuer DN differs from its subject DN.
// ===========================================================================

const x509_selfsign = @import("../proto/x509_selfsign.zig");
const StdEd25519 = std.crypto.sign.Ed25519;

const not_before: i64 = 1_704_067_200; // 2024-01-01
const not_after: i64 = 1_924_991_999; // 2030-12-31

// A small fixed-buffer DER writer mirroring x509_selfsign's, used to mint a
// CA-signed leaf (issuer DN != subject DN) signed by a separate issuer key.
const W = struct {
    buf: []u8,
    pos: usize = 0,
    fn init(buf: []u8) W {
        return .{ .buf = buf };
    }
    fn bytes(self: *const W) []const u8 {
        return self.buf[0..self.pos];
    }
    fn raw(self: *W, b: []const u8) void {
        @memcpy(self.buf[self.pos..][0..b.len], b);
        self.pos += b.len;
    }
    fn tlv(self: *W, tag: u8, val: []const u8) void {
        self.buf[self.pos] = tag;
        self.pos += 1;
        if (val.len < 128) {
            self.buf[self.pos] = @intCast(val.len);
            self.pos += 1;
        } else {
            // Single-byte long form (all test certs fit < 256, < 65536).
            var tmp: [8]u8 = undefined;
            var n = val.len;
            var c: usize = 0;
            while (n != 0) : (n >>= 8) {
                tmp[tmp.len - 1 - c] = @intCast(n & 0xff);
                c += 1;
            }
            self.buf[self.pos] = 0x80 | @as(u8, @intCast(c));
            self.pos += 1;
            @memcpy(self.buf[self.pos..][0..c], tmp[tmp.len - c ..]);
            self.pos += c;
        }
        self.raw(val);
    }
};

const oid_ed25519_bytes = [_]u8{ 0x2b, 0x65, 0x70 };

fn writeAlgEd25519(w: *W) void {
    var body: [8]u8 = undefined;
    var b = W.init(&body);
    b.tlv(0x06, &oid_ed25519_bytes);
    w.tlv(0x30, b.bytes());
}

fn writeNameCn(w: *W, cn: []const u8) void {
    var attr_body: [80]u8 = undefined;
    var ab = W.init(&attr_body);
    ab.tlv(0x06, &[_]u8{ 0x55, 0x04, 0x03 }); // commonName
    ab.tlv(0x0c, cn); // UTF8String
    var attr: [96]u8 = undefined;
    var a = W.init(&attr);
    a.tlv(0x30, ab.bytes());
    var rdn: [112]u8 = undefined;
    var r = W.init(&rdn);
    r.tlv(0x31, a.bytes()); // SET
    w.tlv(0x30, r.bytes());
}

fn writeValidity(w: *W, nb: i64, na: i64) void {
    var body: [40]u8 = undefined;
    var b = W.init(&body);
    var nbuf: [15]u8 = undefined;
    var abuf: [15]u8 = undefined;
    const before = x509_selfsign_formatTime(&nbuf, nb);
    const after = x509_selfsign_formatTime(&abuf, na);
    b.tlv(before.tag, nbuf[0..before.len]);
    b.tlv(after.tag, abuf[0..after.len]);
    w.tlv(0x30, b.bytes());
}

const TimeOut = struct { tag: u8, len: usize };

// Reuse the project epoch->ASN.1 time encoding by formatting via UTCTime for the
// in-range years the tests use (2024-2030 -> 1950..2049 => UTCTime).
fn x509_selfsign_formatTime(out: *[15]u8, unix_seconds: i64) TimeOut {
    const spd: i64 = 86_400;
    const days = @divFloor(unix_seconds, spd);
    const sod = @mod(unix_seconds, spd);
    const z = days + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097;
    const yoe = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36_524) - @divTrunc(doe, 146_096), 365);
    var year = yoe + era * 400;
    const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp = @divTrunc(5 * doy + 2, 153);
    const day = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const month = mp + if (mp < 10) @as(i64, 3) else -9;
    if (month <= 2) year += 1;
    const hour = @divTrunc(sod, 3600);
    const minute = @divTrunc(sod - hour * 3600, 60);
    const second = sod - hour * 3600 - minute * 60;
    const w2 = struct {
        fn f(o: []u8, v: i64) void {
            o[0] = '0' + @as(u8, @intCast(@divTrunc(v, 10)));
            o[1] = '0' + @as(u8, @intCast(@mod(v, 10)));
        }
    }.f;
    w2(out[0..2], @mod(year, 100));
    w2(out[2..4], month);
    w2(out[4..6], day);
    w2(out[6..8], hour);
    w2(out[8..10], minute);
    w2(out[10..12], second);
    out[12] = 'Z';
    return .{ .tag = 0x17, .len = 13 };
}

fn writeSpkiEd25519(w: *W, pub_key: [32]u8) void {
    var body: [64]u8 = undefined;
    var b = W.init(&body);
    writeAlgEd25519(&b);
    var bit: [33]u8 = undefined;
    bit[0] = 0;
    @memcpy(bit[1..], &pub_key);
    b.tlv(0x03, &bit);
    w.tlv(0x30, b.bytes());
}

/// Mint a leaf cert whose issuer DN is `issuer_cn`, subject DN is `subject_cn`,
/// embedding `subject_pub`, signed (Ed25519) with `issuer_kp`. Returns the DER
/// in `out`. `pub` so sibling crypto tests can mint an issuer≠subject leaf (e.g.
/// the signature_algorithms_cert chain-conformance tests in `tls_server.zig`).
pub fn mintEd25519Leaf(
    out: []u8,
    issuer_cn: []const u8,
    subject_cn: []const u8,
    subject_pub: [32]u8,
    issuer_kp: StdEd25519.KeyPair,
    nb: i64,
    na: i64,
) ![]const u8 {
    var tbs_body: [512]u8 = undefined;
    var tb = W.init(&tbs_body);
    // version [0] EXPLICIT INTEGER 2
    var ver: [5]u8 = undefined;
    var vw = W.init(&ver);
    vw.tlv(0x02, &[_]u8{0x02});
    tb.tlv(0xa0, vw.bytes());
    tb.tlv(0x02, &[_]u8{ 0x12, 0x34 }); // serial
    writeAlgEd25519(&tb); // signature alg in TBS
    writeNameCn(&tb, issuer_cn);
    writeValidity(&tb, nb, na);
    writeNameCn(&tb, subject_cn);
    writeSpkiEd25519(&tb, subject_pub);

    var tbs: [560]u8 = undefined;
    var tw = W.init(&tbs);
    tw.tlv(0x30, tb.bytes());
    const tbs_der = tw.bytes();

    const sig = try StdEd25519.KeyPair.sign(issuer_kp, tbs_der, null);
    const sig_bytes = sig.toBytes();

    var body: [700]u8 = undefined;
    var bw = W.init(&body);
    bw.raw(tbs_der);
    writeAlgEd25519(&bw);
    var bit: [65]u8 = undefined;
    bit[0] = 0;
    @memcpy(bit[1..], &sig_bytes);
    bw.tlv(0x03, &bit);

    var cert = W.init(out);
    cert.tlv(0x30, bw.bytes());
    return cert.bytes();
}

const oid_basic_constraints_bytes = [_]u8{ 0x55, 0x1D, 0x13 };
const oid_subject_alt_name_bytes = [_]u8{ 0x55, 0x1D, 0x11 };
const oid_name_constraints_bytes = [_]u8{ 0x55, 0x1D, 0x1E };

/// Extension inputs for `mintEd25519CertExt`. All fields default to "omit this
/// extension" so a plain leaf needs only `dns_names`.
const CertExtOpts = struct {
    /// Emit BasicConstraints `cA:TRUE` (critical flag omitted; the parser does
    /// not require it) with an optional pathLenConstraint.
    is_ca: bool = false,
    path_len: ?u8 = null,
    /// SubjectAltName dNSName entries.
    dns_names: []const []const u8 = &.{},
    /// NameConstraints permittedSubtrees (dNSName only; no excludedSubtrees —
    /// the F1 regression tests below only need permitted-subtree rejection).
    permitted_dns: []const []const u8 = &.{},
};

fn writeExtTlv(w: *W, oid: []const u8, ext_value: []const u8) void {
    var body: [224]u8 = undefined;
    var b = W.init(&body);
    b.tlv(0x06, oid); // extnID
    b.tlv(0x04, ext_value); // extnValue OCTET STRING
    w.tlv(0x30, b.bytes()); // Extension SEQUENCE
}

fn writeBasicConstraintsExt(w: *W, path_len: ?u8) void {
    var body: [8]u8 = undefined;
    var b = W.init(&body);
    b.tlv(0x01, &[_]u8{0xff}); // cA: TRUE
    if (path_len) |pl| b.tlv(0x02, &[_]u8{pl});
    var val: [16]u8 = undefined;
    var v = W.init(&val);
    v.tlv(0x30, b.bytes());
    writeExtTlv(w, &oid_basic_constraints_bytes, v.bytes());
}

fn writeSanExt(w: *W, dns_names: []const []const u8) void {
    var body: [160]u8 = undefined;
    var b = W.init(&body);
    for (dns_names) |name| b.tlv(0x82, name); // dNSName [2]
    var val: [176]u8 = undefined;
    var v = W.init(&val);
    v.tlv(0x30, b.bytes());
    writeExtTlv(w, &oid_subject_alt_name_bytes, v.bytes());
}

/// NameConstraints permittedSubtrees only (RFC 5280 §4.2.1.10):
/// SEQUENCE { permittedSubtrees [0] GeneralSubtrees }, GeneralSubtrees =
/// SEQUENCE OF GeneralSubtree, GeneralSubtree = SEQUENCE { base GeneralName }
/// (minimum/maximum omitted — both OPTIONAL/DEFAULT).
fn writeNameConstraintsExt(w: *W, permitted_dns: []const []const u8) void {
    var subtrees_body: [160]u8 = undefined;
    var sb = W.init(&subtrees_body);
    for (permitted_dns) |name| {
        var gs_body: [96]u8 = undefined;
        var gsb = W.init(&gs_body);
        gsb.tlv(0x82, name); // base: dNSName [2]
        sb.tlv(0x30, gsb.bytes()); // GeneralSubtree SEQUENCE
    }
    var nc_body: [176]u8 = undefined;
    var ncb = W.init(&nc_body);
    ncb.tlv(0xa0, sb.bytes()); // permittedSubtrees [0]
    var val: [192]u8 = undefined;
    var v = W.init(&val);
    v.tlv(0x30, ncb.bytes());
    writeExtTlv(w, &oid_name_constraints_bytes, v.bytes());
}

/// Mint an Ed25519 certificate (issuer DN `issuer_cn`, subject DN
/// `subject_cn`, self-signed when the two DNs and `signing_kp` describe the
/// same certificate) carrying the extensions in `opts`. `mintEd25519Leaf`
/// above has no extensions support at all, and none of `x509_selfsign.zig`'s
/// builders support NameConstraints or an Ed25519 "issued by" CA — this helper
/// exists only for the F1 NameConstraints/pathLenConstraint enforcement
/// regression tests below (and their mirror in `tls12_client.zig`/
/// `tls_client.zig`), which need small, fully ad hoc chains. `pub` so both
/// TLS client engines' own test sections can mint the same fixtures.
pub fn mintEd25519CertExt(
    out: []u8,
    issuer_cn: []const u8,
    subject_cn: []const u8,
    subject_pub: [32]u8,
    signing_kp: StdEd25519.KeyPair,
    nb: i64,
    na: i64,
    opts: CertExtOpts,
) ![]const u8 {
    var tbs_body: [768]u8 = undefined;
    var tb = W.init(&tbs_body);
    // version [0] EXPLICIT INTEGER 2
    var ver: [5]u8 = undefined;
    var vw = W.init(&ver);
    vw.tlv(0x02, &[_]u8{0x02});
    tb.tlv(0xa0, vw.bytes());
    tb.tlv(0x02, &[_]u8{ 0x12, 0x34 }); // serial
    writeAlgEd25519(&tb); // signature alg in TBS
    writeNameCn(&tb, issuer_cn);
    writeValidity(&tb, nb, na);
    writeNameCn(&tb, subject_cn);
    writeSpkiEd25519(&tb, subject_pub);

    var ext_seq_body: [512]u8 = undefined;
    var esb = W.init(&ext_seq_body);
    if (opts.is_ca) writeBasicConstraintsExt(&esb, opts.path_len);
    if (opts.dns_names.len != 0) writeSanExt(&esb, opts.dns_names);
    if (opts.permitted_dns.len != 0) writeNameConstraintsExt(&esb, opts.permitted_dns);
    if (esb.pos != 0) {
        var ext_seq: [520]u8 = undefined;
        var es = W.init(&ext_seq);
        es.tlv(0x30, esb.bytes()); // Extensions SEQUENCE
        tb.tlv(0xa3, es.bytes()); // [3] EXPLICIT
    }

    var tbs: [800]u8 = undefined;
    var tw = W.init(&tbs);
    tw.tlv(0x30, tb.bytes());
    const tbs_der = tw.bytes();

    const sig = try StdEd25519.KeyPair.sign(signing_kp, tbs_der, null);
    const sig_bytes = sig.toBytes();

    var body: [900]u8 = undefined;
    var bw = W.init(&body);
    bw.raw(tbs_der);
    writeAlgEd25519(&bw);
    var bit: [65]u8 = undefined;
    bit[0] = 0;
    @memcpy(bit[1..], &sig_bytes);
    bw.tlv(0x03, &bit);

    var cert = W.init(out);
    cert.tlv(0x30, bw.bytes());
    return cert.bytes();
}

fn ed25519KpFromSeed(seed_byte: u8) !StdEd25519.KeyPair {
    return StdEd25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed_byte)));
}

test "valid Ed25519 two-cert chain (leaf signed by self-signed root) verifies" {
    const root_kp = try ed25519KpFromSeed(0x01);
    const leaf_kp = try ed25519KpFromSeed(0x02);

    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Onyx Test Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x10, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    var leaf_buf: [700]u8 = undefined;
    const leaf = try mintEd25519Leaf(
        &leaf_buf,
        "Onyx Test Root", // issuer DN == root subject DN
        "leaf.example.test",
        leaf_kp.public_key.toBytes(),
        root_kp,
        not_before,
        not_after,
    );

    const chain = [_][]const u8{ leaf, root };
    try verifySimpleChain(&chain);
    try verifySimpleChainAt(&chain, not_before + 1);
}

test "valid ECDSA-P256 self-signed root verifies and a flipped signature byte is rejected" {
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var root_buf: [1024]u8 = undefined;
    const root = try x509_selfsign.buildSelfSignedEcdsaP256(&root_buf, .{
        .common_name = "ecdsa.root.test",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x20, 0x01 },
        .key_pair = kp,
        .is_ca = true,
    });

    const chain = [_][]const u8{root};
    try verifySimpleChain(&chain);

    // Negative: corrupt the trailing signature byte and reject.
    var bad = try std.testing.allocator.alloc(u8, root.len);
    defer std.testing.allocator.free(bad);
    @memcpy(bad, root);
    bad[bad.len - 1] ^= 0x01;
    const bad_chain = [_][]const u8{bad};
    try std.testing.expectError(error.BadSignature, verifySimpleChain(&bad_chain));
}

test "valid RSA-SHA256 self-signed root verifies" {
    const rsa_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
    const rsa_e = hexToBytes("010001");
    const rsa_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
    const rsa_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
    const rsa_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
    const rsa_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
    const rsa_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
    const rsa_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");
    const priv = @import("rsa_sign.zig").PrivateKey{ .n = &rsa_n, .e = &rsa_e, .d = &rsa_d, .p = &rsa_p, .q = &rsa_q, .dp = &rsa_dp, .dq = &rsa_dq, .qinv = &rsa_qinv };

    var root_buf: [2048]u8 = undefined;
    const root = try x509_selfsign.buildSelfSignedRsa(&root_buf, .{
        .common_name = "rsa.root.test",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x30, 0x01 },
        .public_modulus = &rsa_n,
        .public_exponent = &rsa_e,
        .private_key = priv,
        .is_ca = true,
    });

    const chain = [_][]const u8{root};
    try verifySimpleChain(&chain);
    try verifySimpleChainAt(&chain, not_before + 1);
}

test "chain where leaf signature is corrupted is rejected" {
    const root_kp = try ed25519KpFromSeed(0x05);
    const leaf_kp = try ed25519KpFromSeed(0x06);

    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Corrupt Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x40, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    var leaf_buf: [700]u8 = undefined;
    const leaf = try mintEd25519Leaf(&leaf_buf, "Corrupt Root", "leaf.test", leaf_kp.public_key.toBytes(), root_kp, not_before, not_after);

    // Flip the last byte of the leaf (its Ed25519 signature tail).
    var corrupted = try std.testing.allocator.alloc(u8, leaf.len);
    defer std.testing.allocator.free(corrupted);
    @memcpy(corrupted, leaf);
    corrupted[corrupted.len - 1] ^= 0x01;

    const chain = [_][]const u8{ corrupted, root };
    try std.testing.expectError(error.BadSignature, verifySimpleChain(&chain));
}

test "chain where leaf was signed by a different key than the issuer SPKI is rejected" {
    const root_kp = try ed25519KpFromSeed(0x07); // root's published key
    const attacker_kp = try ed25519KpFromSeed(0x08); // actually signs the leaf
    const leaf_kp = try ed25519KpFromSeed(0x09);

    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Honest Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x50, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    // The leaf names "Honest Root" as issuer (DN links) but is signed by the
    // attacker's key, which is NOT the key in the root's SPKI.
    var leaf_buf: [700]u8 = undefined;
    const leaf = try mintEd25519Leaf(&leaf_buf, "Honest Root", "forged.test", leaf_kp.public_key.toBytes(), attacker_kp, not_before, not_after);

    const chain = [_][]const u8{ leaf, root };
    try std.testing.expectError(error.BadSignature, verifySimpleChain(&chain));
}

test "unsupported signature algorithm is rejected with UnsupportedSigAlg" {
    // Craft a minimal cert whose outer signatureAlgorithm OID is a supported-
    // looking-but-not OID (md5WithRSAEncryption, 1.2.840.113549.1.1.4), with a
    // valid RSA-shaped SPKI so dispatch reaches the OID switch and rejects it.
    // We build it by taking a valid Ed25519 self-signed cert and verifying the
    // dispatcher's unsupported branch directly via verifyCertSignature.
    const fixture = try testDer();
    defer fixture.deinit();
    const info = try linkInfo(fixture.der);

    const md5_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 };
    try std.testing.expectError(
        error.UnsupportedSigAlg,
        verifyCertSignature(info.tbs_der, info.signature_der, &md5_rsa, info.sig_alg_params, info.spki_der),
    );
}

test "exploit: sha1WithRSAEncryption certificate signatures are rejected" {
    const fixture = try testDer();
    defer fixture.deinit();
    const info = try linkInfo(fixture.der);
    // 1.2.840.113549.1.1.5 — sha1WithRSAEncryption. Dispatch must not fall
    // through to a PKCS#1 SHA-1 verify even if the SPKI is RSA-shaped.
    const sha1_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
    try std.testing.expectError(
        error.UnsupportedSigAlg,
        verifyCertSignature(info.tbs_der, info.signature_der, &sha1_rsa, info.sig_alg_params, info.spki_der),
    );
}

test "expired certificate is rejected by verifySimpleChainAt" {
    const root_kp = try ed25519KpFromSeed(0x0a);
    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Expiring Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x60, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    const chain = [_][]const u8{root};
    // Signature still verifies, but the clock is past not_after.
    try verifySimpleChain(&chain);
    try std.testing.expectError(error.Expired, verifySimpleChainAt(&chain, not_after + 1));
    try std.testing.expectError(error.NotYetValid, verifySimpleChainAt(&chain, not_before - 1));
}

test "bootstrapped Ed25519 self-signed leaf still validates with real signature checks" {
    const tls_certs = @import("../daemon/tls_certs.zig");
    var loaded = try tls_certs.loadOrBootstrap(std.testing.allocator, std.testing.io, .{
        .enabled = true,
        .dns_name = "bootstrap.test",
    });
    defer loaded.deinit(std.testing.allocator);

    // The daemon's own bootstrap chain must pass the upgraded, signature-checking
    // verifier (this is what main.zig's validateTlsChain runs at boot).
    try verifySimpleChain(loaded.cert_chain);
    const cert = try x509.parse(loaded.cert_chain[0]);
    try verifySimpleChainAt(loaded.cert_chain, cert.not_before.epoch_seconds + 1);
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ===========================================================================
// RSASSA-PSS certificate-signature tests.
//
// Test signatures use a self-verifying Mersenne modulus n = M2203 = 2^2203 - 1
// (a known Mersenne PRIME) with e = d = n - 2. Because n is prime,
// x^(n-1) ≡ 1 (mod n) (Fermat), and e·d ≡ (-1)(-1) ≡ 1 (mod n-1), so
// s = EM^d and EM = s^e round-trip through a single public modexp — NO key
// generation, NO modular inverse, NO external tooling. M2203 is the smallest
// Mersenne prime at or above rsa_verify's 2048-bit modern-hardening floor, so
// verifyCertSignature still accepts the key (M1279, the prior vector, is now
// refused). At 276 bytes it carries SHA-512 with a 64-byte salt, and its
// emBits = 2202 ⇒ emLen = 276 keeps 6 non-byte-aligned top bits, so the PSS
// top-bit masking path stays exercised (M2281's emBits = 2280 would not).
//
// The EMSA-PSS-ENCODE below is written straight from RFC 8017 §9.1.1 and is
// deliberately independent of the verify path under test (its hashing and MGF1
// use std.crypto directly, not rsa_verify's helpers).
// ===========================================================================

const m2203_n = blk: {
    var n: [276]u8 = @splat(0xFF);
    n[0] = 0x07; // 2^2203 - 1 has 2203 set bits ⇒ top byte 0x07, then 275×0xFF
    break :blk n;
};
// n - 2: identical to n except the least-significant byte 0xFF → 0xFD.
const m2203_ed = blk: {
    var d: [276]u8 = @splat(0xFF);
    d[0] = 0x07;
    d[275] = 0xFD;
    break :blk d;
};

/// id-sha1 (1.3.14.3.2.26) — used only to prove PSS-with-SHA-1 is rejected.
const oid_sha1 = [_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };

fn testHash(alg: rsa_verify.HashAlg, msg: []const u8, out: []u8) void {
    switch (alg) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(msg, out[0..32], .{}),
        .sha384 => std.crypto.hash.sha2.Sha384.hash(msg, out[0..48], .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(msg, out[0..64], .{}),
    }
}

/// MGF1 (RFC 8017 §B.2.1), written directly (mask is produced, not XORed) so the
/// encoder does not lean on the module under test.
fn testMgf1(alg: rsa_verify.HashAlg, seed: []const u8, mask_out: []u8) void {
    const h_len = alg.digestLen();
    var counter: u32 = 0;
    var off: usize = 0;
    var buf: [64 + 4]u8 = undefined;
    var block: [64]u8 = undefined;
    while (off < mask_out.len) : (counter += 1) {
        @memcpy(buf[0..seed.len], seed);
        std.mem.writeInt(u32, buf[seed.len..][0..4], counter, .big);
        testHash(alg, buf[0 .. seed.len + 4], block[0..h_len]);
        const take = @min(h_len, mask_out.len - off);
        @memcpy(mask_out[off..][0..take], block[0..take]);
        off += take;
    }
}

fn testBitLenBE(bytes: []const u8) usize {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) i += 1;
    if (i == bytes.len) return 0;
    return (bytes.len - i - 1) * 8 + (8 - @clz(bytes[i]));
}

/// EMSA-PSS-ENCODE(mhash, emBits=bitLen(n)-1, salt) then s = EM^d mod n.
fn testSignPss(
    out_sig: []u8,
    n: []const u8,
    d: []const u8,
    alg: rsa_verify.HashAlg,
    mhash: []const u8,
    salt: []const u8,
) !void {
    const k = n.len;
    const h_len = alg.digestLen();
    const em_bits = testBitLenBE(n) - 1;
    const em_len = (em_bits + 7) / 8;

    var mprime: [8 + 64 + 64]u8 = undefined;
    @memset(mprime[0..8], 0);
    @memcpy(mprime[8..][0..h_len], mhash);
    @memcpy(mprime[8 + h_len ..][0..salt.len], salt);
    var hbuf: [64]u8 = undefined;
    testHash(alg, mprime[0 .. 8 + h_len + salt.len], hbuf[0..h_len]);

    const db_len = em_len - h_len - 1;
    const ps_len = db_len - salt.len - 1;
    var db: [256]u8 = undefined;
    @memset(db[0..ps_len], 0);
    db[ps_len] = 0x01;
    @memcpy(db[ps_len + 1 ..][0..salt.len], salt);
    var mask: [256]u8 = undefined;
    testMgf1(alg, hbuf[0..h_len], mask[0..db_len]);
    for (0..db_len) |i| db[i] ^= mask[i];
    const top_bits: u3 = @intCast(8 * em_len - em_bits);
    if (top_bits != 0) db[0] &= @as(u8, 0xFF) >> top_bits;

    var em: [320]u8 = undefined; // ≥ emLen (276 for the M2203 test modulus)
    @memcpy(em[0..db_len], db[0..db_len]);
    @memcpy(em[db_len..][0..h_len], hbuf[0..h_len]);
    em[em_len - 1] = 0xbc;

    try rsa_verify.modExp(em[0..em_len], d, n, out_sig[0..k]);
}

/// Build an RSA SubjectPublicKeyInfo DER from a big-endian modulus/exponent
/// (both already valid positive DER-INTEGER magnitudes: MSB clear).
fn testBuildRsaSpki(out: []u8, n: []const u8, e: []const u8) []const u8 {
    // n and e are BOTH full-modulus-width here (the self-signing key sets
    // e = d = n-2), so each INTEGER TLV is ~1+3+276 = 280 bytes: size the DER
    // scratch for two of them plus the SEQUENCE/BIT-STRING wrappers, not for a
    // short exponent.
    var rsapk_body: [640]u8 = undefined;
    var rp = W.init(&rsapk_body);
    rp.tlv(0x02, n);
    rp.tlv(0x02, e);
    var rsapk_seq: [640]u8 = undefined;
    var rs = W.init(&rsapk_seq);
    rs.tlv(0x30, rp.bytes());

    var bit_buf: [660]u8 = undefined;
    bit_buf[0] = 0x00; // BIT STRING unused-bits octet
    @memcpy(bit_buf[1..][0..rs.bytes().len], rs.bytes());
    const bit_val = bit_buf[0 .. 1 + rs.bytes().len];

    var alg_body: [32]u8 = undefined;
    var ab = W.init(&alg_body);
    ab.tlv(0x06, &[_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }); // rsaEncryption
    ab.tlv(0x05, &[_]u8{}); // NULL
    var alg_seq: [40]u8 = undefined;
    var as_ = W.init(&alg_seq);
    as_.tlv(0x30, ab.bytes());

    var spki_body: [640]u8 = undefined;
    var sb = W.init(&spki_body);
    sb.raw(as_.bytes());
    sb.tlv(0x03, bit_val);
    var spki = W.init(out);
    spki.tlv(0x30, sb.bytes());
    return spki.bytes();
}

fn testBuildHashAlgId(out: []u8, oid: []const u8, include_null: bool) []const u8 {
    var body: [32]u8 = undefined;
    var b = W.init(&body);
    b.tlv(0x06, oid);
    if (include_null) b.tlv(0x05, &[_]u8{});
    var seq = W.init(out);
    seq.tlv(0x30, b.bytes());
    return seq.bytes();
}

const PssBuildOpts = struct {
    hash_oid: []const u8,
    mgf_hash_oid: []const u8,
    /// saltLength INTEGER content, or null to omit the [2] field entirely.
    salt_content: ?[]const u8,
    /// trailerField INTEGER value, or null to omit the [3] field.
    trailer: ?u8 = null,
    /// Whether the hash AlgorithmIdentifiers carry an explicit NULL parameters.
    hash_null_params: bool = true,
};

/// Build an RSASSA-PSS-params SEQUENCE DER (the raw signatureAlgorithm
/// `parameters`), fully parameterized for both positive and fail-closed tests.
fn testBuildPssParams(out: []u8, opts: PssBuildOpts) []const u8 {
    var body: [400]u8 = undefined;
    var bw = W.init(&body);

    // hashAlgorithm [0]
    var halg: [40]u8 = undefined;
    const halg_bytes = testBuildHashAlgId(&halg, opts.hash_oid, opts.hash_null_params);
    var e0: [48]u8 = undefined;
    var e0w = W.init(&e0);
    e0w.tlv(0xA0, halg_bytes);
    bw.raw(e0w.bytes());

    // maskGenAlgorithm [1] = SEQUENCE { OID mgf1, <inner hash AlgId> }
    var inner: [40]u8 = undefined;
    const inner_bytes = testBuildHashAlgId(&inner, opts.mgf_hash_oid, opts.hash_null_params);
    var mgf_body: [64]u8 = undefined;
    var mgfw = W.init(&mgf_body);
    mgfw.tlv(0x06, &oid_mgf1);
    mgfw.raw(inner_bytes);
    var mgf_seq: [72]u8 = undefined;
    var mgfsw = W.init(&mgf_seq);
    mgfsw.tlv(0x30, mgfw.bytes());
    var e1: [80]u8 = undefined;
    var e1w = W.init(&e1);
    e1w.tlv(0xA1, mgfsw.bytes());
    bw.raw(e1w.bytes());

    // saltLength [2] (optional)
    if (opts.salt_content) |sc| {
        var salt_int: [16]u8 = undefined;
        var siw = W.init(&salt_int);
        siw.tlv(0x02, sc);
        var e2: [24]u8 = undefined;
        var e2w = W.init(&e2);
        e2w.tlv(0xA2, siw.bytes());
        bw.raw(e2w.bytes());
    }

    // trailerField [3] (optional)
    if (opts.trailer) |t| {
        var tr_int: [8]u8 = undefined;
        var tiw = W.init(&tr_int);
        tiw.tlv(0x02, &[_]u8{t});
        var e3: [16]u8 = undefined;
        var e3w = W.init(&e3);
        e3w.tlv(0xA3, tiw.bytes());
        bw.raw(e3w.bytes());
    }

    var seq = W.init(out);
    seq.tlv(0x30, bw.bytes());
    return seq.bytes();
}

test "verifyCertSignature accepts RSASSA-PSS over SHA-256/384/512 and rejects a flipped byte" {
    const tbs = "onyx RSASSA-PSS cert-signature end-to-end test bytes";
    var spki_buf: [700]u8 = undefined;
    const spki = testBuildRsaSpki(&spki_buf, &m2203_n, &m2203_ed);

    const cases = .{
        .{ rsa_verify.HashAlg.sha256, @as([]const u8, &PssHashOid.sha256), @as(u8, 32) },
        .{ rsa_verify.HashAlg.sha384, @as([]const u8, &PssHashOid.sha384), @as(u8, 48) },
        .{ rsa_verify.HashAlg.sha512, @as([]const u8, &PssHashOid.sha512), @as(u8, 64) },
    };
    inline for (cases) |case| {
        const alg = case[0];
        const hash_oid = case[1];
        const salt_len = case[2];

        var mhash: [64]u8 = undefined;
        testHash(alg, tbs, mhash[0..alg.digestLen()]);
        const salt = @as([64]u8, @splat(0x5A));
        var sig: [276]u8 = undefined; // full M2203 modulus length
        try testSignPss(&sig, &m2203_n, &m2203_ed, alg, mhash[0..alg.digestLen()], salt[0..salt_len]);

        var params_buf: [256]u8 = undefined;
        const params = testBuildPssParams(&params_buf, .{
            .hash_oid = hash_oid,
            .mgf_hash_oid = hash_oid,
            .salt_content = &[_]u8{salt_len},
        });

        try verifyCertSignature(tbs, &sig, &SigOid.rsassa_pss, params, spki);

        // A single flipped signature byte must be rejected.
        var bad = sig;
        bad[13] ^= 0x01;
        try std.testing.expectError(
            error.BadSignature,
            verifyCertSignature(tbs, &bad, &SigOid.rsassa_pss, params, spki),
        );
    }
}

test "verifyCertSignature accepts RSASSA-PSS whose hash AlgorithmIdentifiers omit the NULL params" {
    const tbs = "pss without explicit null hash params";
    var mhash: [32]u8 = undefined;
    testHash(.sha256, tbs, &mhash);
    const salt = @as([32]u8, @splat(0x33));
    var sig: [276]u8 = undefined; // full M2203 modulus length
    try testSignPss(&sig, &m2203_n, &m2203_ed, .sha256, &mhash, &salt);

    var spki_buf: [700]u8 = undefined;
    const spki = testBuildRsaSpki(&spki_buf, &m2203_n, &m2203_ed);
    var params_buf: [256]u8 = undefined;
    const params = testBuildPssParams(&params_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha256,
        .salt_content = &[_]u8{32},
        .trailer = 1, // explicit trailerField 1 is also accepted
        .hash_null_params = false,
    });
    try verifyCertSignature(tbs, &sig, &SigOid.rsassa_pss, params, spki);
}

test "verifyCertSignature rejects RSASSA-PSS when the declared hash differs from the signed hash" {
    const tbs = "declared-hash mismatch";
    var mhash: [32]u8 = undefined;
    testHash(.sha256, tbs, &mhash);
    const salt = @as([32]u8, @splat(0x11));
    var sig: [276]u8 = undefined; // full M2203 modulus length
    try testSignPss(&sig, &m2203_n, &m2203_ed, .sha256, &mhash, &salt);

    var spki_buf: [700]u8 = undefined;
    const spki = testBuildRsaSpki(&spki_buf, &m2203_n, &m2203_ed);
    // The signature is a SHA-256 PSS, but the params declare SHA-512.
    var params_buf: [256]u8 = undefined;
    const params = testBuildPssParams(&params_buf, .{
        .hash_oid = &PssHashOid.sha512,
        .mgf_hash_oid = &PssHashOid.sha512,
        .salt_content = &[_]u8{32},
    });
    try std.testing.expectError(
        error.BadSignature,
        verifyCertSignature(tbs, &sig, &SigOid.rsassa_pss, params, spki),
    );
}

test "verifyCertSignature rejects RSASSA-PSS with a missing/oversized salt (fail-closed cap)" {
    var spki_buf: [700]u8 = undefined;
    const spki = testBuildRsaSpki(&spki_buf, &m2203_n, &m2203_ed);
    const sig = @as([276]u8, @splat(0)); // full M2203 modulus length

    // saltLength = 4096, far above the max_pss_salt_len (512) cap → reject.
    var over_buf: [256]u8 = undefined;
    const over = testBuildPssParams(&over_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha256,
        .salt_content = &[_]u8{ 0x10, 0x00 },
    });
    try std.testing.expectError(
        error.BadSignature,
        verifyCertSignature("x", &sig, &SigOid.rsassa_pss, over, spki),
    );

    // A PSS OID with absent parameters is malformed → reject (never default).
    try std.testing.expectError(
        error.BadSignature,
        verifyCertSignature("x", &sig, &SigOid.rsassa_pss, null, spki),
    );
}

test "parsePssParams accepts the three supported hashes with matching MGF1" {
    inline for (.{
        .{ rsa_verify.HashAlg.sha256, @as([]const u8, &PssHashOid.sha256), @as(u8, 32) },
        .{ rsa_verify.HashAlg.sha384, @as([]const u8, &PssHashOid.sha384), @as(u8, 48) },
        .{ rsa_verify.HashAlg.sha512, @as([]const u8, &PssHashOid.sha512), @as(u8, 64) },
    }) |case| {
        var buf: [256]u8 = undefined;
        const params = testBuildPssParams(&buf, .{
            .hash_oid = case[1],
            .mgf_hash_oid = case[1],
            .salt_content = &[_]u8{case[2]},
        });
        const parsed = try parsePssParams(params);
        try std.testing.expectEqual(case[0], parsed.hash);
        try std.testing.expectEqual(@as(usize, case[2]), parsed.salt_len);
    }
    // saltLength exactly at the cap (512 = 0x0200) is accepted.
    var cap_buf: [256]u8 = undefined;
    const cap = testBuildPssParams(&cap_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha256,
        .salt_content = &[_]u8{ 0x02, 0x00 },
    });
    try std.testing.expectEqual(@as(usize, 512), (try parsePssParams(cap)).salt_len);
}

test "parsePssParams is fail-closed on SHA-1, MGF/hash mismatch, oversized salt, trailer, and malformed input" {
    // A) SHA-1 hashAlgorithm (and MGF1-SHA1) → never accepted.
    var a_buf: [256]u8 = undefined;
    const a = testBuildPssParams(&a_buf, .{
        .hash_oid = &oid_sha1,
        .mgf_hash_oid = &oid_sha1,
        .salt_content = &[_]u8{20},
    });
    try std.testing.expectError(error.UnsupportedSigAlg, parsePssParams(a));

    // B) hashAlgorithm SHA-256 but MGF1 inner hash SHA-512 → mismatch.
    var b_buf: [256]u8 = undefined;
    const b = testBuildPssParams(&b_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha512,
        .salt_content = &[_]u8{32},
    });
    try std.testing.expectError(error.BadSignature, parsePssParams(b));

    // C) oversized saltLength (513 = 0x0201, one past the cap) → reject.
    var c_buf: [256]u8 = undefined;
    const c = testBuildPssParams(&c_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha256,
        .salt_content = &[_]u8{ 0x02, 0x01 },
    });
    try std.testing.expectError(error.BadSignature, parsePssParams(c));

    // D) missing saltLength [2] → reject (never fall back to the DEFAULT 20).
    var d_buf: [256]u8 = undefined;
    const d = testBuildPssParams(&d_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha256,
        .salt_content = null,
    });
    try std.testing.expectError(error.UnsupportedSigAlg, parsePssParams(d));

    // E) trailerField = 2 (only 1 is defined) → reject.
    var e_buf: [256]u8 = undefined;
    const e = testBuildPssParams(&e_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha256,
        .salt_content = &[_]u8{32},
        .trailer = 2,
    });
    try std.testing.expectError(error.BadSignature, parsePssParams(e));

    // F) a non-SEQUENCE / truncated blob → structural parse error.
    try std.testing.expectError(error.InvalidTag, parsePssParams(&[_]u8{ 0x05, 0x00 }));
    try std.testing.expectError(error.Truncated, parsePssParams(&[_]u8{0x30}));

    // G) negative saltLength (INTEGER 0x80) → reject.
    var g_buf: [256]u8 = undefined;
    const g = testBuildPssParams(&g_buf, .{
        .hash_oid = &PssHashOid.sha256,
        .mgf_hash_oid = &PssHashOid.sha256,
        .salt_content = &[_]u8{0x80},
    });
    try std.testing.expectError(error.BadSignature, parsePssParams(g));
}
