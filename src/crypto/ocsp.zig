// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal fail-closed OCSP response parser for TLS OCSP stapling.
//!
//! This module implements the DER structure checks needed to consume stapled
//! OCSP responses (RFC 6960) and extract each SingleResponse CertID/status. It
//! intentionally does not verify the BasicOCSPResponse responder signature or
//! validate responder authorization; callers must do that before trusting the
//! freshness or authenticity of the result.
const std = @import("std");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_verify = @import("rsa_verify.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

pub const DefaultMaxResponses = 8;

pub const Error = x509.Error || error{
    InvalidOcspResponse,
    InvalidResponseStatus,
    InvalidGeneralizedTime,
    MissingResponseBytes,
    UnexpectedResponseBytes,
    UnsupportedResponseType,
    TooManyResponses,
};

const Asn1Tag = struct {
    const enumerated = 0x0A;
    const context_0_primitive = 0x80;
    const context_1_primitive = 0x81;
    const context_2_primitive = 0x82;
    const context_2_constructed = 0xA2;
};

const Oid = struct {
    // id-pkix-ocsp-basic: 1.3.6.1.5.5.7.48.1.1
    const ocsp_basic = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
};

pub const ResponseStatus = enum(u8) {
    successful = 0,
    malformedRequest = 1,
    internalError = 2,
    tryLater = 3,
    sigRequired = 5,
    unauthorized = 6,
};

pub const CertStatus = enum {
    good,
    revoked,
    unknown,
};

/// How the BasicOCSPResponse identifies its signer (RFC 6960 ResponderID).
pub const ResponderIdKind = enum {
    /// No responderID captured (parse skipped it / absent).
    none,
    /// byName [1]: the responder's subject `Name`. `responder_id_value` is the
    /// full `Name` TLV, to byte-compare against a cert's `subject_der`.
    by_name,
    /// byKey [2]: SHA-1 of the responder's subjectPublicKey. `responder_id_value`
    /// is that 20-byte KeyHash.
    by_key,
};

pub const SingleResponse = struct {
    /// AlgorithmIdentifier.algorithm from CertID.hashAlgorithm.
    hash_algorithm_oid: []const u8,
    /// CertID.issuerNameHash; retained as a slice into the OCSP DER input.
    issuer_name_hash: []const u8,
    /// CertID.issuerKeyHash; retained as a slice into the OCSP DER input.
    issuer_key_hash: []const u8,
    /// DER INTEGER contents for CertID.serialNumber, including a leading sign
    /// zero when DER required one for a positive serial.
    serial: []const u8,
    cert_status: CertStatus,
    /// Validated GeneralizedTime bytes (`YYYYMMDDHHMMSSZ`).
    this_update: []const u8,
    /// Optional validated nextUpdate GeneralizedTime bytes.
    next_update: ?[]const u8,
    /// Content bytes of the SingleResponse `singleExtensions` — the inner
    /// `SEQUENCE OF Extension` (RFC 6960 §4.2.1), a view into the OCSP DER input,
    /// or empty when absent. Scan it with `sctListFromSingleExtensions` to mine an
    /// RFC 6962 OCSP-delivered SCT list. Defaulted so hand-built literals need not
    /// set it.
    single_extensions_der: []const u8 = &.{},
};

pub fn ParsedResponse(comptime max_responses: usize) type {
    return struct {
        const Self = @This();

        der: []const u8,
        response_status: ResponseStatus,
        basic_response_der: ?[]const u8,
        /// DER TLV for BasicOCSPResponse.tbsResponseData; signed by
        /// BasicOCSPResponse.signature.
        tbs_response_data_der: []const u8,
        /// AlgorithmIdentifier.algorithm from BasicOCSPResponse.signatureAlgorithm.
        signature_algorithm_oid: []const u8,
        /// Raw bytes from BasicOCSPResponse.signature BIT STRING.
        signature_value: []const u8,
        /// How tbsResponseData.responderID names the signer. Defaulted so a
        /// hand-built literal (e.g. a status-decision test) need not set the
        /// delegation fields.
        responder_id_kind: ResponderIdKind = .none,
        /// The ResponderID payload (byName: the `Name` TLV; byKey: the 20-byte
        /// KeyHash). A view into the OCSP DER input.
        responder_id_value: []const u8 = &.{},
        /// BasicOCSPResponse.certs [0] content — a `SEQUENCE OF Certificate` (the
        /// embedded delegated-responder cert chain), or empty when absent. A view
        /// into the OCSP DER input.
        certs_der: []const u8 = &.{},
        responses: [max_responses]SingleResponse,
        response_count: usize,

        pub fn responseAt(self: *const Self, index: usize) ?SingleResponse {
            if (index >= self.response_count) return null;
            return self.responses[index];
        }
    };
}

pub const Parsed = ParsedResponse(DefaultMaxResponses);

pub fn parse(der: []const u8) Error!Parsed {
    return parseBounded(DefaultMaxResponses, der);
}

pub fn parseBounded(comptime max_responses: usize, der: []const u8) Error!ParsedResponse(max_responses) {
    if (der.len == 0) return error.EmptyInput;
    if (der.len > x509.MaxDerLen) return error.Oversize;

    var parsed = ParsedResponse(max_responses){
        .der = der,
        .response_status = .successful,
        .basic_response_der = null,
        .tbs_response_data_der = &.{},
        .signature_algorithm_oid = &.{},
        .signature_value = &.{},
        .responder_id_kind = .none,
        .responder_id_value = &.{},
        .certs_der = &.{},
        .responses = undefined,
        .response_count = 0,
    };

    var top = x509.DerReader.init(der);
    const ocsp_response = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(ocsp_response);
    parsed.response_status = try parseResponseStatus(try body.readExpected(Asn1Tag.enumerated));

    if (parsed.response_status != .successful) {
        if (body.hasRemaining()) return error.UnexpectedResponseBytes;
        return parsed;
    }

    if (!body.hasRemaining()) return error.MissingResponseBytes;
    const response_bytes_explicit = try body.readExpected(x509.Tag.context_0_constructed);
    try body.expectEmpty();
    const basic_der = try parseResponseBytes(body, response_bytes_explicit);
    parsed.basic_response_der = basic_der;
    try parseBasicOcspResponse(max_responses, &parsed, basic_der);
    return parsed;
}

pub fn statusForSerial(parsed: anytype, serial: []const u8) ?CertStatus {
    for (parsed.responses[0..parsed.response_count]) |single| {
        if (serialsEqual(single.serial, serial)) return single.cert_status;
    }
    return null;
}

/// The full SingleResponse matching `serial`, or null when absent. Unlike
/// `statusForSerial` this exposes `thisUpdate`/`nextUpdate` so freshness can be
/// evaluated on the *matching* entry rather than assuming a single-response body.
pub fn singleForSerial(parsed: anytype, serial: []const u8) ?SingleResponse {
    for (parsed.responses[0..parsed.response_count]) |single| {
        if (serialsEqual(single.serial, serial)) return single;
    }
    return null;
}

/// OID 1.3.6.1.4.1.11129.2.4.5 — the OCSP-delivered `SignedCertificateTimestampList`
/// extension (RFC 6962 §3.3), carried in a `SingleResponse`'s `singleExtensions`.
/// One digit past the X.509 embedded-SCT extension (`...2.4.2`).
pub const sct_ocsp_extension_oid = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x05 };

/// Scan a `SingleResponse.single_extensions_der` (the raw `SEQUENCE OF Extension`
/// content) for the OCSP SCT-list extension and return the raw TLS
/// `SignedCertificateTimestampList` bytes — ready for `sct.parseList`, signing the
/// FINAL leaf DER (`x509_entry`) like the TLS extension — or `null` when the
/// extension is absent. The exact-OID compare is the identity boundary; any
/// malformed extension DER fails closed with a typed error. The SCT extension's
/// `extnValue` wraps a `SignedCertificateTimestampList ::= OCTET STRING` (the same
/// shape as the X.509 extension), so `x509.parseSctList` peels the inner OCTET
/// STRING to the TLS list bytes.
pub fn sctListFromSingleExtensions(single_extensions_der: []const u8) Error!?[]const u8 {
    if (single_extensions_der.len == 0) return null;
    var extensions = x509.DerReader.init(single_extensions_der);
    while (extensions.hasRemaining()) {
        const one_tlv = try extensions.readExpected(x509.Tag.sequence);
        var one = try extensions.child(one_tlv);
        const oid_tlv = try one.readExpected(x509.Tag.oid);
        try validateOid(oid_tlv.value);
        if (one.hasRemaining() and try one.peekTag() == x509.Tag.boolean) {
            _ = try one.readTlv(); // optional `critical` flag (ignored)
        }
        const value = try one.readExpected(x509.Tag.octet_string);
        try one.expectEmpty();
        if (std.mem.eql(u8, oid_tlv.value, &sct_ocsp_extension_oid)) {
            return try x509.parseSctList(value.value);
        }
    }
    return null;
}

/// Skew tolerance (seconds) applied to OCSP `thisUpdate`/`nextUpdate` when
/// deciding whether a cached staple is still safe to serve. Five minutes covers
/// ordinary host/responder clock drift without meaningfully weakening the
/// revocation-freshness guarantee.
pub const default_staple_skew_seconds: i64 = 300;

/// Decide whether a raw DER OCSP response is safe to staple *right now* for the
/// certificate with serial `leaf_serial`, given the daemon wall-clock `now_unix`
/// (Unix seconds) and the issuer SubjectPublicKeyInfo used to authenticate the
/// responder signature. This is the security gate the fetch service applies
/// before caching/publishing a staple (OCSP-stapling design §5 step 4):
///   - parse succeeds and `responseStatus == successful`;
///   - the BasicOCSPResponse signature verifies against `issuer_spki_der`,
///     accepting either direct-issuer signing OR an issuer-authorized delegated
///     responder cert (`id-kp-OCSPSigning`, ResponderID-matched, in-window);
///   - the SingleResponse for `leaf_serial` is present and `good`;
///   - it carries a `nextUpdate`, and `thisUpdate <= now < nextUpdate` after
///     applying `skew_seconds` of clock tolerance on each bound.
/// Any parse/verify/decoding failure returns `false` rather than throwing, so a
/// caller can treat a bad fetch as "keep the previous good staple, or none".
pub fn isStapleServable(
    response_der: []const u8,
    issuer_spki_der: []const u8,
    leaf_serial: []const u8,
    now_unix: i64,
    skew_seconds: i64,
) bool {
    const parsed = parse(response_der) catch return false;
    if (parsed.response_status != .successful) return false;
    if (!verifyResponseSignatureWithChain(parsed, issuer_spki_der, now_unix)) return false;

    const single = singleForSerial(parsed, leaf_serial) orelse return false;
    if (single.cert_status != .good) return false;

    const next_bytes = single.next_update orelse return false;
    const this_epoch = x509.generalizedTimeToEpoch(single.this_update) catch return false;
    const next_epoch = x509.generalizedTimeToEpoch(next_bytes) catch return false;
    if (next_epoch <= this_epoch) return false;
    if (now_unix + skew_seconds < this_epoch) return false; // not yet valid
    if (now_unix >= next_epoch + skew_seconds) return false; // expired
    return true;
}

/// Verify a BasicOCSPResponse signed directly by the issuing CA.
///
/// This covers the common stapling case where `signature` authenticates
/// `tbsResponseData` with the issuer certificate's SubjectPublicKeyInfo. OCSP
/// delegated responders are deliberately out of scope here: this function does
/// not validate responder certificates embedded in the BasicOCSPResponse, nor
/// does it enforce id-kp-OCSPSigning EKU. A caller that accepts delegated OCSP
/// responders must build and authorize that responder chain before trusting the
/// response.
pub fn verifyResponseSignature(parsed: anytype, issuer_spki_der: []const u8) bool {
    if (parsed.basic_response_der == null) return false;
    if (parsed.tbs_response_data_der.len == 0 or
        parsed.signature_algorithm_oid.len == 0 or
        parsed.signature_value.len == 0)
    {
        return false;
    }
    return verifyDerSignature(
        parsed.signature_algorithm_oid,
        issuer_spki_der,
        parsed.tbs_response_data_der,
        parsed.signature_value,
    );
}

/// Verify a BasicOCSPResponse that is EITHER directly issuer-signed OR signed by
/// a delegated responder (RFC 6960 §4.2.2.2 — the majority of public CAs). The
/// delegated path authorizes an embedded responder cert BEFORE trusting its
/// signature: the cert must
///   - match the response's ResponderID (byName or byKey),
///   - carry id-kp-OCSPSigning (anyExtendedKeyUsage deliberately does NOT count),
///   - be valid at `now_unix`, and
///   - be signed by `issuer_spki_der` — the CA that issued the certificate whose
///     status this response asserts.
/// Only then is the BasicOCSPResponse signature checked under the responder key.
/// `now_unix` is Unix seconds (used only for the responder-cert validity window).
///
/// Fail-closed: false on any parse/authorization/verification failure. A
/// multi-cert `certs` chain is NOT walked to a different root — only a responder
/// DIRECTLY delegated by `issuer_spki_der` is honored (the RFC 6960 common case).
pub fn verifyResponseSignatureWithChain(parsed: anytype, issuer_spki_der: []const u8, now_unix: i64) bool {
    // Direct issuer signing — the common stapling case; try it first.
    if (verifyResponseSignature(parsed, issuer_spki_der)) return true;

    // Delegated responder: needs a ResponderID, an embedded cert, and a signature.
    if (parsed.responder_id_kind == .none or parsed.certs_der.len == 0) return false;
    if (parsed.tbs_response_data_der.len == 0 or
        parsed.signature_algorithm_oid.len == 0 or
        parsed.signature_value.len == 0)
    {
        return false;
    }

    var reader = x509.DerReader.init(parsed.certs_der);
    const seq = reader.readExpected(x509.Tag.sequence) catch return false;
    var certs = reader.child(seq) catch return false;
    while (certs.hasRemaining()) {
        // `readTlv` (not `readExpected`) so a non-Certificate element is SKIPPED,
        // not fatal: a valid responder cert after a malformed sibling is still
        // tried. A length-malformed TLV can't be skipped safely, so stop there.
        const cert_tlv = certs.readTlv() catch break;
        if (cert_tlv.tag != x509.Tag.sequence) continue;
        if (delegateAuthorizesResponse(parsed, cert_tlv.raw, issuer_spki_der, now_unix)) return true;
    }
    return false;
}

/// True when `cert_der` is an issuer-authorized OCSP responder that signed
/// `parsed`. See `verifyResponseSignatureWithChain` for the authorization rules.
fn delegateAuthorizesResponse(parsed: anytype, cert_der: []const u8, issuer_spki_der: []const u8, now_unix: i64) bool {
    const cert = x509.Certificate.parse(cert_der) catch return false;
    // (a) Authorized for OCSP signing by the exact EKU (RFC 6960 §4.2.2.2).
    if (!cert.eku_ocsp_signing) return false;
    // (b) Is the responder the response committed to in its ResponderID.
    if (!responderIdMatchesCert(parsed, cert)) return false;
    // (c) Within its own validity window at `now_unix`.
    x509_verify.validateDerAt(cert_der, now_unix) catch return false;
    // (d) Issued (signed) by the trusted CA — `linkInfo` exposes the outer
    //     signature that the parsed Certificate view does not.
    const link = x509_verify.linkInfo(cert_der) catch return false;
    x509_verify.verifyCertSignature(link.tbs_der, link.signature_der, link.sig_alg_oid, link.sig_alg_params, issuer_spki_der) catch return false;
    // (e) The response must verify under this authorized responder's key.
    return verifyDerSignature(
        parsed.signature_algorithm_oid,
        cert.spki_der,
        parsed.tbs_response_data_der,
        parsed.signature_value,
    );
}

fn responderIdMatchesCert(parsed: anytype, cert: x509.Certificate) bool {
    return switch (parsed.responder_id_kind) {
        .by_name => std.mem.eql(u8, parsed.responder_id_value, cert.subject_der),
        .by_key => blk: {
            const Sha1 = std.crypto.hash.Sha1;
            var key_hash: [Sha1.digest_length]u8 = undefined;
            Sha1.hash(cert.subject_public_key, &key_hash, .{});
            break :blk parsed.responder_id_value.len == key_hash.len and
                std.mem.eql(u8, parsed.responder_id_value, &key_hash);
        },
        .none => false,
    };
}

/// Verify an X.509-style DER signature whose key is carried in SPKI form.
///
/// This helper is shared by OCSP and CRL parsing code. It intentionally
/// supports only the signature schemes used by the daemon's certificate path:
/// SHA256-RSA PKCS#1 v1.5, RSA-PSS with SHA-256 and 32-byte salt, ECDSA
/// P-256/SHA-256, ECDSA P-384/SHA-384, and Ed25519.
pub fn verifyDerSignature(
    signature_algorithm_oid: []const u8,
    signer_spki_der: []const u8,
    signed_data: []const u8,
    signature: []const u8,
) bool {
    const key = parsePublicKeyFromSpki(signer_spki_der) catch return false;
    verifyWithOid(key, signature_algorithm_oid, signed_data, signature) catch return false;
    return true;
}

fn parseResponseStatus(tlv: x509.Tlv) Error!ResponseStatus {
    if (tlv.value.len != 1) return error.InvalidResponseStatus;
    return switch (tlv.value[0]) {
        0 => .successful,
        1 => .malformedRequest,
        2 => .internalError,
        3 => .tryLater,
        5 => .sigRequired,
        6 => .unauthorized,
        else => error.InvalidResponseStatus,
    };
}

fn parseResponseBytes(parent: x509.DerReader, explicit_tlv: x509.Tlv) Error![]const u8 {
    var explicit = try parent.child(explicit_tlv);
    const seq_tlv = try explicit.readExpected(x509.Tag.sequence);
    try explicit.expectEmpty();

    var seq = try explicit.child(seq_tlv);
    const oid_tlv = try seq.readExpected(x509.Tag.oid);
    try validateOid(oid_tlv.value);
    if (!std.mem.eql(u8, oid_tlv.value, &Oid.ocsp_basic)) return error.UnsupportedResponseType;

    const response = try seq.readExpected(x509.Tag.octet_string);
    try seq.expectEmpty();
    return response.value;
}

fn parseBasicOcspResponse(
    comptime max_responses: usize,
    parsed: *ParsedResponse(max_responses),
    der: []const u8,
) Error!void {
    var top = x509.DerReader.init(der);
    const basic = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(basic);
    const tbs = try body.readExpected(x509.Tag.sequence);

    parsed.tbs_response_data_der = tbs.raw;
    parsed.signature_algorithm_oid = try parseAlgorithmIdentifier(body, try body.readExpected(x509.Tag.sequence));
    parsed.signature_value = try parseSignatureBitString(try body.readExpected(x509.Tag.bit_string));
    if (body.hasRemaining()) {
        // certs [0] EXPLICIT SEQUENCE OF Certificate — captured for delegated
        // responder authorization; its content is the `SEQUENCE OF Certificate`.
        const certs_explicit = try body.readExpected(x509.Tag.context_0_constructed);
        parsed.certs_der = certs_explicit.value;
    }
    try body.expectEmpty();

    try parseResponseData(max_responses, parsed, body, tbs);
}

fn parseResponseData(
    comptime max_responses: usize,
    parsed: *ParsedResponse(max_responses),
    parent: x509.DerReader,
    tbs_tlv: x509.Tlv,
) Error!void {
    var tbs = try parent.child(tbs_tlv);

    if (tbs.hasRemaining() and try tbs.peekTag() == x509.Tag.context_0_constructed) {
        try parseVersion(tbs, try tbs.readTlv());
    }

    const responder = try tbs.readTlv();
    switch (responder.tag) {
        x509.Tag.context_1_constructed => {
            // byName [1] EXPLICIT Name — the wrapper holds the subject `Name`
            // SEQUENCE; capture it whole for a byte-compare against subject_der.
            var inner = try parent.child(responder);
            const name = try inner.readExpected(x509.Tag.sequence);
            parsed.responder_id_kind = .by_name;
            parsed.responder_id_value = name.raw;
        },
        Asn1Tag.context_2_constructed => {
            // byKey [2] EXPLICIT KeyHash (OCTET STRING) — the SHA-1 of the
            // responder's subjectPublicKey.
            var inner = try parent.child(responder);
            const oct = try inner.readExpected(x509.Tag.octet_string);
            parsed.responder_id_kind = .by_key;
            parsed.responder_id_value = oct.value;
        },
        Asn1Tag.context_2_primitive => {
            // byKey [2] IMPLICIT (lenient — some encoders emit a primitive
            // OCTET STRING) — the value is the KeyHash directly.
            parsed.responder_id_kind = .by_key;
            parsed.responder_id_value = responder.value;
        },
        else => return error.InvalidOcspResponse,
    }

    _ = try parseGeneralizedTime(try tbs.readExpected(x509.Tag.generalized_time));

    const responses_tlv = try tbs.readExpected(x509.Tag.sequence);
    var responses = try tbs.child(responses_tlv);
    while (responses.hasRemaining()) {
        if (parsed.response_count >= parsed.responses.len) return error.TooManyResponses;
        parsed.responses[parsed.response_count] = try parseSingleResponse(responses, try responses.readExpected(x509.Tag.sequence));
        parsed.response_count += 1;
    }

    if (tbs.hasRemaining()) {
        _ = try tbs.readExpected(x509.Tag.context_1_constructed); // responseExtensions
    }
    try tbs.expectEmpty();
}

fn parseVersion(parent: x509.DerReader, version_tlv: x509.Tlv) Error!void {
    var explicit = try parent.child(version_tlv);
    const version = try explicit.readExpected(x509.Tag.integer);
    try explicit.expectEmpty();
    try validateDerInteger(version.value);
    if (version.value.len != 1 or version.value[0] != 0) return error.InvalidOcspResponse;
}

fn parseSingleResponse(parent: x509.DerReader, single_tlv: x509.Tlv) Error!SingleResponse {
    var single = try parent.child(single_tlv);
    const cert_id = try parseCertId(single, try single.readExpected(x509.Tag.sequence));
    const status = try parseCertStatus(single, try single.readTlv());
    const this_update = try parseGeneralizedTime(try single.readExpected(x509.Tag.generalized_time));

    var next_update: ?[]const u8 = null;
    if (single.hasRemaining() and try single.peekTag() == x509.Tag.context_0_constructed) {
        var explicit = try single.child(try single.readTlv());
        next_update = try parseGeneralizedTime(try explicit.readExpected(x509.Tag.generalized_time));
        try explicit.expectEmpty();
    }

    var single_extensions_der: []const u8 = &.{};
    if (single.hasRemaining()) {
        // singleExtensions [1] EXPLICIT Extensions (SEQUENCE OF Extension).
        var explicit = try single.child(try single.readExpected(x509.Tag.context_1_constructed));
        const seq = try explicit.readExpected(x509.Tag.sequence);
        try explicit.expectEmpty();
        single_extensions_der = seq.value;
    }
    try single.expectEmpty();

    return .{
        .hash_algorithm_oid = cert_id.hash_algorithm_oid,
        .issuer_name_hash = cert_id.issuer_name_hash,
        .issuer_key_hash = cert_id.issuer_key_hash,
        .serial = cert_id.serial,
        .cert_status = status,
        .this_update = this_update,
        .next_update = next_update,
        .single_extensions_der = single_extensions_der,
    };
}

const CertId = struct {
    hash_algorithm_oid: []const u8,
    issuer_name_hash: []const u8,
    issuer_key_hash: []const u8,
    serial: []const u8,
};

fn parseCertId(parent: x509.DerReader, cert_id_tlv: x509.Tlv) Error!CertId {
    var cert_id = try parent.child(cert_id_tlv);
    const hash_algorithm_oid = try parseAlgorithmIdentifier(cert_id, try cert_id.readExpected(x509.Tag.sequence));
    const issuer_name_hash = try cert_id.readExpected(x509.Tag.octet_string);
    const issuer_key_hash = try cert_id.readExpected(x509.Tag.octet_string);
    const serial = try cert_id.readExpected(x509.Tag.integer);
    try validatePositiveInteger(serial.value);
    try cert_id.expectEmpty();

    return .{
        .hash_algorithm_oid = hash_algorithm_oid,
        .issuer_name_hash = issuer_name_hash.value,
        .issuer_key_hash = issuer_key_hash.value,
        .serial = serial.value,
    };
}

fn parseAlgorithmIdentifier(parent: x509.DerReader, seq_tlv: x509.Tlv) Error![]const u8 {
    var alg = try parent.child(seq_tlv);
    const oid_tlv = try alg.readExpected(x509.Tag.oid);
    try validateOid(oid_tlv.value);
    if (alg.hasRemaining()) {
        _ = try alg.readTlv(); // optional parameters
    }
    try alg.expectEmpty();
    return oid_tlv.value;
}

fn parseCertStatus(parent: x509.DerReader, status_tlv: x509.Tlv) Error!CertStatus {
    return switch (status_tlv.tag) {
        Asn1Tag.context_0_primitive => blk: {
            if (status_tlv.value.len != 0) return error.InvalidOcspResponse;
            break :blk .good;
        },
        x509.Tag.context_1_constructed => blk: {
            var revoked = try parent.child(status_tlv);
            _ = try parseGeneralizedTime(try revoked.readExpected(x509.Tag.generalized_time));
            if (revoked.hasRemaining()) {
                _ = try revoked.readExpected(x509.Tag.context_0_constructed); // revocationReason
            }
            try revoked.expectEmpty();
            break :blk .revoked;
        },
        Asn1Tag.context_2_primitive => blk: {
            if (status_tlv.value.len != 0) return error.InvalidOcspResponse;
            break :blk .unknown;
        },
        else => error.InvalidOcspResponse,
    };
}

fn parseBitString(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

fn parseSignatureBitString(tlv: x509.Tlv) Error![]const u8 {
    const bytes = try parseBitString(tlv);
    if (tlv.value[0] != 0) return error.InvalidBitString;
    return bytes;
}

fn parseGeneralizedTime(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.value.len != 15 or tlv.value[14] != 'Z') return error.InvalidGeneralizedTime;
    _ = try digits(tlv.value[0..4]);
    const month = try digits(tlv.value[4..6]);
    const day = try digits(tlv.value[6..8]);
    const hour = try digits(tlv.value[8..10]);
    const minute = try digits(tlv.value[10..12]);
    const second = try digits(tlv.value[12..14]);
    if (month < 1 or month > 12) return error.InvalidGeneralizedTime;
    if (day < 1 or day > 31) return error.InvalidGeneralizedTime;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidGeneralizedTime;
    return tlv.value;
}

fn digits(bytes: []const u8) Error!u16 {
    var value: u16 = 0;
    for (bytes) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidGeneralizedTime;
        value = value * 10 + @as(u16, byte - '0');
    }
    return value;
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

fn serialsEqual(a_der: []const u8, b_der: []const u8) bool {
    if (std.mem.eql(u8, a_der, b_der)) return true;
    return std.mem.eql(u8, unsignedSerial(a_der), unsignedSerial(b_der));
}

fn unsignedSerial(serial: []const u8) []const u8 {
    if (serial.len > 1 and serial[0] == 0x00) return serial[1..];
    return serial;
}

const PublicKey = union(enum) {
    rsa: rsa_verify.PublicKey,
    ecdsa_p256: ecdsa_p256.PublicKey,
    ecdsa_p384: EcdsaP384.PublicKey,
    ed25519: Ed25519.PublicKey,
};

fn verifyWithOid(key: PublicKey, oid: []const u8, msg: []const u8, sig: []const u8) !void {
    if (oidEq(oid, &oid_ecdsa_sha256)) {
        const pk = switch (key) {
            .ecdsa_p256 => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        const decoded = try ecdsa_p256.signatureFromDer(sig);
        if (!ecdsa_p256.verify(decoded, msg, pk)) return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_ecdsa_sha384)) {
        const pk = switch (key) {
            .ecdsa_p384 => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        const decoded = EcdsaP384.Signature.fromDer(sig) catch return error.BadSignature;
        decoded.verify(msg, pk) catch return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_sha256_rsa)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
        if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, sig)) return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_rsassa_pss)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
        if (!rsa_verify.verifyPss(pk, .sha256, &digest, sig, 32)) return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_ed25519)) {
        const pk = switch (key) {
            .ed25519 => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        if (sig.len != Ed25519.Signature.encoded_length) return error.BadSignature;
        const decoded = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
        decoded.verify(msg, pk) catch return error.BadSignature;
        return;
    }
    return error.UnsupportedSignatureScheme;
}

fn parsePublicKeyFromSpki(spki_der: []const u8) !PublicKey {
    var top = x509.DerReader.init(spki_der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(x509.Tag.sequence);
    const key_bits = try spki.readExpected(x509.Tag.bit_string);
    try spki.expectEmpty();
    const alg = try parseSpkiAlgorithm(spki, alg_seq);
    const key_bytes = try bitStringBytesZero(key_bits);
    if (oidEq(alg.oid, &oid_rsa_encryption)) {
        var r = x509.DerReader.init(key_bytes);
        const rsa_seq = try r.readExpected(x509.Tag.sequence);
        try r.expectEmpty();
        var body = try r.child(rsa_seq);
        const n = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        const e = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        try body.expectEmpty();
        return .{ .rsa = .{ .n = n, .e = e } };
    }
    if (oidEq(alg.oid, &oid_ec_public_key)) {
        const params = alg.params orelse return error.UnsupportedPublicKey;
        if (oidEq(params, &oid_prime256v1)) {
            return .{ .ecdsa_p256 = try ecdsa_p256.parsePublicKeySec1(key_bytes) };
        }
        if (oidEq(params, &oid_secp384r1)) {
            return .{ .ecdsa_p384 = EcdsaP384.PublicKey.fromSec1(key_bytes) catch return error.UnsupportedPublicKey };
        }
        return error.UnsupportedPublicKey;
    }
    if (oidEq(alg.oid, &oid_ed25519)) {
        if (key_bytes.len != Ed25519.PublicKey.encoded_length) return error.UnsupportedPublicKey;
        return .{ .ed25519 = Ed25519.PublicKey.fromBytes(key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return error.UnsupportedPublicKey };
    }
    return error.UnsupportedPublicKey;
}

const SpkiAlgorithm = struct {
    oid: []const u8,
    params: ?[]const u8,
};

fn parseSpkiAlgorithm(parent: x509.DerReader, seq_tlv: x509.Tlv) !SpkiAlgorithm {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    try validateOid(oid.value);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) {
        const p = try r.readTlv();
        if (p.tag == x509.Tag.oid) params = p.value;
    }
    try r.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

fn bitStringBytesZero(tlv: x509.Tlv) ![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    if (tlv.value[0] != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

fn positiveIntegerBytes(tlv: x509.Tlv) ![]const u8 {
    if (tlv.tag != x509.Tag.integer or tlv.value.len == 0) return error.InvalidInteger;
    if (tlv.value[0] & 0x80 != 0) return error.InvalidInteger;
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..];
    if (v.len == 0) return error.InvalidInteger;
    return v;
}

fn oidEq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const oid_rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
const oid_sha256_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
const oid_rsassa_pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_secp384r1 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_ecdsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };

const ocsp_good_one_response = [_]u8{
    0x30, 0x81, 0xBD,
    0x0A, 0x01, 0x00,
    0xA0, 0x81, 0xB7,
    0x30, 0x81, 0xB4,
    0x06, 0x09, 0x2B,
    0x06, 0x01, 0x05,
    0x05, 0x07, 0x30,
    0x01, 0x01, 0x04,
    0x81, 0xA6, 0x30,
    0x81, 0xA3, 0x30,
    0x81, 0x8D, 0x82,
    0x14, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0x18, 0x0F, '2',
    '0',  '2',  '6',
    '0',  '1',  '0',
    '2',  '0',  '3',
    '0',  '4',  '0',
    '5',  'Z',  0x30,
    0x64, 0x30, 0x62,
    0x30, 0x3A, 0x30,
    0x09, 0x06, 0x05,
    0x2B, 0x0E, 0x03,
    0x02, 0x1A, 0x05,
    0x00, 0x04, 0x14,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x04,
    0x14, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x02, 0x01, 0x01,
    0x80, 0x00, 0x18,
    0x0F, '2',  '0',
    '2',  '6',  '0',
    '1',  '0',  '2',
    '0',  '3',  '0',
    '4',  '0',  '5',
    'Z',  0xA0, 0x11,
    0x18, 0x0F, '2',
    '0',  '2',  '6',
    '0',  '2',  '0',
    '2',  '0',  '3',
    '0',  '4',  '0',
    '5',  'Z',  0x30,
    0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x0B,
    0x05, 0x00, 0x03,
    0x02, 0x00, 0x00,
};

test "ocsp parses successful basic response with one good single response" {
    const parsed = try parse(&ocsp_good_one_response);
    try std.testing.expectEqual(ResponseStatus.successful, parsed.response_status);
    try std.testing.expect(parsed.basic_response_der != null);
    try std.testing.expectEqual(@as(usize, 1), parsed.response_count);

    const single = parsed.responses[0];
    try std.testing.expectEqual(CertStatus.good, single.cert_status);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, single.serial);
    try std.testing.expectEqualSlices(u8, "20260102030405Z", single.this_update);
    try std.testing.expect(single.next_update != null);
    try std.testing.expectEqualSlices(u8, "20260202030405Z", single.next_update.?);
    try std.testing.expectEqual(CertStatus.good, statusForSerial(parsed, &[_]u8{0x01}).?);
    try std.testing.expect(statusForSerial(parsed, &[_]u8{0x02}) == null);
    // No singleExtensions present ⇒ empty, and thus no OCSP-delivered SCTs.
    try std.testing.expectEqual(@as(usize, 0), single.single_extensions_der.len);
    try std.testing.expectEqual(@as(?[]const u8, null), try sctListFromSingleExtensions(single.single_extensions_der));
}

test "sctListFromSingleExtensions mines the OCSP SCT extension and fails closed" {
    // Empty singleExtensions ⇒ no SCTs.
    try std.testing.expectEqual(@as(?[]const u8, null), try sctListFromSingleExtensions(""));

    // One Extension: SEQUENCE { OID sct-ocsp (…2.4.5), OCTET STRING( OCTET
    // STRING( 0xAA 0xBB ) ) }. `parseSctList` peels the inner OCTET STRING.
    const ext = [_]u8{
        0x30, 0x12,
        0x06, 0x0A,
        0x2B, 0x06,
        0x01, 0x04,
        0x01, 0xD6,
        0x79, 0x02,
        0x04, 0x05,
        0x04, 0x04,
        0x04, 0x02,
        0xAA, 0xBB,
    };
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, (try sctListFromSingleExtensions(&ext)).?);

    // A non-matching extension OID (basicConstraints) ⇒ null: not this source.
    const other = [_]u8{ 0x30, 0x08, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x01, 0x00 };
    try std.testing.expectEqual(@as(?[]const u8, null), try sctListFromSingleExtensions(&other));

    // Truncated extension DER ⇒ fail closed with a typed error, never a read past.
    try std.testing.expectError(error.Truncated, sctListFromSingleExtensions(&[_]u8{ 0x30, 0x12, 0x06 }));
}

test "ocsp rejects malformed outer responses" {
    try std.testing.expectError(error.EmptyInput, parse(""));
    try std.testing.expectError(error.Truncated, parse(ocsp_good_one_response[0 .. ocsp_good_one_response.len - 1]));
    try std.testing.expectError(error.MissingResponseBytes, parse(&[_]u8{ 0x30, 0x03, 0x0A, 0x01, 0x00 }));
    try std.testing.expectError(error.InvalidResponseStatus, parse(&[_]u8{ 0x30, 0x03, 0x0A, 0x01, 0x04 }));
    try std.testing.expectError(
        error.UnexpectedResponseBytes,
        parse(&[_]u8{ 0x30, 0x08, 0x0A, 0x01, 0x01, 0xA0, 0x03, 0x30, 0x01, 0x00 }),
    );
}

test "ocsp covers cert status tag bytes" {
    var good_reader = x509.DerReader.init(&[_]u8{ 0x80, 0x00 });
    try std.testing.expectEqual(CertStatus.good, try parseCertStatus(good_reader, try good_reader.readTlv()));

    var revoked_reader = x509.DerReader.init(&[_]u8{
        0xA1, 0x11,
        0x18, 0x0F,
        '2',  '0',
        '2',  '6',
        '0',  '1',
        '0',  '2',
        '0',  '3',
        '0',  '4',
        '0',  '5',
        'Z',
    });
    try std.testing.expectEqual(CertStatus.revoked, try parseCertStatus(revoked_reader, try revoked_reader.readTlv()));

    var unknown_reader = x509.DerReader.init(&[_]u8{ 0x82, 0x00 });
    try std.testing.expectEqual(CertStatus.unknown, try parseCertStatus(unknown_reader, try unknown_reader.readTlv()));

    var malformed_reader = x509.DerReader.init(&[_]u8{ 0x80, 0x01, 0x00 });
    try std.testing.expectError(error.InvalidOcspResponse, parseCertStatus(malformed_reader, try malformed_reader.readTlv()));
}

test "ocsp verifyResponseSignature accepts direct issuer Ed25519 signature" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x5A)));
    const spki = try testEd25519Spki(allocator, kp.public_key.toBytes());
    defer allocator.free(spki);
    const response = try testSignedOcspResponse(allocator, kp, &[_]u8{0x44}, .good, "20260202030405Z");
    defer allocator.free(response);

    const parsed = try parse(response);
    try std.testing.expect(verifyResponseSignature(parsed, spki));
    try std.testing.expectEqual(CertStatus.good, statusForSerial(parsed, &[_]u8{0x44}).?);

    var tampered = try allocator.dupe(u8, response);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    const bad = try parse(tampered);
    try std.testing.expect(!verifyResponseSignature(bad, spki));
}

test "buildRequest emits a well-formed single-CertID OCSP request" {
    const allocator = std.testing.allocator;
    const Sha1 = std.crypto.hash.Sha1;
    // Issuer Name = SEQUENCE{ SET{ SEQUENCE{ OID cn, UTF8String "CA" }}}.
    const issuer_name = "\x30\x0d\x31\x0b\x30\x09\x06\x03\x55\x04\x03\x0c\x02\x43\x41";
    const issuer_key = "\x04\x11\x22\x33\x44\x55"; // fake raw public-key bytes
    const serial = "\x12\x34\x56\x78";

    const req = try buildRequest(allocator, .{
        .issuer_name_der = issuer_name,
        .issuer_key_bytes = issuer_key,
        .serial_der = serial,
    });
    defer allocator.free(req);

    // Outer OCSPRequest is a DER SEQUENCE whose length covers the whole buffer.
    try std.testing.expectEqual(@as(u8, x509.Tag.sequence), req[0]);
    try std.testing.expectEqual(@as(usize, req[1] + 2), req.len); // short-form len (< 128)

    // The SHA-1 issuerNameHash, issuerKeyHash, the SHA-1 CertID OID, and the leaf
    // serial contents all appear verbatim in the request.
    var nh: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(issuer_name, &nh, .{});
    var kh: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(issuer_key, &kh, .{});
    try std.testing.expect(std.mem.indexOf(u8, req, &nh) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, &kh) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, &oid_sha1) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, serial) != null);

    // Structurally re-parse the CertID nesting: SEQ{ SEQ{ SEQ{ SEQ{ CertID... }}}}.
    var r = x509.DerReader{ .input = req };
    const ocsp_req = try r.readExpected(x509.Tag.sequence);
    var tbs_r = try r.child(ocsp_req);
    const tbs = try tbs_r.readExpected(x509.Tag.sequence);
    var list_r = try tbs_r.child(tbs);
    const list = try list_r.readExpected(x509.Tag.sequence);
    var one_r = try list_r.child(list);
    const one = try one_r.readExpected(x509.Tag.sequence);
    var cid_r = try one_r.child(one);
    _ = try cid_r.readExpected(x509.Tag.sequence); // CertID SEQUENCE parses cleanly
}

test "buildRequestForCerts derives the CertID from parsed leaf + issuer certs" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x6c)));
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&buf, .{
        .common_name = "issuer.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x6c, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"issuer.test"},
        .is_ca = true,
    });
    const cert = try x509.parse(der);

    // A self-signed cert is its own issuer — good enough to exercise the CertID
    // wiring (leaf serial + issuer Name + issuer raw key).
    const req = try buildRequestForCerts(allocator, cert, cert);
    defer allocator.free(req);
    try std.testing.expectEqual(@as(u8, x509.Tag.sequence), req[0]);

    const Sha1 = std.crypto.hash.Sha1;
    var nh: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(cert.subject_der, &nh, .{});
    var kh: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(cert.subject_public_key, &kh, .{});
    try std.testing.expect(std.mem.indexOf(u8, req, &nh) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, &kh) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, cert.serial_der) != null);
}

test "isStapleServable accepts a good, signed, in-window response" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7B)));
    const spki = try testEd25519Spki(allocator, kp.public_key.toBytes());
    defer allocator.free(spki);
    const response = try testSignedOcspResponse(allocator, kp, &[_]u8{0x44}, .good, "20260202030405Z");
    defer allocator.free(response);

    // The helper stamps thisUpdate=20260102030405Z, nextUpdate=20260202030405Z.
    const this_epoch = try x509.generalizedTimeToEpoch("20260102030405Z");
    const next_epoch = try x509.generalizedTimeToEpoch("20260202030405Z");
    const in_window = this_epoch + @divTrunc(next_epoch - this_epoch, 2);

    try std.testing.expect(isStapleServable(response, spki, &[_]u8{0x44}, in_window, 0));

    // Before thisUpdate and after nextUpdate (beyond skew) are both stale/premature.
    try std.testing.expect(!isStapleServable(response, spki, &[_]u8{0x44}, this_epoch - 100, 0));
    try std.testing.expect(!isStapleServable(response, spki, &[_]u8{0x44}, next_epoch + 100, 0));

    // Skew tolerance lets a slightly-off clock still serve a boundary response.
    try std.testing.expect(isStapleServable(response, spki, &[_]u8{0x44}, this_epoch - 100, 300));
    try std.testing.expect(isStapleServable(response, spki, &[_]u8{0x44}, next_epoch + 100, 300));
}

test "isStapleServable rejects revoked, wrong-serial, and tampered responses" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7C)));
    const spki = try testEd25519Spki(allocator, kp.public_key.toBytes());
    defer allocator.free(spki);
    const in_window = try x509.generalizedTimeToEpoch("20260115030405Z");

    // Revoked status is never servable, even in-window and correctly signed.
    const revoked = try testSignedOcspResponse(allocator, kp, &[_]u8{0x44}, .revoked, "20260202030405Z");
    defer allocator.free(revoked);
    try std.testing.expect(!isStapleServable(revoked, spki, &[_]u8{0x44}, in_window, 0));

    const good = try testSignedOcspResponse(allocator, kp, &[_]u8{0x44}, .good, "20260202030405Z");
    defer allocator.free(good);

    // A serial the response does not cover has no matching SingleResponse.
    try std.testing.expect(!isStapleServable(good, spki, &[_]u8{0x45}, in_window, 0));

    // Any signature/body tamper fails verification.
    const tampered = try allocator.dupe(u8, good);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expect(!isStapleServable(tampered, spki, &[_]u8{0x44}, in_window, 0));

    // A different issuer key fails verification even for a pristine good response.
    const other = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x2D)));
    const other_spki = try testEd25519Spki(allocator, other.public_key.toBytes());
    defer allocator.free(other_spki);
    try std.testing.expect(!isStapleServable(good, other_spki, &[_]u8{0x44}, in_window, 0));

    // Garbage bytes decode-fail rather than throw.
    try std.testing.expect(!isStapleServable("not der", spki, &[_]u8{0x44}, in_window, 0));

    // A response with no nextUpdate has no verifiable upper freshness bound.
    const no_next = try testSignedOcspResponse(allocator, kp, &[_]u8{0x44}, .good, null);
    defer allocator.free(no_next);
    try std.testing.expect(!isStapleServable(no_next, spki, &[_]u8{0x44}, in_window, 0));
}

/// Test-only mint: a BasicOCSPResponse signed by `kp` (Ed25519). Used by
/// substrate KATs and by `armor ocsp` CLI tests. Not a production builder.
pub fn testSignedOcspResponse(
    allocator: std.mem.Allocator,
    kp: Ed25519.KeyPair,
    serial: []const u8,
    status: CertStatus,
    next_update: ?[]const u8,
) ![]u8 {
    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(allocator);
    try appendDerTlv(allocator, &tbs_body, Asn1Tag.context_2_primitive, &(@as([20]u8, @splat(0xA5))));
    try appendDerTlv(allocator, &tbs_body, x509.Tag.generalized_time, "20260102030405Z");

    var responses_body: std.ArrayList(u8) = .empty;
    defer responses_body.deinit(allocator);
    var single_body: std.ArrayList(u8) = .empty;
    defer single_body.deinit(allocator);
    var cert_id_body: std.ArrayList(u8) = .empty;
    defer cert_id_body.deinit(allocator);
    try appendAlgId(allocator, &cert_id_body, &oid_sha1, true);
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.octet_string, &(@as([20]u8, @splat(0x11))));
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.octet_string, &(@as([20]u8, @splat(0x22))));
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.integer, serial);
    try appendDerSeq(allocator, &single_body, cert_id_body.items);
    switch (status) {
        .good => try appendDerTlv(allocator, &single_body, Asn1Tag.context_0_primitive, ""),
        .unknown => try appendDerTlv(allocator, &single_body, Asn1Tag.context_2_primitive, ""),
        .revoked => {
            var revoked_body: std.ArrayList(u8) = .empty;
            defer revoked_body.deinit(allocator);
            try appendDerTlv(allocator, &revoked_body, x509.Tag.generalized_time, "20260102030405Z");
            try appendDerTlv(allocator, &single_body, x509.Tag.context_1_constructed, revoked_body.items);
        },
    }
    try appendDerTlv(allocator, &single_body, x509.Tag.generalized_time, "20260102030405Z");
    if (next_update) |nu| {
        // nextUpdate is [0] EXPLICIT GeneralizedTime.
        var next_body: std.ArrayList(u8) = .empty;
        defer next_body.deinit(allocator);
        try appendDerTlv(allocator, &next_body, x509.Tag.generalized_time, nu);
        try appendDerTlv(allocator, &single_body, x509.Tag.context_0_constructed, next_body.items);
    }
    try appendDerSeq(allocator, &responses_body, single_body.items);
    try appendDerSeq(allocator, &tbs_body, responses_body.items);

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(allocator);
    try appendDerSeq(allocator, &tbs, tbs_body.items);
    const sig = try kp.sign(tbs.items, null);
    const sig_bytes = sig.toBytes();

    var basic_body: std.ArrayList(u8) = .empty;
    defer basic_body.deinit(allocator);
    try basic_body.appendSlice(allocator, tbs.items);
    try appendAlgId(allocator, &basic_body, &oid_ed25519, false);
    try appendDerBitString(allocator, &basic_body, &sig_bytes);
    var basic: std.ArrayList(u8) = .empty;
    defer basic.deinit(allocator);
    try appendDerSeq(allocator, &basic, basic_body.items);

    var rb_body: std.ArrayList(u8) = .empty;
    defer rb_body.deinit(allocator);
    try appendDerTlv(allocator, &rb_body, x509.Tag.oid, &Oid.ocsp_basic);
    try appendDerTlv(allocator, &rb_body, x509.Tag.octet_string, basic.items);
    var rb: std.ArrayList(u8) = .empty;
    defer rb.deinit(allocator);
    try appendDerSeq(allocator, &rb, rb_body.items);

    var outer_body: std.ArrayList(u8) = .empty;
    defer outer_body.deinit(allocator);
    try appendDerTlv(allocator, &outer_body, Asn1Tag.enumerated, &[_]u8{0});
    try appendDerTlv(allocator, &outer_body, x509.Tag.context_0_constructed, rb.items);
    var outer: std.ArrayList(u8) = .empty;
    errdefer outer.deinit(allocator);
    try appendDerSeq(allocator, &outer, outer_body.items);
    return outer.toOwnedSlice(allocator);
}

/// Build a BasicOCSPResponse signed by a DELEGATED responder (ECDSA-P256):
/// `responder_id_der` is the fully-encoded ResponderID element (byKey/byName, any
/// tagging), the response is signed with `responder_kp`, and `responder_cert_der`
/// is embedded in `certs [0]`. Status good, thisUpdate 2026-01-02, nextUpdate
/// `next_update`.
fn testDelegatedOcspResponse(
    allocator: std.mem.Allocator,
    responder_kp: ecdsa_p256.KeyPair,
    responder_cert_der: []const u8,
    responder_id_der: []const u8,
    serial: []const u8,
    next_update: []const u8,
) ![]u8 {
    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(allocator);
    try tbs_body.appendSlice(allocator, responder_id_der); // responderID
    try appendDerTlv(allocator, &tbs_body, x509.Tag.generalized_time, "20260102030405Z"); // producedAt

    var single_body: std.ArrayList(u8) = .empty;
    defer single_body.deinit(allocator);
    var cert_id_body: std.ArrayList(u8) = .empty;
    defer cert_id_body.deinit(allocator);
    try appendAlgId(allocator, &cert_id_body, &oid_sha1, true);
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.octet_string, &(@as([20]u8, @splat(0x11))));
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.octet_string, &(@as([20]u8, @splat(0x22))));
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.integer, serial);
    try appendDerSeq(allocator, &single_body, cert_id_body.items);
    try appendDerTlv(allocator, &single_body, Asn1Tag.context_0_primitive, ""); // certStatus good
    try appendDerTlv(allocator, &single_body, x509.Tag.generalized_time, "20260102030405Z"); // thisUpdate
    var next_body: std.ArrayList(u8) = .empty;
    defer next_body.deinit(allocator);
    try appendDerTlv(allocator, &next_body, x509.Tag.generalized_time, next_update);
    try appendDerTlv(allocator, &single_body, x509.Tag.context_0_constructed, next_body.items); // nextUpdate [0]

    var responses_body: std.ArrayList(u8) = .empty;
    defer responses_body.deinit(allocator);
    try appendDerSeq(allocator, &responses_body, single_body.items);
    try appendDerSeq(allocator, &tbs_body, responses_body.items);

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(allocator);
    try appendDerSeq(allocator, &tbs, tbs_body.items);

    // Sign tbsResponseData with the responder key (ECDSA-P256/SHA-256).
    const sig = try ecdsa_p256.sign(tbs.items, responder_kp);
    var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = try ecdsa_p256.signatureToDer(sig, &sig_der_buf);

    var basic_body: std.ArrayList(u8) = .empty;
    defer basic_body.deinit(allocator);
    try basic_body.appendSlice(allocator, tbs.items);
    try appendAlgId(allocator, &basic_body, &oid_ecdsa_sha256, false);
    try appendDerBitString(allocator, &basic_body, sig_der);
    // certs [0] EXPLICIT SEQUENCE OF Certificate { responder }.
    var certs_seq: std.ArrayList(u8) = .empty;
    defer certs_seq.deinit(allocator);
    try appendDerSeq(allocator, &certs_seq, responder_cert_der);
    try appendDerTlv(allocator, &basic_body, x509.Tag.context_0_constructed, certs_seq.items);

    var basic: std.ArrayList(u8) = .empty;
    defer basic.deinit(allocator);
    try appendDerSeq(allocator, &basic, basic_body.items);

    var rb_body: std.ArrayList(u8) = .empty;
    defer rb_body.deinit(allocator);
    try appendDerTlv(allocator, &rb_body, x509.Tag.oid, &Oid.ocsp_basic);
    try appendDerTlv(allocator, &rb_body, x509.Tag.octet_string, basic.items);
    var rb: std.ArrayList(u8) = .empty;
    defer rb.deinit(allocator);
    try appendDerSeq(allocator, &rb, rb_body.items);

    var outer_body: std.ArrayList(u8) = .empty;
    defer outer_body.deinit(allocator);
    try appendDerTlv(allocator, &outer_body, Asn1Tag.enumerated, &[_]u8{0});
    try appendDerTlv(allocator, &outer_body, x509.Tag.context_0_constructed, rb.items);
    var outer: std.ArrayList(u8) = .empty;
    errdefer outer.deinit(allocator);
    try appendDerSeq(allocator, &outer, outer_body.items);
    return outer.toOwnedSlice(allocator);
}

/// SHA-1 of a cert's subjectPublicKey — the byKey ResponderID hash.
fn responderKeyHashFromCert(cert_der: []const u8) ![20]u8 {
    const cert = try x509.Certificate.parse(cert_der);
    var kh: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(cert.subject_public_key, &kh, .{});
    return kh;
}

/// ResponderID byKey [2] IMPLICIT (primitive OCTET STRING contents) — the lenient
/// encoding many responders emit. Caller frees.
fn ridByKeyPrimitive(allocator: std.mem.Allocator, key_hash: []const u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(allocator);
    try appendDerTlv(allocator, &b, Asn1Tag.context_2_primitive, key_hash);
    return b.toOwnedSlice(allocator);
}

/// ResponderID byKey [2] EXPLICIT { KeyHash OCTET STRING } — the RFC 6960 form.
/// Caller frees.
fn ridByKeyExplicit(allocator: std.mem.Allocator, key_hash: []const u8) ![]u8 {
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(allocator);
    try appendDerTlv(allocator, &inner, x509.Tag.octet_string, key_hash);
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(allocator);
    try appendDerTlv(allocator, &b, Asn1Tag.context_2_constructed, inner.items);
    return b.toOwnedSlice(allocator);
}

/// ResponderID byName [1] EXPLICIT Name — `subject_der` is the responder cert's
/// subject `Name` TLV (itself a SEQUENCE). Caller frees.
fn ridByName(allocator: std.mem.Allocator, subject_der: []const u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(allocator);
    try appendDerTlv(allocator, &b, x509.Tag.context_1_constructed, subject_der);
    return b.toOwnedSlice(allocator);
}

test "isStapleServable accepts a delegated OCSP responder (issuer-signed + OCSPSigning EKU)" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const allocator = std.testing.allocator;

    // CA (issuer) and the delegated responder each get their own P-256 key.
    const issuer_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const responder_kp = ecdsa_p256.KeyPair.generate(std.testing.io);

    // The CA cert — we authorize the responder against ITS public key (SPKI).
    var ca_buf: [1024]u8 = undefined;
    const ca_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ca_buf, .{
        .common_name = "ocsp.ca.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x01},
        .key_pair = issuer_kp,
        .is_ca = true,
    });
    const ca = try x509.Certificate.parse(ca_der);

    // The delegated responder cert: ISSUER-signed, id-kp-OCSPSigning.
    var resp_buf: [1024]u8 = undefined;
    const responder_der = try x509_selfsign.buildEcdsaP256IssuedBy(&resp_buf, .{
        .common_name = "ocsp.responder.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x02},
        .key_pair = responder_kp,
        .eku_ocsp_signing = true,
    }, issuer_kp);
    const key_hash = try responderKeyHashFromCert(responder_der);
    const rid = try ridByKeyPrimitive(allocator, &key_hash);
    defer allocator.free(rid);

    const response = try testDelegatedOcspResponse(allocator, responder_kp, responder_der, rid, &[_]u8{0x44}, "20260202030405Z");
    defer allocator.free(response);

    const this_epoch = try x509.generalizedTimeToEpoch("20260102030405Z");
    const next_epoch = try x509.generalizedTimeToEpoch("20260202030405Z");
    const in_window = this_epoch + @divTrunc(next_epoch - this_epoch, 2);

    // Accepted: authorized responder, matched ResponderID, good + in window.
    try std.testing.expect(isStapleServable(response, ca.spki_der, &[_]u8{0x44}, in_window, 0));
    // Rejected under a DIFFERENT issuer key (the responder was not delegated by it).
    const other_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var other_buf: [1024]u8 = undefined;
    const other_der = try x509_selfsign.buildSelfSignedEcdsaP256(&other_buf, .{
        .common_name = "other.ca.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x03},
        .key_pair = other_kp,
        .is_ca = true,
    });
    const other = try x509.Certificate.parse(other_der);
    try std.testing.expect(!isStapleServable(response, other.spki_der, &[_]u8{0x44}, in_window, 0));
}

test "isStapleServable rejects a responder cert lacking id-kp-OCSPSigning" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const allocator = std.testing.allocator;

    const issuer_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const responder_kp = ecdsa_p256.KeyPair.generate(std.testing.io);

    var ca_buf: [1024]u8 = undefined;
    const ca_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ca_buf, .{
        .common_name = "ocsp.ca.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x01},
        .key_pair = issuer_kp,
        .is_ca = true,
    });
    const ca = try x509.Certificate.parse(ca_der);

    // Issuer-signed but WITHOUT the OCSPSigning EKU — must not be trusted to
    // sign OCSP responses (a plain issuer-signed leaf is not a responder).
    var resp_buf: [1024]u8 = undefined;
    const responder_der = try x509_selfsign.buildEcdsaP256IssuedBy(&resp_buf, .{
        .common_name = "not.a.responder.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x02},
        .key_pair = responder_kp,
        .eku_ocsp_signing = false,
    }, issuer_kp);
    const key_hash = try responderKeyHashFromCert(responder_der);
    const rid = try ridByKeyPrimitive(allocator, &key_hash);
    defer allocator.free(rid);

    const response = try testDelegatedOcspResponse(allocator, responder_kp, responder_der, rid, &[_]u8{0x44}, "20260202030405Z");
    defer allocator.free(response);

    const this_epoch = try x509.generalizedTimeToEpoch("20260102030405Z");
    const next_epoch = try x509.generalizedTimeToEpoch("20260202030405Z");
    const in_window = this_epoch + @divTrunc(next_epoch - this_epoch, 2);
    try std.testing.expect(!isStapleServable(response, ca.spki_der, &[_]u8{0x44}, in_window, 0));
}

test "delegated OCSP: byName + EXPLICIT-byKey accept; ResponderID-mismatch and wrong-signer reject" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const allocator = std.testing.allocator;
    const serial = &[_]u8{0x44};

    const issuer_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const responder_kp = ecdsa_p256.KeyPair.generate(std.testing.io);

    var ca_buf: [1024]u8 = undefined;
    const ca_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ca_buf, .{
        .common_name = "ocsp.ca.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x01},
        .key_pair = issuer_kp,
        .is_ca = true,
    });
    const ca = try x509.Certificate.parse(ca_der);

    var resp_buf: [1024]u8 = undefined;
    const responder_der = try x509_selfsign.buildEcdsaP256IssuedBy(&resp_buf, .{
        .common_name = "ocsp.responder.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x02},
        .key_pair = responder_kp,
        .eku_ocsp_signing = true,
    }, issuer_kp);
    const responder = try x509.Certificate.parse(responder_der);

    const this_epoch = try x509.generalizedTimeToEpoch("20260102030405Z");
    const next_epoch = try x509.generalizedTimeToEpoch("20260202030405Z");
    const in_window = this_epoch + @divTrunc(next_epoch - this_epoch, 2);

    // (1) byName [1] EXPLICIT accept — exercises the byName parse + match arm.
    {
        const rid = try ridByName(allocator, responder.subject_der);
        defer allocator.free(rid);
        const resp = try testDelegatedOcspResponse(allocator, responder_kp, responder_der, rid, serial, "20260202030405Z");
        defer allocator.free(resp);
        try std.testing.expect(isStapleServable(resp, ca.spki_der, serial, in_window, 0));
    }

    // (2) byKey [2] EXPLICIT { OCTET STRING } accept — exercises that parse branch.
    var kh: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(responder.subject_public_key, &kh, .{});
    {
        const rid = try ridByKeyExplicit(allocator, &kh);
        defer allocator.free(rid);
        const resp = try testDelegatedOcspResponse(allocator, responder_kp, responder_der, rid, serial, "20260202030405Z");
        defer allocator.free(resp);
        try std.testing.expect(isStapleServable(resp, ca.spki_der, serial, in_window, 0));
    }

    // (3) ResponderID names a DIFFERENT subject than the embedded cert → reject at
    //     the binding check (b), even though the cert is issuer-signed + OCSP-EKU.
    {
        const rid = try ridByName(allocator, ca.subject_der); // the CA's name, not the responder's
        defer allocator.free(rid);
        const resp = try testDelegatedOcspResponse(allocator, responder_kp, responder_der, rid, serial, "20260202030405Z");
        defer allocator.free(resp);
        try std.testing.expect(!isStapleServable(resp, ca.spki_der, serial, in_window, 0));
    }

    // (4) Response signed by a key OTHER than the responder's → passes (a)-(d) but
    //     the response-signature check (e) fails. Isolates (e).
    {
        const wrong_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
        const rid = try ridByKeyPrimitive(allocator, &kh);
        defer allocator.free(rid);
        const resp = try testDelegatedOcspResponse(allocator, wrong_kp, responder_der, rid, serial, "20260202030405Z");
        defer allocator.free(resp);
        try std.testing.expect(!isStapleServable(resp, ca.spki_der, serial, in_window, 0));
    }
}

pub fn testEd25519Spki(allocator: std.mem.Allocator, public_key: [Ed25519.PublicKey.encoded_length]u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendAlgId(allocator, &body, &oid_ed25519, false);
    try appendDerBitString(allocator, &body, &public_key);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
}

/// Inputs identifying the certificate an OCSP request asks about. All three are
/// DER byte views the caller extracts from the leaf + issuer certificates:
pub const CertIdInput = struct {
    /// The issuer's full Name TLV (the `SEQUENCE` of RDNs, tag+len+value).
    issuer_name_der: []const u8,
    /// The issuer's subjectPublicKey BIT STRING value WITHOUT the leading
    /// unused-bits octet (i.e. the raw public-key bytes).
    issuer_key_bytes: []const u8,
    /// The leaf certificate's serialNumber INTEGER contents (x509 `serial_der`).
    serial_der: []const u8,
};

/// Build a DER `OCSPRequest` (RFC 6960 §4.1) with a single SHA-1 `CertID` and no
/// optional signature or nonce. Caller owns the returned slice.
///
/// SHA-1 here is an *identifier* hash — the `CertID` responders key their
/// pre-produced responses on (Let's Encrypt and virtually all responders). It is
/// NOT a certificate or protocol signature, so it does not conflict with the
/// modern-only ban on SHA-1 cert signatures.
pub fn buildRequest(allocator: std.mem.Allocator, in: CertIdInput) std.mem.Allocator.Error![]u8 {
    const Sha1 = std.crypto.hash.Sha1;
    var name_hash: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(in.issuer_name_der, &name_hash, .{});
    var key_hash: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(in.issuer_key_bytes, &key_hash, .{});

    // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    var cert_id: std.ArrayList(u8) = .empty;
    defer cert_id.deinit(allocator);
    try appendAlgId(allocator, &cert_id, &oid_sha1, true);
    try appendDerTlv(allocator, &cert_id, x509.Tag.octet_string, &name_hash);
    try appendDerTlv(allocator, &cert_id, x509.Tag.octet_string, &key_hash);
    try appendDerTlv(allocator, &cert_id, x509.Tag.integer, in.serial_der);

    // Request ::= SEQUENCE { reqCert CertID } → requestList → TBSRequest → OCSPRequest.
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try appendDerSeq(allocator, &request, cert_id.items);
    var request_list: std.ArrayList(u8) = .empty;
    defer request_list.deinit(allocator);
    try appendDerSeq(allocator, &request_list, request.items);
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(allocator);
    try appendDerSeq(allocator, &tbs, request_list.items);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, tbs.items);
    return out.toOwnedSlice(allocator);
}

/// Build an OCSPRequest for a leaf certificate given its issuer, pulling the
/// CertID inputs straight from the parsed certs (leaf serial + issuer Name +
/// issuer raw public key). Caller owns the returned slice.
pub fn buildRequestForCerts(
    allocator: std.mem.Allocator,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
) std.mem.Allocator.Error![]u8 {
    return buildRequest(allocator, .{
        .issuer_name_der = issuer.subject_der,
        .issuer_key_bytes = issuer.subject_public_key,
        .serial_der = leaf.serial_der,
    });
}

fn appendAlgId(allocator: std.mem.Allocator, out: *std.ArrayList(u8), oid: []const u8, with_null: bool) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendDerTlv(allocator, &body, x509.Tag.oid, oid);
    if (with_null) try appendDerTlv(allocator, &body, x509.Tag.null_value, "");
    try appendDerSeq(allocator, out, body.items);
}

fn appendDerSeq(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    try appendDerTlv(allocator, out, x509.Tag.sequence, value);
}

fn appendDerBitString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.append(allocator, 0);
    try body.appendSlice(allocator, value);
    try appendDerTlv(allocator, out, x509.Tag.bit_string, body.items);
}

fn appendDerTlv(allocator: std.mem.Allocator, out: *std.ArrayList(u8), tag: u8, value: []const u8) !void {
    try out.append(allocator, tag);
    try appendDerLen(allocator, out, value.len);
    try out.appendSlice(allocator, value);
}

fn appendDerLen(allocator: std.mem.Allocator, out: *std.ArrayList(u8), len: usize) !void {
    if (len < 128) {
        try out.append(allocator, @intCast(len));
        return;
    }
    var tmp: [@sizeOf(usize)]u8 = undefined;
    var n = len;
    var count: usize = 0;
    while (n != 0) : (n >>= 8) {
        tmp[tmp.len - 1 - count] = @intCast(n & 0xff);
        count += 1;
    }
    try out.append(allocator, 0x80 | @as(u8, @intCast(count)));
    try out.appendSlice(allocator, tmp[tmp.len - count ..]);
}

const oid_sha1 = [_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };
