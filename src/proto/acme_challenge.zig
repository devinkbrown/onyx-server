// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ACME (RFC 8555 §8) challenge key authorization helpers.
//!
//! This module computes the small, deterministic strings an ACME client needs
//! to answer the two common challenge types defined by RFC 8555:
//!
//!   * HTTP-01 (§8.3) — the client serves the *key authorization* as a file at
//!     `/.well-known/acme-challenge/<token>`.
//!   * DNS-01  (§8.4) — the client publishes `base64url(SHA-256(keyAuth))` as a
//!     TXT record at `_acme-challenge.<domain>`.
//!
//!   * TLS-ALPN-01 (RFC 8737) — the client answers a TLS handshake that offers
//!     only the `acme-tls/1` ALPN protocol with a self-signed certificate that
//!     carries the critical `id-pe-acmeIdentifier` extension holding
//!     `SHA-256(keyAuth)`.
//!
//! The *key authorization* (§8.1) is the challenge `token`, a `.` separator,
//! and the base64url-encoded SHA-256 thumbprint of the account key's JWK
//! (RFC 7638). This module does NOT compute the thumbprint — the caller
//! supplies it (e.g. from the sibling JWK module). The only key material it
//! touches is the caller-supplied ephemeral TLS-ALPN-01 certificate key, which
//! signs the self-signed challenge certificate.
//!
//! Pure: no I/O, no clock, no RNG. Hashing uses `std.crypto.hash.sha2.Sha256`
//! and base64url encoding is delegated to the sibling `base64url.zig`. The
//! caller owns every output buffer; functions return the populated sub-slice.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64url = @import("base64url.zig");
const toml = @import("toml.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const tls12_handshake = @import("tls12_handshake.zig");

/// The fixed URL path prefix every HTTP-01 challenge is served under (§8.3).
pub const well_known_prefix = "/.well-known/acme-challenge/";

/// The byte that joins the token and the thumbprint in a key authorization.
const join_byte: u8 = '.';

/// Defensive upper bound on ACME token length. Tokens are server-chosen opaque
/// base64url strings; RFC 8555 §8.1 requires "at least 128 bits of entropy"
/// but sets no maximum. We accept a generous range and reject absurd inputs.
pub const default_max_token_len: usize = 256;

/// Operationally tunable wire-parse cap on challenge token length. Overridable
/// via `[acme].wire_max_token_len`; defaults to the historic 256-byte bound so
/// behavior is unchanged when unset.
pub var max_token_len: usize = default_max_token_len;

/// Overlay `[acme].wire_max_token_len` onto the module-level token cap. Absent
/// or zero values leave the current cap unchanged (behavior preserved).
pub fn applyToml(doc: *const toml.Document) void {
    if (doc.getUint("acme.wire_max_token_len")) |v| {
        if (v != 0) max_token_len = @intCast(v);
    }
}

/// Errors surfaced by this module.
///
/// `NoSpaceLeft` — a provided output buffer was too small for the result.
pub const Error = error{NoSpaceLeft};

/// Length, in bytes, of a key authorization for the given parts.
///
/// Equal to `token.len + 1 + thumbprint_b64.len` (the `1` is the `.`).
pub fn keyAuthorizationLen(token: []const u8, thumbprint_b64: []const u8) usize {
    return token.len + 1 + thumbprint_b64.len;
}

/// Build the key authorization `token "." thumbprint_b64` into `out` (§8.1).
///
/// `thumbprint_b64` is the base64url SHA-256 thumbprint of the account-key JWK
/// (RFC 7638), supplied by the caller. Returns the populated slice of `out`,
/// or `error.NoSpaceLeft` if `out` cannot hold the full result.
pub fn keyAuthorization(
    token: []const u8,
    thumbprint_b64: []const u8,
    out: []u8,
) Error![]const u8 {
    const need = keyAuthorizationLen(token, thumbprint_b64);
    if (out.len < need) return error.NoSpaceLeft;

    @memcpy(out[0..token.len], token);
    out[token.len] = join_byte;
    @memcpy(out[token.len + 1 ..][0..thumbprint_b64.len], thumbprint_b64);
    return out[0..need];
}

/// Length, in bytes, of the HTTP-01 path for `token`.
pub fn http01PathLen(token: []const u8) usize {
    return well_known_prefix.len + token.len;
}

/// Build the HTTP-01 challenge path `/.well-known/acme-challenge/<token>` into
/// `out` (§8.3). This is the URL path at which the server must serve the key
/// authorization. Returns the populated slice, or `error.NoSpaceLeft`.
pub fn http01Path(token: []const u8, out: []u8) Error![]const u8 {
    const need = http01PathLen(token);
    if (out.len < need) return error.NoSpaceLeft;

    @memcpy(out[0..well_known_prefix.len], well_known_prefix);
    @memcpy(out[well_known_prefix.len..][0..token.len], token);
    return out[0..need];
}

/// Exact number of base64url characters produced for a DNS-01 TXT value.
///
/// The value is the base64url (unpadded) encoding of a 32-byte SHA-256 digest.
pub fn dns01TxtValueLen() usize {
    return base64url.encodedLen(Sha256.digest_length);
}

/// Compute the DNS-01 TXT record value for `key_auth` (§8.4).
///
/// Returns `base64url(SHA-256(key_authorization))` — the value published at
/// `_acme-challenge.<domain>` — into `out`. Returns the populated slice, or
/// `error.NoSpaceLeft` if `out` is too small (need `dns01TxtValueLen()`).
pub fn dns01TxtValue(key_auth: []const u8, out: []u8) Error![]const u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(key_auth, &digest, .{});

    return base64url.encode(out, &digest) catch |err| switch (err) {
        error.NoSpaceLeft => error.NoSpaceLeft,
        // `encode` only ever fails with NoSpaceLeft; map any other variant
        // (none expected) conservatively to the same buffer-size error.
        else => error.NoSpaceLeft,
    };
}

/// Return true if `c` is a member of the URL-safe base64 alphabet (RFC 4648 §5):
/// `A-Z`, `a-z`, `0-9`, `-`, `_`. ACME tokens never contain padding.
fn isBase64UrlChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => true,
        else => false,
    };
}

/// Validate an ACME challenge `token` (§8.1).
///
/// A token must be non-empty, within a reasonable length bound, and contain
/// only URL-safe base64 characters (no padding). Returns false otherwise.
pub fn validateToken(token: []const u8) bool {
    if (token.len == 0) return false;
    if (token.len > max_token_len) return false;
    for (token) |c| {
        if (!isBase64UrlChar(c)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// DNS names (shared by DNS-01 and TLS-ALPN-01)
// ---------------------------------------------------------------------------

/// The label prepended to an identifier for its DNS-01 TXT record (§8.4).
pub const dns01_label = "_acme-challenge.";

/// Maximum presentation length of a DNS name without the trailing dot
/// (RFC 1035 §2.3.4: 255 octets on the wire, 253 characters in text).
pub const max_dns_name_len: usize = 253;

/// Strict LDH hostname check (RFC 1035 §2.3.1 as relaxed by RFC 1123 §2.1),
/// plus the `_` byte so the DNS-01 owner `_acme-challenge.<domain>` (§8.4)
/// passes. Every label is 1..63 bytes of `A-Z a-z 0-9 - _`, never starting or
/// ending with `-`; no trailing dot, no wildcard. This is the gate in front of
/// every value handed to an operator DNS hook or placed in a certificate, so
/// a leading `-` (option injection) or any shell metacharacter is rejected.
pub fn isValidDnsName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_dns_name_len) return false;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => {},
            else => return false,
        };
    }
    return true;
}

/// Build the DNS-01 owner name `_acme-challenge.<domain>` (§8.4) into `out`.
/// For a wildcard order the authorization identifier already omits `*.`
/// (RFC 8555 §7.1.4), so `domain` is always a plain name.
pub fn dns01RecordName(domain: []const u8, out: []u8) Error![]const u8 {
    const need = dns01_label.len + domain.len;
    if (out.len < need) return error.NoSpaceLeft;
    @memcpy(out[0..dns01_label.len], dns01_label);
    @memcpy(out[dns01_label.len..need], domain);
    return out[0..need];
}

// ---------------------------------------------------------------------------
// TLS-ALPN-01 (RFC 8737)
// ---------------------------------------------------------------------------

/// The ALPN protocol ID a TLS-ALPN-01 validation offers (RFC 8737 §6.2).
pub const acme_tls_alpn_protocol = "acme-tls/1";

/// DER contents of OID id-pe-acmeIdentifier, 1.3.6.1.5.5.7.1.31
/// (RFC 8737 §6.1).
pub const id_pe_acme_identifier_oid = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f };

/// Upper bound on the encoded challenge certificate. The real size is ~400
/// bytes for a 253-byte name; this leaves headroom while staying fixed-size.
pub const max_tls_alpn01_cert_len: usize = 1024;

pub const TlsAlpn01Error = error{
    NoSpaceLeft,
    InvalidDomain,
    InvalidValidity,
    SigningFailed,
};

/// The acmeIdentifier extension payload: `SHA-256(keyAuthorization)`
/// (RFC 8737 §3: "The extension MUST contain the SHA-256 digest of the key
/// authorization").
pub fn tlsAlpn01Digest(key_authorization: []const u8) [Sha256.digest_length]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(key_authorization, &digest, .{});
    return digest;
}

pub const TlsAlpn01CertParams = struct {
    /// The single dNSName the certificate's subjectAltName carries (RFC 8737
    /// §3: "The certificate MUST contain a subjectAltName extension containing
    /// the dNSName being validated and no other entries").
    domain: []const u8,
    /// The key authorization (§8.1) for this challenge.
    key_authorization: []const u8,
    /// Ephemeral key: its public key becomes the SPKI and it self-signs.
    key_pair: ecdsa_p256.KeyPair,
    /// 16 serial bytes; normalised to a positive, minimal, non-zero INTEGER.
    serial: [16]u8,
    not_before: i64,
    not_after: i64,
};

/// Build the self-signed TLS-ALPN-01 validation certificate (RFC 8737 §3):
/// X.509 v3, ecdsa-with-SHA256, subjectAltName = { dNSName domain } only, and
/// the id-pe-acmeIdentifier extension marked critical whose extnValue is the
/// DER `Authorization ::= OCTET STRING (SIZE (32))` holding the SHA-256 of the
/// key authorization (RFC 8737 §3 and the ASN.1 module in §6.1). Returns a
/// slice of `out`.
pub fn buildTlsAlpn01Certificate(out: []u8, params: TlsAlpn01CertParams) TlsAlpn01Error![]const u8 {
    if (!isValidDnsName(params.domain)) return error.InvalidDomain;
    if (params.not_after <= params.not_before or params.not_before < 0) return error.InvalidValidity;

    // --- extensions ---
    var san_names_buf: [max_dns_name_len + 4]u8 = undefined;
    var san_names = Der.init(&san_names_buf);
    try san_names.tlv(0x82, params.domain); // [2] dNSName
    var san_seq_buf: [max_dns_name_len + 8]u8 = undefined;
    var san_seq = Der.init(&san_seq_buf);
    try san_seq.tlv(0x30, san_names.bytes());

    var san_ext_buf: [max_dns_name_len + 24]u8 = undefined;
    var san_ext = Der.init(&san_ext_buf);
    try san_ext.tlv(0x06, &oid_subject_alt_name);
    try san_ext.tlv(0x04, san_seq.bytes());

    const digest = tlsAlpn01Digest(params.key_authorization);
    var auth_buf: [34]u8 = undefined;
    var auth = Der.init(&auth_buf);
    try auth.tlv(0x04, &digest); // Authorization ::= OCTET STRING (SIZE (32))
    var acme_ext_buf: [64]u8 = undefined;
    var acme_ext = Der.init(&acme_ext_buf);
    try acme_ext.tlv(0x06, &id_pe_acme_identifier_oid);
    try acme_ext.tlv(0x01, &.{0xff}); // critical: TRUE (RFC 8737 §3 "MUST be critical")
    try acme_ext.tlv(0x04, auth.bytes()); // extnValue

    var ext_list_buf: [max_dns_name_len + 120]u8 = undefined;
    var ext_list = Der.init(&ext_list_buf);
    try ext_list.tlv(0x30, san_ext.bytes());
    try ext_list.tlv(0x30, acme_ext.bytes());
    var ext_seq_buf: [max_dns_name_len + 128]u8 = undefined;
    var ext_seq = Der.init(&ext_seq_buf);
    try ext_seq.tlv(0x30, ext_list.bytes());

    // --- TBSCertificate ---
    var serial = params.serial;
    serial[0] = (serial[0] & 0x7f) | 0x40; // positive, minimal, non-zero (RFC 5280 §4.1.2.2)

    var tbs_body_buf: [max_tls_alpn01_cert_len]u8 = undefined;
    var tbs_body = Der.init(&tbs_body_buf);
    try tbs_body.tlv(0xa0, &.{ 0x02, 0x01, 0x02 }); // [0] version v3
    try tbs_body.tlv(0x02, &serial);
    try tbs_body.raw(&ecdsa_with_sha256_alg);
    try tbs_body.raw(&challenge_name);
    var validity_buf: [40]u8 = undefined;
    var validity = Der.init(&validity_buf);
    try writeTime(&validity, params.not_before);
    try writeTime(&validity, params.not_after);
    try tbs_body.tlv(0x30, validity.bytes());
    try tbs_body.raw(&challenge_name);
    try tbs_body.raw(&ecP256Spki(params.key_pair.public_key.toUncompressedSec1()));
    try tbs_body.tlv(0xa3, ext_seq.bytes()); // [3] extensions

    var tbs_buf: [max_tls_alpn01_cert_len]u8 = undefined;
    var tbs = Der.init(&tbs_buf);
    try tbs.tlv(0x30, tbs_body.bytes());

    const sig = ecdsa_p256.sign(tbs.bytes(), params.key_pair) catch return error.SigningFailed;
    var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = ecdsa_p256.signatureToDer(sig, &sig_der_buf) catch return error.SigningFailed;
    var bit_buf: [ecdsa_p256.Signature.der_encoded_length_max + 1]u8 = undefined;
    bit_buf[0] = 0; // zero unused bits
    @memcpy(bit_buf[1..][0..sig_der.len], sig_der);

    var cert_body_buf: [max_tls_alpn01_cert_len]u8 = undefined;
    var cert_body = Der.init(&cert_body_buf);
    try cert_body.raw(tbs.bytes());
    try cert_body.raw(&ecdsa_with_sha256_alg);
    try cert_body.tlv(0x03, bit_buf[0 .. sig_der.len + 1]);

    var cert = Der.init(out);
    try cert.tlv(0x30, cert_body.bytes());
    return cert.bytes();
}

/// Result of inspecting a TLS-ALPN-01 validation ClientHello.
pub const AcmeTlsHello = struct {
    /// The SNI host_name (RFC 6066 §3) the validator is checking.
    server_name: []const u8,
};

/// Inspect the first plaintext TLS record a client sent and report whether it
/// is a TLS-ALPN-01 validation handshake: a single-record ClientHello carrying
/// a `server_name` host_name (RFC 8737 §3: "the ACME server ... MUST use the
/// Server Name Indication extension") and an ALPN extension whose protocol list
/// is exactly `acme-tls/1` (RFC 8737 §3: the client "MUST ... include an
/// ALPN extension ... containing only the acme-tls/1 protocol"). Anything else
/// — fragmented hellos, duplicate extensions, malformed vectors, extra ALPN
/// protocols — returns null, so the listener falls back to its normal
/// certificate (fail closed: the challenge certificate is never presented to an
/// ordinary client). The returned slice borrows `record`.
pub fn peekAcmeTlsHello(record: []const u8) ?AcmeTlsHello {
    if (record.len < 5 + tls12_handshake.handshake_header_len) return null;
    if (record[0] != 22) return null; // ContentType.handshake
    const rec_len = std.mem.readInt(u16, record[3..5], .big);
    if (record.len < 5 + @as(usize, rec_len)) return null;
    const hs = record[5 .. 5 + @as(usize, rec_len)];
    if (hs.len < tls12_handshake.handshake_header_len) return null;
    if (hs[0] != tls12_handshake.client_hello_msg_type) return null;
    const body_len = (@as(usize, hs[1]) << 16) | (@as(usize, hs[2]) << 8) | hs[3];
    if (hs.len - tls12_handshake.handshake_header_len < body_len) return null; // fragmented
    const body = hs[tls12_handshake.handshake_header_len..][0..body_len];
    const hello = tls12_handshake.parseClientHello(body) catch return null;

    var sni: ?[]const u8 = null;
    var alpn_ok = false;
    var saw_alpn = false;
    var it = hello.extensionIterator();
    while (it.next() catch return null) |ext| switch (ext.ext_type) {
        0 => { // server_name (RFC 6066 §3)
            if (sni != null) return null;
            sni = parseSniHostName(ext.data) orelse return null;
        },
        16 => { // application_layer_protocol_negotiation (RFC 7301 §3.1)
            if (saw_alpn) return null;
            saw_alpn = true;
            alpn_ok = alpnIsExactlyAcmeTls(ext.data);
        },
        else => {},
    };
    if (!alpn_ok) return null;
    const name = sni orelse return null;
    if (!isValidDnsName(name)) return null;
    return .{ .server_name = name };
}

fn parseSniHostName(data: []const u8) ?[]const u8 {
    if (data.len < 2) return null;
    const list_len = std.mem.readInt(u16, data[0..2], .big);
    if (list_len != data.len - 2) return null;
    var list = data[2..];
    var host: ?[]const u8 = null;
    while (list.len != 0) {
        if (list.len < 3) return null;
        const name_type = list[0];
        const name_len = std.mem.readInt(u16, list[1..3], .big);
        if (list.len - 3 < name_len) return null;
        const name = list[3..][0..name_len];
        list = list[3 + @as(usize, name_len) ..];
        if (name_type == 0) { // host_name; RFC 6066 §3 forbids two of a type
            if (host != null) return null;
            host = name;
        }
    }
    return host;
}

fn alpnIsExactlyAcmeTls(data: []const u8) bool {
    if (data.len < 2) return false;
    const list_len = std.mem.readInt(u16, data[0..2], .big);
    if (list_len != data.len - 2) return false;
    const list = data[2..];
    if (list.len != 1 + acme_tls_alpn_protocol.len) return false;
    if (list[0] != acme_tls_alpn_protocol.len) return false;
    return std.mem.eql(u8, list[1..], acme_tls_alpn_protocol);
}

// --- minimal DER writer (definite-length, up to 64 KiB contents) -------------

const Der = struct {
    buf: []u8,
    len: usize = 0,

    fn init(buf: []u8) Der {
        return .{ .buf = buf };
    }

    fn bytes(self: *const Der) []const u8 {
        return self.buf[0..self.len];
    }

    fn raw(self: *Der, data: []const u8) error{NoSpaceLeft}!void {
        if (self.buf.len - self.len < data.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
    }

    fn tlv(self: *Der, tag: u8, content: []const u8) error{NoSpaceLeft}!void {
        var hdr: [4]u8 = undefined;
        hdr[0] = tag;
        const hdr_len: usize = if (content.len < 0x80) blk: {
            hdr[1] = @intCast(content.len);
            break :blk 2;
        } else if (content.len <= 0xff) blk: {
            hdr[1] = 0x81;
            hdr[2] = @intCast(content.len);
            break :blk 3;
        } else if (content.len <= 0xffff) blk: {
            hdr[1] = 0x82;
            std.mem.writeInt(u16, hdr[2..4], @intCast(content.len), .big);
            break :blk 4;
        } else return error.NoSpaceLeft;
        try self.raw(hdr[0..hdr_len]);
        try self.raw(content);
    }
};

/// RFC 5280 §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050.
fn writeTime(w: *Der, unix: i64) TlsAlpn01Error!void {
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(unix) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    var text: [15]u8 = undefined;
    if (yd.year >= 1950 and yd.year < 2050) {
        _ = std.fmt.bufPrint(&text, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            yd.year % 100, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        }) catch return error.NoSpaceLeft;
        try w.tlv(0x17, text[0..13]);
    } else {
        if (yd.year > 9999) return error.InvalidValidity;
        _ = std.fmt.bufPrint(&text, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        }) catch return error.NoSpaceLeft;
        try w.tlv(0x18, text[0..15]);
    }
}

/// id-ce-subjectAltName (2.5.29.17).
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 };

/// AlgorithmIdentifier ecdsa-with-SHA256 (1.2.840.10045.4.3.2), parameters
/// absent (RFC 5758 §3.2).
const ecdsa_with_sha256_alg = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

/// Name ::= SEQUENCE { SET { SEQUENCE { id-at-commonName, UTF8String
/// "acme-tls-alpn-01" } } }. RFC 8737 places no requirement on the subject;
/// a fixed short CN keeps it within ub-common-name (64) for any domain.
const challenge_name = [_]u8{
    0x30, 0x1b, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10,
} ++ "acme-tls-alpn-01".*;

/// DER SubjectPublicKeyInfo for an uncompressed P-256 public key.
fn ecP256Spki(sec1: [65]u8) [91]u8 {
    var out: [91]u8 = .{
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    } ++ @as([65]u8, @splat(0));
    @memcpy(out[26..91], &sec1);
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "keyAuthorization concatenates token, dot, and thumbprint" {
    // Arrange
    const token = "DGyRejmCefe7v4NfDGDKfA";
    const thumbprint = "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";
    var buf: [128]u8 = undefined;

    // Act
    const key_auth = try keyAuthorization(token, thumbprint, &buf);

    // Assert
    try testing.expectEqualStrings(token ++ "." ++ thumbprint, key_auth);
    try testing.expectEqual(keyAuthorizationLen(token, thumbprint), key_auth.len);
}

test "keyAuthorization returns NoSpaceLeft when buffer too small" {
    // Arrange
    const token = "abc";
    const thumbprint = "xyz";
    var buf: [3]u8 = undefined; // need 7 ("abc.xyz")

    // Act
    const result = keyAuthorization(token, thumbprint, &buf);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "http01Path produces well-known acme-challenge prefix" {
    // Arrange
    const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    var buf: [128]u8 = undefined;

    // Act
    const path = try http01Path(token, &buf);

    // Assert
    try testing.expectEqualStrings("/.well-known/acme-challenge/" ++ token, path);
    try testing.expect(std.mem.startsWith(u8, path, well_known_prefix));
    try testing.expect(std.mem.endsWith(u8, path, token));
}

test "http01Path returns NoSpaceLeft for tiny buffer" {
    // Arrange
    const token = "tok";
    var buf: [4]u8 = undefined; // prefix alone is far longer

    // Act
    const result = http01Path(token, &buf);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "dns01TxtValue equals base64url(sha256(keyAuth)) recomputed independently" {
    // Arrange
    const key_auth = "DGyRejmCefe7v4NfDGDKfA.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";
    var out: [64]u8 = undefined;

    // Act
    const txt = try dns01TxtValue(key_auth, &out);

    // Assert — independently recompute the expected value.
    var expected_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(key_auth, &expected_digest, .{});
    var expected_buf: [64]u8 = undefined;
    const expected = try base64url.encode(&expected_buf, &expected_digest);
    try testing.expectEqualStrings(expected, txt);
    try testing.expectEqual(dns01TxtValueLen(), txt.len);
    // base64url of a 32-byte digest is 43 unpadded characters.
    try testing.expectEqual(@as(usize, 43), txt.len);
}

test "dns01TxtValue returns NoSpaceLeft when buffer too small" {
    // Arrange
    const key_auth = "token.thumb";
    var out: [10]u8 = undefined; // need 43

    // Act
    const result = dns01TxtValue(key_auth, &out);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "validateToken accepts a well-formed base64url token" {
    // Arrange
    const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";

    // Act
    const ok = validateToken(token);

    // Assert
    try testing.expect(ok);
}

test "validateToken rejects an empty token" {
    // Arrange
    const token = "";

    // Act / Assert
    try testing.expect(!validateToken(token));
}

test "validateToken rejects illegal characters" {
    // Arrange — padding, plus/slash, dot, and whitespace are all invalid.
    const bad = [_][]const u8{
        "abc=def", // padding char
        "abc+def", // standard-alphabet '+'
        "abc/def", // standard-alphabet '/'
        "abc.def", // the key-auth separator is not a token char
        "abc def", // whitespace
        "abc\ndef", // control char
    };

    // Act / Assert
    for (bad) |t| {
        try testing.expect(!validateToken(t));
    }
}

test "validateToken rejects an over-long token" {
    // Arrange
    const token = &@as([(default_max_token_len + 1)]u8, @splat('a'));

    // Act / Assert
    try testing.expect(!validateToken(token));
}

test "validateToken accepts all alphabet boundary characters" {
    // Arrange — every distinct class plus the two special chars.
    const token = "AZaz09-_";

    // Act / Assert
    try testing.expect(validateToken(token));
}

test "applyToml overrides the wire token cap and restores cleanly" {
    // Arrange
    const saved = max_token_len;
    defer max_token_len = saved; // never leak the override into other tests
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[acme]\nwire_max_token_len = 8\n");
    defer doc.deinit(allocator);

    // Act
    applyToml(&doc);

    // Assert — a 9-char token now fails, an 8-char token passes.
    try testing.expectEqual(@as(usize, 8), max_token_len);
    try testing.expect(!validateToken("AAAAAAAAA"));
    try testing.expect(validateToken("AAAAAAAA"));
}

test "applyToml leaves the cap unchanged when key absent or zero" {
    const saved = max_token_len;
    defer max_token_len = saved;
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[acme]\nwire_max_token_len = 0\n");
    defer doc.deinit(allocator);

    applyToml(&doc);
    try testing.expectEqual(default_max_token_len, max_token_len);
}

test "isValidDnsName accepts LDH names and the DNS-01 owner, rejects injection shapes" {
    try testing.expect(isValidDnsName("irc.example.com"));
    try testing.expect(isValidDnsName("_acme-challenge.irc.example.com"));
    try testing.expect(isValidDnsName("a"));
    try testing.expect(!isValidDnsName(""));
    try testing.expect(!isValidDnsName("-rf.example.com")); // option injection
    try testing.expect(!isValidDnsName("example.com.")); // trailing dot
    try testing.expect(!isValidDnsName("*.example.com"));
    try testing.expect(!isValidDnsName("a..b"));
    try testing.expect(!isValidDnsName("$(reboot).example.com"));
    try testing.expect(!isValidDnsName("ex ample.com"));
    try testing.expect(!isValidDnsName("bad-.example.com"));
    var long_label: [68]u8 = undefined;
    @memset(long_label[0..64], 'a');
    @memcpy(long_label[64..68], ".com");
    try testing.expect(!isValidDnsName(&long_label));
    var long_name: [259]u8 = undefined;
    for (0..4) |i| {
        @memset(long_name[i * 64 ..][0..63], 'a');
        long_name[i * 64 + 63] = '.';
    }
    @memcpy(long_name[256..259], "com");
    try testing.expect(!isValidDnsName(&long_name));
    try testing.expect(isValidDnsName(long_name[0..253])); // exactly at the 253-byte bound
}

test "dns01RecordName prefixes _acme-challenge (RFC 8555 §8.4)" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("_acme-challenge.example.org", try dns01RecordName("example.org", &buf));
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, dns01RecordName("example.org", &tiny));
}

test "tls-alpn-01 certificate carries one SAN and a critical acmeIdentifier = SHA-256(keyAuth)" {
    const x509 = @import("../crypto/x509.zig");
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x5a)));
    const key_auth = "tok-123.thumbprint-abc";
    var buf: [max_tls_alpn01_cert_len]u8 = undefined;
    const der = try buildTlsAlpn01Certificate(&buf, .{
        .domain = "irc.example.test",
        .key_authorization = key_auth,
        .key_pair = kp,
        .serial = @as([16]u8, @splat(0xff)),
        .not_before = 1_800_000_000,
        .not_after = 1_800_000_000 + 7 * 86400,
    });

    // The production X.509 parser recognises the extension as critical and
    // refuses it as unsupported (RFC 5280 §4.2) — proof the flag is on the wire.
    try testing.expectError(error.UnsupportedCriticalExtension, x509.parse(der));

    // Walk the structure with the same DER reader.
    var top = x509.DerReader.init(der);
    const cert_tlv = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var cert = try top.child(cert_tlv);
    const tbs_tlv = try cert.readExpected(x509.Tag.sequence);
    const tbs_full = tbs_tlv.raw;
    const sig_alg = try cert.readExpected(x509.Tag.sequence);
    try testing.expectEqualSlices(u8, ecdsa_with_sha256_alg[2..], sig_alg.value);
    const sig_bits = try cert.readExpected(x509.Tag.bit_string);
    try cert.expectEmpty();
    try testing.expectEqual(@as(u8, 0), sig_bits.value[0]);
    const sig = try ecdsa_p256.signatureFromDer(sig_bits.value[1..]);
    try testing.expect(ecdsa_p256.verify(sig, tbs_full, kp.public_key));

    var tbs = try cert.child(tbs_tlv);
    const version = try tbs.readExpected(x509.Tag.context_0_constructed);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x02 }, version.value);
    const serial = try tbs.readExpected(x509.Tag.integer);
    try testing.expectEqual(@as(usize, 16), serial.value.len);
    try testing.expect(serial.value[0] & 0x80 == 0 and serial.value[0] != 0);
    _ = try tbs.readExpected(x509.Tag.sequence); // signature alg
    const issuer = try tbs.readExpected(x509.Tag.sequence);
    var validity = try tbs.child(try tbs.readExpected(x509.Tag.sequence));
    try testing.expectEqualStrings("270115080000Z", (try validity.readExpected(x509.Tag.utc_time)).value);
    try testing.expectEqualStrings("270122080000Z", (try validity.readExpected(x509.Tag.utc_time)).value);
    const subject = try tbs.readExpected(x509.Tag.sequence);
    try testing.expectEqualSlices(u8, issuer.value, subject.value); // self-issued
    const spki = try tbs.readExpected(x509.Tag.sequence);
    try testing.expectEqualSlices(u8, &ecP256Spki(kp.public_key.toUncompressedSec1()), spki.raw);
    const explicit = try tbs.readExpected(x509.Tag.context_3_constructed);
    try tbs.expectEmpty();

    var ext_holder = try tbs.child(explicit);
    var exts = try ext_holder.child(try ext_holder.readExpected(x509.Tag.sequence));
    var saw_san = false;
    var saw_acme = false;
    while (exts.hasRemaining()) {
        var ext = try exts.child(try exts.readExpected(x509.Tag.sequence));
        const oid = try ext.readExpected(x509.Tag.oid);
        var critical = false;
        if ((try ext.peekTag()) == x509.Tag.boolean) {
            const b = try ext.readExpected(x509.Tag.boolean);
            try testing.expectEqualSlices(u8, &.{0xff}, b.value); // DER TRUE
            critical = true;
        }
        const value = try ext.readExpected(x509.Tag.octet_string);
        try ext.expectEmpty();
        if (std.mem.eql(u8, oid.value, &id_pe_acme_identifier_oid)) {
            saw_acme = true;
            try testing.expect(critical); // RFC 8737 §3: MUST be critical
            var inner = x509.DerReader.init(value.value);
            const auth = try inner.readExpected(x509.Tag.octet_string);
            try inner.expectEmpty();
            var want: [32]u8 = undefined;
            Sha256.hash(key_auth, &want, .{});
            try testing.expectEqualSlices(u8, &want, auth.value);
        } else if (std.mem.eql(u8, oid.value, &oid_subject_alt_name)) {
            saw_san = true;
            try testing.expect(!critical);
            var san_top = x509.DerReader.init(value.value);
            var names = try san_top.child(try san_top.readExpected(x509.Tag.sequence));
            const name = try names.readExpected(x509.Tag.san_dns_name);
            try testing.expectEqualStrings("irc.example.test", name.value);
            try names.expectEmpty(); // exactly one entry
        } else return error.TestUnexpectedResult;
    }
    try testing.expect(saw_san and saw_acme);
    try testing.expectEqual(x509.SubjectPublicKey.ecdsa_p256, std.meta.activeTag(try x509.extractPublicKey(spki.raw)));
}

test "tls-alpn-01 certificate rejects invalid names and validity, uses GeneralizedTime from 2050" {
    const x509 = @import("../crypto/x509.zig");
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x5b)));
    var buf: [max_tls_alpn01_cert_len]u8 = undefined;
    const base: TlsAlpn01CertParams = .{
        .domain = "x.test",
        .key_authorization = "a.b",
        .key_pair = kp,
        .serial = @as([16]u8, @splat(0)),
        .not_before = 1_800_000_000,
        .not_after = 1_800_000_100,
    };
    var bad = base;
    bad.domain = "*.x.test";
    try testing.expectError(error.InvalidDomain, buildTlsAlpn01Certificate(&buf, bad));
    bad = base;
    bad.not_after = bad.not_before;
    try testing.expectError(error.InvalidValidity, buildTlsAlpn01Certificate(&buf, bad));
    var tiny: [64]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, buildTlsAlpn01Certificate(&tiny, base));

    var late = base;
    late.not_after = 2_556_144_000; // 2051-01-01
    const der = try buildTlsAlpn01Certificate(&buf, late);
    try testing.expect(std.mem.indexOf(u8, der, "20510101000000Z") != null);
    var top = x509.DerReader.init(der);
    _ = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
}

/// Build a TLS record carrying a ClientHello with the given SNI host names and
/// ALPN protocols (empty slice = extension omitted).
fn testClientHello(out: []u8, sni: []const []const u8, alpn: []const []const u8, dup_alpn: bool) []const u8 {
    var exts: [512]u8 = undefined;
    var e: usize = 0;
    if (sni.len != 0) {
        var list: [256]u8 = undefined;
        var l: usize = 0;
        for (sni) |n| {
            list[l] = 0;
            std.mem.writeInt(u16, list[l + 1 ..][0..2], @intCast(n.len), .big);
            @memcpy(list[l + 3 ..][0..n.len], n);
            l += 3 + n.len;
        }
        std.mem.writeInt(u16, exts[e..][0..2], 0, .big);
        std.mem.writeInt(u16, exts[e + 2 ..][0..2], @intCast(l + 2), .big);
        std.mem.writeInt(u16, exts[e + 4 ..][0..2], @intCast(l), .big);
        @memcpy(exts[e + 6 ..][0..l], list[0..l]);
        e += 6 + l;
    }
    var reps: usize = if (alpn.len != 0) (if (dup_alpn) 2 else 1) else 0;
    while (reps > 0) : (reps -= 1) {
        var list: [128]u8 = undefined;
        var l: usize = 0;
        for (alpn) |p| {
            list[l] = @intCast(p.len);
            @memcpy(list[l + 1 ..][0..p.len], p);
            l += 1 + p.len;
        }
        std.mem.writeInt(u16, exts[e..][0..2], 16, .big);
        std.mem.writeInt(u16, exts[e + 2 ..][0..2], @intCast(l + 2), .big);
        std.mem.writeInt(u16, exts[e + 4 ..][0..2], @intCast(l), .big);
        @memcpy(exts[e + 6 ..][0..l], list[0..l]);
        e += 6 + l;
    }
    var body: [700]u8 = undefined;
    var b: usize = 0;
    body[0] = 0x03;
    body[1] = 0x03;
    @memset(body[2..34], 0x11);
    body[34] = 0; // session id
    body[35] = 0;
    body[36] = 2;
    body[37] = 0x13;
    body[38] = 0x01; // TLS_AES_128_GCM_SHA256
    body[39] = 1;
    body[40] = 0; // null compression
    b = 41;
    std.mem.writeInt(u16, body[b..][0..2], @intCast(e), .big);
    b += 2;
    @memcpy(body[b..][0..e], exts[0..e]);
    b += e;
    out[0] = 22;
    out[1] = 3;
    out[2] = 1;
    std.mem.writeInt(u16, out[3..5], @intCast(4 + b), .big);
    out[5] = 1;
    out[6] = @intCast(b >> 16);
    out[7] = @intCast((b >> 8) & 0xff);
    out[8] = @intCast(b & 0xff);
    @memcpy(out[9..][0..b], body[0..b]);
    return out[0 .. 9 + b];
}

test "peekAcmeTlsHello matches only SNI + ALPN exactly acme-tls/1 (RFC 8737 §3)" {
    var buf: [1024]u8 = undefined;
    const ok = testClientHello(&buf, &.{"irc.example.test"}, &.{"acme-tls/1"}, false);
    const hello = peekAcmeTlsHello(ok) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("irc.example.test", hello.server_name);

    // Ordinary client offering acme-tls/1 among others: not a validation.
    try testing.expect(peekAcmeTlsHello(testClientHello(&buf, &.{"irc.example.test"}, &.{ "irc", "acme-tls/1" }, false)) == null);
    // No ALPN / wrong ALPN.
    try testing.expect(peekAcmeTlsHello(testClientHello(&buf, &.{"irc.example.test"}, &.{}, false)) == null);
    try testing.expect(peekAcmeTlsHello(testClientHello(&buf, &.{"irc.example.test"}, &.{"h2"}, false)) == null);
    // No SNI.
    try testing.expect(peekAcmeTlsHello(testClientHello(&buf, &.{}, &.{"acme-tls/1"}, false)) == null);
    // Duplicate ALPN extension.
    try testing.expect(peekAcmeTlsHello(testClientHello(&buf, &.{"irc.example.test"}, &.{"acme-tls/1"}, true)) == null);
    // Two host_name entries.
    try testing.expect(peekAcmeTlsHello(testClientHello(&buf, &.{ "a.test", "b.test" }, &.{"acme-tls/1"}, false)) == null);
    // Invalid SNI bytes.
    try testing.expect(peekAcmeTlsHello(testClientHello(&buf, &.{"bad name"}, &.{"acme-tls/1"}, false)) == null);

    // Truncated record / fragmented handshake / wrong content type.
    const full = testClientHello(&buf, &.{"irc.example.test"}, &.{"acme-tls/1"}, false);
    try testing.expect(peekAcmeTlsHello(full[0 .. full.len - 1]) == null);
    var copy: [1024]u8 = undefined;
    @memcpy(copy[0..full.len], full);
    copy[0] = 23;
    try testing.expect(peekAcmeTlsHello(copy[0..full.len]) == null);
    @memcpy(copy[0..full.len], full);
    std.mem.writeInt(u16, copy[3..5], @intCast(full.len - 5 - 10), .big); // record shorter than hello
    try testing.expect(peekAcmeTlsHello(copy[0 .. full.len - 10]) == null);
}
